//! End-to-end regression for opaque arbitrary-format Blossom attachments.
//!
//! Requires a relay started with `BUZZ_MEDIA_ALLOW_ALL_FILE_TYPES=true`, plus
//! Postgres, Redis, and a pre-created S3/MinIO bucket.
//!
//! Run: `cargo test -p buzz-test-client --test e2e_media_any_type -- --ignored`

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use reqwest::{Client, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn relay_http_url() -> String {
    std::env::var("RELAY_HTTP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
}

fn sign_upload(keys: &Keys, sha256: &str) -> nostr::Event {
    let expiration = (Timestamp::now().as_secs() + 300).to_string();
    let tags = vec![
        Tag::parse(["t", "upload"]).expect("upload tag"),
        Tag::parse(["x", sha256]).expect("hash tag"),
        Tag::parse(["expiration", &expiration]).expect("expiration tag"),
    ];
    EventBuilder::new(Kind::from(24242), "Opaque attachment test")
        .tags(tags)
        .sign_with_keys(keys)
        .expect("sign upload auth")
}

fn auth_header(event: &nostr::Event) -> String {
    format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(event.as_json().as_bytes())
    )
}

async fn upload(
    client: &Client,
    keys: &Keys,
    body: &[u8],
    declared_mime: &str,
) -> Response {
    let sha256 = hex::encode(Sha256::digest(body));
    let auth = sign_upload(keys, &sha256);
    client
        .put(format!("{}/upload", relay_http_url()))
        .header("Authorization", auth_header(&auth))
        .header("Content-Type", declared_mime)
        .header("X-SHA-256", sha256)
        .body(body.to_vec())
        .send()
        .await
        .expect("upload request")
}

fn assert_inert_download(response: &Response) {
    assert_eq!(response.headers()["content-type"], "application/octet-stream");
    assert_eq!(response.headers()["content-disposition"], "attachment");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'none'"
    );
}

#[tokio::test]
#[ignore = "requires isolated relay + Postgres + Redis + MinIO"]
async fn arbitrary_formats_are_authenticated_opaque_downloads_with_safe_ranges() {
    let client = http_client();
    let keys = Keys::generate();

    // Auth remains mandatory even with the permissive content policy.
    let html = b"<!doctype html><script>window.neutralFixture=1</script>";
    let unauthenticated = client
        .put(format!("{}/upload", relay_http_url()))
        .header("Content-Type", "text/html")
        .header("X-SHA-256", hex::encode(Sha256::digest(html)))
        .body(html.to_vec())
        .send()
        .await
        .expect("unauthenticated request");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let fixtures: &[(&str, &str, &[u8])] = &[
        (
            "html",
            "image/svg+xml",
            b"<!doctype html><script>window.neutralFixture=1</script>",
        ),
        (
            "svg",
            "text/html",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script/></svg>",
        ),
        ("jsx", "text/javascript", b"export default () => null;"),
        ("exe", "application/x-msdownload", b"MZ\x90\x00neutral fixture"),
        ("elf", "application/x-executable", b"\x7fELF\x02\x01\x01neutral fixture"),
        (
            "macho",
            "application/x-mach-binary",
            b"\xcf\xfa\xed\xfe\x00\x00\x00\x00neutral fixture",
        ),
        ("zip", "application/zip", b"PK\x03\x04neutral zip fixture"),
        (
            "docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            b"PK\x03\x04word/document.xml neutral fixture",
        ),
        (
            "xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            b"PK\x03\x04xl/workbook.xml neutral fixture",
        ),
        ("pdf", "application/pdf", b"%PDF-1.7\nneutral fixture"),
        ("audio", "audio/mpeg", b"ID3\x04\x00\x00\x00\x00\x00\x00"),
        ("unknown", "application/x-private-format", b"\x00\x13\xff\x80arbitrary octets"),
        ("empty", "application/octet-stream", b""),
    ];

    for (name, declared_mime, bytes) in fixtures {
        let response = upload(&client, &keys, bytes, declared_mime).await;
        assert_eq!(response.status(), StatusCode::OK, "{name} upload");
        let descriptor: serde_json::Value = response.json().await.expect("descriptor JSON");
        let url = descriptor["url"].as_str().expect("descriptor URL");
        assert_eq!(descriptor["type"], "application/octet-stream", "{name}");
        assert_eq!(descriptor["size"], bytes.len() as u64, "{name}");
        assert!(url.contains(descriptor["sha256"].as_str().unwrap()), "{name} URL/hash");

        if *name == "html" {
            let other_tenant = client
                .get(url)
                .header("Host", "unbound.example.invalid")
                .send()
                .await
                .expect("cross-tenant request");
            assert_eq!(other_tenant.status(), StatusCode::NOT_FOUND);
        }

        let get = client.get(url).send().await.expect("download request");
        assert_eq!(get.status(), StatusCode::OK, "{name} GET");
        assert_inert_download(&get);
        assert_eq!(get.bytes().await.unwrap().as_ref(), *bytes, "{name} bytes");
    }

    // Range and HEAD responses must retain the same inert-download headers.
    let descriptor: serde_json::Value = upload(&client, &keys, html, "text/html")
        .await
        .json()
        .await
        .expect("idempotent descriptor");
    let url = descriptor["url"].as_str().unwrap();
    let range = client
        .get(url)
        .header("Range", "bytes=0-3")
        .send()
        .await
        .expect("range request");
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_inert_download(&range);
    assert_eq!(
        range.headers()["content-range"].to_str().unwrap(),
        format!("bytes 0-3/{}", html.len())
    );
    assert_eq!(range.bytes().await.unwrap().as_ref(), &html[..4]);

    let head = client.head(url).send().await.expect("HEAD request");
    assert_eq!(head.status(), StatusCode::OK);
    assert_inert_download(&head);

    // File limit remains active even with arbitrary formats enabled.
    let oversized = vec![b'x'; 65_537]; // CI sets BUZZ_MAX_FILE_BYTES=65,536.
    let response = upload(&client, &keys, &oversized, "application/octet-stream").await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
