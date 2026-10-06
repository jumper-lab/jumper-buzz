FROM ghcr.io/block/buzz@sha256:a2b59030b29242adb0783a05cbabd63f51518fdfe7b724845a68f77adab7e1f9
COPY --chmod=0755 buzz-relay /usr/local/bin/buzz-relay
