# Coraza-SPOA sidecar for haproxy-manager.
#
# Layout: built from upstream source. main.go is at the repo root; CRS rules
# are bundled into the binary at build time (referenced as @owasp_crs/), so
# the CRS version is whatever ships with the pinned coraza-spoa tag.
#
# Pin: review the upstream CHANGELOG (https://github.com/corazawaf/coraza-spoa/releases)
# before bumping. New tags can ship newer CRS, which can introduce new rules
# whose IDs fall into the "enforce day-one" ranges in overrides.conf — verify
# those are still high-confidence before promoting a new tag to prod.

ARG CORAZA_SPOA_VERSION=v0.7.1

# golang:1.25 from the in-house mirror. The 2026-05-12 Cloudflare incident
# took out docker.io blob pulls TWICE in one day (first for python:3.12-slim,
# then for this image's golang:1.25), so both are mirrored at
# repo.anhonesthost.net via the .gitea/workflows/mirror-base-image.yaml
# weekly job.
FROM repo.anhonesthost.net/cloud-hosting-platform/golang:1.25 AS build
ARG CORAZA_SPOA_VERSION
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${CORAZA_SPOA_VERSION}" \
        https://github.com/corazawaf/coraza-spoa.git . \
    && go mod download \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/coraza-spoa .

# Catalog extractor: walks the bundled CRS at build time and emits
# rules-catalog.json so WHP's UI can render rule metadata without parsing
# .conf files at runtime. Uses the SAME coraza-coreruleset version pin as
# the coraza-spoa binary above (drift between the two would mislabel rules).
FROM repo.anhonesthost.net/cloud-hosting-platform/golang:1.25 AS catalog
WORKDIR /src
COPY catalog-extractor/ .
RUN go build -trimpath -o /out/catalog-extractor . \
    && /out/catalog-extractor > /out/rules-catalog.json

# Distroless runtime: no shell, no package manager, no /tmp by default —
# smallest attack surface for an exposed service. Audit log directory is
# bind-mounted; coraza-spoa writes to it via direct file I/O (no shell needed).
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="coraza-spoa-whp" \
      org.opencontainers.image.description="Coraza WAF SPOA agent configured for WHP haproxy-manager integration" \
      org.opencontainers.image.source="https://github.com/shadowdao/haproxy-manager-base" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/coraza-spoa /coraza-spoa
COPY config.yaml /etc/coraza-spoa/config.yaml
COPY overrides.conf /etc/coraza/overrides.conf
COPY pre-overrides.conf /etc/coraza/pre-overrides.conf
COPY local-overrides.conf /etc/coraza/local-overrides.conf
COPY host-exceptions/ /etc/coraza/host-exceptions/
COPY --from=catalog /out/rules-catalog.json /etc/coraza/rules-catalog.json

# Audit log directory — bind-mount /var/log/coraza:/var/log/coraza from host
# so logs persist across container restarts and AI Monitor can tail them.
# Distroless nonroot user has UID 65532; the host directory must be writable
# by that UID (install script will chown it appropriately).
VOLUME ["/var/log/coraza"]

# SPOE TCP port — bound on 0.0.0.0:9000 inside the container. The host-side
# port mapping is controlled by `docker run -p` (typically not exposed beyond
# the internal docker network, since haproxy-manager reaches it by container
# name on client-net).
EXPOSE 9000

ENTRYPOINT ["/coraza-spoa", "--config", "/etc/coraza-spoa/config.yaml"]
