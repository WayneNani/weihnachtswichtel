# syntax=docker/dockerfile:1.7
#
# Weihnachtswichtel – Container-Image (ein Binary, Web-UI und WASM eingebettet).
#
#   docker build -t wichtel .
#   docker run -d --name wichtel -p 127.0.0.1:8080:8080 -v wichtel-data:/data \
#     -e WICHTEL_PUBLIC_URL=https://wichteln.example.org \
#     -e WICHTEL_VAPID_SUBJECT=mailto:betrieb@example.org \
#     -e WICHTEL_TRUST_PROXY=1 wichtel
#
# Stufen: rust-base (Rust + wasm32 + wasm-bindgen-cli) → wasm (crates/wichtel-wasm → wasm-pkg)
#         → web (Node 22: web/dist) → server (cargo build --release, bettet web/dist ein)
#         → Laufzeit (debian-slim, non-root, nur das Binary). Betrieb: deploy/README.md.
#
# Rust ist auf die Toolchain gepinnt, mit der das Repo gebaut und getestet wird (rust-version im
# Workspace = 1.90 ist nur das Minimum). Für reproduzierbare Builds können die Basis-Images
# zusätzlich per Digest gepinnt werden (FROM …@sha256:…).

ARG RUST_VERSION=1.97.0
ARG NODE_VERSION=22.23.4
ARG DEBIAN_RELEASE=trixie

# ------------------------------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS rust-base
RUN rustup target add wasm32-unknown-unknown \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
# wasm-bindgen-cli muss exakt der Version von `wasm-bindgen` in Cargo.lock entsprechen
# (scripts/build-wasm.sh prüft das). Vorkompiliertes Binary statt `cargo install`.
COPY Cargo.lock /tmp/Cargo.lock
RUN set -eu; \
    v="$(grep -A1 '^name = "wasm-bindgen"$' /tmp/Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"; \
    arch="$(uname -m)"; \
    case "$arch" in x86_64|aarch64) ;; *) echo "keine wasm-bindgen-Binaries für $arch" >&2; exit 1 ;; esac; \
    name="wasm-bindgen-$v-$arch-unknown-linux-musl"; \
    curl -fsSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/$v/$name.tar.gz" \
      | tar -xz -C /tmp; \
    install -m 0755 "/tmp/$name/wasm-bindgen" /usr/local/bin/wasm-bindgen; \
    rm -rf "/tmp/$name" /tmp/Cargo.lock; \
    wasm-bindgen --version

# ------------------------------------------------------------------------------------------------
FROM rust-base AS wasm
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY scripts/build-wasm.sh scripts/build-wasm.sh
RUN --mount=type=cache,id=wichtel-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wichtel-target,target=/src/target \
    scripts/build-wasm.sh --out-dir /out/wasm-pkg

# ------------------------------------------------------------------------------------------------
FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,id=wichtel-npm,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY web/ ./
COPY --from=wasm /out/wasm-pkg src/wasm-pkg
RUN npm run build \
 && test -f dist/pkg/wichtel_wasm_bg.wasm

# ------------------------------------------------------------------------------------------------
FROM rust-base AS server
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
# rust-embed bettet web/dist zur Compile-Zeit in das Binary ein.
COPY --from=web /src/web/dist web/dist
RUN --mount=type=cache,id=wichtel-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wichtel-target,target=/src/target \
    cargo build --locked --release -p wichtel-server \
 && install -D -m 0755 target/release/wichtel-server /out/wichtel-server

# ------------------------------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime
# ca-certificates: Web-Push an die Push-Dienste der Browserhersteller (TLS, System-Zertifikate).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 wichtel \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin wichtel \
 && install -d -o 10001 -g 10001 -m 0700 /data
COPY --from=server /out/wichtel-server /usr/local/bin/wichtel-server

USER 10001:10001
WORKDIR /data
ENV WICHTEL_ADDR=0.0.0.0:8080 \
    WICHTEL_DB=/data/wichtel.db \
    RUST_LOG=info,turso=warn,turso_core=warn \
    NO_COLOR=1
# Datenbank (+ WAL) und der beim ersten Start erzeugte VAPID-Schlüssel liegen hier.
VOLUME ["/data"]
EXPOSE 8080

# Der Server beendet sich geordnet auf SIGINT (Ctrl-C); SIGTERM würde als PID 1 ignoriert.
STOPSIGNAL SIGINT

# Ohne curl/wget: HTTP-Anfrage über bash /dev/tcp an /api/health (Antwort-Body „ok“).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["bash", "-c", "p=\"${WICHTEL_PORT:-${WICHTEL_ADDR##*:}}\"; exec 3<>\"/dev/tcp/127.0.0.1/$p\" && printf 'GET /api/health HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && timeout 3 cat <&3 | grep -qx 'ok'"]

ENTRYPOINT ["/usr/local/bin/wichtel-server"]
