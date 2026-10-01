# syntax=docker/dockerfile:1.7
#
# Builds UwUSync Server from source:
#
#   docker build -f docker/Dockerfile -t uwusync-server .
#
# CI uses docker/Dockerfile.release instead, with binaries it cross-compiled
# before, which is much faster for arm64. Both end in the same image.

FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY . .
# `--locked` so the image is built from the versions in Cargo.lock and not from
# whatever was published this morning. The cached target directory can hold an
# earlier build whose sources look unchanged to cargo, so the server's own
# sources are touched first; the registry cache of everything else stays.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    touch src/main.rs src/lib.rs \
 && cargo build --release --locked \
 && cp target/release/uwusync-server /usr/local/bin/uwusync-server

# Debian still has the tools distroless does not: make /data, owned by the user
# the server runs as.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS prep
COPY --from=build /usr/local/bin/uwusync-server /usr/local/bin/uwusync-server
# uwussh-server is its name from when it was UwUSSH Server, for a compose.yaml or a habit from then.
RUN chmod 755 /usr/local/bin/uwusync-server \
 && ln -s uwusync-server /usr/local/bin/uwussh-server \
 && install -d -o 10001 -g 10001 /data

# The runtime is distroless: glibc and not much else — no shell, no package
# manager, so a break-in has almost nothing to build on. Pinned by digest;
# cc-debian13 is trixie, so its glibc matches the build. The server opens one
# port above 1024 and writes one directory, so it needs no capability at all
# and no root.
FROM gcr.io/distroless/cc-debian13@sha256:159783207c2cd44c2aa5715961d13c8612368ac9bd450f887e3f08fc8ea461e3
COPY --from=prep /usr/local/bin/ /usr/local/bin/
COPY --from=prep --chown=10001:10001 /data /data
USER 10001:10001
ENV UWUSYNC_DATA=/data \
    UWUSYNC_LISTEN=0.0.0.0:8443 \
    HOME=/data
VOLUME /data
EXPOSE 8443
# No curl in here, so the server asks itself — over its own TLS, and only
# healthy when the other end holds this server's key.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["/usr/local/bin/uwusync-server", "health"]
ENTRYPOINT ["/usr/local/bin/uwusync-server"]
CMD ["serve"]
