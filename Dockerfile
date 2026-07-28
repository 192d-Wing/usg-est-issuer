FROM docker.io/library/rust:1.95-bookworm@sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb AS build
RUN apt-get update \
    && apt-get install --no-install-recommends --yes cmake golang-go \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:471dbca9cad607b9a32c10e9c31fb09ffaeb2d460e0afbff86c27abbc80b1b98
COPY --from=build /src/target/release/usg-est-issuer /usr/local/bin/usg-est-issuer
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/usg-est-issuer"]
