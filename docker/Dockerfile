FROM rust:1.89.0-slim AS builder
WORKDIR /build
COPY . .
ARG BUILD_PROFILE=release
ARG BIN_MODE=indexer

RUN apt update && apt install -y git make libssl-dev pkg-config libpq-dev build-essential \
    && cargo build --profile $BUILD_PROFILE --bin $BIN_MODE --locked \
    && cp /build/target/$BUILD_PROFILE/$BIN_MODE /build/vectorx-$BIN_MODE

FROM ubuntu:22.04 AS run
WORKDIR /app
ARG BIN_MODE=indexer
ENV BIN_MODE_ENV=indexer

COPY --from=builder /build/vectorx-$BIN_MODE /usr/local/bin

RUN adduser --disabled-password --gecos "" --no-create-home --uid 1000 bridge \
    && apt-get update && apt-get install -y ca-certificates libpq-dev \
    && apt clean \
    && chown -R bridge:bridge /usr/local/bin/vectorx-$BIN_MODE

USER bridge

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["/usr/local/bin/vectorx-${BIN_MODE_ENV}"]
