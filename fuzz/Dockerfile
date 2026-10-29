FROM rust:1.91-bookworm
WORKDIR /src
RUN rustup toolchain install nightly --profile minimal \
    && cargo install cargo-fuzz --locked --version 0.13.2
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
COPY fuzz ./fuzz
RUN cargo +nightly fuzz run repository_format fuzz/seed-corpus -- -max_total_time=30 -max_len=16384
