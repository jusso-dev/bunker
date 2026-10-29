# Repository format fuzzing

Install `cargo-fuzz` and a nightly Rust toolchain, then run:

```sh
cargo +nightly fuzz run repository_format fuzz/seed-corpus -- -max_total_time=60 -max_len=16384
```

The target exercises encrypted-object authentication/truncation handling, the manifest deserializer, and cross-platform path validation. It does not establish cryptographic security, filesystem crash consistency, or cloud-provider correctness. Run the ordinary repository integration suite as well. Use a copied corpus outside the checkout for exploratory runs to avoid committing generated inputs.

If a platform's nightly sanitizer/linker cannot link the dependencies, use the Linux job in `.github/workflows/fuzz.yml` or build `fuzz/Dockerfile` with an explicitly selected Docker context. The container build runs the same bounded corpus and fails on a crash.
