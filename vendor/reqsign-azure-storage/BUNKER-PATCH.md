# Bunker certificate-provider feature patch

Source: Apache `reqsign-azure-storage` 3.3.0, crates.io archive SHA-256
`7260e6c1d89422ba62d624a32c491b561386fb364ac4bf0959c740e34b251a2e`.
Original Apache-2.0 LICENSE, NOTICE, source and tests are retained. Registry cache
metadata and the upstream archive lockfile are omitted.

Changes relative to that release:

- Add default-enabled `client-certificate` feature; make `pem`, `rsa`, and
  `reqsign-core/jwt` conditional on it in both manifests.
- Gate the client-certificate provider module, export, default-chain slot and
  builder methods behind that feature on non-Wasm targets.
- Gate associated integration-test imports and calls the same way.

Bunker and OpenDAL both disable this crate's default features and supply a
static-only credential chain. Consequently the vulnerable RSA implementation is
absent from Bunker's resolved build, rather than merely unreachable. No signing
algorithm or cryptographic implementation is modified. Re-enabling the feature
reintroduces the upstream dependency and its advisory; it is not supported here.

Validation: Bunker workspace check; four upstream static-provider unit tests with
`--no-default-features`; resolved-tree check that `rsa` is absent; root
`cargo audit --no-fetch` passed against 1,381 cached advisories on 2026-10-29.
An additional patched trust-root package (`webpki-root-certs` 1.0.11) was selected
in the root lockfile to resolve RUSTSEC-2026-0383. No audit ignore is configured.

Remove this local patch when an upstream release supplies equivalent optional
certificate credentials, then rerun static-chain tests and the dependency audit.
This patch has not been submitted upstream from this task.
