# Changelog

All notable changes to `vgi-tlsfp` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-29

Initial release.

### Added
- **JA3 / JA3S** (Salesforce, BSD-3) and **base JA4 TLS-client** (FoxIO, BSD-3,
  patent-disclaimed) fingerprints as pure SQL scalars under catalog `tlsfp`,
  schema `main`.
- Two input modes per fingerprint that share one implementation: raw handshake
  **bytes** (parsed by the worker) and already-extracted **parts**.
- Functions: `ja3`, `ja3_string`, `ja3_from_parts`, `ja3s`, `ja3s_from_parts`,
  `ja4`, `ja4_raw`, `ja4_from_parts`, `parse_client_hello`, `is_tls_handshake`,
  `tlsfp_version`.
- Pure, fuzzable `tlsfp-core` crate (no Arrow/VGI deps, forbids `unsafe`), kept
  physically free of any JA4+ / JARM code (enforced by tests).
- Golden vectors (Salesforce JA3 README strings; FoxIO canonical JA4 + JA4_r),
  bytes-vs-parts agreement tests, GREASE-stripping tests, and a proptest proving
  every entry point is total (no panic) over arbitrary bytes.
- haybarn sqllogictest E2E across the subprocess / http / unix transports, and a
  clean `vgi-lint` run at `--fail-on info` (100/100).

### Explicitly excluded (licensing / architecture)
- The **JA4+ suite** (JA4S / JA4H / JA4L / JA4X / JA4SSH — FoxIO License 1.1,
  patent-pending) and **JARM** (active-scan fingerprint). Not implemented.
