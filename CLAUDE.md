# CLAUDE.md — vgi-tlsfp

Guidance for working in this repo. `tlsfp` is a [VGI](https://query.farm) worker
that computes **TLS fingerprints (JA3, JA3S, base JA4 TLS-client)** as pure SQL
scalars over raw handshake bytes. It mirrors the conventions of the other Query
Farm Rust workers (`vgi-units`, `vgi-fixedformat`).

## ⛔ Licensing hard-stop (read first)

Ship **only the patent-free fingerprints**:
- **JA3 / JA3S** — Salesforce, BSD-3, reimplemented from the public spec.
- **base JA4 TLS-client** — FoxIO, BSD-3, patent-disclaimed for this fingerprint,
  reimplemented from the public spec.

**Do NOT implement the JA4+ suite — JA4S / JA4H / JA4L / JA4X / JA4SSH — (FoxIO
License 1.1, patent-pending) or JARM.** The `tlsfp-core` crate must stay
*physically free* of any JA4+ / JARM code. Two tests enforce this:
- `tlsfp-core` `licensing_scope_no_ja4plus_symbols` scans every core source file
  for forbidden identifiers (`ja4s`, `ja4h`, `ja4l`, `ja4x`, `ja4ssh`, `jarm`).
- `tlsfp-worker` `no_ja4plus_or_jarm_on_public_surface` asserts the registered
  SQL surface exposes no JA4+/JARM function and that the only `ja4*` names are
  exactly `ja4`, `ja4_raw`, `ja4_from_parts`.

If you add code, keep both green. Never vendor JA4+ reference code.

## Layout

```
crates/tlsfp-core/     pure engine (no Arrow/VGI deps; forbids unsafe)
  src/grease.rs        RFC 8701 GREASE detection
  src/parser.rs        bounds-checked ClientHello/ServerHello parser (total over arbitrary bytes)
  src/ja3.rs           JA3 / JA3S string + MD5 builders
  src/ja4.rs           base JA4 TLS-client (JA4_a/b/c, JA4_r) builders
  src/lib.rs           bytes-mode convenience API + licensing-scope test
  tests/fingerprint.rs golden vectors, bytes-vs-parts agreement, proptest no-panic
crates/tlsfp-worker/   Arrow adapters + VGI registration
  src/main.rs          catalog metadata + Worker wiring
  src/arrow_io.rs      BLOB/int/LIST readers + the parse_client_hello STRUCT schema
  src/meta.rs          per-object metadata helpers + sample-hex constants
  src/scalar/*.rs      one module per function family (version, guard, ja3, ja3s, ja4, decode)
  src/fixtures.rs      (test-only) canonical handshake byte fixtures
ci/                    haybarn integration runner + version check + require-rewrite awk
test/sql/              sqllogictest E2E suite
```

## Algorithm notes

- **GREASE** is stripped from cipher / extension / curve lists in every
  fingerprint. The `*_from_parts` functions call the *same* string builders as the
  bytes path, so the two modes can never disagree (asserted in tests).
- **JA3** uses the ClientHello `legacy_version` and keeps lists in **wire order**.
- **JA4** uses the **effective** TLS version (highest non-GREASE value from the
  `supported_versions` extension, else `legacy_version`) and **sorts** the cipher
  and extension lists before hashing (more robust than JA3). JA4_c removes SNI
  (`0x0000`) and ALPN (`0x0010`) from the hashed extension set but the JA4_a count
  still includes them; signature algorithms are appended in original order.
- **Per-row NULL safety:** the parser is total (returns `None` on any truncation);
  scalars map that to SQL `NULL`. The crate forbids `unsafe`, so arbitrary bytes
  can only ever yield a clean `None` (proptest-verified).

## Golden vectors

- JA3: the two Salesforce README string→MD5 vectors (`ada70206…`, `de350869…`).
- JA4: the FoxIO canonical example `t13d1516h2_8daaf6152771_e5627efa2ab1` and its
  published `ja4_r`, anchored both `from_parts` and end-to-end from a hand-built
  ClientHello fixture (`crates/tlsfp-worker/src/fixtures.rs`,
  `crates/tlsfp-core/tests/fingerprint.rs`).

## Gates (all must stay green)

```bash
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uvx --from vgi-lint-check vgi-lint lint "$PWD/target/release/tlsfp-worker" --fail-on info
# haybarn SQL E2E (per transport):
HAYBARN_UNITTEST=… WORKER_BIN="$PWD/target/release/tlsfp-worker" TRANSPORT=subprocess ci/run-integration.sh
```

vgi-lint executes the in-metadata example queries, so every `FunctionExample.sql`
and `vgi.executable_examples` entry must be **self-contained and bind** (use
`from_hex('…')` literals / list literals, not references to fictional tables).
Sample-handshake hex constants live in `src/meta.rs`.

## Dependencies / licensing

`md-5` + `sha2` (RustCrypto, MIT/Apache) for the digests; `proptest` (dev). No
copyleft, no patent exposure — provided the JA4+/JARM exclusion is honored. Worker
binary is **MIT** (fleet convention).
