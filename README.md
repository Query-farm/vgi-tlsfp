<p align="center">
  <a href="https://query.farm"><img src="https://query.farm/logo.svg" alt="Query.Farm" height="60"></a>
</p>

# vgi-tlsfp — TLS Client/Server Fingerprinting in DuckDB SQL

**Compute JA3, JA3S, and the base JA4 (TLS-client) fingerprints directly in SQL**
over raw `ClientHello`/`ServerHello` bytes — or over fields you already extracted
with Zeek/pcap tooling. Apply a fingerprint to a column of captured handshakes and
`GROUP BY` it to surface a C2 or bot family, then JOIN the resulting VARCHAR hashes
to certificate ([`vgi-x509`](https://github.com/Query-farm)) and flow
([`vgi-netflow`](https://github.com/Query-farm)) data to pivot from a fingerprint
to the certs and flows behind it.

`tlsfp` is a [VGI](https://query.farm) worker: a standalone binary DuckDB launches
and talks to over Apache Arrow. Every function is **pure, deterministic compute —
no network, no state.** Malformed or truncated bytes return `NULL` per row rather
than failing the query.

> ### ⛔ Licensing scope
> This worker ships **only the patent-free fingerprints**: **JA3 / JA3S**
> (Salesforce, BSD-3) and **base JA4 TLS-client** (FoxIO, BSD-3, patent-disclaimed
> for this specific fingerprint), all reimplemented from the public specs. The
> **JA4+ suite — JA4S / JA4H / JA4L / JA4X / JA4SSH — is under the FoxIO License
> 1.1 (patent-pending) and is NOT implemented**, and **JARM** (an active-scan
> fingerprint) is excluded by construction. The pure-compute `tlsfp-core` crate is
> kept *physically free* of any JA4+ / JARM code, enforced by tests.

## Quick start

```sql
INSTALL vgi FROM community; LOAD vgi;
ATTACH 'tlsfp' (TYPE vgi, LOCATION '/path/to/tlsfp-worker');
SET search_path = 'tlsfp.main';

-- cluster suspect infrastructure by client fingerprint
SELECT ja3(client_hello) AS ja3, ja4(client_hello) AS ja4, count(*) n
FROM captured_handshakes GROUP BY 1, 2 ORDER BY n DESC;

-- compute from already-parsed fields (no raw bytes needed)
SELECT ja3_from_parts(771, ciphers, extensions, curves, point_formats) FROM zeek_ssl;
```

The `client_hello`/`server_hello` inputs are the raw TLS handshake record (e.g.
from Zeek's `ssl.log` raw field or a pcap reader) — either a full TLS record
(starting `0x16…`) or the bare handshake message (`0x01…` / `0x02…`). This is a
*fingerprint* primitive, not a packet-capture tool.

## Function reference (`tlsfp.main`)

| Function | Returns | Description |
| --- | --- | --- |
| `ja3(client_hello BLOB)` | `VARCHAR` | JA3 fingerprint (MD5, 32 hex) of a ClientHello. `NULL` if unparseable. |
| `ja3_string(client_hello BLOB)` | `VARCHAR` | The pre-hash JA3 string (for audit / custom re-hashing). |
| `ja3_from_parts(version INT, ciphers INT[], extensions INT[], curves INT[], point_formats INT[])` | `VARCHAR` | JA3 from already-extracted fields. |
| `ja3s(server_hello BLOB)` | `VARCHAR` | JA3S fingerprint (MD5) of a ServerHello. |
| `ja3s_from_parts(version INT, cipher INT, extensions INT[])` | `VARCHAR` | JA3S from already-extracted fields. |
| `ja4(client_hello BLOB)` | `VARCHAR` | JA4 base TLS-client fingerprint, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`. |
| `ja4_raw(client_hello BLOB)` | `VARCHAR` | The un-hashed JA4_r form. |
| `ja4_from_parts(version INT, ciphers INT[], extensions INT[], sig_algs INT[], alpn VARCHAR)` | `VARCHAR` | JA4 from already-extracted fields (`version` is the effective TLS version code, e.g. `772`). |
| `parse_client_hello(client_hello BLOB)` | `STRUCT(version INT, sni VARCHAR, ciphers INT[], extensions INT[], curves INT[], alpn VARCHAR[])` | Faithful decode of a ClientHello (GREASE preserved). |
| `is_tls_handshake(bytes BLOB)` | `BOOLEAN` | Total guard: does the input look like a TLS handshake? `NULL` input → `NULL`. |
| `tlsfp_version()` | `VARCHAR` | The running worker's version string. |

### Conventions

- **`*_string` / `*_raw` companions** expose the pre-hash JA3 string and the
  un-hashed JA4_r form, for audit/debugging and so you can re-hash with your own
  policy.
- **GREASE** values (RFC 8701) are stripped from every fingerprint; the two input
  modes (bytes vs parts) share one implementation and always agree.
- **Per-row safety:** malformed/truncated bytes return `NULL`, never an error that
  fails the scan. Filter with `is_tls_handshake(bytes)` first if you like.
- Outputs are plain VARCHAR hashes that JOIN to `vgi-x509` (server-cert
  fingerprints) and `vgi-netflow` (5-tuple) for threat-hunt pivots.

## Examples

```sql
-- JA4 of a captured handshake
SELECT ja4(client_hello) FROM captured_handshakes;

-- JA3S of the server side
SELECT ja3s(server_hello) FROM captured_handshakes;

-- guard then fingerprint (skip non-handshake rows)
SELECT ja3(client_hello) FROM captured_handshakes
WHERE is_tls_handshake(client_hello);

-- decode a ClientHello's fields
SELECT (parse_client_hello(client_hello)).sni,
       (parse_client_hello(client_hello)).ciphers
FROM captured_handshakes;

-- the two input modes agree
SELECT ja3(client_hello)
     = ja3_from_parts(771, ciphers, extensions, curves, point_formats)
FROM zeek_ssl;
```

## Build & test

```bash
cargo build --release            # produces target/release/tlsfp-worker
cargo test                       # unit + integration + proptest (no-panic fuzz)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

### SQL end-to-end (haybarn)

The `test/sql/*.test` sqllogictest suite runs against the real DuckDB `vgi`
extension over **every transport** (subprocess / http / unix). See
[`ci/README.md`](ci/README.md):

```bash
cargo build --release
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
WORKER_BIN="$PWD/target/release/tlsfp-worker" \
TRANSPORT=subprocess ci/run-integration.sh
```

### Metadata quality (vgi-lint)

```bash
uvx --from vgi-lint-check vgi-lint lint "$PWD/target/release/tlsfp-worker" --fail-on info
```

## Architecture

Two crates:

- **`tlsfp-core`** — the pure, fuzzable engine: a minimal bounds-checked
  `ClientHello`/`ServerHello` parser and the JA3/JA3S/JA4 string + hash builders.
  No Arrow, no VGI, no I/O. Forbids `unsafe`. **Contains no JA4+ / JARM code.**
- **`tlsfp-worker`** — thin Arrow adapters that register the scalars and serve
  them over VGI.

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Query Farm LLC. Part of the
[Query.Farm](https://query.farm) VGI ecosystem of DuckDB workers.
