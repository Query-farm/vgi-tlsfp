//! The `tlsfp` VGI worker.
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'tlsfp' (TYPE vgi, LOCATION '…')`). It computes **TLS client/server
//! fingerprints — JA3, JA3S, and the base JA4 (TLS-client)** — as pure SQL
//! scalars over raw `ClientHello`/`ServerHello` bytes (or already-extracted
//! fields), under the catalog `tlsfp`, schema `main`:
//!
//! ```sql
//! INSTALL vgi FROM community; LOAD vgi;
//! ATTACH 'tlsfp' (TYPE vgi, LOCATION './target/release/tlsfp-worker');
//! SET search_path = 'tlsfp.main';
//!
//! -- cluster suspect infrastructure by client fingerprint
//! SELECT ja3(client_hello) AS ja3, ja4(client_hello) AS ja4, count(*) n
//! FROM captured_handshakes GROUP BY 1,2 ORDER BY n DESC;
//!
//! -- compute from already-parsed fields (no raw bytes needed)
//! SELECT ja3_from_parts(771, ciphers, extensions, curves, point_formats) FROM zeek_ssl;
//! ```
//!
//! All fingerprint math lives in the pure, fuzzable `tlsfp-core` crate, which is
//! kept physically free of any JA4+ / JARM code (see the hard-stop in
//! `tlsfp-core`'s `lib.rs`); the `scalar/` modules are thin Arrow adapters.

mod arrow_io;
#[cfg(test)]
mod fixtures;
mod meta;
mod scalar;

use vgi::catalog::CatSchema;
use vgi::catalog::CatalogModel;
use vgi::Worker;

/// Worker version string, surfaced by `tlsfp_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The fixed analyst-task suite (`vgi.agent_test_tasks`) that `vgi-lint simulate`
/// grades. Every task is **self-contained and deterministic**: because the worker
/// exposes only pure scalars (no tables), each prompt supplies its input inline —
/// a hex `ClientHello`/`ServerHello` the analyst decodes with `from_hex(...)`, or
/// explicit list/scalar literals — so both the analyst's answer and the canonical
/// `reference_sql` run against the attached worker and compare exactly.
fn agent_test_tasks_value() -> String {
    use crate::meta::AgentTask;
    use crate::meta::SAMPLE_CLIENT_HELLO_HEX as CH;
    use crate::meta::SAMPLE_SERVER_HELLO_HEX as SH;
    crate::meta::agent_test_tasks_json(&[
        AgentTask {
            name: "ja4_of_clienthello",
            prompt: &format!(
                "I captured one TLS ClientHello; its raw bytes in hex are '{CH}'. Compute its \
                 base JA4 (TLS-client) fingerprint. Return one row with a single column named \
                 ja4."
            ),
            reference_sql: &format!("SELECT tlsfp.main.ja4(from_hex('{CH}')) AS ja4"),
            unordered: false,
            ignore_column_names: true,
        },
        AgentTask {
            name: "ja3_from_extracted_fields",
            prompt: "A Zeek ssl.log row already exposes these parsed ClientHello fields: legacy \
                     version 771, offered cipher suites [4865,4866,4867,49195,49199], extensions \
                     [0,11,10,13], elliptic curves [29,23,24], and EC point formats [0]. Compute \
                     the JA3 fingerprint from those fields (no raw bytes). Return one row with a \
                     single column named ja3.",
            reference_sql: "SELECT tlsfp.main.ja3_from_parts(771, [4865,4866,4867,49195,49199], \
                            [0,11,10,13], [29,23,24], [0]) AS ja3",
            unordered: false,
            ignore_column_names: true,
        },
        AgentTask {
            name: "guard_then_ja3",
            prompt: &format!(
                "I have one captured record whose raw bytes in hex are '{CH}'. First confirm the \
                 bytes really are a TLS handshake, and also compute their JA3 fingerprint. Return \
                 one row with exactly two columns, in this order: is_handshake (the boolean guard \
                 result) then ja3 (the fingerprint)."
            ),
            reference_sql: &format!(
                "SELECT tlsfp.main.is_tls_handshake(from_hex('{CH}')) AS is_handshake, \
                 tlsfp.main.ja3(from_hex('{CH}')) AS ja3"
            ),
            unordered: false,
            ignore_column_names: true,
        },
        AgentTask {
            name: "ja3s_of_serverhello",
            prompt: &format!(
                "I captured one TLS ServerHello; its raw bytes in hex are '{SH}'. Compute its \
                 JA3S (server) fingerprint. Return one row with a single column named ja3s."
            ),
            reference_sql: &format!("SELECT tlsfp.main.ja3s(from_hex('{SH}')) AS ja3s"),
            unordered: false,
            ignore_column_names: true,
        },
        AgentTask {
            name: "worker_version",
            prompt: "What version of the tlsfp worker is currently running? Return a single row \
                     with one column named version.",
            reference_sql: "SELECT tlsfp.main.tlsfp_version() AS version",
            unordered: false,
            ignore_column_names: true,
        },
    ])
}

/// Catalog + schema metadata (description, provenance, discovery tags) surfaced
/// to DuckDB and the `vgi-lint` metadata-quality linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "TLS client/server fingerprinting (JA3, JA3S, JA4 TLS-client) as pure SQL scalars \
             over raw handshake bytes."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "TLS Fingerprinting (JA3 / JA3S / JA4)".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "tls, fingerprint, ja3, ja3s, ja4, clienthello, serverhello, threat hunting, \
                     network security, c2, malware, bot detection, soc, dfir, clustering",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Compute TLS fingerprints — JA3 and JA3S (Salesforce) and the base JA4 TLS-client \
                 (FoxIO) — directly in SQL from raw ClientHello/ServerHello bytes or already-\
                 extracted fields. Use it to cluster suspicious client/server infrastructure by \
                 fingerprint and JOIN those hashes to certificate and flow data for threat \
                 hunting. Only the patent-free fingerprints are provided (no JA4+ suite, no JARM)."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# tlsfp — TLS Client/Server Fingerprinting in SQL\n\n\
                 **Compute JA3, JA3S, and the base JA4 (TLS-client) fingerprints directly in \
                 DuckDB SQL** from raw `ClientHello`/`ServerHello` bytes — or from fields you \
                 already extracted with Zeek/pcap tooling. Apply a fingerprint to a column of \
                 captured handshakes and `GROUP BY` it to surface a C2 or bot family, then JOIN \
                 the resulting VARCHAR hashes to certificate (`vgi-x509`) and flow (`vgi-netflow`) \
                 data to pivot from a fingerprint to the certs and flows behind it.\n\n\
                 Every function is pure, deterministic compute — no network, no state. Each \
                 fingerprint offers two input modes: pass the **raw handshake record** (the worker \
                 parses it) or the **component fields**. Malformed or truncated bytes return \
                 `NULL` per row rather than failing the query, and an `is_tls_handshake(bytes)` \
                 guard scalar lets you filter first. The `*_string`/`*_raw` companions expose the \
                 pre-hash JA3 string and the un-hashed JA4_r form for audit and custom re-hashing, \
                 and `parse_client_hello` decodes the handshake into a struct of its fields.\n\n\
                 **Licensing:** only the patent-free fingerprints are implemented — JA3/JA3S \
                 (BSD-3) and base JA4 TLS-client (BSD-3, patent-disclaimed). The JA4+ suite \
                 (JA4S/JA4H/JA4L/JA4X/JA4SSH, FoxIO License 1.1, patent-pending) and JARM are \
                 intentionally NOT implemented. The `tlsfp` worker is part of the \
                 [Query.Farm](https://query.farm) VGI ecosystem of DuckDB workers — see the \
                 [source repository](https://github.com/Query-farm/vgi-tlsfp)."
                    .to_string(),
            ),
            ("vgi.agent_test_tasks".to_string(), agent_test_tasks_value()),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-tlsfp/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-tlsfp/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-tlsfp".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "TLS fingerprint functions: ja3/ja3s/ja4 and their string/raw/from-parts \
                 companions, parse_client_hello, and the is_tls_handshake guard."
                    .to_string(),
            ),
            tags: vec![
                (
                    "vgi.title".to_string(),
                    "TLS Fingerprinting — main".to_string(),
                ),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "tls, ja3, ja3s, ja4, fingerprint, clienthello, serverhello, \
                         parse_client_hello, is_tls_handshake, threat hunting",
                    ),
                ),
                ("domain".to_string(), "network-security".to_string()),
                ("category".to_string(), "fingerprinting".to_string()),
                ("topic".to_string(), "tls-fingerprinting".to_string()),
                (
                    "vgi.categories".to_string(),
                    crate::meta::categories_json(&[
                        (
                            "JA3 / JA3S",
                            "Salesforce JA3 client and JA3S server fingerprints, computed from raw \
                             handshake bytes or already-extracted fields, plus the pre-hash JA3 \
                             string for audit.",
                        ),
                        (
                            "JA4",
                            "Base JA4 TLS-client fingerprints (FoxIO), computed from raw \
                             ClientHello bytes or extracted fields, plus the un-hashed JA4_r form \
                             for audit.",
                        ),
                        (
                            "Parsing & guards",
                            "Decode a ClientHello into its component fields and test whether raw \
                             bytes are a TLS handshake before fingerprinting.",
                        ),
                        (
                            "Worker",
                            "Worker introspection, such as the running worker version.",
                        ),
                    ]),
                ),
                (
                    "vgi.doc_llm".to_string(),
                    "TLS fingerprint functions: ja3/ja3_string/ja3_from_parts, \
                     ja3s/ja3s_from_parts, ja4/ja4_raw/ja4_from_parts, parse_client_hello, and \
                     the is_tls_handshake guard. Compute JA3/JA3S/JA4 over raw handshake bytes or \
                     extracted fields to cluster TLS infrastructure."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema (`main`) for the `tlsfp` worker — its whole surface of \
                     pure TLS-fingerprint scalars.\n\n\
                     Each fingerprint offers two input modes: pass the **raw handshake record** \
                     and let the worker parse it, or pass the **already-extracted fields** when a \
                     tool such as Zeek has parsed the handshake for you. Both modes share the same \
                     builders, so they always agree.\n\n\
                     The functions group into a few families:\n\n\
                     - **JA3 / JA3S** — Salesforce client and server fingerprints, with a pre-hash \
                     string companion for audit.\n\
                     - **JA4** — the base FoxIO TLS-client fingerprint, with its un-hashed raw \
                     form for audit.\n\
                     - **Parsing & guards** — decode a handshake into its component fields, and \
                     cheaply test whether raw bytes even look like a TLS handshake before \
                     fingerprinting.\n\n\
                     Everything is deterministic compute with no network or state, and malformed \
                     or truncated input yields `NULL` per row rather than failing the query."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT tlsfp.main.ja3(client_hello) AS ja3, tlsfp.main.ja4(client_hello) AS \
                     ja4, count(*) n FROM captured_handshakes GROUP BY 1,2 ORDER BY n DESC;\n\
                     SELECT tlsfp.main.ja3s(server_hello) FROM captured_handshakes;\n\
                     SELECT tlsfp.main.ja3_from_parts(771, ciphers, extensions, curves, \
                     point_formats) FROM zeek_ssl;\n\
                     SELECT tlsfp.main.parse_client_hello(client_hello).* FROM \
                     captured_handshakes;\n\
                     SELECT tlsfp.main.ja4(client_hello) FROM captured_handshakes WHERE \
                     tlsfp.main.is_tls_handshake(client_hello);"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            // Scalars only (per spec): the fingerprints are deterministic compute,
            // so the worker registers no table functions.
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'tlsfp' (TYPE vgi, …)`. Default to
    // `tlsfp`, but honor an override so a test harness can rename it.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "tlsfp");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "tlsfp".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
