//! Shared helpers for the per-object discovery/description metadata the
//! `vgi-lint` strict profile expects on every function: `vgi.title` (VGI124),
//! `vgi.doc_llm` (VGI112), `vgi.doc_md` (VGI113), and `vgi.keywords`
//! (VGI126/VGI138). Per-object `vgi.source_url` is intentionally NOT emitted —
//! that tag belongs on the catalog object only (VGI139).

/// Hex of a canonical FoxIO-JA4 `ClientHello` (fingerprints to
/// `t13d1516h2_8daaf6152771_e5627efa2ab1`). Used to make the in-metadata example
/// queries self-contained and runnable (so the `vgi-lint` execution rules pass).
pub const SAMPLE_CLIENT_HELLO_HEX: &str = "010000cf0303111111111111111111111111111111111111111111\
11111111111111111111110000200a0a002f0035009c009d130113021303c013c014c02bc02cc02fc030cca8cca90100\
008600000010000e00000b6578616d706c652e636f6d000500050100000000000a000a0008001d001700180019000b0002\
0100000d0012001004030804040105030805050108060601001000050003026832001200000015000000170000001b0000\
1a1a000000230000002b0007060a0a03040303002d000201000033000044690000ff01000100";

/// Hex of a small `ServerHello` (selected cipher 0xc02f, extensions
/// renegotiation_info + ALPN). JA3S = `7bee5c1d424b7e5f943b06983bb11422`.
pub const SAMPLE_SERVER_HELLO_HEX: &str =
    "020000360303222222222222222222222222222222222222222222222222222222222222222200c02f00000eff0100\
0100001000050003026832";

/// The sample `ClientHello` with its SNI host changed from `example.com` to
/// `example.org` (same length, nothing else touched). JA3/JA4 hash only whether
/// SNI is present, not the host, so it fingerprints identically to
/// [`SAMPLE_CLIENT_HELLO_HEX`] — one client stack reaching two server names.
pub fn sample_client_hello_org_hex() -> String {
    SAMPLE_CLIENT_HELLO_HEX.replacen("2e636f6d", "2e6f7267", 1)
}

/// Composed example: pivot from a JA4 fingerprint to the server names it
/// reached (`is_tls_handshake` + `ja4` + `parse_client_hello`). Shown on the
/// schema list and on `ja4`'s own examples.
pub fn ja4_sni_pivot_example() -> (&'static str, String) {
    let ch = SAMPLE_CLIENT_HELLO_HEX;
    let org = sample_client_hello_org_hex();
    (
        "Pivot from a JA4 fingerprint to the server names it contacted: drop non-handshake rows \
         with is_tls_handshake, group the rest by ja4, and collect each fingerprint's distinct \
         SNI host names from parse_client_hello. Two ClientHellos from the same client stack \
         (to example.com and example.org) collapse to one JA4 with both names; the junk row is \
         dropped.",
        format!(
            "WITH h AS (SELECT pkt FROM (VALUES (from_hex('{ch}')), (from_hex('{org}')), \
             (from_hex('00'))) AS t(pkt) WHERE tlsfp.main.is_tls_handshake(pkt)) SELECT \
             tlsfp.main.ja4(pkt) AS ja4, count(*) AS handshakes, \
             list_sort(list(DISTINCT (tlsfp.main.parse_client_hello(pkt)).sni)) AS server_names \
             FROM h GROUP BY 1 ORDER BY handshakes DESC, ja4"
        ),
    )
}

/// Composed example: fingerprint both sides of each session and count sessions
/// per JA3/JA3S pair (`ja3` + `ja3s`). Shown on the schema list and on `ja3s`.
pub fn ja3_ja3s_pair_example() -> (&'static str, String) {
    let ch = SAMPLE_CLIENT_HELLO_HEX;
    let org = sample_client_hello_org_hex();
    let sh = SAMPLE_SERVER_HELLO_HEX;
    (
        "Profile TLS sessions by their JA3/JA3S client-server pair (the classic C2-detection \
         pairing): fingerprint the ClientHello with ja3 and the ServerHello with ja3s for each \
         captured session, then count sessions per pair.",
        format!(
            "SELECT tlsfp.main.ja3(s.client_hello) AS ja3, tlsfp.main.ja3s(s.server_hello) AS \
             ja3s, count(*) AS sessions FROM (VALUES (1, from_hex('{ch}'), from_hex('{sh}')), \
             (2, from_hex('{org}'), from_hex('{sh}'))) AS s(session_id, client_hello, \
             server_hello) GROUP BY 1, 2 ORDER BY sessions DESC, ja3, ja3s"
        ),
    )
}

/// Composed example: audit a JA3 by showing its pre-hash string and checking the
/// fingerprint is the MD5 of it (`ja3_string` + `ja3`). Shown on the schema list
/// and on `ja3_string`.
pub fn ja3_audit_example() -> (&'static str, String) {
    let ch = SAMPLE_CLIENT_HELLO_HEX;
    (
        "Audit a JA3 fingerprint: show the pre-hash ja3_string next to ja3 and confirm the \
         fingerprint is exactly the MD5 of that string.",
        format!(
            "SELECT tlsfp.main.ja3_string(c.client_hello) AS ja3_string, \
             tlsfp.main.ja3(c.client_hello) AS ja3, md5(tlsfp.main.ja3_string(c.client_hello)) = \
             tlsfp.main.ja3(c.client_hello) AS hash_matches FROM (VALUES (from_hex('{ch}'))) AS \
             c(client_hello) ORDER BY ja3"
        ),
    )
}

/// Build a `vgi.example_queries` JSON value from `(description, sql)` pairs — the
/// described-example carrier VGI515 requires (the native `duckdb_functions()`
/// examples column drops descriptions, so every curated example is mirrored here
/// with its human-readable description). Same `[{"description","sql"}]` shape as
/// `executable_examples_json`.
pub fn example_queries_json(items: &[(&str, &str)]) -> String {
    executable_examples_json(items)
}

/// Build a `vgi.executable_examples` JSON value from `(description, sql)` pairs —
/// guaranteed-runnable, catalog-qualified queries (VGI509).
pub fn executable_examples_json(items: &[(&str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let objs: Vec<String> = items
        .iter()
        .map(|(d, sql)| {
            format!(
                "{{\"description\":\"{}\",\"sql\":\"{}\"}}",
                esc(d),
                esc(sql)
            )
        })
        .collect();
    format!("[{}]", objs.join(","))
}

/// Build the `vgi.categories` registry value: an ordered JSON array of
/// `{"name","description"}` objects (VGI413). Each object then names one of these
/// via its own `vgi.category` tag.
pub fn categories_json(items: &[(&str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let objs: Vec<String> = items
        .iter()
        .map(|(name, desc)| {
            format!(
                "{{\"name\":\"{}\",\"description\":\"{}\"}}",
                esc(name),
                esc(desc)
            )
        })
        .collect();
    format!("[{}]", objs.join(","))
}

/// Encode comma-separated keywords as the JSON array of strings `vgi.keywords`
/// requires (VGI138), e.g. `["ja3","ja4","tls"]`.
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// One analyst task for the `vgi.agent_test_tasks` suite that `vgi-lint simulate`
/// grades: a `name` and the analyst-visible `prompt`. The private graders (the
/// deterministic canonical `reference_sql` and the `unordered` /
/// `ignore_column_names` opt-outs) live in `vgi-agent-tests.yaml` at the repo
/// root, keyed by `name`, so the agent being graded never sees them (VGI416).
pub struct AgentTask<'a> {
    pub name: &'a str,
    pub prompt: &'a str,
}

/// Build the `vgi.agent_test_tasks` JSON value from a fixed suite of tasks.
pub fn agent_test_tasks_json(tasks: &[AgentTask]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\"}}",
                esc(t.name),
                esc(t.prompt)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the standard per-object discovery/description tags: `vgi.title`,
/// `vgi.doc_llm`, `vgi.doc_md`, `vgi.keywords`, and `vgi.category` (which must
/// name one of the schema's `vgi.categories`, VGI413).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        ("vgi.category".to_string(), category.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Every in-metadata example, agent-task prompt, and grader is built from
    /// these hex constants, so they must decode to real handshakes: a stray byte
    /// (as once crept into the ClientHello's 32-byte random) silently turns every
    /// example's fingerprint into NULL.
    #[test]
    fn sample_hex_constants_fingerprint_to_goldens() {
        let ch = unhex(SAMPLE_CLIENT_HELLO_HEX);
        assert_eq!(ch, crate::fixtures::canonical_client_hello());
        assert_eq!(
            tlsfp_core::ja4_bytes(&ch).as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1")
        );
        let org = unhex(&sample_client_hello_org_hex());
        assert_eq!(tlsfp_core::ja4_bytes(&org), tlsfp_core::ja4_bytes(&ch));
        assert_eq!(tlsfp_core::ja3_bytes(&org), tlsfp_core::ja3_bytes(&ch));
        assert_eq!(
            tlsfp_core::ja3s_bytes(&unhex(SAMPLE_SERVER_HELLO_HEX)).as_deref(),
            Some("7bee5c1d424b7e5f943b06983bb11422")
        );
    }

    #[test]
    fn org_sample_differs_only_in_sni_host() {
        let org = sample_client_hello_org_hex();
        assert_eq!(org.len(), SAMPLE_CLIENT_HELLO_HEX.len());
        assert_ne!(org, SAMPLE_CLIENT_HELLO_HEX);
        // "example.org" in hex replaces "example.com".
        assert!(org.contains("6578616d706c652e6f7267"));
        assert!(!org.contains("6578616d706c652e636f6d"));
    }
}
