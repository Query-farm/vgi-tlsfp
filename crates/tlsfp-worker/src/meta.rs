//! Shared helpers for the per-object discovery/description metadata the
//! `vgi-lint` strict profile expects on every function: `vgi.title` (VGI124),
//! `vgi.doc_llm` (VGI112), `vgi.doc_md` (VGI113), and `vgi.keywords`
//! (VGI126/VGI138). Per-object `vgi.source_url` is intentionally NOT emitted —
//! that tag belongs on the catalog object only (VGI139).

/// Hex of a canonical FoxIO-JA4 `ClientHello` (fingerprints to
/// `t13d1516h2_8daaf6152771_e5627efa2ab1`). Used to make the in-metadata example
/// queries self-contained and runnable (so the `vgi-lint` execution rules pass).
pub const SAMPLE_CLIENT_HELLO_HEX: &str = "010000cf0303111111111111111111111111111111111111111111\
1111111111111111111111110000200a0a002f0035009c009d130113021303c013c014c02bc02cc02fc030cca8cca90100\
008600000010000e00000b6578616d706c652e636f6d000500050100000000000a000a0008001d001700180019000b0002\
0100000d0012001004030804040105030805050108060601001000050003026832001200000015000000170000001b0000\
1a1a000000230000002b0007060a0a03040303002d000201000033000044690000ff01000100";

/// Hex of a small `ServerHello` (selected cipher 0xc02f, extensions
/// renegotiation_info + ALPN). JA3S = `7bee5c1d424b7e5f943b06983bb11422`.
pub const SAMPLE_SERVER_HELLO_HEX: &str =
    "020000360303222222222222222222222222222222222222222222222222222222222222222200c02f00000eff0100\
0100001000050003026832";

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

/// Build the `vgi.agent_test_tasks` JSON value: a fixed suite of analyst tasks
/// `vgi-lint simulate` runs. Each `(name, prompt, reference_sql)` triple becomes
/// a task object.
pub fn agent_test_tasks_json(tasks: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|(name, prompt, reference_sql)| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\",\"reference_sql\":\"{}\"}}",
                esc(name),
                esc(prompt),
                esc(reference_sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the four standard per-object discovery/description tags.
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
    ]
}
