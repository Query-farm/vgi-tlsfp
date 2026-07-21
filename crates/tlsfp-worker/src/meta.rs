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
/// grades: a `name`, the analyst-visible `prompt`, a deterministic canonical
/// `reference_sql`, and the two grading opt-outs (`unordered` compares row-sets
/// ignoring order; `ignore_column_names` compares by value only).
pub struct AgentTask<'a> {
    pub name: &'a str,
    pub prompt: &'a str,
    pub reference_sql: &'a str,
    pub unordered: bool,
    pub ignore_column_names: bool,
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
                "{{\"name\":\"{}\",\"prompt\":\"{}\",\"reference_sql\":\"{}\",\
                 \"unordered\":{},\"ignore_column_names\":{}}}",
                esc(t.name),
                esc(t.prompt),
                esc(t.reference_sql),
                t.unordered,
                t.ignore_column_names,
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
