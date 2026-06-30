//! `tlsfp-core` — pure-compute TLS fingerprinting.
//!
//! A minimal `ClientHello`/`ServerHello` parser plus the **JA3**, **JA3S**, and
//! **base JA4 (TLS-client)** fingerprint builders. No Arrow, no VGI, no I/O, no
//! state — every entry point is a deterministic function of its input bytes (or
//! component fields), so it is trivially fuzzable and embeddable.
//!
//! # ⛔ Licensing scope — JA4+ is intentionally absent
//!
//! This crate implements **only** the patent-free fingerprints:
//! - **JA3 / JA3S** — Salesforce, BSD-3-Clause, reimplemented from the public
//!   spec.
//! - **JA4 (base TLS-client)** — FoxIO, BSD-3-Clause, patent-disclaimed for this
//!   specific fingerprint, reimplemented from the public spec.
//!
//! The **JA4+ suite — JA4S, JA4H, JA4L, JA4X, JA4SSH — is under the FoxIO License
//! 1.1 (patent-pending) and is NOT implemented here.** **JARM** (an active-scan
//! fingerprint) is likewise excluded by construction — it is not derivable from
//! `ClientHello`/`ServerHello` bytes. This crate is kept *physically free* of any
//! JA4+ / JARM code; see the `licensing_scope` test below, which fails the build
//! if a JA4+ identifier ever appears in the source.
//!
//! # Input modes
//!
//! Every fingerprint offers two paths that share one string/​hash implementation,
//! so they can never disagree:
//! - **bytes** — pass the raw handshake record (TLS record or bare handshake
//!   message); the crate parses it. Malformed bytes return `None` (→ SQL `NULL`).
//! - **parts** — pass the already-extracted fields (e.g. from Zeek's `ssl.log`).

pub mod grease;
pub mod ja3;
pub mod ja4;
pub mod parser;

pub use parser::{
    is_tls_handshake, parse_client_hello, parse_server_hello, ClientHello, ServerHello,
};

// ---- JA3 (bytes mode) ------------------------------------------------------

/// JA3 hash (MD5, 32 lowercase hex) of a raw `ClientHello`, or `None` if the
/// bytes do not parse as a `ClientHello`.
pub fn ja3_bytes(client_hello: &[u8]) -> Option<String> {
    parse_client_hello(client_hello).map(|ch| ja3::ja3(&ch))
}

/// Pre-hash JA3 string of a raw `ClientHello`, or `None` if it does not parse.
pub fn ja3_string_bytes(client_hello: &[u8]) -> Option<String> {
    parse_client_hello(client_hello).map(|ch| ja3::ja3_string(&ch))
}

// ---- JA3S (bytes mode) -----------------------------------------------------

/// JA3S hash (MD5, 32 lowercase hex) of a raw `ServerHello`, or `None` if the
/// bytes do not parse as a `ServerHello`.
pub fn ja3s_bytes(server_hello: &[u8]) -> Option<String> {
    parse_server_hello(server_hello).map(|sh| ja3::ja3s(&sh))
}

// ---- JA4 (bytes mode) ------------------------------------------------------

/// JA4 fingerprint of a raw `ClientHello`, or `None` if it does not parse.
pub fn ja4_bytes(client_hello: &[u8]) -> Option<String> {
    parse_client_hello(client_hello).map(|ch| ja4::ja4(&ch))
}

/// JA4_r (raw, un-hashed) form of a raw `ClientHello`, or `None` if it does not
/// parse.
pub fn ja4_raw_bytes(client_hello: &[u8]) -> Option<String> {
    parse_client_hello(client_hello).map(|ch| ja4::ja4_raw(&ch))
}

#[cfg(test)]
mod tests {
    /// Physical-licensing guard: assert no JA4+ / JARM identifier appears in any
    /// source file of this crate. JA4+ (JA4S/JA4H/JA4L/JA4X/JA4SSH, FoxIO License
    /// 1.1, patent-pending) and JARM must never be implemented here. We scan for
    /// the lowercase *identifier* spellings (how they would appear in code); the
    /// upper-case mentions in doc comments that explain the exclusion are allowed.
    #[test]
    fn licensing_scope_no_ja4plus_symbols() {
        // The algorithm/implementation modules. `lib.rs` is intentionally NOT
        // scanned: it lists the forbidden tokens *in this very test* so that the
        // guard can run at all.
        let sources = [
            ("grease.rs", include_str!("grease.rs")),
            ("parser.rs", include_str!("parser.rs")),
            ("ja3.rs", include_str!("ja3.rs")),
            ("ja4.rs", include_str!("ja4.rs")),
        ];
        let forbidden = ["ja4s", "ja4h", "ja4l", "ja4x", "ja4ssh", "jarm"];
        for (name, src) in sources {
            for token in forbidden {
                assert!(
                    !src.contains(token),
                    "forbidden JA4+/JARM identifier {token:?} found in {name} — this crate must \
                     stay physically free of JA4+ code"
                );
            }
        }
    }
}
