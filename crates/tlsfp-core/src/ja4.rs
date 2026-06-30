//! JA4 — the **base TLS-client** fingerprint (FoxIO, BSD-3, patent-disclaimed for
//! this specific fingerprint), reimplemented from the public spec
//! (<https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>).
//!
//! > **Licensing note (read `lib.rs`):** this module implements **only** the
//! > base JA4 TLS-client fingerprint. The JA4+ suite (JA4S/JA4H/JA4L/JA4X/JA4SSH)
//! > is **not** implemented anywhere in this crate.
//!
//! ## Format
//!
//! `ja4 = ja4_a + "_" + ja4_b + "_" + ja4_c`, where
//! - **JA4_a** = `(proto)(version)(sni)(cipher_count)(ext_count)(alpn)` —
//!   `t13d1516h2` for a TLS-1.3 TCP `ClientHello` with SNI, 15 ciphers, 16
//!   extensions, ALPN `h2`.
//! - **JA4_b** = first 12 hex of `SHA256` of the GREASE-stripped cipher list,
//!   **sorted** ascending, as 4-hex lowercase, comma-joined.
//! - **JA4_c** = first 12 hex of `SHA256` of the GREASE-stripped extension list
//!   (**sorted**, with SNI `0x0000` and ALPN `0x0010` removed), then `_`, then
//!   the signature-algorithm list **in original order**.
//!
//! [`ja4_raw`] returns the un-hashed form `ja4_a_<ciphers>_<exts>_<sigalgs>`.

use sha2::{Digest, Sha256};

use crate::grease::{is_grease, not_grease};
use crate::parser::ClientHello;

const SNI_EXT: u16 = 0x0000;
const ALPN_EXT: u16 = 0x0010;

/// Map a 2-byte TLS version code to JA4's 2-character label.
fn version_label(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// The effective TLS version JA4 reports: the highest non-GREASE value from the
/// `supported_versions` extension, or the `legacy_version` if that extension is
/// absent/empty.
fn effective_version(supported_versions: &[u16], legacy_version: u16) -> u16 {
    supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(legacy_version)
}

/// JA4 ALPN field: first + last alphanumeric character of the first ALPN value.
/// If either end byte is non-alphanumeric, use the first hex char of the first
/// byte and the last hex char of the last byte (FoxIO rule). `"00"` if no ALPN.
fn alpn_label(first_proto: Option<&[u8]>) -> String {
    let bytes = match first_proto {
        Some(b) if !b.is_empty() => b,
        _ => return "00".to_string(),
    };
    let f = bytes[0];
    let l = bytes[bytes.len() - 1];
    if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
        format!("{}{}", f as char, l as char)
    } else {
        let hf = format!("{f:02x}");
        let hl = format!("{l:02x}");
        format!("{}{}", &hf[0..1], &hl[1..2])
    }
}

/// Two-digit, zero-padded, 99-capped count.
fn count2(n: usize) -> String {
    format!("{:02}", n.min(99))
}

/// Lowercase 4-hex of a code point, e.g. `0x1301 → "1301"`.
fn hex4(v: u16) -> String {
    format!("{v:04x}")
}

fn sha256_12(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out.truncate(12);
    out
}

/// The component pieces JA4 needs, decoupled from byte parsing so the bytes path
/// and the parts path share one implementation.
struct Ja4Inputs<'a> {
    effective_version: u16,
    sni_present: bool,
    ciphers: &'a [u16],
    extensions: &'a [u16],
    sig_algs: &'a [u16],
    alpn_first: Option<&'a [u8]>,
}

impl Ja4Inputs<'_> {
    /// JA4_a, e.g. `t13d1516h2`. Protocol is fixed to `t` (TLS over TCP) — this
    /// worker fingerprints handshake bytes, not QUIC/DTLS transport framing.
    fn ja4_a(&self) -> String {
        let cipher_count = self.ciphers.iter().copied().filter(not_grease).count();
        let ext_count = self.extensions.iter().copied().filter(not_grease).count();
        format!(
            "t{}{}{}{}{}",
            version_label(self.effective_version),
            if self.sni_present { "d" } else { "i" },
            count2(cipher_count),
            count2(ext_count),
            alpn_label(self.alpn_first),
        )
    }

    /// The sorted, GREASE-stripped cipher list as 4-hex, comma-joined.
    fn sorted_ciphers_csv(&self) -> String {
        let mut v: Vec<u16> = self.ciphers.iter().copied().filter(not_grease).collect();
        v.sort_unstable();
        v.iter().map(|c| hex4(*c)).collect::<Vec<_>>().join(",")
    }

    /// The sorted, GREASE-stripped extension list (SNI + ALPN removed) as 4-hex.
    fn sorted_exts_csv(&self) -> String {
        let mut v: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(not_grease)
            .filter(|e| *e != SNI_EXT && *e != ALPN_EXT)
            .collect();
        v.sort_unstable();
        v.iter().map(|e| hex4(*e)).collect::<Vec<_>>().join(",")
    }

    /// The signature-algorithm list in original (wire) order, as 4-hex.
    fn sig_algs_csv(&self) -> String {
        self.sig_algs
            .iter()
            .copied()
            .filter(not_grease)
            .map(hex4)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn ja4_b(&self) -> String {
        let csv = self.sorted_ciphers_csv();
        if csv.is_empty() {
            return "000000000000".to_string();
        }
        sha256_12(&csv)
    }

    fn ja4_c(&self) -> String {
        let exts = self.sorted_exts_csv();
        let sigs = self.sig_algs_csv();
        if exts.is_empty() && sigs.is_empty() {
            return "000000000000".to_string();
        }
        sha256_12(&format!("{exts}_{sigs}"))
    }

    fn ja4(&self) -> String {
        format!("{}_{}_{}", self.ja4_a(), self.ja4_b(), self.ja4_c())
    }

    fn ja4_raw(&self) -> String {
        format!(
            "{}_{}_{}_{}",
            self.ja4_a(),
            self.sorted_ciphers_csv(),
            self.sorted_exts_csv(),
            self.sig_algs_csv(),
        )
    }
}

fn inputs_from_client_hello(ch: &ClientHello) -> Ja4Inputs<'_> {
    Ja4Inputs {
        effective_version: effective_version(&ch.supported_versions, ch.legacy_version),
        sni_present: ch.extensions.contains(&SNI_EXT),
        ciphers: &ch.ciphers,
        extensions: &ch.extensions,
        sig_algs: &ch.sig_algs,
        alpn_first: ch.alpn.first().map(|s| s.as_bytes()),
    }
}

/// JA4 hash for a parsed [`ClientHello`].
pub fn ja4(ch: &ClientHello) -> String {
    inputs_from_client_hello(ch).ja4()
}

/// JA4_r (raw, un-hashed) form for a parsed [`ClientHello`].
pub fn ja4_raw(ch: &ClientHello) -> String {
    inputs_from_client_hello(ch).ja4_raw()
}

/// JA4 from already-extracted component fields. `version` is the **effective**
/// TLS version (e.g. `0x0304` for TLS 1.3); SNI presence is inferred from whether
/// `extensions` contains `0x0000`; `alpn` is the first ALPN value (empty → none).
pub fn ja4_from_parts(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    sig_algs: &[u16],
    alpn: &str,
) -> String {
    let alpn_first = (!alpn.is_empty()).then_some(alpn.as_bytes());
    Ja4Inputs {
        effective_version: version,
        sni_present: extensions.contains(&SNI_EXT),
        ciphers,
        extensions,
        sig_algs,
        alpn_first,
    }
    .ja4()
}

/// JA4_r (raw) from component fields — the un-hashed companion to
/// [`ja4_from_parts`].
pub fn ja4_raw_from_parts(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    sig_algs: &[u16],
    alpn: &str,
) -> String {
    let alpn_first = (!alpn.is_empty()).then_some(alpn.as_bytes());
    Ja4Inputs {
        effective_version: version,
        sni_present: extensions.contains(&SNI_EXT),
        ciphers,
        extensions,
        sig_algs,
        alpn_first,
    }
    .ja4_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical FoxIO JA4 example. The ja4_r below is published verbatim in
    // the JA4 spec; the final fingerprint and its SHA-256 sub-hashes are pinned.
    const CANON_CIPHERS: &[u16] = &[
        0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
        0xc02f, 0xc030, 0xcca8, 0xcca9,
    ];
    // 16 extensions: SNI (0000) and ALPN (0010) included for the JA4_a count, but
    // removed from the sorted JA4_c list.
    const CANON_EXTS: &[u16] = &[
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023,
        0x002b, 0x002d, 0x0033, 0x4469, 0xff01,
    ];
    const CANON_SIGS: &[u16] = &[
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];

    #[test]
    fn canonical_ja4_from_parts() {
        let ja4 = ja4_from_parts(0x0304, CANON_CIPHERS, CANON_EXTS, CANON_SIGS, "h2");
        assert_eq!(ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn canonical_ja4_raw_matches_published_spec() {
        let raw = ja4_raw_from_parts(0x0304, CANON_CIPHERS, CANON_EXTS, CANON_SIGS, "h2");
        assert_eq!(
            raw,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_\
             0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
             0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn version_from_supported_versions_beats_legacy() {
        // legacy 0x0303 but supported_versions has 0x0304 → "13".
        assert_eq!(effective_version(&[0x0a0a, 0x0303, 0x0304], 0x0303), 0x0304);
        // grease-only → falls back to legacy.
        assert_eq!(effective_version(&[0x0a0a], 0x0301), 0x0301);
    }

    #[test]
    fn alpn_edge_cases() {
        assert_eq!(alpn_label(Some(b"h2")), "h2");
        assert_eq!(alpn_label(Some(b"http/1.1")), "h1"); // first 'h', last '1'
        assert_eq!(alpn_label(None), "00");
        assert_eq!(alpn_label(Some(b"")), "00");
    }

    #[test]
    fn no_ciphers_or_exts_uses_zero_hash() {
        let i = Ja4Inputs {
            effective_version: 0x0303,
            sni_present: false,
            ciphers: &[],
            extensions: &[],
            sig_algs: &[],
            alpn_first: None,
        };
        assert_eq!(i.ja4_b(), "000000000000");
        assert_eq!(i.ja4_c(), "000000000000");
    }
}
