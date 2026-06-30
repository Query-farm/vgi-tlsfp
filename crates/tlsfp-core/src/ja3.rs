//! JA3 (TLS client) and JA3S (TLS server) fingerprints — Salesforce, BSD-3,
//! reimplemented from the public spec (<https://github.com/salesforce/ja3>).
//!
//! ## JA3 string
//!
//! `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`
//!
//! Each field is a `-`-joined list of **decimal** code points; the five fields
//! are joined by `,`. GREASE values (RFC 8701) are removed from the cipher,
//! extension, and elliptic-curve lists before joining. The JA3 hash is the MD5 of
//! that string, as 32 lowercase hex characters.
//!
//! ## JA3S string
//!
//! `SSLVersion,Cipher,SSLExtension` — the server-side analogue, where `Cipher` is
//! the single suite the server selected. Hash is likewise MD5.

use md5::{Digest, Md5};

use crate::grease::not_grease;
use crate::parser::{ClientHello, ServerHello};

/// Join a slice of integers with `-` after dropping GREASE values, e.g.
/// `[0x0a0a, 4865, 4866] → "4865-4866"`.
fn join_u16_no_grease(values: &[u16]) -> String {
    let mut s = String::new();
    for v in values.iter().copied().filter(not_grease) {
        if !s.is_empty() {
            s.push('-');
        }
        s.push_str(&v.to_string());
    }
    s
}

/// Join a slice of bytes with `-` (point formats have no GREASE values).
fn join_u8(values: &[u8]) -> String {
    let mut s = String::new();
    for v in values {
        if !s.is_empty() {
            s.push('-');
        }
        s.push_str(&v.to_string());
    }
    s
}

fn md5_hex(s: &str) -> String {
    let digest = Md5::digest(s.as_bytes());
    let mut out = String::with_capacity(32);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Build the **pre-hash** JA3 string from already-extracted component fields.
/// GREASE is stripped from `ciphers`, `extensions`, and `curves`. This is the one
/// place the JA3 string is assembled, so the bytes path and the parts path can
/// never disagree.
pub fn ja3_string_from_parts(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    point_formats: &[u8],
) -> String {
    format!(
        "{},{},{},{},{}",
        version,
        join_u16_no_grease(ciphers),
        join_u16_no_grease(extensions),
        join_u16_no_grease(curves),
        join_u8(point_formats),
    )
}

/// MD5 of [`ja3_string_from_parts`].
pub fn ja3_from_parts(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    point_formats: &[u8],
) -> String {
    md5_hex(&ja3_string_from_parts(
        version,
        ciphers,
        extensions,
        curves,
        point_formats,
    ))
}

/// Pre-hash JA3 string for a parsed [`ClientHello`].
pub fn ja3_string(ch: &ClientHello) -> String {
    ja3_string_from_parts(
        ch.legacy_version,
        &ch.ciphers,
        &ch.extensions,
        &ch.curves,
        &ch.point_formats,
    )
}

/// JA3 hash (MD5, 32 lowercase hex) for a parsed [`ClientHello`].
pub fn ja3(ch: &ClientHello) -> String {
    md5_hex(&ja3_string(ch))
}

/// Build the pre-hash JA3S string from component fields: `version,cipher,exts`.
pub fn ja3s_string_from_parts(version: u16, cipher: u16, extensions: &[u16]) -> String {
    format!("{},{},{}", version, cipher, join_u16_no_grease(extensions))
}

/// MD5 of [`ja3s_string_from_parts`].
pub fn ja3s_from_parts(version: u16, cipher: u16, extensions: &[u16]) -> String {
    md5_hex(&ja3s_string_from_parts(version, cipher, extensions))
}

/// Pre-hash JA3S string for a parsed [`ServerHello`].
pub fn ja3s_string(sh: &ServerHello) -> String {
    ja3s_string_from_parts(sh.legacy_version, sh.cipher, &sh.extensions)
}

/// JA3S hash (MD5, 32 lowercase hex) for a parsed [`ServerHello`].
pub fn ja3s(sh: &ServerHello) -> String {
    md5_hex(&ja3s_string(sh))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors published in the Salesforce JA3 README
    // (https://github.com/salesforce/ja3). These pin the MD5 + string-assembly
    // path independently of any byte parsing.
    #[test]
    fn ja3_readme_vector_1() {
        let s = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
        assert_eq!(md5_hex(s), "ada70206e40642a3e4461f35503241d5");
    }

    #[test]
    fn ja3_readme_vector_2_empty_fields() {
        let s = "769,4-5-10-9-100-98-3-6-19-18-99,,,";
        assert_eq!(md5_hex(s), "de350869b8c85de67a350c8d186f11e6");
    }

    #[test]
    fn from_parts_reproduces_readme_vector_1() {
        // Same logical inputs, assembled by the public from-parts API.
        let s = ja3_string_from_parts(
            769,
            &[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
            &[0, 10, 11],
            &[23, 24, 25],
            &[0],
        );
        assert_eq!(
            s,
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
        );
        assert_eq!(
            ja3_from_parts(
                769,
                &[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
                &[0, 10, 11],
                &[23, 24, 25],
                &[0],
            ),
            "ada70206e40642a3e4461f35503241d5"
        );
    }

    #[test]
    fn grease_is_stripped() {
        // GREASE 0x0a0a/0x1a1a in ciphers and extensions must vanish.
        let s = ja3_string_from_parts(
            771,
            &[0x0a0a, 4865, 0x1a1a, 4866],
            &[0x2a2a, 0, 10],
            &[0x3a3a, 23],
            &[0],
        );
        assert_eq!(s, "771,4865-4866,0-10,23,0");
    }

    #[test]
    fn ja3s_string_shape() {
        assert_eq!(
            ja3s_string_from_parts(771, 49199, &[0x0a0a, 65281, 16]),
            "771,49199,65281-16"
        );
    }
}
