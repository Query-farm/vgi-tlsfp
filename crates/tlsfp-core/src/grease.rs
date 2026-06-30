//! TLS GREASE detection (RFC 8701).
//!
//! GREASE ("Generate Random Extensions And Sustain Extensibility") reserves 16
//! cipher-suite / extension / named-group code points that clients sprinkle into
//! their `ClientHello` to keep the ecosystem tolerant of unknown values. They are
//! deliberately random per-connection, so **every** TLS fingerprint (JA3, JA3S,
//! JA4) strips them before hashing — otherwise the same client would fingerprint
//! differently on each handshake.
//!
//! The 16 reserved values are `0x0a0a, 0x1a1a, 0x2a2a, … 0xfafa`: both bytes are
//! equal and their low nibble is `0xa`.

/// Returns `true` if `v` is one of the 16 reserved GREASE code points (RFC 8701).
///
/// ```
/// # use tlsfp_core::grease::is_grease;
/// assert!(is_grease(0x0a0a));
/// assert!(is_grease(0xfafa));
/// assert!(!is_grease(0x1301)); // TLS_AES_128_GCM_SHA256
/// assert!(!is_grease(0x0a1a)); // bytes differ
/// ```
#[inline]
pub fn is_grease(v: u16) -> bool {
    let lo = (v & 0x00ff) as u8;
    let hi = (v >> 8) as u8;
    lo == hi && (lo & 0x0f) == 0x0a
}

/// Returns `true` if `v` is **not** a GREASE value (convenience for `.filter`).
#[inline]
pub fn not_grease(v: &u16) -> bool {
    !is_grease(*v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_sixteen_grease_values() {
        let greases = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
            0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ];
        for g in greases {
            assert!(is_grease(g), "{g:#06x} should be GREASE");
        }
        // Exactly 16 values in [0, 0xffff] are GREASE.
        let count = (0u32..=0xffff).filter(|v| is_grease(*v as u16)).count();
        assert_eq!(count, 16);
    }

    #[test]
    fn non_grease_examples() {
        for v in [0x0000u16, 0x1301, 0x002f, 0xc02f, 0x0a0b, 0x0b0a, 0xaaab] {
            assert!(!is_grease(v), "{v:#06x} should not be GREASE");
        }
    }
}
