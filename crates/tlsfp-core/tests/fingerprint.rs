//! Integration tests over the public `tlsfp-core` API: an end-to-end golden
//! vector from real `ClientHello` bytes, bytes-vs-parts agreement, and a
//! proptest proving every entry point is total (no panic) on arbitrary input.

use proptest::prelude::*;
use tlsfp_core::ja3::ja3 as ja3_of;
use tlsfp_core::ja4::ja4 as ja4_of;
use tlsfp_core::{
    is_tls_handshake, ja3_bytes, ja3s_bytes, ja4_bytes, ja4_raw_bytes, parse_client_hello,
    parse_server_hello,
};

/// Build the FoxIO canonical-JA4 `ClientHello` as a bare handshake message. Its
/// sorted GREASE-free sets are exactly the published example, so it fingerprints
/// to `t13d1516h2_8daaf6152771_e5627efa2ab1`. (A leading GREASE cipher and a
/// GREASE extension exercise stripping on the bytes path.)
fn canonical_client_hello() -> Vec<u8> {
    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }
    fn u16s(vs: &[u16]) -> Vec<u8> {
        vs.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    let ciphers: Vec<u16> = {
        let mut c = vec![0x0a0au16];
        c.extend_from_slice(&[
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ]);
        c
    };

    let host = b"example.com";
    let mut sni = ((1 + 2 + host.len()) as u16).to_be_bytes().to_vec();
    sni.push(0x00);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host);

    let curves = [0x001du16, 0x0017, 0x0018, 0x0019];
    let mut sg = ((curves.len() * 2) as u16).to_be_bytes().to_vec();
    sg.extend_from_slice(&u16s(&curves));

    let sigs = [
        0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut sa = ((sigs.len() * 2) as u16).to_be_bytes().to_vec();
    sa.extend_from_slice(&u16s(&sigs));

    let alpn = vec![0x00, 0x03, 0x02, b'h', b'2'];
    let sv = vec![0x06u8, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03];

    let mut exts = Vec::new();
    exts.extend(ext(0x0000, &sni));
    exts.extend(ext(0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    exts.extend(ext(0x000a, &sg));
    exts.extend(ext(0x000b, &[0x01, 0x00]));
    exts.extend(ext(0x000d, &sa));
    exts.extend(ext(0x0010, &alpn));
    exts.extend(ext(0x0012, &[]));
    exts.extend(ext(0x0015, &[]));
    exts.extend(ext(0x0017, &[]));
    exts.extend(ext(0x001b, &[]));
    exts.extend(ext(0x1a1a, &[])); // GREASE
    exts.extend(ext(0x0023, &[]));
    exts.extend(ext(0x002b, &sv));
    exts.extend(ext(0x002d, &[0x01, 0x00]));
    exts.extend(ext(0x0033, &[]));
    exts.extend(ext(0x4469, &[]));
    exts.extend(ext(0xff01, &[0x00]));

    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x11; 32]);
    body.push(0x00);
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    body.extend_from_slice(&u16s(&ciphers));
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = vec![0x01u8];
    let n = body.len();
    msg.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    msg.extend_from_slice(&body);
    msg
}

#[test]
fn canonical_ja4_and_ja3_from_real_bytes() {
    let ch = canonical_client_hello();
    assert_eq!(
        ja4_bytes(&ch).unwrap(),
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
    // JA3 must parse to a 32-hex MD5.
    let ja3 = ja3_bytes(&ch).unwrap();
    assert_eq!(ja3.len(), 32);
    assert!(ja3.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(is_tls_handshake(&ch));
}

#[test]
fn bytes_and_parts_modes_agree() {
    let bytes = canonical_client_hello();
    let ch = parse_client_hello(&bytes).expect("parses");

    // JA3: recompute from the extracted component fields.
    let from_parts_ja3 = tlsfp_core::ja3::ja3_from_parts(
        ch.legacy_version,
        &ch.ciphers,
        &ch.extensions,
        &ch.curves,
        &ch.point_formats,
    );
    assert_eq!(from_parts_ja3, ja3_of(&ch));
    assert_eq!(from_parts_ja3, ja3_bytes(&bytes).unwrap());

    // JA4: the effective version (from supported_versions) is 0x0304; recompute
    // from parts and confirm it equals the bytes path.
    let alpn = ch.alpn.first().map(|s| s.as_str()).unwrap_or("");
    let from_parts_ja4 =
        tlsfp_core::ja4::ja4_from_parts(0x0304, &ch.ciphers, &ch.extensions, &ch.sig_algs, alpn);
    assert_eq!(from_parts_ja4, ja4_of(&ch));
    assert_eq!(from_parts_ja4, ja4_bytes(&bytes).unwrap());
}

proptest! {
    // Every parser/fingerprint entry point must be TOTAL over arbitrary bytes:
    // it may return None/Err but must never panic (the crate forbids `unsafe`,
    // so the worst case is a clean None).
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn no_panic_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = is_tls_handshake(&data);
        let _ = parse_client_hello(&data);
        let _ = parse_server_hello(&data);
        let _ = ja3_bytes(&data);
        let _ = ja3s_bytes(&data);
        let _ = ja4_bytes(&data);
        let _ = ja4_raw_bytes(&data);
    }

    // Fuzz with a valid handshake prefix so we exercise deeper parsing paths
    // (lengths, extension walking) rather than bailing at the type byte.
    #[test]
    fn no_panic_with_handshake_prefix(tail in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut data = vec![0x01u8, 0x00, 0x01, 0x00, 0x03, 0x03];
        data.extend_from_slice(&tail);
        let _ = parse_client_hello(&data);
        let _ = ja3_bytes(&data);
        let _ = ja4_bytes(&data);
        let mut sh = vec![0x02u8, 0x00, 0x01, 0x00, 0x03, 0x03];
        sh.extend_from_slice(&tail);
        let _ = parse_server_hello(&sh);
        let _ = ja3s_bytes(&sh);
    }
}
