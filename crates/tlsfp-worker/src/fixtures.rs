//! Test-only TLS handshake fixtures, shared across the scalar test modules.
//!
//! [`canonical_client_hello`] builds a `ClientHello` whose **sorted, GREASE-free**
//! cipher/extension/signature-algorithm sets are exactly the FoxIO canonical JA4
//! example, so it must fingerprint to `t13d1516h2_8daaf6152771_e5627efa2ab1` and
//! reproduce the published JA4_r verbatim — an independent, end-to-end check of
//! the byte parser. It deliberately injects GREASE (a GREASE cipher, a GREASE
//! extension, and a GREASE entry in `supported_versions`) to prove the stripping
//! works on the bytes path too.

/// A TLS extension: `type(2) | len(2) | body`.
fn ext(etype: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&etype.to_be_bytes());
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// `u16` values flattened big-endian.
fn u16s(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// The canonical-JA4 `ClientHello` as a bare handshake message (starts at `0x01`).
pub fn canonical_client_hello() -> Vec<u8> {
    // 15 canonical ciphers, with a leading GREASE value to exercise stripping.
    let ciphers: Vec<u16> = {
        let mut c = vec![0x0a0au16];
        c.extend_from_slice(&[
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ]);
        c
    };

    // SNI extension body for "example.com".
    let host = b"example.com";
    let mut sni_body = Vec::new();
    let entry_len = 1 + 2 + host.len(); // name_type + name_len + name
    sni_body.extend_from_slice(&(entry_len as u16).to_be_bytes()); // server_name_list len
    sni_body.push(0x00); // name_type = host_name
    sni_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(host);

    // supported_groups: 29,23,24,25 (u16-len prefixed list of u16).
    let curves = [0x001du16, 0x0017, 0x0018, 0x0019];
    let mut sg_body = Vec::new();
    sg_body.extend_from_slice(&((curves.len() * 2) as u16).to_be_bytes());
    sg_body.extend_from_slice(&u16s(&curves));

    // ec_point_formats: [0] (u8-len prefixed list of u8).
    let ecpf_body = vec![0x01u8, 0x00];

    // signature_algorithms: canonical 8 (u16-len prefixed list of u16).
    let sigs = [
        0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut sa_body = Vec::new();
    sa_body.extend_from_slice(&((sigs.len() * 2) as u16).to_be_bytes());
    sa_body.extend_from_slice(&u16s(&sigs));

    // ALPN: ["h2"] (u16-len prefixed list of (u8-len, bytes)).
    let alpn_body = {
        let proto = b"h2";
        let mut b = Vec::new();
        let inner_len = 1 + proto.len();
        b.extend_from_slice(&(inner_len as u16).to_be_bytes());
        b.push(proto.len() as u8);
        b.extend_from_slice(proto);
        b
    };

    // supported_versions: GREASE + 0x0304 (TLS 1.3) + 0x0303 (u8-len prefixed).
    let sv_body = {
        let versions = [0x0a0au16, 0x0304, 0x0303];
        let mut b = Vec::new();
        b.push((versions.len() * 2) as u8);
        b.extend_from_slice(&u16s(&versions));
        b
    };

    // Assemble the 16 canonical extensions + a GREASE extension (0x1a1a).
    let mut exts = Vec::new();
    exts.extend(ext(0x0000, &sni_body));
    exts.extend(ext(0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00])); // status_request
    exts.extend(ext(0x000a, &sg_body));
    exts.extend(ext(0x000b, &ecpf_body));
    exts.extend(ext(0x000d, &sa_body));
    exts.extend(ext(0x0010, &alpn_body));
    exts.extend(ext(0x0012, &[])); // signed_certificate_timestamp
    exts.extend(ext(0x0015, &[])); // padding
    exts.extend(ext(0x0017, &[])); // extended_master_secret
    exts.extend(ext(0x001b, &[])); // compress_certificate
    exts.extend(ext(0x1a1a, &[])); // GREASE extension (stripped from fingerprints)
    exts.extend(ext(0x0023, &[])); // session_ticket
    exts.extend(ext(0x002b, &sv_body)); // supported_versions
    exts.extend(ext(0x002d, &[0x01, 0x00])); // psk_key_exchange_modes
    exts.extend(ext(0x0033, &[])); // key_share
    exts.extend(ext(0x4469, &[])); // application_settings
    exts.extend(ext(0xff01, &[0x00])); // renegotiation_info

    // ClientHello body.
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0x00); // session_id length = 0
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes()); // cipher_suites len
    body.extend_from_slice(&u16s(&ciphers));
    body.push(0x01); // compression_methods length
    body.push(0x00); // null compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes()); // extensions length
    body.extend_from_slice(&exts);

    // Handshake header: type(1) + length(3).
    let mut msg = Vec::new();
    msg.push(0x01); // ClientHello
    let blen = body.len();
    msg.push((blen >> 16) as u8);
    msg.push((blen >> 8) as u8);
    msg.push(blen as u8);
    msg.extend_from_slice(&body);
    msg
}

/// Wrap a bare handshake message in a single TLS record header (`0x16`,
/// version, length) — used to verify the parser unwraps records.
pub fn wrap_record(handshake: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + handshake.len());
    v.push(0x16); // content type = handshake
    v.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
    v.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    v.extend_from_slice(handshake);
    v
}

/// A minimal `ServerHello` (bare handshake message) selecting cipher `0xc02f`
/// with extensions `renegotiation_info (0xff01)` and `ALPN (0x0010)`. JA3S string
/// is therefore `771,49199,65281-16`.
pub fn server_hello() -> Vec<u8> {
    let mut exts = Vec::new();
    exts.extend(ext(0xff01, &[0x00]));
    exts.extend(ext(0x0010, &[0x00, 0x03, 0x02, b'h', b'2']));

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version (771)
    body.extend_from_slice(&[0x22; 32]); // random
    body.push(0x00); // session_id length
    body.extend_from_slice(&0xc02fu16.to_be_bytes()); // selected cipher (49199)
    body.push(0x00); // compression method
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = Vec::new();
    msg.push(0x02); // ServerHello
    let blen = body.len();
    msg.push((blen >> 16) as u8);
    msg.push((blen >> 8) as u8);
    msg.push(blen as u8);
    msg.extend_from_slice(&body);
    msg
}
