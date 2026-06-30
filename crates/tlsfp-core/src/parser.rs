//! A minimal, allocation-light, **bounds-checked** TLS handshake parser for the
//! two messages the fingerprints need: `ClientHello` and `ServerHello`.
//!
//! Design goals:
//! - **Total over arbitrary bytes.** Every read goes through a bounds-checked
//!   cursor that returns `None` past the end of the buffer, so truncated or hostile input
//!   yields `None` (→ SQL `NULL`) rather than a panic. The crate forbids
//!   `unsafe`, so the worst case is always a clean `None`.
//! - **No TLS library dependency.** We only decode the handful of fields the
//!   fingerprints consume; we never validate certificates or crypto.
//!
//! ## Accepted framing
//!
//! Input may be either the raw **handshake message** (starting at the 1-byte
//! handshake type `0x01`/`0x02`) or a full **TLS record** (starting with content
//! type `0x16` + a 2-byte legacy version + 2-byte length). [`strip_record_header`]
//! transparently unwraps the latter. We intentionally do **not** reassemble
//! multi-record handshakes — a fingerprintable `ClientHello` fits in one record
//! in every real client.

/// TLS extension type codes the fingerprints care about.
mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
}

/// A decoded `ClientHello`, holding the raw fields (GREASE still present — the
/// fingerprint builders strip it). All lists preserve wire order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version` (the 2-byte version in the handshake body, e.g. `0x0303`).
    pub legacy_version: u16,
    /// Cipher suite code points, in wire order (GREASE included).
    pub ciphers: Vec<u16>,
    /// Extension type codes, in wire order (GREASE included).
    pub extensions: Vec<u16>,
    /// `supported_groups` (ext `0x000a`) named-group values (GREASE included).
    pub curves: Vec<u16>,
    /// `ec_point_formats` (ext `0x000b`) values.
    pub point_formats: Vec<u8>,
    /// `signature_algorithms` (ext `0x000d`) values, in wire order.
    pub sig_algs: Vec<u16>,
    /// `supported_versions` (ext `0x002b`) values, in wire order (GREASE included).
    pub supported_versions: Vec<u16>,
    /// First `host_name` from the SNI extension (ext `0x0000`), if present.
    pub sni: Option<String>,
    /// ALPN (ext `0x0010`) protocol identifiers, in wire order.
    pub alpn: Vec<String>,
}

/// A decoded `ServerHello` — the three fields JA3S consumes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// `legacy_version` (the 2-byte version in the handshake body).
    pub legacy_version: u16,
    /// The single cipher suite the server selected.
    pub cipher: u16,
    /// Extension type codes the server returned, in wire order (GREASE included).
    pub extensions: Vec<u16>,
}

/// A forward-only, bounds-checked cursor over a byte slice. Every accessor
/// returns `None` past the end, so a malformed length never reads out of bounds.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }

    /// Read a 3-byte big-endian length (TLS handshake bodies use 24-bit lengths).
    fn u24(&mut self) -> Option<usize> {
        let a = self.u8()? as usize;
        let b = self.u8()? as usize;
        let c = self.u8()? as usize;
        Some((a << 16) | (b << 8) | c)
    }

    /// Borrow the next `n` bytes, advancing the cursor, or `None` if short.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Skip a vector prefixed by a 1-byte length.
    fn skip_u8_vec(&mut self) -> Option<()> {
        let n = self.u8()? as usize;
        self.take(n).map(|_| ())
    }
}

/// If `data` begins with a TLS record header for the handshake content type
/// (`0x16`, major version `0x03`), return the record payload; otherwise return
/// `data` unchanged (it is assumed to already start at the handshake message).
pub fn strip_record_header(data: &[u8]) -> &[u8] {
    if data.len() >= 5 && data[0] == 0x16 && data[1] == 0x03 {
        let len = ((data[3] as usize) << 8) | (data[4] as usize);
        let end = 5usize.saturating_add(len).min(data.len());
        &data[5..end]
    } else {
        data
    }
}

/// Cheap structural check: does `data` look like a TLS `ClientHello`/`ServerHello`
/// handshake (optionally wrapped in a record), with a self-consistent length?
/// Never allocates; used by the `is_tls_handshake` guard scalar.
pub fn is_tls_handshake(data: &[u8]) -> bool {
    let hs = strip_record_header(data);
    if hs.len() < 4 {
        return false;
    }
    // Handshake type must be ClientHello (1) or ServerHello (2).
    if hs[0] != 0x01 && hs[0] != 0x02 {
        return false;
    }
    let len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    // Body must fit, the legacy version major byte must be 0x03 (SSL3/TLS1.x),
    // and the body must be large enough to hold version + random.
    len + 4 <= hs.len() && len >= 34 && hs.get(4) == Some(&0x03)
}

/// Parse a `ClientHello` (handshake message or full record). Returns `None` on
/// any truncation or type mismatch — total over arbitrary input.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    let hs = strip_record_header(data);
    let mut r = Reader::new(hs);

    if r.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let body_len = r.u24()?;
    // Constrain the rest of parsing to the declared body so a bogus extension
    // length can never read past the message.
    let body = r.take(body_len.min(r.remaining()))?;
    let mut r = Reader::new(body);

    let mut ch = ClientHello {
        legacy_version: r.u16()?,
        ..Default::default()
    };
    r.take(32)?; // random
    r.skip_u8_vec()?; // session_id

    // cipher_suites: 2-byte length, then u16 each.
    let cs_len = r.u16()? as usize;
    let cs = r.take(cs_len)?;
    let mut cr = Reader::new(cs);
    while cr.remaining() >= 2 {
        ch.ciphers.push(cr.u16()?);
    }

    r.skip_u8_vec()?; // compression_methods

    // Extensions are optional (absent in some legacy hellos).
    if r.remaining() >= 2 {
        let ext_total = r.u16()? as usize;
        let ext_buf = r.take(ext_total.min(r.remaining()))?;
        parse_extensions(ext_buf, &mut ch);
    }
    Some(ch)
}

/// Parse a `ServerHello` (handshake message or full record). Returns `None` on
/// truncation or type mismatch.
pub fn parse_server_hello(data: &[u8]) -> Option<ServerHello> {
    let hs = strip_record_header(data);
    let mut r = Reader::new(hs);

    if r.u8()? != 0x02 {
        return None; // not a ServerHello
    }
    let body_len = r.u24()?;
    let body = r.take(body_len.min(r.remaining()))?;
    let mut r = Reader::new(body);

    let mut sh = ServerHello {
        legacy_version: r.u16()?,
        ..Default::default()
    };
    r.take(32)?; // random
    r.skip_u8_vec()?; // session_id
    sh.cipher = r.u16()?;
    r.u8()?; // compression_method (single byte)

    if r.remaining() >= 2 {
        let ext_total = r.u16()? as usize;
        let ext_buf = r.take(ext_total.min(r.remaining()))?;
        let mut er = Reader::new(ext_buf);
        while er.remaining() >= 4 {
            let etype = er.u16()?;
            let elen = er.u16()? as usize;
            er.take(elen.min(er.remaining()))?;
            sh.extensions.push(etype);
        }
    }
    Some(sh)
}

/// Walk the extensions block of a `ClientHello`, recording each type code and
/// decoding the handful of extension bodies the fingerprints consume. A
/// malformed individual extension body is skipped rather than failing the whole
/// parse (best-effort, matching how real fingerprinters tolerate odd hellos).
fn parse_extensions(buf: &[u8], ch: &mut ClientHello) {
    let mut r = Reader::new(buf);
    while r.remaining() >= 4 {
        let etype = match r.u16() {
            Some(t) => t,
            None => break,
        };
        let elen = match r.u16() {
            Some(l) => l as usize,
            None => break,
        };
        let body = match r.take(elen.min(r.remaining())) {
            Some(b) => b,
            None => break,
        };
        ch.extensions.push(etype);
        match etype {
            ext::SERVER_NAME => ch.sni = parse_sni(body),
            ext::SUPPORTED_GROUPS => ch.curves = parse_u16_list_u16len(body),
            ext::EC_POINT_FORMATS => ch.point_formats = parse_u8_list_u8len(body),
            ext::SIGNATURE_ALGORITHMS => ch.sig_algs = parse_u16_list_u16len(body),
            ext::SUPPORTED_VERSIONS => ch.supported_versions = parse_u16_list_u8len(body),
            ext::ALPN => ch.alpn = parse_alpn(body),
            _ => {}
        }
    }
}

/// SNI body: `server_name_list<2>` of `(name_type<1>, name<2:bytes>)`. Returns
/// the first `host_name` (type 0) as a lossy-UTF-8 string.
fn parse_sni(body: &[u8]) -> Option<String> {
    let mut r = Reader::new(body);
    let list_len = r.u16()? as usize;
    let list = r.take(list_len.min(r.remaining()))?;
    let mut lr = Reader::new(list);
    while lr.remaining() >= 3 {
        let name_type = lr.u8()?;
        let name_len = lr.u16()? as usize;
        let name = lr.take(name_len)?;
        if name_type == 0 {
            return Some(String::from_utf8_lossy(name).into_owned());
        }
    }
    None
}

/// ALPN body: `protocol_name_list<2>` of `(len<1>, name)`.
fn parse_alpn(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut r = Reader::new(body);
    let list_len = match r.u16() {
        Some(n) => n as usize,
        None => return out,
    };
    let list = match r.take(list_len.min(r.remaining())) {
        Some(b) => b,
        None => return out,
    };
    let mut lr = Reader::new(list);
    while let Some(n) = lr.u8() {
        match lr.take(n as usize) {
            Some(name) => out.push(String::from_utf8_lossy(name).into_owned()),
            None => break,
        }
    }
    out
}

/// A `u16` vector prefixed by a 2-byte byte-length (e.g. `supported_groups`).
fn parse_u16_list_u16len(body: &[u8]) -> Vec<u16> {
    let mut r = Reader::new(body);
    let n = match r.u16() {
        Some(n) => n as usize,
        None => return Vec::new(),
    };
    let list = match r.take(n.min(r.remaining())) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while lr.remaining() >= 2 {
        if let Some(v) = lr.u16() {
            out.push(v);
        }
    }
    out
}

/// A `u16` vector prefixed by a 1-byte byte-length (e.g. `supported_versions`).
fn parse_u16_list_u8len(body: &[u8]) -> Vec<u16> {
    let mut r = Reader::new(body);
    let n = match r.u8() {
        Some(n) => n as usize,
        None => return Vec::new(),
    };
    let list = match r.take(n.min(r.remaining())) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while lr.remaining() >= 2 {
        if let Some(v) = lr.u16() {
            out.push(v);
        }
    }
    out
}

/// A `u8` vector prefixed by a 1-byte byte-length (e.g. `ec_point_formats`).
fn parse_u8_list_u8len(body: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(body);
    let n = match r.u8() {
        Some(n) => n as usize,
        None => return Vec::new(),
    };
    match r.take(n.min(r.remaining())) {
        Some(b) => b.to_vec(),
        None => Vec::new(),
    }
}
