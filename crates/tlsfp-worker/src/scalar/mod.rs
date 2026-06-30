//! Scalar functions exposed by the tlsfp worker, registered under `tlsfp.main`.
//!
//! All functions are pure, deterministic compute — no network, no state. The
//! fingerprint scalars come in two input modes that share `tlsfp-core`'s single
//! string/hash implementation: **bytes** (parse a raw handshake) and **parts**
//! (already-extracted fields). Malformed/truncated bytes return `NULL` per row.

mod decode;
mod guard;
mod ja3;
mod ja3s;
mod ja4;
mod version;

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use vgi::{ProcessParams, Worker};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::blob_bytes;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(version::TlsfpVersion);
    worker.register_scalar(guard::IsTlsHandshake);
    worker.register_scalar(ja3::Ja3);
    worker.register_scalar(ja3::Ja3String);
    worker.register_scalar(ja3::Ja3FromParts);
    worker.register_scalar(ja3s::Ja3s);
    worker.register_scalar(ja3s::Ja3sFromParts);
    worker.register_scalar(ja4::Ja4);
    worker.register_scalar(ja4::Ja4Raw);
    worker.register_scalar(ja4::Ja4FromParts);
    worker.register_scalar(decode::ParseClientHello);
}

/// The set of public scalar function names this worker exposes — the single
/// source of truth used both by registration documentation and by the
/// licensing-scope test (no JA4+ name may appear here).
#[cfg(test)]
pub fn registered_scalar_names() -> Vec<&'static str> {
    vec![
        "tlsfp_version",
        "is_tls_handshake",
        "ja3",
        "ja3_string",
        "ja3_from_parts",
        "ja3s",
        "ja3s_from_parts",
        "ja4",
        "ja4_raw",
        "ja4_from_parts",
        "parse_client_hello",
    ]
}

/// Shared `process` body for the BLOB→VARCHAR fingerprint scalars: read each
/// row's bytes (NULL → NULL), apply `f` (which returns `None` for handshake bytes
/// that do not parse → NULL), and build the VARCHAR output column.
pub(crate) fn blob_to_string_batch(
    params: &ProcessParams,
    batch: &RecordBatch,
    f: impl Fn(&[u8]) -> Option<String>,
) -> Result<RecordBatch> {
    let col = batch.column(0);
    let mut out = StringBuilder::new();
    for i in 0..batch.num_rows() {
        match blob_bytes(col, i)? {
            Some(bytes) => match f(bytes) {
                Some(s) => out.append_value(s),
                None => out.append_null(),
            },
            None => out.append_null(),
        }
    }
    let arr: ArrayRef = Arc::new(out.finish());
    RecordBatch::try_new(params.output_schema.clone(), vec![arr])
        .map_err(|e| RpcError::runtime_error(e.to_string()))
}

#[cfg(test)]
mod licensing_tests {
    use super::registered_scalar_names;

    /// No JA4+ (JA4S/JA4H/JA4L/JA4X/JA4SSH) or JARM function may be exposed on the
    /// SQL surface, and the only `ja4`-family names allowed are exactly the base
    /// JA4 TLS-client trio.
    #[test]
    fn no_ja4plus_or_jarm_on_public_surface() {
        let names = registered_scalar_names();
        let forbidden = ["ja4s", "ja4h", "ja4l", "ja4x", "ja4ssh", "jarm"];
        for n in &names {
            for bad in forbidden {
                assert_ne!(*n, bad, "JA4+/JARM function {bad:?} must not be registered");
                assert!(
                    !n.starts_with(bad),
                    "function {n:?} looks like a forbidden JA4+/JARM family member"
                );
            }
        }
        let ja4_family: Vec<_> = names.iter().filter(|n| n.starts_with("ja4")).collect();
        assert_eq!(
            ja4_family,
            vec![&"ja4", &"ja4_raw", &"ja4_from_parts"],
            "the only ja4-family scalars allowed are the base JA4 TLS-client trio"
        );
    }
}
