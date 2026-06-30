//! JA3 client fingerprint scalars:
//! - `ja3(client_hello BLOB) -> VARCHAR` — MD5 hash (32 hex), NULL if unparseable.
//! - `ja3_string(client_hello BLOB) -> VARCHAR` — the pre-hash JA3 string.
//! - `ja3_from_parts(version INT, ciphers INT[], extensions INT[], curves INT[],
//!   point_formats INT[]) -> VARCHAR` — MD5 from already-extracted fields.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{list_int_type, list_u16_at, u16_at};
use crate::scalar::blob_to_string_batch;

/// Shared BLOB argument spec for the client-hello fingerprint scalars.
fn client_hello_arg() -> ArgSpec {
    ArgSpec::column_typed(
        "client_hello",
        0,
        DataType::Binary,
        "Raw TLS ClientHello bytes — either a full TLS record (starting 0x16…) or the bare \
         handshake message (starting 0x01…). Malformed/truncated bytes yield NULL.",
    )
}

pub struct Ja3;

impl ScalarFunction for Ja3 {
    fn name(&self) -> &str {
        "ja3"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description:
                "Compute the JA3 fingerprint (MD5, 32 hex) of a raw TLS ClientHello; NULL \
                          if the bytes do not parse"
                    .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT tlsfp.main.ja3(from_hex('{}'));",
                    crate::meta::SAMPLE_CLIENT_HELLO_HEX
                ),
                description: "Compute the JA3 fingerprint of a captured ClientHello.".into(),
                expected_output: None,
            }],
            tags: {
                let mut tags = crate::meta::object_tags(
                    "JA3 Client Fingerprint",
                    "Compute the JA3 TLS client fingerprint — the 32-hex MD5 of the ClientHello's \
                     version, cipher suites, extensions, elliptic curves, and EC point formats \
                     (GREASE stripped). Accepts a full TLS record or a bare handshake message; \
                     returns NULL for bytes that do not parse as a ClientHello. Use it to cluster \
                     client/bot/C2 infrastructure and to JOIN against threat-intel JA3 lists.",
                    "JA3 client fingerprint (MD5 hex) of a raw ClientHello, e.g. \
                     `ja3(client_hello)`. NULL if unparseable.",
                    "ja3, tls fingerprint, client fingerprint, clienthello, threat hunting, \
                     malware, c2, bot detection, md5, cluster",
                );
                tags.push((
                    "vgi.executable_examples".to_string(),
                    crate::meta::executable_examples_json(&[
                        (
                            "JA3 of a ClientHello (bytes mode).",
                            &format!(
                                "SELECT tlsfp.main.ja3(from_hex('{}')) AS ja3",
                                crate::meta::SAMPLE_CLIENT_HELLO_HEX
                            ),
                        ),
                        (
                            "JA3 from already-extracted fields (parts mode).",
                            "SELECT tlsfp.main.ja3_from_parts(771, [47,53,4865], [0,11,10], \
                             [29,23], [0]) AS ja3",
                        ),
                    ]),
                ));
                tags
            },
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![client_hello_arg()]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        blob_to_string_batch(params, batch, tlsfp_core::ja3_bytes)
    }
}

pub struct Ja3String;

impl ScalarFunction for Ja3String {
    fn name(&self) -> &str {
        "ja3_string"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return the pre-hash JA3 string \
                          (version,ciphers,extensions,curves,point_formats) of a raw ClientHello; \
                          NULL if it does not parse"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT tlsfp.main.ja3_string(from_hex('{}'));",
                    crate::meta::SAMPLE_CLIENT_HELLO_HEX
                ),
                description: "Inspect the un-hashed JA3 string for audit/debugging.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA3 String (pre-hash)",
                "Return the un-hashed JA3 string for a raw ClientHello: the decimal \
                 SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat fields \
                 (GREASE stripped) that JA3 hashes with MD5. Exposed for audit, debugging, and \
                 re-hashing under a custom policy. NULL when the bytes do not parse.",
                "Pre-hash JA3 string of a ClientHello, e.g. `ja3_string(client_hello)` → \
                 '771,4865-4866-…,0-23-…,29-23-…,0'.",
                "ja3, ja3 string, pre-hash, audit, debug, clienthello, raw fingerprint, \
                 cipher list, extension list",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![client_hello_arg()]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        blob_to_string_batch(params, batch, tlsfp_core::ja3_string_bytes)
    }
}

pub struct Ja3FromParts;

impl ScalarFunction for Ja3FromParts {
    fn name(&self) -> &str {
        "ja3_from_parts"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Compute the JA3 fingerprint (MD5, 32 hex) from already-extracted \
                          ClientHello fields (version, ciphers, extensions, curves, point_formats)"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT tlsfp.main.ja3_from_parts(771, [47,53,4865], [0,11,10], [29,23], \
                      [0]);"
                    .into(),
                description: "Compute JA3 from fields already parsed by Zeek/pcap tooling.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA3 From Extracted Fields",
                "Compute the JA3 fingerprint from the already-extracted ClientHello component \
                 fields — the TLS version, the cipher-suite list, the extension list, the \
                 elliptic-curve (supported_groups) list, and the EC point-format list — for \
                 callers who parsed the handshake elsewhere (e.g. Zeek's ssl.log). GREASE values \
                 are stripped exactly as in the bytes path, so the two modes always agree.",
                "JA3 from parsed fields, e.g. `ja3_from_parts(771, ciphers, extensions, curves, \
                 point_formats)`.",
                "ja3, from parts, zeek, ssl.log, precomputed fields, ja3 from fields, cipher list, \
                 extension list, curves",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::column_typed(
                "version",
                0,
                DataType::Int32,
                "The ClientHello legacy TLS version as a decimal integer, e.g. 771 for TLS 1.2.",
            ),
            ArgSpec::column_typed(
                "ciphers",
                1,
                list_int_type(),
                "The list of offered cipher-suite code points (INTEGER[]); GREASE values are \
                 ignored.",
            ),
            ArgSpec::column_typed(
                "extensions",
                2,
                list_int_type(),
                "The list of extension type code points (INTEGER[]); GREASE values are ignored.",
            ),
            ArgSpec::column_typed(
                "curves",
                3,
                list_int_type(),
                "The list of supported elliptic-curve / named-group code points (INTEGER[]).",
            ),
            ArgSpec::column_typed(
                "point_formats",
                4,
                list_int_type(),
                "The list of EC point-format code points (INTEGER[]), e.g. [0].",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let version = batch.column(0);
        let ciphers = batch.column(1);
        let extensions = batch.column(2);
        let curves = batch.column(3);
        let point_formats = batch.column(4);
        let mut out = StringBuilder::new();
        for i in 0..batch.num_rows() {
            // Any NULL operand → NULL result.
            match (
                u16_at(version, i)?,
                list_u16_at(ciphers, i)?,
                list_u16_at(extensions, i)?,
                list_u16_at(curves, i)?,
                list_u16_at(point_formats, i)?,
            ) {
                (Some(v), Some(c), Some(e), Some(cu), Some(pf)) => {
                    let pf_u8: Vec<u8> = pf.iter().map(|x| *x as u8).collect();
                    out.append_value(tlsfp_core::ja3::ja3_from_parts(v, &c, &e, &cu, &pf_u8));
                }
                _ => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, run_scalar_blob};
    use crate::fixtures::{canonical_client_hello, wrap_record};
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    #[test]
    fn ja3_string_and_hash_agree_and_strip_grease() {
        assert_eq!(bound_type(&Ja3), DataType::Utf8);
        let ch = canonical_client_hello();
        let s = run_scalar_blob(&Ja3String, &[Some(&ch)]).unwrap();
        let s = s.as_string::<i32>().value(0).to_string();
        // version 771; GREASE cipher 0x0a0a and GREASE ext 0x1a1a are gone.
        assert_eq!(
            s,
            "771,47-53-156-157-4865-4866-4867-49171-49172-49195-49196-49199-49200-52392-52393,\
             0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65281,29-23-24-25,0"
        );
        // ja3 == md5(ja3_string).
        let h = run_scalar_blob(&Ja3, &[Some(&ch)]).unwrap();
        let h = h.as_string::<i32>().value(0).to_string();
        let digest = md5_hex(&s);
        assert_eq!(h, digest);
    }

    #[test]
    fn record_wrapped_equals_bare() {
        let ch = canonical_client_hello();
        let wrapped = wrap_record(&ch);
        let a = run_scalar_blob(&Ja3, &[Some(&ch)]).unwrap();
        let b = run_scalar_blob(&Ja3, &[Some(&wrapped)]).unwrap();
        assert_eq!(a.as_string::<i32>().value(0), b.as_string::<i32>().value(0));
    }

    #[test]
    fn bad_bytes_yield_null() {
        let out = run_scalar_blob(&Ja3, &[Some(b"junk"), Some(&[]), None]).unwrap();
        assert!(out.is_null(0));
        assert!(out.is_null(1));
        assert!(out.is_null(2));
    }

    fn md5_hex(s: &str) -> String {
        use md5::{Digest, Md5};
        let d = Md5::digest(s.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect()
    }
}
