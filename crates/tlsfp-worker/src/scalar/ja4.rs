//! JA4 (base TLS-client) fingerprint scalars:
//! - `ja4(client_hello BLOB) -> VARCHAR` — the JA4 fingerprint, NULL if unparseable.
//! - `ja4_raw(client_hello BLOB) -> VARCHAR` — the un-hashed JA4_r form.
//! - `ja4_from_parts(version INT, ciphers INT[], extensions INT[], sig_algs INT[],
//!   alpn VARCHAR) -> VARCHAR`.
//!
//! Only the **base JA4 TLS-client** fingerprint is implemented; the JA4+ suite
//! (JA4S/JA4H/JA4L/JA4X/JA4SSH) is out of scope for licensing reasons.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{list_int_type, list_u16_at, text_str, u16_at};
use crate::scalar::blob_to_string_batch;

fn client_hello_arg() -> ArgSpec {
    ArgSpec::column_typed(
        "client_hello",
        0,
        DataType::Binary,
        "Raw TLS ClientHello bytes — a full TLS record (0x16…) or the bare handshake message \
         (0x01…). Malformed/truncated bytes yield NULL.",
    )
}

pub struct Ja4;

impl ScalarFunction for Ja4 {
    fn name(&self) -> &str {
        "ja4"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Compute the JA4 (base TLS-client) fingerprint of a raw TLS ClientHello; \
                          NULL if the bytes do not parse"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT tlsfp.main.ja4(from_hex('{}'));",
                    crate::meta::SAMPLE_CLIENT_HELLO_HEX
                ),
                description: "Compute the JA4 fingerprint of a captured ClientHello.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA4 Client Fingerprint",
                "Compute the JA4 base TLS-client fingerprint of a raw ClientHello, e.g. \
                 't13d1516h2_8daaf6152771_e5627efa2ab1'. JA4_a encodes the transport, TLS version, \
                 SNI presence, cipher/extension counts, and ALPN; JA4_b and JA4_c are truncated \
                 SHA-256 hashes of the sorted cipher and extension lists (GREASE stripped). More \
                 robust than JA3 because the inputs are sorted. Returns NULL for non-ClientHello \
                 bytes. (Only the base JA4 TLS-client fingerprint is provided — not the JA4+ suite.)",
                "JA4 TLS-client fingerprint of a raw ClientHello, e.g. `ja4(client_hello)` → \
                 't13d…_…_…'. NULL if unparseable.",
                "ja4, tls fingerprint, client fingerprint, clienthello, threat hunting, c2, \
                 bot detection, sha256, cluster, foxio",
                "JA4",
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
        blob_to_string_batch(params, batch, tlsfp_core::ja4_bytes)
    }
}

pub struct Ja4Raw;

impl ScalarFunction for Ja4Raw {
    fn name(&self) -> &str {
        "ja4_raw"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return the un-hashed JA4_r string \
                          (ja4_a_<ciphers>_<extensions>_<sig_algs>) of a raw ClientHello; NULL if \
                          it does not parse"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT tlsfp.main.ja4_raw(from_hex('{}'));",
                    crate::meta::SAMPLE_CLIENT_HELLO_HEX
                ),
                description: "Inspect the un-hashed JA4_r string for audit/debugging.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA4_r (raw, un-hashed)",
                "Return the raw JA4_r form of a ClientHello: the JA4_a prefix, then the sorted \
                 GREASE-stripped cipher list, the sorted extension list (SNI and ALPN removed), \
                 and the signature-algorithm list in original order — all as comma-separated \
                 4-hex values rather than hashed. Exposed for audit, debugging, and re-hashing \
                 under a custom policy. NULL when the bytes do not parse.",
                "Raw, un-hashed JA4_r string, e.g. `ja4_raw(client_hello)` → \
                 't13d1516h2_002f,0035,…_0005,000a,…_0403,0804,…'.",
                "ja4, ja4_r, raw, un-hashed, audit, debug, clienthello, cipher list, \
                 extension list, signature algorithms",
                "JA4",
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
        blob_to_string_batch(params, batch, tlsfp_core::ja4_raw_bytes)
    }
}

pub struct Ja4FromParts;

impl ScalarFunction for Ja4FromParts {
    fn name(&self) -> &str {
        "ja4_from_parts"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Compute the JA4 (base TLS-client) fingerprint from already-extracted \
                          ClientHello fields (effective TLS version, ciphers, extensions, \
                          signature algorithms, ALPN)"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT tlsfp.main.ja4_from_parts(772, [4865,4866], [0,43,13], [1027,2052], \
                      'h2');"
                    .into(),
                description: "Compute JA4 from fields already parsed by Zeek/pcap tooling.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA4 From Extracted Fields",
                "Compute the JA4 base TLS-client fingerprint from already-extracted ClientHello \
                 fields: the effective TLS version code (e.g. 772 for TLS 1.3), the cipher-suite \
                 list, the extension list (SNI presence is inferred from whether it contains \
                 0x0000=0), the signature-algorithm list (kept in order), and the first ALPN \
                 value (e.g. 'h2', empty string for none). GREASE is stripped exactly as in the \
                 bytes path so the two modes agree.",
                "JA4 from parsed fields, e.g. `ja4_from_parts(772, ciphers, extensions, sig_algs, \
                 'h2')`.",
                "ja4, from parts, zeek, ssl.log, precomputed fields, ja4 from fields, alpn, \
                 signature algorithms, sorted",
                "JA4",
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
                "The effective TLS version code point (the highest non-GREASE supported_versions \
                 value), e.g. 772 for TLS 1.3 or 771 for TLS 1.2.",
            ),
            ArgSpec::column_typed(
                "ciphers",
                1,
                list_int_type(),
                "The offered cipher-suite code points; GREASE is ignored and the list is sorted \
                 before hashing.",
            ),
            ArgSpec::column_typed(
                "extensions",
                2,
                list_int_type(),
                "The extension type code points; GREASE is ignored. Include 0 (SNI) to mark SNI \
                 present; SNI and ALPN are removed from the hashed set.",
            ),
            ArgSpec::column_typed(
                "sig_algs",
                3,
                list_int_type(),
                "The signature-algorithm code points, kept in original order in the JA4_c hash.",
            ),
            ArgSpec::column_typed(
                "alpn",
                4,
                DataType::Utf8,
                "The first ALPN protocol value, e.g. 'h2'; pass an empty string when no ALPN was \
                 offered.",
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
        let sig_algs = batch.column(3);
        let alpn = batch.column(4);
        let mut out = StringBuilder::new();
        for i in 0..batch.num_rows() {
            match (
                u16_at(version, i)?,
                list_u16_at(ciphers, i)?,
                list_u16_at(extensions, i)?,
                list_u16_at(sig_algs, i)?,
                text_str(alpn, i)?,
            ) {
                (Some(v), Some(c), Some(e), Some(s), Some(a)) => {
                    out.append_value(tlsfp_core::ja4::ja4_from_parts(v, &c, &e, &s, a))
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
    use crate::arrow_io::test_support::run_scalar_blob;
    use crate::fixtures::canonical_client_hello;
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    #[test]
    fn canonical_ja4_from_bytes() {
        // The independent golden anchor: our hand-built ClientHello must produce
        // the published FoxIO canonical fingerprint and JA4_r verbatim.
        let ch = canonical_client_hello();
        let ja4 = run_scalar_blob(&Ja4, &[Some(&ch)]).unwrap();
        assert_eq!(
            ja4.as_string::<i32>().value(0),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
        let raw = run_scalar_blob(&Ja4Raw, &[Some(&ch)]).unwrap();
        assert_eq!(
            raw.as_string::<i32>().value(0),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_\
             0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
             0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn ja4_bad_bytes_null() {
        let out = run_scalar_blob(&Ja4, &[Some(b"nope"), None]).unwrap();
        assert!(out.is_null(0));
        assert!(out.is_null(1));
    }
}
