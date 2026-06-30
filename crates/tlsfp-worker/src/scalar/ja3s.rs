//! JA3S server fingerprint scalars:
//! - `ja3s(server_hello BLOB) -> VARCHAR` — MD5 hash, NULL if unparseable.
//! - `ja3s_from_parts(version INT, cipher INT, extensions INT[]) -> VARCHAR`.

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

pub struct Ja3s;

impl ScalarFunction for Ja3s {
    fn name(&self) -> &str {
        "ja3s"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Compute the JA3S fingerprint (MD5, 32 hex) of a raw TLS ServerHello; \
                          NULL if the bytes do not parse"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT tlsfp.main.ja3s(from_hex('{}'));",
                    crate::meta::SAMPLE_SERVER_HELLO_HEX
                ),
                description: "Fingerprint the server side of a handshake with JA3S.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA3S Server Fingerprint",
                "Compute the JA3S TLS server fingerprint — the 32-hex MD5 of the ServerHello's \
                 version, the single selected cipher suite, and the server's extension list \
                 (GREASE stripped). Accepts a full TLS record or a bare handshake message; returns \
                 NULL for bytes that do not parse as a ServerHello. Paired with JA3, it captures \
                 how a server responds to a given client and helps cluster C2 servers.",
                "JA3S server fingerprint (MD5 hex) of a raw ServerHello, e.g. \
                 `ja3s(server_hello)`. NULL if unparseable.",
                "ja3s, server fingerprint, serverhello, tls fingerprint, c2, malware server, \
                 cluster, md5",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "server_hello",
            0,
            DataType::Binary,
            "Raw TLS ServerHello bytes — a full TLS record (0x16…) or the bare handshake message \
             (0x02…). Malformed/truncated bytes yield NULL.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        blob_to_string_batch(params, batch, tlsfp_core::ja3s_bytes)
    }
}

pub struct Ja3sFromParts;

impl ScalarFunction for Ja3sFromParts {
    fn name(&self) -> &str {
        "ja3s_from_parts"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Compute the JA3S fingerprint (MD5, 32 hex) from already-extracted \
                          ServerHello fields (version, selected cipher, extensions)"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT tlsfp.main.ja3s_from_parts(771, 49199, [65281, 16]);".into(),
                description: "Compute JA3S from fields already parsed by Zeek/pcap tooling.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "JA3S From Extracted Fields",
                "Compute the JA3S fingerprint from the already-extracted ServerHello fields — the \
                 TLS version, the single cipher suite the server selected, and the server's \
                 extension list — for callers who parsed the handshake elsewhere (e.g. Zeek). \
                 GREASE values in the extension list are stripped exactly as in the bytes path.",
                "JA3S from parsed fields, e.g. `ja3s_from_parts(771, 49199, extensions)`.",
                "ja3s, from parts, zeek, ssl.log, precomputed fields, server fingerprint, \
                 selected cipher, extension list",
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
                "The ServerHello TLS version as a decimal integer, e.g. 771 for TLS 1.2.",
            ),
            ArgSpec::column_typed(
                "cipher",
                1,
                DataType::Int32,
                "The single cipher-suite code point the server selected, e.g. 49199.",
            ),
            ArgSpec::column_typed(
                "extensions",
                2,
                list_int_type(),
                "The list of extension type code points the server returned (INTEGER[]); GREASE \
                 values are ignored.",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let version = batch.column(0);
        let cipher = batch.column(1);
        let extensions = batch.column(2);
        let mut out = StringBuilder::new();
        for i in 0..batch.num_rows() {
            match (
                u16_at(version, i)?,
                u16_at(cipher, i)?,
                list_u16_at(extensions, i)?,
            ) {
                (Some(v), Some(c), Some(e)) => {
                    out.append_value(tlsfp_core::ja3::ja3s_from_parts(v, c, &e))
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
    use crate::fixtures::{server_hello, wrap_record};
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    fn md5_hex(s: &str) -> String {
        use md5::{Digest, Md5};
        let d = Md5::digest(s.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn ja3s_bytes_matches_from_parts() {
        let sh = server_hello();
        let bytes = run_scalar_blob(&Ja3s, &[Some(&sh)]).unwrap();
        let bytes = bytes.as_string::<i32>().value(0).to_string();
        // JA3S string is "771,49199,65281-16"; verify the hash directly.
        assert_eq!(bytes, md5_hex("771,49199,65281-16"));
        // And record-wrapped is identical.
        let wrapped = run_scalar_blob(&Ja3s, &[Some(&wrap_record(&sh))]).unwrap();
        assert_eq!(bytes, wrapped.as_string::<i32>().value(0));
    }

    #[test]
    fn ja3s_bad_bytes_null() {
        let out = run_scalar_blob(&Ja3s, &[Some(b"x"), None]).unwrap();
        assert!(out.is_null(0));
        assert!(out.is_null(1));
    }
}
