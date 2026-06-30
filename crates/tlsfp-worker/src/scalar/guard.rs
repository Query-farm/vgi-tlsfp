//! `is_tls_handshake(bytes BLOB) -> BOOLEAN` — a total guard scalar for filtering
//! a column down to plausible TLS `ClientHello`/`ServerHello` records before
//! fingerprinting. Never errors on bad bytes; NULL input → NULL.

use std::sync::Arc;

use arrow_array::builder::BooleanBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::blob_bytes;

pub struct IsTlsHandshake;

impl ScalarFunction for IsTlsHandshake {
    fn name(&self) -> &str {
        "is_tls_handshake"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Return TRUE if the bytes look like a TLS ClientHello/ServerHello \
                          handshake (optionally wrapped in a TLS record), else FALSE; NULL input \
                          → NULL"
                .into(),
            return_type: Some(DataType::Boolean),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT tlsfp.main.is_tls_handshake(from_hex('{}'));",
                    crate::meta::SAMPLE_CLIENT_HELLO_HEX
                ),
                description: "Filter a column to plausible TLS handshakes before fingerprinting."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "TLS Handshake Detector",
                "Return TRUE when the input bytes structurally resemble a TLS ClientHello or \
                 ServerHello handshake record (a valid handshake type and a self-consistent \
                 length), and FALSE otherwise. Totally safe on arbitrary bytes — it never errors \
                 — so it is the recommended WHERE-clause guard before calling ja3/ja3s/ja4. NULL \
                 input returns NULL.",
                "Guard scalar: TRUE iff `bytes` look like a TLS ClientHello/ServerHello, e.g. \
                 `WHERE is_tls_handshake(pkt)`.",
                "tls, handshake, clienthello, serverhello, guard, validate, is tls, filter, \
                 detect tls",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "bytes",
            0,
            DataType::Binary,
            "The raw bytes to test, e.g. a captured TLS record or handshake message. Returns TRUE \
             if they look like a ClientHello/ServerHello handshake.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut out = BooleanBuilder::new();
        for i in 0..batch.num_rows() {
            match blob_bytes(col, i)? {
                Some(bytes) => out.append_value(tlsfp_core::is_tls_handshake(bytes)),
                None => out.append_null(),
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
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    #[test]
    fn binds_boolean_and_classifies() {
        assert_eq!(bound_type(&IsTlsHandshake), DataType::Boolean);
        let ch = crate::fixtures::canonical_client_hello();
        let out = run_scalar_blob(
            &IsTlsHandshake,
            &[Some(&ch), Some(b"not a handshake"), Some(&[]), None],
        )
        .unwrap();
        let b = out.as_boolean();
        assert!(b.value(0), "canonical ClientHello is a handshake");
        assert!(!b.value(1));
        assert!(!b.value(2));
        assert!(out.is_null(3));
    }
}
