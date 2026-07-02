//! `parse_client_hello(client_hello BLOB) -> STRUCT(version INT, sni VARCHAR,
//! ciphers INT[], extensions INT[], curves INT[], alpn VARCHAR[])`.
//!
//! A raw decode of the fingerprint-relevant ClientHello fields, for callers who
//! want the components without computing a hash. GREASE is **preserved** here
//! (this is a faithful decode, not a fingerprint); the `*_from_parts` functions
//! strip it. A row whose bytes do not parse yields a NULL struct.

use std::sync::Arc;

use arrow_array::builder::{Int32Builder, ListBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{blob_bytes, client_hello_struct_fields};

pub struct ParseClientHello;

fn list_int_builder() -> ListBuilder<Int32Builder> {
    ListBuilder::new(Int32Builder::new()).with_field(Arc::new(Field::new(
        "item",
        DataType::Int32,
        true,
    )))
}

fn list_str_builder() -> ListBuilder<StringBuilder> {
    ListBuilder::new(StringBuilder::new()).with_field(Arc::new(Field::new(
        "item",
        DataType::Utf8,
        true,
    )))
}

impl ScalarFunction for ParseClientHello {
    fn name(&self) -> &str {
        "parse_client_hello"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Decode a raw TLS ClientHello into STRUCT(version, sni, ciphers, \
                          extensions, curves, alpn); NULL struct if the bytes do not parse"
                .into(),
            return_type: Some(DataType::Struct(client_hello_struct_fields())),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT (tlsfp.main.parse_client_hello(from_hex('{}'))).sni;",
                    crate::meta::SAMPLE_CLIENT_HELLO_HEX
                ),
                description: "Decode the fingerprint-relevant fields of a ClientHello.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "ClientHello Decoder",
                "Decode a raw TLS ClientHello into a struct of its fingerprint-relevant fields: \
                 the legacy TLS version, the SNI host name (NULL if absent), the cipher-suite \
                 list, the extension-type list, the elliptic-curve (supported_groups) list, and \
                 the ALPN protocol list. This is a faithful decode that PRESERVES GREASE values \
                 (the ja3/ja4 functions strip them). Returns a NULL struct for bytes that do not \
                 parse as a ClientHello.",
                "Decode a ClientHello into STRUCT(version, sni, ciphers, extensions, curves, \
                 alpn), e.g. `parse_client_hello(client_hello).*`.",
                "parse, decode, clienthello, tls, sni, ciphers, extensions, curves, alpn, \
                 struct, inspect handshake",
                "Parsing & guards",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column_typed(
            "client_hello",
            0,
            DataType::Binary,
            "Raw TLS ClientHello bytes — a full TLS record (0x16…) or the bare handshake message \
             (0x01…). Malformed/truncated bytes yield a NULL struct.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(
            client_hello_struct_fields(),
        )))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        let mut version = Int32Builder::new();
        let mut sni = StringBuilder::new();
        let mut ciphers = list_int_builder();
        let mut extensions = list_int_builder();
        let mut curves = list_int_builder();
        let mut alpn = list_str_builder();
        let mut valid: Vec<bool> = Vec::with_capacity(rows);

        for i in 0..rows {
            let parsed = match blob_bytes(col, i)? {
                Some(bytes) => tlsfp_core::parse_client_hello(bytes),
                None => None,
            };
            match parsed {
                Some(ch) => {
                    version.append_value(ch.legacy_version as i32);
                    match &ch.sni {
                        Some(s) => sni.append_value(s),
                        None => sni.append_null(),
                    }
                    for c in &ch.ciphers {
                        ciphers.values().append_value(*c as i32);
                    }
                    ciphers.append(true);
                    for e in &ch.extensions {
                        extensions.values().append_value(*e as i32);
                    }
                    extensions.append(true);
                    for cu in &ch.curves {
                        curves.values().append_value(*cu as i32);
                    }
                    curves.append(true);
                    for a in &ch.alpn {
                        alpn.values().append_value(a);
                    }
                    alpn.append(true);
                    valid.push(true);
                }
                None => {
                    version.append_null();
                    sni.append_null();
                    ciphers.append(false);
                    extensions.append(false);
                    curves.append(false);
                    alpn.append(false);
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(version.finish()),
            Arc::new(sni.finish()),
            Arc::new(ciphers.finish()),
            Arc::new(extensions.finish()),
            Arc::new(curves.finish()),
            Arc::new(alpn.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            client_hello_struct_fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{blob_batch, process_params};
    use crate::fixtures::canonical_client_hello;
    use arrow_array::cast::AsArray;
    use arrow_array::types::Int32Type;
    use arrow_array::Array;
    use vgi::arguments::Arguments;

    fn run(rows: &[Option<&[u8]>]) -> ArrayRef {
        let batch = blob_batch(rows);
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            ..Default::default()
        };
        let bound = ParseClientHello.on_bind(&bind).unwrap();
        let params = process_params(bound.output_schema, Arguments::default());
        ParseClientHello
            .process(&params, &batch)
            .unwrap()
            .column(0)
            .clone()
    }

    #[test]
    fn decodes_canonical_fields_and_nulls() {
        let ch = canonical_client_hello();
        let out = run(&[Some(&ch), Some(b"junk"), None]);
        let s = out.as_struct();

        // Row 0: valid decode.
        assert!(!out.is_null(0));
        let version = s.column(0).as_primitive::<Int32Type>();
        assert_eq!(version.value(0), 771); // legacy_version preserved
        let sni = s.column(1).as_string::<i32>();
        assert_eq!(sni.value(0), "example.com");
        // Ciphers preserve GREASE (0x0a0a = 2570) as the first element.
        let ciphers = s.column(2).as_list::<i32>().value(0);
        let ciphers = ciphers.as_primitive::<Int32Type>();
        assert_eq!(ciphers.value(0), 0x0a0a);
        assert_eq!(ciphers.len(), 16);
        // ALPN list contains "h2".
        let alpn = s.column(5).as_list::<i32>().value(0);
        let alpn = alpn.as_string::<i32>();
        assert_eq!(alpn.value(0), "h2");

        // Rows 1 and 2: NULL struct.
        assert!(out.is_null(1), "unparseable bytes → NULL struct");
        assert!(out.is_null(2), "NULL input → NULL struct");
    }
}
