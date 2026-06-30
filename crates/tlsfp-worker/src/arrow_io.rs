//! Small Arrow helpers shared across the scalar functions: reading BLOB, integer,
//! and `LIST(INTEGER)` input cells, plus the typed schemas the fingerprint
//! scalars publish (`LIST(INTEGER)` args and the `parse_client_hello` STRUCT).
//! The `#[cfg(test)]` harness drives a `ScalarFunction` end-to-end without the
//! RPC/IPC plumbing.

use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::{
    Int16Type, Int32Type, Int64Type, Int8Type, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
};
use arrow_array::{Array, ArrayRef};
use arrow_schema::{DataType, Field, Fields};
use vgi_rpc::{Result, RpcError};

/// Borrow the raw bytes of a BLOB (or VARCHAR) input cell at `row`, or `None` if
/// null. Errors if the column is neither binary nor string.
pub fn blob_bytes(col: &ArrayRef, row: usize) -> Result<Option<&[u8]>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row),
        DataType::LargeBinary => col.as_binary::<i64>().value(row),
        DataType::Utf8 => col.as_string::<i32>().value(row).as_bytes(),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row).as_bytes(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB argument, got {other:?}"
            )))
        }
    }))
}

/// Borrow the UTF-8 text of a VARCHAR cell at `row`, or `None` if null.
pub fn text_str(col: &ArrayRef, row: usize) -> Result<Option<&str>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Utf8 => col.as_string::<i32>().value(row),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a VARCHAR argument, got {other:?}"
            )))
        }
    }))
}

/// Read an integer cell at `row` as `u16` (TLS code points are 16-bit), accepting
/// any common integer width DuckDB may hand over; `None` if null. Out-of-range
/// values are masked to 16 bits.
pub fn u16_at(col: &ArrayRef, row: usize) -> Result<Option<u16>> {
    if col.is_null(row) {
        return Ok(None);
    }
    let v = int_value_i128(col, row).ok_or_else(|| {
        RpcError::value_error(format!(
            "expected an INTEGER argument, got {:?}",
            col.data_type()
        ))
    })?;
    Ok(Some((v as u64 & 0xffff) as u16))
}

/// Read row `row` of a `LIST(INTEGER)` column as `Vec<u16>`, or `None` if the
/// list cell is null. NULL elements become `0`. Errors if the column is not a
/// list.
pub fn list_u16_at(col: &ArrayRef, row: usize) -> Result<Option<Vec<u16>>> {
    let list = col.as_list_opt::<i32>().ok_or_else(|| {
        RpcError::value_error(format!(
            "expected a LIST(INTEGER) argument, got {:?}",
            col.data_type()
        ))
    })?;
    if !list.is_valid(row) {
        return Ok(None);
    }
    let values = list.value(row);
    let n = values.len();
    let out = (0..n)
        .map(|i| {
            int_value_i128(&values, i)
                .map(|v| (v as u64 & 0xffff) as u16)
                .unwrap_or(0)
        })
        .collect();
    Ok(Some(out))
}

/// Extract a signed `i128` from any common integer array element, or `None` if
/// the element is null or the array is not an integer type.
fn int_value_i128(arr: &ArrayRef, i: usize) -> Option<i128> {
    if !arr.is_valid(i) {
        return None;
    }
    macro_rules! try_t {
        ($t:ty) => {
            if let Some(a) = arr.as_primitive_opt::<$t>() {
                return Some(a.value(i) as i128);
            }
        };
    }
    try_t!(Int32Type);
    try_t!(Int64Type);
    try_t!(UInt32Type);
    try_t!(UInt64Type);
    try_t!(Int16Type);
    try_t!(UInt16Type);
    try_t!(Int8Type);
    try_t!(UInt8Type);
    None
}

/// The Arrow `DataType` of a `LIST(INTEGER)` argument/column (element field named
/// `item`, nullable) — used in both `argument_specs` and the `parse_client_hello`
/// STRUCT so bind and process agree exactly.
pub fn list_int_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Int32, true)))
}

/// The Arrow `DataType` of a `LIST(VARCHAR)` column (for `alpn`).
pub fn list_varchar_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

/// Fields of the `parse_client_hello` STRUCT output:
/// `STRUCT(version INT, sni VARCHAR, ciphers INT[], extensions INT[], curves
/// INT[], alpn VARCHAR[])`. Shared so `on_bind` and `process` never drift.
pub fn client_hello_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("version", DataType::Int32, true),
        Field::new("sni", DataType::Utf8, true),
        Field::new("ciphers", list_int_type(), true),
        Field::new("extensions", list_int_type(), true),
        Field::new("curves", list_int_type(), true),
        Field::new("alpn", list_varchar_type(), true),
    ])
}

/// Test-only helpers shared by the scalar Arrow-boundary unit tests.
#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use arrow_array::builder::BinaryBuilder;
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{Field, Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// A single-column BLOB input batch. `None` entries become NULLs.
    pub fn blob_batch(rows: &[Option<&[u8]>]) -> RecordBatch {
        let mut b = BinaryBuilder::new();
        for r in rows {
            match r {
                Some(s) => b.append_value(s),
                None => b.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "bytes",
            arr.data_type().clone(),
            true,
        )]));
        RecordBatch::try_new(schema, vec![arr]).unwrap()
    }

    /// Build a `ProcessParams` carrying the given output schema and arguments.
    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
            copy_from: None,
        }
    }

    /// Run a scalar function over a prebuilt input batch.
    pub fn run_scalar_on<F: ScalarFunction>(
        f: &F,
        batch: RecordBatch,
        arguments: Arguments,
    ) -> Result<ArrayRef> {
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            arguments: arguments.clone(),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema.clone(), arguments);
        let out = f.process(&params, &batch)?;
        Ok(out.column(0).clone())
    }

    /// Run a scalar over a single-column BLOB input batch.
    pub fn run_scalar_blob<F: ScalarFunction>(f: &F, rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
        run_scalar_on(f, blob_batch(rows), Arguments::default())
    }

    /// The declared output `DataType` from `on_bind` for a no-arg scalar.
    pub fn bound_type<F: ScalarFunction>(f: &F) -> arrow_schema::DataType {
        let bind = BindParams::default();
        let bound = f.on_bind(&bind).unwrap();
        bound.output_schema.field(0).data_type().clone()
    }
}
