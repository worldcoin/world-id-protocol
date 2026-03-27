use alloy::primitives::{Address, B256, U256};
use serde_json::{Map, Number, Value};

pub fn address_to_value(address: Address) -> Value {
    Value::String(format!("{address:#x}"))
}

pub fn b256_to_value(value: B256) -> Value {
    Value::String(format!("{value:#x}"))
}

pub fn u256_to_value(value: U256) -> Value {
    Value::String(value.to_string())
}

pub fn normalize_json_value(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.into_iter().map(normalize_json_value).collect())
        }
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, normalize_json_value(v)))
                .collect(),
        ),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() || n.is_f64() {
                Value::Number(n)
            } else {
                Value::String(n.to_string())
            }
        }
        other => other,
    }
}

pub fn insert_string(
    map: &mut Map<String, Value>,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    map.insert(key.into(), Value::String(value.into()));
}

pub fn insert_u64(map: &mut Map<String, Value>, key: impl Into<String>, value: u64) {
    map.insert(key.into(), Value::Number(Number::from(value)));
}
