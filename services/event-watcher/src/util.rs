use alloy::primitives::Address;
use serde_json::{Map, Number, Value};

pub fn address_to_value(address: Address) -> Value {
    Value::String(format!("{address:#x}"))
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
