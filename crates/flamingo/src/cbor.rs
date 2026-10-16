//! Deterministic CBOR maps (RFC 8949 §4.2.1) with text keys.

use ciborium::Value;

/// Encodes `value`; maps built with [`map`] are already in deterministic key order.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("writing CBOR into a Vec cannot fail");
    bytes
}

/// A map with its entries sorted by the bytewise order of their encoded keys.
pub fn map(entries: Vec<(&str, Value)>) -> Value {
    let mut entries: Vec<(Vec<u8>, Value, Value)> = entries
        .into_iter()
        .map(|(key, value)| {
            let key = Value::Text(key.into());
            (encode(&key), key, value)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Map(entries.into_iter().map(|(_, k, v)| (k, v)).collect())
}

/// The entries of a decoded map, taken out by key.
pub struct Fields(Vec<(Value, Value)>);

impl Fields {
    /// The entries of `value`, if it is a map.
    pub fn of(value: Value) -> Option<Self> {
        value.into_map().ok().map(Self)
    }

    /// Removes and returns the value under `key`.
    pub fn take(&mut self, key: &str) -> Option<Value> {
        let index = self.0.iter().position(|(k, _)| k.as_text() == Some(key))?;
        Some(self.0.remove(index).1)
    }

    /// Whether every entry was taken.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A byte string of exactly `N` bytes.
pub fn array<const N: usize>(value: Value) -> Option<[u8; N]> {
    value.into_bytes().ok()?.try_into().ok()
}

/// An unsigned integer that fits `T`.
pub fn uint<T: TryFrom<u64>>(value: &Value) -> Option<T> {
    let integer = value.as_integer()?;
    u64::try_from(integer)
        .ok()
        .and_then(|n| T::try_from(n).ok())
}
