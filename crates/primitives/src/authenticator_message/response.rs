//! Decodes payloads directly to avoid an extra buffered plaintext copy.

use std::fmt;

use serde::{Deserialize, Deserializer, de::Error as _};

use super::{ErrorObject, Id, Response, Version};

impl<'de, R: Deserialize<'de>, D: Deserialize<'de>> Deserialize<'de> for Response<R, D> {
    fn deserialize<S: Deserializer<'de>>(deserializer: S) -> Result<Self, S::Error> {
        struct ResponseVisitor<R, D>(std::marker::PhantomData<(R, D)>);

        impl<'de, R: Deserialize<'de>, D: Deserialize<'de>> serde::de::Visitor<'de>
            for ResponseVisitor<R, D>
        {
            type Value = Response<R, D>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .write_str("a response map with version, id and exactly one result or error")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut version = None;
                let mut id: Option<Option<Id>> = None;
                let mut result: Option<R> = None;
                let mut error: Option<ErrorObject<D>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => {
                            if version.is_some() {
                                return Err(A::Error::duplicate_field("version"));
                            }
                            version = Some(map.next_value::<Version>()?);
                        }
                        "id" => {
                            if id.is_some() {
                                return Err(A::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value()?);
                        }
                        "result" => {
                            if result.is_some() {
                                return Err(A::Error::duplicate_field("result"));
                            }
                            result = Some(map.next_value()?);
                        }
                        "error" => {
                            if error.is_some() {
                                return Err(A::Error::duplicate_field("error"));
                            }
                            error = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(A::Error::unknown_field(
                                &key,
                                &["version", "id", "result", "error"],
                            ));
                        }
                    }
                }
                let version = version.ok_or_else(|| A::Error::missing_field("version"))?;
                let id = id.ok_or_else(|| A::Error::missing_field("id"))?;
                match (result, error) {
                    (Some(result), None) => {
                        let id = id.ok_or_else(|| {
                            A::Error::custom("success response requires a non-null id")
                        })?;
                        Ok(Response::Success {
                            version,
                            id,
                            result,
                        })
                    }
                    (None, Some(error)) => Ok(Response::Error { version, id, error }),
                    _ => Err(A::Error::custom(
                        "response requires exactly one result or error",
                    )),
                }
            }
        }

        deserializer.deserialize_map(ResponseVisitor(std::marker::PhantomData))
    }
}
