/// Generic errors that may occur with basic serialization and deserialization.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
    /// Error that occurs when serializing a value. Generally not expected.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Error that occurs when deserializing a value. This can happen often when not providing valid inputs.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    /// Number is equal or larger than the target field modulus.
    #[error("Provided value is not in the field")]
    NotInField,
    /// Index is out of bounds.
    #[error("Provided index is out of bounds")]
    OutOfBounds,
    /// Invalid input provided (e.g., incorrect length, format, etc.)
    #[error("Invalid input at {attribute}: {reason}")]
    InvalidInput {
        /// The attribute that is invalid
        attribute: String,
        /// The reason the input is invalid
        reason: String,
    },
}
