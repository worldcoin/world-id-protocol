//! The `uint16` error codes of a Verifier response (WIP-201 §4.5.1).

/// A `VerifierError` code: the Verifier refused the request before the Engine call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum VerifierErrorCode {
    /// The request does not meet the request formats or does not fit the loaded release.
    MalformedRequest = 0x0001,
    /// The request's `expires_at` has passed.
    Expired = 0x0002,
    /// The request was seen before.
    Replay = 0x0003,
    /// As WIP-107 §4.7 defines.
    BillingNullifierRequired = 0x0004,
    /// As WIP-107 §4.7 defines.
    BillingUnregistered = 0x0005,
}

impl VerifierErrorCode {
    /// The code for `code`, if it is one.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            0x0001 => Self::MalformedRequest,
            0x0002 => Self::Expired,
            0x0003 => Self::Replay,
            0x0004 => Self::BillingNullifierRequired,
            0x0005 => Self::BillingUnregistered,
            _ => return None,
        })
    }

    /// The `uint16` on the wire.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// `EngineError` code `engine_timeout`: the Engine did not finish by the last response slot.
pub const ENGINE_TIMEOUT: u16 = 0x0000;
/// `EngineError` code `unlisted_error`: the Engine returned a code its release does not list.
pub const UNLISTED_ERROR: u16 = 0xFFFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in 0x0001..=0x0005 {
            assert_eq!(VerifierErrorCode::from_code(code).unwrap().code(), code);
        }
        for code in [0x0000, 0x0006, 0xFFFF] {
            assert_eq!(VerifierErrorCode::from_code(code), None);
        }
    }
}
