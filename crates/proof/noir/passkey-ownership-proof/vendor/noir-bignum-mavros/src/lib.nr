pub mod bignum;

mod constants;

// Pre-defined fields and `BigNum`s for people to use:
pub mod fields;

// Structs enabling people to define their own bignum params
pub mod params;

// Free functions and other utils called by the BigNum trait.
pub(crate) mod fns;
pub(crate) mod utils;

// ProveKit v1's Noir frontend type-checks dependency test modules during
// preparation. The upstream v0.9.2 tests use newer Noir APIs that are not
// available in v1, so the compatibility copy omits them from normal builds.

// Internal functions required by derive macros for external crates
// Exported through the `internal` submodule to make it clear they are not
// intended for direct use by end users
pub mod internal {
    // Constrained operations
    pub use crate::fns::constrained_ops::add;
    pub use crate::fns::constrained_ops::assert_is_not_equal;
    pub use crate::fns::constrained_ops::assert_is_not_zero;
    pub use crate::fns::constrained_ops::assert_is_not_zero_integer;
    pub use crate::fns::constrained_ops::cmp;
    pub use crate::fns::constrained_ops::derive_from_seed;
    pub use crate::fns::constrained_ops::div;
    pub use crate::fns::constrained_ops::eq;
    pub use crate::fns::constrained_ops::from_field;
    pub use crate::fns::constrained_ops::is_zero;
    pub use crate::fns::constrained_ops::is_zero_integer;
    pub use crate::fns::constrained_ops::mul;
    pub use crate::fns::constrained_ops::neg;
    pub use crate::fns::constrained_ops::sqr;
    pub use crate::fns::constrained_ops::sub;
    pub use crate::fns::constrained_ops::udiv;
    pub use crate::fns::constrained_ops::udiv_mod;
    pub use crate::fns::constrained_ops::umod;
    pub use crate::fns::constrained_ops::validate_in_field;
    pub use crate::fns::constrained_ops::validate_in_range;

    // Unconstrained operations
    pub use crate::fns::unconstrained_ops::__add;
    pub use crate::fns::unconstrained_ops::__derive_from_seed;
    pub use crate::fns::unconstrained_ops::__div;
    pub use crate::fns::unconstrained_ops::__eq;
    pub use crate::fns::unconstrained_ops::__invmod;
    pub use crate::fns::unconstrained_ops::__is_zero;
    pub use crate::fns::unconstrained_ops::__mul;
    pub use crate::fns::unconstrained_ops::__neg;
    pub use crate::fns::unconstrained_ops::__pow;
    pub use crate::fns::unconstrained_ops::__sqr;
    pub use crate::fns::unconstrained_ops::__sqrt;
    pub use crate::fns::unconstrained_ops::__sub;
    pub use crate::fns::unconstrained_ops::__udiv_mod;

    // Serialization functions
    pub use crate::fns::serialization::from_be_bytes;
    pub use crate::fns::serialization::from_le_bytes;
    pub use crate::fns::serialization::to_be_bytes;
    pub use crate::fns::serialization::to_le_bytes;
}

// Re-export the main structs so that users don't have to specify the paths
pub use bignum::BigNum;
pub use bignum::derive_bignum;

// This compatibility package intentionally exposes only the P-256 field types
// used by the passkey circuit.
pub use fields::secp256r1Fq::Secp256r1_Fq;
pub use fields::secp256r1Fr::Secp256r1_Fr;
