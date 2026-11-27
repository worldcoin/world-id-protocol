//! Pipeline type strings (WIP-201 §4.3.1).
//!
//! A type string names a pipeline's roles, which of them the Flamingo Token commits to, and how
//! many strictness levels it has, e.g. `EXAMPLE<2>(reference#,live#,evidence*)`.

use std::collections::HashSet;

use world_id_primitives::FieldElement;

use crate::{MAX_COMMITTED, pipeline_type};

/// Maximum length of a type string, in bytes.
pub const MAX_TYPE_BYTES: usize = 255;

/// Why a type string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid pipeline type: {0}")]
pub struct TypeError(&'static str);

/// A parsed type string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineType {
    name: String,
    levels: u8,
    members: Vec<Member>,
    hash: FieldElement,
}

/// One role of a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// What the input is to the type, e.g. `live`.
    pub role: String,
    /// Whether the Flamingo Token carries the hash of its entry (`#`).
    pub committed: bool,
    /// How many inputs a pipeline gives the role.
    pub cardinality: Cardinality,
}

/// How many inputs a pipeline of a type gives a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    /// No suffix: exactly one input.
    One,
    /// `?`: exactly one input, whose entry a request may leave absent.
    Optional,
    /// `*`: any number of inputs, fixed by the pipeline.
    Any,
    /// `+`: at least one input, fixed by the pipeline.
    AtLeastOne,
}

impl Cardinality {
    /// Whether a pipeline may give the role `count` inputs.
    #[must_use]
    pub const fn allows(self, count: usize) -> bool {
        match self {
            Self::One | Self::Optional => count == 1,
            Self::Any => true,
            Self::AtLeastOne => count >= 1,
        }
    }
}

impl PipelineType {
    /// Parses a type string and checks the rules of WIP-201 §4.3.1.
    ///
    /// # Errors
    /// Fails for a string that does not match the grammar, is longer than [`MAX_TYPE_BYTES`],
    /// repeats a role, commits a `*` or `+` role, or commits more than [`MAX_COMMITTED`] roles.
    pub fn parse(type_string: &str) -> Result<Self, TypeError> {
        if type_string.len() > MAX_TYPE_BYTES {
            return Err(TypeError("longer than MAX_TYPE_BYTES"));
        }
        let (name, rest) = type_string
            .split_once('<')
            .ok_or(TypeError("missing strictness levels"))?;
        let (levels, rest) = rest
            .split_once('>')
            .ok_or(TypeError("missing strictness levels"))?;
        let members = rest
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
            .ok_or(TypeError("missing members"))?;
        if !is_name(name) {
            return Err(TypeError("name"));
        }
        let levels = parse_levels(levels).ok_or(TypeError("strictness levels"))?;
        let members = members
            .split(',')
            .map(parse_member)
            .collect::<Result<Vec<_>, _>>()?;
        let mut roles = HashSet::with_capacity(members.len());
        if !members.iter().all(|m| roles.insert(m.role.as_str())) {
            return Err(TypeError("repeated role"));
        }
        if members.iter().filter(|m| m.committed).count() > MAX_COMMITTED {
            return Err(TypeError("more than MAX_COMMITTED committed roles"));
        }
        Ok(Self {
            name: name.to_owned(),
            levels,
            members,
            hash: pipeline_type(type_string),
        })
    }

    /// The type's name, e.g. `EXAMPLE`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `n` of `<n>`: the levels are `1` to `n`, or none for `0`.
    #[must_use]
    pub const fn levels(&self) -> u8 {
        self.levels
    }

    /// Whether `strictness` is a level of the type; with no levels, only `0` is.
    #[must_use]
    pub const fn has_level(&self, strictness: u8) -> bool {
        if self.levels == 0 {
            strictness == 0
        } else {
            strictness >= 1 && strictness <= self.levels
        }
    }

    /// The roles, in type order.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The member with `role`, if the type has it.
    #[must_use]
    pub fn member(&self, role: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.role == role)
    }

    /// The committed roles in type order: committed role `k` fills `entry_hash_k`.
    pub fn committed_roles(&self) -> impl Iterator<Item = &str> {
        self.members
            .iter()
            .filter(|m| m.committed)
            .map(|m| m.role.as_str())
    }

    /// `pipeline_type`, the hash the Flamingo Token carries.
    #[must_use]
    pub const fn hash(&self) -> FieldElement {
        self.hash
    }
}

/// `segment *("/" segment)` with `segment = 1*(%x41-5A / DIGIT / "-")`.
fn is_name(name: &str) -> bool {
    name.split('/').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// `"0" / %x31-39 *2DIGIT`, at most 255.
fn parse_levels(levels: &str) -> Option<u8> {
    let canonical = levels == "0"
        || (!levels.starts_with('0')
            && (1..=3).contains(&levels.len())
            && levels.bytes().all(|b| b.is_ascii_digit()));
    if canonical { levels.parse().ok() } else { None }
}

/// `role ["#"] ["?" / "*" / "+"]` with `role = %x61-7A *(%x61-7A / DIGIT / "_")`.
fn parse_member(member: &str) -> Result<Member, TypeError> {
    let (member, cardinality) = match member.as_bytes().last() {
        Some(b'?') => (&member[..member.len() - 1], Cardinality::Optional),
        Some(b'*') => (&member[..member.len() - 1], Cardinality::Any),
        Some(b'+') => (&member[..member.len() - 1], Cardinality::AtLeastOne),
        _ => (member, Cardinality::One),
    };
    let (role, committed) = member
        .strip_suffix('#')
        .map_or((member, false), |role| (role, true));
    let valid_role = role.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && role
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !valid_role {
        return Err(TypeError("role"));
    }
    if committed && matches!(cardinality, Cardinality::Any | Cardinality::AtLeastOne) {
        return Err(TypeError("committed role with * or +"));
    }
    Ok(Member {
        role: role.to_owned(),
        committed,
        cardinality,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "EXAMPLE<2>(reference#,live#,evidence*)";

    #[test]
    fn parses_the_spec_example() {
        let ty = PipelineType::parse(EXAMPLE).unwrap();
        assert_eq!(ty.name(), "EXAMPLE");
        assert_eq!(ty.levels(), 2);
        assert!(!ty.has_level(0) && ty.has_level(1) && ty.has_level(2) && !ty.has_level(3));
        assert_eq!(
            ty.committed_roles().collect::<Vec<_>>(),
            ["reference", "live"]
        );
        assert_eq!(ty.member("evidence").unwrap().cardinality, Cardinality::Any);
        assert_eq!(ty.hash(), pipeline_type(EXAMPLE));
    }

    #[test]
    fn parses_every_cardinality_and_level_form() {
        let ty = PipelineType::parse("WORLD-ID/WIP-9/T/V1<0>(a,b#?,c*,d+,e_1#)").unwrap();
        let cards: Vec<_> = ty.members().iter().map(|m| m.cardinality).collect();
        assert_eq!(
            cards,
            [
                Cardinality::One,
                Cardinality::Optional,
                Cardinality::Any,
                Cardinality::AtLeastOne,
                Cardinality::One,
            ]
        );
        assert!(ty.has_level(0) && !ty.has_level(1));
        assert_eq!(ty.committed_roles().collect::<Vec<_>>(), ["b", "e_1"]);
        assert_eq!(PipelineType::parse("T<255>(a)").unwrap().levels(), 255);
    }

    #[test]
    fn rejects_strings_outside_the_grammar() {
        let long = format!("T<1>({})", "a".repeat(MAX_TYPE_BYTES));
        for bad in [
            "",
            "T(a)",
            "T<1>",
            "T<1>()",
            "T<1>(a,)",
            "T<1>(a) ",
            "T <1>(a)",
            "t<1>(a)",
            "T/<1>(a)",
            "<1>(a)",
            "T<01>(a)",
            "T<256>(a)",
            "T<1000>(a)",
            "T<-1>(a)",
            "T<1>(A)",
            "T<1>(1a)",
            "T<1>(_a)",
            "T<1>(a?#)",
            "T<1>(a##)",
            "T<1>(a?*)",
            "T<1>(a, b)",
            "T<1>(a)(b)",
            "T<1>(é)",
            long.as_str(),
        ] {
            assert!(PipelineType::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_rule_violations() {
        for (bad, reason) in [
            ("T<1>(a,a)", "repeated role"),
            ("T<1>(a#*)", "committed role with * or +"),
            ("T<1>(a#+)", "committed role with * or +"),
            (
                "T<1>(a#,b#,c#,d#,e#)",
                "more than MAX_COMMITTED committed roles",
            ),
        ] {
            assert_eq!(PipelineType::parse(bad), Err(TypeError(reason)));
        }
        assert!(PipelineType::parse("T<1>(a#,b#,c#,d#,e)").is_ok());
    }

    #[test]
    fn cardinalities_allow_their_counts() {
        assert!(Cardinality::One.allows(1) && !Cardinality::One.allows(0));
        assert!(Cardinality::Optional.allows(1) && !Cardinality::Optional.allows(2));
        assert!(Cardinality::Any.allows(0) && Cardinality::Any.allows(9));
        assert!(!Cardinality::AtLeastOne.allows(0) && Cardinality::AtLeastOne.allows(2));
    }
}
