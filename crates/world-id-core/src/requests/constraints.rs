use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Logical operator kinds supported
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintKind {
    All,
    Any,
}

/// Constraint expression tree: either a list of types/expressions under `all` or `any`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ConstraintExpr<'a> {
    All { all: Vec<ConstraintNode<'a>> },
    Any { any: Vec<ConstraintNode<'a>> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ConstraintNode<'a> {
    /// Credential type string
    Type(Cow<'a, str>),
    /// Expressions
    Expr(ConstraintExpr<'a>),
}

impl<'a> ConstraintExpr<'a> {
    /// Evaluate the constraint against a predicate that reports whether a credential type was provided successfully
    pub fn evaluate<F>(&self, has_type: &F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        match self {
            ConstraintExpr::All { all } => all.iter().all(|n| n.evaluate(has_type)),
            ConstraintExpr::Any { any } => any.iter().any(|n| n.evaluate(has_type)),
        }
    }

    /// Validate the maximum nesting depth. Depth counts the number of Expr nodes encountered.
    /// A flat list has depth 1. Allow at most 2 (one nested level under root).
    pub fn validate_max_depth(&self, max_depth: usize) -> bool {
        fn validate_expr<'a>(expr: &ConstraintExpr<'a>, depth: usize, max_depth: usize) -> bool {
            if depth > max_depth {
                return false;
            }
            match expr {
                ConstraintExpr::All { all } => {
                    all.iter().all(|n| validate_node(n, depth, max_depth))
                }
                ConstraintExpr::Any { any } => {
                    any.iter().all(|n| validate_node(n, depth, max_depth))
                }
            }
        }
        fn validate_node<'a>(
            node: &ConstraintNode<'a>,
            parent_depth: usize,
            max_depth: usize,
        ) -> bool {
            match node {
                ConstraintNode::Type(_) => true,
                ConstraintNode::Expr(child) => validate_expr(child, parent_depth + 1, max_depth),
            }
        }
        validate_expr(self, 1, max_depth)
    }
}

impl<'a> ConstraintNode<'a> {
    fn evaluate<F>(&self, has_type: &F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        match self {
            ConstraintNode::Type(t) => has_type(t),
            ConstraintNode::Expr(expr) => expr.evaluate(has_type),
        }
    }
}
