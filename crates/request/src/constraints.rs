use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Upper bound on total constraint AST nodes (expr + type nodes).
/// This prevents extremely large request bodies from causing excessive work.
pub const MAX_CONSTRAINT_NODES: usize = 12;

/// Logical operator kinds supported in constraint expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintKind {
    /// All of the children must be satisfied
    All,
    /// Any of the children must be satisfied
    Any,
    /// All satisfiable children should be selected
    Enumerate,
}

/// Constraint expression tree: a list of types/expressions under `all`, `any`, or `enumerate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ConstraintExpr<'a> {
    /// All children must be satisfied
    All {
        /// Children nodes that must all be satisfied
        all: Vec<ConstraintNode<'a>>,
    },
    /// Any child may satisfy the expression
    Any {
        /// Children nodes where any one must be satisfied
        any: Vec<ConstraintNode<'a>>,
    },
    /// All satisfiable children should be selected
    Enumerate {
        /// Children nodes to evaluate and collect if satisfiable
        enumerate: Vec<ConstraintNode<'a>>,
    },
}

/// Node of a constraint expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum ConstraintNode<'a> {
    /// Issuer schema id string
    Type(Cow<'a, str>),
    /// Expressions
    Expr(ConstraintExpr<'a>),
}

impl ConstraintExpr<'_> {
    /// Evaluate the constraint against a predicate that reports whether a issuer schema id was provided successfully
    pub fn evaluate<F>(&self, has_type: &F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        match self {
            ConstraintExpr::All { all } => all.iter().all(|n| n.evaluate(has_type)),
            ConstraintExpr::Any { any } => any.iter().any(|n| n.evaluate(has_type)),
            ConstraintExpr::Enumerate { enumerate } => {
                enumerate.iter().any(|n| n.evaluate(has_type))
            }
        }
    }

    /// Validate the maximum nesting depth. Depth counts the number of Expr nodes encountered.
    /// A flat list has depth 1. Allow at most 2 (one nested level under root).
    #[must_use]
    pub fn validate_max_depth(&self, max_depth: usize) -> bool {
        fn validate_expr(expr: &ConstraintExpr<'_>, depth: usize, max_depth: usize) -> bool {
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
                ConstraintExpr::Enumerate { enumerate } => {
                    enumerate.iter().all(|n| validate_node(n, depth, max_depth))
                }
            }
        }
        fn validate_node(node: &ConstraintNode<'_>, parent_depth: usize, max_depth: usize) -> bool {
            match node {
                ConstraintNode::Type(_) => true,
                ConstraintNode::Expr(child) => validate_expr(child, parent_depth + 1, max_depth),
            }
        }
        validate_expr(self, 1, max_depth)
    }

    /// Validate the maximum total number of nodes in the constraint AST.
    /// Counts both expression containers and leaf type nodes. Short-circuits
    /// once the running total exceeds `max_nodes` to avoid full traversal.
    #[must_use]
    pub fn validate_max_nodes(&self, max_nodes: usize) -> bool {
        fn count_expr(expr: &ConstraintExpr<'_>, count: &mut usize, max_nodes: usize) -> bool {
            // Count the expr node itself
            *count += 1;
            if *count > max_nodes {
                return false;
            }
            match expr {
                ConstraintExpr::All { all } => {
                    for n in all {
                        if !count_node(n, count, max_nodes) {
                            return false;
                        }
                    }
                    true
                }
                ConstraintExpr::Any { any } => {
                    for n in any {
                        if !count_node(n, count, max_nodes) {
                            return false;
                        }
                    }
                    true
                }
                ConstraintExpr::Enumerate { enumerate } => {
                    for n in enumerate {
                        if !count_node(n, count, max_nodes) {
                            return false;
                        }
                    }
                    true
                }
            }
        }

        fn count_node(node: &ConstraintNode<'_>, count: &mut usize, max_nodes: usize) -> bool {
            match node {
                ConstraintNode::Type(_) => {
                    *count += 1;
                    *count <= max_nodes
                }
                ConstraintNode::Expr(child) => count_expr(child, count, max_nodes),
            }
        }

        let mut count = 0;
        count_expr(self, &mut count, max_nodes)
    }
}

impl ConstraintNode<'_> {
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
