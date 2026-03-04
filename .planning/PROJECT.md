# Structured Timeout Errors

## What This Is

An investigation and implementation to ensure timeout errors from the Tower timeout middleware layer in the gateway and indexer services return structured error responses matching the existing error format used throughout the services.

## Core Value

All error responses from gateway and indexer services follow a consistent structured format — timeouts included.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] Investigate current timeout behavior in gateway service (Tower timeout layer)
- [ ] Investigate current timeout behavior in indexer service (Tower timeout layer)
- [ ] Determine if timeouts currently return unstructured/empty error responses
- [ ] If unstructured: implement structured timeout error responses matching existing error format
- [ ] Ensure timeout errors are distinguishable from other error types in the response body

### Out of Scope

- Changing timeout duration values — this is about response format only
- Adding new error categories beyond timeouts — focus on the Tower timeout layer gap
- Client-side error handling changes — server-side only

## Context

- Both gateway (`services/gateway/`) and indexer (`services/indexer/`) are Rust services using Tower middleware
- A Tower timeout layer handles request timeouts, but may return responses without structured error bodies
- Other error paths in these services already return structured JSON error responses
- This is a consistency fix, not driven by a specific client-facing incident

## Constraints

- **Compatibility**: Must match the existing error response format used by the services
- **Scope**: Only the Tower timeout layer — not a broader error handling refactor

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Match existing error format | Consistency across all error responses | — Pending |
| Investigate before implementing | Confirm the problem exists before writing code | — Pending |

---
*Last updated: 2026-03-04 after initialization*
