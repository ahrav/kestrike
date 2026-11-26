# Comments

Read this before changing source comments, as `AGENTS.md` directs.
`scripts/forbid-comment-markers.sh` rejects comment-lint override markers; the
rules below need judgment.

## A comment describes the code and nothing else

A comment states the behavior, invariants, edge cases, and non-obvious reasons
of the code it annotates. A reader with no access to the PR, the issue tracker,
or chat history understands it from the code alone.

Never write these:

| Category | Example |
| --- | --- |
| Tracking IDs | `// F-011: BatchValidation error variant` |
| PR or review references | `// PR blotter pull request 124`, `// per review feedback` |
| Provenance | a file, class, method, or parameter name from the implementation this code was ported from |
| Parity justification | `// matches the original`, `// same as the reference codec` |
| Test justification | `// Added to cover finding F7` |
| History | `// Previously used a linear scan`, `// Moved from old_engine.rs` |
| Status | `// for now`, `// not yet wired`, `// will become` |
| Conversation | `// Good catch`, `// Note to reviewer` |

One reference is allowed: the academic source that defines the invariant, for
example `(Lamport, *Paxos Made Simple*, 2001, P2c)`. When behavior diverges
from a reference implementation, state the Rust behavior and the language
reason for it. The reason for a change belongs in the commit message or issue
body under [the issue workflow](issue-tracker.md).

```rust
// BAD: Previously compared by round only, changed to include NodeId
// GOOD: Proposals are ordered by (round, NodeId); equal rounds break on proposer identity.

// BAD: Added per reviewer suggestion to reject stale prepares
// GOOD: A prepare below the promised number is rejected; accepting it would break the promise.

// BAD (test): decodes the same way as the reference codec
// GOOD (test): 'W' decodes to nibble 0, so an all-'W' tail yields eight zero bytes.
```

## What to document

Document a non-obvious reason: an invariant, a contract, an ordering or safety
requirement, a tradeoff, or a failure mode the signature does not convey.

- A module file (`//!`) states its purpose and the invariants it owns.
- A public or `pub(crate)` type, enum, or trait (`///`) states its role, the
  invariants instances uphold, and what a variant or field means when its name
  does not say.
- A public or `pub(crate)` function (`///`) states preconditions, side effects,
  errors, and the reason it exists when its name and signature leave that
  unclear.

The test is the reason, not the visibility. A trivial accessor needs no doc
comment; a function whose correctness depends on an unstated precondition does.
Delete a comment that restates the code.
A test comment states the property the test asserts and why.

## Self-check

1. Does the comment cite a finding ID, PR number, or reviewer? Delete it.
2. Does it name a symbol from a ported source, or justify behavior by parity
   with one? Delete it.
3. Does it say when or why the code changed instead of what it does? Rewrite it.
4. Does it restate the code, or describe where the code is headed? Delete it.
5. Would it make sense to someone who has never seen the PR? If not, rewrite it.
