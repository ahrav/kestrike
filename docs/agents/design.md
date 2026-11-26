# Design principles

Read this before changing Rust code, as `AGENTS.md` directs. Four rules shape
changes: stop accretive design, stay in scope, investigate before choosing,
and search before adding code.

## Accretive design

Complexity that accumulates one small delta at a time costs more than one
refactor. A small diff is a goal only when the result is the shape you would
write from scratch.

The pattern: a function takes `X`. A new need adds `Y`, then `Z`, then a closure
threaded through intermediate functions that forward it unchanged. Tests stub
the closure with `|_, _| {}`. Each step was minimal; the signature no longer
matches the function's real dependency set.

Stop and reconsider when you see:

- a parameter forwarded through two or more functions that only pass it on;
- a signature that takes `&X` while needing state on `&Y`, so callers smuggle
  `Y` in through closures, indices, or shared state;
- tests passing `|_, _| {}`, `None`, or sentinels for parameters they do not
  exercise;
- `if feature_disabled { return; }` guards across methods, because one piece
  of state has two modes with no type-level distinction;
- a back-pointer that ownership or module visibility forbids;
- layers of `Option` or flag plumbing encoding the same binary choice.

When you see it:

1. Name the function's real dependency set.
2. Propose the refactor: move the function to its owner, extract a
   coordinator, split it along its axis of variation, or replace flag plumbing
   with two types.
3. Size it in call sites and lines. When its one-time cost is comparable to the
   accretive change plus its debt, do the refactor.
4. When the refactor exceeds the task's scope, draft a ticket under
   [the issue workflow](issue-tracker.md) and ask the user to approve the debt.
   Publish the ticket or take the shortcut only with that approval.

Locally minimal changes remain the default. A new input is sometimes a new
input. Callbacks, builders, options structs, and generics are fine when chosen
on purpose. The warning sign is the combination: pure forwarding, sentinel
stubs, a growing parameter list, and scattered null checks.

## Scope

Touch only files the task requires. Report a pre-existing flake, unrelated
warning, or refactoring opportunity at the end of your response and leave it
alone. A bug fix needs no cleanup pass; a one-time operation needs no new
helper module. When unsure whether something is in scope, ask.

## Design decisions

A fix that compiles but weakens an invariant looks correct until it loses data
under partition. Before choosing:

1. Research the options: their failure modes, the invariant each preserves, and
   their maintenance cost.
2. Prefer an implementation you can reason about over a clever one.
3. Give each function one concern, with clear phase boundaries.
4. Name the invariant a safety or liveness decision protects.
5. When the choice is unclear, present the options with tradeoffs and let the
   user decide.

## Search before adding code

Before writing a function, struct, trait, method, or module, confirm it does not
exist. Search by concept ("proposal number", "quorum", "promise"), not only by
the name you plan to use. Read the target module, its siblings, and the shared
utility modules. Extend or generalize existing logic instead of writing a
parallel version. When unsure, ask.

A duplicate is a second function doing the same thing under another name, a
method reimplementing trait or utility logic, a struct identical in shape to an
existing one, or a copied block with small variations. Review rejects a
duplicate that a search would have found.

## Module organization

A `mod.rs` holds module documentation, `mod` declarations, and `pub use`
re-exports. It may also hold the single primary type that names the module,
with its metrics and constants, when no other type lives there.

A banner comment separating concepts inside a file means the second concept
needs its own file. The file name is the banner and its `//!` comment is the
explanation.

The contents of one file share a common invariant, a common abstraction
boundary (a type and its impls), or one algorithm and its helpers. Before adding
a type to a file, ask: does the file already hold an unrelated item, would the
addition need a banner, and would a reader expect it here from the file name?
If any answer points elsewhere, create a new file.
