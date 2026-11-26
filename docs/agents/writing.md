# Writing

Apply these rules to chat, docs, comments, commit messages, review descriptions,
and agent handoffs. Preserve technical facts and uncertainty when shortening text.

Start with the answer or action. Use short sentences, active voice, concrete
nouns, and plain words. Remove filler, hype, stock phrases, fake friendliness,
and statements about the act of explaining. Use headings and lists only when
they improve scanning. State missing evidence instead of inventing certainty.
Preserve quoted text, code, commands, paths, identifiers, logs, diffs, and JSON
exactly. [The comment rules](comments.md) govern source comments.

## Agent instructions

When editing instructions, use `/writing-for-agents` if available. Otherwise:

- Name the consumer, load trigger, required action, and completion gate.
- Keep universal rules in `AGENTS.md`; link branch-specific detail from its
  trigger. Give each rule one home.
- A rule a check can enforce belongs in CI or a hook, not in a guide.
- Put approval boundaries before mutations. Missing tools or authority stop work.
- Report unrun behavioral tests; wording alone does not prove agent compliance.

Read the [review policy](../../REVIEW.md) before a code review.

## Enforcement

`.github/workflows/agent-checks.yml` rejects comment-lint override markers,
runs the hook and review-workflow contract tests, and checks that every link,
anchor, and backticked repository path in `REVIEW.md`, `AGENTS.md`, and
`docs/agents/` resolves in a clean clone. Run the same checks locally:

```sh
bash scripts/forbid-comment-markers.sh
python3 scripts/test-agent-hooks.py
python3 scripts/test-review-workflow.py
```

`git config --local core.hooksPath .githooks` enables the tracked hooks. The
pre-commit hook runs the marker check on staged additions; the pre-push hook
runs [the pre-push checks](ci.md#pre-push-checks), then a configured global
pre-push hook. Inspect existing hooks before
changing the hook path and keep their checks. Workstation steering hooks review
comments and prose; they can fail open, so follow the policy when none runs.
