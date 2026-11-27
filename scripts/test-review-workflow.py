#!/usr/bin/env python3
"""Check the security and posting contract of the Claude review workflow."""

import base64
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/claude-code-review.yml"
RUST_LANES = ROOT / ".github/workflows/agent-checks.yml"
REVIEW_POLICY = ROOT / "REVIEW.md"
CRATES = sorted(ROOT.glob("crates/*/Cargo.toml"))

REPO = "ahrav/kestrike"
NUMBER = "574"
HEAD_SHA = "414eae0afb864a912c79455ca4c85341214c507e"
HEAD_SHA_EXPR = "${{ github.event.pull_request.head.sha }}"
BASE_SHA = "bd835fdb85c6521a5a1558c7209c5fe6360d8575"
BASE_SHA_EXPR = "${{ github.event.pull_request.base.sha }}"
STABLE = "1.99.0"
RUNNER_TEMP = "/home/runner/work/_temp"

# Kilo's review service truncates REVIEW.md past this many characters and loads
# only the prefix, so every rule past the limit is lost to that reviewer.
KILO_GUIDANCE_LIMIT = 10_000

# The entry points and agent guides an agent reads before work; each named path
# must exist in a fresh clone.
GUIDANCE = [ROOT / "REVIEW.md", ROOT / "AGENTS.md", *sorted((ROOT / "docs/agents").rglob("*.md"))]

# Paths `.gitignore` keeps out of every clone; guidance may name them as local
# working records.
LOCAL_ONLY = ("docs/lessons/", "docs/policies/", "docs/specs/", "docs/superpowers/")
LOCAL_ONLY_MARK = "local-only: "
OUTSIDE_MARK = "outside the repository: "

POLICY_POSTING_BANS = (
    "Stay read-only.",
    "Return review findings without posting comments or mutating issues.",
)


def render(text):
    """Substitute the workflow expressions with one concrete pull request."""
    return (
        text.replace("${{ github.repository }}", REPO)
        .replace("${{ github.event.pull_request.number }}", NUMBER)
        .replace(HEAD_SHA_EXPR, HEAD_SHA)
        .replace(BASE_SHA_EXPR, BASE_SHA)
        .replace("${{ env.STABLE }}", STABLE)
        .replace("${{ runner.temp }}", RUNNER_TEMP)
        .replace("${{ github.event.action }}", "synchronize")
    )


def split_rules(value):
    """Split an --allowedTools or --disallowedTools value on commas outside parentheses."""
    rules, depth, current = [], 0, ""
    for char in value:
        if char == "," and depth == 0:
            rules.append(current.strip())
            current = ""
            continue
        depth += {"(": 1, ")": -1}.get(char, 0)
        current += char
    rules.append(current.strip())
    return [rule for rule in rules if rule]


class ReviewWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.lines = cls.text.splitlines()
        cls.prompt = render(cls.block_after("prompt: |"))
        cls.rules = split_rules(render(cls.flag_value("--allowedTools")))
        cls.denied = split_rules(render(cls.flag_value("--disallowedTools")))

    @classmethod
    def flag_value(cls, flag):
        match = re.search(flag + r' "([^"]*)"', cls.text)
        if match is None:
            raise AssertionError(f"workflow does not pass {flag}")
        return match.group(1)

    @classmethod
    def block_after(cls, header):
        """Return the indented block scalar that follows a `key: |` line."""
        start = next(i for i, line in enumerate(cls.lines) if line.strip() == header)
        indent = len(cls.lines[start]) - len(cls.lines[start].lstrip())
        body = []
        for line in cls.lines[start + 1:]:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            body.append(line.strip())
        return "\n".join(body)

    def step(self, uses_prefix):
        """Return the text of the step whose `uses:` starts with uses_prefix."""
        start = next(i for i, line in enumerate(self.lines) if f"uses: {uses_prefix}" in line)
        return self.step_from(start)

    def step_named(self, name):
        """Return the text of the step whose `- name:` equals name."""
        start = next(i for i, line in enumerate(self.lines) if line.strip() == f"- name: {name}")
        return self.step_from(start)

    def step_from(self, start):
        end = next(
            (i for i in range(start + 1, len(self.lines))
             if self.lines[i].lstrip().startswith("- ")),
            len(self.lines),
        )
        return "\n".join(self.lines[start:end])

    def action_inputs(self):
        """Return the key lines of the `with:` mapping of the one step that uses the action."""
        self.assertEqual(self.text.count("uses: anthropics/claude-code-action@"), 1)
        step = self.step("anthropics/claude-code-action@").splitlines()
        start = step.index("        with:")
        end = next(
            (i for i in range(start + 1, len(step))
             if step[i].strip() and len(step[i]) - len(step[i].lstrip()) <= 8),
            len(step),
        )
        return [line for line in step[start + 1:end] if re.match(r" {10}[^\s#]", line)]

    def job_env(self):
        return self.job_mapping("env:")

    def job_permissions(self):
        return self.job_mapping("permissions:")

    def job_mapping(self, header):
        """Return the job mapping, rejecting a workflow-level copy."""
        self.assertNotIn(header, [line.rstrip() for line in self.lines], f"workflow-level {header}")
        job = self.lines.index("  review:")
        start = next(
            i for i in range(job + 1, len(self.lines))
            if self.lines[i].rstrip() == f"    {header}"
        )
        indent = len(self.lines[start]) - len(self.lines[start].lstrip())
        grants = {}
        for line in self.lines[start + 1:]:
            if len(line) - len(line.lstrip()) <= indent:
                break
            scope, _, level = line.strip().partition(":")
            grants[scope.strip()] = level.strip()
        return grants

    def test_review_uses_the_isolated_runner_for_same_repository_prs(self):
        self.assertIn("    runs-on: ubuntu-24.04\n", self.text)
        self.assertIn("    timeout-minutes: 30", self.text)
        self.assertEqual(
            " ".join(self.block_after("if: >-").split()),
            "github.event.action != 'closed' && "
            "(github.event.action != 'edited' || github.event.changes.base != null) && "
            "github.event.pull_request.draft == false && "
            "github.event.pull_request.head.repo.full_name == github.repository && "
            "github.event.pull_request.base.ref == github.event.repository.default_branch",
        )
        self.assertNotIn("allowed_non_write_users:", self.text)
        admitted = "          allowed_bots: kestrike-swarm"
        self.assertEqual(
            ([line for line in self.lines if "allowed_bots" in line.lower()], self.action_inputs().count(admitted)),
            ([admitted], 1),
            "the pinned action's inputs name one GitHub App whose events start the review",
        )

    def test_review_runs_on_a_hosted_runner_without_a_shared_job_lock(self):
        job = self.text.split("\njobs:\n", 1)[1]
        self.assertNotRegex(job, r"(?m)^    concurrency:")
        self.assertIn("runs-on: ubuntu-24.04\n", job)
        self.assertNotIn("self-hosted", job)

    def test_the_model_token_is_reachable_only_from_the_default_branchs_copy_of_the_workflow(self):
        """The trigger runs the base branch's copy of this file, the job runs for pull requests into the
        default branch, and the token is a secret of an environment that admits the default branch."""
        header = self.text.split("\njobs:\n", 1)[0]
        self.assertIn("\non:\n  pull_request_target:\n", header)
        self.assertNotRegex(header, r"(?m)^  pull_request:")
        self.assertIn("    environment: claude-review\n", self.text)
        self.assertIn("github.event.pull_request.base.ref == github.event.repository.default_branch", self.text)
        action = self.step("anthropics/claude-code-action@")
        self.assertIn("claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}", action)
        self.assertEqual(self.text.count("secrets.CLAUDE_CODE_OAUTH_TOKEN"), 1)
        self.assertEqual(set(re.findall(r"secrets\.(\w+)", self.text)), {"GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"})

    def test_model_and_action_remain_pinned(self):
        self.assertIn("--model claude-opus-5-5", self.text)
        self.assertIn("--effort xhigh", self.text)
        self.assertIn(
            "uses: anthropics/claude-code-action@2dca132ff0e0c4094ce6048b422c6915a071210b",
            self.text,
        )

    def test_model_has_no_shell(self):
        """Claude Code runs its built-in read-only Bash commands (cat, git, grep, echo, ...)
        with no allow rule, and the action leaves its token in .git/config and the job
        environment. Denying the Bash tool removes the shell; every input the model needs
        is a file the workflow wrote."""
        self.assertEqual(
            self.rules,
            ["Read", "Grep", "Glob", "mcp__github_inline_comment__create_inline_comment"],
        )
        self.assertIn("Bash", self.denied)
        self.assertNotRegex(self.prompt, r"`(gh|git|cargo|rustup|rustfmt) ")

    def test_file_reads_are_fenced_to_the_checkout_and_the_review_directory(self):
        """.git/config holds the action's token; /etc, $HOME and the runner's own files
        hold more. Reads stop at the checkout plus the directory of workflow-written inputs."""
        self.assertIn("Read(./.git/**)", self.denied)
        self.assertIn("Read(//proc/**)", self.denied)
        self.assertIn(
            """--settings '{"permissions":{"blockReadsOutsideWorkingDirectories":true}}'""",
            self.text,
        )
        self.assertIn("--add-dir ${{ runner.temp }}/review", self.text)

    def test_diff_is_generated_by_the_workflow_from_the_event_commits(self):
        """`gh pr diff` follows the live PR and the API diff stops at 300 files. A trusted
        step diffs the merge base against the event head with git and fails closed."""
        step = self.step_named("Diff of the reviewed commits")
        self.assertIn("BASE_SHA: ${{ github.event.pull_request.base.sha }}", step)
        self.assertIn("HEAD_SHA: ${{ github.event.pull_request.head.sha }}", step)
        self.assertNotIn("${{", step.split("run:")[1])
        self.assertIn('compare/$BASE_SHA...$HEAD_SHA" --jq .merge_base_commit.sha', step)
        # `.git/info/attributes` outranks the checked-out .gitattributes, so `* !diff`
        # returns the diff attribute to unspecified: a PR-supplied `*.rs -diff` cannot
        # hide source lines and git's own heuristic still keeps binaries as markers
        # (`--text` would stream their bytes). An empty diff is a valid review input
        # (a push that reverts the PR), so failure is judged by exit status alone.
        self.assertRegex(step, r"printf '\* !diff\\n' > \"\$\(git rev-parse --git-path info\)/attributes\"")
        self.assertRegex(step, r'git diff "\$merge_base" "\$HEAD_SHA" > "\$RUNNER_TEMP/review/pr\.diff"')
        self.assertIn("set -euo pipefail", step)
        self.assertNotIn("--text", step)
        self.assertNotIn("test -s", step)
        self.assertIn(f"{RUNNER_TEMP}/review/pr.diff", self.prompt)

    def test_fetch_auth_is_environment_only_and_scoped_to_fetch(self):
        step = self.step_named("Diff of the reviewed commits")
        lines = step.splitlines()
        start = lines.index("        run: |") + 1
        body = []
        for line in lines[start:]:
            if line.strip() and len(line) - len(line.lstrip()) < 10:
                break
            body.append(line[10:])
        token = "workflow-regression-token"
        auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        with tempfile.TemporaryDirectory(prefix="kestrike-review-") as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            info = root / "info"
            info.mkdir()
            gh = binaries / "gh"
            gh.write_text('#!/bin/sh\nprintf "%s\\n" "$BASE_SHA"\n')
            gh.chmod(0o755)
            git = binaries / "git"
            git.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['GIT_CALLS'], 'a') as stream:\n"
                "    stream.write(json.dumps({'argv': sys.argv[1:], 'config': "
                "{key: value for key, value in os.environ.items() "
                "if key.startswith('GIT_CONFIG_')}}) + '\\n')\n"
                "if sys.argv[1] == 'rev-parse':\n"
                "    print(os.environ['GIT_INFO'])\n"
            )
            git.chmod(0o755)
            env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_CONFIG_")}
            env.update(
                PATH=f"{binaries}{os.pathsep}{env['PATH']}", GH_TOKEN=token,
                GITHUB_REPOSITORY=REPO, GITHUB_SERVER_URL="https://github.com",
                BASE_SHA=BASE_SHA, HEAD_SHA=HEAD_SHA, RUNNER_TEMP=directory,
                GIT_CALLS=str(root / "git-calls.jsonl"), GIT_INFO=str(info),
            )
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", "\n".join(body)],
                cwd=root, env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in (root / "git-calls.jsonl").read_text().splitlines()]
            self.assertEqual(calls[0], {
                "argv": ["fetch", "--depth=1", "origin", BASE_SHA],
                "config": {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                           "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {auth}"},
            })
            self.assertGreater(len(calls), 1)
            for call in calls:
                self.assertNotIn(token, " ".join(call["argv"]))
                self.assertNotIn(auth, " ".join(call["argv"]))
            for call in calls[1:]:
                self.assertEqual(call["config"], {})
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertNotIn(auth, result.stdout + result.stderr)

    def test_existing_comments_are_listed_by_the_workflow_with_pagination(self):
        """GitHub returns 30 comments per page; findings past the first page would be
        repeated on later runs."""
        step = self.step_named("Existing review comments")
        comments = f"repos/{REPO}/pulls/{NUMBER}/comments"
        self.assertIn(
            'gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/comments" | jq "$trusted"', step
        )
        self.assertIn(
            'gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" | jq "$trusted"', step
        )
        self.assertIn("PR_NUMBER: ${{ github.event.pull_request.number }}", step)
        self.assertNotIn("${{", step.split("run:")[1])
        # Anyone can comment on a public pull request; the model reads the trusted authors' comments.
        self.assertIn(
            """trusted='[.[][] | select(.user.type == "Bot" or """
            """(.author_association | IN("OWNER", "MEMBER", "COLLABORATOR")))]'""", step
        )
        self.assertIn(f"{RUNNER_TEMP}/review/review-comments.json", self.prompt)
        self.assertIn(f"{RUNNER_TEMP}/review/issue-comments.json", self.prompt)
        self.assertNotIn(comments, self.prompt)

    def test_rust_format_check_runs_rustfmt_alone_with_the_pinned_toolchain(self):
        """cargo-fmt runs `cargo metadata`, which executes the rustc named by a PR-supplied
        .cargo/config.toml, so the trusted step calls rustfmt itself on the changed files
        with the toolchain the workspace lane pins. The step runs before the action, with
        no secret in its environment."""
        step = self.step_named("Rust format check")
        self.assertIn('rustup run "$STABLE" rustfmt --check --edition 2024', step)
        # git quotes non-ASCII paths in --name-only output; -z and xargs -0 pass them intact.
        self.assertIn("git diff -z --name-only", step)
        self.assertIn("xargs -0", step)
        self.assertNotIn("cargo", step)
        self.assertNotIn("secrets.", step)
        lanes = re.search(r'^\s*STABLE: "([^"]+)"', RUST_LANES.read_text(), re.M)
        assert lanes is not None, "rust lanes workflow lacks a STABLE pin"
        self.assertEqual(self.job_env().get("STABLE"), f'"{lanes.group(1)}"')
        self.assertRegex(self.text, r'rustup toolchain install "\$STABLE" --profile minimal --component rustfmt')
        self.assertTrue(CRATES)
        for manifest in CRATES:
            with self.subTest(manifest=manifest.name):
                self.assertIn('edition = "2024"', manifest.read_text())
        self.assertIn(f"{RUNNER_TEMP}/review/rustfmt.txt", self.prompt)
        order = [self.lines.index(f"      - name: {name}") for name in ("Rust format check",)]
        action = next(i for i, line in enumerate(self.lines) if "uses: anthropics/claude-code-action@" in line)
        self.assertLess(order[0], action)

    def test_inline_findings_name_the_head_commit_and_deleted_lines(self):
        action = self.step("anthropics/claude-code-action@")
        self.assertRegex(action, r'classify_inline_comments: "false"')
        self.assertIn(f"commit_id {HEAD_SHA}", self.prompt)
        self.assertIn("side LEFT", self.prompt)

    def test_prompt_points_at_the_pr_copies_of_restored_configuration(self):
        """The action restores .claude/**, .mcp.json, CLAUDE.md and similar paths from the
        base branch and keeps the PR's versions under .claude-pr/."""
        self.assertIn(".claude-pr/", self.prompt)

    def test_summary_is_structured_output_posted_by_the_workflow(self):
        """The model returns the summary as data; a trusted step posts it to this PR and
        refuses a body that carries the job token."""
        schema = re.search(r"--json-schema '(\{.*\})'", self.text)
        assert schema is not None, "claude_args lacks --json-schema"
        self.assertIn('"required":["summary"]', schema.group(1).replace(" ", ""))
        self.assertIn("`summary` field", self.prompt)
        self.assertIn("id: review", self.step("anthropics/claude-code-action@"))
        post = self.step_named("Post review summary")
        self.assertIn("STRUCTURED_OUTPUT: ${{ steps.review.outputs.structured_output }}", post)
        self.assertIn("PR_NUMBER: ${{ github.event.pull_request.number }}", post)
        self.assertNotIn("${{", post.split("run:")[1])
        self.assertRegex(post, r'if grep -qF -- "\$GH_TOKEN" "\$RUNNER_TEMP/review-summary\.md"; then')
        self.assertIn("exit 1", post)
        self.assertRegex(post, r'gh pr comment "\$PR_NUMBER" --repo "\$GITHUB_REPOSITORY" --body-file ')

    def test_allowlist_contains_no_nested_quotes(self):
        """claude_args is split like a shell line; a quote inside a rule ends the list."""
        self.assertNotIn('"', ",".join(self.rules + self.denied))

    def test_draft_close_and_retarget_cancel_a_running_review(self):
        start = next(i for i, line in enumerate(self.lines) if line.strip() == "pull_request_target:")
        types = self.lines[start + 1].strip()
        self.assertTrue(types.startswith("types:"), types)
        for event in ("converted_to_draft", "closed", "edited"):
            self.assertIn(event, types)
        self.assertIn(
            "github.event.action != 'closed' && "
            "(github.event.action != 'edited' || github.event.changes.base != null) && "
            "github.event.pull_request.draft == false",
            " ".join(self.block_after("if: >-").split()),
        )
        # A newer pending run cancels an older pending run in its group even when its own
        # job is later skipped, so a title or body edit must not share the review's group.
        self.assertIn(
            "group: claude-code-review-${{ github.event.pull_request.number }}"
            "${{ github.event.action == 'edited' && github.event.changes.base == null && '-noop' || '' }}",
            self.text,
        )
        self.assertIn("cancel-in-progress: true", self.text)

    def test_model_reachable_token_cannot_write_repository_contents(self):
        action = self.step("anthropics/claude-code-action@")
        self.assertRegex(action, r"github_token: \$\{\{ secrets\.GITHUB_TOKEN \}\}")
        grants = self.job_permissions()
        self.assertNotIn("id-token", grants)
        writes = {scope for scope, level in grants.items() if level == "write"}
        self.assertEqual(writes, {"pull-requests"})
        self.assertEqual(grants.get("contents"), "read")

    def test_prompt_overrides_review_policy_posting_bans(self):
        policy = " ".join(REVIEW_POLICY.read_text().split())
        for sentence in POLICY_POSTING_BANS:
            with self.subTest(sentence=sentence):
                self.assertIn(sentence, policy)
                self.assertIn(f'"{sentence}"', self.prompt)

    def test_checkout_matches_reviewed_head_commit(self):
        checkout = self.step("actions/checkout@")
        self.assertIn(f"ref: {HEAD_SHA_EXPR}", checkout)
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn(f"head commit {HEAD_SHA}", self.prompt)


class ReviewGuidance(unittest.TestCase):
    """Reviewers receive the whole review policy, and its references resolve."""

    def test_review_policy_fits_the_kilo_guidance_limit(self):
        length = guidance_length(REVIEW_POLICY.read_text(encoding="utf-8"))
        self.assertLessEqual(
            length, KILO_GUIDANCE_LIMIT,
            f"REVIEW.md has {length} characters; Kilo truncates past {KILO_GUIDANCE_LIMIT}",
        )

    def test_length_counts_utf16_units(self):
        self.assertEqual(guidance_length("ab"), 2)
        self.assertEqual(guidance_length("\U0001F600"), 2)

    def test_guidance_references_resolve(self):
        for doc in GUIDANCE:
            with self.subTest(doc=doc.relative_to(ROOT).as_posix()):
                self.assertEqual(unresolved(doc), [])

    def test_reference_check_reports_each_broken_or_local_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts/real.py").write_text("")
            (root / "docs/policies").mkdir(parents=True)
            (root / "docs/policies/rules.md").write_text("# Rules\n")
            (root / "other.md").write_text(
                "# Other\n\n## Kept `section`\n\n## Kept `section`\n\n"
                "```text\n# Fenced\n```\n\n## Café [linked](x.md) ##\n"
            )
            doc = root / "guide.md"
            doc.write_text(
                "# Guide\n\n"
                "[a](missing.md) [b](#absent) [c](other.md#gone) [d](other.md#fenced)\n"
                "[e](other.md#kept-section) [f](other.md#kept-section-1) [g](#guide)\n"
                "[h](other.md#café-linked) [i](<other.md>) [j](https://example.com/x)\n"
                '[k](titled.md "Title") [l](docs/policies/rules.md)\n\n'
                "[ref]: referenced.md\n\n"
                "Read `scripts/real.py`, `scripts/gone.py`, `scripts/real.py:3`,\n"
                "`docs/policies/rules.md` and `docs/policies/`.\n\n"
                "```text\n[z](fenced-link.md) `scripts/fenced.py`\n```\n"
            )
            self.assertEqual(unresolved(doc, root), [
                "missing.md", "#absent", "other.md#gone", "other.md#fenced",
                "titled.md", LOCAL_ONLY_MARK + "docs/policies/rules.md", "referenced.md",
                "scripts/gone.py", LOCAL_ONLY_MARK + "docs/policies/rules.md",
            ])

    def test_reference_check_reports_a_missing_chaos_path_and_a_missing_bare_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            doc = root / "guide.md"
            doc.write_text("# Guide\n\nRead `chaos/gone.md` under `chaos/`, beside `scripts/`.\n")
            self.assertEqual(unresolved(doc, root), ["chaos/gone.md", "chaos/"])

    def test_the_guide_renders_the_claim_in_place_of_the_claim_entry(self):
        guide = (ROOT / "docs/agents/chaos.md").read_text(encoding="utf-8")
        section = guide[guide.index("## The readiness claim"):]
        block = section[section.index("```sh\n") + len("```sh\n"):]
        render = block[:block.index("\n)\n") + len("\n)\n")]
        self.assertTrue(render.startswith("(\n"), render)
        stub = "import os, sys\nprint('rendered')\nsys.exit(int(os.environ.get('FAIL', '0')))\n"
        for case in ("plain", "link", "directory", "failing"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "chaos/tools").mkdir(parents=True)
                (root / "chaos/tools/validate_contract.py").write_text(stub)
                claim, target, staged = root / "chaos/READINESS.md", root / "target.md", root / "staged.md"
                target.write_text("target\n")
                staged.write_text("staged\n")
                (root / "chaos/READINESS.md.new").symlink_to(staged)
                if case == "link":
                    claim.symlink_to(target)
                elif case == "directory":
                    claim.mkdir()
                else:
                    claim.write_text("old\n")
                env = dict(os.environ, FAIL="1" if case == "failing" else "0")
                done = subprocess.run(("bash", "-c", render), cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(done.returncode, 1 if case in ("directory", "failing") else 0, done.stderr)
                self.assertEqual((target.read_text(), staged.read_text()), ("target\n", "staged\n"))
                self.assertEqual(sorted(p.name for p in (root / "chaos").iterdir()),
                                 ["READINESS.md", "READINESS.md.new", "tools"])
                if case == "directory":
                    self.assertEqual(list(claim.iterdir()), [])
                else:
                    self.assertFalse(claim.is_symlink())
                    self.assertEqual(claim.read_text(), "old\n" if case == "failing" else "rendered\n")
                    if case != "failing":
                        self.assertEqual(claim.stat().st_mode & 0o777, 0o644)

    def test_reference_check_reports_a_file_where_a_reference_names_a_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "chaos").write_text("")
            (root / "scripts").mkdir()
            (root / "scripts/real.py").write_text("")
            doc = root / "guide.md"
            doc.write_text("# Guide\n\n`chaos/` `scripts/` `scripts/real.py/` [a](chaos/) [b](scripts/) [c](chaos)\n")
            self.assertEqual(unresolved(doc, root), ["chaos/", "chaos/", "scripts/real.py/"])

    def test_reference_check_closes_a_fence_only_on_a_matching_fence(self):
        # A shorter run or a run with an info string lies inside the block. Taking
        # either as the close makes the real closing fence open a new block, which
        # hides the references that follow it.
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "guide.md"
            doc.write_text(
                "# Guide\n\n"
                "````markdown\n```\n[a](inside-long.md)\n````\n\n"
                "[b](after-long.md)\n\n"
                "```markdown\n```text\n[c](inside-info.md)\n```\n\n"
                "[d](after-info.md)\n"
            )
            self.assertEqual(unresolved(doc, Path(tmp)), ["after-long.md", "after-info.md"])

    def test_reference_check_reports_targets_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "scripts").mkdir(parents=True)
            (root / "scripts/real.py").write_text("")
            (Path(tmp) / "host.md").write_text("# Host\n")
            (root / "docs").mkdir()
            doc = root / "docs/guide.md"
            doc.write_text("# Guide\n\n[up](../../host.md) [abs](/scripts/real.py) [gone](/scripts/gone.py)\n")
            self.assertEqual(unresolved(doc, root), [OUTSIDE_MARK + "../../host.md", "/scripts/gone.py"])

    def test_reference_check_resolves_a_root_reached_through_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            (real / "scripts").mkdir(parents=True)
            (real / "scripts/real.py").write_text("")
            link = Path(tmp) / "link"
            link.symlink_to(real, target_is_directory=True)
            (real / "guide.md").write_text("# Guide\n\n[a](scripts/real.py) `scripts/real.py`\n")
            self.assertEqual(unresolved(link / "guide.md", link), [])

    def test_reference_check_reads_footnotes_as_footnotes(self):
        # A footnote's text is prose; a link inside it is still checked.
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "guide.md"
            doc.write_text(
                "# Guide\n\nText[^1] and more[^note].\n\n"
                "[^1]: Some note\n"
                "[^note]: See [x](gone.md).\n"
                "[ref]: referenced.md\n"
            )
            self.assertEqual(unresolved(doc, Path(tmp)), ["gone.md", "referenced.md"])

    def test_reference_check_rejects_a_target_outside_the_root(self):
        # A clean clone holds only the tree under root, so a reference resolves
        # only when its target lies inside root.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "docs").mkdir(parents=True)
            (Path(tmp) / "outside.md").write_text("# Outside\n")
            doc = root / "docs/guide.md"
            doc.write_text("# Guide\n\n[a](../../outside.md) [b](../../outside.md#outside)\n")
            self.assertEqual(
                unresolved(doc, root),
                [OUTSIDE_MARK + "../../outside.md", OUTSIDE_MARK + "../../outside.md#outside"],
            )

    def test_reference_check_reads_an_angle_bracket_destination_with_spaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "present guide.md").write_text("# There\n")
            doc = root / "guide.md"
            doc.write_text(
                "# Guide\n\n[a](<missing guide.md>) [b](<present guide.md#there>)\n"
                '[c](<present guide.md#gone> "Title")\n\n'
                "[r]: <present guide.md#there>\n[s]: <missing guide.md>\n"
            )
            self.assertEqual(
                unresolved(doc, root), ["missing guide.md", "present guide.md#gone", "missing guide.md"]
            )

    def test_heading_anchors_disambiguate_against_every_earlier_anchor(self):
        # GitHub suffixes a repeated slug until the result is unused anywhere, so a
        # literal `Foo-1` after two `Foo` headings becomes `foo-1-1`, and a third
        # `Foo` continues its own counter to `foo-2`.
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "guide.md"
            doc.write_text("# Foo\n\n# Foo\n\n# Foo-1\n\n# Bar-1\n\n# Bar\n\n# Bar\n\n# Foo\n")
            self.assertEqual(
                heading_anchors(doc), {"foo", "foo-1", "foo-1-1", "bar-1", "bar", "bar-2", "foo-2"}
            )

    def test_heading_anchors_drop_a_link_destination_with_balanced_parentheses(self):
        # A destination may hold one level of balanced parentheses, so the slug keeps
        # the link text alone; an unbalanced `(` leaves the brackets literal text.
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "guide.md"
            doc.write_text("## [Restore](manual_(ops))\n## [Release](manual_(staging).md) now\n## [Open](x(y) end\n")
            self.assertEqual(heading_anchors(doc), {"restore", "release-now", "openxy-end"})


def guidance_length(text):
    """Return the length of text in UTF-16 code units, never fewer than code points."""
    return max(len(text), len(text.encode("utf-16-le")) // 2)


FENCE = re.compile(r"\s{0,3}(`{3,}|~{3,})(.*)")


def prose_lines(text):
    """Yield the lines of Markdown text that lie outside fenced code blocks.

    As CommonMark specifies, a block closes only on a run of its opening fence
    character at least as long as the opening run, followed by whitespace alone.
    """
    fence = None
    for line in text.splitlines():
        marker = FENCE.match(line)
        if fence is None:
            if marker:
                fence = marker.group(1)
                continue
            yield line
        elif (marker and marker.group(1)[0] == fence[0]
              and len(marker.group(1)) >= len(fence) and not marker.group(2).strip()):
            fence = None


def local_only(relative):
    return relative.startswith(LOCAL_ONLY)


DESTINATION = r"(?:<([^>]*)>|([^)\s>]+))"
LINK = re.compile(r"\]\(\s*" + DESTINATION + r"""(?:\s+(?:"[^"]*"|'[^']*'))?\s*\)""")
# A `[^label]:` line defines a footnote, whose text is prose.
REFERENCE = re.compile(r"^\s{0,3}\[(?!\^)[^\]]+\]:\s*" + DESTINATION)
CODE_PATH = re.compile(
    r"`((?:chaos|crates|docs|scripts|verification|tla|quint|\.github|\.githooks)/[^`\s*<>{}]*"
    r"|REVIEW\.md|AGENTS\.md|\.gitignore|Cargo\.toml)`"
)


def unresolved(doc, root=ROOT):
    """Return the references in doc that a clean clone of root cannot follow.

    A Markdown link resolves from doc's directory, or from root when it starts
    with `/`, and a backticked repository path from root. A reference is
    reported with OUTSIDE_MARK when its target lies outside root, plainly when
    its file or heading anchor is missing or a reference that ends in `/` names
    something other than a directory, and with LOCAL_ONLY_MARK when it
    names a file `.gitignore` keeps out of every clone, even where a local copy
    exists. A local-only directory named as a whole is allowed.
    """
    root = root.resolve()
    lines = list(prose_lines(doc.read_text(encoding="utf-8")))
    found = []
    for line in lines:
        matches = [*LINK.finditer(line), *REFERENCE.finditer(line)]
        targets = [m.group(1) or m.group(2) or "" for m in matches]
        for target in targets:
            if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:|//", target):
                continue
            path, _, anchor = target.partition("#")
            path = path.partition("?")[0]
            if path.startswith("/"):
                resolved = (root / path.lstrip("/")).resolve()
            else:
                resolved = (doc.parent / path).resolve() if path else doc.resolve()
            found.append((target, resolved, anchor, path.endswith("/")))
    for line in lines:
        for match in CODE_PATH.finditer(line):
            text = re.sub(r":\d+(?::\d+)?$", "", match.group(1))
            path, _, anchor = text.partition("#")
            if not (path.endswith("/") and local_only(path)):
                found.append((text, (root / path).resolve(), anchor, path.endswith("/")))
    missing = []
    for text, path, anchor, directory in found:
        relative = os.path.relpath(path, root)
        if relative.split(os.sep)[0] == os.pardir:
            missing.append(OUTSIDE_MARK + text)
        elif local_only(relative):
            missing.append(LOCAL_ONLY_MARK + relative)
        elif not path.exists() or directory and not path.is_dir() or (
            anchor and anchor not in heading_anchors(path)
        ):
            missing.append(text)
    return missing


def heading_anchors(path):
    """Return the anchors GitHub generates for the ATX headings in a Markdown file.

    A repeated slug takes the suffix `-N`, with N raised until the result differs
    from every earlier anchor.
    """
    if path.suffix != ".md" or not path.is_file():
        return set()
    seen = {}
    for line in prose_lines(path.read_text(encoding="utf-8")):
        heading = re.match(r"\s{0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$", line)
        if not heading:
            continue
        title = re.sub(r"!?\[([^\[\]]*)\]\([^()]*(?:\([^()]*\)[^()]*)*\)", r"\1", heading.group(1)).lower()
        slug = anchor = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        while anchor in seen:
            seen[slug] += 1
            anchor = f"{slug}-{seen[slug]}"
        seen[anchor] = 0
    return set(seen)


if __name__ == "__main__":
    unittest.main()
