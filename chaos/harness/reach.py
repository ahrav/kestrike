#!/usr/bin/env python3
"""Probe a credential fence of the chaos contract, or print who the campaign runs as.

    python3 -I chaos/harness/reach.py identity
    python3 -I chaos/harness/reach.py aws ARGUMENTS...
    python3 -I chaos/harness/reach.py token-scope workflow

A fence row starts the script in python3's isolated mode, `-I`, so its imports come
from the interpreter's installation and a file beside it stays unread.

`identity` prints the Unix user, the AWS role and the GitHub login of github.com the
campaign runs as, with no account number, and exits 0.

`aws` runs the AWS CLI in the worker's region, `us-west-2`, with every endpoint
override of the environment and the configuration removed and the CLI's auto-prompt
off, and with ARGUMENTS only when they equal one of the three probes of
`chaos/ledger.json`, word for word: `s3api list-buckets`, a dry run of
`ec2 stop-instances` on this worker's own instance, and a dry run of
`ec2 create-volume`. Each is a read or a dry run, so the call changes nothing when
the fence fails. The instance id `self`, the value of `--instance-ids`, stands for this
worker's own instance: an instance role's session takes the instance id as its name.
The script reads the CLI's error line for the probe's own operation, which starts
`aws: [ERROR]:`, only after the CLI's exit 254, its status for an answer of the service. It exits 0 when
the call went through or the dry run answered `DryRunOperation`, and 1 when AWS
refused that operation with `AccessDenied` or `UnauthorizedOperation`; then it prints
that error line, with every IAM unique id replaced by `<id>`, every 12-digit account
number by `<account>` and the encoded authorization message cut, and the CLI's exit
status. Any other answer exits 2 and prints neither the CLI's output nor its error
text, so a refusal's text appears only beside exit 1.

`token-scope workflow` reads, with `GH_HOST` and the enterprise tokens removed from the
environment, the OAuth scopes that github.com reports in the response
headers for the credential `gh` has stored for it. It exits 1 with "the token lacks the
scope workflow" when the list is well formed and holds no `workflow`, and 0 when it
holds it. `gh` and git's credential helper `gh auth git-credential` both take the
token of `GH_TOKEN` or `GITHUB_TOKEN` in place of the stored credential, so with
either variable set `identity` and `token-scope` exit 2 before any `gh` call: a
receipt then exists only for an environment in which a push takes the stored
credential, the one whose scopes were read. No other OAuth scope includes `workflow`, so its absence from the list is the
token's refusal. GitHub refuses a push over HTTPS that creates or changes a file under
`.github/workflows/` from a token without that scope, except a file whose path and
contents already stand on another branch of the repository, and the refusal comes
only at push time, so the scope list is the boundary a probe can read. A fine-grained
or app token reports no OAuth scope list, and the probe then exits 2.

Exit 2 means the arguments are wrong, a token variable stands in for the stored GitHub
credential, a command could not be started, its answer could not be read or ran past
65,536 bytes, or the probe's time of 100 s ran out.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time

# The deadline stays below the 120 s after which probe_fence.py kills this script,
# so this script ends its own child first.
DEADLINE_S = 100
LIMIT = 65536
HOST = "github.com"
ACCOUNT = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
ENCODED = re.compile(r"Encoded authorization failure message: \S+")
UNIQUE = re.compile(r"(?<![A-Z0-9])A[A-Z]{3}[A-Z0-9]{16,17}(?![A-Z0-9])")
ARN = re.compile(r"arn:aws[a-z-]*:sts::[0-9]{12}:assumed-role/([\w+=,.@-]+)/([\w+=,.@-]+)")
ERROR = re.compile(r"aws: \[ERROR\]: An error occurred \(([A-Za-z.]+)\) when calling the ([A-Za-z]+) operation")
SCOPE = re.compile(r"[a-z_]+(?::[a-z_]+)?")
USER = re.compile(r"[a-z_][a-z0-9_.-]*")
LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
PROBES = {
    ("s3api", "list-buckets"): ("ListBuckets", ("AccessDenied",)),
    ("ec2", "stop-instances", "--dry-run", "--instance-ids", "self"): ("StopInstances", ("UnauthorizedOperation",)),
    ("ec2", "create-volume", "--dry-run", "--size", "1", "--availability-zone", "us-west-2a"): (
        "CreateVolume",
        ("UnauthorizedOperation",),
    ),
}
REGION = "us-west-2"
START = time.monotonic()


def environment() -> dict[str, str]:
    """The inherited environment with every endpoint override removed and the worker's region pinned."""
    drop = ("AWS_ENDPOINT_URL", "AWS_REGION", "AWS_DEFAULT_REGION", "GH_HOST", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
    env = {key: value for key, value in os.environ.items() if not key.startswith(drop)}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_CLI_AUTO_PROMPT="off", AWS_CLI_ERROR_FORMAT="legacy")
    return env


def redact(output: str) -> str:
    output = ENCODED.sub("Encoded authorization failure message: <cut>", output)
    return ACCOUNT.sub("<account>", UNIQUE.sub("<id>", output))


def fail(message: str) -> int:
    print(redact(f"reach: {message}")[:400], file=sys.stderr)
    return 2


def run(command: list[str]) -> tuple[int, str, str]:
    """The command's status, standard output and standard error, within the probe's time."""
    remaining = DEADLINE_S - (time.monotonic() - START)
    if remaining <= 0:
        raise SystemExit(fail(f"the probe's {DEADLINE_S} s ran out before {command[0]}"))
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=environment(), start_new_session=True)
    except OSError as error:
        raise SystemExit(fail(f"cannot run {command[0]}: {type(error).__name__}")) from error
    try:
        stdout, stderr = child.communicate(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        raise SystemExit(fail(f"{command[0]} ran past the probe's {DEADLINE_S} s")) from error
    if len(stdout) > LIMIT or len(stderr) > LIMIT:
        raise SystemExit(fail(f"{command[0]} printed more than {LIMIT} bytes"))
    out, err = stdout.decode("utf-8"), stderr.decode("utf-8")
    return child.returncode, out, err


def gh_api(*arguments: str) -> tuple[int, str, str]:
    """`gh api` on github.com with the stored credential, which a push takes when no token variable is set."""
    set_names = [name for name in ("GH_TOKEN", "GITHUB_TOKEN") if name in os.environ]
    if set_names:
        raise SystemExit(fail(f"{' and '.join(set_names)} set in the environment, where gh and git's credential helper take "
                              "that token in place of the stored credential; unset it and run the probe again"))
    return run(["gh", "api", "--hostname", HOST, *arguments])


def one_line(text: str, form: re.Pattern[str]) -> str | None:
    """The text without its trailing newline when it is one line of the given form."""
    line = text.removesuffix("\n")
    return line if form.fullmatch(line) else None


def assumed_role() -> tuple[str, str] | None:
    """The campaign's AWS role and its session name, from the caller's ARN."""
    status, out, _ = run(["aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text"])
    match = ARN.fullmatch(out.removesuffix("\n")) if status == 0 else None
    return (match.group(1), match.group(2)) if match else None


def identity() -> int:
    status, out, _ = run(["id", "-un"])
    user = one_line(out, USER) if status == 0 else None
    if user is None:
        return fail("cannot read the Unix user from id -un")
    status, out, _ = gh_api("user", "--jq", ".login | strings")
    login = one_line(out, LOGIN) if status == 0 else None
    if login is None:
        return fail(f"cannot read the GitHub login of {HOST}")
    role = assumed_role()
    if role is None:
        return fail("cannot read the AWS role from aws sts get-caller-identity")
    print(redact(f"unix user {user}; aws role {role[0]}; github login {login}"))
    return 0


def aws(arguments: list[str]) -> int:
    probe = PROBES.get(tuple(arguments))
    if probe is None:
        return fail("the arguments are none of the three probes of chaos/ledger.json")
    operation, refusals = probe
    if arguments[-2:] == ["--instance-ids", "self"]:
        role = assumed_role()
        if role is None or not re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", role[1]):
            return fail("cannot read this worker's instance id from its role session")
        arguments = [*arguments[:-1], role[1]]
    status, _, err = run(["aws", *arguments])
    if status == 0:
        print(f"aws: the {operation} call went through\naws exit 0")
        return 0
    if status != 254:
        return fail(f"aws exit {status}, which is no answer of the service")
    lines = [(match.group(1), line) for line in err.split("\n") if (match := ERROR.match(line)) and match.group(2) == operation]
    if len(lines) != 1:
        return fail(f"aws exit {status} with {len(lines)} error lines for the operation {operation}")
    code, line = lines[0]
    if (code == "DryRunOperation" and "--dry-run" in arguments) or code in refusals:
        print(f"{redact(line).strip()}\naws exit {status}")
        return 0 if code == "DryRunOperation" else 1
    return fail(f"aws exit {status} with the error code {code} for {operation}, which is no refusal of it")


def token_scope(scope: str) -> int:
    if scope != "workflow":
        return fail("token-scope reads only the scope workflow, which no other OAuth scope includes")
    status, out, _ = gh_api("--include", "/")
    head, blank, _ = out.replace("\r\n", "\n").partition("\n\n")
    if status != 0 or not blank:
        return fail(f"gh api exit {status}; cannot read the response headers of {HOST}")
    fields = [line.split(":", 1)[1] for line in head.split("\n")[1:] if line.lower().startswith("x-oauth-scopes:")]
    if len(fields) != 1 or not fields[0].strip():
        return fail(f"{HOST} reported no OAuth scope list for this token, as for a fine-grained or app token, so this probe cannot bound it")
    scopes = sorted(word.strip() for word in fields[0].split(","))
    if not all(SCOPE.fullmatch(word) for word in scopes):
        return fail(f"the OAuth scope list of {HOST} is malformed")
    if scope in scopes:
        print(f"the token holds the scope {scope}")
        return 0
    print(f"the token lacks the scope {scope}; its scopes are {', '.join(scopes)}")
    return 1


def main() -> int:
    command, arguments = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else ("", [])
    try:
        if command == "identity" and not arguments:
            return identity()
        if command == "aws" and arguments:
            return aws(arguments)
        if command == "token-scope" and len(arguments) == 1:
            return token_scope(arguments[0])
    except Exception as error:
        return fail(f"stopped by {type(error).__name__}")
    return fail("usage: reach.py identity | aws PROBE-ARGUMENTS | token-scope workflow; see the file's docstring")


if __name__ == "__main__":
    sys.exit(main())
