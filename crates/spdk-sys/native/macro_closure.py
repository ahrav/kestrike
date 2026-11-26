"""Writes a preprocessed header with only the macro definitions allowlisted macros reach.

Usage: macro_closure.py <header> <output> <allowlist regex> <preprocessor command...>

bindgen emits only the macros its variable allowlist names, and runs one clang
macro fallback reparse for each macro of its input that its expression parser
rejects. The output keeps every non-directive line of the header, every #undef,
and the #define lines of the allowlisted macros and of each macro whose name
appears in a kept definition or on a #pragma line. Every other #define, and
every definition the compiler or its command line supplies, becomes an empty
line, so the line markers keep numbering the declarations after them and the
preprocessor command supplies those definitions again. Token pasting can form
a macro name that appears in no definition, so the preprocessor command
expands each kept macro at line 1 of one presumed file after all of the
header's definitions and after the kept ones, and the script fails unless both
expansions agree line for line. A kept definition that names __COUNTER__ fails
the run: its first expansion consumed counter state the kept header cannot
replay.
"""
import re
import subprocess
import sys

header, output, allowlist, cpp = sys.argv[1], sys.argv[2], re.compile(sys.argv[3]), sys.argv[4:]
try:
    with open(header) as source:
        lines = source.read().split("\n")
except OSError as error:
    sys.exit(f"macro_closure.py: cannot read {header}: {error}")

directive = re.compile(r"#(?:define|undef) ([A-Za-z_]\w*)(.*)")
marker = re.compile(r'# \d+ "([^"]*)"')
pragma = re.compile(r"#\s*pragma\b(.*)")
identifier = re.compile(r"[A-Za-z_]\w*")
bodies = {}
supplied = set()
origin = None
for index, line in enumerate(lines):
    if m := marker.match(line):
        origin = m.group(1)
    elif m := directive.match(line):
        bodies.setdefault(m.group(1), []).append(m.group(2))
        if origin in ("<built-in>", "<command line>"):
            supplied.add(index)
allowed = sorted(name for name in bodies if allowlist.fullmatch(name))
if not allowed:
    sys.exit(f"macro_closure.py: no definition in {header} matches the allowlist")
roots = [name for line in lines if (m := pragma.match(line)) for name in identifier.findall(m.group(1)) if name in bodies]
kept = set(allowed)
pending = allowed + roots
while pending:
    name = pending.pop()
    if name in bodies and name not in kept:
        kept.add(name)
    for body in bodies.get(name, ()):
        pending.extend(dependency for dependency in identifier.findall(body) if dependency in bodies and dependency not in kept)
for name in sorted(kept):
    if any("__COUNTER__" in identifier.findall(body) for body in bodies[name]):
        sys.exit(f"macro_closure.py: {name} names __COUNTER__, whose state the kept definitions cannot replay")


def kept_line(index, line):
    """The output line for one header line: a dropped or supplied directive becomes an empty line."""
    m = directive.match(line)
    if m is None or (line.startswith("#undef") or m.group(1) in kept) and index not in supplied:
        return line
    return ""


def expansions(definitions):
    """Preprocesses the definitions, then one `"name" name` line per kept macro, each at line 1 of `probe`.

    The reset before every probe line keeps __LINE__ and the output's spacing the same after either
    preamble, and the quoted name labels a result without expanding the name."""
    probe = list(definitions)
    for name in sorted(kept):
        probe += ['#line 1 "probe"', f'"{name}" {name}']
    run = subprocess.run(cpp, input="\n".join(probe) + "\n", capture_output=True, text=True)
    if run.returncode != 0:
        sys.exit(f"macro_closure.py: the preprocessor failed: {run.stderr[-2000:]}")
    rows = [line for line in run.stdout.split("\n") if line.strip()]
    if [row.split(maxsplit=1)[0] for row in rows] != [f'"{name}"' for name in sorted(kept)]:
        sys.exit("macro_closure.py: the preprocessor printed other rows than one per kept macro")
    return rows


kept_lines = [kept_line(index, line) for index, line in enumerate(lines)]
reduced = expansions([line for line in kept_lines if directive.match(line)])
full = expansions([line for line in lines if directive.match(line)])
if reduced != full:
    only_kept = sorted(set(reduced) - set(full))[:10]
    only_full = sorted(set(full) - set(reduced))[:10]
    sys.exit(
        "macro_closure.py: the kept definitions change these expansions; "
        f"kept definitions: {only_kept}; all definitions: {only_full}"
    )
try:
    with open(output, "w") as target:
        target.write("\n".join(kept_lines))
except OSError as error:
    sys.exit(f"macro_closure.py: cannot write {output}: {error}")
