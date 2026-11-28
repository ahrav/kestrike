Check the ordering catalog in verification/orderings/expected.json against the scoped production files, and run each
row's weakening against its model tests in a copy of the checkout.

Usage:
  weaken-orderings check
  weaken-orderings run --work DIR [--row ID]...

The catalog names the scoped `files`, the production files the GenMC kernel
package compiles by `#[path]`, and holds one row per site and step. A site
is one `Ordering` stronger than `Relaxed`, or one fence call, in a file's
production text: its text with each test-only element blanked, as
the tools library's `production_text::blanked` returns it. An element ends at
the close of its first `{...}` block at the latest, and the text of an
element that continues past that block is read as production text. A
scoped file holds no element that `analyzed` there lists as cut: each
test-only element ends at the same offset under every reading that applies
where it stands, at no `,` that may lie among its own generic arguments or
closure parameters, and, unless it is an item or a statement, outside
every macro's tokens. Sites are matched outside comments and literals. A
fence call is a call of a path, a leading `::` included, whose last
segment holds `fence`, declarations and definitions
aside. A hook of `HOOKS` mentioned as `S::NAME` is excluded by name while
the file holds at least one definition of it with a body and every such
body is empty; the rule reads only that file. An ordering passed directly
to a fence call belongs to the fence; an ordering nested deeper in the
fence's arguments is a site of its own. A scoped file's production text
spells each ordering variant as part of an `Ordering::` path and names
each fence path only in a path call whose callee the matcher delimits
whole, a macro fragment, or a forwarder invocation
`name!(<type>, std::sync::atomic::fence);`. Each `$fence` call sits in
the body of a `macro_rules!` that is one arm
`($name:ty, $fence:path) => {..}`. That macro's production invocations, at
least one, all pass `std::sync::atomic::fence`, lie among no other macro's
tokens and follow the definition with only blank text between, so each
invocation expands that arm; no other macro receives the std fence. This
binds each forwarder's source text to the std fence; the type argument
stays free.

A step is one level of weakening: `SeqCst` goes to `Acquire` for a `load`,
`Release` for a `store` and `AcqRel` for an `rmw`; `AcqRel` goes to
`Acquire` and to `Release`, so its site takes two rows; `Release` and
`Acquire` go to `Relaxed`; a `fence` row deletes the call and a `;`
directly after it. The matcher reads the `op` of an ordering from the
atomic method, called as `receiver.method(...)`, whose argument it is. A
compare-exchange's success ordering is an `rmw` and its failure ordering a
`load`, and `fetch_update`'s set and fetch orderings are an `rmw` and a
`load`, each read by argument position while no earlier argument holds
`<` or `>` outside brackets. The `op` of a strength constant, a
`const NAME: Ordering` item, comes from each `S::NAME` mention in its
file's scanned production text: the mentions must all sit in atomic calls
of one op. A constant with no such mention takes its op from `EXTERNAL`,
a pin kept by hand and keyed by the defining file and the constant's
name: `RELOAD` of `storage/credit.rs` reaches `record_credits` in
`storage/lease.rs` as `S::RELOAD`, and both of its `credit::credits` calls
load with it. Any other constant with no mention is unread. The row's
`op` must agree with the one the matcher reads.

A row holds `id`, `path`, `find`, text that occurs exactly once in the
file's production text and holds exactly one site, `replace`, the `find`
after one step, and `op` (`load`, `store`, `rmw` or `fence`). It may hold
a GenMC `binding` and a `twin` list. Each twin entry names a `lane`
(`loom`, `genmc` or `rc11`), a `test` and `steps`, the positive number of
steps by which that existing control weakens the same site; only a
one-step twin predicts the row's own result. A row holds exactly one
disposition:

- `kill`: a nonempty list with at most one entry per lane, each `lane`
  (`loom` or `genmc`), `tests` and `failure`, recording that the named
  tests failed with `failure` under the row's plant;
- `survives`: `reason` and `passed`, a list of `lane` and `tests` entries
  that passed under the plant, empty when no model run decides the site;
- `unrun`: `needs`, a list of `lane`, `tests` and `failure` entries naming
  the runs that decide the row and a failure each would count as a kill,
  or an empty list beside a `reason` that states why no model run decides
  the site.

The rows whose sites no model run decides are those of `UNMODELED`, a pin
kept by hand and keyed by row id. Only they may hold an empty `passed` or
`needs`; every other row names at least one run.

A `kill` or `survives` row records the `revision`, the 40-hex-digit
commit, of the run that set it. A row without a binding names its
enclosing item in `scope`, given as a binding's `scope` is: the nested
item headers, an `impl` header for a strength constant. An item's body is
the first `{` block after its header, and a `;` before that brace ends the
search, so a header whose signature holds a `;`, such as `[W; N]`, is
named through its return type. A bound row's enclosing item is its
binding's production scope, and its `find` holds the binding's call. The
binding guard of the GenMC judge holds that call to its scope.

A loom test's model source is the module file its path reaches from
`crates/kestrike/src/mod.rs`: each module the path names is loaded by
its parent's declaration, a `#[path]` one or a bare `mod name;`, read as
the scope rule below reads declarations, and the last file reached
declares the remaining module inline. A module that its parent declares
more than once, inline or by two files, has no model source. A GenMC
case's kernel file is the one file of the kernel package named
`<family>_kernel.rs`, the family being the leading lowercase letters of the
case name; `check` and `run` find it by the same rule.

An included file is classified by the declarations that load it and by
the standing of each module file that holds one, read up to the crate
root: `mod.rs`, `lib.rs` and `main.rs` of `crates/kestrike/src`, which
stand as production. A bare `mod name;` loads `name.rs` or `name/mod.rs`
from the directory its module file's declarations load from: the crate's
source directory for a root, `D` for `D/mod.rs`, `D` for the sibling
`D.rs` that a bare `mod D;` loads, and its own directory for a file a path
attribute loads. A `#[path = "..."]` on a `mod` item loads that path from
the module file's own directory. Inside inline `mod` blocks both load from
the declaring directory extended by the blocks' names. A module file's
standing is the standing its own declarations give it, and only a module
file with standing gives one: a live declaration passes its module file's
standing on, a declaration inside a test-only item of a production module
file excludes, and an excluded module file excludes. A path attribute
counts in a root, in a module file whose bare declarations load from the
included file's directory, and nowhere else: a declaration from another
crate source is refused. The crate sources searched for path attributes
are those whose committed text holds one. The file is production when a
chain of live declarations from a root loads it, and excluded when every
chain that loads it passes a test-only item. Among the tokens of a macro,
a `macro_rules!` definition or an invocation, a path attribute or a `mod`
keyword loads nothing. A module name may be a raw identifier.

`check` refuses, each by name:

- `unrowed site`: a site that no accepted row's `find` holds; `site rows`:
  a site whose rows are not one per step;
- `find`: a `find` that does not occur exactly once in its file's
  production text, or that holds other than one site;
- `step`: a `replace` that is not its `find` after one step for its `op`,
  an `op` the matcher reads otherwise, or a rowed site whose `op` the
  matcher cannot read;
- `spelling`: in a scoped file's production text, an ordering variant
  outside an `Ordering::` path, a test-only element that `analyzed` lists
  as cut, a glob import of `Ordering`'s variants, an
  `Ordering as` rename, a fence path named outside a call, a fence called
  as a method, a fence callee the matcher cannot delimit, a `$fence` call
  outside a `macro_rules!` body, a macro holding a `$fence` call that is
  never invoked, is invoked among another macro's tokens, whose
  invocations pass another fence, that is not one arm
  `($name:ty, $fence:path) => {..}` or that an invocation does not
  directly follow, or a macro that receives `std::sync::atomic::fence`
  and holds no `$fence` call;
- `scope file`: a production file the kernel package includes by `#[path]`
  that `files` lacks, a listed file the package does not include as
  production, a listed file that cannot be read, a file the package
  includes from outside the repository, an included file that no module
  file declares through declarations that reach the crate root or that
  only a path attribute outside its module files and the crate root
  declares, a module file that cannot be read, a module file holding
  a path attribute the scope rule cannot read, or a path attribute or a
  `mod` keyword among a macro's tokens, a live path attribute of a
  package source that the shared include scanner misses or a match of
  that scanner outside live code, an include path holding an escape, an
  include inside the package that is no Rust source the scan reads, the
  name `include` in a package source's code, or a scoped file whose
  production text names `include` or holds a path attribute or a `mod`
  keyword, whether it declares a file or opens an inline module (the raw
  identifier `r#mod` is a name); the
  report lists the files declared only in test-only items under
  `excluded`;
- `reference`: a `binding` absent from `verification/genmc/expected.json`,
  bound in another file, holding no call or scope, or whose call the row's
  `find` lacks; a twin list that is no list of entries, a twin whose `test`
  is no twin of its `lane` (a loom control of a loom record of
  `verification/obligations.json`, a GenMC violation case, a `Sometimes`
  litmus test) or whose `steps` is no positive integer, or a lane named
  twice; an entry test that its lane does not hold as positive (for `loom`
  a test a loom record lists under `tests` and no loom record lists under
  `controls`, for `genmc` a `positive` GenMC case); a loom test whose
  model source cannot be read; a loom `failure` that some model source of
  its tests holds in no message literal of an assertion, a panic or an
  `expect`, as the whole literal, its text before the first `{`, or the
  text after one of its `: ` separators, or that more than one message
  literal of one model source holds; or a GenMC `failure` that is not
  the text of exactly one `c"..."` literal that is the last argument of a
  `check!` call in the kernel file of its case's family, or whose family has
  no kernel file;
- `disposition`: a row with no disposition, more than one, or a malformed
  one: a `kill` that is no nonempty list, a `survives` or `unrun` that is
  no object, a missing or blank field such as a `survives` row with an
  empty reason, a lane other than `loom` or `genmc`, `kill` entries
  naming a lane twice, or an empty `passed` or `needs` on a row outside
  `UNMODELED`;
- `enclosing item`: a row without a binding and without a `scope`, or a
  row whose enclosing item resolves to other than one body, whose body
  lacks the row's `find`, or whose site lies in an `fn` or `impl` nested in
  that body;
- `revision`: a `kill` or `survives` row whose `revision` is no string of
  exactly 40 lowercase hex digits;
- `row`: a malformed row: no object, a missing `id`, `path`, `op`, `find`
  or `replace`, a blank or repeated `id`, a `path` outside `files`, an `op`
  outside the four, a key outside the row's fields, both a `binding` and a
  `scope`, or an `id`, `path`, `find`, `replace`, `binding` or `scope`
  value of the wrong type.

The rows of a listed file that is not read are not matched; the file's
own refusal names it. `check` prints one JSON report with the refusals,
each row's disposition (null for a row with none or more than one), the
unrun rows, the site count, the excluded files and `credited`, true
exactly when `check` refuses nothing and no row is unrun. Exit 0 is a
catalog without refusals, unrun rows included; 1 is a refusal; 2 is a
catalog, declaration or package that cannot be read,
reported as `{"error": ...}` on standard output. A usage error exits 2
with the tool's usage text on standard error and no report, and `--help`
prints this text and exits 0.

A passing check shows that each cataloged text is unchanged and that each
site has its rows. The test outcomes live in each row's disposition: the
report maps each row to its disposition and lists the unrun rows. An
entry's `failure` is held to the model source or the kernel file of its
tests, a file that other tests share; the run that sets the disposition
shows which of those tests fails with it. An entry's tests are held to the
positive tests of its lane; that they reach the row's site and ran under
its plant is the claim of the run recorded in the row's `revision`.
Several weakenings keep every row's text and pass: two consumers of one op
that exchange their strength constants, or a consumer edit that leaves its
constant another `S::NAME` mention of the same op; an edit to the consumer
outside the scoped files of a constant `EXTERNAL` pins; any caller
choosing another strength; an ordering taken from a constant defined
outside the scoped files; a word forwarder that ignores the ordering it is
passed; a forwarder invocation on another type beside a hand-written impl
for the production word; a path `std::sync::atomic::fence` that a local
`mod std` resolves elsewhere; and a cataloged statement kept in its item
while a dead branch, a
non-test `cfg`, the text of a test-only element after its first `{...}`
block, or an unreached path holds it and a weaker access does the live
work. Such text follows any first block that does not end its element:
for example the `else` of a test-only `if`, the rest of a `const` or `let`
initializer, the later arguments of a call that holds a closure body or a
struct literal, a method call on a block, a body after a struct pattern,
or an item body after a braced const argument in its header. The
predicates read as test-only are `cfg(test)` and `cfg(all(test, ...))`;
any other `cfg` is read as production text, on a module declaration as on
a site, and an inner `#![cfg(test)]` of a module file is read as
production text too. The scope rule reads `mod.rs`, `lib.rs` and
`main.rs` of the crate's source directory as the crate root; how those
files include one another is outside it. A constant left with no in-file
mention and no `EXTERNAL` pin is refused.

`run` is an operator command. It needs the workflow's `STABLE` toolchain
and, for its Cargo configuration read, the `NIGHTLY` toolchain. It refuses
a `DIR` inside the checkout, a `DIR` that cannot be listed (a regular file
among them), is not empty or cannot hold the copy, and a checkout where
`git status` names a path under `crates/kestrike-tools`, changed or
untracked and not ignored, or a change of the root `Cargo.toml`,
`.cargo/config.toml`, `scripts/tool.sh`, `.github/workflows/agent-checks.yml`
(whose `STABLE` pin the launcher builds the tool with),
`scripts/judge-genmc.py` or `scripts/judge-rc11.py`, which the lane judges
with, so the report's revision names the code that judged it: the launcher
builds the tool from the working tree on each call. The check does not hold
the ignored `Cargo.lock`, which fixes the dependency versions, or a source
restored under an older file time, which Cargo's fingerprint does not see. It copies the checkout's `HEAD` to
`DIR/copy` with `git archive`, prints that revision on standard error,
since uncommitted changes stay out of the copy, and refuses a copy whose
catalog `check` refuses, with the crate sources walked in the copy, or
whose workflow names no `STABLE`, `NIGHTLY` or `LOOM` pin, bare or in
matched quotes. It refuses a planted file whose bytes a text restore cannot
reproduce, such as CR LF line endings. It reads the merged Cargo
configuration with `cargo +NIGHTLY config get` in the copy, and in the
kernel package when a GenMC case is selected, and refuses an entry the
GenMC judge's `check_config` refuses, a `LOOM_*` environment entry when a
loom test is selected, or a read that fails, quoting Cargo's last lines.
When a GenMC case is selected it refuses a copy whose declaration the
copy's GenMC judge refuses on the unweakened sources:
`check_transcription`, a binding whose kernel or production operation
drifted, or `check_correspondence`, a case that disagrees with the litmus
tests it names. A plant then differs from the judged sources in its one
site.
A run with a loom test refuses a copy that resolves a loom version other
than the `LOOM` pin or whose resolution fails. It writes its copy, build
outputs, evidence, `progress.json` and `report.json` under `DIR`; the
toolchains, the GenMC checker the lane builds under
`~/.cache/kestrike-genmc` and Cargo's registry caches are its only writes
elsewhere. Each output is a new file whose name carries a serial number
and, for a planted run, the row's catalog position, never its id. The
selected rows are every row, or each `--row`. A row's entries are its
`kill` entries, its `survives` passed entries or its `unrun` needs; a row
with none is `skipped`, with the row's reason, which agrees with a
`survives` row that no model runs.

First the baseline: each test the selected rows name runs once on the
unweakened copy, and each must give `survived`, or the run stops with exit
3 and no row result, and must leave every scoped file a regular file with
the unweakened copy's digest, or the run stops with exit 4. Then, per row,
`run` writes the plant, the row's
`replace` at its one `find` in the production text, as a new file created
exclusively beside the scoped file, with its mode and a later modification
time, runs each test the row's entries name once and judges that run for
each entry, then checks that the planted file still holds the plant,
writes the unweakened file back the same way, and stops with exit 4 when
the plant had changed, the unweakened file cannot be written back, or any
scoped file is then a symbolic link, no regular file, unreadable or one
whose digest differs from the unweakened copy's. A plant a test removed,
replaced or made unreadable is written back with the unweakened file's
mode. The restore also runs when a
test's run fails or the run is interrupted by SIGINT, SIGTERM or SIGHUP (each
one the invoking shell did not ignore), and it runs with those signals
blocked. From before a row's plant is written until its restore has been
checked, and while a baseline test runs, a handled signal is recorded: it
ends the running test's wait and starts no further test of the row, and
the run ends once that test's process group has ended, through the
restore. Each test runs in its own session; when it
ends, times out or is interrupted, its process group gets SIGTERM, then
SIGKILL once the leader has exited, a further signal arrives or 45 seconds
pass, which outlasts the lane's own 30-second grace.

- A loom test runs as `cargo +STABLE test -p kestrike --lib --release
  TEST -- --exact` in the copy, with the workflow's toolchain pins; every
  `LOOM_*` variable and every compiler, wrapper, flag, target, runner,
  profile and output-directory variable (`RUSTC*`, `RUSTFLAGS`,
  `RUSTDOCFLAGS`, `CARGO_ENCODED_*FLAGS`, `CARGO_BUILD_*` but
  `CARGO_BUILD_JOBS`, `CARGO_TARGET_*`, `CARGO_PROFILE_*`) cleared;
  `RUSTFLAGS="--cfg loom"`, `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`
  under `DIR`, plain Cargo status lines and a 60-minute deadline.
  `killed`: the test failed and a panic in its output reports the location
  of the one assertion, panic or `expect` whose message literal holds the
  entry's `failure`, the line of its macro or method name in the test's
  model source, with the failure in its first message line. `survived`:
  `test result: ok. 1 passed; 0 failed; 0 ignored`, so a filter that
  matches no test, or an ignored test, gives `no verdict`. A planted row's
  results count once `cargo` reports compiling `kestrike` under the
  plant; the row's later tests reuse that build. A loom result records no
  search bound: with every `LOOM_*` variable cleared and refused, the bound
  is the one the test's model source sets at `revision`.
- A GenMC entry runs `bash scripts/rust-lane.sh genmc PROFILE CASE...` in
  the copy, with each case once, `EVIDENCE` under `DIR` and plain Cargo
  status lines, under 20 minutes per case plus 45, the sum of the lane's
  own deadlines and 5 minutes; the profile is `pr` when it holds every
  case, else `scheduled`. `run` judges each case's raw output with the
  tool's GenMC judge over the copy: its configuration and command checks
  first, with the identity record's fields checked for shape, then
  `judge_case`. `survived`: `judge_case` accepts the case's positive
  declaration. `killed`: it accepts that declaration as a violation that
  names the case family's kernel file and the entry's `failure` as its one
  `check!`. A planted case counts once the lane's `cargo check` of the case
  compiled the kernel package.
- Anything else is `no verdict`, with its reason: a timeout, missing
  rebuild evidence, another failure text or assertion, an ignored or
  absent test, a build failure, a crashed test, or a lane output the
  judge refuses.

`progress.json` holds the report so far, rewritten whole before the
baseline, after each baseline test, after each loom test and GenMC batch
of a planted row and after each row, with `active`, the row or `baseline` in progress, or null
between them; a planted row in progress holds no `agrees`. It is the
record of a run that stops after its configuration checks. `report.json`
holds `revision`, the copy's; `pins`, the toolchain pins with the `rustc`
version, the host architecture, the CPU count, `CARGO_BUILD_JOBS`, the
loom version the copy resolved (`loom resolved`) and the digest of the
workspace lock file that resolution wrote in the copy (`Cargo.lock
sha256`, null when it wrote none); `baseline` and, per row
under `rows`, the plant, `expected`, `results`, `seconds` and `agrees`, or
for a skipped row `result` and `reason`; `mismatched`; `no verdict`, the
rows with a test that no entry judged `killed` or `survived`; and the
run's `seconds`, from the command's start to its last row. Each result
holds the command (for a loom test with its `RUSTFLAGS`), `exit` (a GenMC
case's own, an integer or null, with the lane's as `lane_exit`), its
`seconds` (for a GenMC case, the whole lane run's), the output's path and
sha256 digest, shared by the results of one run, and the result with its
reason, and for a GenMC case the `executions` its accepted judgment
counted. A `kill` row agrees when every result is `killed`, a `survives`
row when every result is `survived`; an `unrun` row always agrees. Both
JSON files get the mode a plain create gets under the umask.

Exit 0: a completed run whose every row agrees; 1: a completed run with a
row that does not, named under `mismatched`, or an unhandled error, shown
by one line `weaken-orderings: MESSAGE` and no `report.json`; 2: a refused work directory,
checkout, catalog, configuration, GenMC declaration, pin or file, a
`--row` that names no row, or a usage error; 3: a red baseline; 4: a
baseline test that left a scoped file changed, a changed plant, a failed
restore or a restore that left a scoped file changed. A completed run writes `report.json` and
prints its path, `mismatched` and `no verdict` as one JSON line. Exits 2,
3 and 4 print `weaken-orderings:` and the reason on standard error, for
exit 3 the baseline results as indented JSON. A handled signal before the
report is written restores the plant and prints
`weaken-orderings: signal NUMBER`, with no `report.json`; the tool then
ends itself by SIGINT, whichever signal arrived. Obligation credit comes from lane
receipts alone, and `run`'s outputs are the files under `DIR`.
