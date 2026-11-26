# TLA+ models

Three models check Kestrike's protocols at finite bounds.
[Lifecycle.tla](Lifecycle.tla) composes one remote PUT with one GET of the
published record. [Identity.tla](Identity.tla) models the identities of the
owner's request namespace and the client's board.
[Recovery.tla](Recovery.tla) models one key's records across a process death
and its recovery. Each model's section below states its invariants, bounds and
cases.

## Finite verification suite

[check.py](check.py) runs SANY, exhaustive TLC checks, reachability witnesses,
and fault injections. Positive checks have no state or action constraints and
keep deadlock checking enabled.

Reachability cases expect a **named invariant violation**: the invariant denies
an intended scenario. Mutations run in temporary copies; the runner never
modifies the committed specification.

## Running and retaining evidence

Install Python 3.9 or later, a JDK, and `tla2tools.jar` from the
[TLA+ releases](https://github.com/tlaplus/tlaplus/releases). From the repository
root:

```sh
python3 tla/check.py --jar /absolute/path/to/tla2tools.jar
```

`TLA_TOOLS_JAR` can supply the jar path. `--workers` defaults to `8`;
`--case put` selects a case and can be repeated. `--output` selects a
new evidence directory. Larger cases take minutes and use substantial disk
space; the default suite includes them.

The runner retains exact module and configuration copies, SANY and TLC logs,
coverage, input hashes, jar hash and manifest, runtime version, date, commands,
exit statuses, and state counts in that directory. Only the expected named
outcome, with the exit status TLC reports for it, counts as success; a parser
failure, an unrelated invariant violation or a failure after the named
outcome fails the suite. Every case that completes requires coverage of each
action its `coverage` names. A kill case, a mutation case whose outcome is an
invariant or action-property violation, also needs one counterexample step of
an action that reaches its mutated definition; the runner refuses before TLC
starts a kill case the definition reader cannot read or that no action
reaches (see [the kill rules](#registry-counts-and-kill-rules)). Re-run the
entire suite when the checker changes.

TLC prints each coverage line of an action as `distinct:generated`: the
distinct states the action found, then the states it generated. The first
numbers of the lines of `recovery`'s final coverage report, the `Init` line
included, sum to its distinct-state count. An action
is covered when its last coverage line reports a generated state, the second
number.

### Registry, counts and kill rules

`verification/tlc/expected.json` restates each runner case in its `cases` map,
one line per case: `outcome`, the terminal line the case declares; `invariants`
and `properties`, the names the generated configuration checks, in order; and
`distinct`, the distinct-state count, a positive integer, on exactly the cases
that complete. An entry holds `properties` only when the configuration checks
a property, and it holds no other member. `models` lists the `Safety`
conjuncts of each model that defines `Safety` and of no other model,
`uncontrolled` lists the conjuncts no mutation case kills, and `type_kills`
lists the mutation cases whose outcome is the `TypeOK` violation. The
`profiles` lists stay beside the map. The judge applies this static contract
on every judgment, and its self-test applies it to the committed tree on every
pull request. It checks in this order and refuses the first breach as drift,
by case or conjunct name: each runner case named once, in a tier a profile
runs; an entry per case;
every `.cfg` the base of a case and every base and mutation target present;
the outcome; the presence and form of `distinct`; the two lists and the
entry's members; `models`; the passing baseline; the reading of each kill case
and its mutation outside its property; and `uncontrolled` and `type_kills`.

A count is exact and belongs to the tool pins: a tool bump or a model edit
updates the counts in the same change. The judge compares the count it
derives from each completing case's retained `tlc.log` with the pin and
refuses a difference as an outcome mismatch. A violation case pins no count.
An invariant, action-property or deadlock violation stops an eight-worker
search at the moment one worker finds it, so its count depends on the run;
the four temporal-property controls run their final check on the whole graph,
and they pin no count because the rule covers every violation. A count sees
states: a guard edit that removes transitions between states that stay
reachable keeps it, and so does an added fairness conjunct.

After a lane run, print the entries of its cases with

```sh
GH_TOKEN=$(gh auth token) bash scripts/rust-lane.sh tlc pr
python3 scripts/judge-tlc.py pins --evidence evidence
```

`pins` reads the evidence directory a `scripts/rust-lane.sh tlc` run wrote, at
the path the run recorded in `tlc.argv` (`$EVIDENCE`, by default `evidence`),
and output that `tla/check.py` writes alone lacks the lane's identity and
command records. It reads the profile from `tlc.argv`, applies every check of
`judge` except the comparisons with the `cases` map, and prints each entry,
with the count of each completing case derived from its log, only for a run
those checks credit. Every other section of the registry must already hold,
so a new case is in its tier's `profiles` list before `pins` prints its entry.
Every case is in the `pr` tier, so a `pr` run prints every entry.

A kill case is a mutation case whose outcome is an invariant or
action-property violation; it counts as a kill under three rules. Its passing
baseline is a case that completes without a mutation, shares its module, base,
specification, settings and symmetry, generates the same configuration apart
from its invariant and property statements, runs in every profile that runs
the mutant, and checks the killing property in the kill's own kind: an
invariant directly or as a `Safety` conjunct, an action property as a
property. The mutation anchor occurs once in the target and lies in one
definition, which the killing property does not reference through any chain
of definitions, `Init` does not reach and an action of `Next` does reach; the
replacement changes no other definition; the case runs the target's
`Spec == Init /\ [][Next]_vars`, and its generated configuration selects
`SPECIFICATION Spec` alone and overrides no definition of the target in a
`CONSTANT` statement; and the target module defines the property and `Next`.
A mutation case whose outcome opens as an invariant or action-property
violation that the rules cannot read, such as a violation by the initial
state, is drift, and so is a kill target that instantiates a module with
`INSTANCE`. The definition reader reads a module from its header to the first
run of four or more `=` after it. SANY ignores text outside the module, so
the reader refuses, as drift, text other than comments before the header or
after that run. It also refuses a module without either, a name the module
defines twice, a column-0 module line it cannot parse, including a
function definition `F[x \in S] ==`, and a span whose `LET` and `IN` outside
string literals do not pair or that holds an `==` outside a `LET`, which would
fold a second definition into the first. No generated configuration, a case's
extra text included, may hold a constraint or a `VIEW`, which prune or merge
states, or any `CHECK_DEADLOCK` statement, which overrides the deadlock
check; a `SYMMETRY` statement in a case that declares no symmetry, a selector
other than `SPECIFICATION` with the case's specification, and a keyword where
a constant's value stands are drift too. The counterexample takes a step of an action of
`Next` that reaches the mutated definition; the runner and the judge both read
it from `tlc.log`. The receipt records each kill case's baseline and that
action set.

The rules match TLA+ text by top-level definition name after comments are
removed and treat every identifier, and every part of one after an
underscore, such as the `vars` of `[][A]_vars` and `WF_vars`, as a reference
whatever its scope, so they establish textual reachability between
definitions, a by-name approximation of semantic dependency. A local name, a
record field or a word in a string that repeats a definition's name counts as
a reference. An added reference makes the outside-the-property rule and the
`Init` refusal stricter. An added action widens the step rule: a step of an
action that names the mutated definition only through such a collision
satisfies it, and the passing baseline, the named outcome and the other credit
checks still apply. The action set holds the names `Next`'s body names, and
TLC labels each step with the innermost definition its action expands to: a
definition `Next` names whose body is a disjunction of other actions gives its
steps the inner names, and a disjunct of `Next` that is not an operator
application, such as Identity's `Mismatch /\ URetry("RETRY2")`, keeps the
label `Next`, which is no action. A kill whose mutated steps all carry labels
`Next`'s body does not name fails the step rule until each such action is a
definition `Next` names; one matching step anywhere on the trace satisfies
it. The rules read the target module, the root module's definitions and the
generated configuration, and they follow each `C <- Op` substitution as `C`
naming `Op`. The rules accept a
mutation of any size or effect inside one definition: `duplicate-credit` sets a
credit of 2 directly and passes all three. An equal count shows an equal
number of states at the configured bounds, and the models' correspondence to
the implementation remains the assumption the receipt states. An
invariant-list pin fixes invariant names; review of the model diff covers
invariant bodies, and the conjuncts under `uncontrolled` rest on their
baselines alone. A change that edits a model and the registry together passes
the static contract, and the registry diff shows it to the reviewer.

A pull request's checks apply the static contract, which checks that each
completing entry holds a positive integer count and compares it with no run;
the TLC lane runs on
schedule and on manual dispatch, so only a lane run of a profile that holds a
case compares that case's count, and a changed count surfaces after merge
unless the author runs the lane. A lane that is skipped or does not complete
earns no TLC credit. No time bound applies to a case beyond the lane's
deadline on the whole profile run, which ends 105 minutes after the lane
starts.

### Unreached spans

For a credited run, `report.json` holds `unreached`: for each of
`tla/Recovery.tla`, `tla/Lifecycle.tla` and `tla/Identity.tla`, the spans of
model text that the rule below classifies as unreached over the judged
profile's completing cases, as entries `{section, at, text}`, or a refusal
string when they cannot be read. A model's cases are the profile's cases that
target it, complete and have no mutation. `at` is `line:col-line:col` in the
file of the span's module; for a module other than the model, which the entry
lists under the case's target model, the module's name and a space precede
it. `text` is the committed text there, its runs of white space joined into
single spaces on one line. `unreached_read` counts the cases and the span lines
of sections read for the models whose value is a list of entries. The
lane summary prints each entry, each refusal, or, when all three lists are
empty, one line with those two numbers. The member is a report: it decides no
verdict, exit code or credit.

A refusal string `<case>: <reason>` names the first case by name whose log
fails its digest check, is refused by the reader below, or lists a section
span outside its module's committed text. The form
`<case>: the span report failed: <error>` reports a failure of the rule or of
anything else; its case is the model's first case by name, a label rather than
the cause. The form `<model file>: <reason>`, with the bare file name such as
`Recovery.tla`, reports a profile with no case of the model, a failure before
the model's cases are selected, or a failure of the setup the three models
share.

The reader takes the last complete coverage report of each log, the one a
line `End of statistics.` or `End of statistics (` ends. A section is a
header with two counts other than `Init`, named by its operator and, when the
header carries one, its parenthesized location; it ran in a case when its
second count, the states it generated, is positive there. A span is a location
TLC lists in a span line under a section, with the line's count and its
nesting depth; the span lines under `Init` and under invariant and property
headers stay outside the rule. An
occurrence of a span S in a section's listing is a span line whose location
contains S, under which no nested line's location also contains S; S is
evaluated in a set of listings when an occurrence of S, or of a listed span
inside S, has a positive count. A span is unreached when:

- its section ran in one case or more, it lists the span with 0 in a case
  where it ran, and the span is not evaluated in that section's listings of the
  cases where it ran; or
- its section ran in no case, and the span is not evaluated in any section of
  any case.

Of two unreached spans of one section, one inside the other, the report keeps
the outer one; containment compares module, start and end. A log with a line
of another form inside its last complete report, with a span line above the
report's first header, with no complete report, with a last report that holds
no section, or whose last report does not show an action of the case's
`coverage` as a section that ran is refused by name. An action ran when the
last section of its operator ran, located or not. A log that lists a section
span ending before its start, or lying outside its module's committed file, or
in a module whose file is absent or cannot be read, is refused the same way,
before the rule reads any span of it. Columns count characters, a tab moving to
the next multiple of eight plus one, which matches SANY's columns for text
inside the Basic Multilingual Plane.

The rule was designed on two assumptions about TLC's listing: that TLC lists a
span with count 0 only when it never evaluated it, and that it lists a span
apart from its enclosing span whenever the two counts differ. Experiments with
the pinned TLC refine both. The count of an action-level span, such as a
primed assignment or `UNCHANGED v`, is the number of times evaluation passed
through it on the way to a completed successor state, so such a span lists 0
when TLC evaluated it and a later conjunct then failed. A guard or another
expression span can list a positive count under a section whose header
generated no state: `identity-two-slots` lists `CReturnStale`'s guard
331:8-331:26 with 6,779,920 under a header of `0:0`. Its listed number is not
always the count of its own operand: in `identity-board` the same guard lists
2,118,850 above an operand line with 6,793,990. A span with no successor through
it is reported only when no occurrence of it, or of a listed span inside it, is
positive in the listings the rule compares. TLC leaves out a sub-expression it
never evaluated, so the rule sees such a branch only through the innermost
listed line that contains it, and the report sees action-level spans that TLC
lists even at 0. TLC can also fold a helper's body into the line of the call
site: `WrongOp` lists its call `Count("wrong")` at 183:8-183:21 with 514,380
and no line at `Count`'s body, 75:13-75:50, while `Conflict`, which did not
run, lists that body with 0. The listing
rules come from one pinned version; rerun the suite when the checker changes.
The unreached span report has these limits:

- A span is a location TLC lists. The report names listed spans that meet the
  rule above, and it counts no TRUE and FALSE outcomes of a condition.
- A helper operator that one action calls at several places is reached when
  an occurrence of the helper's own location, or of a listed span inside it,
  has a positive count in the listings the rule compares. A call that TLC lists
  only at its call site's line leaves no line at the body's location, so the
  report can name the body under a section, or a section that ran in no case,
  even when that call evaluated it.
- A section that ran in no case adds an entry only for a span that no section
  of any case evaluates, so such a section whose spans other sections share
  leaves no entry. The case's `coverage`, not this report, checks that an
  action ran.
- The rule's work grows with the square of the number of span lines a model's
  cases list, and no reader caps a log's size. The time limits of the lane's
  step and job bound it: a log with enough span lines to run past them ends
  the lane with no credit.
- Coverage is blind where a model has no state: session identity and replay
  are outside Lifecycle.
- It describes the model-checking cases at their finite bounds and says
  nothing about the implementation. An empty list shows that no listed span
  meets the rule above. A span listed only in cases where its section did not
  run, while the section ran in another case, is not compared, and the model's
  adequacy is left to review.

## PUT, fill and read lifecycle

[Lifecycle.tla](Lifecycle.tla) composes one remote PUT from client to
publication with one GET of the published record. The client asks for
authority, prepares, supplies payload only after READY and within the owner's
grant, and reports `Published`, `Failed`, `NotStarted` or `Unknown`. The owner
credits each fragment once, fails the upload when a copy with different bytes
arrives after the credited one, submits each write range once with the header
range last, and publishes the client's bytes only when every range completed
under current authority. An ended fill drains until its own writes end. Device
terminals name the serial and range of their command, so a revoked serial's
late terminal reaches only its own write. A read holds its record until every
command ends, hands off chunks in order after their terminals, and delivers
one `Done`.

```text
client  BEGIN -> AUTHORITY -> PREPARE -> READY -> DATA within grant -> ACK base
owner                       credit once -> submit payload ranges -> header last
device                                     terminals keyed by (serial, range)
owner   all ranges written, current authority, no conflict -> publish -> RESULT
read    admit -> current + read-ahead commands -> chunks in order -> one Done
```

Messages stay in a set once sent, so redelivery stands for retransmission and
replay; a configuration with `Expiry` drops the owner's retained terminal row
and its replies, after which a retransmission learns `UnknownOutcome`.
Payload ranges submit in any order once their fragments arrived and the grant
ignores receive pressure; both over-approximate production, which consumes
the contiguous prefix and grants `base + window - held`. A copy with
different bytes reaches the owner only after the copy it credited: an
authenticated DATA frame comes only from the uploading session, and source
custody keeps a fragment's bytes fixed while retained, so a differing copy
that arrives first is indistinguishable at the owner from the client's own.
Source custody is the per-fragment slot, held while retained and while the
NIC reads it. Byte geometry is the fragment and range sets with `Cover`.
Session identity and replay are outside the model. No refinement mapping to the implementation is claimed.

Each action of `Next` maps to the code that performs it, or to a declared
abstraction, in one row of
[the model links registry](../verification/models/links.json), which
`python3 scripts/model-links.py check` holds to the model, to the runner's
coverage and to the cited code. Two actions are abstractions: `NConflict`, a
copy of a credited fragment with other bytes, which only a holder of the
session's keys can send and no production code sends, and `Done`, the step
taken in the named terminal stutters `Finished` and `Held`. Each row's note
explains the pairing and records the differences between the model and the
cited code that its reviewer found, which need not be all of them. A passing check shows that each cited item still equals the code
its recorded digest covers. A digest can be pasted without reading the
item, and no check enforces the reading; whether each pairing is right and
whether the model matches the code stay outside the check.

| Invariant | Guarantee |
|---|---|
| `PublishedComplete` | The PUT's serial publishes only with every fragment credited once, every range written, no conflict and current authority. |
| `PublishedNeedsResult` | A client `Published` needs that publication; full receipt is not enough. |
| `PublishedClientBytes` | The PUT's serial publishes the bytes the client sent. |
| `FailedMeansUnpublished` | A known failure or `NotStarted` means the serial never published. |
| `SupplyAfterReady` | Payload supply waits for READY. |
| `SourceCustody`, `NoDataAfterEnd` | A source slot frees only once retention and NIC access both ended; an ended upload holds no slot it could send again. |
| `WriteCustody` | An ended fill holds no outstanding write. |
| `SuccessorIsolated` | A successor publishes only after its own write's terminal. |
| `HeaderLast` | The header range submits after every payload range. |
| `OneDone`, `ChunksVerified` | One `Done` and no chunk after it; chunks follow their terminals. |
| `ClosedIsFinal` | Close releases the upload, so a closed client's outcome is final. |

Each case in [check.py](check.py) enables only the faults its obligation
needs, over two fragments, two write ranges (three in `put-three-ranges`),
a grant window of one fragment and two read commands. `put-zero-bytes` is a
header-only upload. The inverted invariants in
[LifecycleMC.tla](LifecycleMC.tla) witness publication, failure, an
`Unknown` client beside a publication, a cancelled upload that published,
full receipt with a write held, an unproven stop holding its commands, a conflicting duplicate, a late write of the
revoked serial beside its successor, a cancel with two reads out, a loss
after an accepted submit and a header-only publication. Mutation cases
publish a missing range, credit a duplicate, let a later differing copy
replace the credited bytes, publish under revoked
authority, hand off an unverified chunk or a chunk after `Done`, treat full
receipt as publication or `Unknown` as failure, free a source slot the NIC
still reads, keep a slot sendable after the upload ended, end a fill with a
write out, let a late terminal end the
successor's write, decide a closed upload from a retained RESULT, and admit a
read at an untyped version; each must violate its named invariant or property.

`deadlock checking` stays on. The named terminal stutters are `Finished`
(the client closed, the owner ended and nothing is outstanding) and `Held`
(an unproven stop holds commands).

### Final liveness

`FairSpec` adds weak fairness for the client, owner, Tick and Poll work and
delivery (`Service`), an advancing owner clock (`Clock`), an eventually
supplying client (`Supplier`), eventual device terminals (`Device`) and
abandonment of an `Unknown` upload. The liveness cases run with `-lncheck
final`, no symmetry and no constraints. `live-drain` checks that the upload
decides, an ended fill and the read drain, and a decided upload closes; its
`Decides` and `Drains` rest on the owner deadline, which `Clock` makes
eventual. `live-publish`, without deadlines or write faults, checks that the
upload publishes and learns it. Each control drops one assumption or adds one
fault and must violate its property: `stalled-supplier` (`Publishes`), `result-expiry`
(`Publishes`), `retained-unknown`, where an expired result leaves `Unknown`
without abandonment (`Releases`), and `unproven-stop` (`Drains`).

### Profiles

Every case is in the `pr` tier, so `--tier pr` and `--tier scheduled` run the
same cases. Each TLC obligation record names the `pr` module.
`scripts/rust-lane.sh tlc pr|scheduled` runs a profile under the JDK and jar
pinned in `verification/tlc/expected.json`, and `scripts/judge-tlc.py` credits
it when the installed JDK tree, the jar, the models and each case's generated
configuration match that declaration and the run meets the
[registry and kill rules](#registry-counts-and-kill-rules), among them each
completing case's count pin and each kill case's mutated step.

The pinned jar is an exact copy of the tlaplus `v1.8.0` build of 2026-10-06
(tlaplus commit `94d0c50`), held as the `tla2tools.jar` asset of this
repository's `tlc-tools-2026-10-06` release. Upstream replaces its `v1.8.0`
asset on every master build, so the lane fetches this copy through the
GitHub API, authenticated with `GH_TOKEN`. The workflow passes the job's
read-only token to the TLC step; locally, run
`GH_TOKEN=$(gh auth token) bash scripts/rust-lane.sh tlc pr`. To move the
pin, publish a new release asset and update the declaration's URL, digest
and version together. A new jar can change counts, so in the same change run
the lane's `pr` profile under the new pin, compare each completing case's
count with what `pins` prints, and update the `cases` counts that changed. A
lane run whose counts differ from the pins fails at the judge, and `pins`
still prints its entries; run `pins` on the run's evidence before the next
lane run replaces it, since a run deletes the previous `tlc` directory and
`results.json`.
## Request identity and replay

[Identity.tla](Identity.tla) models the identities that bound every effect of
the owner's request namespace and the client's board. The owner keeps one wire
slot per peer and slot number: its session's highest admitted generation (the
watermark), the live request's table handle and a retained outcome row. A
request's operation, GET or PUT, is fixed at admission; the request table
charges one per-peer share across operations. In the model, a wire identity
admits only above the watermark, below the generation limit, on a free
binding with room, and a refusal changes no identity and moves only its
refusal counters. In the owner, the watermark also rises to a generation
settled from outside the table: an eligible refused or unknown fresh
identity is settled, which on a free binding raises the watermark and keeps
the refusal's row, if the answer has one, and on a held binding records only
the refused generation,
as the registry's `Refuse` and `UnknownAnswer` rows state. At the watermark a frame
of the other operation counts `WrongOperation`. A matching PUT retry replays
the retained row under the row's epoch before its expiry; a changed shape
conflicts; an expired row, an older generation or a fresh one answers
`UnknownOutcome`, which the client takes as `Unknown`. The model's RESULT
stands for each terminal the owner sends: a GET's terminal, a PUT's RESULT,
from which the client decides `Published`, and a PUT's ERROR.
A GET or PUT whose RESULT went
out frees its wire slot while its record drains, marked unbound, so a fresh
generation on the slot admits on share and table room alone; a release names
the draining record by its mark. In the owner, the sent ERROR of a PUT whose
record still drains frees its wire slot this way, and a published PUT's
record is released as its RESULT is queued; the model's `Unbind` applies to
an ended PUT of either terminal, more PUT terminals than the owner unbinds,
and leaves out the owner's raise of the watermark to a generation refused
while the binding was held (the registry's `Unbind` row). Session replacement clears a peer's
watermarks and rows and keeps its live bindings until they drain. The client's upload decides `Published` only from a RESULT of its exact
peer, wire slot, generation and epoch, and a RESULT resolves `Unknown` while
the client holds the upload, after an abandon as well; the upload keeps one
identity for the run, and retirement with a successor on the same wire slot
is the delayed-RESULT history's. The client board attaches a core number to each
request namespace; request generations restart with a new core, so a returned
lease credits the live request only under the lease's core and generation and
otherwise frees one orphan. The fill and read inside a request, and the
outcome it reports, are the Lifecycle model's; here a request ends in
one step that retains its row's operation, epoch and expiry and sends a RESULT.

Each action of `Next` maps to the code that performs it, or to a declared
abstraction, in one row of
[the model links registry](../verification/models/links.json), under
`python3 scripts/model-links.py check`, which
[the Lifecycle section](#put-fill-and-read-lifecycle) describes with the limit
of what a pass shows. Three actions are abstractions:
`Tick`, the owner's clock, which reaches the owner as the time each call
receives; `Stray`, a PUT retry the upload did not send, naming any wire
identity of the peer's current session other than the upload's own when it
is sent, which the network or another client sends; and `Done`, the terminal
stutter.

| Invariant | Guarantee |
|---|---|
| `ExactBinding`, `OneBindingPerHandle` | A live binding names its peer, slot and, while its session lasts, its watermark; every live record is bound once or, once its terminal went out and the slot was freed, marked unbound, never both, and a marked record has ended. |
| `OneAdmission` | Each wire identity admits at most once per session. |
| `Capacity` | GET and PUT share the table and each peer's share. |
| `PutCaps` | PUT records, ended ones included, stay within the global cap `PutCap` and the per-peer cap `PeerPutCap` until `Release` frees them. |
| `ResultHasAdmission`, `NoExpiredReplay`, `NoCrossedReplay` | A RESULT names an admitted identity of its epoch; a replay answers only from a current row of the frame's epoch and operation. |
| `ExactRelease` | A release frees only the record admitted under the table generation it names; with `OneBindingPerHandle`, only the handle it names, bound or marked, and a successor's binding on the freed slot stays. |
| `PublishedNeedsResult` | The client's `Published` names a RESULT of its exact identity and epoch. |
| `OrphanConservation` | Orphans equal the leases of closed requests still handed out. |

Cases run owner identity without client leases and the board without a PUT.
The base case runs one peer, one slot, two generations and two sessions; the
widened cases run one session, no linger and one wider bound: `identity-two-peers` (a table of one shared by two peers),
`identity-two-slots`, `identity-share-of-one` (two slots under a share of one), `identity-three-generations`, `identity-mismatch` (a
retry with another shape), `identity-stale-data` (DATA of a released upload)
and `identity-board` (two cores, four generations). Witnesses reach a
refusal, `WrongOperation`, a conflict, an `UnknownOutcome`, a replay, a retry
after expiry, an `Unknown` resolved by a RESULT, a retained `Unknown`, shared
pressure between a GET and a PUT, a draining binding after replacement,
dropped stale DATA, a release naming a stale table generation, an unbound
GET record, an unbound PUT record, a successor bound beside an unbound
record, an orphan and a lease returned under an earlier core. Each control removes one identity
check and must violate its invariant: admission without the wire generation
or onto a busy slot, over the share or over the global or the per-peer PUT
cap, a release
without the table generation or without the handle, a replay after expiry,
across operations, of a generation other than the watermark's or of an
earlier session's retry, a RESULT for a request whose session was replaced,
a reply
without the peer, the generation or the epoch, and a lease credited without
its core or its generation. `admit-over-share` runs at the bounds of
`identity-share-of-one`, its passing baseline, which completes its search
there. `admit-over-put-cap` admits a PUT that would bring the live PUT
records past `PutCap` and must violate `PutCaps`; it runs at the bounds of
`identity-put-caps`, its passing baseline, where the global cap binds: one
peer's PUT fills it while the other peer still has room under its own cap.
`admit-over-peer-put-cap` admits a PUT
that would bring a peer's PUT records past `PeerPutCap` and must violate
`PutCaps` too; it runs at the bounds of `identity-peer-put-cap`, its passing
baseline, where the per-peer cap alone binds. `replay-without-watermark` lets
`Replay` answer a retry of a generation other than the slot's watermark from
the slot's current row, a GET row or a PUT row, so a stray retry of an
identity the owner never admitted gets a RESULT and must violate
`ResultHasAdmission`; it runs at the bounds of `identity`, its passing
baseline. The RESULT it sends names a generation the owner admitted under no
epoch, so the case tests the conjunct's generation alone. Two more controls
at the same bounds test its epoch: each sends a RESULT under an epoch other
than the admission's.
`replay-without-epoch` lets `Answers` take a retry of an earlier session, so
a stray retry sent before a replacement gets a RESULT under its own epoch for
an identity the owner admitted under the next one. `result-after-replacement`
lets `End` retain a row and send a RESULT for a request whose session was
replaced, under the new epoch. Row epochs are defensive in the model as in
production: session retirement clears the rows, so a row of another epoch is
never routed. The clock runs to `Linger + 1` and on while a retained row is
current, so every row reaches its expiry before `Done`.

PUT admission also requires room under the PUT caps, which correspond to the
owner's `put.puts` and `put.peer_puts`; `Table` and `Share` correspond to
`request_slots` and `peer_requests`. The base configuration sets each cap to
the table or the share, where admission depends on `Table` and `Share` alone.
The model admits any `PutCap` and `PeerPutCap` combination, a superset of the
owner's `peers * peer_puts <= puts`, so it also explores the global cap
binding while a peer's own cap has room; the owner reaches the global cap
only through every peer at its own cap. `Headroom` states the GET reserves of
one the owner's start requires: PUT records leave at least one table handle
and one slot of each peer's share, so a fresh GET finds room whenever no
other GET holds it. `identity-put-caps` checks it at `Table = 2, Share = 2,
PutCap = 1, PeerPutCap = 1` over two peers of one wire slot each, one session
and no linger, where the global cap binds, and `identity-put-cap-at-table`
sets `PutCap = Table` there and must violate `Headroom`.
`identity-peer-put-cap` checks it over one peer of two wire slots at
`Table = 3, Share = 2, PutCap = 2, PeerPutCap = 1`, where the per-peer cap
alone binds, and `identity-peer-put-cap-at-share` sets `PeerPutCap = Share`
there and must violate `Headroom`. The witnesses `IdNoCappedPut` and
`IdNoPeerCappedPut` reach a PUT refused by the global and by the per-peer cap
while the table and share have room, and `IdNoReservedGet` reaches a peer at
its PUT cap whose GET fills both its share and the table. `IdNoSharedPressure`
counts a PUT that a held GET keeps out of a full share or table;
`identity-cap-without-pressure` holds it at `Table = 3, Share = 3, PutCap = 3,
PeerPutCap = 1` over one peer of three wire slots, where a peer holding a GET
and a PUT has room and the per-peer cap alone refuses its next PUT. The checks cover
safety over every interleaving the actions allow, fair or unfair; a request
ends, releases and fails only through the model's actions, so a PUT record
keeps its charge across `End` and `Replace` until `Release`. The cases with
binding caps run one session; the Rust replacement tests cover a binding cap
across `Replace`.

## Recovery envelope

[Recovery.tla](Recovery.tla) models one key's records across a process
death and its recovery. Seven components stay separate: the volatile
incarnation (bindings, queued writes, replay position and the extents it
reused after recovery), the persistent media, published roots and the
issuer's last generation, the old process's outstanding writes, the
observation of each recovery-safe exclusion's acknowledgment, the protected
exclusions, the freshness state (the invalidation feed and its floor, the
highest observed acknowledged cursor) and the protected extents. A ghost map
records each generation's label, issue count and invalidation cursor and
decides nothing; the model's generation is the record generation.

`Crash` resets the volatile state, moves its queued writes to the old
process and keeps every other component and the ghost map unchanged. Each
old write then lands as one whole unit of its own record or never lands.
`Replay` advances the replay position; `Recover` binds a label only once
replay reached the floor, to a durable published root that no exclusion and
no replayed invalidation names, and ends `Recovered` or `Withheld`; the recovered incarnation then
fills and reuses free extents under the issuer it persisted, and issuing
past the last generation ends `Exhausted`. Each terminal is witnessed.
`Replacement` is the hypothesis under which a label's successor root may
publish once its predecessors are excluded; `Fence` enables a persistence
fence that makes every queued write of the running incarnation durable at
once. Both are constants:
`recovery-replacement` and `recovery-fence` exhaust the model with each on,
and `recovery-two-invalidations` exhausts it with a feed of two
invalidations. The catalog credits the default and two-invalidation
configurations; `recovery-replacement`, `recovery-fence`, `NoVisibleSuccessor`,
`successor-before-exclusion`, `ack-before-exclusion`, `NoReleasedProtection`
and `reuse-protected-extent` run as checked cases
without catalog credit, since they rest on the replacement and
exclusion decisions and the qualified persistence profile. Exhausting the
generations halts the owner with its queued writes still queued.

Three abstractions bound what the freshness, issue and reuse checks claim.
A client observes an acknowledgment only while the incarnation that sent it
lives: a response still in a dead incarnation's link is emission only, so
the floor stands fixed at the crash. The issuer's durable write of its last
generation is atomic with the issue. The recovered incarnation reuses an
extent only once the dead incarnation's outstanding writes are proven
stopped, after which none of them lands; `Free`'s outstanding-write conjunct
stands for that proof by reading the old process's queue, so the model lets
the recovered incarnation reuse any extent no old write still targets. That
admits every reuse production performs after the proof, and
`UnknownIneligible` with its `reuse-beside-old-work` and `fill-beside-old-work`
controls checks that a late landing on a reused or refilled extent is the
hazard the proof removes; the proof,
abstracted here, is what classifies those extents as ineligible. Within the
model's bounds every binding names an admissible root, so `Free`'s admissible-root
conjunct covers its binding conjunct; `reuse-admissible-extent` drops the
root conjunct alone, and the catalog credits that proof.

Recovery assumes these Lifecycle invariants, which it abstracts to one
record per extent: `PublishedComplete` and `HeaderLast` (a root publishes
only after its record is written), `WriteCustody` (an ended fill holds no
outstanding write, so a death leaves exactly the queued writes to the old
process) and `SuccessorIsolated` (a late terminal reaches only its own
write, so late work keeps its identity).

| Invariant | Guarantee |
|---|---|
| `XBeforeV` | A successor is visible only after every other root of its label is excluded. |
| `AckAfterX` | An exclusion's acknowledgment is emitted only after the exclusion holds. |
| `AdmissionNeedsEvidence` | A binding names a record durable on the media. |
| `RecoveredNeedsReplay` | A recovered binding needs replay at or past the floor. |
| `ReplayHonored` | A recovered binding names no record whose invalidation the replay covered, acknowledged or not. |
| `AdmitAuthorized` | A binding names a published root. |
| `ServeFresh` | After a crash no binding names a record whose invalidation's acknowledgment was observed; the ghost cursor, read apart from the feed recovery replays, is the evidence. |
| `ReuseTwoProofs` | An admissible root keeps its record, and a reused extent holds none. |
| `GenerationNeverReissued` | No generation is issued twice, and every queued, outstanding or published record carries a generation issued to its own label and stands or lands in one place. |
| `LateWorkKeepsIdentity` | Every record on the media, late work included, carries its own label's generation. |
| `UnknownIneligible` | A reused extent, or one the recovered incarnation's queued write targets, is one no outstanding old write may still land on. |
| `ExcludedStayOut` | A binding names no excluded or acknowledged-excluded record. |
| `LiveAckIsNotExclusion` | Every exclusion rests on a recovery-safe request; a live invalidation adds none. |
| `LiveBindingFresh` | While the incarnation runs, no binding names an invalidated record. |
| `ExhaustionIsTyped` | The run ends `Exhausted` only once every generation is issued. |
| `ProtectedUntilObserved` | An excluded root keeps its record until its acknowledgment is observed; protection holds the extent and only the observation releases it. |

`Recovery.cfg` checks `TypeOK` and then `Safety`, which conjoins them. The
default configuration runs one key with two labels over two extents, three
generations and a feed holding one invalidation, and
`recovery-two-invalidations` widens the feed to two, with deadlock checking
on and no constraint; `Finished` is the terminal stutter
once no old work remains. One key suffices because the envelope's
components never relate records of different keys, so a second key adds
states without a new interleaving of any invariant, an assumption the
model states rather than checks; the bound is declared here and in the
catalog records. The model covers one crash, taken while the incarnation
runs. [RecoveryMC.tla](RecoveryMC.tla) holds inverted-invariant witnesses
of the terminals and of the states the invariants constrain, and each
invariant has a unique-anchor mutation in
[check.py](check.py); a mutation case checks `TypeOK` and its named
invariant, so another invariant a mutation also breaks goes unreported
there (`crash-clears-exclusions` also breaks `AckAfterX`). `ServeFresh` has a
second mutation, `feed-trims-acknowledged`, in which `FreshAck` drops the
acknowledged entries from the feed: recovery then binds the invalidated
record, and the ghost cursor catches it where the feed cannot.

Each action has one row in
[the model links registry](../verification/models/links.json). A site row
names one or more cut sites of the closed site registry,
[`Site::name`](../crates/kestrike/src/sim/cut/identity.rs), by quoting each
site's name arm, which carries no digest, and names the production items that
perform the action's effect. For `PersistFence`, `FreshAck` and `OldLand`
the code has no item that performs the effect; their rows cite the nearest
items and their notes state the difference.
Every other action maps to a declared abstraction, whose text the row holds.
`python3 scripts/model-links.py check` holds each cited production item to
its recorded digest; [the Lifecycle section](#put-fill-and-read-lifecycle)
states what a pass shows. The table
gives each action the
positive cases that cover it, the witnesses of the states it serves and the
mutation of the invariant it serves:

| Action | Positive case | Witness of the state it serves | Related mutation |
|---|---|---|---|
| `Fill` | `recovery` | `NoFullIssue`, `NoRecoveredFill` | `issuer-forgets-at-crash`, `fill-beside-old-work` |
| `Exhaust` | `recovery` | `NoExhausted`, `NoRecoveredExhaustion` | `exhaust-early` |
| `Land` | `recovery` | `NoLiveBinding` | `publish-without-evidence` (its guard rests on `Land`) |
| `PersistFence` | `recovery-fence` | none: at these bounds it reaches no state `Land` does not | none |
| `Publish` | `recovery`, `recovery-replacement` | `NoLiveBinding`, `NoVisibleSuccessor` | `publish-without-evidence`, `successor-before-exclusion` |
| `RequestExclude` | `recovery` | `NoObservedExclusion` | `live-invalidation-excludes` |
| `Exclude` | `recovery` | `NoExclusionAcrossCrash` | `crash-clears-exclusions` |
| `Ack` | `recovery` | `NoObservedExclusion` | `ack-before-exclusion` |
| `Observe` | `recovery` | `NoObservedExclusion` | `ack-before-exclusion` |
| `Lose` | `recovery` | `NoLostAcknowledgment` | `ack-before-exclusion` |
| `Unprotect` | `recovery` | `NoReleasedProtection` | `reuse-protected-extent` |
| `LiveInvalidate` | `recovery` | `NoLiveInvalidation` | `live-invalidation-excludes`, `live-invalidation-clears-other`, `feed-trims-acknowledged` |
| `FreshAck` | `recovery` | `NoRecoveryPastFloor` | `recover-below-floor`, `feed-trims-acknowledged` |
| `Crash` | `recovery` | `NoExclusionAcrossCrash` | `crash-clears-exclusions`, `issuer-forgets-at-crash` |
| `OldLand` | `recovery` | `NoLateLanding` | `late-write-relabelled` |
| `OldDrop` | `recovery` | `NoReuseBesideOldWork` | `reuse-beside-old-work` |
| `Replay` | `recovery` | `NoWithheldBelowFloor`, `NoInvalidationWithheld`, `NoReplayAboveFloor` | `recover-invalidated`, `recover-unobserved-invalidated` |
| `Recover` | `recovery` | `NoRecovered`, `NoWithheld` | `recover-unpublished`, `recover-below-floor` |
| `Reuse` | `recovery` | `NoReuse` | `reuse-beside-old-work` |
| `Finished` | `recovery` | `NoWithheld`, `NoExhausted` | none |

Every case runs in the `pr` tier: the 42 cases take about a minute together
with eight workers, the positive cases about 6 to 10 seconds each, far inside
the lane's 105 minutes.
