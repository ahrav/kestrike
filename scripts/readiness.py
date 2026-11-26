#!/usr/bin/env python3
"""Check the failover readiness record: the gates that keep failover closed, the pinned files it reads, each
failure scenario's evidence by kind, the graded items and their floors, the wave plan and authority roles, and the
runbook index against the alarm catalog; and judge supplied evidence against it into a readiness recommendation.

Usage:
  readiness.py check [--record F]
  readiness.py judge --inputs F [--record F] [--output F]

The record is `verification/readiness/failover.json`, read by this script and its tests. It holds:
  record    "failover-readiness", and `version`, an integer from 1 to 2^64 - 1.
  parent    `digest`, the acceptance record's description of a body digest, and the specification #120 and the plan
            #255, each {issue, body_sha256}. #120's entry equals the acceptance record's contract pin; #255's digest
            is checked for its SHA-256 shape only. Compute it as the SHA-256 of the issue's `body` field decoded from
            the GitHub REST API's JSON response, keeping any newline the body holds and adding none.
  pins      one key per file of PINS, each the SHA-256 of that file's bytes; a key may read null but is never absent.
            The acceptance record and the two profile manifests are always pinned. The game-day catalog, the runbook
            index and the alarm catalog may read null; a null pin skips the byte comparison and adds an open item to
            the gate PINS names for it, beside the reasons the rules that judge the file list for that gate. A
            present optional file holds at most INPUT_LIMIT bytes. A change to a file whose pin is not null updates
            that pin here in the same change.
  kinds     the evidence kinds KINDS, in order: the acceptance record's evidence kinds `model`, `simulation`,
            `hardware` and `store`, then `staging`, `rehearsal` and `review`.
  gates     the GATES in order, each {owner, lifts_when, lifted}. A lift is a reviewed diff of this record. A lift of a
            DEFERRED gate also needs a change to this check that replaces its standing reason with a rule judging the
            evidence. `budgets`, `authority`, `evidence-age` and the gates of the optional pins (`gamedays`,
            `runbooks` and `monitors`) lift once the rules below list no reason, and `judge` grades a lift of an
            optional pin's gate, and of `real-path`, against its items (LIFT_EVIDENCE).
  sources   the readiness record's own evidence sources, each {kind, owner, evidence}. A citation `source:item` names
            a source of this table and one receipt that source holds, or, as `gameday:<GD-n>`, a package of the
            game-day catalog; `check` reads the item as an identifier and reads no receipt.
  classes   one row per failure scenario: `meaning`, `failure_class` (FC1 to FC12 with a null `requirement`, or null
            with the `requirement` the row evidences: `R1` to `R12` of the plan #255, or `#120 R<n>` of the
            specification), `delegated` (null, `acceptance`, or the owners of a case they keep), `evidence` (kind ->
            citations `source:item`) and `excluded` (kind -> {reason, owner}). The `staging` kind is always cited or
            excluded; another kind neither cited nor excluded is open.
  items     one graded criterion each, in one of the DOMAINS: `id`, `domain`, `class` (a class row or null),
            `requirement` (its class row's requirement when that row names one), `criterion`, `kind`, `source`,
            `applicability` (`applicable`, or {not_applicable: reason, approver: null until the owner approves}, only
            off the floors or on the retention floor),
            `invalidators` (labels of INVALIDATORS, each naming the change that voids the item's evidence; the
            check reads the labels and observes no change, and `max_age_days` is the clock for state outside the
            repository), `max_age_days` (null until the owner sets it), `floor` (a FLOORS id or null) and
            `gap_owner`. An applicable item of a class row holds no kind that row excludes. A source is null (an
            open gap), `review` (a named reviewer grades it),
            `gate:<id>` (read from the gate's lift, a reviewed diff this check contradicts while the repository's
            evidence does; only the activation floor item named for one of ACTIVATION's gates cites it, at the kind
            ACTIVATION gives), `acceptance:<class>/<column>` (the acceptance judge's cell of a delegated class at that
            column and the item's kind, a cell the acceptance record cites evidence in; a safety or retention floor item
            reads its own column, and a cold class claims no retention; a safety or retention floor item of a delegated
            class at an acceptance kind cites its own cell or is an open gap),
            `record:<catalog id>` (credited through its lane, of the job's kind in JOB_KINDS), `runbook:<index id>`
            (rehearsal), `gameday:<GD-n>` (of its package's MODE_KINDS kind), `hit-gate` or `fis:<profile>`
            (hardware). A review item cites a reviewer or its gate.
  floors    FLOORS id -> meaning: the floor classes of item no exception may cover; each item names its floor. A
            retention floor item may still read not applicable where its scenario recovers no shard, with a reason
            the owner's approver accepts; it then holds no retained set, and a warm acceptance class's retention
            item reads applicable. The wave-halt and safety-alarms floors hold each item FLOOR_ITEMS names, at its
            kind, and may hold more.
  waves     {unit: az-color, order, authorization: AUTHORIZATION}, the fields a wave's authorization names.
  authority the ROLES, each null or a role the owner names.
  unmapped  failure class id -> the reason no class row names it.

The runbook index `docs/runbooks/failover/index.json` is {index, version, entries}, version the integer 1, parsed from
the bytes its pin covers; an absent file reads as an index with no entry. An entry is one runbook slug: `id` the slug
(SLUG: a letter or digit, then letters, digits, `-` and `_`), `file` the runbook, a UTF-8 file of at most INPUT_LIMIT
bytes under `docs/runbooks/failover/` named by its own resolved path, `kind` (procedure or investigation), `actions`
({path, symbol, sha256}: a source anchor, its path the source's repository-relative one, resolving as production code in
a source that decodes as its language reads it, and the SHA-256 of that source's bytes when rehearsed, null on a DRAFT
entry), `alarms`, `status` (STATUSES), `verified_sha256`, `verified_revision`, `rungs`, `paths`, `limitations` and
`rehearsal` ({record_sha256, executor, author, date, result of RESULTS} or null). Each alarm catalog `runbook` slug
needs an entry, and an entry no row names holds no alarms, of either kind. `executor` and `author` are opaque handles
copied from the rehearsal record, which stays outside the repository under `record_sha256`; the check compares the
handles and reads no record. VERIFIED needs a MET rehearsal and no limitations, VERIFIED WITH LIMITATIONS a MET one and
its limitations; either needs the tabletop rung, at least one path, a verified digest and revision, and each action's
sha256. `paths` lists the file's anchors the rehearsal exercised, each a heading slug or an explicit anchor of the file
(`anchors`). A PARTIAL, NOT_MET or INVALID rehearsal stays on a DRAFT entry. `verified_revision` is checked for its
commit shape only. One file may serve several slugs, one entry each, and entries that share a file carry equal SHARED
fields. A byte change of the file or of an action's source after its digest was recorded reads STALE. The alarm catalog
is {rows: [...]}, each row carrying `id`, `severity` (page or ticket), `runbook` (a SLUG, the id of its runbook's index
entry) and, when stated, `basis` (an object from each number of the row to the label of its basis; any other value but
null is refused). An entry's `alarms` are exactly the rows whose `runbook` is its id, and a row whose `runbook` names no
index entry is an open item of the `runbooks` gate.

The game-day catalog `verification/readiness/gamedays.json` is {catalog, version, run_rule, budgets, entries}.
`run_rule` is the text every run obeys. Its budgets are BUDGETS in order with the units it fixes, each {unit, meaning,
value}, the value null until the owner sets it. The entries are GD-1 to GD-14 in order, each with `id`, `mode` (the one
GAMEDAY_MODES fixes; MODE_KINDS maps it to the kind it produces: a causal or rehearsal package runs in staging and
grades staging items, a tabletop grades rehearsal items), `class` (the class row of its items, or null when its items
name no class), `claim`, `not_claimed`, `hypothesis` ({clause, bound, items}: a bound naming a budget or null, and the
package's items the clause grades, which together cover them; GAMEDAY_BOUNDS fixes which budget bounds which item of
each package), `injection` ({action, profile}: the profile a name of `scripts/fis-profiles.json` whose action
GAMEDAY_ACTIONS fixes for the package, or null for a package it names no action for), `oracle` ({reach, expected}: how
the run shows it reached its intended fault, and the outcome it records), `guardrail` (abort conditions), `restoration`
({class, steps}: `automatic` when the system returns to its prior state without an operator, `persistent-manual` when an
operator step restores it, and `destructive` when state the run changed cannot be restored; a tabletop injects no
profile and restores `automatic`, and a package of HOST_STOPS never restores `automatic`), `prerequisites` (as many
distinct texts as GAMEDAY_PREREQUISITES counts: a missing one carries `TBD - BLOCKS EXECUTION` and a met one stays
listed without it), `runbooks` (index ids) and `items` (the items whose source names the package). A clause with a bound
grades only items off the floors, so a missed budget is a gap an exception may cover, and each class with a staging
safety floor item keeps its simulation safety item on the floor beside it. GAMEDAY_SAFETY fixes the items of each
package that stay on the safety floor, so no exception covers a staged safety failure, each item of a package carries
the `guardrail` invalidator and, where the package names a profile, the `manifest` one, and each item of a tabletop
carries the `runbook` invalidator, since the tabletop walks a runbook. A package's digest is `canonical` of its entry,
the run rule, the budgets its clauses name and, when it names a profile, the profile's row with the manifest fields the
controller reads for it, so a change to one of them stales only the run records of the packages that read it. A row
cites a package as `gameday:<GD-n>` under its mode's kind, only a package that grades one of the row's items, and every
class a package grades cites it so. Run records stay outside the repository.

The record holds at most RECORD_LIMIT bytes, and `check` refuses a larger file before it reads any of them. Class and
source names are lowercase words joined by hyphens, every text field holds a character other than whitespace, and a
citation holds none. A row delegated to `acceptance` names the failure class DELEGATED_FAILURE_CLASSES binds its
acceptance class to, and cites `acceptance:<class>` under each of the acceptance record's four evidence kinds, its unrun
kinds included; it defers each of those cells to the acceptance record's verdict. Its `staging` cell holds a written
exclusion, and its `rehearsal` and `review` cells hold no citation and read excluded or open. DELEGATED_FAILURE_CLASSES
holds one entry per acceptance class; `check` binds only those rows' failure classes, and every other row's failure
class or requirement is a label the reviewed record sets.

`check` loads `scripts/acceptance.py` and runs its context and its `check` over the committed acceptance record,
manifest, measurement records and catalog (the measurement frame's check runs `cargo` to resolve source anchors, so this
needs the Rust toolchain). It reads the always-pinned files before that context, judges the acceptance record and the
hardware manifest from the bytes it compares with their pins and the Quint manifest from the bytes the acceptance
context hashed, and refuses a repeated object key in the record, the acceptance record, the hardware manifest or the
Quint manifest. The real-path gate's reasons are the open items `scripts/hit-gate.py`'s `check` lists for that manifest,
plus the platform row rule. It refuses, with exit 2, DELEGATED_FAILURE_CLASSES keyed other than the acceptance record's
classes, and a record off these rules: a record over RECORD_LIMIT bytes; keys other than KEYS; a kind other than
"failover-readiness" or a version off its range; parent keys other than PARENT_KEYS or plan keys other than PLAN_KEYS; a
parent other than the acceptance record's digest description, its contract pin and the plan at a SHA-256; pin keys other
than PINS, a pin other than its file's bytes, a pin naming an absent file, or a null pin of an always-pinned file; kinds
other than KINDS; gate ids other than GATES in GATES order, or a gate with other keys than GATE_KEYS, an owner or
lifts_when that is empty or blank, or a non-boolean `lifted`; a lift the repository's evidence contradicts
(`contradictions`); a source or class name off the name rule; a source other than {kind, owner, evidence} of a kind,
named `acceptance` or like an acceptance record source, or cited by no row; a row with other keys than CLASS_KEYS, no
meaning, or neither of the two failure class and requirement pairs; a citation list that is empty or repeats an entry; a
citation that holds whitespace or names no source and item, names a source absent from the table, or names a source
whose kind is not the kind it is cited under, so a rehearsal never fills a staging cell and a staging run never fills a
hardware cell; a citation whose source the acceptance record names or whose item is a catalog record or package id the
acceptance record cites, since one receipt has one home; a citation of `acceptance` by a row not delegated to it; a row
delegated to `acceptance` that is no acceptance class, names another failure class than DELEGATED_FAILURE_CLASSES binds,
or cites anything but `acceptance:<class>` under each acceptance evidence kind; acceptance classes not all delegated; a
row delegated to named owners that cites anything or leaves a kind unexcluded; a nondelegated row that names a failure
class and excludes every kind; a failure class whose every row excludes every kind; a kind both cited and excluded; a
failure class FC1 to FC12 that no row names and no `unmapped` entry explains, or that a row names and `unmapped` also
lists; an item off its shape, with no criterion, of a kind its class row excludes, or whose source breaks the grammar
above or cites a catalog record the acceptance record cites; a domain with no item; floors other than FLOORS, a floor
with no item, an activation floor other than the items of ACTIVATION's gates, a wave-halt or safety-alarms floor without
each item FLOOR_ITEMS names at its kind, a cold class holding a retention floor item, a warm acceptance class whose
retention floor item reads not applicable, or a class row (other than one delegated to named owners or excluding every
kind) without a safety item and, when warm, a retention item, at most one of each per kind; waves or authority off their
shape; a malformed runbook index, alarm catalog or fault-injection profile table, or one that repeats an object key; an
optional pinned file, runbook file or action source over INPUT_LIMIT bytes; an alarm row or index entry whose runbook id
is no SLUG; an index entry whose file is no UTF-8 file under `docs/runbooks/failover/` in its own spelling; an index
entry whose action anchor does not resolve, or whose action source does not decode, which reads STALE and names the
anchor; an action path in another spelling than its source's repository-relative one; a DRAFT entry's action that holds
a digest; rehearsal paths that name no anchor of the file; an entry whose alarms are not the present catalog's rows that
link it; an entry other than DRAFT without the rehearsal, rung, paths, digests and revision its status needs; a
rehearsal whose executor is its author, compared without case or surrounding space; entries of one file that differ; any
class row with neither a staging citation nor a written staging exclusion; a citation of a package that grades none of
the row's items, or of a package id under a source other than `gameday`; a source named `gameday`; a fault-injection
manifest without its profiles and eligible-types maps; a malformed game-day catalog, budgets or units other than
BUDGETS, a mode other than GAMEDAY_MODES fixes, budget bindings other than GAMEDAY_BOUNDS fixes, a profile whose action
is not the one GAMEDAY_ACTIONS fixes or is no eligible action, prerequisites other than as many distinct texts as
GAMEDAY_PREREQUISITES counts, a package that grades no item, whose clause items do not cover its items, whose items are
not the items citing it, whose class is none of its items' classes, or whose graded class cites it under no cell of its
kind; a bounded clause that grades a floor item; a package whose safety floor items are not the ones GAMEDAY_SAFETY
fixes; a tabletop with a profile, a restoration other than `automatic`, a floor item or an item without the `runbook`
invalidator; a package item without the `guardrail` invalidator or, where its package names a profile, the `manifest`
one; a package that stops or restarts hosts, a partition or an AZ (HOST_STOPS) without the guardrails HOST_GUARD or with
an `automatic` restoration; and a class row of its own whose safety floor lacks its simulation item while it leaves
simulation unexcluded.

On a well-formed record it prints a JSON report and then the line NOT READY, and exits 0: `gates`, every gate that reads
`lifted: false`, in record order; `open`, each gate whose lift this check contradicts with the contradictions a lift
would meet, and each gate that carries STANDING's note (a gate missing from `open` stays open while it reads
`lifted: false`, and its lift is a reviewed diff this check holds no evidence against); `failure_classes`, each failure
class FC1 to FC12 with the rows that name it;
`unmapped`, the record's reasons; and per row its failure class, its requirement, its delegate, its open kinds, its
excluded kinds and, for a row delegated to `acceptance`, the evidence kinds the acceptance record lists unrun for its
class; the items per domain and per floor, each not-applicable item with its reason and approver, and `gaps`, each
applicable item with a null source and its gap owner (a source names where an item's grade is read, and the check reads
no grade, so an item with a source may still hold no evidence); each index entry's status, STALE when its file's bytes
differ from `verified_sha256`; and the alarm cross-check, `skipped` while the alarm catalog is absent. Under
`evidence-age` each item with a null `max_age_days` reads POLICY UNDEFINED, under `authority` each null role, launch and
risk naming one role, and each not-applicable item with no approver are open, and under `runbooks` each DRAFT, STALE or
VERIFIED WITH LIMITATIONS entry (with its limitations) and each catalog row with no entry is open, as is an index with
no entry, an absent catalog, a present catalog with a null pin and a catalog with no row. Under `gamedays` each
package's TBD prerequisites, null budgets and a tabletop's empty `runbooks` block it; under `budgets` each null budget
is open, as is a null game-day catalog pin and an absent catalog; the report lists each package's mode, kind, digest
and blockers. Under
`monitors` the rows with the label `assumed` under any number, the rows stating no basis (absent, null or empty) and
a catalog with no row are open. While `monitors`, `runbooks` or `gamedays` is unlifted and its file pinned,
the report adds STANDING's reason under `open`: this check judges the definitions only (for `runbooks` it holds no
inventory of operator actions). That reason is a note that contradicts no lift, and `judge` grades a lift of any of them
against its items (LIFT_EVIDENCE). `unrun` lists whole kinds; `acceptance.py check` prints the gaps within a cited
kind. A pass shows that the record is well formed, agrees with its pins and lifts only gates that the committed
acceptance record, Quint manifest, obligation catalog, hardware manifest, pins, item table, authority roles, runbook
index, alarm catalog and game-day catalog leave uncontradicted. It judges the shape and links of those files and no
receipt: neither that evidence is fresh, that an alarm reaches its route, that a rehearsal happened, that a game day ran
nor that a wave is authorized. Every pass prints NOT READY, because a verdict needs the evidence receipts that only
`judge` reads.

`judge` runs `check`, so it needs the Rust toolchain too, then reads an inputs file (INPUT_KEYS):
  revision    the 40-hex release revision that acceptance, lane, hit-gate, fault-injection and game-day evidence must
              name; `date` the judging day (YYYY-MM-DD), which aging and exception expiry read. The judge reads the
              record, the pinned files, the committed evidence and every script a judge loads from the tree it
              runs in, so it runs in a git checkout of `revision` and refuses, with exit 2, a checkout at another
              commit, one holding a tracked file that differs from that commit in the working tree or the index
              or that an index flag (assume-unchanged, skip-worktree) hides from git's comparison, and one git
              cannot read. The tree state is the one `git status` and `git ls-files -v` report at the time of the
              check; untracked files (the inputs, the evidence, the receipt) are admitted. An explicit `--record`
              is judged as read and named by `record_sha256`.
  acceptance  an inputs file of `scripts/acceptance.py judge`, judged by it read-only; the acceptance record's classes
              carry their lane, package and comparison evidence, so this file is the one input that supplies them,
              recovery package campaigns included. A lane evidence path and a package, comparison or sizing file it
              names are resolved as a `lanes` path is, and one that does not resolve refuses the file.
  lanes       [{job, module, evidence}], each credited by `scripts/verify-receipts.py credit --receipt --read-only`
              through the acceptance judge's lane runner, after a path that does not resolve (a symbolic link
              loop) and a tree with a link or special file are refused; a lane receipt naming another revision reads
              STALE.
  hit_gate    a hit-gate campaign, judged by `scripts/hit-gate.py`; its candidate is the revision.
  fis         {profile: {episode, lane}}: a fault-injection episode receipt in the controller's version 1 envelope,
              checked for its profile and episode id, and the hardware lane receipt of that episode, which
              `scripts/hardware-lane.py judge_profile` re-validates at the revision under the pinned manifest; the
              lane receipt must carry the hardware lane's envelope and the pinned profile's lane profile and role.
              `lane` is null only for an episode that failed to inject or reads INVALID before a launch.
  gamedays    [{id, package_sha256, catalog_sha256, record}]: a run record kept outside the repository. The record
              holds `id`, `mode`, `revision`, `run_status`, `verdict`, `package_sha256` and `catalog_sha256` (equal to
              the inputs entry's, the latter the package digest `check` reports), optional per-item `objectives`
              (item -> MET, NOT_MET or INVALID) and `date`, and for a tabletop `executor`, who walked it, and
              `author`, who wrote it, two attested names the judge compares as text. The record's `verdict` and
              `objectives` are its producer's attestation: the judge checks the record's bindings and reads the
              outcome as stated. One record per package: the receipt covers the runs supplied, and the owner
              reads any earlier attempt apart.
  runbooks    {index id: rehearsal record file}, each id an index entry. The judge hashes the file's bytes and
              compares the SHA-256 with the `record_sha256` the committed entry records, so the operator holds the
              record the reviewed index names. The bytes are hashed and left unparsed: the entry's result, paths,
              executor and author are the record's reviewed summary. A runbook item binds by bytes: the runbook
              file's digest and each action source's digest, which `check` compares on every run, and this
              record's digest. The entry's `verified_revision` names the commit the rehearsal ran against, an
              earlier commit than any that holds the entry, so the judge compares it with no revision.
  reviews     [{item, reviewer, revision, date, artifact_sha256, grade, reason}] for items whose source is `review`,
              with a named reviewer and reason, the 40-hex release revision the reviewer graded and a grade of
              REVIEW_GRADES. `artifact_sha256` is the reviewer's handle for an artifact kept outside the
              repository: the judge checks its SHA-256 shape and copies it into the receipt, where the wave's
              authorizer reads the artifact behind it.
  exceptions  [{item, reason, risk_owner, approver, expiry, compensating_control}].
Every file this script decodes itself is decoded with distinct object keys; the files the acceptance inputs file or a
hit-gate campaign names are decoded by their owning judges. Each item reads one of GRADES. An item that is not
applicable reads NOT APPLICABLE once its approver is set, MISSING before. Otherwise its source decides. A game-day run
record, a fault-injection episode and a lane receipt are checked for their bindings before their verdict; an index
entry's DRAFT or STALE status decides before its supplied record. A null source, an absent input or an absent reviewer
entry reads MISSING; evidence naming no revision, evidence its owning judge refuses or a record of another filled
package reads UNVERIFIED; a run record of another game-day package id or mode is refused and reads MISSING; evidence
bound to another revision, package definition, fault-injection action, test timeout, profile digest or manifest file,
hardware manifest, rehearsal record or runbook bytes reads STALE. Then INVALID or FAILED_TO_INJECT reads MISSING; a
fail, DISPROVEN or
NOT_MET reads FAILED, also from a halted run or a tabletop without an independent executor, as does the preservation
floor item `suffix-damage` while a hit-gate receipt at the revision hands preservation off; INCONCLUSIVE, a run other
than COMPLETED, a tabletop without an executor apart from its author, a demoted acceptance column, a DRAFT runbook or
one VERIFIED WITH LIMITATIONS, which names them, reads UNVERIFIED; and a pass, HELD of a causal run or episode or MET of
a rehearsal or tabletop reads VERIFIED, a verdict outside its mode's words UNVERIFIED. A fault-injection episode also
verifies when the controller's own abort stopped it, and a HELD episode verifies only with its release proof, the
manifest its lane receipt ran under, no custody in doubt, and the SHA-256 of the lane receipt judged here, the
`canonical` digest of the pinned fault-injection profile and the SHA-256 of the pinned fault-injection manifest file,
whose top-level fields admit the controller's targets, which the episode names as `lane_receipt_sha256`,
`profile_sha256` and `fis_profiles_sha256`. Its fault window is read from the lane receipt: each `observed` event a
case records carries, under
`after`, the controller's latest mark when the lane appended it, and the episode verifies only when a `timeout` event's
mark equals `effect_window.start_ordinal` and either a `restored` event's mark equals `effect_window.end_ordinal`, past
that timeout, or the `stop` event at `stop_under_fault` follows that timeout under the start mark. The episode's
`status`, `verdict`, `abort` and doubt flags are the controller's attestation of what the provider reported, which
no file the inputs name records. Hit latency reads FAILED on a pacing handoff or a failed cell outside the publish
phase and UNVERIFIED on a preservation handoff alone; a lifted `real-path` gate item reads the hit gate's grade until
that reads VERIFIED. A
rehearsal or tabletop objective for an item decides over a MET or PARTIAL summary, a null or malformed one reads
UNVERIFIED, and a PARTIAL item without one reads UNVERIFIED; an objective naming an item outside the package's `items`
is listed as refused, and that item keeps its own source's grade. A package `check` reports blocked earns no VERIFIED.
Every grade read from a parsed run record is marked `run_record_graded` in the receipt, the MISSING of a record of
another package id or mode included; an absent record and one its owning judge refuses, which is never parsed, carry no
mark. A reviewer entry naming another revision than the inputs `revision` reads STALE, whatever invalidators its item
lists; otherwise its item copies its grade. Either way the item is marked reviewer-graded. A gate item reads VERIFIED
once its gate is lifted.
Dated evidence (a reviewer entry, a game-day run record, a runbook rehearsal) of an item with `max_age_days` demotes a
VERIFIED grade to STALE past that age on `date`, and to UNVERIFIED when it or the inputs carry no date or it postdates
`date`, keeping its identity and its reviewer or run-record mark; other evidence binds by revision and digest alone.

The receipt holds the SHA-256 of the record, the inputs file, this script and each owning judge's script, the pins, each
piece of evidence's identity (for refused evidence the reason and the SHA-256 of each file read before it, and for the
acceptance receipt its own evidence identities), per item its grade, reason and identity, per domain its unresolved
items, per class row its cells by kind (the worst of its citations by ORDER, EXCLUDED, or MISSING with the citations
that grade nothing) and, for a row delegated to the acceptance record, its class verdict, the open gates with their
reasons, the lifted gates the evidence contradicts (a lifted `monitors`, `runbooks`, `gamedays` or `real-path` gate
whose LIFT_EVIDENCE items are unresolved, and the acceptance gate without an accepted receipt at the revision), the
exception register with each exception's declared fields and state and its `canonical` digest, `valid_until` and
`recommended_verdict`: NOT READY while a floor item is
unresolved, an unresolved item has no accepted exception, an authority role is null or a failure class is listed
`unmapped`; READY WITH EXPLICIT EXCEPTIONS when accepted exceptions cover every unresolved item; READY otherwise. An
exception is accepted only with every EXCEPTION_KEYS field named, an `expiry` on or after `date`, an unresolved
non-floor item, and the risk authority as its approver, apart from its risk owner and from the launch authority.
The approver equals the risk authority's text exactly, while the comparisons with the risk owner and with the launch
authority set case and surrounding space aside, so each comparison rejects a handle in doubt.
`valid_until` is an inclusive upper bound: the earliest accepted exception expiry or age limit of dated VERIFIED
evidence, null when neither applies; an item's invalidator, such as a new revision, ends the recommendation sooner and
returns the next wave to a full review. `ready` is true only for READY with no open or contradicted gate, and `judge`
exits 0 only then and 1 otherwise. It exits 2 and writes no receipt on a refused record, inputs file or committed
context, or a failed write, and a file already at `--output` then stays as it was. An `--output` is refused when it does
not resolve, when it names the record, the inputs file, a pinned file, this script, an owning judge's script, a file the
judge read for an inputs entry or a package, comparison or sizing file the acceptance inputs file names, and when it
lies inside a lane tree either file names. Any other `--output` at which an entry exists when the write is due is
refused too: the judge creates its receipt and replaces no file, so a rerun names a new path. That covers a file a
campaign names in turn (a samples file, a receipt or a raw artifact), which its owning judge alone opens; the operator
keeps `--output` apart from a path such a campaign names where no file exists. The receipt holds each
owning judge's script digest read at load, and the run is refused if one changed. The owning judges (OWNING) are the
scripts this process loads to grade evidence, through `acceptance.py` and through the hardware lane, and
`verify-receipts.py`, which the lane runner runs as a command. A lane's `judge_sha256` names `verify-receipts.py`
alone, and this list follows it: the checkers that command loads in its own process are outside both, and the check of
the checkout's tracked files binds them to the revision. The receipt is a recommendation, and its reader is the named
human who authorizes each writable wave in a separate artifact.
"""

import argparse
import datetime
import functools
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tokenize
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RECORD = ROOT / "verification/readiness/failover.json"
SPEC = importlib.util.spec_from_file_location("acceptance", HERE / "acceptance.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("scripts/acceptance.py cannot be loaded")
acc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acc)
mf, gate = acc.mf, acc.gate
Refusal, FAULTS = acc.Refusal, acc.FAULTS


def parse(data, what):
    """`data` decoded as JSON with every object's keys distinct, or this module's Refusal naming `what`."""
    try:
        return acc.rp.parse(data, what)
    except acc.rp.Refusal as error:
        raise Refusal(str(error)) from error


KEYS = {"record", "version", "parent", "pins", "kinds", "gates", "sources", "classes", "items", "floors", "waves",
        "authority", "unmapped"}
PARENT_KEYS = {"digest", "specification", "plan"}
KINDS = (*mf.EVIDENCE, "staging", "rehearsal", "review")
PLAN_KEYS = {"issue", "body_sha256"}
GATE_KEYS = {"owner", "lifts_when", "lifted"}
GATES = ("end-contract", "store-qualification", "real-path", "suffix-damage", "platform-row", "acceptance",
         "trace-replay", "models", "simulation", "monitors", "runbooks", "gamedays", "hardware-multi-shard",
         "fis-multi-attach", "attach-slots", "deploy-gate", "budgets", "authority", "evidence-age")
PINS = {"acceptance_sha256": (acc.RECORD.relative_to(ROOT).as_posix(), None),
        "hardware_profiles_sha256": (gate.MANIFEST.relative_to(ROOT).as_posix(), None),
        "fis_profiles_sha256": ("scripts/fis-profiles.json", None),
        "gamedays_sha256": ("verification/readiness/gamedays.json", "gamedays"),
        "runbooks_sha256": ("docs/runbooks/failover/index.json", "runbooks"),
        "alarms_sha256": ("crates/kestrike/src/failover/report/alarms.json", "monitors")}
OWNER_INPUTS = ("budgets", "authority", "evidence-age")
PLATFORM = "aarch64-r8gb-"
HARDWARE = ("platform-row", "real-path", "hardware-multi-shard", "fis-multi-attach")
END = "preserve-p4-retention-proposed"
DEFERRED = {"hardware-multi-shard": "#255 defers the multi-shard hardware cells and this check holds no rule that "
                                    "judges them",
            "fis-multi-attach": "#255 defers the two-role fault-injection episode and this check holds no rule that "
                                "judges it"}
FAILURE_CLASSES = tuple(f"FC{n}" for n in range(1, 13))
REQUIREMENT = re.compile(r"(#120 )?R([1-9]|1[0-2])")
CLASS_KEYS = {"meaning", "failure_class", "requirement", "delegated", "evidence", "excluded"}
NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
DELEGATE = "acceptance"
GAMEDAY = "gameday"
RECORD_LIMIT = 1 << 20
DELEGATED_FAILURE_CLASSES = {"host-loss": "FC2", "same-host-restart": "FC1", "controller-reset": "FC1",
                             "process-kill": "FC1", "actual-volume-loss": "FC8"}
DOMAINS = ("scope-and-support", "slos-and-failure-semantics", "observability", "capacity-and-quotas",
           "change-and-compatibility", "dependencies", "overload-and-client-behavior", "degraded-modes",
           "data-protection", "security", "runbooks-and-training", "performance", "resilience-tests",
           "launch-execution")
ITEM_KEYS = {"id", "domain", "class", "requirement", "criterion", "kind", "source", "applicability", "invalidators",
             "max_age_days", "floor", "gap_owner"}
FLOORS = ("activation", "safety", "retention", "wave-halt", "safety-alarms")
ACTIVATION = {"end-contract": "review", "store-qualification": "store", "real-path": "hardware",
              "suffix-damage": "review"}
FLOOR_ITEMS = {"wave-halt": {"wave-halt": "staging"},
               "safety-alarms": {"safety-alarm-routing-staging": "staging",
                                 "safety-alarm-routing-production": "review"}}
INVALIDATORS = {"revision": "a release revision other than the one the evidence ran on",
                "manifest": "a change to scripts/hardware-profiles.json or scripts/fis-profiles.json",
                "catalog": "a change to verification/obligations.json or to the alarm catalog",
                "runbook": "a change to a runbook file or to the runbook index",
                "format": "a change to the on-volume or wire format set",
                "incident": "a production incident in the item's domain",
                "guardrail": "a game-day guardrail that fired or changed",
                "policy": "a change to the owner's policy or to state outside the repository: the on-call roster, a "
                          "production route, a provider quota or a vendor contact"}
JOB_KINDS = {**dict.fromkeys(("quint", "tlc", "kani", "verus", "loom", "genmc", "rc11", "sweep"), "model"),
             **dict.fromkeys(("workspace", "long-run", "campaigns", "search", "search-nightly"), "simulation")}
ROLES = ("launch", "risk")
AUTHORIZATION = ["readiness_receipt_sha256", "exception_register_sha256", "release", "az", "color", "decision",
                 "valid_until", "authority"]
INDEX = {"index": "failover-runbooks", "version": 1}
ACTION_KEYS = {"path", "symbol", "sha256"}
ENTRY_KEYS = {"id", "file", "kind", "actions", "alarms", "status", "verified_sha256", "verified_revision", "rungs",
              "paths", "limitations", "rehearsal"}
SHARED = ("status", "verified_sha256", "verified_revision", "rungs", "paths", "limitations", "rehearsal")
STATUSES = ("DRAFT", "VERIFIED", "VERIFIED WITH LIMITATIONS")
RUNGS = ("tabletop", "isolated-live", "game-day")
REHEARSAL_KEYS = {"record_sha256", "executor", "author", "date", "result"}
RESULTS = ("MET", "PARTIAL", "NOT_MET", "INVALID")
VERIFIED = {"VERIFIED": False, "VERIFIED WITH LIMITATIONS": True}
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
SEVERITIES = ("page", "ticket")
GAMEDAY_MODES = {"GD-1": "rehearsal", "GD-2": "causal", "GD-3": "causal", "GD-4": "causal", "GD-5": "rehearsal",
                 "GD-6": "causal", "GD-7": "causal", "GD-8": "causal", "GD-9": "causal", "GD-10": "causal",
                 "GD-11": "tabletop", "GD-12": "rehearsal", "GD-13": "rehearsal", "GD-14": "rehearsal"}
GAMEDAYS = tuple(GAMEDAY_MODES)
GAMEDAY_KEYS = {"id", "mode", "class", "claim", "not_claimed", "hypothesis", "injection", "oracle", "guardrail",
                "restoration", "prerequisites", "runbooks", "items"}
BUDGETS = {"planned-handoff-dark-time": "s", "fresh-host-recovery-time": "s", "re-enrollment-drain": "s",
           "origin-load": "requests/s", "alarm-delivery-time": "s"}
GAMEDAY_BOUNDS = {"GD-1": {("planned-handoff-dark-time", "planned-handoff-staging"),
                           ("re-enrollment-drain", "planned-handoff-staging")},
                  "GD-2": {("origin-load", "host-loss-multi-shard-staging"),
                           ("re-enrollment-drain", "host-loss-multi-shard-staging")},
                  "GD-3": {("fresh-host-recovery-time", "owner-standby-loss-staging"),
                           ("re-enrollment-drain", "owner-standby-loss-staging")},
                  "GD-5": {("origin-load", "az-loss-return-staging")},
                  "GD-7": {("re-enrollment-drain", "control-plane-outage-staging"),
                           ("re-enrollment-drain", "reconciler-stop-staging")},
                  "GD-14": {("alarm-delivery-time", "paging-route-drill-staging")}}
GAMEDAY_ACTIONS = {"GD-8": "aws:ebs:pause-volume-io"}
GAMEDAY_PREREQUISITES = {"GD-1": 5, "GD-2": 4, "GD-3": 6, "GD-4": 4, "GD-5": 3, "GD-6": 4, "GD-7": 4, "GD-8": 6,
                         "GD-9": 4, "GD-10": 4, "GD-11": 2, "GD-12": 5, "GD-13": 5, "GD-14": 3}
GAMEDAY_SAFETY = {"GD-1": ["planned-handoff-staging-safety"], "GD-2": ["host-loss-multi-shard-staging-safety"],
                  "GD-3": ["owner-standby-loss-staging-safety"], "GD-4": ["partition-loss-staging-safety"],
                  "GD-5": ["az-loss-return-staging-safety"], "GD-6": ["store-outage-staging-safety"],
                  "GD-7": ["control-plane-outage-staging-safety", "reconciler-stop-staging-safety"],
                  "GD-8": ["volume-impairment-hold-staging-safety"], "GD-10": ["attach-slots-exhausted-staging-safety"],
                  "GD-12": ["deploy-restart-staging-safety"], "GD-13": ["rollback-refusal-staging-safety"]}
MODE_KINDS = {"causal": "staging", "rehearsal": "staging", "tabletop": "rehearsal"}
RESTORATIONS = ("automatic", "persistent-manual", "destructive")
HOST_STOPS = ("GD-2", "GD-3", "GD-4", "GD-5", "GD-7", "GD-10", "GD-12", "GD-13")
HOST_GUARD = ["any generation change", "any CreateVolume by the reconciler principal"]
TBD = "TBD - BLOCKS EXECUTION"
STANDING = {"monitors": "this check judges the alarm rows' basis only; the judge grades the controls, clean twins "
                        "and routes from the observability and safety-alarms items",
            "runbooks": "this check holds no inventory of operator actions, so the coverage of operator procedures "
                        "(item operator-procedures) is judged outside it",
            "gamedays": "this check judges the catalog's definitions only; the judge grades the run records, which "
                        "stay outside the repository"}
STANDING_PINS = {opens: key for key, (_, opens) in PINS.items() if opens in STANDING}
ENVELOPE = {"version": 1, "section": "readiness"}
FIS_ENVELOPE = {"version": 1, "section": "fis"}
JUDGE_SHA256 = hashlib.sha256(gate.read_file(__file__, "judge")).hexdigest()
# The scripts whose code grades evidence here: each one this process loads, through `acceptance.py` or the hardware
# lane, and `verify-receipts.py`, which the acceptance judge's lane runner runs as a command.
OWNING = ("acceptance.py", "verify-receipts.py", "hit-gate.py", "hardware-lane.py", "recovery-packages.py",
          "measurement-frame.py", "sizing-worksheet.py", "reproduce-test.py", "select-tests.py")


def owning_digests():
    """The SHA-256 of each owning judge's script, read now."""
    return {name: hashlib.sha256(gate.read_file(HERE / name, name)).hexdigest() for name in OWNING}


OWNING_SHA256 = owning_digests()
INPUT_KEYS = {"revision", "date", "acceptance", "lanes", "hit_gate", "fis", "gamedays", "runbooks", "reviews",
              "exceptions"}
GRADES = ("VERIFIED", "FAILED", "STALE", "MISSING", "UNVERIFIED", "NOT APPLICABLE")
REVIEW_GRADES = GRADES[:-1]
ORDER = ("VERIFIED", "NOT APPLICABLE", "UNVERIFIED", "MISSING", "STALE", "FAILED")
RESOLVED = ("VERIFIED", "NOT APPLICABLE")
CELL_GRADES = {"pass": "VERIFIED", "fail": "FAILED", "inconclusive": "UNVERIFIED", "unrun": "MISSING"}
HIT_GRADES = {"pass": "VERIFIED", "fail": "FAILED", "handoff": "FAILED", "inconclusive": "UNVERIFIED"}
VERDICT_GRADES = {(True, "HELD"): "VERIFIED", (True, "DISPROVEN"): "FAILED", (True, "INCONCLUSIVE"): "UNVERIFIED",
                  (False, "MET"): "VERIFIED", (False, "NOT_MET"): "FAILED",
                  (False, "INCONCLUSIVE"): "UNVERIFIED", (False, "INVALID"): "MISSING"}
REVIEW_KEYS = {"item", "reviewer", "revision", "date", "artifact_sha256", "grade", "reason"}
EXCEPTION_KEYS = {"item", "reason", "risk_owner", "approver", "expiry", "compensating_control"}
PRESERVATION, REAL_PATH = "suffix-damage", "real-path"
LIFT_EVIDENCE = {"gamedays": lambda name, i: (i["source"] or "").startswith(f"{GAMEDAY}:"),
                 "monitors": lambda name, i: i["domain"] == "observability" or i["floor"] == "safety-alarms",
                 "runbooks": lambda name, i: name == "operator-procedures"
                 or (i["source"] or "").startswith("runbook:"),
                 REAL_PATH: lambda name, i: i["source"] == "hit-gate"}
DATED = (f"{GAMEDAY}:", "runbook:")
FIS_DOUBTS = ("quarantine", "custody_unknown", "fault_end_unconfirmed")
# The observer role under which `scripts/fis-controller.py` appends its fault-start and fault-end marks.
FIS_ROLE = "fis"
RUN_TEXTS = ("id", "mode", "revision", "run_status", "verdict", "package_sha256", "catalog_sha256", "executor",
             "author")
text, texts = mf.text, mf.texts
RUNBOOKS = "docs/runbooks/failover/"
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
COMMENT = re.compile(r" {0,3}<!--")
LINK = re.compile(r"!?\[([^\[\]]*)\]\([^()]*(?:\([^()]*\)[^()]*)*\)")
INPUT_LIMIT = 1 << 20
HEADING = re.compile(r" {0,3}#{1,6}(?=[ \t]|$)")
LEADING = re.compile(r'(?: {0,3}(?:>(?: |(?! ))|[-+*] |[0-9]{1,9}[.)] ))* {0,3}<a[ \t\f]+(?:id|name)="([^"&\0]+)"'
                     r"""(?:[ \t\f]+[A-Za-z_:][\w.:-]*(?:[ \t\f]*=[ \t\f]*(?:[^\s"'=<>`]+|'[^']*'|"[^"]*"))?)*"""
                     r"[ \t\f]*/?>", re.ASCII)


def filled(value):
    """Whether `value` is a string holding a character other than whitespace."""
    return isinstance(value, str) and bool(value.strip())


def need(condition, message, what="readiness record"):
    acc.need(condition, message, what)


def pinned_files():
    """The bytes of each file PINS names. An absent always-pinned file is refused; an absent optional one reads None,
    and a present optional one, a file this check owns, holds at most INPUT_LIMIT bytes."""
    return {key: gate.read_file(ROOT / path, path) if opens is None
            else gate.read_file(ROOT / path, path, INPUT_LIMIT) if (ROOT / path).exists() else None
            for key, (path, opens) in PINS.items()}


def check_pins(record, ctx):
    """Refuse a pin other than its file's bytes, a pin naming an absent file and a null pin of an always-pinned file."""
    pins = record["pins"]
    need(isinstance(pins, dict) and set(pins) == set(PINS), f"pins are not {sorted(PINS)}")
    for key, (path, opens) in PINS.items():
        value, data = pins[key], ctx["files"][key]
        if value is None:
            need(opens is not None, f"pin {key} is null: {path} is always pinned")
            continue
        need(data is not None, f"pin {key} names {path}, which is absent")
        need(hashlib.sha256(data).hexdigest() == value, f"pin {key} is not the SHA-256 of {path}")


def contradictions(record, ctx, judged):
    """Gate id -> the reasons lifting it contradicts the evidence the repository holds, for each gate whose lifting
    condition the repository records. `judged` maps each gate the record and catalog rules judge to the reasons they
    found, and an empty list leaves the gate uncontradicted. The other lifts are reviewed diffs of the record."""
    found = {}

    def add(name, why):
        found.setdefault(name, []).append(why)

    open_gates, document = ctx["acceptance_gates"], ctx["document"]
    on_end = [case for case in ctx["end_cases"] if case in ctx["quint_blocked"]]
    if on_end:
        add("end-contract", f"{len(on_end)} cases of obligation {END} stay blocked in verification/quint/expected.json")
    if mf.COLUMNS["store"] in open_gates:
        add("store-qualification", f"acceptance.py check lists the store gate {mf.COLUMNS['store']!r}")
    qualification = document["qualification"]
    for item in ctx["hit_gate_open"]:
        add("real-path", f"the manifest's hit-gate qualification is open: {item}")
    if open_gates:
        add("acceptance", f"acceptance.py check lists {len(open_gates)} open gates, so no receipt is accepted")
    if "trace-replay" in ctx["acceptance"]["unrun"]:
        add("trace-replay", "the acceptance record lists trace-replay as an unrun domain")
    preservation = qualification["preservation"]
    if preservation["qualified"] is not True:
        add("suffix-damage", f"preservation {preservation['obligation']} is unqualified")
    rows = [name for name, row in document["platforms"].items()
            if name.startswith(PLATFORM) and row.get("machine") == "aarch64" and row.get("supported") is True]
    if not rows:
        for name in HARDWARE:
            add(name, f"no {PLATFORM}* platform row of machine aarch64 reads supported: true")
    elif not any(document["profiles"][qualification["profile"]]["platforms"].get(name) == "runs" for name in rows):
        add("real-path", f"profile {qualification['profile']} reads runs on no supported {PLATFORM}* row")
    for name, why in DEFERRED.items():
        add(name, why)
    for key, (path, opens) in PINS.items():
        if opens is None:
            continue
        if record["pins"][key] is None:
            exists = " although the file exists" if ctx["files"][key] is not None else ""
            add(opens, f"pin {key} is null, so the record pins no {path}{exists}")
            found[opens] += judged.get(opens, [])
        else:
            found[opens] = found.get(opens, []) + judged[opens]
    for key in OWNER_INPUTS:
        found[key] = judged[key]
    return {name: why for name, why in found.items() if why}


def check_gates(record, ctx, judged):
    """Refuse a malformed gate map or a contradicted lift; return gate id -> its contradictions, in GATES order."""
    gates = record["gates"]
    need(isinstance(gates, dict) and list(gates) == list(GATES), f"gates are not {list(GATES)}, in order")
    for name, g in gates.items():
        need(isinstance(g, dict) and set(g) == GATE_KEYS and filled(g["owner"]) and filled(g["lifts_when"])
             and isinstance(g["lifted"], bool), f"gate {name} is not {sorted(GATE_KEYS)} with text owner and "
             "lifts_when and a boolean lifted")
    found = contradictions(record, ctx, judged)
    for name, whys in found.items():
        need(not gates[name]["lifted"], f"gate {name} is lifted while {'; '.join(whys)}")
    return {name: found[name] for name in GATES if name in found}


def gameday_kind(package, ctx):
    """The evidence kind the validated game-day package `package` produces, its mode's in MODE_KINDS, or None when the
    catalog lacks it."""
    entry = (ctx["packages"] or {}).get(package)
    return entry and MODE_KINDS[entry["mode"]]


def one_home(name, cite, ctx):
    """Refuse a citation that names no source and item, or whose source the acceptance record names or whose item is
    a catalog record or package id it cites, so one receipt keeps one home; return the citation's source."""
    source, _, item = cite.partition(":")
    need(filled(source) and filled(item), f"class {name} cites {cite!r}, which names no source and item")
    need(not any(ch.isspace() for ch in cite), f"class {name} cites {cite!r}, which holds whitespace")
    acceptance_sources, receipt_ids = ctx["acceptance_cited"]
    need(source not in acceptance_sources and item not in receipt_ids, f"class {name} cites {cite}, whose receipt "
         f"has two homes: the acceptance record cites {source if source in acceptance_sources else item}")
    return source


def check_citation(name, kind, cite, record, ctx):
    """Refuse one citation of a row of its own; return the source it names."""
    source = one_home(name, cite, ctx)
    item = cite.partition(":")[2]
    need(source != DELEGATE, f"class {name} cites {cite}: only a row delegated to the acceptance record cites it")
    need(source == GAMEDAY or item.upper() not in GAMEDAYS, f"class {name} cites {cite}: only "
         f"{GAMEDAY}:<GD-n> cites a game-day package")
    if source == GAMEDAY:
        found = gameday_kind(item, ctx)
        need(found is not None, f"class {name} cites {cite}, which names no package of the game-day catalog")
    else:
        found = record["sources"].get(source, {}).get("kind")
        need(found is not None, f"class {name} cites {cite}, whose source {source} is not in the source table")
    need(found == kind, f"class {name} cites {found} source {source} under {kind}: a kind cell credits only its own "
         "evidence kind")
    return source


def check_class(name, c, record, ctx):
    """Refuse a malformed class row; return the names of the readiness sources it cites."""
    need(isinstance(c, dict) and set(c) == CLASS_KEYS, f"class {name} keys are not {sorted(CLASS_KEYS)}")
    need(filled(c["meaning"]), f"class {name} meaning is no text")
    fc, requirement, delegated = c["failure_class"], c["requirement"], c["delegated"]
    named = fc in FAILURE_CLASSES and requirement is None
    evidenced = fc is None and isinstance(requirement, str) and bool(REQUIREMENT.fullmatch(requirement))
    need(named or evidenced, f"class {name} holds neither a failure class FC1 to FC12 with a null requirement nor a "
         "null failure class with a requirement R1 to R12 or #120 R1 to R12")
    need(delegated is None or filled(delegated), f"class {name} delegate is neither null nor a text")
    evidence, excluded = c["evidence"], c["excluded"]
    need(isinstance(evidence, dict) and set(evidence) <= set(KINDS) and all(texts(v) for v in evidence.values()),
         f"class {name} evidence is no distinct non-empty citation list per kind of {list(KINDS)}")
    need(isinstance(excluded, dict) and set(excluded) <= set(KINDS) and all(
        isinstance(v, dict) and set(v) == {"reason", "owner"} and filled(v["reason"]) and filled(v["owner"])
        for v in excluded.values()), f"class {name} exclusions are not a {{reason, owner}} of text per kind of "
         f"{list(KINDS)}")
    both = sorted(set(evidence) & set(excluded))
    need(not both, f"class {name} both cites and excludes {both}")
    need("staging" in evidence or "staging" in excluded, f"class {name} has neither a staging citation nor a written "
         "staging exclusion")
    if delegated is not None:
        # The one-home rule names a receipt's second home before the delegation rules below refuse the citation.
        for cite in (cite for cites in evidence.values() for cite in cites if cite != f"{DELEGATE}:{name}"):
            one_home(name, cite, ctx)
    if delegated == DELEGATE:
        need(name in ctx["acceptance"]["classes"], f"class {name} is delegated to the acceptance record, which holds "
             "no such class")
        bound = DELEGATED_FAILURE_CLASSES[name]
        need(fc == bound, f"class {name} is delegated to the acceptance record, whose {name} class evidences {bound}, "
             f"and names {fc}")
        need(evidence == {kind: [f"{DELEGATE}:{name}"] for kind in mf.EVIDENCE}, f"class {name} is delegated to the "
             f"acceptance record and cites anything but {DELEGATE}:{name} under each of {list(mf.EVIDENCE)}")
        return set()
    if delegated is not None:
        need(not evidence and set(excluded) == set(KINDS), f"class {name} is delegated to {delegated} and cites "
             "evidence or leaves a kind unexcluded")
        return set()
    need(fc is None or set(excluded) != set(KINDS), f"class {name} names {fc} and excludes every kind, so no evidence "
         "of its own can stand behind it")
    return {check_citation(name, kind, cite, record, ctx) for kind, cites in evidence.items() for cite in cites}


def check_classes(record, ctx):
    """Refuse a malformed source table, class table or failure-class map; return the report's class sections."""
    sources, classes, unmapped = record["sources"], record["classes"], record["unmapped"]
    acceptance_classes = ctx["acceptance"]["classes"]
    if set(DELEGATED_FAILURE_CLASSES) != set(acceptance_classes):
        raise Refusal(f"readiness.py binds failure classes to the acceptance classes "
                      f"{sorted(DELEGATED_FAILURE_CLASSES)}, and the acceptance record holds "
                      f"{sorted(acceptance_classes)}")
    acceptance_sources, _ = ctx["acceptance_cited"]
    need(isinstance(sources, dict), "sources is no map of sources")
    for name, s in sources.items():
        need(isinstance(s, dict) and set(s) == {"kind", "owner", "evidence"} and s["kind"] in KINDS
             and filled(s["owner"]) and filled(s["evidence"]), f"source {name} is not {{kind, owner, evidence}} "
             f"with a kind of {list(KINDS)} and text owner and evidence")
    need(GAMEDAY not in sources, f"source {GAMEDAY} names the game-day catalog")
    need(isinstance(classes, dict) and classes, "classes is no non-empty map of class rows")
    misnamed = sorted(name for name in [*sources, *classes] if not NAME.fullmatch(name))
    need(not misnamed, f"names {misnamed} are not lowercase words joined by hyphens")
    # The cited-by-no-class rule below also refuses a reserved source; this rule names the reservation first.
    reserved = sorted(set(sources) & (acceptance_sources | {DELEGATE}))
    need(not reserved, f"sources {reserved} are named like the acceptance record or one of its sources")
    cited = set().union(*(check_class(name, c, record, ctx) for name, c in classes.items()))
    need(set(sources) <= cited, f"sources {sorted(set(sources) - cited)} are cited by no class")
    delegated_rows = {name for name, c in classes.items() if c["delegated"] == DELEGATE}
    need(delegated_rows == set(acceptance_classes), f"the rows delegated to the acceptance record are not its classes "
         f"{sorted(acceptance_classes)}")
    need(isinstance(unmapped, dict) and set(unmapped) <= set(FAILURE_CLASSES) and all(map(filled, unmapped.values())),
         "unmapped is no reason per failure class")
    rows_by_fc = {fc: [name for name, c in classes.items() if c["failure_class"] == fc] for fc in FAILURE_CLASSES}
    missing = [fc for fc in FAILURE_CLASSES if not rows_by_fc[fc] and fc not in unmapped]
    need(not missing, f"failure classes {missing} are named by no class row and explained by no unmapped entry")
    twice = [fc for fc in unmapped if rows_by_fc[fc]]
    need(not twice, f"failure classes {twice} are named by a class row and listed unmapped")
    unheld = [fc for fc, names in rows_by_fc.items()
              if names and all(set(classes[name]["excluded"]) == set(KINDS) for name in names)]
    need(not unheld, f"failure classes {unheld} are named only by rows that exclude every kind, so no row can hold "
         "their evidence")
    rows = {}
    for name, c in classes.items():
        rows[name] = {"failure_class": c["failure_class"], "requirement": c["requirement"],
                      "delegated": c["delegated"],
                      "open": [k for k in KINDS if k not in c["evidence"] and k not in c["excluded"]],
                      "excluded": [k for k in KINDS if k in c["excluded"]]}
        if c["delegated"] == DELEGATE:
            rows[name]["unrun"] = [k for k in mf.EVIDENCE if k in acceptance_classes[name]["unrun"]]
    return {"failure_classes": rows_by_fc, "unmapped": dict(unmapped), "classes": rows}


def distinct_texts(value):
    """Whether `value` is a non-empty list of distinct strings, each holding a character other than whitespace."""
    return isinstance(value, list) and bool(value) and all(map(filled, value)) and len(set(value)) == len(value)


def item_source(item, record, ctx, runbook_ids):
    """Refuse an item whose source is outside the grammar or names evidence of another kind than the item's."""
    name, kind, source = item["id"], item["kind"], item["source"]
    need(source is None or filled(source), f"item {name} source is neither null nor a text")
    need(kind != "review" or source is None or source == "review" or source.startswith("gate:"),
         f"item {name} is a review item whose source {source!r} is a machine receipt")
    if source is None or source == "review":
        need(source is None or kind == "review", f"item {name} cites a reviewer but is of kind {kind}")
        return
    head, _, rest = source.partition(":")
    cls, floor = item["class"], item["floor"]
    delegated = record["classes"].get(cls, {}).get("delegated") == DELEGATE
    need(not delegated or floor not in ("safety", "retention") or kind not in mf.EVIDENCE
         or source == f"{DELEGATE}:{cls}/{floor}", f"item {name} is a {floor} floor item of acceptance class {cls}, so "
         f"it cites {DELEGATE}:{cls}/{floor} or is an open gap, and cites {source}")
    if head == "gate":
        # Named first: the binding rule below also refuses an unknown gate.
        need(rest in GATES, f"item {name} cites gate {rest!r}, which is no gate")
        need(name == rest and floor == "activation" and ACTIVATION.get(rest) == kind, f"item {name} cites {source}: a "
             "gate source belongs to the activation floor item named for that gate, of the kind ACTIVATION gives it")
    elif head == DELEGATE:
        cited, _, column = rest.partition("/")
        need(cls == cited and delegated and column in acc.COLUMNS and kind in mf.EVIDENCE, f"item {name} cites "
             f"{source}: an acceptance item reads one acceptance kind cell of its own delegated class")
        need(column != "retention" or not ctx["acceptance"]["classes"][cls]["cold"], f"item {name} cites the "
             f"retention of {cls}, which starts cold and claims no retention")
        need(column in ctx["acceptance"]["classes"][cls]["evidence"].get(kind, {}), f"item {name} cites {source} "
             f"under {kind}, a cell the acceptance record cites nothing in")
    elif head == "record":
        entry = ctx["catalog"].get(rest)
        need(entry is not None, f"item {name} cites catalog record {rest!r}, which the catalog lacks")
        need(JOB_KINDS.get(entry["job"]) == kind, f"item {name} cites record {rest} of job {entry['job']}, which is "
             f"no {kind} evidence")
        need(rest not in ctx["acceptance_cited"][1], f"item {name} cites {rest}, whose receipt has two homes: the "
             "acceptance record cites it")
    elif head == "runbook":
        need(kind == "rehearsal" and rest in runbook_ids, f"item {name} cites {source}: a runbook item is a "
             "rehearsal of an index entry")
    elif head == GAMEDAY:
        found = gameday_kind(rest, ctx)
        need(found is not None, f"item {name} cites {source}, which names no package of the game-day catalog")
        need(found == kind, f"item {name} cites {source}: a game-day item is of the evidence kind its package's mode "
             "produces, a tabletop rehearsal and a staging run staging")
    elif source == "hit-gate" or head == "fis":
        need(kind == "hardware" and (head != "fis" or rest in ctx["fis"]["profiles"]), f"item {name} cites "
             f"{source}: a hit-gate or fault-injection item is hardware evidence of a named profile")
    else:
        need(False, f"item {name} cites {source!r}, which names no source this record grades")


def applicable(value):
    """Whether `value` is `applicable` or {not_applicable, approver}: a reason and a null or named approver."""
    return value == "applicable" or isinstance(value, dict) and set(value) == {"not_applicable", "approver"} and filled(
        value["not_applicable"]) and (value["approver"] is None or filled(value["approver"]))


def check_item(i, record, ctx, runbook_ids):
    """Refuse one item off its shape, its class row or its source grammar."""
    name, cls, kind = i["id"], i["class"], i["kind"]
    need(filled(i["criterion"]), f"item {name} has no criterion")
    need(i["domain"] in DOMAINS, f"item {name} domain {i['domain']!r} is none of {list(DOMAINS)}")
    need(cls is None or isinstance(cls, str) and cls in record["classes"], f"item {name} names no class row")
    need(isinstance(i["requirement"], str) and REQUIREMENT.fullmatch(i["requirement"]), f"item {name} names "
         "no requirement")
    row = record["classes"][cls] if cls is not None else {}
    need(not row.get("requirement") or i["requirement"] == row["requirement"], f"item {name} names "
         f"{i['requirement']}, but its class {cls} evidences {row.get('requirement')}")
    need(kind in KINDS, f"item {name} kind {kind!r} is none of {list(KINDS)}")
    need(applicable(i["applicability"]), f"item {name} applicability is neither applicable nor {{not_applicable, "
         "approver}")
    need(i["applicability"] == "applicable" or i["floor"] in (None, "retention"), f"item {name} is a {i['floor']} "
         "floor item, and only an item off the floors or on the retention floor may read not applicable")
    need(i["applicability"] != "applicable" or kind not in row.get("excluded", {}), f"item {name} is an applicable "
         f"{kind} item of class {cls}, which excludes {kind}")
    need(distinct_texts(i["invalidators"]) and set(i["invalidators"]) <= set(INVALIDATORS), f"item {name} invalidators "
         f"are no distinct list of {list(INVALIDATORS)}")
    need(i["max_age_days"] is None or gate.integer(i["max_age_days"], 1), f"item {name} max_age_days")
    need(i["floor"] is None or i["floor"] in FLOORS, f"item {name} floor {i['floor']!r} is none of {list(FLOORS)}")
    need(filled(i["gap_owner"]), f"item {name} names no gap owner")
    item_source(i, record, ctx, runbook_ids)


def check_floors(record, ctx, by_floor):
    """Refuse a floor without the items FLOORS, ACTIVATION and FLOOR_ITEMS require of it, and a class row without
    its safety item and, when warm, its retention item."""
    need(all(by_floor.values()), f"floors {[f for f, held in by_floor.items() if not held]} hold no item")
    activation = {i["id"]: i["source"] for i in by_floor["activation"]}
    need(activation == {g: f"gate:{g}" for g in ACTIVATION}, f"the activation floor is not the items of gates "
         f"{list(ACTIVATION)}")
    for floor, required in FLOOR_ITEMS.items():
        held = {i["id"]: i["kind"] for i in by_floor[floor]}
        missing = [f"{name} ({kind})" for name, kind in required.items() if held.get(name) != kind]
        need(not missing, f"the {floor} floor lacks {missing}: it holds each item FLOOR_ITEMS names at its kind")
    acceptance = ctx["acceptance"]["classes"]
    for name, c in record["classes"].items():
        cold = c["delegated"] == DELEGATE and acceptance[name]["cold"]
        retention = [i["id"] for i in by_floor["retention"] if i["class"] == name]
        need(not cold or not retention, f"class {name} starts cold and claims no retention, but holds retention "
             f"floor items {retention}")
        waived = [i["id"] for i in by_floor["retention"] if i["class"] == name and i["applicability"] != "applicable"]
        need(c["delegated"] != DELEGATE or not waived, f"class {name} is a warm acceptance class, so its retention "
             f"floor items {waived} cannot read not applicable")
        if c["delegated"] not in (None, DELEGATE) or set(c["excluded"]) == set(KINDS):
            continue
        for floor in ("safety", *(() if cold else ("retention",))):
            kinds = [i["kind"] for i in by_floor[floor] if i["class"] == name]
            need(kinds and len(set(kinds)) == len(kinds), f"class {name} holds {len(kinds)} {floor} floor items, "
                 "not at least one and at most one per kind")
        safety = [i["kind"] for i in by_floor["safety"] if i["class"] == name]
        need(c["delegated"] is not None or "simulation" in c["excluded"] or "simulation" in safety, f"class {name} "
             "holds no simulation safety floor item: a staging safety item stands beside its safety column")


def check_items(record, ctx, runbook_ids):
    """Refuse a malformed item table or floor map; return the report's item sections and the evidence-age and
    authority reasons."""
    items, floors = record["items"], record["floors"]
    need(isinstance(items, list) and items and all(isinstance(i, dict) and set(i) == ITEM_KEYS for i in items),
         f"items are no list of {sorted(ITEM_KEYS)} objects")
    ids = [i["id"] for i in items]
    need(all(map(filled, ids)) and len(set(ids)) == len(ids), "item ids are no distinct texts")
    for i in items:
        check_item(i, record, ctx, runbook_ids)
    by_domain = {d: [i["id"] for i in items if i["domain"] == d] for d in DOMAINS}
    empty = [d for d, held in by_domain.items() if not held]
    need(not empty, f"domains {empty} hold no item")
    need(isinstance(floors, dict) and list(floors) == list(FLOORS) and all(map(filled, floors.values())),
         f"floors are not {list(FLOORS)} with a meaning each")
    by_floor = {f: [i for i in items if i["floor"] == f] for f in FLOORS}
    check_floors(record, ctx, by_floor)
    waived = {i["id"]: dict(i["applicability"]) for i in items if i["applicability"] != "applicable"}
    report = {"domains": by_domain, "floors": {f: [i["id"] for i in held] for f, held in by_floor.items()},
              "not_applicable": waived,
              "gaps": {i["id"]: i["gap_owner"] for i in items if i["source"] is None and i["id"] not in waived}}
    reasons = {"evidence-age": [f"POLICY UNDEFINED: item {i['id']} has a null max_age_days" for i in items
                                if i["max_age_days"] is None],
               "authority": [f"item {name} reads not applicable with no approver: {w['not_applicable']}"
                             for name, w in waived.items() if w["approver"] is None]}
    return report, reasons


def same_person(a, b):
    """Whether handles `a` and `b` read alike once case and surrounding whitespace are set aside."""
    return a.strip().casefold() == b.strip().casefold()


def check_launch(record):
    """Refuse a malformed wave plan or authority; return the authority gate's reasons."""
    waves, authority = record["waves"], record["authority"]
    need(isinstance(waves, dict) and set(waves) == {"unit", "order", "authorization"} and waves["unit"] == "az-color"
         and distinct_texts(waves["order"]) and waves["authorization"] == AUTHORIZATION, "waves are not one az-color "
         f"unit at a time in an order, each authorized by {AUTHORIZATION}")
    need(isinstance(authority, dict) and list(authority) == list(ROLES) and all(
        v is None or filled(v) for v in authority.values()), f"authority is not the roles {list(ROLES)}, each null or "
         "a role")
    reasons = [f"authority role {role} is null" for role, v in authority.items() if v is None]
    if None not in authority.values() and same_person(authority["launch"], authority["risk"]):
        reasons.append("authority roles launch and risk name one role, and the launch authority is never the only "
                       "accepter of the residual risk")
    return {"authority": reasons}


def runbook_slug(value):
    """Whether `value` is a runbook slug, the id of a runbook index entry: a letter or digit, then letters, digits,
    `-` and `_`."""
    return isinstance(value, str) and SLUG.fullmatch(value) is not None


def check_alarms(ctx):
    """The alarm catalog's rows as id -> row, or None when it is absent; refuse a malformed catalog."""
    data = ctx["files"]["alarms_sha256"]
    if data is None:
        return None
    catalog = parse(data, "alarm catalog")
    rows = catalog.get("rows") if isinstance(catalog, dict) else None
    if not isinstance(rows, list) or not all(
            isinstance(r, dict) and filled(r.get("id")) and r.get("severity") in SEVERITIES
            and runbook_slug(r.get("runbook")) for r in rows):
        raise Refusal("malformed alarm catalog: it holds no rows list of {id, severity page or ticket, runbook "
                      "slug}")
    ids = [r["id"] for r in rows]
    need(len(set(ids)) == len(ids), "an alarm id repeats", "alarm catalog")
    need(all(r.get("basis") is None or isinstance(r["basis"], dict) and all(map(filled, r["basis"].values()))
             for r in rows), "a row's basis is neither null nor an object of labels", "alarm catalog")
    return {r["id"]: r for r in rows}


def anchors(content):
    """The anchors a Markdown file defines as GitHub renders them, read line by line over a subset of Markdown, from the
    lines outside fenced blocks and HTML comment blocks. A fence opens, behind at most three spaces, on a run of three
    or more backticks (whose remainder holds no backtick) or tildes and closes on such a run of its opening character at
    least as long, followed by spaces and tabs alone; a comment block opens on a line led by `<!--` with no `-->` after
    its `<!` and closes on the line holding `-->`. Lines end at LF, CR or CRLF. A visible line contributes the id or
    name of an `<a id="...">` or `<a name="...">` whose whole open tag leads the line (LEADING): at most three spaces
    and the quote and list markers the line begins with (`>` with one space, a bullet or an ordered marker with its one
    space, each after at most three spaces), then `<a`, the quoted id or name, any further attributes and `>` or `/>`,
    with spaces, tabs or form feeds between them. Nothing earlier on the line can then own the tag, and no line of an
    indented code block matches: such a line is indented four columns past the markers on it, or four columns past the
    content of a list item an earlier line opened. An id or name holding `&` counts nothing, since the page decodes it
    to another id. A visible line also contributes an ATX heading's slug, read from the heading's source text. A slug
    keeps a link's text and drops its destination, which may hold one level of balanced parentheses; it drops a closing
    run of `#` that follows whitespace, is lowercased, loses every character other than a letter, a digit, `-`, `_` and
    a space, and reads each space as `-`. A repeated slug takes the suffix `-N`, N raised until the result differs from
    every earlier heading anchor.

    The scan reads each line alone. Of the page's structure it models the fenced and comment blocks the first paragraph
    states and nothing else: a quote, a list item, a raw HTML block, indented code and a span that runs across the lines
    of a paragraph are unseen. So it differs from the page in two directions. It hides a rendered anchor that follows
    other content on its line, a heading on a quote or list-marker line, the page's slug of a heading that holds markup
    other than a link (a tag, emphasis markers or an entity, which stay in the scan's slug), and an anchor on a line
    indented four columns inside a list item. A path naming such an anchor is refused by name, and the anchor counts
    once its tag leads a line. It counts an anchor or heading that the page shows as code or text, or hides, on a line
    an unseen construct holds. A code span, a comment, a tag or a link that opens on an earlier line of the paragraph
    and closes on a later one holds the lines between. A raw HTML block holds its lines up to the next blank line when a
    line led by a block tag such as `<details>` opens it, or a line that holds a lone complete tag and continues no
    paragraph (the file's first line, or a line after a blank line, a heading or a closed block), and up to its closing
    tag when `<pre>`, `<script>`, `<style>` or `<textarea>` opens it; the page shows an ATX line inside it as text and
    opens no fence on a run inside it. A fenced or comment block inside a quote, or opened on a list item's marker line,
    opens nothing in the scan, which reads its lines as text. The scan's fence opens and closes only on a line that
    starts with a fence run behind at most three spaces. The page's differs in a list item and in a raw HTML block: it
    opens a fence on an item's marker line and behind four or more columns (a tab included) on the item's later lines,
    closes an item's fence on a run behind that many columns and where the item ends, and opens none on a run inside a
    raw HTML block. Where the two differ, the scan's fence state leaves the page's until a later run brings them
    together: the scan reads lines the page fences as text, so an anchor or heading on one counts when the line is
    indented under four columns, and it can read the fenced blocks that follow as text and the text between them as
    fenced."""
    found, seen, fence, comment = set(), {}, None, False
    for line in re.split(r"\r\n?|\n", content):
        if comment:
            comment = "-->" not in line
            continue
        marker = FENCE.match(line)
        if fence is not None:
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence) and not marker.group(
                    2).strip(" \t"):
                fence = None
            continue
        if marker and not (marker.group(1)[0] == "`" and "`" in marker.group(2)):
            fence = marker.group(1)
            continue
        opener = COMMENT.match(line)
        if opener and "-->" not in line[opener.end() - 2:]:
            comment = True
            continue
        lead = LEADING.match(line)
        if lead:
            found.add(lead.group(1))
        heading = HEADING.match(line)
        if not heading:
            continue
        words = line[heading.end():].strip()
        closed = words.rstrip("#")
        if closed != words and (not closed or closed[-1] in " \t"):
            words = closed.strip()
        title = LINK.sub(r"\1", words).lower()
        base = anchor = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        while anchor in seen:
            seen[base] += 1
            anchor = f"{base}-{seen[base]}"
        seen[anchor] = 0
    return found | set(seen)


def dated(value):
    """Whether `value` is a calendar date written YYYY-MM-DD."""
    try:
        return isinstance(value, str) and DATE.fullmatch(value) is not None and bool(datetime.date.fromisoformat(value))
    except ValueError:
        return False


def need_index(condition, message):
    need(condition, message, "runbook index")


def runbook_file(name, path, root):
    """The bytes and text of runbook `path`, a file whose resolved path from `root` is `path` itself, under
    docs/runbooks/failover/, of at most INPUT_LIMIT bytes; refuse any other spelling, a link out of that directory
    and a file that does not decode as UTF-8."""
    need_index(path.startswith(RUNBOOKS), f"runbook {name} names {path}, which is no file under {RUNBOOKS}")
    try:
        target = (root / path).resolve(strict=True)
        canonical = target.relative_to(root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        target, canonical = None, None
    if target is None or canonical != path or not target.is_file():
        raise Refusal(f"malformed runbook index: runbook {name} names {path}, which is no file under {RUNBOOKS} in its "
                      "own spelling")
    data = gate.read_file(target, f"runbook {name}", INPUT_LIMIT)
    try:
        return data, data.decode()
    except UnicodeDecodeError as error:
        raise Refusal(f"malformed runbook index: runbook {name} names {path}, which is no UTF-8 text: "
                      f"{error}") from error


def source_text(path, data):
    """Whether `data`, the bytes of source `path`, decodes as its language reads it: Rust as UTF-8, Python in the
    encoding its PEP 263 line or byte-order mark declares (UTF-8 by default)."""
    try:
        encoding = tokenize.detect_encoding(io.BytesIO(data).readline)[0] if path.endswith(".py") else "utf-8"
        data.decode(encoding)
    except (SyntaxError, LookupError, UnicodeDecodeError):
        return False
    return True


def check_action(name, action, verified):
    """Refuse an action anchor whose digest is malformed, whose path is another spelling than its source's
    repository-relative path, whose source holds more than INPUT_LIMIT bytes, that does not resolve as production code,
    whose source changes between its digest and its anchor being read, or whose source does not decode as its language
    reads it, a verified entry's action without a digest and a DRAFT entry's action with one; return why the entry reads
    STALE (the source changed after its sha256 was recorded), or None. The size is judged before the source is read or
    parsed."""
    path, symbol, digest = action["path"], action["symbol"], action["sha256"]
    need_index(digest is None or mf.digest(digest), f"runbook {name} action {path} {symbol!r} sha256 is neither null "
               "nor a SHA-256")
    target = mf.repository_path(path)[1] if filled(path) else None
    need_index(target is None or target.relative_to(mf.ROOT).as_posix() == path, f"runbook {name} action {path} is "
               "not its source's repository-relative path")
    data = (gate.read_file(target, f"runbook {name} action source", INPUT_LIMIT)
            if target is not None and target.is_file() else b"")
    why = mf.resolve(action, producer=True)
    need_index(target is None or not target.is_file()
               or gate.read_file(target, f"runbook {name} action source", INPUT_LIMIT) == data,
               f"runbook {name} action source {path} changed while the check read it")
    need_index(why is None, f"runbook {name} is STALE: its action anchor {path} {symbol!r} does not resolve as "
               f"production code: {why}")
    need_index(source_text(path, data), f"runbook {name} is STALE: its action source {path} does not decode as its "
               "language reads it")
    need_index(verified == (digest is not None), f"runbook {name} is "
               f"{'verified without' if verified else 'DRAFT with'} the sha256 of its action source {path}")
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        return f"runbook {name} is STALE: its action source {path} changed after its sha256 was recorded"
    return None


def check_rehearsal(name, e, defined):
    """Refuse a malformed rehearsal, one its author executed, and a status other than DRAFT without the rehearsal,
    rung, paths, digest and revision it needs; `defined` holds the file's anchors, which `paths` names."""
    status, r = e["status"], e["rehearsal"]
    need_index(r is None or isinstance(r, dict) and set(r) == REHEARSAL_KEYS, f"runbook {name} rehearsal is neither "
               f"null nor {sorted(REHEARSAL_KEYS)}")
    if r is not None:
        need_index(mf.digest(r["record_sha256"]), f"runbook {name} rehearsal record_sha256 is no SHA-256")
        need_index(filled(r["executor"]) and filled(r["author"]), f"runbook {name} rehearsal names no executor and "
                   "author handle")
        need_index(dated(r["date"]), f"runbook {name} rehearsal date is no YYYY-MM-DD calendar date")
        need_index(r["result"] in RESULTS, f"runbook {name} rehearsal result is none of {list(RESULTS)}")
        need_index(not same_person(r["executor"], r["author"]), f"runbook {name} was rehearsed by its author: a "
                   "rehearsal counts only when someone other than the author executes it")
    unknown = sorted(set(e["paths"]) - defined)
    need_index(not unknown, f"runbook {name} paths {unknown} are no anchors of {e['file']}")
    if status == "DRAFT":
        return
    limited = VERIFIED[status]
    need_index(r is not None and r["result"] == "MET", f"runbook {name} reads {status} without a MET rehearsal")
    need_index(bool(e["limitations"]) == limited, f"runbook {name} reads {status} "
               f"{'without' if limited else 'with'} limitations")
    need_index("tabletop" in e["rungs"], f"runbook {name} reads {status} without the tabletop rung")
    need_index(bool(e["paths"]), f"runbook {name} reads {status}, but its rehearsal names no path of {e['file']}")
    need_index(e["verified_sha256"] is not None and e["verified_revision"] is not None, f"runbook {name} reads "
               f"{status} without a verified digest and revision")


def check_entry(e, linked, root):
    """Refuse a malformed runbook index entry; return why it reads STALE, or None. `linked` maps each runbook slug to
    the alarm ids whose rows name it, or is None while the alarm catalog is absent."""
    need_index(isinstance(e, dict) and set(e) == ENTRY_KEYS, f"an entry is not {sorted(ENTRY_KEYS)}")
    name, path = e["id"], e["file"]
    need_index(runbook_slug(name), f"runbook id {name!r} is no slug")
    need_index(filled(path), f"runbook {name} names no file")
    data, content = runbook_file(name, path, root)
    defined = anchors(content)
    need_index(e["kind"] in ("procedure", "investigation"), f"runbook {name} kind is neither procedure nor "
               "investigation")
    need_index(e["status"] in STATUSES, f"runbook {name} status is none of {list(STATUSES)}")
    actions = e["actions"]
    need_index(isinstance(actions, list) and all(isinstance(a, dict) and set(a) == ACTION_KEYS for a in actions),
               f"runbook {name} actions are no {sorted(ACTION_KEYS)} list")
    stale = [why for why in (check_action(name, a, e["status"] != "DRAFT") for a in actions) if why]
    need_index(isinstance(e["alarms"], list) and all(map(filled, e["alarms"])), f"runbook {name} alarms are no list "
               "of alarm ids")
    if linked is not None:
        unknown = sorted(set(e["alarms"]) - set().union(*linked.values()))
        need_index(not unknown, f"runbook {name} names unknown alarms {unknown}")
        need_index(sorted(e["alarms"]) == linked.get(name, []), f"runbook {name} names alarms "
                   f"{sorted(e['alarms'])}, but the alarm catalog rows that link it are {linked.get(name, [])}")
    need_index(e["verified_sha256"] is None or mf.digest(e["verified_sha256"]), f"runbook {name} verified_sha256 is "
               "neither null nor a SHA-256")
    need_index(e["verified_revision"] is None or isinstance(e["verified_revision"], str)
               and mf.COMMIT.fullmatch(e["verified_revision"]), f"runbook {name} verified_revision is neither null "
               "nor a commit")
    rungs = e["rungs"]
    need_index(isinstance(rungs, list) and all(isinstance(g, str) and g in RUNGS for g in rungs)
               and len(set(rungs)) == len(rungs), f"runbook {name} rungs are no distinct list of {list(RUNGS)}")
    need_index(all(isinstance(e[k], list) and all(map(filled, e[k])) for k in ("paths", "limitations")),
               f"runbook {name} paths and limitations are no lists of text")
    check_rehearsal(name, e, defined)
    if e["verified_sha256"] and hashlib.sha256(data).hexdigest() != e["verified_sha256"]:
        stale.insert(0, f"runbook {name} is STALE: {path} changed after its verified_sha256 was recorded")
    return "; ".join(stale) or None


def runbook_index(ctx):
    """The runbook index parsed from the bytes `check_pins` compares with its pin, or an empty index when the file is
    absent; refuse an envelope other than INDEX with an entries list."""
    data = ctx["files"]["runbooks_sha256"]
    index = parse(data, "runbook index") if data is not None else {**INDEX, "entries": []}
    need_index(isinstance(index, dict) and set(index) == {*INDEX, "entries"} and index["index"] == INDEX["index"]
               and type(index["version"]) is int and index["version"] == INDEX["version"]
               and isinstance(index["entries"], list), f"the index is not {INDEX} with an entries list")
    return index["entries"]


def monitors(alarms):
    """The monitors gate's reasons from the alarm catalog's rows, or from its absence (None). A row rests on an
    assumed basis when any of its numbers carries the label `assumed`, and states no basis when it labels no number."""
    if alarms is None:
        return ["the alarm catalog is absent, so the alarm cross-check is skipped"]
    bases = {a: [label.strip().casefold() for label in (r.get("basis") or {}).values()] for a, r in alarms.items()}
    assumed = [a for a, labels in bases.items() if "assumed" in labels]
    unstated = [a for a, labels in bases.items() if not labels]
    return [*([f"alarm rows {assumed} carry basis assumed"] if assumed else []),
            *([f"alarm rows {unstated} state no basis"] if unstated else []),
            *([] if alarms else ["the alarm catalog holds no row"])]


def check_runbooks(record, ctx, alarms):
    """Refuse a malformed runbook index; return each entry's status, the alarm cross-check's state and the runbooks
    reasons. `alarms` holds the alarm catalog's rows, or is None while the catalog is absent."""
    entries = runbook_index(ctx)
    linked = None
    if alarms is not None:
        linked = {}
        for a, r in alarms.items():
            linked.setdefault(r["runbook"], []).append(a)
        linked = {slug: sorted(ids) for slug, ids in linked.items()}
    checked = [(e, check_entry(e, linked, ctx["root"])) for e in entries]
    statuses = {e["id"]: "STALE" if why else e["status"] for e, why in checked}
    need_index(len(statuses) == len(entries), "a runbook id repeats")
    by_file = {}
    for e in entries:
        first = by_file.setdefault(e["file"], e)
        need_index({k: first[k] for k in SHARED} == {k: e[k] for k in SHARED}, f"runbook entries of {e['file']} "
                   f"differ in {list(SHARED)}: one file has one verification and one rehearsal")
    reasons = [why for _, why in checked if why]
    reasons += [f"runbook {e['id']} is DRAFT" for e in entries if e["status"] == "DRAFT"]
    reasons += [f"runbook {e['id']} reads VERIFIED WITH LIMITATIONS, so it holds the gate until a later rehearsal "
                f"lets it read VERIFIED: {'; '.join(e['limitations'])}" for e, why in checked
                if e["status"] == "VERIFIED WITH LIMITATIONS" and not why]
    if not entries:
        reasons.append("the runbook index holds no entry")
    if alarms is None:
        reasons.append("the alarm catalog is absent, so no runbook slug is checked")
        cross_check = "skipped: the alarm catalog is absent"
    else:
        if record["pins"]["alarms_sha256"] is None:
            reasons.append("pin alarms_sha256 is null, so the rows these entries answer are unpinned")
        if not alarms:
            reasons.append("the alarm catalog holds no row")
        reasons += [f"{r['severity']} alarm {a} names runbook {r['runbook']}, which has no index entry"
                    for a, r in alarms.items() if r["runbook"] not in statuses]
        cross_check = f"checked: {len(alarms)} alarm rows against {len(entries)} index entries"
    return statuses, cross_check, {"runbooks": reasons}


def check_fis(ctx):
    """Refuse a fault-injection profile manifest without a profiles map and an eligible-types map; return the
    manifest."""
    fis = ctx["fis"]
    need(isinstance(fis, dict) and isinstance(fis.get("profiles"), dict) and isinstance(fis.get("eligible_types"), dict)
         and all(isinstance(row, dict) for row in fis["profiles"].values()), "it holds no profiles map of objects and "
         "no eligible_types map", "fault-injection profiles")
    return fis


def check_gameday_catalog(ctx, runbooks):
    """Refuse a malformed game-day catalog; return its entries by id, or None when its file is absent. `runbooks` holds
    the runbook index ids."""
    if ctx["files"]["gamedays_sha256"] is None:
        return None
    catalog = ctx["gamedays"]
    ok = functools.partial(need, what="game-day catalog")
    ok(isinstance(catalog, dict) and set(catalog) == {"catalog", "version", "run_rule", "budgets", "entries"}
       and catalog["catalog"] == "failover-gamedays" and gate.integer(catalog["version"], 1)
       and filled(catalog["run_rule"]), "the head is not failover-gamedays {version, run_rule, budgets, entries}")
    budgets, entries = catalog["budgets"], catalog["entries"]
    ok(isinstance(budgets, dict) and list(budgets) == list(BUDGETS) and all(
        isinstance(b, dict) and set(b) == {"unit", "meaning", "value"} and b["unit"] == BUDGETS[k]
        and filled(b["meaning"]) and (b["value"] is None or gate.positive(b["value"])) for k, b in budgets.items()),
       f"budgets are not {BUDGETS} by id and unit, each {{unit, meaning, value null or positive}}")
    ok(isinstance(entries, list) and all(isinstance(e, dict) and set(e) == GAMEDAY_KEYS for e in entries)
       and [e["id"] for e in entries] == list(GAMEDAYS), f"entries are not {list(GAMEDAYS)} of {sorted(GAMEDAY_KEYS)}")
    for e in entries:
        check_package(e, budgets, ctx["fis"], runbooks, ok)
    return {e["id"]: e for e in entries}


def check_package(e, budgets, fis, runbooks, ok):
    """Refuse one game-day entry off its shape through `ok`, which names the catalog in the refusal."""
    name, hypothesis, oracle, injection, restoration = (e[k] for k in ("id", "hypothesis", "oracle", "injection",
                                                                       "restoration"))
    ok(e["mode"] == GAMEDAY_MODES[name], f"{name} mode is not {GAMEDAY_MODES[name]}, the mode GAMEDAY_MODES fixes")
    ok(e["class"] is None or filled(e["class"]), f"{name} class is neither null nor a text")
    ok(filled(e["claim"]) and texts(e["not_claimed"]) and all(map(filled, e["not_claimed"])),
       f"{name} claim and not_claimed")
    ok(texts(e["items"]) and all(map(filled, e["items"])), f"package {name} grades no item")
    ok(isinstance(hypothesis, list) and all(
        isinstance(h, dict) and set(h) == {"clause", "bound", "items"} and filled(h["clause"])
        and (h["bound"] is None or isinstance(h["bound"], str) and h["bound"] in budgets) and texts(h["items"])
        for h in hypothesis) and {i for h in hypothesis for i in h["items"]} == set(e["items"]),
       f"{name} hypothesis is no clause list whose bounds are budget ids or null and whose items cover the package's")
    bounds = {(h["bound"], i) for h in hypothesis if h["bound"] is not None for i in h["items"]}
    ok(bounds == GAMEDAY_BOUNDS.get(name, set()), f"{name} binds the budgets {sorted(bounds)} to its items, not the "
       f"bindings {sorted(GAMEDAY_BOUNDS.get(name, set()))} GAMEDAY_BOUNDS fixes")
    profile = injection.get("profile") if isinstance(injection, dict) else None
    row = fis["profiles"].get(profile) if isinstance(profile, str) else None
    action = GAMEDAY_ACTIONS.get(name)
    ok(isinstance(injection, dict) and set(injection) == {"action", "profile"} and filled(injection["action"])
       and (profile is None if action is None else row is not None and row.get("action") == action
            and action in fis["eligible_types"]),
       f"{name} injection is no action with " + (
           f"a fault-injection profile of the action {action} GAMEDAY_ACTIONS fixes" if action
           else "a null profile, the one GAMEDAY_ACTIONS fixes"))
    ok(isinstance(oracle, dict) and set(oracle) == {"reach", "expected"} and all(map(filled, oracle.values())),
       f"{name} oracle names no reach of its intended fault and no expected outcome")
    ok(texts(e["guardrail"]) and all(map(filled, e["guardrail"])), f"{name} names no abort guardrail")
    ok(name not in HOST_STOPS or set(HOST_GUARD) <= set(e["guardrail"]), f"{name} stops or restarts hosts, a "
       f"partition or an AZ without the abort guardrails {HOST_GUARD}")
    ok(isinstance(restoration, dict) and set(restoration) == {"class", "steps"}
       and restoration["class"] in RESTORATIONS and filled(restoration["steps"]),
       f"{name} restoration is no class of {list(RESTORATIONS)} with its steps")
    ok(name not in HOST_STOPS or restoration["class"] != "automatic", f"{name} stops or restarts hosts, which stay "
       "down until an operator step, so its restoration is not automatic")
    ok(e["mode"] != "tabletop" or (profile, restoration["class"]) == (None, "automatic"),
       f"{name} is a tabletop, which injects no fault and changes no state")
    ok(texts(e["prerequisites"]) and all(map(filled, e["prerequisites"])) and len(e["prerequisites"])
       == GAMEDAY_PREREQUISITES[name], f"{name} prerequisites are not {GAMEDAY_PREREQUISITES[name]} distinct texts")
    ok(isinstance(e["runbooks"], list) and all(map(filled, e["runbooks"])) and set(e["runbooks"]) <= runbooks,
       f"{name} names a runbook the index lacks")


def package_digest(e, rule, budgets, fis):
    """`canonical` of the entry with the catalog's run rule, the budgets its clauses name and, for a package that names
    a fault-injection profile, the profile's row and the manifest fields the controller reads for it (its action's
    eligible volume types, the production I/O timeout and the latency bounds), so a change to any of them stales only
    the run records of the packages that read it."""
    bounds = sorted({h["bound"] for h in e["hypothesis"] if h["bound"] is not None})
    row = fis["profiles"].get(e["injection"]["profile"])
    injection = row and {"row": row, "eligible_types": fis["eligible_types"].get(row["action"]),
                         "production_timeout_io_us": fis.get("production_timeout_io_us"), "bounds": fis.get("bounds")}
    return mf.canonical({"entry": e, "run_rule": rule, "budgets": {b: budgets[b] for b in bounds},
                         "profile": injection})


def check_gamedays(record, ctx):
    """Refuse a package whose items are not the items citing it, whose class is none of its items' classes, that a
    class citing it does not grade or a class it grades does not cite under its kind, whose bounded clause grades a
    floor item, whose safety floor items are not the ones GAMEDAY_SAFETY fixes, or that is a tabletop grading a floor
    item or an item no runbook change invalidates; return each entry's mode, kind, digest and blocking reasons, and the
    gamedays and budgets reasons."""
    packages = ctx["packages"]
    if packages is None:
        return {}, {"budgets": [f"the game-day catalog {PINS['gamedays_sha256'][0]} is absent, so no budget value is "
                                "set"]}
    items = {i["id"]: i for i in record["items"]}
    for name, e in packages.items():
        cite, kind = f"{GAMEDAY}:{name}", MODE_KINDS[e["mode"]]
        citing_items = [i for i in record["items"] if i["source"] == cite]
        graded = sorted(i["id"] for i in citing_items)
        need(sorted(e["items"]) == graded, f"package {name} grades {sorted(e['items'])}, but the items citing it are "
             f"{graded}")
        classes = sorted({i["class"] for i in citing_items} - {None})
        need(e["class"] in classes if e["class"] is not None else not classes, f"{name} names class {e['class']}, "
             f"but its items grade the classes {classes}")
        for c, row in record["classes"].items():
            cited = any(cite in cites for cites in row["evidence"].values())
            need(not cited or c in classes, f"class {c} cites {cite}, which grades items of {classes} only")
            need(c not in classes or cite in row["evidence"].get(kind, []), f"class {c} holds items {name} grades "
                 f"and cites it under no {kind} cell")
        floored = sorted({i for h in e["hypothesis"] if h["bound"] is not None for i in h["items"]
                          if items[i]["floor"] is not None})
        need(not floored, f"{name} bounds a clause that grades the floor items {floored}: a missed budget is a gap an "
             "exception may cover")
        need(e["mode"] != "tabletop" or all(items[i]["floor"] is None for i in e["items"]), f"{name} is a tabletop "
             "and grades a floor item")
        held, fixed = sorted(i for i in e["items"] if items[i]["floor"] == "safety"), GAMEDAY_SAFETY.get(name, [])
        need(held == fixed, f"{name} holds the safety floor items {held}, not the items {fixed} GAMEDAY_SAFETY fixes: "
             "no exception covers a staged safety failure")
        stale = [i for i in e["items"] if e["mode"] == "tabletop" and "runbook" not in items[i]["invalidators"]]
        need(not stale, f"{name} is a tabletop of a runbook, and its items {stale} lack the runbook invalidator")
        owed = ["guardrail", *(["manifest"] if e["injection"]["profile"] is not None else [])]
        unlabeled = [i for i in e["items"] if not set(owed) <= set(items[i]["invalidators"])]
        need(not unlabeled, f"{name} items {unlabeled} lack the invalidators {owed} of a package's run")
    rule, budgets, fis = ctx["gamedays"]["run_rule"], ctx["gamedays"]["budgets"], ctx["fis"]
    blocked = {name: [*(p for p in e["prerequisites"] if TBD in p),
                      *(["it names no runbook to walk"] if e["mode"] == "tabletop" and not e["runbooks"] else []),
                      *(f"budget {b} is null" for b in dict.fromkeys(h["bound"] for h in e["hypothesis"])
                        if b is not None and budgets[b]["value"] is None)]
               for name, e in packages.items()}
    unpinned = record["pins"]["gamedays_sha256"] is None
    reasons = {"gamedays": [f"{name} is blocked: {why}" for name, held in blocked.items() for why in held],
               "budgets": [*(["pin gamedays_sha256 is null, so the record pins no budget value"] if unpinned else []),
                           *(f"budget {b} is null" for b, v in budgets.items() if v["value"] is None)]}
    return {name: {"mode": e["mode"], "kind": MODE_KINDS[e["mode"]], "digest": package_digest(e, rule, budgets, fis),
                   "blocked": blocked[name]} for name, e in packages.items()}, reasons


def check(record, ctx):
    """Raise Refusal at the first rule `record` breaks; return the check's report."""
    need(isinstance(record, dict) and set(record) == KEYS, f"keys are not {sorted(KEYS)}")
    need(record["record"] == "failover-readiness" and gate.integer(record["version"], 1), "record kind and version")
    parent, acceptance_parent = record["parent"], ctx["acceptance"]["parent"]
    need(isinstance(parent, dict) and set(parent) == PARENT_KEYS, f"parent keys are not {sorted(PARENT_KEYS)}")
    need(parent["digest"] == acceptance_parent["digest"] and parent["specification"] == acceptance_parent["contract"],
         "parent specification is not #120 at the acceptance record's contract pin, or its digest description differs")
    plan = parent["plan"]
    need(isinstance(plan, dict) and set(plan) == PLAN_KEYS, f"parent plan keys are not {sorted(PLAN_KEYS)}")
    need(plan["issue"] == "#255" and mf.digest(plan["body_sha256"]), "parent plan is not #255 at a body SHA-256")
    check_pins(record, ctx)
    need(record["kinds"] == list(KINDS), f"kinds are not {list(KINDS)}")
    alarms = check_alarms(ctx)
    statuses, cross_check, runbook_reasons = check_runbooks(record, ctx, alarms)
    check_fis(ctx)
    packages = check_gameday_catalog(ctx, set(statuses))
    ctx = {**ctx, "packages": packages}
    classes = check_classes(record, ctx)
    items, item_reasons = check_items(record, ctx, set(statuses))
    gamedays, staged = check_gamedays(record, ctx)
    judged = {"monitors": monitors(alarms)}
    for reasons in (runbook_reasons, check_launch(record), item_reasons, staged):
        for name, whys in reasons.items():
            judged.setdefault(name, []).extend(whys)
    found = check_gates(record, ctx, judged)
    for name, reason in STANDING.items():
        if not record["gates"][name]["lifted"] and record["pins"][STANDING_PINS[name]] is not None:
            found.setdefault(name, []).append(reason)
    found = {name: found[name] for name in GATES if name in found}
    return {"gates": [name for name, g in record["gates"].items() if not g["lifted"]], "open": found, **classes,
            **items, "gamedays": gamedays, "runbooks": statuses, "alarm_cross_check": cross_check,
            "verdict": "NOT READY"}


def check_inputs(inputs, record, ctx):
    """Refuse an inputs file off the shape `judge` reads."""
    ok = functools.partial(need, what="inputs file")
    ok(isinstance(inputs, dict) and set(inputs) <= INPUT_KEYS and "revision" in inputs, f"keys within {INPUT_KEYS}")
    ok(isinstance(inputs["revision"], str) and mf.COMMIT.fullmatch(inputs["revision"]), "no 40-hex revision")
    ok(inputs.get("date") is None or dated(inputs["date"]), "date is no YYYY-MM-DD")
    ok(all(inputs.get(k) is None or text(inputs[k]) for k in ("acceptance", "hit_gate")), "acceptance and hit_gate "
       "name files")
    lanes = inputs.get("lanes", [])
    ok(isinstance(lanes, list) and all(isinstance(x, dict) and set(x) == {"job", "module", "evidence"}
                                       and text(x["job"]) and (x["module"] is None or text(x["module"]))
                                       and text(x["evidence"]) for x in lanes)
       and len({(x["job"], x["module"]) for x in lanes}) == len(lanes), "lanes are no distinct {job, module, evidence}")
    fis = inputs.get("fis", {})
    ok(isinstance(fis, dict) and set(fis) <= set(ctx["fis"]["profiles"]) and all(
        isinstance(v, dict) and set(v) == {"episode", "lane"} and text(v["episode"])
        and (v["lane"] is None or text(v["lane"])) for v in fis.values()),
       "fis maps fault-injection profile names to {episode, lane} receipt files, the lane null only before a launch")
    gamedays = inputs.get("gamedays", [])
    ok(isinstance(gamedays, list) and all(
        isinstance(g, dict) and set(g) == {"id", "package_sha256", "catalog_sha256", "record"} and g["id"] in GAMEDAYS
        and mf.digest(g["package_sha256"]) and mf.digest(g["catalog_sha256"]) and text(g["record"]) for g in gamedays)
       and len({g["id"] for g in gamedays}) == len(gamedays), "gamedays are no distinct {id, package_sha256, "
       "catalog_sha256, record} of GD-1 to GD-14")
    runbooks = inputs.get("runbooks", {})
    unknown = sorted(set(runbooks) - {e["id"] for e in runbook_index(ctx)}) if isinstance(runbooks, dict) else []
    ok(isinstance(runbooks, dict) and not unknown and all(text(v) for v in runbooks.values()),
       f"runbooks map runbook index ids to rehearsal record files; {unknown} are no index ids")
    reviewed = {i["id"] for i in record["items"] if i["source"] == "review"}
    reviews = inputs.get("reviews", [])
    ok(isinstance(reviews, list) and all(
        isinstance(r, dict) and set(r) == REVIEW_KEYS and r["item"] in reviewed and filled(r["reviewer"])
        and isinstance(r["revision"], str) and mf.COMMIT.fullmatch(r["revision"]) and dated(r["date"])
        and mf.digest(r["artifact_sha256"]) and r["grade"] in REVIEW_GRADES and filled(r["reason"])
        for r in reviews) and len({r["item"] for r in reviews}) == len(reviews),
       f"reviews are no distinct {sorted(REVIEW_KEYS)} of items whose source is review, each with a named reviewer "
       f"and reason, a 40-hex revision and a grade of {list(REVIEW_GRADES)}")
    exceptions = inputs.get("exceptions", [])
    ok(isinstance(exceptions, list) and all(isinstance(e, dict) and "item" in e for e in exceptions),
       "exceptions are no list of objects naming an item")


def graded(grade, reason, identity=None, **extra):
    return {"grade": grade, "reason": reason, "identity": identity, **extra}


def unusable(ev, absent):
    """MISSING for absent evidence, UNVERIFIED for evidence its owning judge refused, with the digests of the bytes
    read before the refusal, else None."""
    if ev is None:
        return graded("MISSING", absent)
    return graded("UNVERIFIED", ev["missing"], {"read": ev["read"]} if ev.get("read") else None) \
        if "missing" in ev else None


def bound(evidence, revision, identity=None):
    """UNVERIFIED when `evidence` names no revision, STALE when it names another than `revision`, else None."""
    cited, identity = evidence.get("revision"), identity or evidence.get("identity")
    if not (isinstance(cited, str) and mf.COMMIT.fullmatch(cited)):
        return graded("UNVERIFIED", f"the evidence names no 40-hex revision: {cited!r}", identity)
    return None if cited == revision else graded("STALE", f"the evidence names revision {cited}, not {revision}",
                                                 identity)


def independent(run):
    """Whether a tabletop run record names an executor and an author who differ, compared as runbook rehearsals are."""
    return filled(run.get("executor")) and filled(run.get("author")) and not same_person(run["executor"], run["author"])


def gameday_grade(item, entry, ev, revision, package):
    """One item's grade from its package's run record; `package` is the check report's entry, its digest and blocking
    reasons. The bindings decide first: a record of another mode or package id is refused and grades MISSING, one
    bound to another catalog definition or revision reads STALE, and one of another filled package UNVERIFIED. Then a
    failed injection or an INVALID run grades MISSING, a run that did not complete UNVERIFIED, and a tabletop without
    an executor apart from its author UNVERIFIED. A rehearsal or tabletop objective for the item decides over a MET or
    PARTIAL summary, and a blocked package earns no VERIFIED."""
    if stopped := unusable(ev, f"no run record of {entry['id']}"):
        return stopped
    run, identity, digest = ev["record"], ev["identity"], package["digest"]
    if run.get("mode") != entry["mode"] or run.get("id") != entry["id"]:
        return graded("MISSING", f"a {run.get('mode')} record of {run.get('id')} offered for the {entry['mode']} "
                      f"package {entry['id']} is refused", identity)
    if {ev["input"]["catalog_sha256"], run.get("catalog_sha256")} != {digest}:
        return graded("STALE", f"the record names another catalog definition than the committed {entry['id']} "
                      f"package and its budgets, {digest}", identity)
    if stale := bound(run, revision, identity):
        return stale
    if run.get("package_sha256") != ev["input"]["package_sha256"]:
        return graded("UNVERIFIED", "the record names another filled package than the inputs entry", identity)
    status, verdict = run.get("run_status"), run.get("verdict")
    if status == "FAILED_TO_INJECT" or verdict == "INVALID":
        return graded("MISSING", f"the run reads {status} {verdict}: the fault was not injected or the run is "
                      "invalid", identity)
    causal, objectives, reason = entry["mode"] == "causal", run.get("objectives"), f"{entry['id']} reads {verdict}"
    if not causal and verdict in ("MET", "PARTIAL") and objectives is not None:
        objective = objectives.get(item, verdict) if isinstance(objectives, dict) else None
        reason += f" and its objective for {item} reads {objective}"
        verdict = objective if objective in ("MET", "NOT_MET", "INVALID") else "INCONCLUSIVE"
    elif not causal and verdict == "PARTIAL":
        verdict = "INCONCLUSIVE"
    grade = VERDICT_GRADES.get((causal, verdict), "UNVERIFIED")
    if grade in ("FAILED", "MISSING"):
        return graded(grade, reason, identity)
    doubts = [*([f"the run reads {status}, not COMPLETED"] if status != "COMPLETED" else []),
              *(["the tabletop names no executor apart from its author"]
                if entry["mode"] == "tabletop" and not independent(run) else []),
              *([f"the committed package is blocked: {package['blocked'][0]}"] if package["blocked"] else [])]
    return graded("UNVERIFIED", f"{reason}, but {'; '.join(doubts)}", identity) if doubts and grade == "VERIFIED" \
        else graded(grade, reason, identity)


def failed_injection(section):
    """Whether a fault-injection episode reads FAILED_TO_INJECT or INVALID, the outcomes that need no lane receipt."""
    return section["status"] == "FAILED_TO_INJECT" or section["verdict"] == "INVALID"


def lane_events(section):
    """The `observed` events a lane receipt's cases record, each an object; a case or event of another shape holds
    none."""
    cases = section.get("cases")
    return [event for case in (cases if isinstance(cases, list) else []) if isinstance(case, dict)
            for event in (case["observed"] if isinstance(case.get("observed"), list) else [])
            if isinstance(event, dict) and event.get("kind") == "observed"]


def witnessed(section, events):
    """Whether the lane receipt's `events` witness the fault window the episode names. Each event's `after` holds the
    controller's latest mark when the lane appended it, so a timeout whose mark is the window's start followed the
    fault's start, restored bytes whose mark is the window's end followed the fault's end, and a stop whose mark is
    still the start preceded that end. The window holds when the first such timeout precedes the end mark and
    restored bytes follow it, or when the stop the episode names under the fault follows that timeout."""
    window = section.get("effect_window")
    start, end = (window.get("start_ordinal"), window.get("end_ordinal")) if isinstance(window, dict) else (None, None)

    def past(name, mark):
        return [e["ordinal"] for e in events if e.get("name") == name and gate.integer(e.get("ordinal"))
                and gate.integer(mark) and isinstance(e.get("after"), dict)
                and gate.integer(e["after"].get(FIS_ROLE)) and e["after"][FIS_ROLE] == mark]

    timeouts, stop = past("timeout", start), section.get("stop_under_fault")
    if not timeouts:
        return False
    return bool(gate.integer(end) and end > min(timeouts) and past("restored", end)) or (
        gate.integer(stop) and stop > min(timeouts) and stop in past("stop", start))


def held_doubts(section, ev):
    """Why a HELD episode stays unverified: no release proof, a fault window the lane receipt's observed events do
    not witness, custody in doubt, or no binding to the lane receipt bytes, the hardware manifest, and the pinned
    fault-injection profile and manifest file it was judged against."""
    manifest = section.get("hardware_manifest")
    return [*(["records no release proof"] if section.get("release_proof") is not True else []),
            *(["names a fault window its lane receipt's observed events do not witness"]
              if not witnessed(section, ev["observed"]) else []),
            *(f"records {k}" for k in FIS_DOUBTS if section.get(k)),
            *(["names another manifest than its lane receipt ran under"] if not isinstance(manifest, dict)
              or manifest.get("sha256") != ev["lane_manifest"] else []),
            *(["names no SHA-256 of the lane receipt judged here"]
              if section.get("lane_receipt_sha256") != ev["identity"]["lane_sha256"] else []),
            *(["names no digest of the pinned fault-injection profile"]
              if section.get("profile_sha256") != ev["profile_sha256"] else []),
            *(["names no SHA-256 of the pinned fault-injection manifest file"]
              if section.get("fis_profiles_sha256") != ev["fis_profiles_sha256"] else [])]


def fis_grade(ev, revision):
    """One fault-injection item's grade. A lane receipt bound to another revision, fault or manifest than the pinned
    ones reads STALE; then a failed injection or an INVALID episode grades MISSING, DISPROVEN FAILED, a lane the
    hardware judge refuses UNVERIFIED, and a HELD episode VERIFIED only once it completed, or the controller's own abort
    stopped it, with no doubt `held_doubts` names."""
    if stopped := unusable(ev, "no fault-injection episode"):
        return stopped
    section, identity = ev["episode"], ev["identity"]
    status, verdict = section["status"], section["verdict"]
    if ev["lane"]:
        if stale := bound(ev, revision, identity):
            return stale
        if ev["drift"]:
            return graded("STALE", "; ".join(ev["drift"]), identity)
    if failed_injection(section):
        return graded("MISSING", f"the episode reads {status} {verdict}, so it reads MISSING", identity)
    if verdict == "DISPROVEN":
        return graded("FAILED", f"the episode reads DISPROVEN: {section.get('first_failure')}", identity)
    if ev["reasons"]:
        return graded("UNVERIFIED", f"the hardware lane judge refuses its receipt: {ev['reasons'][0]}", identity)
    if status != "COMPLETED" and (status, section.get("abort")) != ("HALTED", "stopped"):
        return graded("UNVERIFIED", f"the episode reads {status}, neither COMPLETED nor stopped by its own abort",
                      identity)
    if verdict == "HELD" and (doubts := held_doubts(section, ev)):
        return graded("UNVERIFIED", f"the HELD episode {'; '.join(doubts)}", identity)
    return graded(VERDICT_GRADES.get((True, verdict), "UNVERIFIED"), f"the episode reads {verdict}", identity)


def acceptance_stop(accepted, revision):
    """The grade an absent, refused or unbound acceptance receipt gives its cells, or None for one bound to
    `revision`."""
    return unusable(accepted, "no acceptance inputs") or bound(accepted, revision)


def acceptance_cell(accepted, cls, column, kind, revision):
    """The acceptance judge's (class, column, kind) cell as a grade: a refused or other-revision receipt grades its
    cells as it grades its items, and a column the judge demoted demotes a passing kind cell."""
    if stopped := acceptance_stop(accepted, revision):
        return stopped
    structural = accepted["receipt"]["classes"][cls]["columns"][column]["structural"]
    raw = structural["kinds"].get(kind, {}).get("verdict", "unrun")
    verdict, demotions = acc.demoted(raw, structural.get("reasons")), structural.get("reasons") or []
    reason = f"the acceptance cell reads {raw}" + (f", demoted by {demotions[0]}" if verdict != raw else "")
    return graded(CELL_GRADES.get(verdict, "UNVERIFIED"), reason, accepted["identity"])


def hit_stop(ev, revision):
    """The grade an absent, refused or unbound hit-gate receipt gives, or None for one whose candidate is
    `revision`."""
    return unusable(ev, "no hit-gate campaign") or bound({"revision": ev["receipt"].get("candidate")}, revision,
                                                         ev["identity"])


def handoff_of(ev, revision):
    """The preservation handoff of a hit-gate receipt bound to `revision`, or None."""
    return None if hit_stop(ev, revision) else ev["receipt"].get("handoff")


def hit_grade(ev, revision, publish):
    """The hit-latency grade. A preservation handoff decides the preservation floor, so latency reads FAILED only on a
    pacing handoff or a failed cell outside the `publish` phase, and otherwise stays undecided."""
    if stopped := hit_stop(ev, revision):
        return stopped
    receipt = ev["receipt"]
    verdict, pacing = receipt["verdict"], receipt.get("pacing") or {}
    reasons = [*receipt.get("reasons", []), pacing.get("reason")]
    if verdict == "handoff" and receipt.get("handoff"):
        failed = pacing.get("verdict") == "handoff" or any(
            c["verdict"] == "fail" for name, c in receipt["cells"].items() if name.split("/")[1] != publish)
        verdict = "fail" if failed else "inconclusive"
        reasons.append(f"preservation {receipt['handoff']['obligation']} hands off: {receipt['handoff']['reason']}")
    why = "; ".join(r for r in reasons if r)
    return graded(HIT_GRADES.get(verdict, "UNVERIFIED"), f"the hit gate reads {verdict}" + (f": {why}" if why else ""),
                  ev["identity"])


def runbook_grade(name, ctx, ev):
    """A runbook item's grade: STALE or DRAFT from the index check, MISSING with no supplied rehearsal record,
    UNVERIFIED with one that cannot be read, STALE with one whose bytes hash to another digest than the entry
    records, and VERIFIED only for a VERIFIED entry; an entry VERIFIED WITH LIMITATIONS reads UNVERIFIED and names
    them."""
    status, supplied = ev["runbook_status"][name], ev["runbooks"].get(name)
    entry = next(e for e in runbook_index(ctx) if e["id"] == name)
    recorded = entry["rehearsal"]
    identity = recorded and {"record_sha256": recorded["record_sha256"], "date": recorded["date"]}
    if status in ("STALE", "DRAFT"):
        return graded("STALE" if status == "STALE" else "UNVERIFIED", f"runbook {name} is {status}", identity)
    if stopped := unusable(supplied, f"no rehearsal record for runbook {name}"):
        return stopped
    if supplied["record_sha256"] != recorded["record_sha256"]:
        return graded("STALE", f"the supplied rehearsal record {supplied['record_sha256']} is not the one runbook "
                      f"{name} records", identity)
    if status != "VERIFIED":
        return graded("UNVERIFIED", f"runbook {name} is {status}: {'; '.join(entry['limitations'])}", identity)
    return graded("VERIFIED", f"runbook {name} is {status}", identity)


def source_grade(item, record, ctx, ev, revision):
    """The grade of one applicable item from the evidence its source names."""
    source = item["source"]
    if source is None:
        return graded("MISSING", f"no source grades it yet; {item['gap_owner']} owns the gap")
    head, _, rest = source.partition(":")
    if source == "review":
        review = ev["reviews"].get(item["id"])
        if not review:
            return graded("MISSING", "no reviewer entry")
        identity = {k: review[k] for k in ("reviewer", "date", "artifact_sha256", "revision")}
        return {**(bound(review, revision, identity) or graded(review["grade"], review["reason"], identity)),
                "reviewer_graded": True}
    if head == "gate":
        if rest == PRESERVATION and (handoff := handoff_of(ev["hit_gate"], revision)):
            return graded("FAILED", f"the hit gate at the revision hands off preservation {handoff['obligation']}: "
                          f"{handoff['reason']}", ev["hit_gate"]["identity"])
        if not record["gates"][rest]["lifted"]:
            return graded("MISSING", f"gate {rest} is open")
        publish = ctx["document"]["qualification"]["pacing"]["phase"]
        if rest == REAL_PATH and (hit := hit_grade(ev["hit_gate"], revision, publish))["grade"] != "VERIFIED":
            return {**hit, "reason": f"gate {rest} is lifted, and the hit gate it qualifies reads {hit['grade']}: "
                                     f"{hit['reason']}"}
        return graded("VERIFIED", f"gate {rest} is lifted")
    if head == DELEGATE:
        cls, _, column = rest.partition("/")
        return acceptance_cell(ev["acceptance"], cls, column, item["kind"], revision)
    if head == "record":
        entry = ctx["catalog"][rest]
        lane = ev["lanes"].get((entry["job"], entry.get("module")))
        if lane is not None and (stopped := unusable(lane, "")):
            return stopped
        verdict, reasons, identity = acc.lane_verdict(rest, ev["lanes"], ctx["catalog"])
        if lane is not None and (stale := bound(lane, revision, identity)):
            return stale
        return graded(CELL_GRADES[verdict], "; ".join(reasons) or "credited", identity)
    if head == "runbook":
        return runbook_grade(rest, ctx, ev)
    if head == GAMEDAY:
        run = ev["gamedays"].get(rest)
        result = gameday_grade(item["id"], ctx["gamedays"]["entries"][GAMEDAYS.index(rest)], run, revision,
                               ev["packages"][rest])
        return result if unusable(run, "") else {**result, "run_record_graded": True}
    if source == "hit-gate":
        return hit_grade(ev["hit_gate"], revision, ctx["document"]["qualification"]["pacing"]["phase"])
    if head == "fis":
        return fis_grade(ev["fis"].get(rest), revision)
    raise Refusal(f"item {item['id']} cites {source}, which no grader reads")


def dated_source(source):
    """Whether `source` yields dated evidence, which ages: a reviewer entry, a game-day run record, a runbook
    rehearsal."""
    return source == "review" or (source or "").startswith(DATED)


def grade_item(item, record, ctx, ev, inputs):
    """One item's grade. Dated evidence ages against the inputs `date` once the item sets `max_age_days`, and an aged
    result keeps its identity and reviewer mark; other evidence binds by revision and digest only. Aging demotes only
    a VERIFIED grade."""
    applicability = item["applicability"]
    if applicability != "applicable":
        return graded("NOT APPLICABLE", applicability["not_applicable"]) if applicability["approver"] else graded(
            "MISSING", "its not-applicable reason awaits an approver")
    result = source_grade(item, record, ctx, ev, inputs["revision"])
    age, today = item["max_age_days"], inputs.get("date")
    if result["grade"] != "VERIFIED" or age is None or not dated_source(item["source"]):
        return result
    when = (result.get("identity") or {}).get("date")
    if today is None or when is None:
        return {**result, "grade": "UNVERIFIED", "reason": "the inputs or the evidence name no date to age it by"}
    days = (datetime.date.fromisoformat(today) - datetime.date.fromisoformat(when)).days
    if days < 0:
        return {**result, "grade": "UNVERIFIED",
                "reason": f"the evidence is dated {when}, after the judging day {today}"}
    return {**result, "grade": "STALE", "reason": f"the evidence of {when} is older than {age} days"} if days > age \
        else result


def worst(grades):
    return max(grades, key=ORDER.index) if grades else "MISSING"


def class_cells(record, items, ev, revision):
    """Per class row its cells by evidence kind: the worst grade of the kind's citations by ORDER, EXCLUDED, or
    MISSING with the citations that grade nothing. An acceptance citation reads the columns the acceptance record cites
    under the kind, and a delegated row adds the acceptance judge's class verdict, its budget half included."""
    cells = {}
    for name, c in record["classes"].items():
        row = {}
        for kind in KINDS:
            if kind in c["excluded"]:
                row[kind] = {"grade": "EXCLUDED", "reason": c["excluded"][kind]["reason"]}
                continue
            grades, empty = [], []
            for cite in c["evidence"].get(kind, []):
                if cite.startswith(f"{DELEGATE}:"):
                    columns = ev["acceptance_record"]["classes"][name]["evidence"].get(kind, {})
                    found = [acceptance_cell(ev["acceptance"], name, column, kind, revision)["grade"]
                             for column in columns]
                else:
                    found = [i["grade"] for i in items.values() if i["source"] == cite and i["class"] == name
                             and i["kind"] == kind]
                grades += found or ["MISSING"]
                empty += [] if found else [cite]
            row[kind] = {"grade": worst(grades), "citations": c["evidence"].get(kind, []),
                         **({"ungraded": empty} if empty else {})}
        if c["delegated"] == DELEGATE:
            stopped = acceptance_stop(ev["acceptance"], revision)
            if stopped:
                row["acceptance_verdict"] = {"grade": stopped["grade"], "reason": stopped["reason"]}
            else:
                raw = ev["acceptance"]["receipt"]["classes"][name]["verdict"]
                row["acceptance_verdict"] = {"grade": CELL_GRADES.get(raw, "UNVERIFIED"),
                                             "reason": f"the acceptance class reads {raw}"}
        cells[name] = row
    return cells


def register(exceptions, record, items, today):
    """Each supplied exception's declared fields with its state: accepted, or rejected with the first reason."""
    floors = {i["id"] for i in record["items"] if i["floor"]}
    risk, launch = record["authority"]["risk"], record["authority"]["launch"]
    out = []
    for e in exceptions:
        missing = sorted(k for k in EXCEPTION_KEYS if not filled(e.get(k)))
        if missing:
            state = f"rejected: incomplete, it lacks {missing}"
        elif set(e) != EXCEPTION_KEYS:
            state = f"rejected: it holds keys {sorted(set(e) - EXCEPTION_KEYS)} outside {sorted(EXCEPTION_KEYS)}"
        elif not dated(e["expiry"]):
            state = "rejected: its expiry is no YYYY-MM-DD"
        elif e["item"] not in items:
            state = "rejected: it names no item"
        elif e["item"] in floors:
            state = "rejected: the item is a floor, which no exception covers"
        elif items[e["item"]]["grade"] in RESOLVED:
            state = "rejected: the item is resolved"
        elif today is None:
            state = "rejected: the inputs name no date to check its expiry by"
        elif e["expiry"] < today:
            state = f"rejected: it expired on {e['expiry']}"
        # The approver equals the risk authority's text exactly, and the two separation checks after it set case and
        # surrounding space aside, so each comparison rejects a handle in doubt.
        elif e["approver"] != risk:
            state = "rejected: its approver is not the risk authority"
        elif same_person(e["approver"], e["risk_owner"]):
            state = "rejected: its approver approves its own risk"
        elif filled(launch) and same_person(e["approver"], launch):
            state = "rejected: its approver is the launch authority, who may not be the only accepter of the risk"
        else:
            state = "accepted"
        out.append({**{k: e[k] if text(e.get(k)) else None for k in sorted(EXCEPTION_KEYS) if k in e},
                    "state": state})
    return out


def verdict(record, items, exceptions):
    """The recommended verdict from the items, the exceptions, the authority and the failure classes no row names,
    with its reasons."""
    covered = {e["item"] for e in exceptions if e["state"] == "accepted"}
    unresolved = [n for n, i in items.items() if i["grade"] not in RESOLVED and n not in covered]
    floors = [n for n in unresolved if items[n]["floor"]]
    others = [n for n in unresolved if not items[n]["floor"]]
    reasons = []
    if floors:
        reasons.append(f"floor items {floors} are unresolved")
    if others:
        reasons.append(f"items {others} are unresolved and no accepted exception covers them")
    reasons += [f"the authority gate is open: role {role} is null" for role, v in record["authority"].items()
                if v is None]
    reasons += [f"failure class {fc} has no class row: {why}" for fc, why in record["unmapped"].items()]
    if reasons:
        return "NOT READY", reasons
    return ("READY WITH EXPLICIT EXCEPTIONS", [f"accepted exceptions cover {sorted(covered)}"]) if covered else (
        "READY", [])


def objectives_of(ev):
    """The per-item objectives of a judged run record, empty when it was refused or names none as a map."""
    objectives = ev.get("record", {}).get("objectives")
    return objectives if isinstance(objectives, dict) else {}


def lift_contradictions(record, items, ev, revision):
    """Gate id -> why its lift contradicts the evidence the judge grades: the items LIFT_EVIDENCE selects for a
    standing gate or for `real-path` are unresolved, or no acceptance receipt bound to `revision` is accepted."""
    found = {}
    for name, judged_by in LIFT_EVIDENCE.items():
        unresolved = [n for n, i in items.items() if judged_by(n, i) and i["grade"] not in RESOLVED]
        if record["gates"][name]["lifted"] and unresolved:
            found[name] = f"gate {name} is lifted while its items {unresolved} are unresolved"
    accepted = ev["acceptance"]
    if record["gates"]["acceptance"]["lifted"] and (acceptance_stop(accepted, revision)
                                                    or not accepted["identity"]["accepted"]):
        found["acceptance"] = "gate acceptance is lifted while no acceptance receipt bound to the revision is accepted"
    return found


def valid_until(items, exceptions):
    """An inclusive upper bound on the recommendation: the earliest accepted exception expiry or age limit of dated
    VERIFIED evidence, or null when neither applies. An invalidator of an item, such as a new revision, ends it
    sooner."""
    limits = [e["expiry"] for e in exceptions if e["state"] == "accepted"]
    for i in items.values():
        when = (i.get("identity") or {}).get("date")
        if i["grade"] == "VERIFIED" and i["max_age_days"] is not None and dated_source(i["source"]) and when:
            try:
                limit = datetime.date.fromisoformat(when) + datetime.timedelta(days=i["max_age_days"])
            except OverflowError:
                limit = datetime.date.max
            limits.append(limit.isoformat())
    return min(limits, default=None)


def evidence_identity(v, shown=lambda v: v.get("identity")):
    """A judged piece of evidence's identity as `shown` projects it, or its refusal with the digests of the bytes read
    before it."""
    if not v:
        return None
    return {"refused": v["missing"], "read": v.get("read", {})} if "missing" in v else shown(v)


def judge(record, inputs, ctx, judges, record_sha256, inputs_sha256):
    """The readiness receipt of `inputs` under `record`, with `judges` re-deriving each piece of evidence."""
    report = check(record, ctx)
    check_inputs(inputs, record, ctx)
    revision = inputs["revision"]

    def judged(call, *args):
        seen = judges.seen
        seen.clear()
        try:
            return call(*args)
        except FAULTS as error:
            return {"missing": f"refused: {type(error).__name__}: {error}", "read": dict(seen)}

    lanes = {(x["job"], x["module"]): judged(judges.lane, x["job"], x["module"], x["evidence"], revision)
             for x in inputs.get("lanes", [])}
    ev = {"acceptance": inputs.get("acceptance") and judged(judges.acceptance, inputs["acceptance"]),
          "acceptance_record": ctx["acceptance"], "lanes": lanes,
          "hit_gate": inputs.get("hit_gate") and judged(judges.hit_gate, inputs["hit_gate"]),
          "fis": {p: judged(judges.fis, p, v, revision) for p, v in inputs.get("fis", {}).items()},
          "gamedays": {g["id"]: {"input": g, **judged(judges.gameday, g["record"])}
                       for g in inputs.get("gamedays", [])},
          "packages": report["gamedays"],
          "runbooks": {name: judged(judges.rehearsal, path) for name, path in inputs.get("runbooks", {}).items()},
          "runbook_status": report["runbooks"], "reviews": {r["item"]: r for r in inputs.get("reviews", [])}}
    items = {i["id"]: {**grade_item(i, record, ctx, ev, inputs), "kind": i["kind"], "domain": i["domain"],
                       "class": i["class"], "floor": i["floor"], "source": i["source"],
                       "max_age_days": i["max_age_days"]} for i in record["items"]}
    exceptions = register(inputs.get("exceptions", []), record, items, inputs.get("date"))
    recommended, reasons = verdict(record, items, exceptions)
    gates = {name: report["open"].get(name, []) for name in report["gates"]}
    contradicted = lift_contradictions(record, items, ev, revision)
    graded_by = {g: {n["id"] for n in record["items"] if n["source"] == f"{GAMEDAY}:{g}"} for g in ev["gamedays"]}
    packages = {g: {"identity": evidence_identity(v), "refused": [
        f"objective {i} names an item {g} does not grade: a package grades only its own items, of its mode's kind"
        for i in objectives_of(v) if i not in graded_by[g]]} for g, v in ev["gamedays"].items()}
    if (owning := owning_digests()) != OWNING_SHA256:
        raise Refusal(f"owning judges {sorted(n for n in OWNING if owning[n] != OWNING_SHA256[n])} changed while the "
                      "judge ran")
    return {"envelope": ENVELOPE, "record_sha256": record_sha256, "inputs_sha256": inputs_sha256,
            "judge_sha256": JUDGE_SHA256, "owning_judges_sha256": owning, "pins": record["pins"],
            "revision": revision, "date": inputs.get("date"),
            "evidence": {"acceptance": evidence_identity(ev["acceptance"], lambda v: {
                             **v["identity"], "evidence": v["receipt"].get("evidence")}),
                         "lanes": {json.dumps(list(k)): evidence_identity(v, lambda v: {
                             key: v.get(key) for key in ("receipt_sha256", "judge_sha256", "revision")})
                             for k, v in lanes.items()},
                         "hit_gate": evidence_identity(ev["hit_gate"]),
                         "fis": {p: evidence_identity(v) for p, v in ev["fis"].items()}, "gamedays": packages},
            "items": items,
            "domains": {d: [n for n, i in items.items() if i["domain"] == d and i["grade"] not in RESOLVED]
                        for d in DOMAINS},
            "classes": class_cells(record, items, ev, revision), "gates": gates, "contradicted": contradicted,
            "exceptions": exceptions, "exception_register_sha256": mf.canonical(exceptions),
            "recommended_verdict": recommended, "reasons": reasons,
            "ready": recommended == "READY" and not gates and not contradicted,
            "valid_until": valid_until(items, exceptions),
            "authorization": "a recommendation only: a named human authorizes each wave in a separate artifact"}


def resolved(path, what):
    """`path` resolved, or a Refusal naming `what` for a path that does not resolve, such as a symbolic link loop."""
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError, ValueError) as error:
        raise Refusal(f"{what} {path!r} does not resolve: {error}") from error


class Judges:
    """The owning judges, each re-deriving one kind of receipt from the files an inputs file names, read-only. `seen`
    holds the SHA-256 of each file the current call read, by path, so a refusal still names the bytes it refused;
    `opened` holds every file an adapter read and every package, comparison and sizing file the acceptance inputs file
    names, and `trees` every lane tree the run names, none of which `--output` may name."""

    def __init__(self, ctx, lane):
        self.ctx, self.lane_module, self.seen, self.opened, self.trees = ctx, lane, {}, set(), set()
        self.judged_manifest = None
        self.acc = acc.Judges(ctx["acceptance_ctx"], lane, ctx["log"])

    def read(self, path, what):
        data = gate.read_file(path, what)
        self.seen[str(path)] = hashlib.sha256(data).hexdigest()
        self.opened.add(Path(path).resolve())
        return data

    def tree(self, evidence):
        """The resolved lane evidence path `evidence`, recorded as a tree `--output` may not name."""
        root = resolved(evidence, "lane evidence")
        self.trees.add(root)
        return root

    def acceptance(self, path):
        raw = self.read(path, "acceptance inputs file")
        inputs = parse(raw, "acceptance inputs file")
        named = inputs if isinstance(inputs, dict) else {}
        lanes, files = named.get("lanes"), [named.get("sizing")]
        for key in ("packages", "comparisons"):
            files += named[key].values() if isinstance(named.get(key), dict) else []
        for x in lanes if isinstance(lanes, list) else []:
            if isinstance(x, dict) and text(x.get("evidence")):
                self.tree(x["evidence"])
        self.opened.update(resolved(file, "acceptance evidence file") for file in files if text(file))
        receipt = acc.judge(self.ctx["acceptance"], inputs, self.ctx["acceptance_ctx"], self.acc,
                            hashlib.sha256(self.ctx["files"]["acceptance_sha256"]).hexdigest(), self.seen[str(path)])
        return {"receipt": receipt, "revision": receipt["revision"],
                "identity": {"inputs_sha256": self.seen[str(path)], "receipt_sha256": mf.canonical(receipt),
                             "accepted": receipt["accepted"]}}

    def lane(self, job, module, evidence, revision):
        root = self.tree(evidence)
        if not root.is_dir():
            raise Refusal(f"lane evidence {evidence!r} is no directory")

        def unlisted(error):
            raise Refusal(f"lane evidence {evidence!r} holds a directory that cannot be listed: {error}") from error

        for directory, folders, files in os.walk(root, onerror=unlisted):
            for entry in (Path(directory, name) for name in (*folders, *files)):
                if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
                    raise Refusal(f"lane evidence {evidence!r} holds {str(entry.relative_to(root))!r}, a symbolic "
                                  "link or special file")
        data = self.read(root / "receipt.json", "lane receipt")
        receipt = parse(data, "lane receipt")
        cited = receipt.get("revision") if isinstance(receipt, dict) else None
        if not isinstance(cited, str):
            raise Refusal(f"the lane receipt of {evidence!r} is no object naming a revision")
        if cited != revision:
            return {"obligations": [], "refusals": [], "revision": cited, "receipt_sha256": self.seen[str(root /
                    "receipt.json")], "judge_sha256": None}
        return {**self.acc.lane(job, module, evidence, revision), "revision": cited}

    def hit_gate(self, path):
        data = self.read(path, "hit-gate campaign")
        sha = self.seen[str(path)]
        receipt = gate.judge(self.ctx["document"], self.ctx["acceptance_ctx"]["manifest_sha256"],
                             set(self.ctx["catalog"]), parse(data, "hit-gate campaign"), self.lane_module, sha)
        return {"receipt": receipt, "identity": {"campaign_sha256": sha, "receipt_sha256": mf.canonical(receipt)}}

    def manifest(self):
        """The hardware lane's check of the pinned manifest bytes and of its registry rows, made once."""
        if self.judged_manifest is None:
            data = self.ctx["files"]["hardware_profiles_sha256"]
            try:
                platforms, profiles = self.lane_module.check_manifest(parse(data, "hardware manifest"))
                self.lane_module.registry_rows(profiles)
            except self.lane_module.Stop as error:
                raise Refusal(f"the hardware lane refuses its manifest: {error}") from error
            self.judged_manifest = platforms, profiles, hashlib.sha256(data).hexdigest()
        return self.judged_manifest

    def fis(self, profile, files, revision):
        raw = self.read(files["episode"], "fault-injection receipt")
        receipt = parse(raw, "fault-injection receipt")
        episode = receipt.get("fis") if isinstance(receipt, dict) and receipt.get("envelope") == FIS_ENVELOPE else None
        if not (isinstance(episode, dict) and all(isinstance(episode.get(k), str)
                                                  for k in ("profile", "episode", "status", "verdict"))):
            raise Refusal(f"the fault-injection receipt is no {FIS_ENVELOPE} envelope with a text profile, episode, "
                          "status and verdict")
        if episode["profile"] != profile:
            raise Refusal(f"the episode receipt is profile {episode['profile']!r}, not {profile}")
        identity, pinned = {"episode_sha256": self.seen[str(files["episode"])]}, self.ctx["fis"]["profiles"][profile]
        if files["lane"] is None:
            if not failed_injection(episode):
                raise Refusal(f"the episode reads {episode['status']} {episode['verdict']} and names no lane receipt")
            return {"episode": episode, "lane": False, "identity": identity}
        lane = parse(self.read(files["lane"], "hardware lane receipt"), "hardware lane receipt")
        section = lane.get("hardware") if isinstance(lane, dict) else None
        if not (filled(episode["episode"]) and isinstance(section, dict)
                and section.get("episode") == episode["episode"]):
            named = section.get("episode") if isinstance(section, dict) else None
            raise Refusal(f"the lane receipt is episode {named!r}, not the fault-injection episode "
                          f"{episode['episode']!r}")
        role = (pinned["lane"]["profile"], pinned["lane"]["role"])
        if lane.get("envelope") != self.lane_module.ENVELOPE or (section.get("profile"), section.get("role")) != role:
            raise Refusal(f"the lane receipt is no hardware lane receipt of profile {role[0]} role {role[1]}")
        platforms, profiles, sha = self.manifest()
        timeouts = episode["timeouts"] if isinstance(episode.get("timeouts"), dict) else {}
        ran, digest = section.get("manifest_sha256"), mf.canonical(pinned)
        whole = hashlib.sha256(self.ctx["files"]["fis_profiles_sha256"]).hexdigest()
        drift = [*([f"the episode ran {episode.get('action')!r}, not the pinned profile's {pinned['action']!r}"]
                   if episode.get("action") != pinned["action"] else []),
                 *([f"the episode's test timeout is {timeouts.get('test_timeout_io_us')!r} us, not the pinned "
                    f"{pinned['timeout_io_us']}"] if timeouts.get("test_timeout_io_us") != pinned["timeout_io_us"]
                   else []),
                 *([f"the episode ran profile definition {episode['profile_sha256']}, not the pinned {digest}"]
                   if mf.digest(episode.get("profile_sha256")) and episode["profile_sha256"] != digest else []),
                 *([f"the episode ran under fault-injection manifest {episode['fis_profiles_sha256']}, not the pinned "
                    f"{whole}"] if mf.digest(episode.get("fis_profiles_sha256"))
                   and episode["fis_profiles_sha256"] != whole else []),
                 *([f"the lane receipt ran under manifest {ran}, not the pinned {sha}"]
                   if mf.digest(ran) and ran != sha else [])]
        _, reasons = self.lane_module.judge_profile(platforms, role[0], profiles[role[0]], [lane], sha, revision)
        return {"episode": episode, "lane": True, "revision": section.get("revision"), "reasons": reasons,
                "drift": drift, "lane_manifest": ran, "profile_sha256": digest, "fis_profiles_sha256": whole,
                "observed": lane_events(section),
                "identity": {**identity, "lane_sha256": self.seen[str(files["lane"])]}}

    def rehearsal(self, path):
        """The SHA-256 of the rehearsal record's bytes, which `runbook_grade` compares with the digest the committed
        index entry records. The bytes are hashed and left unparsed: the entry is the record's reviewed summary."""
        self.read(path, "rehearsal record")
        return {"record_sha256": self.seen[str(path)]}

    def gameday(self, path):
        """The parsed run record with the SHA-256 of its bytes and its date. Its verdict is its producer's
        attestation, which `gameday_grade` reads after the record's bindings."""
        run = parse(self.read(path, "game-day run record"), "game-day run record")
        if not isinstance(run, dict):
            raise Refusal("the game-day run record is no object")
        wrong = [k for k in RUN_TEXTS if run.get(k) is not None and not isinstance(run[k], str)]
        if wrong:
            raise Refusal(f"the game-day run record's {wrong} are not text")
        return {"record": run, "identity": {"record_sha256": self.seen[str(path)], "date": run.get("date")
                                            if dated(run.get("date")) else None}}


def guard_output(path, judges, *named):
    """Refuse an `--output` that does not resolve, that names a file of `named`, a pinned file, this script, an owning
    judge's script or a file `judges` recorded, or that lies inside a lane tree `judges` recorded: the write would
    change the evidence the receipt names. Refuse any other path at which an entry exists, so the run creates its
    receipt and replaces no file, whichever judge read it."""
    target = resolved(path, "--output")
    committed = (*(ROOT / file for file, _ in PINS.values()), __file__, *(HERE / name for name in OWNING))
    read = {Path(p).resolve() for p in (*named, *committed)} | judges.opened
    if target in read or any(target.is_relative_to(tree) for tree in judges.trees):
        raise Refusal(f"--output {path!r} names evidence this run read")
    if os.path.lexists(path):
        raise Refusal(f"--output {path!r} names an existing entry: the judge creates its receipt and replaces no file")


def acceptance_cited(acceptance):
    """The index of what the acceptance record cites, derived from that record: its source names and the catalog
    record and class package ids it cites, each the identity of a receipt whose home is the acceptance record."""
    sources = acceptance["sources"]
    records = {r for s in sources.values() for r in s.get("records", [])}
    packages = {c["package"] for c in acceptance["classes"].values() if c["package"] is not None}
    return set(sources), records | packages


def context(lane):
    """The acceptance record with its open gates and the index of what it cites (`acceptance_cited`), the Quint
    manifest's blocked cases, the cases of the END obligation (its tests and the tests of its controls), the open items
    of the hit-gate check over the committed hardware manifest, the obligation catalog, the pinned files' bytes (None
    for an absent file, whatever its pin), the repository root runbook files resolve against, the parsed
    fault-injection profiles and the game-day catalog (None when its file is absent), each judged from the bytes its
    digest names; `check` parses the runbook index and the alarm catalog from those bytes."""
    files = pinned_files()
    fis = parse(files["fis_profiles_sha256"], "fault-injection profiles")
    if not (isinstance(fis, dict) and isinstance(fis.get("profiles"), dict)
            and all(isinstance(p, dict) for p in fis["profiles"].values())):
        raise Refusal(f"{PINS['fis_profiles_sha256'][0]} holds no profiles map of profile objects")
    acceptance = parse(files["acceptance_sha256"], "acceptance record")
    manifest = files["hardware_profiles_sha256"]
    parse(manifest, "hardware manifest")
    args = argparse.Namespace(records=str(mf.RECORDS), manifest=str(gate.MANIFEST), obligations=str(gate.OBLIGATIONS))
    acc_ctx, log = acc.context(args, lane)
    if manifest is None or hashlib.sha256(manifest).hexdigest() != acc_ctx["manifest_sha256"]:
        raise Refusal(f"{PINS['hardware_profiles_sha256'][0]} changed while the check read it")
    quint_data = gate.read_file(acc.QUINT, "Quint manifest")
    if hashlib.sha256(quint_data).hexdigest() != acc_ctx["quint_sha256"]:
        raise Refusal(f"{acc.QUINT.relative_to(ROOT).as_posix()} changed while the check read it")
    quint = parse(quint_data, "Quint manifest")
    open_gates, _ = acc.check(acceptance, acc_ctx)
    end = acc_ctx["catalog"][END]
    gamedays = files["gamedays_sha256"]
    return {"acceptance": acceptance, "acceptance_gates": open_gates, "acceptance_cited": acceptance_cited(acceptance),
            "document": acc_ctx["document"], "hit_gate_open": gate.check(acc_ctx["document"], set(acc_ctx["catalog"])),
            "quint_blocked": quint["blocked"],
            "end_cases": [*end["tests"], *(control["test"] for control in end["controls"])], "files": files,
            "catalog": acc_ctx["catalog"], "root": ROOT, "fis": fis, "acceptance_ctx": acc_ctx, "log": log,
            "gamedays": parse(gamedays, "game-day catalog") if gamedays is not None else None}


def checkout_commit(lane):
    """The commit checked out in the tree this script runs from, or a Refusal when git cannot name it."""
    try:
        return lane.git_revision()
    except lane.Stop as error:
        raise Refusal(f"the checkout's commit cannot be read: {error}") from error


def modified_files(root=ROOT):
    """The tracked files of the checkout at `root` that git does not show to hold their commit's bytes: each one that
    differs from the commit in the working tree or in the index, and each one an index flag (assume-unchanged or
    skip-worktree) leaves out of that comparison. Untracked files are left out. A Refusal when git cannot read the
    checkout."""
    def git(*args):
        try:
            done = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args], capture_output=True,
                                  text=True, check=False)
        except OSError as error:
            raise Refusal(f"the checkout's state cannot be read: {error}") from error
        if done.returncode != 0:
            raise Refusal(f"the checkout's state cannot be read: git {args[0]} exited {done.returncode}: "
                          f"{done.stderr.strip()}")
        return done.stdout

    changed = {line[3:] for line in git("status", "--porcelain", "--untracked-files=no").splitlines()}
    # `ls-files -v` tags an entry H when git compares it and with another letter when a flag hides it.
    hidden = {entry[2:] for entry in git("ls-files", "-v", "-z").split("\0") if entry and entry[0] != "H"}
    return sorted(changed | hidden)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the failover readiness record and judge its evidence.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "judge"):
        commands.add_parser(name).add_argument("--record", default=str(RECORD))
    commands.choices["judge"].add_argument("--inputs", required=True)
    commands.choices["judge"].add_argument("--output")
    args = parser.parse_args(argv)
    try:
        lane = gate.lane_module()
        data = gate.read_file(args.record, "readiness record", RECORD_LIMIT)
        record = parse(data, "readiness record")
        ctx = context(lane)
        if args.command == "check":
            report = check(record, ctx)
            rendered = json.dumps(report, indent=1) + "\n" + report["verdict"] + "\n"
            ready = True
        else:
            raw, judges = gate.read_file(args.inputs, "inputs file"), Judges(ctx, lane)
            inputs = parse(raw, "inputs file")
            # The record, the committed evidence and every script a judge loads are read from this tree, so the tree
            # is the revision's commit with each tracked file as committed. A revision off its shape is left to
            # `judge`, which refuses the inputs file.
            named = inputs.get("revision") if isinstance(inputs, dict) else None
            if isinstance(named, str) and mf.COMMIT.fullmatch(named):
                if named != (head := checkout_commit(lane)):
                    raise Refusal(f"the inputs name revision {named} and this checkout is at {head}: judge runs in "
                                  "a checkout of the revision it judges")
                if changed := modified_files():
                    raise Refusal(f"tracked files of this checkout differ from commit {head} or are hidden from "
                                  f"git's comparison: {changed}: judge reads the revision's own bytes")
            receipt = judge(record, inputs, ctx, judges, hashlib.sha256(data).hexdigest(),
                            hashlib.sha256(raw).hexdigest())
            rendered = json.dumps(receipt, indent=1, sort_keys=True, allow_nan=False) + "\n"
            ready = receipt["ready"]
            if args.output:
                guard_output(args.output, judges, args.record, args.inputs)
                gate.write_receipt(args.output, rendered)
                rendered = ""
    except FAULTS as error:
        print(f"readiness: refused: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(rendered)
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
