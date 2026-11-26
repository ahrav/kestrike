# Finding: a fill promised before the owner's close is placed and granted after it

Rehearsal of record of #304, under the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`. Scenario `ks-escape-2075`, invariant
`ks-no-fill-admitted-after-close`, run `record-loop-1`. The bug issue is #298, and the
audit report is `chaos/loop/audits/record-loop-1.md` (verdict accept). Paths are under
`crates/kestrike/src/`. The first pass of #304 reported the same break for run
`loop-escape-1` at build `9e1936bceaef`; that text stands at commit `74b137023`.

Note of 2026-11-24T20:00Z, added after the review of pull request blotter pull request 2126: the figures and
receipts this finding cites are those of run `record-loop-1` at build `3b9e5e9f1598`,
which stand at commit `caded992b`. `chaos/runs/record-loop-1/` and
`chaos/receipts/record-loop-1/` then held a run of build `7899890b4d5f` under the same id,
with the same verdicts and 679,248 catches (`chaos/loop/log.md`, amendment of
2026-11-24T14:05Z; `chaos/loop/stops/remakes-after-the-record.md`).

Note of 2026-11-25, added with the runs of record made again that day: the run of build
`7899890b4d5f` stands at commit `5755aacea`. `chaos/runs/record-loop-1-1125b/` and
`chaos/receipts/record-loop-1-1125b/` now hold its replacement of build `c948fcfa86a0`, with
the same verdicts and 668,452 catches (`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).

```text
Class:     candidate correctness bug
Property:  Rule text "a fill admitted after the cache closed" (net/world_tests/narrate/rules.rs,
           arrays ORACLE and HISTORY_SHARED), which the history k5-closed-admits-nothing already
           judges (docs/agents/simulation.md, An agreed property, place 2). Module documentation of
           storage::writable: "Close refuses new receives, reservations and publications." (place 4),
           the text that forbids the behavior. The module documentation of storage::readiness,
           invariant ALLOCATION-READY, reads the other way: "Fills and builders admitted earlier keep
           their reservations or escrowed extents in every state." (OQ-12 of #297, asked on #298;
           trusted_base of chaos/project.yaml prints it as open for the owner).
Trigger:   No fault. The scripted history k9-placement-across-close
           (net/world_tests/histories/keyops.rs) over the sequence storage: it promises a fill of two
           extents of key 2 with no extent placed, closes the owner (Owner::close), then places both
           extents (PlacingFill::place) and asks for the shard hold (PlacingFill::reserve_storage).
           Its twin k9-placement-across-storage-close runs the same steps with the storage's own
           close in place of Owner::close.
Effect:    With debug assertions (inferred from the archive's build command, which leaves them on):
           every run of the history ends in the declared violation, 609,978 of 609,978 runs of
           record-loop-1 caught under the rule, none passed or missed: the closed owner grants the
           placement and then the shard hold, or refuses it Closed and keeps an additional-key claim;
           the evidence counts by rule and does not say which. The twin passed 599,132 of 599,132
           runs in the same sweep. Without debug assertions: not run in this campaign. Data at risk:
           #298's reading of the code, which no run shows, since the history aborts the granted fill
           in the step that judges it: no data, and the grant holds the key's index place, a pending
           pair, two lease credits and the extents' pool units after the close until the fill ends.
Evidence:  Build 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5 (archive of
           cb9ad9321, clean), root /data/tsw/campaigns/2082r/record-loop-1, campaign name
           record-loop-1, default counts, run ranges 0 to 609,978 (the history) and 0 to 599,132
           (the twin), 28 workers for 120 s; 48 runs of each replayed equal in a fresh process (no
           "replay differs" suspect). Bundle: none saved; the evidence holds counts by ending.
           Receipts chaos/receipts/record-loop-1/: ks-escape-2075 held,
           ks-no-fill-admitted-after-close broken. Enrollment run record-escape-live, same build:
           613,009 of 613,009 caught, twin 603,203 passes. Control run record-escape-judged-open: the
           control k9-placement-judged-open caught 404,227 times under the same rule, none missed.
           The row of KNOWN in crates/campaign-supervisor/src/campaign/known.rs cites #298, and #303
           records the history's 500-root tally.
Unknown:   Which of the two module texts the owner holds (OQ-12). Which failing branch each run took.
           The effect without debug assertions on this build. PlacingFill::retry, the path of a
           placement that waits for a free run, which the history does not drive. A follower that
           joins the granted fill, and a restart with the fill held.
```

The class stays candidate under "Prove a bug" of `docs/agents/simulation.md`, which
leaves these conditions unmet: no failing bundle was saved (condition 1); the mechanism is
#298's reading of the code, and the audit marks the cause as not shown by the run's
evidence, with the twin's passes as support and no proof (condition 2); no fix exists yet
that the history passes on (condition 3); one audit judged the break, where the guide asks
two read-only reviewers on different models, and the owner has not answered which module
text holds (OQ-12), so the class follows that disagreement until the owner answers
(condition 4); and no run without debug assertions was made on this build (condition 6).
The fix is the owner's to approve, as `chaos/loop/stops/2075-fix.md` states.
