//! The control profiles and the failure each must end in.
//!
//! A control is a profile that plants a wrong behavior in a healthy
//! profile's scenario. It is caught by a run that ends in its failure: a
//! violation of one obligation, under one rule when the control names one;
//! a violation of one of several obligations; an unsuccessful ending under
//! one rule; or a panic with one payload.
//!
//! A scripted history that expects no pass is a control too: its script
//! plants a wrong behavior or leaves out a step a witness needs, and the
//! worker's listing declares the failure its run ends in, which
//! [`Control::history`] reads.
//!
//! [`declared`] names the controls calibration requires of a profile.
//! [`swept`] names the controls a sweep runs beside a profile: the
//! declared ones and the ones only a sweep runs. A swarm control is caught
//! only on a root whose member gives its plant an effect, `asserting`
//! judges the worker's build, a single-owner profile's corrupted control
//! fails the record check `corrupted` already requires of `upload`, and
//! the controls that plant at a collected result are caught only on a
//! root whose run collects that result, and an ordering control is caught
//! only on a root whose run forms its premise, so calibration requires
//! none of them. A sweep counts a control run that ends in its failure as caught.
//! It counts as missed one that passes or ends under [`UNSEEN`], and an
//! unsuccessful or inconclusive ending of a control whose plant takes
//! effect in every run.

use crate::protocol::{Fails, Profile, Summary};
use crate::record::{CalibrationEvidence, Class, Digest};

/// A control profile and the failure its run must end in. The texts of a
/// control this module names are constants; those of a history borrow
/// the worker's listing.
#[derive(Clone, Copy)]
pub(in crate::campaign) struct Control<'a> {
    pub profile: &'a str,
    failure: Failure<'a>,
}
#[derive(Clone, Copy)]
enum Failure<'a> {
    /// A violation of the obligation with this code, under this rule when
    /// one is named.
    Violation(u8, Option<&'a str>),
    /// A violation of one of the obligations with these codes, under any
    /// rule. A plant in a drawn shape fails whichever check meets it first.
    Violated(&'static [u8]),
    /// A violation of the obligation with this code under this rule, in
    /// every run: the plant precedes the run's first turn.
    Certain(u8, &'a str),
    /// An unsuccessful ending under this rule, of which a summary prints
    /// at most 41 bytes: the run's rule is matched against that start.
    Unsuccessful(&'a str),
    /// An unsuccessful ending under this witness of a history, matched
    /// whole. A witness of 41 bytes or more matches no run, since the
    /// summary's cut could be the start of another witness.
    Witness(&'a str),
    Panic(&'a str),
}
const ROUTING: &str = "a key was served from an owner its routing contract does not name";
const STALE: &str = "a GET returned a version older than one collected or removed before it";
const LEAK: &str = "a healed owner kept the resources of finished work";
const UNCHECKED: &str = "a bound slot's record fails its header or chunk checks";
const VERSION_END: &str = "a key's version counter reached its end";
const MISREAD: &str = "a complete read returned bytes other than the label's content";
const UNPUBLISHED: &str = "a hit of a version no linearized fill published";
const LEAKED: &str = "the free runs differ from the units no slot holds";
const UNACCOUNTED: &str = "a datagram a link delivered to an owner has no single account";
const UNREPORTED: &str = "an upload collected as published without its result";
const EXPOSED: &str = "a refused read exposed bytes";
const FOREIGN: &str = "a GET returned bytes no upload of its key wrote";
/// The payload of the debug assertion the `asserting` control plants. A
/// worker built without debug assertions runs past it, so the control
/// ends unsuccessful under [`UNSEEN`] there.
const ASSERTION: &str = "a planted debug assertion once the upload published";
const WRONG_OWNER: Control = Control {
    profile: "cluster-wrong-owner",
    failure: Failure::Violation(2, Some(ROUTING)),
};
const STALE_READ: Control = Control {
    profile: "cluster-stale-read",
    failure: Failure::Violation(2, Some(STALE)),
};
const VERSION: Control = Control {
    profile: "cluster-version-end",
    failure: Failure::Unsuccessful(VERSION_END),
};

/// The rule a control's run ends unsuccessful under when its plant did
/// what a rule forbids and no check failed, as the summary prints it.
pub(in crate::campaign) const UNSEEN: &str = "the control's plant met no check";

/// The rule a control's run ends unsuccessful under when it finished
/// before its plant did what a rule forbids, as the summary prints it.
pub(in crate::campaign) const NO_EFFECT: &str = "the control's plant took no effect";

/// Each single-owner profile whose one control runs its scenario over a
/// resident record changed before the run, with that control. `failing`
/// and `uncertain` have that control beside others, in [`FAILING`] and
/// [`UNCERTAIN`].
const CORRUPTED: [(&str, Control); 11] = [
    ("faulted", corrupted("faulted-corrupted")),
    ("local", corrupted("local-corrupted")),
    ("control", corrupted("control-corrupted")),
    ("deferring", corrupted("deferring-corrupted")),
    ("replacing", corrupted("replacing-corrupted")),
    ("settled", corrupted("settled-corrupted")),
    ("boundary-tiny", corrupted("boundary-tiny-corrupted")),
    (
        "boundary-collision",
        corrupted("boundary-collision-corrupted"),
    ),
    (
        "boundary-fragmentation",
        corrupted("boundary-fragmentation-corrupted"),
    ),
    (
        "boundary-mixed-size",
        corrupted("boundary-mixed-size-corrupted"),
    ),
    (
        "boundary-real-counter",
        corrupted("boundary-real-counter-corrupted"),
    ),
];

/// The control of `upload` that runs its scenario over a resident record
/// changed before the run.
const CORRUPTED_UPLOAD: Control = corrupted("corrupted");

/// The control `profile`, whose every run a record byte changed before
/// the run fails under the record-check rule of the Bytes obligation.
const fn corrupted(profile: &'static str) -> Control<'static> {
    Control {
        profile,
        failure: Failure::Certain(1, UNCHECKED),
    }
}

pub(in crate::campaign) const fn violation<'a>(
    profile: &'a str,
    obligation: u8,
    rule: &'a str,
) -> Control<'a> {
    Control {
        profile,
        failure: Failure::Violation(obligation, Some(rule)),
    }
}

/// The controls of `failing`: its corrupted control, a GET of the
/// stranger key handed the resident object as a complete read, and that
/// GET refused with a byte handed out.
const FAILING: [Control; 3] = [
    corrupted("failing-corrupted"),
    Control {
        profile: "failing-hit",
        failure: Failure::Violation(2, Some(UNPUBLISHED)),
    },
    Control {
        profile: "failing-exposed",
        failure: Failure::Violation(8, Some(EXPOSED)),
    },
];

/// The controls of `uncertain`: its corrupted control, and an unknown
/// upload outcome collected as published.
const UNCERTAIN: [Control; 2] = [
    corrupted("uncertain-corrupted"),
    Control {
        profile: "uncertain-published",
        failure: Failure::Violation(2, Some(UNREPORTED)),
    },
];

/// An ordering control's premise: the count of the ordering constraints
/// its plant lists, the depth of Burckhardt et al., *A Randomized
/// Scheduler with Probabilistic Guarantees of Finding Bugs* (ASPLOS
/// 2010), with that paper's n and k as bounds of a run. The order of the
/// publication report before the changed read, which every plant also
/// needs, stands outside the count (see [`ORDERING`]). The chooser picks
/// each GET's issue and the order of events ready at one instant, a GET's
/// issue and the report's collection included; link draws and the turn
/// controller's clock rule decide when a read or the publication report
/// becomes ready. The three numbers describe the premise and are no input
/// to a bound on the caught rate.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the table records each premise; the tests hold its numbers to their sources"
    )
)]
pub(in crate::campaign) struct Premise {
    pub control: Control<'static>,
    /// Ordering constraints the plant lists, the order of the report
    /// before the changed read left out.
    pub depth: u8,
    /// Registered actors of a run: the `actors` count the checked-in
    /// cluster listing holds for the profile.
    pub n: u64,
    /// The turn limit of a run: the `turns` count the supervisor resolves
    /// for the profile with no override.
    pub k: u64,
}

const fn ordering(profile: &'static str, depth: u8) -> Premise {
    Premise {
        control: violation(profile, 1, FOREIGN),
        depth,
        n: 26,
        k: 20_000,
    }
}

/// The ordering controls of `cluster-broad`, one at each depth. Each
/// changes at most one read of the hot key's first version: a read whose
/// GET was accepted before that version was reported published, counted
/// in the depth, and that was decided after that report, an order every
/// depth shares and leaves uncounted. At depth 1 that is any such read, at
/// depth 2 client 0's once a GET of client 1 was decided, at depth 3
/// client 0's once a GET of client 1 accepted after its own was decided.
pub(in crate::campaign) const ORDERING: [Premise; 3] = [
    ordering("cluster-order-1", 1),
    ordering("cluster-order-2", 2),
    ordering("cluster-order-3", 3),
];

/// The controls of [`ORDERING`], in its order.
const ORDERED: [Control; 3] = [
    ORDERING[0].control,
    ORDERING[1].control,
    ORDERING[2].control,
];

/// The control of `contended`: an upload a fired chaos point refused
/// `Contended` collected as published. Its plant takes effect only on a
/// root whose upload ends `Contended`.
const CONTENDED_ACKED: Control = Control {
    profile: "contended-acked",
    failure: Failure::Violation(2, Some(UNREPORTED)),
};

/// Every healthy profile a sweep runs controls beside.
pub(in crate::campaign) const HEALTHY: [&str; 21] = [
    "upload",
    "long",
    "rekey",
    "cluster-broad",
    "cluster-pressure",
    "cluster-long",
    "cluster-swarm",
    "faulted",
    "contended",
    "local",
    "control",
    "deferring",
    "uncertain",
    "failing",
    "replacing",
    "settled",
    "boundary-tiny",
    "boundary-collision",
    "boundary-fragmentation",
    "boundary-mixed-size",
    "boundary-real-counter",
];

/// The controls calibration requires of the healthy profile `profile`.
pub(in crate::campaign) fn declared(profile: &str) -> &'static [Control<'static>] {
    match profile {
        "upload" => &[
            Control {
                profile: "planted",
                failure: Failure::Violation(1, None),
            },
            CORRUPTED_UPLOAD,
            Control {
                profile: "acked",
                failure: Failure::Violation(2, None),
            },
            Control {
                profile: "panicking",
                failure: Failure::Panic("a planted panic once the upload published"),
            },
        ],
        "long" => &[Control {
            profile: "long-planted",
            failure: Failure::Violation(1, None),
        }],
        "rekey" => &[Control {
            profile: "rekey-stalled",
            failure: Failure::Violation(6, None),
        }],
        "cluster-broad" => &[WRONG_OWNER, STALE_READ],
        "cluster-pressure" => &[WRONG_OWNER, STALE_READ, VERSION],
        "cluster-long" => &[
            Control {
                profile: "cluster-late-stale",
                failure: Failure::Violation(2, Some(STALE)),
            },
            Control {
                profile: "cluster-late-leak",
                failure: Failure::Unsuccessful(LEAK),
            },
            Control {
                profile: "cluster-late-corrupt",
                failure: Failure::Violation(1, Some(UNCHECKED)),
            },
            VERSION,
        ],
        _ => &[],
    }
}

/// The controls only a sweep runs beside the healthy profile `profile`.
fn sweep_only(profile: &str) -> &'static [Control<'static>] {
    match profile {
        "upload" => &[
            Control {
                profile: "asserting",
                failure: Failure::Panic(ASSERTION),
            },
            Control {
                profile: "misread",
                failure: Failure::Violation(1, Some(MISREAD)),
            },
            Control {
                profile: "staged-hit",
                failure: Failure::Violation(2, Some(UNPUBLISHED)),
            },
            Control {
                profile: "leaked",
                failure: Failure::Violation(4, Some(LEAKED)),
            },
            Control {
                profile: "uncounted",
                failure: Failure::Violation(8, Some(UNACCOUNTED)),
            },
        ],
        "failing" => &FAILING,
        "uncertain" => &UNCERTAIN,
        "contended" => &[CONTENDED_ACKED],
        "cluster-broad" => &ORDERED,
        "cluster-swarm" => &[
            // Key 0's uploads and reads at the wrong owner fail a routing,
            // binding or read check, whichever the member's shape meets.
            Control {
                profile: "cluster-swarm-wrong-owner",
                failure: Failure::Violated(&[1, 2]),
            },
            Control {
                profile: "cluster-swarm-stale-read",
                failure: Failure::Violated(&[2]),
            },
            Control {
                profile: "cluster-swarm-late-stale",
                failure: Failure::Violated(&[2]),
            },
            Control {
                profile: "cluster-swarm-leak",
                failure: Failure::Unsuccessful(LEAK),
            },
            Control {
                profile: "cluster-swarm-corrupt",
                failure: Failure::Violated(&[1]),
            },
            Control {
                profile: "cluster-swarm-misread",
                failure: Failure::Violation(1, Some(FOREIGN)),
            },
            // An acknowledged INVALIDATE that removed nothing leaves its
            // key's object bound, which the binding check meets when the
            // acknowledgment arrives. An upload of a version the INVALIDATE
            // named that publishes after it is met by the binding check or
            // by a read, whichever observes it first.
            Control {
                profile: "cluster-swarm-unremoved",
                failure: Failure::Violated(&[1, 2]),
            },
        ],
        _ => CORRUPTED
            .iter()
            .find(|(healthy, _)| *healthy == profile)
            .map_or(&[], |(_, control)| std::slice::from_ref(control)),
    }
}

/// The controls a sweep runs beside the healthy profile `profile`.
pub(in crate::campaign) fn swept(profile: &str) -> impl Iterator<Item = &'static Control<'static>> {
    declared(profile).iter().chain(sweep_only(profile))
}

/// How a run ended, as far as a control's failure reads it.
pub(in crate::campaign) enum Ended<'a> {
    /// A violation with this failure identity.
    Violation(&'a str),
    /// An unsuccessful ending under this rule, as the summary prints it.
    Unsuccessful(&'a str),
    /// A panic with this claim.
    Panic(&'a str),
}

impl<'c> Control<'c> {
    /// The control the listed history `history` is: its name and the
    /// failure its listing line declares, a violation of one obligation
    /// under one rule or an unsuccessful ending under one witness. `None`
    /// for a profile that declares no failure, as a history that expects
    /// a pass does.
    pub(in crate::campaign) fn history(history: &'c Profile) -> Option<Self> {
        let failure = match history.fails.as_ref()? {
            Fails::Violation(obligation, rule) => Failure::Violation(*obligation, Some(rule)),
            Fails::Unsuccessful(witness) => Failure::Witness(witness),
        };
        Some(Self {
            profile: &history.name,
            failure,
        })
    }

    /// Whether the control's plant takes effect in every run, so a run
    /// that ends unsuccessful or inconclusive was missed.
    pub(in crate::campaign) fn certain(&self) -> bool {
        matches!(self.failure, Failure::Certain(..))
    }

    /// Whether a run that `ended` this way ended in the control's failure.
    pub(in crate::campaign) fn caught<'a>(&self, ended: &Ended<'a>) -> bool {
        // A version 2 failure identity of a check or a history rule: its
        // obligation's code, and the digest of the rule it failed.
        let violated = |identity: &'a str| {
            (identity.len() == 88
                && identity.is_ascii()
                && &identity[..2] == "02"
                && matches!(&identity[2..4], "01" | "02"))
            .then(|| {
                (
                    u8::from_str_radix(&identity[4..6], 16).ok(),
                    &identity[14..78],
                )
            })
        };
        match (&self.failure, ended) {
            (Failure::Violation(obligation, rule), Ended::Violation(identity)) => {
                violated(identity).is_some_and(|(code, digest)| {
                    code == Some(*obligation)
                        && rule.is_none_or(|rule| digest == Digest::of(rule.as_bytes()).to_string())
                })
            }
            (Failure::Certain(obligation, rule), Ended::Violation(identity)) => violated(identity)
                .is_some_and(|(code, digest)| {
                    code == Some(*obligation) && digest == Digest::of(rule.as_bytes()).to_string()
                }),
            (Failure::Violated(obligations), Ended::Violation(identity)) => violated(identity)
                .is_some_and(|(code, _)| code.is_some_and(|code| obligations.contains(&code))),
            (Failure::Unsuccessful(rule), Ended::Unsuccessful(found)) => {
                found.as_bytes() == &rule.as_bytes()[..rule.len().min(41)]
            }
            (Failure::Witness(rule), Ended::Unsuccessful(found)) => {
                rule.len() < 41 && rule.as_bytes() == found.as_bytes()
            }
            (Failure::Panic(rule), Ended::Panic(found)) => found.ends_with(&format!(": {rule}")),
            _ => false,
        }
    }
}

/// The control named `profile`, when a sweep runs it beside a healthy
/// profile.
pub(in crate::campaign) fn named(profile: &str) -> Option<&'static Control<'static>> {
    HEALTHY
        .iter()
        .flat_map(|healthy| swept(healthy))
        .find(|control| control.profile == profile)
}

pub(super) fn detected(
    control: &Control,
    evidence: &CalibrationEvidence,
    summary: Option<&Summary>,
    panic: Option<&str>,
) -> bool {
    let ended = match evidence.finished.class {
        Class::Violation => summary
            .and_then(|summary| summary.identity.as_ref())
            .map(|identity| Ended::Violation(identity.as_str())),
        Class::Unsuccessful => summary
            .and_then(|summary| summary.unsuccessful.as_ref())
            .map(|rule| Ended::Unsuccessful(rule.as_str())),
        Class::EngineFailure => panic.map(Ended::Panic),
        _ => None,
    };
    ended.is_some_and(|ended| control.caught(&ended))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sweep runs a profile's calibration controls and then the ones
    /// only a sweep runs: `asserting`, `misread`, `staged-hit`, `leaked` and `uncounted` beside
    /// `upload`, the seven swarm controls beside `cluster-swarm`, and a
    /// corrupted control and its result plants beside each of `failing`
    /// and `uncertain`, and `contended-acked` beside `contended`, which
    /// calibration requires none of.
    #[test]
    fn a_sweep_adds_the_assertion_and_swarm_controls_to_the_declared_ones() {
        let names = |profile| {
            swept(profile)
                .map(|control| control.profile)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names("upload"),
            [
                "planted",
                "corrupted",
                "acked",
                "panicking",
                "asserting",
                "misread",
                "staged-hit",
                "leaked",
                "uncounted"
            ]
        );
        assert_eq!(
            names("failing"),
            ["failing-corrupted", "failing-hit", "failing-exposed"]
        );
        assert_eq!(
            names("uncertain"),
            ["uncertain-corrupted", "uncertain-published"]
        );
        assert_eq!(names("contended"), ["contended-acked"]);
        assert!(declared("contended").is_empty());
        assert_eq!(
            names("cluster-swarm"),
            [
                "cluster-swarm-wrong-owner",
                "cluster-swarm-stale-read",
                "cluster-swarm-late-stale",
                "cluster-swarm-leak",
                "cluster-swarm-corrupt",
                "cluster-swarm-misread",
                "cluster-swarm-unremoved",
            ]
        );
        assert!(declared("cluster-swarm").is_empty());
        assert_eq!(
            names("cluster-long"),
            declared("cluster-long")
                .iter()
                .map(|control| control.profile)
                .collect::<Vec<_>>()
        );
        assert!(named("asserting").is_some() && named("upload").is_none());
    }

    /// A sweep runs the three ordering controls beside `cluster-broad`
    /// after its calibration controls, one at each depth 1 to 3, each
    /// caught under the foreign-bytes rule of the Bytes obligation, and
    /// calibration requires none of them. Each row's n is the `actors`
    /// count the checked-in cluster listing holds for its profile, and its
    /// k is the `turns` count a run of that profile gets with no override.
    #[test]
    fn the_ordering_controls_carry_their_depth_and_the_bounds_of_a_run() {
        let names: Vec<_> = swept("cluster-broad")
            .map(|control| control.profile)
            .collect();
        assert_eq!(
            names,
            [
                "cluster-wrong-owner",
                "cluster-stale-read",
                "cluster-order-1",
                "cluster-order-2",
                "cluster-order-3",
            ]
        );
        let listing =
            crate::protocol::Listing::parse(include_str!("../../../testdata/cluster-listing.txt"))
                .unwrap();
        for (at, row) in ORDERING.iter().enumerate() {
            let profile = row.control.profile;
            assert_eq!(profile, format!("cluster-order-{}", at + 1));
            assert_eq!(usize::from(row.depth), at + 1, "{profile}");
            assert!(
                matches!(row.control.failure, Failure::Violation(1, Some(FOREIGN))),
                "{profile}"
            );
            assert!(
                declared("cluster-broad")
                    .iter()
                    .all(|control| control.profile != profile),
                "{profile}"
            );
            let listed = listing.profile(profile).expect("a listed control");
            assert_eq!(listed.class, crate::protocol::Class::Control, "{profile}");
            let actors = listed.held.iter().find(|(key, _)| key == "actors");
            assert_eq!(actors.map(|(_, least)| *least), Some(row.n), "{profile}");
            let counts = crate::campaign::freeze::resolved_counts(
                &listing,
                &listed.held,
                &std::collections::BTreeMap::new(),
            )
            .unwrap();
            let turns = counts.get(&crate::campaign::text("turns").unwrap());
            assert_eq!(
                turns,
                Some(&row.k),
                "{profile}: k is the turns count a run gets"
            );
        }
    }

    /// Each profile the worker's table pairs with a `-corrupted` control
    /// has no control calibration requires, is a healthy profile of a
    /// sweep, and has that control among its swept ones, as a control whose
    /// plant takes effect in every run. The table holds 13 pairs.
    #[test]
    fn a_sweep_runs_the_corrupted_control_of_each_profile_the_worker_pairs() {
        let bundle = include_str!("../../../../kestrike/src/net/world_tests/bundle.rs");
        let pairs: Vec<(&str, &str)> = bundle
            .lines()
            .filter_map(|line| {
                let (control, healthy) = line
                    .trim()
                    .strip_prefix("(\"")?
                    .strip_suffix("\"),")?
                    .split_once("\", \"")?;
                control
                    .ends_with("-corrupted")
                    .then_some((control, healthy))
            })
            .collect();
        assert_eq!(pairs.len(), 13);
        for (control, healthy) in pairs {
            assert_eq!(control, format!("{healthy}-corrupted"));
            assert!(declared(healthy).is_empty(), "{healthy}");
            assert!(HEALTHY.contains(&healthy), "{healthy}");
            let found = swept(healthy).find(|swept| swept.profile == control);
            assert!(found.is_some_and(Control::certain), "{healthy}");
        }
    }

    #[test]
    fn control_rules_obligation_codes_and_record_geometry_follow_worker_sources() {
        let obligations = include_str!("../../../../kestrike/src/oracle/obligation.rs")
            .split_once("pub(crate) enum Obligation {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0
            .lines()
            .map(str::trim)
            .filter(|line| line.ends_with(',') && !line.starts_with('/'))
            .map(|line| line.trim_end_matches(','))
            .collect::<Vec<_>>();
        assert_eq!(
            obligations,
            [
                "Bytes",
                "History",
                "Custody",
                "Resources",
                "Restart",
                "Progress",
                "Isolation",
                "Contain"
            ]
        );
        let sources = [
            include_str!("../../../../kestrike/src/net/world_tests/cluster.rs"),
            include_str!("../../../../kestrike/src/net/world_tests.rs"),
            include_str!("../../../../kestrike/src/net/observe.rs"),
        ]
        .concat();
        for rule in [
            ROUTING,
            STALE,
            LEAK,
            UNCHECKED,
            VERSION_END,
            "a planted panic once the upload published",
            ASSERTION,
            UNSEEN,
            NO_EFFECT,
            MISREAD,
            UNPUBLISHED,
            LEAKED,
            UNACCOUNTED,
            UNREPORTED,
            EXPOSED,
            FOREIGN,
        ] {
            assert!(
                sources.contains(&format!("\"{rule}\"")),
                "worker rule changed: {rule}"
            );
        }
        for profile in HEALTHY {
            assert!(swept(profile).next().is_some(), "{profile}");
            for control in swept(profile) {
                let codes = match &control.failure {
                    Failure::Violation(code, _) | Failure::Certain(code, _) => {
                        std::slice::from_ref(code)
                    }
                    Failure::Violated(codes) => codes,
                    Failure::Unsuccessful(_) | Failure::Witness(_) | Failure::Panic(_) => &[],
                };
                for code in codes {
                    let obligation = obligations[usize::from(*code) - 1];
                    assert!(
                        matches!(
                            obligation,
                            "Bytes" | "History" | "Resources" | "Progress" | "Contain"
                        ),
                        "{}: {obligation}",
                        control.profile
                    );
                }
            }
        }
        let uncounted = swept("upload").find(|control| control.profile == "uncounted");
        assert!(
            matches!(uncounted.map(|control| control.failure), Some(Failure::Violation(code, Some(UNACCOUNTED))) if obligations[usize::from(code) - 1] == "Contain"),
            "uncounted declares the containment obligation and the accounts text"
        );
        let leaked = swept("upload").find(|control| control.profile == "leaked");
        let Some(Failure::Violation(code, rule)) = leaked.map(|control| control.failure) else {
            panic!("leaked declares a violation beside upload");
        };
        assert_eq!(
            (obligations[usize::from(code) - 1], rule),
            ("Resources", Some(LEAKED))
        );
        for line in [
            format!("pub(crate) const FREE_RUNS: &str = \"{LEAKED}\";"),
            "Fault::FreeRuns => Failure::Violation(Obligation::Resources, FREE_RUNS),".into(),
        ] {
            assert!(
                sources.contains(&line),
                "worker free-run rule changed: {line}"
            );
        }
        let catalog = include_str!("../../../../kestrike/src/net/world_tests/catalog.rs");
        let controls: Vec<_> = catalog
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("entry(\"")?
                    .strip_suffix("\", Class::Control),")
            })
            .collect();
        assert!(controls.len() >= 12, "{controls:?}");
        for control in controls {
            assert!(named(control).is_some(), "{control} declares no failure");
        }
        let identity = include_str!("../../../../kestrike/src/net/world_tests/bundle.rs");
        assert!(identity.contains("pub(crate) const IDENTITY_VERSION: u8 = 2;"));
        assert!(identity.contains("obligation as u8 + 1"));
        let geometry = include_str!("../../../../kestrike/src/sim/trace.rs");
        assert!(geometry.contains("pub(crate) const RECORD: usize = 48;"));
        assert!(geometry.contains("pub(crate) const PAYLOAD: usize = RECORD - 4;"));
    }
}
