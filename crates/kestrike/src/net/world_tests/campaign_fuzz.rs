//! A fuzz input selects one of the target's scenarios, a mixed-world or a
//! recovery-world run, and feeds every decision of that run, under the real
//! authentication, geometry and checks the worker's runs use.
//!
//! An input is a format byte, `1`, a scenario byte indexing the target's
//! scenario list, and the feed the run's chooser reads in decision order.
//! An input past [`MAX_INPUT`] bytes, or with another format byte, is
//! invalid. A scenario byte past the list is unsupported. A mixed-world
//! feed whose setup draws a zero boot nonce, or a draw that gives the spare
//! client a zero boot nonce, is invalid, because a start
//! refuses that nonce. A feed that ends before a decision the run draws, setup and rekey
//! entropy draws included, is incomplete; when the run recorded a
//! violation first, or its bundle fails to load, the input is a failure.
//! Any other refused decision is a
//! failure whose claim names the chooser's error. Only a valid, supported
//! input whose feed covers every decision can pass.
//!
//! [`CAMPAIGN`] selects from [`SCENARIOS`], each of which can pass:
//!
//! - `upload` publishes one upload and reads it back.
//! - `faulted` runs `upload` over links that lose, duplicate, reorder and
//!   delay traffic, until a read returns the exact bytes.
//! - `deferring` defers an upload's supply, then invalidates its published
//!   key.
//! - `uncertain` leaves an upload's outcome unknown, then abandons and
//!   retries it.
//! - `rekey` rekeys the owner, then reads the resident object from each
//!   client until both episodes heal.
//! - `replacing` changes one client's session, then reads from each client
//!   until both reads decide and that client reads exactly in its new
//!   session.
//! - `failing` reads a key never published until the owner answers
//!   `Missing`.
//! - `crashing` runs the recovery world under the `recovery-16k` profile:
//!   each cut it activates kills the owner, relaunches it cold and checks
//!   its recovered lookup.
//!
//! The wrong-byte control is its own target, [`PLANTED`], over the one
//! scenario `planted`, so the byte a mutation rewrites selects only
//! scenarios that can pass.

use std::sync::OnceLock;

use crate::sim::choice::{ChoiceError, Chooser};
use crate::sim::fuzz::{Class, MAX_INPUT, Target};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Closed, Infrastructure, Outcome, Terminal, load};
use crate::sim::turn::End;

use super::super::put_tests::spare_nonce;
use super::branch::{hex, terminal_text};
use super::bundle::{admit, breach, run_into};
use super::{setup_draws, sites};

/// The input format this target reads.
pub(crate) const FORMAT: u8 = 1;

/// The scenarios an input selects, by index.
pub(crate) const SCENARIOS: [&str; 8] = [
    "upload",
    "faulted",
    "deferring",
    "uncertain",
    "rekey",
    "replacing",
    "failing",
    "crashing",
];

/// Turns one run may take.
pub(crate) const TURNS: u64 = 4_000;

/// The campaign target.
pub(crate) static CAMPAIGN: Target = Target {
    name: "campaign",
    run: campaign,
    seeds,
};

pub(crate) static PLANTED: Target = Target {
    name: "planted",
    run: planted,
    seeds: Vec::new,
};

/// The manifest of `scenario` pinning the running worker; the worker's
/// digest is read once per process.
fn manifest(scenario: &str) -> Result<Manifest, String> {
    static OWN: OnceLock<Result<String, String>> = OnceLock::new();
    let own = OWN.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let path = std::env::current_exe().map_err(|error| error.to_string())?;
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        Ok(hex(&Sha256::digest(bytes)))
    });
    let platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let profile = profile_of(scenario);
    let text = crate::sim::manifest_tests::sample(profile, own.as_ref()?, &platform);
    Manifest::parse(&text)
        .map(|manifest| {
            let manifest = manifest.with("turns", TURNS);
            // A recovery scenario relaunches once per cut of its table, so
            // its restart bound is the table's length.
            match crate::sim::recovery::Recovery::named(profile) {
                Some(recovery) => manifest.with("restarts", recovery.table().len() as u64),
                None => manifest,
            }
        })
        .map_err(|error| format!("{error:?}"))
}

/// The manifest profile scenario `scenario` runs. `crashing` runs the
/// `recovery-16k` profile, so the worker's recovery profiles keep their
/// `recovery-` prefix; every other scenario is its own profile.
fn profile_of(scenario: &str) -> &str {
    if scenario == "crashing" {
        "recovery-16k"
    } else {
        scenario
    }
}

fn campaign(input: &[u8]) -> Class {
    classify(input, &SCENARIOS)
}

fn planted(input: &[u8]) -> Class {
    classify(input, &["planted"])
}

/// Judges one campaign input: its format, its scenario, then the run its
/// feed drives, to its terminal and teardown.
fn classify(input: &[u8], scenarios: &[&str]) -> Class {
    if input.len() > MAX_INPUT {
        return Class::Invalid("the input passes its byte bound");
    }
    let [format, scenario, feed @ ..] = input else {
        return Class::Invalid("the input holds fewer than its format and scenario bytes");
    };
    if *format != FORMAT {
        return Class::Invalid("the input names another format");
    }
    let Some(name) = scenarios.get(usize::from(*scenario)) else {
        return Class::Unsupported(*scenario);
    };
    let failure = |reason: String| Class::Failure {
        claim: format!("the {name} manifest did not admit: {reason}"),
        bundle: Vec::new(),
    };
    let manifest = match manifest(name) {
        Ok(manifest) => manifest,
        Err(reason) => return failure(reason),
    };
    let admitted = match admit(&manifest) {
        Ok(admitted) => admitted,
        Err(refusal) => return failure(format!("{refusal:?}")),
    };
    // A start refuses a zero boot nonce, as production does; a feed that
    // draws one, or whose spare client's nonce derived from a draw is
    // zero, names a run the system never starts.
    let mut probe = Chooser::fed(&sites(), feed.to_vec());
    if admitted.live()
        && let Ok((_, nonces)) = setup_draws(&mut probe)
        && (nonces.contains(&[0; 16]) || spare_nonce(nonces[1]) == [0; 16])
    {
        return Class::Invalid("the feed draws a zero boot nonce, which a start refuses");
    }
    let chooser = admitted.fed(feed.to_vec());
    let (closed, end, finished) = run_into(admitted, Vec::new(), chooser);
    class_of(name, end, closed, finished)
}

/// Judges a run of scenario `name` by how it ended and its closed bundle.
/// A `Short` refusal is incomplete, or a failure when the bundle records a
/// violation or fails to load. Any other chooser refusal is a failure
/// whose claim names the defect. A counting terminal passes only when its
/// bundle loads and meets [`ledger::counts`](crate::sim::ledger::counts),
/// and is unsuccessful when its loaded bundle falls short of that rule. The
/// pass carries `finished`, the fed run's tape, as its run; a tape that did
/// not finish is a failure. A
/// violation or infrastructure defect is a failure, and any other terminal
/// is unsuccessful.
fn class_of(
    name: &str,
    end: End,
    closed: Closed<Vec<u8>>,
    finished: Result<Vec<u8>, ChoiceError>,
) -> Class {
    let claim = || format!("{name}: {}", terminal_text(closed.terminal));
    let refused = match end {
        End::Defect(defect) => defect.choice().map(|error| (defect, error)),
        _ => None,
    };
    match (refused, closed.terminal) {
        (Some((_, ChoiceError::Short)), _) => cut_short(name, closed),
        (Some((defect, _)), _) => Class::Failure {
            claim: format!("{name}: the chooser refused a decision: {defect:?}"),
            bundle: closed.sink,
        },
        (_, terminal) if terminal.counts() => credited(name, closed, finished),
        (
            _,
            Terminal::Complete {
                outcome: Outcome::Violation,
                ..
            }
            | Terminal::Infrastructure(Infrastructure::Defect),
        ) => Class::Failure {
            claim: claim(),
            bundle: closed.sink,
        },
        _ => Class::Unsuccessful(claim()),
    }
}

fn credited(name: &str, closed: Closed<Vec<u8>>, finished: Result<Vec<u8>, ChoiceError>) -> Class {
    match load(&closed.sink, u64::MAX) {
        Ok(loaded) if crate::sim::ledger::counts(&loaded) => match finished {
            Ok(run) => Class::Pass { run },
            Err(error) => Class::Failure {
                claim: format!("{name}: the fed run's tape did not finish: {error:?}"),
                bundle: closed.sink,
            },
        },
        Ok(loaded) => Class::Unsuccessful(format!(
            "{name}: the recovery campaign withholds credit: {:?}",
            crate::sim::ledger::campaign(&loaded)
        )),
        Err(error) => Class::Failure {
            claim: format!("{name}: the passing run's bundle did not load: {error:?}"),
            bundle: closed.sink,
        },
    }
}

fn cut_short(name: &str, closed: Closed<Vec<u8>>) -> Class {
    let breach = match load(&closed.sink, u64::MAX) {
        Ok(loaded) => match loaded.violation {
            Some(code) => breach(&code),
            None => return Class::Incomplete,
        },
        Err(error) => {
            return Class::Failure {
                claim: format!("{name}: the cut run's bundle did not load: {error:?}"),
                bundle: closed.sink,
            };
        }
    };
    let violating = breach.map_or("an unnamed record".to_owned(), |breach| {
        format!("{breach:?}")
    });
    Class::Failure {
        claim: format!(
            "{name}: {} at the feed's end, violating {violating}",
            terminal_text(closed.terminal)
        ),
        bundle: closed.sink,
    }
}

pub(crate) fn seeds() -> Vec<(String, Vec<u8>)> {
    SCENARIOS
        .iter()
        .enumerate()
        .map(|(at, name)| (format!("{name}.input"), input(at as u8, at as u64)))
        .collect()
}

/// An input selecting scenario `at` over the 8 KiB feed seeded by `seed`.
pub(crate) fn input(at: u8, seed: u64) -> Vec<u8> {
    let mut stream = crate::storage::seeded::SplitMix64::new(seed);
    let mut out = vec![FORMAT, at];
    while out.len() < 8 * 1024 + 2 {
        out.extend(stream.next_u64().to_le_bytes());
    }
    out
}

#[cfg(test)]
pub(crate) mod tests;
