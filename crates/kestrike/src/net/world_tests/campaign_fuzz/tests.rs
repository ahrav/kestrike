//! The campaign fuzz target's input classes, its wrong-byte control, the
//! containment of a panicking run, and the worker's fuzz forms in fresh
//! processes.

use std::cell::RefCell;
use std::io::Write as _;

use crate::sim::choice::{ChoiceError, Chooser, Site};
use crate::sim::entropy::{DrawRefusal, key_pair_site, nonce_site};
use crate::sim::fuzz::{Class, MAX_INPUT, Target, claim_entry, counts, drive, generated, judged};
use crate::sim::trace::{Closed, Infrastructure, Outcome, Recorder, Terminal, load};
use crate::sim::turn::{Defect, End};

use super::super::super::fetch::Outcome as Fetched;
use super::super::super::frame::Status;
use super::super::super::observe::teardowns;
use super::super::super::owner_tests::key;
use super::super::super::witness::Witness;
use super::super::bundle::named;
use super::super::bundle::{ACT, Breach, ENTROPY, Stops, admit, breach, run_into, run_stopping};
use super::super::replay::{Refused, replay};
use super::super::scratch;
use super::super::{
    ACTORS, DELIVERED, Decided, EPISODE_TURNS, EPISODE_US, Episode, INDEX, LIMITS, REKEY_BUSY,
    REKEY_CUT, REKEY_ZERO, REKEYED, STRANGER, sites,
};
use super::{
    CAMPAIGN, FORMAT, PLANTED, SCENARIOS, TURNS, class_of, classify, input, manifest, seeds,
};
use crate::sim::action::ActionKind;
use crate::sim::ledger::{Campaign, Evidence, Gap, LEDGER, Stage, campaign};

/// A pass earns the checkpoint only when its run differs from every
/// seed's. A seed, a seed with a byte appended and a seed whose last feed
/// byte changed all drive the seed's run and earn nothing, no other class
/// earns it, and a generated feed the oracle passes does.
#[test]
fn a_checkpoint_counts_only_a_pass_whose_run_differs_from_every_seed_s() {
    let seeded: Vec<Vec<u8>> = seeds().into_iter().map(|(_, seed)| seed).collect();
    let runs: Vec<Vec<u8>> = seeded
        .iter()
        .map(|seed| match (CAMPAIGN.run)(seed) {
            Class::Pass { run } => run,
            other => panic!("a seed did not pass: {other:?}"),
        })
        .collect();
    for (at, seed) in seeded.iter().enumerate() {
        let pass = Class::Pass {
            run: runs[at].clone(),
        };
        assert!(!generated(&runs, &pass));
        let mut appended = seed.clone();
        appended.push(0);
        let mut altered = seed.clone();
        *altered.last_mut().unwrap() ^= 1;
        for replay in [&appended, &altered] {
            let class = (CAMPAIGN.run)(replay);
            assert_eq!(class, pass, "{at}: the seed's run");
            assert!(!generated(&runs, &class));
        }
        for class in [
            Class::Unsuccessful("cut".into()),
            Class::Invalid("malformed"),
            Class::Incomplete,
            Class::Unsupported(9),
        ] {
            assert!(!generated(&runs, &class));
        }
        let class = (99..199)
            .map(|feed| input(at as u8, feed))
            .find_map(|fed| match (CAMPAIGN.run)(&fed) {
                class @ Class::Pass { .. } => Some(class),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{at}: no generated feed passes"));
        assert!(generated(&runs, &class), "{class:?}");
    }
    let other = Class::Pass {
        run: b"another run".to_vec(),
    };
    assert!(generated(&[], &other));
    assert!(!generated(&[b"another run".to_vec()], &other));
}

#[test]
fn only_complete_supported_inputs_can_pass() {
    assert_eq!((CAMPAIGN.seeds)(), seeds());
    assert_eq!(seeds().len(), SCENARIOS.len());
    for (name, bytes) in seeds() {
        let class = (CAMPAIGN.run)(&bytes);
        assert!(
            matches!((class.name(), &class), ("pass", Class::Pass { .. })),
            "{name}: {class:?}"
        );
    }
    let Class::Failure { claim, bundle } = (PLANTED.run)(&input(0, 0)) else {
        panic!("the planted scenario did not fail");
    };
    assert!(claim.starts_with("planted: complete violation"), "{claim}");
    let loaded = load(&bundle, u64::MAX).unwrap();
    assert!(matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Violation,
            ..
        }
    ));
    let mut oversize = input(0, 0);
    oversize.resize(MAX_INPUT + 1, 0);
    let mut zero = input(0, 0);
    zero[2..].fill(0);
    let refused: [(&[u8], Class); 7] = [
        (
            &zero,
            Class::Invalid("the feed draws a zero boot nonce, which a start refuses"),
        ),
        (
            &[],
            Class::Invalid("the input holds fewer than its format and scenario bytes"),
        ),
        (
            &[FORMAT],
            Class::Invalid("the input holds fewer than its format and scenario bytes"),
        ),
        (
            &[FORMAT + 1, 0, 0],
            Class::Invalid("the input names another format"),
        ),
        (&oversize, Class::Invalid("the input passes its byte bound")),
        (
            &[FORMAT, SCENARIOS.len() as u8],
            Class::Unsupported(SCENARIOS.len() as u8),
        ),
        (&input(0, 0)[..64], Class::Incomplete),
    ];
    for (bytes, class) in refused {
        assert_eq!((CAMPAIGN.run)(bytes), class, "{} bytes", bytes.len());
    }
}

#[test]
fn no_campaign_input_reaches_the_planted_control() {
    let mut bytes = input(0, 0);
    for scenario in 0..=u8::MAX {
        bytes[1] = scenario;
        if let Class::Failure { claim, .. } = (CAMPAIGN.run)(&bytes) {
            panic!("scenario byte {scenario} failed: {claim}");
        }
    }
}

#[test]
fn a_violation_recorded_before_its_feed_ends_is_a_failure() {
    let bytes = input(0, 0);
    let mut short = 0;
    for cut in 3..=256 {
        match classify(&bytes[..cut], &["corrupted"]) {
            Class::Failure { claim, bundle } => {
                assert!(load(&bundle, u64::MAX).unwrap().violation.is_some());
                if claim.contains("at the feed's end, violating") {
                    short += 1;
                    assert!(matches!(replay(&bundle), Err(Refused::Exhausted)));
                }
            }
            class => panic!("at {cut}: {}", class.name()),
        }
    }
    assert!(short > 64, "{short} cuts ended short");
}

/// A feed cut anywhere is incomplete or, when its run already ended, the
/// pass it was; a cut never turns into a failure.
#[test]
fn a_cut_feed_is_incomplete_never_a_failure() {
    for (name, bytes) in seeds() {
        for cut in [3, 16, 64, 256, 1024, 2048, 4096] {
            let class = (CAMPAIGN.run)(&bytes[..cut]);
            assert!(
                matches!(class, Class::Incomplete | Class::Pass { .. }),
                "{name} at {cut}: {class:?}"
            );
        }
    }
}

/// Some feed drives a complete run that does not count, and it is judged
/// unsuccessful: it earns no pass and is no failure.
#[test]
fn a_complete_run_that_does_not_count_is_unsuccessful() {
    let found = (0..64)
        .flat_map(|seed| (0..SCENARIOS.len() as u8).map(move |at| input(at, seed)))
        .find_map(|bytes| match (CAMPAIGN.run)(&bytes) {
            Class::Unsuccessful(claim) => Some(claim),
            _ => None,
        });
    assert!(
        found.is_some(),
        "no feed ran a complete run that does not count"
    );
}

/// The end and closed bundle of scenario `name`'s run over `feed`, drawn
/// at the scenario's own sites and admission, as the classifier draws it.
fn ran_over(name: &str, feed: &[u8]) -> (End, Closed<Vec<u8>>) {
    let manifest = manifest(name).unwrap();
    let admitted = admit(&manifest).unwrap();
    let chooser = admitted.fed(feed.to_vec());
    let (closed, end, _) = run_into(admitted, Vec::new(), chooser);
    (end, closed)
}

/// [`ran_over`] drawing at `sites` through a plain fed chooser, with the
/// scenario's admission left off.
fn ran_at(name: &str, sites: &[Site], feed: &[u8]) -> (End, Closed<Vec<u8>>) {
    let manifest = manifest(name).unwrap();
    let admitted = admit(&manifest).unwrap();
    let chooser = Chooser::fed(sites, feed.to_vec());
    let (closed, end, _) = run_into(admitted, Vec::new(), chooser);
    (end, closed)
}

/// The outcomes the bundle's action events record for `kind`, in order.
fn acted(bundle: &[u8], kind: ActionKind) -> Vec<u64> {
    let loaded = load(bundle, u64::MAX).unwrap();
    loaded
        .events
        .iter()
        .filter(|event| event.kind == ACT && event.payload[0] == kind as u8)
        .map(|event| u64::from_le_bytes(event.payload[1..9].try_into().unwrap()))
        .collect()
}

/// The refused entropy draws the bundle's events record, each payload
/// trimmed of its zero padding and keeping at least its 8-byte draw header.
fn recorded_refusals(bundle: &[u8]) -> Vec<Vec<u8>> {
    let loaded = load(bundle, u64::MAX).unwrap();
    loaded
        .events
        .iter()
        .filter(|event| event.kind == ENTROPY)
        .map(|event| {
            let end = event
                .payload
                .iter()
                .rposition(|&byte| byte != 0)
                .map_or(0, |at| at + 1);
            event.payload[..end.max(8)].to_vec()
        })
        .collect()
}

/// The trimmed [`ENTROPY`] payload for a `Short` draw at `site` in
/// `incarnation`.
fn short_record(site: Site, incarnation: u32) -> Vec<u8> {
    let mut record = [site.actor.to_le_bytes(), site.site.to_le_bytes()].concat();
    record.extend(incarnation.to_le_bytes());
    record.extend(b"Short");
    record
}

/// The end of a run whose feed ended inside the entropy draw at `site` in
/// `incarnation`.
fn short(site: Site, incarnation: u32) -> End {
    End::Defect(Defect::Entropy(DrawRefusal {
        site,
        incarnation,
        error: ChoiceError::Short,
    }))
}

/// A feed that ends inside any setup draw (the index key pair or a boot
/// nonce) ends the run at that draw's site in the actor's first
/// incarnation. The bundle records the refused draw and closes as an
/// infrastructure defect, and the input is incomplete. Each draw is cut
/// after 0 and after 15 of its 16 bytes.
#[test]
fn ib_entropy_exhaustion_a_setup_cut_is_incomplete_with_its_draw() {
    let bytes = input(0, 0);
    let draws = [key_pair_site(INDEX)]
        .into_iter()
        .chain(ACTORS.map(nonce_site));
    for (at, site) in draws.enumerate() {
        for cut in [16 * at, 16 * at + 15] {
            let feed = &bytes[2..2 + cut];
            let (end, closed) = ran_over("upload", feed);
            assert_eq!(end, short(site, 0), "cut at {cut}");
            let loaded = load(&closed.sink, u64::MAX).unwrap();
            assert_eq!(
                loaded.terminal,
                Terminal::Infrastructure(Infrastructure::Defect)
            );
            assert_eq!(recorded_refusals(&closed.sink), [short_record(site, 0)]);
            let rebuilt = Witness::rebuild(&loaded.events).map(|witness| witness.events());
            assert_eq!(
                rebuilt,
                Ok(Vec::new()),
                "cut at {cut}: the witness read the refused draw's event"
            );
            assert_eq!(classify(&bytes[..2 + cut], &["upload"]), Class::Incomplete);
        }
    }
}

/// A feed that ends inside the rekey's nonce draw ends the run at the
/// owner's nonce site in its second incarnation. The owner refuses the
/// rekey as `REKEY_CUT`, the bundle records that outcome and the refused
/// draw, the input is incomplete, and replay of the bundle reports
/// `Exhausted`. The same feed with the draw's 16 bytes zeroed reaches the
/// owner's all-zero nonce refusal, `REKEY_ZERO`, records no refused draw,
/// and classifies as unsuccessful.
#[test]
fn ib_entropy_exhaustion_a_rekey_cut_is_incomplete_with_its_draw() {
    let (profile, _, _) = named("control", 3).expect("a named scenario");
    assert!(profile.declares(ActionKind::Rekey));
    let bytes = input(0, 5);
    let feed = &bytes[2..];
    let owner = nonce_site(ACTORS[0]);
    let start = (64..feed.len())
        .find(|&cut| ran_over("control", &feed[..cut]).0 == short(owner, 1))
        .expect("some cut ends inside the rekey's nonce draw");
    for cut in start..start + 16 {
        let (end, closed) = ran_over("control", &feed[..cut]);
        assert_eq!(end, short(owner, 1), "cut at {cut}");
        assert_eq!(
            acted(&closed.sink, ActionKind::Rekey).last(),
            Some(&REKEY_CUT)
        );
        assert_eq!(recorded_refusals(&closed.sink), [short_record(owner, 1)]);
        let class = classify(&bytes[..2 + cut], &["control"]);
        assert_eq!(class, Class::Incomplete, "cut at {cut}");
        assert!(
            matches!(replay(&closed.sink), Err(Refused::Exhausted)),
            "cut at {cut}"
        );
    }
    let mut zeroed = bytes.clone();
    zeroed[2 + start..2 + start + 16].fill(0);
    let (end, closed) = ran_over("control", &zeroed[2..]);
    assert!(!matches!(end, End::Defect(_)), "{end:?}");
    assert!(acted(&closed.sink, ActionKind::Rekey).contains(&REKEY_ZERO));
    assert!(recorded_refusals(&closed.sink).is_empty());
    let class = classify(&zeroed, &["control"]);
    assert!(matches!(class, Class::Unsuccessful(_)), "{class:?}");
}

/// A `Short` entropy end judged against a bundle that records a violation
/// is a failure whose claim names the violation and whose bundle keeps it.
#[test]
fn ib_entropy_exhaustion_a_cut_after_a_violation_stays_a_failure() {
    let (_, closed) = ran_over("corrupted", &input(0, 0)[2..]);
    assert!(load(&closed.sink, u64::MAX).unwrap().violation.is_some());
    let end = short(nonce_site(ACTORS[0]), 1);
    let Class::Failure { claim, bundle } = class_of("corrupted", end, closed, Ok(Vec::new()))
    else {
        panic!("a cut after a violation was not a failure");
    };
    assert!(claim.contains("at the feed's end, violating"), "{claim}");
    assert!(load(&bundle, u64::MAX).unwrap().violation.is_some());
}

/// A chooser error other than `Short`, at an entropy draw or another
/// decision, is a failure whose claim names the error. The cases are an
/// unregistered key pair site in a real run, and `Identity`, `Candidates`
/// and `Index` each set as the end of a complete run, both as an entropy
/// defect and as a choice defect.
#[test]
fn ib_entropy_exhaustion_a_non_short_refusal_is_a_failure_naming_it() {
    let feed = &input(0, 0)[2..];
    let unregistered: Vec<Site> = sites()
        .into_iter()
        .filter(|&site| site != key_pair_site(INDEX))
        .collect();
    let (end, closed) = ran_at("upload", &unregistered, feed);
    let Class::Failure { claim, .. } = class_of("upload", end, closed, Ok(Vec::new())) else {
        panic!("an unregistered entropy site was not a failure");
    };
    assert!(claim.contains("Unregistered"), "{claim}");
    let errors = [
        ChoiceError::Identity,
        ChoiceError::Candidates,
        ChoiceError::Index { index: 3, len: 2 },
    ];
    let (_, complete) = ran_over("upload", feed);
    for error in errors {
        let cut = DrawRefusal {
            site: nonce_site(ACTORS[0]),
            incarnation: 1,
            error,
        };
        for defect in [Defect::Entropy(cut), Defect::Choice(error)] {
            let closed = Closed {
                sink: complete.sink.clone(),
                ..complete
            };
            let class = class_of("upload", End::Defect(defect), closed, Ok(Vec::new()));
            let Class::Failure { claim, .. } = class else {
                panic!("{defect:?} was credited {class:?}");
            };
            assert!(claim.contains(&format!("{error:?}")), "{claim}");
        }
    }
}

/// Panics at its first stopped boundary.
struct Panics;

impl Stops<Vec<u8>> for Panics {
    fn stopped(&mut self, _recorder: &mut Recorder<Vec<u8>>, _chooser: &RefCell<Chooser>) {
        panic!("a planted panic in a fuzzed run");
    }
}

/// A target whose every run panics inside the world, the control that a
/// panic tears its world down before the driver aborts.
pub(crate) static PANICKING: Target = Target {
    name: "panicking",
    run: panicking,
    seeds: Vec::new,
};

/// A run that panics inside the world.
fn panicking(_input: &[u8]) -> Class {
    let manifest = manifest("upload").unwrap();
    let chooser = admit(&manifest).unwrap().recorder();
    let _ = run_stopping(admit(&manifest).unwrap(), Vec::new(), chooser, Panics);
    Class::Pass { run: Vec::new() }
}

/// A run that panics is contained: the judgment is a failure, the panic
/// never reaches the caller, and the world's teardown audit ran during the
/// unwind before the judgment returned. The driver's entry is claimed once
/// per process, so a later entry is refused before libFuzzer runs.
#[test]
fn a_panicking_run_tears_down_before_its_failure_returns() {
    let before = teardowns();
    let class = judged(&PANICKING, &[]);
    let Class::Failure { claim, bundle } = &class else {
        panic!("{class:?}");
    };
    assert!(bundle.is_empty());
    assert!(
        claim.starts_with("the run panicked at ") && claim.contains(file!()),
        "{claim}"
    );
    assert!(
        claim.ends_with(": a planted panic in a fuzzed run"),
        "{claim}"
    );
    assert_eq!(teardowns(), before + 1);
    assert_eq!(claim_entry(), Ok(()));
    assert!(claim_entry().is_err());
    let tmp = std::env::temp_dir();
    let again = drive(&CAMPAIGN, &tmp.to_string_lossy(), &["-help=1".into()]);
    assert_eq!(again, Err("the fuzz driver was already entered".into()));
    assert!(counts().starts_with("fuzz: "));
}

/// The fuzz forms belong to the worker: the library's test binary has none,
/// so each fresh-process case fails when it runs there.
#[test]
fn the_fuzz_forms_run_only_in_the_worker() {
    assert!(the_campaign_driver_loads_seeds_and_executes_positively().is_err());
    assert!(a_merge_enters_the_driver_in_its_inner_process().is_err());
    assert!(a_wrong_byte_input_audits_tears_down_then_aborts().is_err());
    assert!(a_panicking_input_tears_down_before_the_driver_aborts().is_err());
    assert!(the_parser_targets_load_seeds_and_execute_positively().is_err());
    assert!(a_parser_failure_replays_and_minimizes().is_err());
    assert!(the_appended_seeds_replay_alike_in_fresh_processes().is_err());
}

/// A fresh worker driven over the panicking control unwinds the run through
/// its world's teardown audit, reports the audit count, retains the input
/// with no bundle, and only then aborts nonzero.
pub(crate) fn a_panicking_input_tears_down_before_the_driver_aborts() -> Result<(), String> {
    let dir = scratch("sim-fuzz-panic")?;
    let checked = (|| {
        let artifacts = dir.join("artifacts");
        std::fs::create_dir(&artifacts).map_err(|error| error.to_string())?;
        let path = dir.join("any.input");
        std::fs::write(&path, b"any").map_err(|error| error.to_string())?;
        let ran = worker(&[
            "--fuzz".as_ref(),
            "panicking".as_ref(),
            "--artifacts".as_ref(),
            artifacts.as_ref(),
            "--".as_ref(),
            path.as_ref(),
        ])?;
        let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
        let audited = stderr.find("fuzz: audited and tore down panicking: the run panicked at ");
        let identified = stderr.contains(": a planted panic in a fuzzed run; 1 teardowns");
        let crashed = stderr.find("deadly signal");
        let ordered = matches!((audited, crashed), (Some(a), Some(c)) if a < c);
        let kept = artifacts.join("first-failure.input").is_file()
            && !artifacts.join("first-failure.bundle").exists();
        let claimed = std::fs::read_to_string(artifacts.join("first-failure.claim"))
            .is_ok_and(|claim| claim.ends_with(": a planted panic in a fuzzed run\n"));
        if ran.status.success() || !ordered || !kept || !identified || !claimed {
            return Err(format!("the driver exited {}: {stderr}", ran.status));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// Runs the worker with `args` and an empty environment. The child starts
/// through [`spawn_quiet`](crate::bind::fixture::spawn_quiet): until it
/// executes it shares this process's open files, and a lock file another
/// test holds would stay locked by it.
pub(crate) fn worker(args: &[&std::ffi::OsStr]) -> Result<std::process::Output, String> {
    use std::process::{Command, Stdio};

    let path = std::env::current_exe().map_err(|error| error.to_string())?;
    let quiet = crate::bind::fixture::spawn_quiet();
    let child = Command::new(path)
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    drop(quiet);
    child
        .and_then(std::process::Child::wait_with_output)
        .map_err(|error| error.to_string())
}

/// The counts a driver's stderr reports for `class`.
fn count(stderr: &str, class: &str) -> Option<u64> {
    let line = stderr
        .lines()
        .rev()
        .find(|line| line.starts_with("fuzz: campaign "))?;
    line.split(' ')
        .find_map(|field| field.strip_prefix(&format!("{class}=")))?
        .parse()
        .ok()
}

/// A fresh worker writes the campaign's seeds, and another enters the
/// driver over them: it loads every seed, executes a positive bounded
/// count, passes each seed, fails none, retains nothing, and reports its
/// checkpoint count. A run over the seed files alone passes each and counts
/// no generated pass, and the same run beside one generated upload input
/// that passes counts one. The worker's
/// fuzz forms refuse an unknown target, a missing `--artifacts` option, a
/// nonexistent artifact directory, a flag that restarts the program, and
/// an existing seed.
pub(crate) fn the_campaign_driver_loads_seeds_and_executes_positively() -> Result<(), String> {
    let dir = scratch("sim-fuzz-seeds")?;
    let checked = (|| {
        let (seeds_dir, artifacts) = (dir.join("seeds"), dir.join("artifacts"));
        for made in [&seeds_dir, &artifacts] {
            std::fs::create_dir(made).map_err(|error| error.to_string())?;
        }
        let wrote = worker(&["--seeds".as_ref(), "campaign".as_ref(), seeds_dir.as_ref()])?;
        let listed = std::fs::read_dir(&seeds_dir)
            .map_err(|e| e.to_string())?
            .count();
        if wrote.status.code() != Some(0) || listed != seeds().len() {
            return Err(format!(
                "--seeds exited {} with {listed} files",
                wrote.status
            ));
        }
        let ran = worker(&[
            "--fuzz".as_ref(),
            "campaign".as_ref(),
            "--artifacts".as_ref(),
            artifacts.as_ref(),
            "--".as_ref(),
            "-runs=40".as_ref(),
            "-seed=1".as_ref(),
            "-max_len=65536".as_ref(),
            seeds_dir.as_ref(),
        ])?;
        let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
        let loaded = format!("seed corpus: files: {listed} ");
        let executed = count(&stderr, "executed").unwrap_or(0);
        if ran.status.code() != Some(0)
            || !stderr.contains(&loaded)
            || executed < listed as u64
            || count(&stderr, "pass").unwrap_or(0) < listed as u64
            || count(&stderr, "failure") != Some(0)
            || std::fs::read_dir(&artifacts)
                .map_err(|e| e.to_string())?
                .count()
                != 0
        {
            return Err(format!("the driver exited {}: {stderr}", ran.status));
        }
        if count(&stderr, "nonseed_pass").is_none() {
            return Err(format!("the counts line lacks its checkpoint: {stderr}"));
        }
        let files: Vec<std::path::PathBuf> = std::fs::read_dir(&seeds_dir)
            .map_err(|e| e.to_string())?
            .map(|entry| entry.map(|entry| entry.path()).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let mut args: Vec<&std::ffi::OsStr> = [
            "--fuzz",
            "campaign",
            "--artifacts",
            artifacts.to_str().unwrap_or_default(),
            "--",
        ]
        .into_iter()
        .map(|arg| arg.as_ref())
        .collect();
        args.extend(files.iter().map(|file| file.as_os_str()));
        let seeded = worker(&args)?;
        let stderr = String::from_utf8_lossy(&seeded.stderr).into_owned();
        if seeded.status.code() != Some(0)
            || count(&stderr, "pass").unwrap_or(0) < listed as u64
            || count(&stderr, "nonseed_pass") != Some(0)
        {
            return Err(format!("the seeds alone earned a checkpoint: {stderr}"));
        }
        // A generated upload input the oracle passes earns the checkpoint once.
        let generated = input(0, 99);
        if !matches!(judged(&CAMPAIGN, &generated), Class::Pass { .. }) {
            return Err("the generated upload input does not pass".into());
        }
        let path = dir.join("generated.input");
        std::fs::write(&path, &generated).map_err(|error| error.to_string())?;
        args.push(path.as_os_str());
        let ran = worker(&args)?;
        let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
        let earned = count(&stderr, "nonseed_pass");
        if ran.status.code() != Some(0) || earned != Some(1) {
            return Err(format!("the generated pass earned {earned:?}: {stderr}"));
        }
        for refused in [
            vec!["--fuzz", "elsewhere", "--artifacts", "x"],
            vec!["--fuzz", "campaign"],
            vec![
                "--fuzz",
                "campaign",
                "--artifacts",
                "/nonexistent-artifacts",
                "--",
                "-help=1",
            ],
            vec![
                "--fuzz",
                "campaign",
                "--artifacts",
                "/tmp",
                "--",
                "-help=1",
                "-fork=2",
            ],
            vec![
                "--fuzz",
                "campaign",
                "--artifacts",
                "/tmp",
                "--",
                "-help=1",
                "-cleanse_crash=1",
            ],
        ] {
            let args: Vec<&std::ffi::OsStr> = refused.iter().map(|arg| arg.as_ref()).collect();
            let ran = worker(&args)?;
            if ran.status.code() != Some(2) {
                return Err(format!("{refused:?} exited {}", ran.status));
            }
        }
        let again = worker(&["--seeds".as_ref(), "campaign".as_ref(), seeds_dir.as_ref()])?;
        if again.status.code() != Some(2) {
            return Err(format!("rewriting seeds exited {}", again.status));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// A corpus merge runs through the worker's own `--fuzz` form. A merge of
/// the campaign's seeds into an empty directory exits 0, reports one
/// successful attempt and shows the inner process's own lines: its merge
/// line and the driver's counts line, the last counts line of the merge's
/// output and its only one, which reports the inputs it ran. The same merge
/// under the panicking target, whose every inner process aborts, prints
/// one counts line for each attempt, reports no successful
/// attempt and leaves the inner process's first failure in the outer
/// process's artifact directory, so the inner process is this worker's
/// form for the same target and directory. A merge is refused with exit
/// 2 before libFuzzer is entered when its artifact directory or a
/// libFuzzer argument holds a space, where the inner command line would
/// split, and when it names no control file; a run that is no merge
/// takes the spaced directory. Each other flag that starts the program
/// again is still refused. The worker is built without coverage counters
/// here, so the case shows that the inner process enters the driver and
/// nothing of what a merge selects.
///
/// A merge that names the first merge's control file exits 2, and so
/// does a merge whose control file follows `-ignore_remaining_args=1`.
/// Each restart flag runs with `-help=1`, so a worker that enters
/// libFuzzer prints help and returns 0.
pub(crate) fn a_merge_enters_the_driver_in_its_inner_process() -> Result<(), String> {
    const MERGED: &str = "MERGE-OUTER: successful in 1 attempt(s)";
    let dir = scratch("sim-fuzz-merge")?;
    let checked = (|| {
        let made = |name: &str| {
            let made = dir.join(name);
            std::fs::create_dir(&made).map_err(|error| error.to_string())?;
            Ok::<_, String>(made)
        };
        let (seeds_dir, spaced) = (made("seeds")?, made("with space")?);
        let wrote = worker(&["--seeds".as_ref(), "campaign".as_ref(), seeds_dir.as_ref()])?;
        if wrote.status.code() != Some(0) {
            return Err(format!("--seeds exited {}", wrote.status));
        }
        let run = |target: &str, artifacts: &std::path::Path, libfuzzer: &[&std::ffi::OsStr]| {
            let mut args: Vec<&std::ffi::OsStr> =
                vec!["--fuzz".as_ref(), target.as_ref(), "--artifacts".as_ref()];
            args.extend([artifacts.as_os_str(), "--".as_ref()]);
            args.extend(libfuzzer);
            let ran = worker(&args)?;
            let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
            Ok::<_, String>((ran.status.code(), stderr))
        };
        let controlled = |name: &str| format!("-merge_control_file={}", dir.join(name).display());
        let merge =
            |target: &str, control: &str, artifacts: &std::path::Path, into: &std::path::Path| {
                // The control file and libFuzzer's own artifacts stay in the
                // case's directory.
                let control = controlled(control);
                let prefix = format!("-artifact_prefix={}/", dir.join("artifacts").display());
                let flags: [&std::ffi::OsStr; 3] =
                    ["-merge=1".as_ref(), control.as_ref(), prefix.as_ref()];
                run(
                    target,
                    artifacts,
                    &[&flags[..], &[into.as_os_str(), seeds_dir.as_os_str()]].concat(),
                )
            };
        let refused = |(code, stderr): (Option<i32>, String), reason: &str, label: &str| {
            let merged = stderr.lines().any(|line| line.starts_with("MERGE-OUTER"));
            if code != Some(2) || !stderr.contains(reason) || merged {
                return Err(format!("{label} exited {code:?}: {stderr}"));
            }
            Ok(())
        };
        let empty = |made: &std::path::Path| {
            let mut entries = std::fs::read_dir(made).map_err(|error| error.to_string())?;
            Ok::<_, String>(entries.next().is_none())
        };
        let artifacts = made("artifacts")?;
        let (code, stderr) = merge("campaign", "first", &artifacts, &made("merged")?)?;
        // The coordinator prints no counts line, so the last one is the
        // inner process's and reports the inputs it ran.
        let executed = count(&stderr, "executed").is_some_and(|executed| executed > 0);
        let inner = stderr.contains("MERGE-INNER: ") && executed;
        if code != Some(0) || !stderr.contains(MERGED) || !inner {
            return Err(format!("the merge exited {code:?}: {stderr}"));
        }
        // The counts lines a run of `target` printed: one for each process
        // that ran inputs.
        let reports = |stderr: &str, target: &str| {
            let counts = format!("fuzz: {target} executed=");
            stderr
                .lines()
                .filter(|line| line.starts_with(&counts))
                .count()
        };
        if reports(&stderr, "campaign") != 1 {
            return Err(format!(
                "the one-attempt merge printed another counts line: {stderr}"
            ));
        }
        let valued = |merge: &str, control: &str, into: &std::path::Path| {
            let control = controlled(control);
            let prefix = format!("-artifact_prefix={}/", dir.join("artifacts").display());
            let mut flags: Vec<&std::ffi::OsStr> = merge.split(' ').map(AsRef::as_ref).collect();
            let named: [&std::ffi::OsStr; 2] = [control.as_ref(), prefix.as_ref()];
            flags.extend(named);
            flags.extend([into.as_os_str(), seeds_dir.as_os_str()]);
            run("campaign", &artifacts, &flags)
        };
        let (code, stderr) = valued("-merge=1 -merge_inner=1", "inner-control", &made("inner")?)?;
        let executed = count(&stderr, "executed").is_some_and(|executed| executed > 0);
        if code != Some(0) || !stderr.contains(MERGED) || !executed {
            return Err(format!(
                "the merge beside -merge_inner exited {code:?}: {stderr}"
            ));
        }
        refused(
            valued("-merge=1x", "valued-control", &made("valued")?)?,
            "a merge takes -merge=0 or -merge=1",
            "a merge with the value 1x",
        )?;
        let aborted = made("aborted")?;
        let (code, stderr) = merge("panicking", "panicking", &aborted, &made("unmerged")?)?;
        let kept = aborted.join("first-failure.claim").is_file();
        if !kept || stderr.contains("MERGE-OUTER: successful") {
            return Err(format!("the panicking merge exited {code:?}: {stderr}"));
        }
        // Each attempt's inner process prints its counts line before it
        // aborts, and the outer process prints none.
        let attempts = stderr.matches("MERGE-OUTER: attempt ").count();
        if attempts == 0 || reports(&stderr, "panicking") != attempts {
            return Err(format!(
                "the panicking merge of {attempts} attempts printed other counts lines: {stderr}"
            ));
        }
        let bytes = "a merge takes only bytes of";
        let unsplit = made("unsplit")?;
        refused(
            merge("campaign", "spaced-artifacts", &spaced, &unsplit)?,
            bytes,
            "a merge with a spaced artifact directory",
        )?;
        refused(
            merge("campaign", "spaced-output", &artifacts, &spaced)?,
            bytes,
            "a merge with a spaced output directory",
        )?;
        let stale = "a merge takes a new control file";
        let record = std::fs::read(dir.join("first")).map_err(|error| error.to_string())?;
        let resumed = made("resumed")?;
        refused(
            merge("campaign", "first", &artifacts, &resumed)?,
            stale,
            "a merge over a finished control file",
        )?;
        let reread = std::fs::read(dir.join("first")).map_err(|error| error.to_string())?;
        if record.is_empty() || reread != record || !empty(&resumed)? {
            return Err("a refused merge changed its control file or its output".into());
        }
        std::os::unix::fs::symlink(dir.join("absent"), dir.join("dangling"))
            .map_err(|error| error.to_string())?;
        refused(
            merge("campaign", "dangling", &artifacts, &resumed)?,
            stale,
            "a merge over a dangling control link",
        )?;
        let merged = dir.join("merged");
        let control = controlled("unread");
        let unread = [
            "-merge=1".as_ref(),
            merged.as_os_str(),
            seeds_dir.as_os_str(),
            "-ignore_remaining_args=1".as_ref(),
            control.as_ref(),
        ];
        refused(
            run("campaign", &artifacts, &unread)?,
            "-ignore_remaining_args=1: a merge takes",
            "a merge with an unread control file",
        )?;
        let uncontrolled = [
            "-merge=1".as_ref(),
            merged.as_os_str(),
            seeds_dir.as_os_str(),
        ];
        refused(
            run("campaign", &artifacts, &uncontrolled)?,
            "-merge_control_file=FILE",
            "a merge with no control file",
        )?;
        let (lined, kept) = (made("lined")?, made("kept")?);
        std::fs::create_dir(lined.join("nested"))
            .and_then(|()| std::fs::write(lined.join("nested").join("a\nb"), b"input"))
            .map_err(|error| error.to_string())?;
        let control = controlled("lined-control");
        let split = [
            "-merge=1".as_ref(),
            control.as_ref(),
            kept.as_os_str(),
            lined.as_os_str(),
        ];
        refused(
            run("campaign", &artifacts, &split)?,
            "a merge takes corpus entry names of one line",
            "a merge over an entry named with a line break",
        )?;
        if dir.join("lined-control").exists() || !empty(&kept)? {
            return Err("a refused merge wrote its control file or its output".into());
        }
        let seed = seeds_dir.join("upload.input");
        let (code, stderr) = run("campaign", &spaced, &[seed.as_os_str()])?;
        if code != Some(0) {
            return Err(format!("a run that is no merge exited {code:?}: {stderr}"));
        }
        for flag in [
            "-fork=2",
            "-jobs=2",
            "-workers=2",
            "-set_cover_merge=1",
            "-minimize_crash=1",
            "-cleanse_crash=1",
        ] {
            let (code, stderr) = run(
                "campaign",
                &artifacts,
                &[flag.as_ref(), "-help=1".as_ref(), seeds_dir.as_os_str()],
            )?;
            if code != Some(2) || !stderr.contains("the driver runs in process") {
                return Err(format!("{flag} exited {code:?}: {stderr}"));
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// A fresh worker driven over the planted wrong-byte input audits and
/// tears the run down, reports it and its counts, and only then aborts
/// nonzero through the driver's crash path; the first failure's input,
/// bundle and claim stay in the artifact directory, and the bundle replays
/// and reduces through the worker's replay forms in further fresh
/// processes.
pub(crate) fn a_wrong_byte_input_audits_tears_down_then_aborts() -> Result<(), String> {
    let dir = scratch("sim-fuzz-crash")?;
    let checked = (|| {
        let artifacts = dir.join("artifacts");
        std::fs::create_dir(&artifacts).map_err(|error| error.to_string())?;
        let path = dir.join("planted.input");
        std::fs::File::create(&path)
            .and_then(|mut file| file.write_all(&input(0, 0)))
            .map_err(|error| error.to_string())?;
        let ran = worker(&[
            "--fuzz".as_ref(),
            "planted".as_ref(),
            "--artifacts".as_ref(),
            artifacts.as_ref(),
            "--".as_ref(),
            path.as_ref(),
        ])?;
        let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
        let audited =
            stderr.find("fuzz: audited and tore down planted: planted: complete violation");
        let counted = stderr.find("failure=1");
        let crashed = stderr.find("deadly signal");
        let ordered =
            matches!((audited, counted, crashed), (Some(a), Some(b), Some(c)) if a < b && b < c);
        if ran.status.success() || !ordered {
            return Err(format!("the driver exited {}: {stderr}", ran.status));
        }
        let bundle = artifacts.join("first-failure.bundle");
        for name in ["first-failure.input", "first-failure.claim"] {
            if !artifacts.join(name).is_file() {
                return Err(format!("no {name} retained"));
            }
        }
        let replayed = worker(&[
            "--replay".as_ref(),
            bundle.as_ref(),
            "--output".as_ref(),
            dir.join("replay").as_ref(),
        ])?;
        let said = String::from_utf8_lossy(&replayed.stdout).into_owned();
        if replayed.status.code() != Some(0) || !said.contains("violating Bytes") {
            return Err(format!("the replay exited {}: {said}", replayed.status));
        }
        let reduced = worker(&[
            "--reduce".as_ref(),
            bundle.as_ref(),
            "--output".as_ref(),
            dir.join("reduced").as_ref(),
        ])?;
        if reduced.status.code() != Some(0) {
            return Err(format!(
                "the reduction exited {}: {}",
                reduced.status,
                String::from_utf8_lossy(&reduced.stderr)
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// Each seed run of the scenarios from `rekey` on, retained as a bundle
/// led by its manifest's canonical form and whose tape holds every fed
/// decision, replays in two fresh workers,
/// and each replay's semantic trace equals the run's: its digest,
/// terminal, decision count, tape, turns and events.
pub(crate) fn the_appended_seeds_replay_alike_in_fresh_processes() -> Result<(), String> {
    let dir = scratch("sim-fuzz-episodes")?;
    let checked = (|| {
        for (at, name) in SCENARIOS.iter().enumerate().skip(4) {
            let manifest = manifest(name)?;
            let admitted = admit(&manifest).map_err(|refusal| format!("{refusal:?}"))?;
            let chooser = admitted.fed(input(at as u8, at as u64)[2..].to_vec());
            let (closed, _, _) = run_into(admitted, Vec::new(), chooser);
            let path = dir.join(format!("{name}.bundle"));
            std::fs::write(&path, &closed.sink).map_err(|error| error.to_string())?;
            let mut replays = Vec::new();
            for copy in ["first", "second"] {
                let out = dir.join(format!("{name}-{copy}"));
                let ran = worker(&[
                    "--replay".as_ref(),
                    path.as_ref(),
                    "--output".as_ref(),
                    out.as_ref(),
                ])?;
                let said = String::from_utf8_lossy(&ran.stdout).into_owned();
                if ran.status.code() != Some(0) || !said.starts_with("replay: reproduced") {
                    return Err(format!(
                        "{name}: the {copy} replay exited {}: {said}",
                        ran.status
                    ));
                }
                let bytes =
                    std::fs::read(out.join("replay.bundle")).map_err(|error| error.to_string())?;
                replays.push(bytes);
            }
            let semantic = |bytes: &[u8]| {
                load(bytes, u64::MAX).map(|loaded| {
                    let events: Vec<_> = loaded
                        .events
                        .iter()
                        .map(|event| (event.kind, event.payload))
                        .collect();
                    let decisions = loaded.work.decisions;
                    (
                        loaded.digest,
                        loaded.terminal,
                        decisions,
                        loaded.tape,
                        loaded.turns,
                        events,
                    )
                })
            };
            let original = semantic(&closed.sink).map_err(|error| format!("{error:?}"))?;
            for replayed in &replays {
                if semantic(replayed).map_err(|error| format!("{error:?}"))? != original {
                    return Err(format!("{name}: a fresh replay differs from the run"));
                }
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// Fresh workers write the record and wire targets' seeds and drive each
/// over them: every seed loads, a positive bounded count executes, no
/// input fails or is retained, and the counts line reports the checkpoint
/// count.
pub(crate) fn the_parser_targets_load_seeds_and_execute_positively() -> Result<(), String> {
    let dir = scratch("sim-fuzz-parsers")?;
    let checked = (|| {
        for target in ["record", "wire"] {
            let (seeds_dir, artifacts) =
                (dir.join(target), dir.join(format!("{target}-artifacts")));
            for made in [&seeds_dir, &artifacts] {
                std::fs::create_dir(made).map_err(|error| error.to_string())?;
            }
            let wrote = worker(&["--seeds".as_ref(), target.as_ref(), seeds_dir.as_ref()])?;
            let listed = std::fs::read_dir(&seeds_dir)
                .map_err(|e| e.to_string())?
                .count();
            if wrote.status.code() != Some(0) || listed == 0 {
                return Err(format!(
                    "{target} seeds exited {} with {listed} files",
                    wrote.status
                ));
            }
            let ran = worker(&[
                "--fuzz".as_ref(),
                target.as_ref(),
                "--artifacts".as_ref(),
                artifacts.as_ref(),
                "--".as_ref(),
                "-runs=2000".as_ref(),
                "-seed=1".as_ref(),
                seeds_dir.as_ref(),
            ])?;
            let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
            let line = stderr
                .lines()
                .rev()
                .find(|line| line.starts_with(&format!("fuzz: {target} ")))
                .unwrap_or("");
            let field = |class: &str| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix(&format!("{class}=")))
                    .and_then(|count| count.parse::<u64>().ok())
            };
            let loaded = format!("seed corpus: files: {listed} ");
            if ran.status.code() != Some(0)
                || !stderr.contains(&loaded)
                || field("nonseed_pass").is_none()
                || field("executed").unwrap_or(0) <= listed as u64
                || field("pass").unwrap_or(0) < listed as u64
                || field("failure") != Some(0)
                || std::fs::read_dir(&artifacts)
                    .map_err(|e| e.to_string())?
                    .count()
                    != 0
            {
                return Err(format!("{target} exited {}: {stderr}", ran.status));
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// A parser failure, from the record control whose reference checks the
/// key first, aborts nonzero after its audit and retains its input and
/// claim; the retained input replays to the same claim in a fresh worker
/// and minimizes there to a shorter input that fails with it again, while
/// the real record target finds nothing to minimize in it and an output
/// naming no file is refused.
pub(crate) fn a_parser_failure_replays_and_minimizes() -> Result<(), String> {
    let dir = scratch("sim-fuzz-parser-failure")?;
    let checked = (|| {
        let input = dir.join("key.input");
        let format = crate::storage::record::fuzz_tests::FORMAT;
        let ops = [
            format, 0, 3, 9, 200, 1, 5, 0, 4, 1, 3, 4, 160, 1, 3, 0, 20, 1,
        ];
        std::fs::write(&input, ops).map_err(|error| error.to_string())?;
        let drive = |name: &str, path: &std::path::Path| {
            let artifacts = dir.join(name);
            std::fs::create_dir(&artifacts).map_err(|error| error.to_string())?;
            let ran = worker(&[
                "--fuzz".as_ref(),
                "record-control".as_ref(),
                "--artifacts".as_ref(),
                artifacts.as_ref(),
                "--".as_ref(),
                path.as_ref(),
            ])?;
            let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
            let audited = stderr.find(
                "fuzz: audited and tore down record-control: header verification under reader",
            );
            let crashed = stderr.find("deadly signal");
            let ordered = matches!((audited, crashed), (Some(a), Some(c)) if a < c);
            if ran.status.success() || !ordered {
                return Err(format!("{name} exited {}: {stderr}", ran.status));
            }
            let claim = std::fs::read_to_string(artifacts.join("first-failure.claim"))
                .map_err(|error| error.to_string())?;
            Ok((artifacts.join("first-failure.input"), claim))
        };
        let (retained, claim) = drive("first", &input)?;
        let (_, replayed) = drive("replay", &retained)?;
        let smallest = dir.join("smallest.input");
        let minimized = worker(&[
            "--minimize".as_ref(),
            "record-control".as_ref(),
            retained.as_ref(),
            "--output".as_ref(),
            smallest.as_ref(),
        ])?;
        let kept = std::fs::read(&smallest).map_err(|error| error.to_string())?;
        if minimized.status.code() != Some(0) || kept.len() >= ops.len() {
            return Err(format!(
                "the minimizer exited {} with {} bytes",
                minimized.status,
                kept.len()
            ));
        }
        let (_, reduced) = drive("minimized", &smallest)?;
        if replayed != claim || reduced != claim {
            return Err(format!(
                "the claims differ: {claim:?}, replayed {replayed:?}, minimized {reduced:?}"
            ));
        }
        let clean = worker(&[
            "--minimize".as_ref(),
            "record".as_ref(),
            input.as_ref(),
            "--output".as_ref(),
            dir.join("none.input").as_ref(),
        ])?;
        if clean.status.code() != Some(1) {
            return Err(format!(
                "minimizing a passing input exited {}",
                clean.status
            ));
        }
        let directory = format!("{}/", dir.join("named").display());
        let nameless = worker(&[
            "--minimize".as_ref(),
            "record-control".as_ref(),
            input.as_ref(),
            "--output".as_ref(),
            directory.as_ref(),
        ])?;
        if nameless.status.code() != Some(2) || dir.join("named").exists() {
            return Err(format!(
                "an output naming no file exited {}",
                nameless.status
            ));
        }
        let taken = dir.join("taken.input");
        std::fs::write(&taken, b"kept").map_err(|error| error.to_string())?;
        let unplaced = dir.join("missing").join("placed.input");
        for output in [&taken, &unplaced] {
            let refused = worker(&[
                "--minimize".as_ref(),
                "record".as_ref(),
                input.as_ref(),
                "--output".as_ref(),
                output.as_ref(),
            ])?;
            if refused.status.code() != Some(2) {
                return Err(format!(
                    "an output at {} exited {}",
                    output.display(),
                    refused.status
                ));
            }
        }
        if std::fs::read(&taken).map_err(|error| error.to_string())? != b"kept" {
            return Err("the minimizer wrote over an existing output".to_owned());
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// The mixed world's run record of scenario `name` over `feed`, kept in
/// memory.
fn mixed_over(name: &str, feed: &[u8]) -> super::super::Ran {
    let (profile, plan, goal) = named(name, 3).expect("a named scenario");
    let chooser = Chooser::fed(&super::super::sites_for(&plan), feed.to_vec());
    let (ran, _, _) = super::super::mixed_run(chooser, &profile, plan, goal, LIMITS, &mut ());
    ran
}

/// Each seed of the scenarios from `rekey` on is an oracle pass whose own
/// history holds the scenario's episode witness: `rekey` a delivered
/// rekey, applied or busy, then a read from each client with the owner's
/// key epoch showing the outcome; `replacing` a delivered session change, then an exact read
/// from its client in a new session both endpoints hold under one epoch;
/// `failing` a read the owner refused as `Missing`; and `crashing` a cut
/// reached, drawn and applied, the owner rebuilt and its lookup checked
/// passing, with the rebuilt owner's lookup the turn after its relaunch.
#[test]
fn ib_campaign_episode_coverage_each_appended_seed_passes_with_its_witness() {
    let seeded = seeds();
    for (at, name) in SCENARIOS.iter().enumerate().skip(4) {
        let bytes = input(at as u8, at as u64);
        assert_eq!(seeded[at], (format!("{name}.input"), bytes.clone()));
        assert!(
            matches!(classify(&bytes, &SCENARIOS), Class::Pass { .. }),
            "{name}"
        );
        let feed = &bytes[2..];
        if *name == "crashing" {
            let (end, closed) = ran_over(name, feed);
            assert_eq!(end, End::Done);
            let loaded = load(&closed.sink, u64::MAX).unwrap();
            assert_eq!(
                crate::sim::trace::recorded_profile(&loaded.fields),
                Some("recovery-16k"),
                "{name}: a recovery run records a recovery profile"
            );
            assert_eq!(campaign(&loaded), Some(Campaign::Credited), "{name}");
            assert!(super::super::recovery::lookups_follow_relaunches(
                &loaded.turns
            ));
            continue;
        }
        let ran = mixed_over(name, feed);
        assert_eq!(ran.report.end, End::Done, "{name}");
        // The record's run took the classified run's turns, so its witness
        // is that history's.
        let (_, classified) = ran_over(name, feed);
        let taken: Vec<[u8; 16]> = ran.report.turns.iter().map(|turn| turn.event.0).collect();
        assert_eq!(
            load(&classified.sink, u64::MAX).unwrap().turns,
            taken,
            "{name}"
        );
        assert!(
            ran.report.turns.len() < TURNS as usize,
            "{name}: past the campaign's turns"
        );
        match *name {
            "failing" => assert!(
                ran.decided
                    .iter()
                    .any(|got| got.key == key(STRANGER) && got.outcome == Fetched::Missing)
            ),
            _ => {
                let (kind, clients) = match *name {
                    "rekey" => (ActionKind::Rekey, 2),
                    _ => (ActionKind::SessionChange, 1),
                };
                assert_eq!(ran.episodes.len(), clients, "{name}");
                assert_eq!(
                    ran.decided.len(),
                    2,
                    "{name}: a decided read from each client"
                );
                for episode in &ran.episodes {
                    assert!(
                        episode.kind == kind && episode.healed(),
                        "{name}: {episode:?}"
                    );
                    let delivered = ran.acts.iter().any(|act| {
                        act.kind == kind
                            && act.turn == episode.turn
                            && act.outcome == episode.outcome
                    });
                    assert!(delivered, "{name}: {episode:?}");
                }
            }
        }
    }
}

/// A rekey the owner refuses for an all-zero nonce opens no episode, so a
/// `rekey` input whose rekey nonce draw is zeroed classifies as
/// unsuccessful.
#[test]
fn ib_campaign_episode_coverage_an_uninjected_fault_earns_no_pass() {
    let bytes = input(4, 4);
    let feed = &bytes[2..];
    let owner = nonce_site(ACTORS[0]);
    let start = (64..feed.len())
        .find(|&cut| ran_over("rekey", &feed[..cut]).0 == short(owner, 1))
        .expect("some cut ends inside the rekey's nonce draw");
    let mut zeroed = bytes.clone();
    zeroed[2 + start..2 + start + 16].fill(0);
    let ran = mixed_over("rekey", &zeroed[2..]);
    assert!(ran.episodes.is_empty());
    assert!(
        ran.acts
            .iter()
            .any(|act| act.kind == ActionKind::Rekey && act.outcome == REKEY_ZERO)
    );
    let class = classify(&zeroed, &SCENARIOS);
    assert!(matches!(class, Class::Unsuccessful(_)), "{class:?}");
}

/// In `rekey-stalled`, client 0's episode heals while client 1's stays
/// unsettled, because the world withholds client 1's Read turns, and the
/// input classifies as a failure whose bundle records the Progress
/// violation for the stalled bound.
#[test]
fn ib_campaign_recovery_a_stalled_episode_fails_while_others_finish() {
    let bytes = input(4, 4);
    let ran = mixed_over("rekey-stalled", &bytes[2..]);
    let [first, second] = ran.episodes[..] else {
        panic!("{:?}", ran.episodes);
    };
    assert!(first.client == 0 && first.healed(), "{first:?}");
    assert!(second.client == 1 && second.settled.is_none(), "{second:?}");
    let mut planted = bytes.clone();
    planted[1] = 0;
    let Class::Failure { claim, bundle } = classify(&planted, &["rekey-stalled"]) else {
        panic!("a stalled episode was not a failure");
    };
    assert!(
        claim.starts_with("rekey-stalled: complete violation"),
        "{claim}"
    );
    let code = load(&bundle, u64::MAX)
        .unwrap()
        .violation
        .expect("a violation record");
    assert_eq!(
        breach(&code),
        Some(Breach::Obligation(crate::oracle::Obligation::Progress))
    );
    assert!(code[3..].starts_with(b"a healed request stalled past its bound"));
}

/// An episode settles only on a GET its own client issued after the
/// delivery, so an earlier success or another client's read discharges no
/// later episode; it stalls one turn past [`EPISODE_TURNS`] or one
/// microsecond past [`EPISODE_US`], and a settled episode stalls when its
/// GET decided one turn past [`EPISODE_TURNS`]. It heals only when the
/// endpoints show its update: an applied rekey moves the key epoch by one
/// and its read ends before any byte, a busy one keeps the epoch and heals
/// at any terminal, and a session change ends in a new session the owner
/// holds, read exactly.
#[test]
fn ib_campaign_recovery_an_episode_settles_only_by_its_own_later_read() {
    let episode = Episode {
        kind: ActionKind::SessionChange,
        outcome: DELIVERED,
        client: 1,
        turn: 10,
        at_us: 1_000,
        before: (1, Some(1)),
        settled: None,
    };
    let got = |client, issued| Decided {
        client,
        key: key(1),
        issued,
        decided: issued + 1,
        outcome: Fetched::Complete,
        exact: true,
    };
    assert_eq!(
        episode.settled_by(&[got(1, 5), got(1, 10), got(0, 12)]),
        None
    );
    assert_eq!(
        episode.settled_by(&[got(1, 5), got(1, 11), got(1, 12)]),
        Some(got(1, 11))
    );
    assert!(!episode.stalled(10 + EPISODE_TURNS, 1_000 + EPISODE_US));
    assert!(episode.stalled(11 + EPISODE_TURNS, 1_000));
    assert!(episode.stalled(10, 1_001 + EPISODE_US));
    let settled = Episode {
        settled: Some((got(1, 11), true)),
        ..episode
    };
    assert!(!settled.stalled(usize::MAX, u64::MAX));
    assert!(settled.healed());
    let decided_at = |decided| Episode {
        settled: Some((
            Decided {
                decided,
                ..got(1, 11)
            },
            true,
        )),
        ..episode
    };
    assert!(!decided_at(10 + EPISODE_TURNS).stalled(usize::MAX, u64::MAX));
    assert!(decided_at(11 + EPISODE_TURNS).stalled(usize::MAX, u64::MAX));
    for (shown, outcome, exact) in [
        (false, Fetched::Complete, true),
        (true, Fetched::Missing, true),
        (true, Fetched::Complete, false),
    ] {
        let read = Decided {
            outcome,
            exact,
            ..got(1, 11)
        };
        let unhealed = Episode {
            settled: Some((read, shown)),
            ..episode
        };
        assert!(!unhealed.healed(), "{unhealed:?}");
    }
    assert!(episode.shown(1, Some(2), Some(2)));
    for (session, held) in [(Some(1), Some(1)), (Some(2), Some(3)), (None, None)] {
        assert!(!episode.shown(1, session, held), "{session:?} {held:?}");
    }
    let rekey = |outcome| Episode {
        kind: ActionKind::Rekey,
        outcome,
        ..episode
    };
    assert!(rekey(REKEYED).shown(2, None, None) && !rekey(REKEYED).shown(1, None, None));
    assert!(rekey(REKEY_BUSY).shown(1, None, None) && !rekey(REKEY_BUSY).shown(2, None, None));
    let missed = Episode {
        settled: Some((
            Decided {
                outcome: Fetched::Missing,
                exact: false,
                ..got(1, 11)
            },
            true,
        )),
        ..rekey(REKEYED)
    };
    assert!(
        missed.healed(),
        "an applied rekey's episode heals at a byteless terminal"
    );
    for (outcome, exact) in [
        (Fetched::Complete, true),
        (Fetched::Incomplete(Status::TimedOut), false),
    ] {
        let read = Decided {
            outcome,
            exact,
            ..got(1, 11)
        };
        let applied = Episode {
            settled: Some((read, true)),
            ..rekey(REKEYED)
        };
        assert!(!applied.healed(), "{applied:?}");
        let busy = Episode {
            settled: Some((read, true)),
            ..rekey(REKEY_BUSY)
        };
        assert!(busy.healed(), "{busy:?}");
    }
}

#[test]
fn ib_campaign_recovery_a_crash_pass_without_ledger_credit_is_unsuccessful() {
    const EVENT: u8 = 6;
    let at = SCENARIOS
        .iter()
        .position(|&name| name == "crashing")
        .unwrap();
    let bytes = input(at as u8, at as u64);
    let (end, closed) = ran_over("crashing", &bytes[2..]);
    assert_eq!(end, End::Done);
    let capacity = manifest("crashing").unwrap().capacity();
    let unmatched = crate::sim::trace::reseal(&closed.sink, capacity, |records| {
        let activated = records
            .iter_mut()
            .find(|record| {
                record[0] == EVENT && record[1] == LEDGER && record[4] == Stage::Activated as u8
            })
            .expect("an activation entry");
        activated[4 + 11] = (activated[4 + 11] & 1) | (Evidence::Unmatched as u8) << 1;
    });
    let loaded = load(&unmatched, u64::MAX).unwrap();
    assert!(loaded.terminal.counts(), "{:?}", loaded.terminal);
    assert_eq!(
        campaign(&loaded),
        Some(Campaign::Inconclusive(Gap::Unmatched { cut: 0 }))
    );
    let resealed = Closed {
        terminal: loaded.terminal,
        digest: loaded.digest,
        work: loaded.work,
        sink: unmatched,
    };
    let Class::Unsuccessful(claim) = class_of("crashing", End::Done, resealed, Ok(Vec::new()))
    else {
        panic!("a crash pass without ledger credit was not unsuccessful");
    };
    assert!(claim.contains("Unmatched { cut: 0 }"), "{claim}");
}

/// The first incarnation's spare client boots with the second drawn nonce
/// with its first byte flipped, so a feed that draws `0xFF` and fifteen zero
/// bytes there gives the spare client a zero boot nonce, which a start
/// refuses. The input names a run the system never starts, so it is
/// invalid, as a zero drawn nonce is.
#[test]
fn a_feed_whose_spare_client_nonce_is_zero_is_invalid() {
    let mut bytes = input(0, 0);
    let spare = [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    bytes[34..50].copy_from_slice(&spare);
    let mut probe = Chooser::fed(&sites(), bytes[2..].to_vec());
    let (_, nonces) = super::super::setup_draws(&mut probe).expect("the feed covers its setup");
    assert_eq!(nonces[1], spare, "the feed's second nonce draw");
    assert!(!nonces.contains(&[0; 16]), "no drawn nonce is zero");
    assert_eq!(
        classify(&bytes, &SCENARIOS),
        Class::Invalid("the feed draws a zero boot nonce, which a start refuses")
    );
}
