// The protocol contract case: the worker's own output for each form the
// supervisor's parser reads, fed through that parser, which reads each
// form with the values the worker derives and refuses it with a line
// removed, repeated, foreign or cut short. The case also reads the launcher's
// published prefix after an injected worker index-sync failure.
//
// Only a build under `cfg(protocol_contract)` compiles this file and
// links the parser. The case lives beside `worker.rs`, whose text the
// worker embeds, so a worker built without the cfg holds neither the
// parser nor this file's text. An archive build must keep the cfg out of
// the flags it inherits for its worker to hold neither.

use sha2::{Digest, Sha256};

use campaign_supervisor::protocol::{
    self, Branch, Divergence, Error, Explore, Listing, Run, Session, Summary,
};

use super::*;
use crate::net::world_tests::branch::MILESTONES;
use crate::net::world_tests::bundle::{HELD, held_by};
use crate::net::world_tests::{bundle::STOP, catalog, histories, session};
use crate::sim::fork::{Classified, Verdict};

pub(super) const NAME: &str = "contract::the_supervisor_parses_every_worker_form";

/// The summary keys whose line a bundle may lack while the parser
/// cannot tell: an identity event and an unsuccessful check's rule.
const OPTIONAL: [&str; 2] = ["identity", "unsuccessful"];

/// Each form the supervisor's parser reads parses with the values the
/// worker derives: the capability listing; the rule catalog; a counting,
/// a capped and a panicked run and the inspection of each bundle; the
/// summary of every listed profile's bundle, among them a failure
/// identity, an unsuccessful rule and a ledger that withholds credit, with
/// the declared failure of each history that expects no pass, and of a
/// cluster bundle without its stop event; a branch and an exploration,
/// and each of them diverging before its milestone; a branch and an
/// exploration of a history at a turn and at a script milestone; a
/// session, its replay, and the replay's verdict for a changed end, a
/// changed turn, a changed record of another tag and a missing window;
/// bundle replay and reduction verdicts. Each printed output also
/// passes [`drift_refused`]. An injected index-sync failure also runs
/// the launcher and checks its published committed prefix.
/// [`words_agree`] holds the parser's stop, terminal and child-class
/// words to the worker's.
pub(super) fn every_form_parses() -> Result<(), String> {
    words_agree()?;
    let scratch = Scratch::new("worker-contract")?;
    let listing = listing(&scratch)?;
    rules(&scratch, &listing)?;
    runs(&scratch, &listing)?;
    bundle_verdicts(&scratch)?;
    profiles(&listing)?;
    let bundle = branches(&scratch)?;
    explorations(&scratch, &bundle)?;
    milestone_instances(&scratch)?;
    sessions(&scratch)?;
    a_failed_index_sync_publishes_only_the_committed_prefix(&scratch)
}

/// `output`'s stdout, when it exited `code`.
fn printed(output: std::process::Output, code: i32) -> Result<String, String> {
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.code() == Some(code) {
        Ok(text)
    } else {
        Err(format!(
            "exited {}, not {code}: {text}{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// `parse` refuses `text`, one form's output, with a line taken
/// out, repeated, cut short of its last newline, or followed by a
/// line of a key no form prints. Removing the one line of a
/// once-printed key is [`Error::Missing`] for that key, or
/// [`Error::Torn`] when no line remains, except that an `optional`
/// key's removal still parses; removing a line of a key in
/// `tallied`, whose every line the form counts, is refused however
/// many lines it has, and removing one of several lines of any other
/// key, an open list such as the listing's clusters, is left
/// unchecked, since the output still parses; repeating a line is
/// refused, and repeating
/// the line of a once-printed key is [`Error::Repeated`] for that
/// key or for the entry it names; a foreign line is
/// [`Error::Unknown`].
fn drift_refused<T>(
    text: &str,
    optional: &[&str],
    tallied: &[&str],
    parse: impl Fn(&str) -> Result<T, Error>,
) -> Result<(), String> {
    let lines: Vec<&str> = text.lines().collect();
    let key = |line: &str| {
        line.split_once(": ")
            .map_or(line, |(key, _)| key)
            .to_owned()
    };
    let edited = |at: usize, copies: usize| {
        let mut out = String::new();
        for (index, line) in lines.iter().enumerate() {
            let times = if index == at { copies } else { 1 };
            for _ in 0..times {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    };
    for (at, line) in lines.iter().enumerate() {
        let name = key(line);
        let listed = tallied.contains(&name.as_str());
        let once = !listed && lines.iter().filter(|other| key(other) == name).count() == 1;
        let removed = parse(&edited(at, 0));
        let refused = if lines.len() == 1 {
            matches!(removed, Err(Error::Torn))
        } else if listed {
            removed.is_err()
        } else if !once {
            true
        } else {
            match &removed {
                Ok(_) => optional.contains(&name.as_str()),
                Err(Error::Missing(missing)) => *missing == name,
                Err(_) => false,
            }
        };
        let repeated = match parse(&edited(at, 2)) {
            Err(Error::Repeated(twice)) if once => {
                twice == name || twice.starts_with(&format!("{name} "))
            }
            Err(_) => !once,
            Ok(_) => false,
        };
        if !refused || !repeated {
            return Err(format!(
                "the output with line {line:?} removed or repeated parsed wrongly: {text}"
            ));
        }
    }
    if !matches!(parse(&text[..text.len() - 1]), Err(Error::Torn)) {
        return Err(format!("the output cut short parsed: {text}"));
    }
    let foreign = format!("{text}foreign: line\n");
    if !matches!(parse(&foreign), Err(Error::Unknown(key)) if key == "foreign") {
        return Err(format!("the output with a foreign line parsed: {text}"));
    }
    Ok(())
}

fn class(class: catalog::Class) -> protocol::Class {
    match class {
        catalog::Class::Live => protocol::Class::Live,
        catalog::Class::Control => protocol::Class::Control,
        catalog::Class::Recovery => protocol::Class::Recovery,
        catalog::Class::History => protocol::Class::History,
    }
}

fn terminal(terminal: Terminal) -> protocol::Terminal {
    match terminal {
        Terminal::Complete {
            outcome,
            fired,
            required,
        } => protocol::Terminal::Complete {
            outcome: match outcome {
                Outcome::Pass => protocol::Outcome::Pass,
                Outcome::Violation => protocol::Outcome::Violation,
                Outcome::Inconclusive => protocol::Outcome::Inconclusive,
                Outcome::Unsuccessful => protocol::Outcome::Unsuccessful,
            },
            fired,
            required,
        },
        Terminal::Infrastructure(class) => protocol::Terminal::Infrastructure(match class {
            Infrastructure::Sink => protocol::Infrastructure::Sink,
            Infrastructure::Cap => protocol::Infrastructure::Cap,
            Infrastructure::Truncated => protocol::Infrastructure::Truncated,
            Infrastructure::Defect => protocol::Infrastructure::Defect,
        }),
    }
}

/// The verdict a summary's `ledger:` line prints for `campaign`.
fn ledger(campaign: Campaign) -> protocol::Ledger {
    match campaign {
        Campaign::Credited => protocol::Ledger::Credited,
        Campaign::Inconclusive(gap) => protocol::Ledger::Inconclusive(format!("{gap:?}")),
        Campaign::Refused(error) => protocol::Ledger::Refused(format!("{error:?}")),
        Campaign::Unrecorded => protocol::Ledger::Unrecorded,
        Campaign::Mismatched(mismatch) => protocol::Ledger::Mismatched(format!("{mismatch:?}")),
    }
}

fn child_class(class: &Classified) -> protocol::ChildClass {
    match class {
        Classified::Success(_) => protocol::ChildClass::Success,
        Classified::Failed { .. } => protocol::ChildClass::Failed,
        Classified::Mismatch { .. } => protocol::ChildClass::Mismatch,
        Classified::Signaled(_) => protocol::ChildClass::Signaled,
        Classified::Silent(_) => protocol::ChildClass::Silent,
        Classified::Malformed(_) => protocol::ChildClass::Malformed,
        Classified::Watchdog => protocol::ChildClass::Watchdog,
        Classified::Lost(_) => protocol::ChildClass::Lost,
    }
}

/// Checks that worker names from `bundle::STOPS`, [`terminal_text`], and
/// [`Classified::name`] match the parser's words for every parser variant.
fn words_agree() -> Result<(), String> {
    let mut differ = Vec::new();
    let stops = crate::net::world_tests::bundle::STOPS.map(|(_, name)| name);
    if stops != protocol::STOPS {
        differ.push(format!("stops {stops:?}, parsed {:?}", protocol::STOPS));
    }
    let complete = |outcome| Terminal::Complete {
        outcome,
        fired: 0,
        required: 0,
    };
    let terminals: Vec<Terminal> = [
        Outcome::Pass,
        Outcome::Violation,
        Outcome::Inconclusive,
        Outcome::Unsuccessful,
    ]
    .map(complete)
    .into_iter()
    .chain(
        [
            Infrastructure::Sink,
            Infrastructure::Cap,
            Infrastructure::Truncated,
            Infrastructure::Defect,
        ]
        .map(Terminal::Infrastructure),
    )
    .collect();
    let mapped: Vec<protocol::Terminal> = terminals.iter().map(|&each| terminal(each)).collect();
    let variants: Vec<protocol::Terminal> = protocol::Outcome::ALL
        .iter()
        .map(|&outcome| protocol::Terminal::Complete {
            outcome,
            fired: 0,
            required: 0,
        })
        .chain(
            protocol::Infrastructure::ALL
                .iter()
                .map(|&class| protocol::Terminal::Infrastructure(class)),
        )
        .collect();
    let printed: Vec<String> = terminals
        .iter()
        .map(|&each| {
            terminal_text(each)
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    let read: Vec<&str> = mapped
        .iter()
        .map(|each| match each {
            protocol::Terminal::Complete { outcome, .. } => outcome.name(),
            protocol::Terminal::Infrastructure(class) => class.name(),
        })
        .collect();
    if printed != read || mapped != variants {
        differ.push(format!("terminal words {printed:?}, parsed {read:?}"));
    }
    let children = [
        Classified::Success(Vec::new()),
        Classified::Failed {
            code: 1,
            payload: Vec::new(),
        },
        Classified::Mismatch {
            code: 1,
            verdict: Verdict::Success,
        },
        Classified::Signaled(libc::SIGKILL),
        Classified::Silent(0),
        Classified::Malformed(0),
        Classified::Watchdog,
        Classified::Lost(String::new()),
    ];
    let printed: Vec<&str> = children.iter().map(Classified::name).collect();
    let classes: Vec<protocol::ChildClass> = children.iter().map(child_class).collect();
    let read: Vec<&str> = classes.iter().map(|class| class.name()).collect();
    if printed != read || classes != protocol::ChildClass::ALL {
        differ.push(format!("child classes {printed:?}, parsed {read:?}"));
    }
    if differ.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the parser's words differ from the worker's: {}",
            differ.join("; ")
        ))
    }
}

/// The rule catalog a fresh process prints parses into the worker's rules,
/// each with the scope of the check that raises it, under the catalog
/// version the supervisor and worker name. `listing.capabilities` must be
/// at least `protocol::RULE_CATALOG`. `known::defects` returns an empty
/// list for `known::KNOWN` against `listing` and the parsed catalog.
fn rules(scratch: &Scratch, listing: &Listing) -> Result<(), String> {
    use crate::net::world_tests::narrate::rules;
    let text = printed(scratch.run(&["--rules".as_ref()])?, COUNTS)?;
    let parsed = protocol::Rules::parse(&text).map_err(|error| format!("{error:?}: {text}"))?;
    drift_refused(&text, &[], &[], protocol::Rules::parse)?;
    let printed: Vec<(&str, &str)> = parsed
        .rules
        .iter()
        .map(|rule| (rule.scope.name(), rule.text.as_str()))
        .collect();
    if printed != rules::scoped().collect::<Vec<_>>()
        || protocol::RULES != u64::from(rules::RULES)
        || listing.capabilities < protocol::RULE_CATALOG
    {
        return Err(format!("the rule catalog parsed as {parsed:?}"));
    }
    let defects = campaign_supervisor::campaign::known::defects(
        campaign_supervisor::campaign::known::KNOWN,
        listing,
        &parsed,
    );
    if !defects.is_empty() {
        return Err(format!("the known-findings table: {}", defects.join("; ")));
    }
    Ok(())
}

/// The capability listing a fresh process prints parses with the
/// worker's versions, bounds, milestones, cluster profiles and
/// every profile admission accepts by name, each with its class, and
/// each history with its expected ending and the failure it declares.
fn listing(scratch: &Scratch) -> Result<Listing, String> {
    let text = printed(scratch.run(&["--capabilities".as_ref()])?, COUNTS)?;
    let listing = Listing::parse(&text).map_err(|error| format!("{error:?}: {text}"))?;
    drift_refused(&text, &[], &["fails"], Listing::parse)?;
    let keys: Vec<(String, protocol::Form)> = crate::sim::manifest::KEYS
        .iter()
        .map(|&key| {
            let form = match crate::sim::manifest::form(key) {
                crate::sim::manifest::Form::Version => protocol::Form::Version(
                    u32::try_from(crate::sim::manifest::VERSION)
                        .expect("the manifest version fits in 32 bits"),
                ),
                crate::sim::manifest::Form::Text => protocol::Form::Text,
                crate::sim::manifest::Form::Digest => protocol::Form::Sha256,
                crate::sim::manifest::Form::Count { max } => protocol::Form::Count { min: 1, max },
            };
            (key.to_owned(), form)
        })
        .collect();
    let parsed_keys: Vec<(String, protocol::Form)> = listing
        .keys
        .iter()
        .map(|key| (key.name.clone(), key.form))
        .collect();
    let expected = |name: &str| {
        histories::every()
            .find(|history| history.name == name)
            .map(|history| match history.expect {
                Expect::Pass => protocol::Expected::Pass,
                Expect::Violation(..) => protocol::Expected::Violation,
                Expect::Unsuccessful(_) => protocol::Expected::Unsuccessful,
            })
    };
    // The obligation's code is its place among the obligations, from 1,
    // as a failure identity holds it.
    let fails = |name: &str| {
        let history = histories::every().find(|history| history.name == name)?;
        match history.expect {
            Expect::Pass => None,
            Expect::Violation(obligation, rule) => {
                let code = obligation as u8 + 1;
                Some(protocol::Fails::Violation(code, rule.to_owned()))
            }
            Expect::Unsuccessful(witness) => {
                Some(protocol::Fails::Unsuccessful(witness.to_owned()))
            }
        }
    };
    let declared = listing.profiles.iter().all(|profile| {
        profile.expected == expected(&profile.name) && profile.fails == fails(&profile.name)
    });
    let clusters: Vec<&str> = cluster::PROFILES.iter().map(|shape| shape.name).collect();
    let listed: Vec<&str> = listing
        .clusters
        .iter()
        .map(|declared| declared.name.as_str())
        .collect();
    let profiles = catalog::FIXED.len() + histories::every().count();
    let classed = listing
        .profiles
        .iter()
        .all(|profile| catalog::class(&profile.name).map(class) == Some(profile.class));
    if (protocol::CAPABILITIES, protocol::SUMMARY) != (catalog::CAPABILITIES, SUMMARY)
        || listing.capabilities != catalog::CAPABILITIES
        || listing.capabilities < protocol::DECLARED_FAILURES
        || (u64::from(listing.summary), u64::from(listing.manifest))
            != (u64::from(SUMMARY), crate::sim::manifest::VERSION)
        || (listing.max_suffixes, listing.max_siblings) != (MAX_SUFFIXES, MAX_SIBLINGS)
        || listing.milestones != MILESTONES
        || listed != clusters
        || listing.profiles.len() != profiles
        || !classed
        || parsed_keys != keys
        || !declared
        || protocol::COVERAGE != Reached::NAMES
        || !held_agree(&listing)
        || !family_agrees(&listing)
    {
        return Err(format!("the listing parsed as {listing:?}"));
    }
    Ok(listing)
}

/// Whether the listing's held keys and each profile's held bounds are
/// the worker's, each least count listed at 1 or more.
fn held_agree(listing: &Listing) -> bool {
    let bounds = |name: &str| {
        held_by(name).map(|held| {
            held.iter()
                .map(|(key, least)| ((*key).to_owned(), (*least).max(1)))
                .collect::<Vec<_>>()
        })
    };
    listing.held == HELD
        && listing
            .profiles
            .iter()
            .all(|profile| bounds(&profile.name).as_ref() == Some(&profile.held))
        && bounds("settled").as_ref() == Some(&listing.family.held)
}

/// Whether the listing's family names the worker's settled words and
/// admits exactly the names the worker's catalog admits, among them each
/// word alone, two words in either order, a repeated word, an unknown
/// word and the bare prefix.
fn family_agrees(listing: &Listing) -> bool {
    let words = &catalog::SETTLED;
    let mut names: Vec<String> = words.iter().map(|word| format!("settled-{word}")).collect();
    names.extend([
        format!("settled-{}-{}", words[0], words[1]),
        format!("settled-{}-{}", words[1], words[0]),
        format!("settled-{0}-{0}", words[0]),
        "settled-unheard".to_owned(),
        "settled-".to_owned(),
        "settled".to_owned(),
    ]);
    listing.family.words == words
        && names
            .iter()
            .all(|name| listing.admits(name) == catalog::listed(name))
}

/// `text`, the summary of `loaded`, parses under `listing` with the
/// values the worker derives from the bundle.
fn summarized(text: &str, loaded: &Loaded, listing: &Listing) -> Result<Summary, String> {
    let parsed = Summary::parse(text, listing).map_err(|error| format!("{error:?}: {text}"))?;
    drift_refused(text, &OPTIONAL, &[], |text| Summary::parse(text, listing))?;
    let work = loaded.work;
    let recorded = loaded.terminal != Terminal::Infrastructure(Infrastructure::Truncated);
    let value = |value: u64| recorded.then_some(value);
    let recovery = recovery_census(loaded).map(|(counts, rows)| {
        let [planned, reached, activated, recovered, checked, skipped] = counts.map(|n| n as u64);
        protocol::Recovery {
            stages: protocol::Stages {
                planned,
                reached,
                activated,
                recovered,
                checked,
                skipped,
            },
            limits: LIMITS.into(),
            windows: rows
                .into_iter()
                .map(|row| {
                    let count = match row.status {
                        Status::Covered | Status::Gap => Some(row.count as u64),
                        Status::NotRequired | Status::Undecided | Status::Unreached => None,
                    };
                    (row.name, count)
                })
                .collect(),
        }
    });
    let agrees = parsed.digest.bytes() == &loaded.digest
        && parsed.terminal == terminal(loaded.terminal)
        && parsed.counts == counts(loaded)
        && (parsed.decisions, parsed.turns, parsed.progress)
            == (
                value(work.decisions),
                value(work.turns),
                value(work.progress),
            )
        && (parsed.virtual_us, parsed.skipped_us)
            == (value(work.virtual_us), value(work.skipped_us))
        && parsed
            .identity
            .as_ref()
            .map(|identity| identity.as_str().to_owned())
            == violated(loaded).map(|identity| hex(identity.bytes()))
        && parsed
            .unsuccessful
            .as_ref()
            .map(|rule| rule.as_str().to_owned())
            == unsuccessful_rule(loaded)
        && parsed.ledger == campaign(loaded).map(ledger)
        && parsed.recovery == recovery;
    if agrees
        && observed_agree(&parsed, loaded)
        && protocol::ReplayResult::Reproduced(claimed(loaded)).agrees(&parsed)
    {
        Ok(parsed)
    } else {
        Err(format!("the summary parsed as {parsed:?}: {text}"))
    }
}

/// Whether `parsed`'s profile, declared limits, stop, observed
/// counts, cause and cluster lines hold the values the worker
/// derives from `loaded`'s recorded manifest and events.
fn observed_agree(parsed: &Summary, loaded: &Loaded) -> bool {
    let declared = crate::net::world_tests::replay::manifest_of(loaded).ok();
    let seen = observed(&loaded.events);
    let profile = declared
        .as_ref()
        .map(|manifest| manifest.profile.as_str())
        .filter(|profile| catalog::listed(profile));
    let limit = |key: &str| declared.as_ref().map(|manifest| manifest.count(key));
    let composed = seen.composed;
    let scripted = profile.and_then(catalog::class) == Some(catalog::Class::History);
    let acted = |value: u64| composed.filter(|_| !scripted).map(|_| value);
    let drawn = composed.and(seen.coverage).map(|(topology, coverage)| {
        let cluster::Topology { owners, keys, hot } = topology;
        let topology = protocol::Topology {
            owners: owners.into(),
            keys: keys.into(),
            hot: hot.into(),
        };
        (topology, coverage)
    });
    let cluster = profile
        .filter(|profile| cluster::shape(profile).is_some())
        .map(|_| (drawn, cluster::UNAVAILABLE.to_owned()));
    let printed = parsed.cluster.as_ref().map(|lines| {
        let drawn = lines
            .drawn
            .as_ref()
            .map(|drawn| (drawn.topology, drawn.coverage));
        (drawn, lines.unavailable.clone())
    });
    parsed.profile.as_deref() == profile
        && (
            parsed.declared_turns,
            parsed.declared_same_time,
            parsed.declared_no_progress,
        ) == (limit("turns"), limit("same_time"), limit("no_progress"))
        && parsed.stop.as_deref() == seen.stop.map(|_| seen.stop_text())
        && parsed.boundaries_checked == composed.map(|composed| composed.checked)
        && (parsed.operations, parsed.witnesses) == (acted(seen.operations), acted(seen.witnesses))
        && parsed.faults_delivered == composed.map(|_| seen.faults)
        && (parsed.owners, parsed.clients)
            == (
                composed.map(|composed| u64::from(composed.owners)),
                composed.map(|composed| u64::from(composed.clients)),
            )
        && parsed.cause == (!counts(loaded)).then(|| cause(loaded, campaign(loaded), &seen))
        && printed == cluster
}

/// The run form's output for a counting, a capped and a panicking
/// upload run, and the inspection of each bundle. A panicked run
/// prints only its run line, which parses as the panic it names and
/// supplies no summary; its bundle inspects as truncated.
fn runs(scratch: &Scratch, listing: &Listing) -> Result<(), String> {
    let executable = own_digest()?;
    let upload = upload_manifest(&executable);
    for (name, text, code) in [
        ("counting", upload.clone(), COUNTS),
        (
            "capped",
            upload.replace("records = 1000000", "records = 200"),
            INCOMPLETE,
        ),
        (
            "panicking",
            upload.replace("profile = upload", "profile = panicking"),
            INCOMPLETE,
        ),
    ] {
        let manifest = scratch.dir.join(format!("{name}.manifest"));
        let bundle = scratch.dir.join(format!("{name}.bundle"));
        std::fs::write(&manifest, &text).map_err(|error| error.to_string())?;
        let ran = printed(
            scratch.run(&[
                "--manifest".as_ref(),
                manifest.as_os_str(),
                "--bundle".as_ref(),
                bundle.as_os_str(),
            ])?,
            code,
        )?;
        let parsed = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let loaded =
            reload(&parsed, &bundle.to_string_lossy()).map_err(|unloaded| unloaded.reason(name))?;
        let inspected = printed(
            scratch.run(&[
                "--inspect".as_ref(),
                bundle.as_os_str(),
                "--manifest".as_ref(),
                manifest.as_os_str(),
            ])?,
            0,
        )?;
        let summary = summarized(&inspected, &loaded, listing)?;
        match Run::parse(&ran, listing) {
            Ok(Run::Panicked(panic)) if name == "panicking" => {
                let line = ran.trim_end_matches('\n');
                let doubled = format!("{ran}{ran}");
                if Some(panic.as_str()) != line.strip_prefix("run: the run panicked at ")
                    || summary.terminal
                        != terminal(Terminal::Infrastructure(Infrastructure::Truncated))
                    || Run::parse(&doubled, listing).is_ok()
                    || Run::parse(line, listing) != Err(Error::Torn)
                {
                    return Err(format!("the panicked run parsed as {panic:?}: {ran}"));
                }
            }
            Ok(Run::Summary(run)) if name != "panicking" && *run == summary => {}
            other => return Err(format!("the {name} run parsed as {other:?}: {ran}")),
        }
    }
    Ok(())
}

/// The summary of every listed profile's bundle, recorded in this
/// process, and of a cluster bundle without its stop event, which
/// prints its topology and coverage unavailable. The run of each history
/// that expects no pass, under the sample manifest's root, ends in the
/// failure its `fails` line declares: a complete violation whose
/// identity holds the listed obligation code and the rule's digest, or a
/// complete unsuccessful ending that prints the whole witness, which is
/// shorter than 41 bytes.
fn profiles(listing: &Listing) -> Result<(), String> {
    let executable = own_digest()?;
    let (mut identities, mut rules, mut withheld) = (0, 0, 0);
    let (mut declared_violations, mut declared_witnesses) = (0, 0);
    for profile in &listing.profiles {
        // A profile whose run panics prints only its run line, which
        // the run form's check parses.
        if matches!(profile.name.as_str(), "panicking" | "asserting") {
            continue;
        }
        let text = crate::sim::manifest_tests::sample(&profile.name, &executable, &platform());
        let manifest = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let admitted =
            admit(&manifest).map_err(|refusal| format!("{}: {refusal:?}", profile.name))?;
        let closed = traced(admitted, Vec::new());
        let mut loaded = load(&closed.sink, manifest.capacity().records())
            .map_err(|error| format!("{}: {error:?}", profile.name))?;
        let parsed = summarized(&summary(&loaded), &loaded, listing)?;
        if parsed.profile.as_deref() != Some(profile.name.as_str())
            || parsed.cluster.is_some() != listing.cluster(&profile.name).is_some()
            || (parsed.ledger.is_some() != (profile.class == protocol::Class::Recovery))
        {
            return Err(format!("{} summarized as {parsed:?}", profile.name));
        }
        match &profile.fails {
            Some(protocol::Fails::Violation(code, rule)) => {
                declared_violations += 1;
                let identity = parsed.identity.as_ref().map(|id| id.as_str());
                let digest = hex(&Sha256::digest(rule.as_bytes()));
                if !matches!(
                    parsed.terminal,
                    protocol::Terminal::Complete {
                        outcome: protocol::Outcome::Violation,
                        ..
                    }
                ) || identity.is_none_or(|id| {
                    id.get(4..6) != Some(format!("{code:02x}").as_str())
                        || id.get(14..78) != Some(digest.as_str())
                }) {
                    return Err(format!(
                        "{} missed its declared violation: {parsed:?}",
                        profile.name
                    ));
                }
            }
            Some(protocol::Fails::Unsuccessful(witness)) => {
                declared_witnesses += 1;
                // A sweep credits a witness shorter than the 41 bytes a
                // summary prints, matched whole.
                if !matches!(
                    parsed.terminal,
                    protocol::Terminal::Complete {
                        outcome: protocol::Outcome::Unsuccessful,
                        ..
                    }
                ) || witness.len() >= 41
                    || parsed.unsuccessful.as_ref().map(|text| text.as_str())
                        != Some(witness.as_str())
                {
                    return Err(format!(
                        "{} missed its declared witness: {parsed:?}",
                        profile.name
                    ));
                }
            }
            None => {}
        }
        identities += usize::from(parsed.identity.is_some());
        rules += usize::from(parsed.unsuccessful.is_some());
        withheld += usize::from(
            parsed
                .ledger
                .as_ref()
                .is_some_and(|ledger| *ledger != protocol::Ledger::Credited),
        );
        if profile.name == "cluster-broad" {
            loaded.events.retain(|event| event.kind != STOP);
            let stopless = summarized(&summary(&loaded), &loaded, listing)?;
            if stopless
                .cluster
                .as_ref()
                .is_none_or(|cluster| cluster.drawn.is_some())
                || stopless.stop.is_some()
            {
                return Err(format!("the stopless bundle summarized as {stopless:?}"));
            }
        }
    }
    // Both kinds of declared failure must have been compared with a run,
    // or the comparison above holds vacuously.
    if declared_violations == 0 || declared_witnesses == 0 {
        return Err("the summaries exercised neither or only one declared failure kind".into());
    }
    // Each optional or withholding line must have reached the
    // parser, or its check above holds vacuously.
    if identities == 0 || rules == 0 || withheld == 0 {
        return Err(format!(
            "the summaries named {identities} identities, {rules} unsuccessful rules and {withheld} withholding ledgers"
        ));
    }
    Ok(())
}

/// A branch of two suffixes of two siblings of a faulted bundle at
/// its pending put parses with every child, and the witness's
/// values print back as its line; a bundle whose replay diverges
/// before that milestone parses as no fork. Returns the faulted
/// bundle's manifest, path and branch.
fn branches(scratch: &Scratch) -> Result<Faulted, String> {
    // A child watchdog well inside the lane step's deadline, so a
    // hung child fails this case before the step times out.
    let text = crate::sim::manifest_tests::sample("faulted", &own_digest()?, &platform())
        .replace("watchdog = 600\n", "watchdog = 60\n");
    if !text.contains("watchdog = 60\n") {
        return Err(format!("the faulted manifest names no watchdog: {text}"));
    }
    let manifest = scratch.dir.join("faulted.manifest");
    let bundle = scratch.dir.join("faulted.bundle");
    std::fs::write(&manifest, &text).map_err(|error| error.to_string())?;
    printed(
        scratch.run(&[
            "--manifest".as_ref(),
            manifest.as_os_str(),
            "--bundle".as_ref(),
            bundle.as_os_str(),
        ])?,
        COUNTS,
    )?;
    let branched = printed(
        scratch.run(&[
            "--branch".as_ref(),
            bundle.as_os_str(),
            "--milestone".as_ref(),
            "pending-put".as_ref(),
            "--suffixes".as_ref(),
            "2".as_ref(),
            "--siblings".as_ref(),
            "2".as_ref(),
            "--output".as_ref(),
            scratch.dir.join("branch").as_os_str(),
        ])?,
        COUNTS,
    )?;
    let branch = Branch::parse(&branched)
        .map_err(|error| format!("{error:?}: {branched}"))?
        .ok_or_else(|| format!("the branch parsed as diverged: {branched}"))?;
    drift_refused(&branched, &[], &["child", "problem"], Branch::parse)?;
    let pairs: Vec<(u64, u64)> = branch
        .children
        .iter()
        .map(|child| (child.suffix, child.sibling))
        .collect();
    let credited = branch.children.iter().all(|child| {
        child.class == protocol::ChildClass::Success
            && child
                .report
                .as_ref()
                .is_some_and(|(_, terminal)| terminal.passes())
    });
    let witness = &branch.witness;
    let upload = witness.upload.map_or_else(
        || "none".to_owned(),
        |protocol::Upload {
             attempt,
             grant,
             held,
             outcome,
         }| { format!("attempt:{attempt},grant:{grant},held:{held},outcome:{outcome}") },
    );
    let line = format!(
        "witness: {} holds={} boundary={} upload={upload} armed={}\n",
        witness.milestone, witness.holds, witness.boundary, witness.armed
    );
    if pairs != [(0, 0), (0, 1), (1, 0), (1, 1)]
        || !credited
        || !branch.reproduced
        || !branch.problems.is_empty()
        || branch.milestone.name != "pending-put"
        || !witness.holds
        || !branched.contains(&line)
    {
        return Err(format!("the branch parsed as {branch:?}: {branched}"));
    }
    let manifest = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
    for child in &branch.children {
        let path = scratch
            .dir
            .join("branch")
            .join(format!("suffix-{}-{}.bundle", child.suffix, child.sibling));
        let (digest, ended, _) = bundled(&manifest, &path)?;
        if child.report != Some((digest, ended)) {
            return Err(format!("child {child:?} reports other than its bundle"));
        }
    }
    let recorded = std::fs::read(&bundle).map_err(|error| error.to_string())?;
    let diverging = scratch.dir.join("diverging.bundle");
    std::fs::write(&diverging, diverging_before(&recorded, "pending-put"))
        .map_err(|error| error.to_string())?;
    for (form, extra) in [("--branch", &["--suffixes", "1"][..]), ("--explore", &[])] {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            form.as_ref(),
            diverging.as_os_str(),
            "--milestone".as_ref(),
            "pending-put".as_ref(),
        ];
        args.extend(extra.iter().map(std::ffi::OsStr::new));
        let output = scratch.dir.join(format!("diverged{form}"));
        args.extend(["--output".as_ref(), output.as_os_str()]);
        let diverged = printed(scratch.run(&args)?, COMPLETE)?;
        drift_refused(&diverged, &[], &[], Branch::parse)?;
        drift_refused(&diverged, &[], &[], Explore::parse)?;
        if Branch::parse(&diverged) != Ok(None) || Explore::parse(&diverged) != Ok(None) {
            return Err(format!("the diverged {form} parsed as a fork: {diverged}"));
        }
    }
    Ok(Faulted {
        text,
        bundle,
        branch,
    })
}

/// The digest, terminal and credit of the bundle at `path`, loaded under
/// `manifest`'s record maximum.
fn bundled(
    manifest: &Manifest,
    path: &std::path::Path,
) -> Result<
    (
        campaign_supervisor::record::Digest,
        protocol::Terminal,
        bool,
    ),
    String,
> {
    let name = path.to_string_lossy();
    let loaded = reload(manifest, &name).map_err(|unloaded| unloaded.reason(&name))?;
    let digest = campaign_supervisor::record::Digest::parse(&hex(&loaded.digest))
        .ok_or("a digest of no 64 digits")?;
    Ok((digest, terminal(loaded.terminal), counts(&loaded)))
}

/// The faulted bundle's manifest text and path, and its branch.
struct Faulted {
    text: String,
    bundle: std::path::PathBuf,
    branch: Branch,
}

/// An exploration of the faulted bundle at its pending put parses
/// with every node and leaf, the manifest's limits, and the
/// branch's milestone and witness.
fn explorations(
    scratch: &Scratch,
    Faulted {
        text,
        bundle,
        branch,
    }: &Faulted,
) -> Result<(), String> {
    let explored = printed(
        scratch.run(&[
            "--explore".as_ref(),
            bundle.as_os_str(),
            "--milestone".as_ref(),
            "pending-put".as_ref(),
            "--output".as_ref(),
            scratch.dir.join("explore").as_os_str(),
        ])?,
        COUNTS,
    )?;
    let explore = Explore::parse(&explored)
        .map_err(|error| format!("{error:?}: {explored}"))?
        .ok_or_else(|| format!("the exploration parsed as diverged: {explored}"))?;
    drift_refused(&explored, &[], &["node", "leaf", "problem"], Explore::parse)?;
    let declared = Manifest::parse(text).map_err(|error| format!("{error:?}"))?;
    for leaf in &explore.leaves {
        let path = scratch
            .dir
            .join("explore")
            .join(format!("leaf-{}.bundle", leaf.path));
        if bundled(&declared, &path)? != (leaf.digest, leaf.verdict, leaf.counts) {
            return Err(format!("leaf {leaf:?} reports other than its bundle"));
        }
    }
    let limits = protocol::Limits {
        depth: declared.count("suffix_depth"),
        children: declared.count("suffix_children"),
        faults: declared.count("suffix_faults"),
        advances: declared.count("suffix_advances"),
    };
    if explore.limits != limits
        || explore.milestone != branch.milestone
        || explore.witness != branch.witness
        || explore.nodes.is_empty()
        || explore
            .leaves
            .iter()
            .any(|leaf| !leaf.counts || !leaf.verdict.passes())
        || !explore.problems.is_empty()
    {
        return Err(format!("the exploration parsed as {explore:?}: {explored}"));
    }
    Ok(())
}

/// Branches of the histories c4 and h5-put, and explorations of c4, at
/// turn and script milestones whose prefixes hold no `UPLOAD` state, parse
/// with the instance as the milestone's and witness's name, the boundary
/// the fork used, `upload=none` and a holding witness, and each refuses
/// its drifted output.
fn milestone_instances(scratch: &Scratch) -> Result<(), String> {
    let executable = own_digest()?;
    for profile in ["c4", "h5-put"] {
        let text = crate::sim::manifest_tests::sample(profile, &executable, &platform())
            .replace("watchdog = 600\n", "watchdog = 60\n");
        if !text.contains("watchdog = 60\n") {
            return Err(format!("the {profile} manifest names no watchdog: {text}"));
        }
        printed(scratch.record(profile, &text)?, COUNTS)?;
    }
    let forked = |form: (&str, &str, &str), extra: &[&str]| {
        let output = format!("{}-{}-{}", form.0, form.1, form.2);
        printed(scratch.at_milestone(form, extra, &output)?, COUNTS)
    };
    let parsed = |name: &str, milestone: &protocol::Milestone, witness: &protocol::Witness| {
        (milestone.name.as_str(), milestone.boundary) == (name, 2)
            && (witness.milestone.as_str(), witness.holds, witness.boundary) == (name, true, 2)
            && (witness.upload, witness.armed) == (None, false)
    };
    for (profile, name) in [("c4", "turn-1"), ("h5-put", "script-3")] {
        let branched = forked(("--branch", profile, name), &["--suffixes", "1"])?;
        let branch = Branch::parse(&branched)
            .map_err(|error| format!("{error:?}: {branched}"))?
            .ok_or_else(|| format!("the branch parsed as diverged: {branched}"))?;
        drift_refused(&branched, &[], &["child", "problem"], Branch::parse)?;
        let clean = branch.reproduced && branch.problems.is_empty();
        if !parsed(name, &branch.milestone, &branch.witness) || !clean {
            return Err(format!("the branch parsed as {branch:?}: {branched}"));
        }
    }
    for (profile, name) in [("c4", "turn-1"), ("c4", "script-5")] {
        let explored = forked(("--explore", profile, name), &[])?;
        let explore = Explore::parse(&explored)
            .map_err(|error| format!("{error:?}: {explored}"))?
            .ok_or_else(|| format!("the exploration parsed as diverged: {explored}"))?;
        drift_refused(&explored, &[], &["node", "leaf", "problem"], Explore::parse)?;
        if !parsed(name, &explore.milestone, &explore.witness) || !explore.problems.is_empty() {
            return Err(format!("the exploration parsed as {explore:?}: {explored}"));
        }
    }
    Ok(())
}

/// A broad cluster session parses with its index's window count and
/// chain and the end line its directory holds; its replay parses as
/// reproduced to that chain and, after its end changes, as an end
/// that differs. The replay verdicts for a changed turn, a changed
/// record of another tag and a missing window parse with the
/// window, record, tag, virtual time and candidate the chunks hold.
fn sessions(scratch: &Scratch) -> Result<(), String> {
    let manifest = scratch.dir.join("broad.manifest");
    let text = crate::sim::manifest_tests::sample("cluster-broad", &own_digest()?, &platform())
        .replace("actors = 32", "actors = 64")
        .replace("same_time = 400", "same_time = 4000")
        .replace("no_progress = 5000", "no_progress = 50000");
    std::fs::write(&manifest, &text).map_err(|error| error.to_string())?;
    let original = scratch.dir.join("session");
    let ran = printed(
        scratch.run(&[
            "--session".as_ref(),
            manifest.as_os_str(),
            "--output".as_ref(),
            original.as_os_str(),
        ])?,
        COUNTS,
    )?;
    let parsed = Session::parse(&ran).map_err(|error| format!("{error:?}: {ran}"))?;
    drift_refused(&ran, &[], &[], Session::parse)?;
    let (lines, chain) = session::committed(&original)?;
    let end = session::ended(&original, lines.len(), &chain)?;
    for (at, line) in lines.iter().enumerate() {
        let window = protocol::WindowLine::parse(line).map_err(|error| error.to_string())?;
        let chunk = session::chunk(&original, at, line)?;
        let printed_chain = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("chain="))
            .ok_or("a chain field")?;
        if window.index as usize != at
            || window.digest.bytes() != &session::origin(&chunk)
            || window.chain.to_string() != printed_chain
        {
            return Err("the stored window parser changes the index or digest".into());
        }
    }
    let closing =
        protocol::SessionEnd::parse(&format!("{end}\n")).map_err(|error| error.to_string())?;
    let tail =
        std::fs::read(original.join("windows/tail.chunk")).map_err(|error| error.to_string())?;
    if closing.tail.bytes() != &session::origin(&tail)
        || closing.windows != lines.len() as u64
        || closing.chain.bytes() != &chain
        || closing.end != protocol::SessionEnding::Ended(parsed.end.clone())
    {
        return Err("the stored end parser changes the window count, chain or end facts".into());
    }
    let panic = "src/world.rs:1:2: planted panic windows=99 apply_ms=000000000001";
    let panic_line = session_panic_end(panic);
    let stored_panic = format!(
        "{panic_line} windows={} chain={} tail={}\n",
        lines.len(),
        hex(&chain),
        hex(&session::origin(&tail))
    );
    let parsed_panic =
        protocol::SessionEnd::parse(&stored_panic).map_err(|error| error.to_string())?;
    if parsed_panic.end != protocol::SessionEnding::Panicked(panic.into())
        || parsed_panic.windows != lines.len() as u64
        || parsed_panic.chain.bytes() != &chain
        || parsed_panic.tail.bytes() != &session::origin(&tail)
    {
        return Err("the stored panic end parser changes the identity or footer".into());
    }
    // The stored end line is the stdout end line with the windows,
    // chain and tail fields appended.
    let stored = end.split(" windows=").next().unwrap_or_default();
    let printed_end = ran.lines().find(|line| line.starts_with("end: "));
    // Each count the stored end line names, read by field name
    // from its text, so a parse that swapped two counts differs.
    let named = |name: &str| {
        end.split(' ')
            .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
            .and_then(|value| value.parse::<u64>().ok())
    };
    let read = [
        "turns",
        "virtual_us",
        "skipped_us",
        "rested_us",
        "apply_ms",
        "carried",
        "registry",
        "outstanding",
        "kept",
        "window_bytes",
    ]
    .map(named);
    let ended = &parsed.end;
    let values = [
        ended.turns,
        ended.virtual_us,
        ended.skipped_us,
        ended.rested_us,
        ended.apply_ms,
        ended.carried,
        ended.registry,
        ended.outstanding,
        ended.kept,
        ended.window_bytes,
    ]
    .map(Some);
    if parsed.windows != lines.len() as u64
        || parsed.chain.bytes() != &chain
        || printed_end != Some(stored)
        || read != values
    {
        return Err(format!("the session parsed as {parsed:?}: {ran}"));
    }
    let replay = |name: &str, code: i32| {
        let output = scratch.run(&[
            "--replay-session".as_ref(),
            original.as_os_str(),
            "--output".as_ref(),
            scratch.dir.join(name).as_os_str(),
        ])?;
        let verdict = printed(output, code)?;
        drift_refused(&verdict, &[], &[], protocol::SessionReplay::parse)?;
        protocol::SessionReplay::parse(&verdict).map_err(|error| format!("{error:?}: {verdict}"))
    };
    let reproduced = protocol::SessionReplay::Reproduced {
        windows: parsed.windows,
        chain: parsed.chain,
    };
    if replay("again", REPRODUCED)? != reproduced {
        return Err("the replay parsed as another verdict".to_owned());
    }
    let end_path = original.join("end");
    let saved = std::fs::read_to_string(&end_path).map_err(|error| error.to_string())?;
    std::fs::write(&end_path, saved.replacen(" turns=", " turns=1", 1))
        .map_err(|error| error.to_string())?;
    let changed = replay("changed-end", DIVERGED)?;
    std::fs::write(&end_path, &saved).map_err(|error| error.to_string())?;
    if changed != protocol::SessionReplay::Diverged(Divergence::End) {
        return Err(format!("a changed end parsed as {changed:?}"));
    }
    divergences(scratch, &original, &lines, &end)
}

/// The replay verdicts [`replay_verdict`] prints against a copy of
/// window 0 with one byte changed in its first turn record or in
/// its first record, a record of another tag, and against the
/// original's windows less the last.
fn divergences(
    scratch: &Scratch,
    original: &std::path::Path,
    lines: &[String],
    end: &str,
) -> Result<(), String> {
    let chunk = session::chunk(original, 0, &lines[0])?;
    // The last byte of each record's body, as an offset into the
    // chunk; a record without a body has none to change.
    let last: Vec<(u8, Option<usize>)> = session::records(&chunk)
        .into_iter()
        .map(|(tag, body)| {
            let offset = |byte: &u8| std::ptr::from_ref(byte).addr() - chunk.as_ptr().addr();
            (tag, body.last().map(offset))
        })
        .collect();
    let turn = last
        .iter()
        .position(|(tag, byte)| *tag == session::TURN && byte.is_some())
        .ok_or("window 0 holds no turn record")?;
    for record in [turn, 0] {
        let at = last[record]
            .1
            .ok_or("window 0's first record has no body")?;
        let mut changed = chunk.clone();
        changed[at] ^= 1;
        let copy = scratch.dir.join(format!("record-{record}"));
        std::fs::create_dir_all(copy.join("windows")).map_err(|error| error.to_string())?;
        std::fs::write(copy.join("windows").join("000000.chunk"), &changed)
            .map_err(|error| error.to_string())?;
        let ours = format!(
            "digest={}",
            hex(&<sha2::Sha256 as sha2::Digest>::digest(&chunk))
        );
        let theirs = format!(
            "digest={}",
            hex(&<sha2::Sha256 as sha2::Digest>::digest(&changed))
        );
        let mut replayed = lines.to_vec();
        replayed[0] = replayed[0].replacen(&ours, &theirs, 1);
        let found = session::divergence(&chunk, &changed).ok_or("the chunks match")?;
        let parsed = verdict((original, lines, end), (&copy, &replayed, end))?;
        let at = found.record as u64;
        let agrees = match (&parsed, found.turn) {
            (
                Divergence::Turn {
                    window: 0,
                    record,
                    virtual_us,
                    candidate,
                },
                Some((now, drawn)),
            ) => *record == at && *virtual_us == now && candidate.as_str() == hex(&drawn),
            (
                Divergence::Record {
                    window: 0,
                    record,
                    tag,
                },
                None,
            ) => *record == at && *tag == found.tag,
            _ => false,
        };
        if !agrees || (record == turn) != matches!(parsed, Divergence::Turn { .. }) {
            return Err(format!(
                "record {record} diverged as {parsed:?}, found {found:?}"
            ));
        }
    }
    let count = lines.len() as u64;
    let expected = Divergence::Windows {
        at: count - 1,
        committed: count,
        replayed: count - 1,
    };
    let parsed = verdict(
        (original, lines, end),
        (original, &lines[..lines.len() - 1], end),
    )?;
    if parsed == expected {
        Ok(())
    } else {
        Err(format!(
            "a missing window diverged as {parsed:?}, not {expected:?}"
        ))
    }
}

/// The divergence the line [`replay_verdict`] prints for `ours`
/// against `theirs` parses as.
fn verdict(
    ours: (&std::path::Path, &[String], &str),
    theirs: (&std::path::Path, &[String], &str),
) -> Result<Divergence, String> {
    let SessionReplay::Diverged(line) = replay_verdict(ours, theirs) else {
        return Err("the replay names no divergence".to_owned());
    };
    let line = format!("{line}\n");
    drift_refused(&line, &[], &[], protocol::SessionReplay::parse)?;
    match protocol::SessionReplay::parse(&line) {
        Ok(protocol::SessionReplay::Diverged(found)) => Ok(found),
        other => Err(format!("{line:?} parsed as {other:?}")),
    }
}

/// The worker's replay and reduction renderers feed every verdict variant
/// through the protocol parser with its complete claim and qualification.
fn bundle_verdicts(scratch: &Scratch) -> Result<(), String> {
    let bytes =
        std::fs::read(scratch.dir.join("counting.bundle")).map_err(|error| error.to_string())?;
    for (verdict, expected, code) in [
        (
            Replayed::Reproduced,
            protocol::ReplayResult::Reproduced(claim(&bytes)),
            REPRODUCED,
        ),
        (
            Replayed::Diverged {
                at: Some(9),
                reason: "Identity".into(),
            },
            protocol::ReplayResult::Diverged {
                at: Some(9),
                reason: "Identity".into(),
            },
            DIVERGED,
        ),
        (
            Replayed::Diverged {
                at: None,
                reason: "Trailing".into(),
            },
            protocol::ReplayResult::Diverged {
                at: None,
                reason: "Trailing".into(),
            },
            DIVERGED,
        ),
    ] {
        let (line, exit) = replay_line(verdict, &bytes);
        drift_refused(&line, &[], &[], protocol::ReplayResult::parse)?;
        if exit != code || protocol::ReplayResult::parse(&line) != Ok(expected) {
            return Err(format!("the replay verdict differs: {line}"));
        }
    }
    let panic = "src/x.rs:1:2: x, y";
    let line = panic_replay_line(panic.into());
    drift_refused(&line, &[], &[], protocol::ReplayResult::parse)?;
    if protocol::ReplayResult::parse(&line) != Ok(protocol::ReplayResult::Panicked(panic.into())) {
        return Err(format!("the panic verdict differs: {line}"));
    }
    let manifest = Manifest::parse(&crate::sim::manifest_tests::sample(
        "corrupted",
        &own_digest()?,
        &platform(),
    ))
    .map_err(|error| format!("{error:?}"))?;
    let event = crate::sim::trace::Event {
        kind: crate::net::world_tests::bundle::IDENTITY,
        payload: [0; crate::sim::trace::PAYLOAD],
    };
    let violation = Identity::Violation(
        crate::net::world_tests::replay::FailureIdentity::of(&event)
            .ok_or("an identity event carries an identity")?,
    );
    for bounded in [false, true] {
        for identity in [Identity::Panic(panic.into()), violation.clone()] {
            let reduced = Reduced {
                manifest: manifest.clone(),
                bundle: vec![0; 3 * RECORD],
                steps: Vec::new(),
                scenario: String::new(),
                identity: identity.clone(),
                conditions: Vec::new(),
                stop: if bounded {
                    Stop::Bounded
                } else {
                    Stop::Exhausted
                },
            };
            let (_, line) = stop_lines(&reduced);
            let line = line.map_err(str::to_owned)?;
            drift_refused(&line, &[], &[], protocol::ReduceResult::parse)?;
            let expected = protocol::ReduceResult {
                records: 3,
                scenario: manifest.scenario.to_string(),
                bounded,
                panic: match identity {
                    Identity::Panic(panic) => Some(panic),
                    Identity::Violation(_) => None,
                },
            };
            if protocol::ReduceResult::parse(&line) != Ok(expected) {
                return Err(format!("the reduction verdict differs: {line}"));
            }
        }
    }
    Ok(())
}

/// A failed index sync rolls back the appended line before the launcher reads
/// the incomplete source, so its artifact retains only the prior window.
fn a_failed_index_sync_publishes_only_the_committed_prefix(
    scratch: &Scratch,
) -> Result<(), String> {
    use crate::sim::turn::Hook;
    use campaign_supervisor::archive::{Built, publish};
    use campaign_supervisor::record::{Artifact, Digest, Native, Provenance, Text};
    use campaign_supervisor::sim::{Input, Options, sim};
    use campaign_supervisor::store::{Name, View, open_host};
    let text = |value: &str| Text::new(value).expect("ASCII fixture text");
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let identity = open_host(&executable)
        .map_err(|error| format!("{error:?}"))?
        .identity();
    let digest = Digest::of(b"session sync fixture");
    let built = Built {
        executable,
        identity,
        lock: b"version = 4\n".to_vec(),
        provenance: Provenance {
            cargo: text("cargo 1.0.0 (fixture)"),
            command: text("test --test sim_worker"),
            dirty: false,
            environment: std::collections::BTreeMap::new(),
            native: Native {
                install_record: text("none"),
                install_record_sha256: digest,
                link_plan_sha256: digest,
                package: text("none"),
            },
            revision: text(&"0".repeat(40)),
            target: text("x86_64-unknown-linux-gnu"),
            toolchain: text("rustc 1.0.0 (fixture)"),
            untracked: 0,
        },
    };
    let archive =
        publish(&scratch.dir.join("sync-archive"), &built).map_err(|error| error.to_string())?;
    let pins = archive.pins();
    let manifest = format!(
        "build = {}\nexecutable = {}\nplatform = {}\ntoolchain = {}\nrecords = 100\nbytes = 48000\n",
        pins.build.as_str(),
        pins.executable.as_str(),
        pins.platform.as_str(),
        pins.toolchain.as_str()
    );
    let source = scratch.dir.join("sync-source");
    std::fs::create_dir(&source).map_err(|error| error.to_string())?;
    let mut writer = session::Writer::new(
        &source,
        &manifest,
        session::Budget {
            records: 100,
            bytes: 48000,
        },
    )
    .map_err(|error| error.to_string())?;
    let mut event = [0; crate::sim::trace::PAYLOAD];
    event[crate::net::world_tests::cluster::WINDOW_VERDICT] = 1;
    writer.begin(b"record", b"");
    writer.commit_with_sync(event, std::fs::File::sync_all);
    let committed = std::fs::read(source.join("index")).map_err(|error| error.to_string())?;
    writer.end(b"choices");
    let mut calls = 0;
    writer.commit_with_sync(event, |file| {
        calls += 1;
        if calls == 1 {
            assert!(file.metadata()?.len() > committed.len() as u64);
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        } else {
            assert_eq!(file.metadata()?.len(), committed.len() as u64);
            file.sync_all()
        }
    });
    assert_eq!(calls, 2);
    assert_eq!(writer.committed(), 1);
    assert!(writer.failed().unwrap().starts_with("window 1: "));
    assert_eq!(
        std::fs::read(source.join("index")).map_err(|error| error.to_string())?,
        committed
    );
    let ended = sim(
        &Input::ReplaySession {
            archive: archive.path().to_owned(),
            source,
            output: None,
        },
        &Options {
            artifacts: scratch.dir.join("sync-artifacts"),
            run_id: Some("failed-sync".into()),
            watchdog: None,
        },
    );
    assert_eq!(
        ended.class,
        campaign_supervisor::exit::Sim::Rejected,
        "{}",
        ended.reason
    );
    let view = View::open(ended.artifact.as_ref().expect("a published artifact"))
        .map_err(|error| error.to_string())?;
    let record = view
        .read_record::<Artifact>(view.root(), &Name::new("artifact").unwrap())
        .map_err(|error| error.to_string())?
        .expect("record");
    let prefix = record
        .record()
        .session_original
        .as_ref()
        .expect("source prefix");
    assert_eq!(prefix.verified_windows, 1);
    assert_eq!(prefix.chain.bytes(), &writer.chain());
    assert!(!prefix.complete && !prefix.counts);
    assert!(record.record().workers.is_empty());
    Ok(())
}
