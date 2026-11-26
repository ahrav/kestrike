//! The failure view of a narrative: a bundle's first failure and the
//! recorded evidence that explains it: a violation's full rule when the
//! catalog holds the text its identity hashes, an audit failure's audit
//! code, the record boundary it surfaced at, and an unsuccessful run's
//! cause. Derived values are labelled derived; unrecorded values are unknown.
//!
//! A run-site failure surfaces after a turn's action, a stopped-boundary
//! check after a clock move, or the setup before the first clock. A settled
//! check raised a settled-site failure. In a recovery world, a recovery
//! check raises a settled-site failure during the run; the failure surfaces
//! at settlement. Clock and settled failures leave the turn unspecified, and
//! a failure without an identity leaves its raiser unspecified. A mixed or
//! cluster check during the
//! run records an `OBSERVED` event with at most 41 rule bytes and no hash,
//! and so do a cluster run's teardown and minimum checks once the run
//! ends; a mixed teardown check, a recovery lifecycle check and a recovery
//! conservation snapshot that read nothing record none.

use std::io::Write;

use sha2::{Digest, Sha256};

use crate::sim::manifest::Manifest;
use crate::sim::trace::{Field, Loaded, Outcome, RECORD, Tag, Terminal};

use super::super::branch::hex;
use super::super::bundle::{IDENTITY, IDENTITY_VERSION, OBSERVED, Site, observed};
use super::super::cluster::{self, COVERAGE, KEPT_RESOURCES, PROBES_FAILED, Reached};
use super::rules::resolve;
use super::{Place, World, decode, names_rule};

/// The bytes of a rule a failure code keeps.
const KEPT: usize = crate::sim::trace::PAYLOAD - 3;

/// The index of the last version-2 identity event in `records` after `at`.
pub(super) fn identity_after(records: &[[u8; RECORD]], at: usize) -> Option<usize> {
    let identity = |record: &[u8; RECORD]| {
        record[..2] == [Tag::Event as u8, IDENTITY] && record[4] == IDENTITY_VERSION
    };
    (at + 1..records.len())
        .rev()
        .find(|&at| identity(&records[at]))
}

/// The rule bytes a failure code's payload `code` keeps, `None` when its
/// recorded length passes the bytes a record holds.
fn kept(code: &[u8]) -> Option<&[u8]> {
    code.get(3..3 + usize::from(code[2]))
}

/// What the catalog says of the rule of the violation record `violation`,
/// a rule failure, under `identity`.
fn rule(violation: &[u8; RECORD], identity: Option<&[u8; RECORD]>) -> String {
    let code = &violation[4..];
    let Some(identity) = identity.map(|identity| &identity[4..]) else {
        return "unknown: no version-2 identity event records its hash".into();
    };
    let (length, hash) = (
        u16::from_le_bytes([identity[5], identity[6]]),
        &identity[7..39],
    );
    let agrees = |text: &str| {
        let whole = u16::try_from(text.len()).unwrap_or(u16::MAX) == length;
        let prefix = kept(code) == Some(&text.as_bytes()[..text.len().min(KEPT)]);
        whole && prefix && identity[1] == code[0] & 0x7f && identity[2] == code[1]
    };
    match resolve(hash) {
        Some(text) if agrees(text) => format!("known \"{}\"", text.escape_default()),
        Some(text) => format!(
            "inconsistent: the identity's hash {} names \"{}\", which the recorded length \
            {length}, prefix, variant or obligation contradicts",
            hex(hash),
            text.escape_default()
        ),
        None => format!(
            "unknown: no cataloged rule hashes to {}; the bundle holds {} of its {length} bytes",
            hex(hash),
            kept(code).map_or(0, <[u8]>::len)
        ),
    }
}

/// The actor and link end of the audit violation record `violation`: the
/// record keeps the actor's low byte and packs the link end with its high
/// byte, and `identity` hashes the whole code, so they read from the hash.
fn audit(violation: &[u8; RECORD], identity: Option<&[u8; RECORD]>) -> String {
    let code = &violation[4..];
    let identity = identity.map(|identity| &identity[4..]);
    let class = code[1].wrapping_add(1);
    let Some(identity) = identity.filter(|identity| identity[1..4] == [4, 0, class]) else {
        return "actor and link end unknown: no audit identity follows".into();
    };
    let resolved = (0..=u8::MAX).find_map(|high| {
        let mut whole = [0; 15];
        whole[..5].copy_from_slice(&code[1..6]);
        whole[5..8].copy_from_slice(&[code[6], high, code[7] ^ (high << 4)]);
        (Sha256::digest(whole)[..] == identity[7..39]).then_some((high, whole[7]))
    });
    match resolved {
        Some((high, toward)) => format!(
            "actor={} toward={toward} (read from the identity hash)",
            u16::from_le_bytes([code[6], high])
        ),
        None => "actor and link end unknown: no actor with a link end below 256 hashes to the \
            identity"
            .into(),
    }
}

/// What raised the failure recorded at `at`: the site its identity names
/// and, at a run site, the record boundary it surfaced at.
fn raised(world: World, records: &[[u8; RECORD]], places: &[Place], at: usize) -> String {
    let last = |tag: Tag| {
        let at = records[..at]
            .iter()
            .rposition(|record| record[0] == tag as u8);
        at.map_or_else(String::new, |at| decode(world, &records[at]).line())
    };
    let none = "raised it, no turn did";
    let sites = [Site::Run as u8, Site::Settled as u8];
    let own = |id: &[u8; RECORD]| sites.contains(&id[8]) && id[5] == records[at][4] & 0x7f;
    let found = identity_after(records, at).map(|at| records[at]);
    let Some(identity) = found.filter(own) else {
        let place = places[at].label();
        return format!("unknown: no version-2 identity records its site; it follows {place}");
    };
    match places[at] {
        _ if identity[8] == Site::Settled as u8 && world == World::Recovery => {
            "at settlement: a recovery check during the run raised it; the bundle names no turn"
                .into()
        }
        _ if identity[8] == Site::Settled as u8 => {
            format!("at settlement, after the last turn: a settled check {none}")
        }
        Place::Turn(turn) => format!("by turn {turn}'s action: {}", last(Tag::Turn)),
        Place::Clock(turns) => format!(
            "at the clock boundary after {turns} turns, {}: a stopped-boundary check {none}",
            last(Tag::Clock)
        ),
        Place::Setup => format!("before the first clock move: the setup {none}"),
        Place::Settle => "unknown: a run site's failure recorded at settlement".into(),
    }
}

/// The note the violation record `violation`, which `identity` names,
/// carries on its line: its full rule, as [`rule`] names it.
pub(super) fn note(violation: &[u8; RECORD], identity: Option<&[u8; RECORD]>) -> Option<String> {
    names_rule(violation[4]).then(|| format!(" (rule {})", rule(violation, identity)))
}

/// Writes the failure view of `records`, which loaded as `loaded` under
/// `manifest` and stand at `places`, to `out`: the terminal's outcome; the
/// violation record with any earlier `OBSERVED` event and its cause, what
/// raised it, its identity and its rule or audit code, or else the first
/// `OBSERVED` event's cause, with the minima the last coverage misses when
/// they derive the rule it records, or the cause the last coverage
/// derives; then the terminal. Returns the records it rendered.
///
/// # Errors
///
/// A failed write.
pub(super) fn write(
    out: &mut impl Write,
    (records, places, world): (&[[u8; RECORD]], &[Place], World),
    loaded: &Loaded,
    manifest: &Manifest,
) -> std::io::Result<u64> {
    let mut rendered = 0;
    let mut line = |out: &mut dyn Write, key: &str, at: usize| {
        rendered += 1;
        let (place, line) = (places[at].label(), decode(world, &records[at]).line());
        writeln!(out, "{key}: #{at} {place}: {line}")
    };
    let find = |head: &[u8]| records.iter().position(|record| record.starts_with(head));
    let outcome = match loaded.terminal {
        Terminal::Complete { outcome, .. } => format!("{outcome:?}"),
        Terminal::Infrastructure(class) => format!("infrastructure {class:?}"),
    };
    writeln!(out, "failure: {}", outcome.to_lowercase())?;
    let observation = find(&[Tag::Event as u8, OBSERVED]);
    if let Some(at) = find(&[Tag::Violation as u8]) {
        if let Some(first) = observation.filter(|&first| first < at) {
            line(out, "observed", first)?;
            writeln!(out, "cause: {}", observed_cause(world, records, first))?;
        }
        let found = identity_after(records, at);
        let identity = found.map(|at| &records[at]);
        line(out, "violation", at)?;
        writeln!(out, "raised: {}", raised(world, records, places, at))?;
        match found {
            Some(found) => line(out, "identity", found)?,
            None => writeln!(out, "identity: none: the site is unrecorded")?,
        }
        match records[at][4] {
            4 => writeln!(out, "audit: {}", audit(&records[at], identity))?,
            variant if names_rule(variant) => {
                writeln!(out, "rule: {}", rule(&records[at], identity))?;
            }
            _ => writeln!(out, "rule: unknown: its variant names no rule")?,
        }
    } else if let Some(at) = observation {
        line(out, "observed", at)?;
        writeln!(out, "cause: {}", observed_cause(world, records, at))?;
        let recorded = kept(&records[at][4..]);
        if let Ok((Some(rule), short)) = shortfall(world, loaded, manifest)
            && recorded == Some(&rule.as_bytes()[..rule.len().min(KEPT)])
        {
            writeln!(
                out,
                "minimum: short of {short} (derived: the recorded coverage under this decoder's \
                minima for {})",
                manifest.profile
            )?;
        }
    } else if matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Unsuccessful,
            ..
        }
    ) {
        writeln!(out, "observed: none: the bundle records no OBSERVED event")?;
        let coverage = |record: &[u8; RECORD]| record.starts_with(&[Tag::Event as u8, COVERAGE]);
        if let Some(at) = records.iter().rposition(coverage) {
            line(out, "coverage", at)?;
        }
        writeln!(out, "cause: {}", short_of(world, loaded, manifest))?;
    }
    if let Some(at) = find(&[Tag::Terminal as u8]) {
        line(out, "terminal", at)?;
    }
    Ok(rendered)
}

/// The cause the `OBSERVED` event at `at` records: its kept rule bytes and,
/// when they are a cluster condition's first 41 bytes, its whole rule and
/// the owner of the last probe step before it, with that step's key for a
/// failed probe; a kept resource's key is unrecorded.
fn observed_cause(world: World, records: &[[u8; RECORD]], at: usize) -> String {
    let Some(bytes) = kept(&records[at][4..]) else {
        return format!("unknown: its rule length {} passes {KEPT}", records[at][6]);
    };
    let text = format!("\"{}\"", bytes.escape_ascii());
    let rule = if bytes.len() < KEPT {
        format!("{text} (whole: {} bytes)", bytes.len())
    } else {
        format!("{text} (its first {KEPT} bytes; the run records no hash, so the rest is unknown)")
    };
    let conditions = [
        (PROBES_FAILED, "probes failed"),
        (KEPT_RESOURCES, "kept resources"),
    ];
    let unsuccessful = world == World::Cluster && records[at][4] & 0x7f == 3;
    let mut conditions = conditions.into_iter().filter(|_| unsuccessful);
    let Some((known, condition)) =
        conditions.find(|(known, _)| bytes == &known.as_bytes()[..known.len().min(KEPT)])
    else {
        return format!("{rule}; owner and key unknown: the bundle names none");
    };
    let probe = [crate::sim::choice::Domain::Workload as u8, cluster::PROBE];
    let turns = records[..at]
        .iter()
        .filter(|record| record[0] == Tag::Turn as u8);
    let probes = turns
        .enumerate()
        .filter(|(_, record)| record[12..14] == probe);
    let key = |record: &[u8; RECORD]| {
        if known == PROBES_FAILED {
            format!("key={}", record[20])
        } else {
            "key unknown".to_owned()
        }
    };
    let owner = match probes.last() {
        Some((turn, record)) => format!(
            "owner={} {} (from turn {turn}, the last probe step before it)",
            record[14],
            key(record)
        ),
        None => "owner and key unknown: no probe step precedes it".into(),
    };
    format!("{rule}; {condition}, whose rule \"{known}\" the recorded bytes begin; {owner}")
}

/// The minima a finished cluster run fell short of, derived from its
/// recorded coverage counts and this decoder's minima when the run stopped
/// at its goal and the recorded configuration names the profile, its root
/// and the coverage topology, with the rule the run's minimum check names.
fn short_of(world: World, loaded: &Loaded, manifest: &Manifest) -> String {
    let profile = &manifest.profile;
    match shortfall(world, loaded, manifest) {
        Ok((Some(rule), short)) => format!(
            "\"{rule}\" (derived: the run's minimum check over the recorded coverage under this \
            decoder's minima for {profile}, short of {short}; a teardown check that failed first \
            would leave no record)"
        ),
        Ok((None, saturated)) => format!(
            "unknown: the recorded coverage meets every minimum this decoder holds for \
            {profile}{saturated}"
        ),
        Err(unknown) => unknown,
    }
}

/// The rule of the first minimum the recorded coverage falls short of, as
/// [`short_of`] derives it, with the minima it misses and the saturation
/// note; with no rule, the note alone. `Err` holds why the coverage cannot
/// be judged.
fn shortfall(
    world: World,
    loaded: &Loaded,
    manifest: &Manifest,
) -> Result<(Option<&'static str>, String), String> {
    let profile = &manifest.profile;
    let seen = observed(&loaded.events);
    let (Some(shape), Some((topology, counts)), World::Cluster) = (
        cluster::shape_at(profile, manifest.root),
        seen.coverage,
        world,
    ) else {
        return Err(
            "unknown: the bundle records no coverage of a cluster profile this decoder holds"
                .into(),
        );
    };
    if seen.stop != Some((1, 0)) {
        return Err("unknown: no recorded goal stop shows the run made its minimum check".into());
    }
    let config = loaded
        .fields
        .iter()
        .find(|(field, _)| *field == Field::Config);
    let record = super::super::bundle::named(profile, manifest.root).map(|named| named.0.record());
    let expected = record.unwrap_or_default();
    let mut drawn = vec![cluster::GENERATOR];
    drawn.extend(shape.name.as_bytes());
    drawn.extend([0, topology.owners, topology.keys, topology.hot]);
    let at = expected.len() + 4;
    let compatible = config.is_some_and(|(_, config)| {
        config.starts_with(&expected) && config.get(at..at + drawn.len()) == Some(&drawn[..])
    });
    if !compatible {
        return Err(format!(
            "unknown: the recorded configuration is not {profile}'s as this decoder runs it"
        ));
    }
    let count = |name| {
        let at = Reached::NAMES.iter().position(|known| *known == name);
        u64::from(counts[at.expect("a count")])
    };
    let reached = Reached {
        published: count("published"),
        hits: count("hits"),
        cross: count("cross"),
        faults: count("faults"),
        healthy: count("healthy"),
        reused: count("reused"),
        ..Reached::default()
    };
    let minima = shape.minima;
    let checked = [
        ("published", minima.published),
        ("hits", minima.hits),
        ("cross", minima.cross),
        ("faults", minima.faults),
        ("healthy", minima.healthy),
        ("reused", minima.reused),
    ];
    let short: Vec<String> = checked
        .into_iter()
        .filter(|&(name, minimum)| count(name) < minimum)
        .map(|(name, minimum)| format!("{name} observed={} required={minimum}", count(name)))
        .collect();
    let saturated = if counts.contains(&u32::MAX) {
        "; a count at 4294967295 is saturated and reads as at least that"
    } else {
        ""
    };
    Ok(match cluster::short_of(&minima, &reached) {
        Some(rule) => (Some(rule), format!("{}{saturated}", short.join(", "))),
        None => (None, saturated.to_owned()),
    })
}

#[cfg(test)]
mod tests;
