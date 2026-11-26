//! Sweep status uses this registry to label suspects by the open findings
//! that explain them.
//!
//! [`KNOWN`] holds a [`Row`] only for a classified finding whose issue is
//! open and whose defect an unplanted scripted history reaches. A row stays
//! until its issue closes or until the fix that flips its pin to a pass
//! deletes it. The row names
//! its pin, a scripted history that drives the real defect's trigger and
//! declares a violation of the row's obligation under its rule, and the
//! obligation and rule the finding's
//! suspects fail in the profiles it names. The protocol contract case
//! requires [`defects`] to return an empty list for [`KNOWN`] against the
//! worker of the same commit, so a fix that flips its pin to a pass also
//! deletes its row.
//!
//! A row lists the profiles whose runs can reach the defect's trigger.
//! When only the pin reaches the trigger, the list is empty and `explains`
//! matches the row to zero suspect keys.
//!
//! A row matches a version 2 failure identity of variant 1, a check's
//! violation, or variant 2, an oracle verdict. Only suspects in the
//! `violation` class qualify as known, so panics stay new. Audit failures
//! and suspects counted under `other` stay new. Status attributes a
//! suspect to a row by profile, obligation and rule, whichever finding
//! produced it. A match shows that a suspect
//! failed the row's obligation and rule in one of its profiles; whether
//! the row's defect caused that suspect takes a replay to show.

#[cfg(test)]
#[path = "known_tests.rs"]
mod tests;

use super::calibration::controls::{self, Ended};
use crate::protocol::{Class, Fails, Listing, Rules};

/// The registry admits findings classified as bugs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bug {
    Safety,
    Correctness,
    Minor,
}

impl Bug {
    pub fn name(self) -> &'static str {
        match self {
            Self::Safety => "safety bug",
            Self::Correctness => "correctness bug",
            Self::Minor => "minor bug",
        }
    }
}

/// One open finding.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub issue: u32,
    pub class: Bug,
    /// A listed history that declares a violation of the row's obligation
    /// under its rule and drives the real defect's trigger.
    pub pin: &'static str,
    /// The profiles whose suspects the row labels, each listed as live,
    /// as recovery, or as a history that expects a pass. A row lists a
    /// profile whose runs can reach the defect's trigger; a row with an
    /// empty list registers its pin and labels zero suspects.
    pub profiles: &'static [&'static str],
    /// The obligation code, the fifth and sixth hexadecimal digits of a
    /// failure identity.
    pub obligation: u8,
    /// The full rule text, as the rule catalog prints it.
    pub rule: &'static str,
}

/// A row leaves `KNOWN` when its issue closes or when the fix that flips
/// its pin to a pass merges.
pub const KNOWN: &[Row] = &[
    // A placement promised before the owner's close is granted its shard
    // hold after it, since the hold reads the storage's cutoff and the
    // owner's close leaves that cutoff open. The pin alone keeps a
    // placement across the owner's close.
    Row {
        issue: 298,
        class: Bug::Correctness,
        pin: "k9-placement-across-close",
        profiles: &[],
        obligation: 2,
        rule: "a fill admitted after the cache closed",
    },
    // With a read share of one command, the command a device terminal frees
    // goes to a GET admitted in the same owner turn, so a read that already
    // waits stays unsubmitted while the demand lasts. The pin alone admits
    // a GET in the turn that frees the command of a one-command read share.
    Row {
        issue: 299,
        class: Bug::Correctness,
        pin: "ss2-peer-read-waits-for-one-command",
        profiles: &[],
        obligation: 6,
        rule: "an eligible peer's GET starved behind a saturated share",
    },
    // If the close service drains the mappings before capture starts, the
    // published checkpoint omits them.
    Row {
        issue: 300,
        class: Bug::Safety,
        pin: "wl1-closed-pass-lost",
        profiles: &[],
        obligation: 5,
        rule: "a retained entry outside every damage set was lost on host loss",
    },
    // A fill acknowledged while a cold tenure's first capture pass is in
    // flight is missing from both the checkpoint and the suffix.
    Row {
        issue: 316,
        class: Bug::Safety,
        pin: "wl2-fill-in-pass-lost",
        profiles: &[],
        obligation: 5,
        rule: "a retained entry outside every damage set was lost on host loss",
    },
    // On a device whose persistence unit is above 4096 bytes, two
    // checkpoints in two slots overwrite both root blocks, and an attach
    // under a lower session formats the media where it must refuse. The
    // pin alone publishes checkpoints on such a device.
    Row {
        issue: 329,
        class: Bug::Correctness,
        pin: "rs1-wide-unit-roots-lost",
        profiles: &[],
        obligation: 5,
        rule: "an attach wrote a root generation at or below one the root slots held",
    },
    // A write submit that the device refuses, for an upload of a peer below
    // its write-command share, leaves the lending on. The defect has two
    // sites, and a history declares this row's violation at each: the pin
    // through `PutCore::receive_wait`, and
    // `lw3-waiter-submit-refused-inside-fragment` through
    // `PutCore::receive`. Of the listed histories, those two alone have the
    // device refuse a submit.
    Row {
        issue: 334,
        class: Bug::Correctness,
        pin: "lw1-waiter-submit-refused-twice",
        profiles: &[],
        obligation: 6,
        rule: "a write command went to a peer at its share while a peer below its share waited",
    },
    // A receive refused for an empty buffer pool, for an upload of a peer
    // below its write-command share, leaves the lending on. Of the listed
    // histories, the pin alone has a receive refused for an empty pool.
    Row {
        issue: 335,
        class: Bug::Correctness,
        pin: "lw2-waiter-receive-finds-no-buffer",
        profiles: &[],
        obligation: 6,
        rule: "a write command went to a peer at its share while a peer below its share waited",
    },
];

/// The index in `table` of the row that explains the suspect key `key` of
/// `profile`. A matching key has class `violation`, and its identity
/// carries the row's obligation and the digest of its rule, in a profile
/// the row names. When several rows match, the earliest takes the key, so
/// a status counts each key under one row. Only an identity whose bytes
/// are all lowercase hexadecimal digits, the form the worker prints,
/// qualifies for a match.
pub(in crate::campaign) fn explains(table: &[Row], profile: &str, key: &str) -> Option<usize> {
    let identity = key.strip_prefix("violation: ")?;
    if !identity
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let identity = Ended::Violation(identity);
    table.iter().position(|row| {
        row.profiles.contains(&profile)
            && controls::violation(row.pin, row.obligation, row.rule).caught(&identity)
    })
}

/// [`defects`] groups all defects for each invalid row into one
/// diagnostic, which names the row by index, issue and pin. Against
/// `listing` and `rules`, a valid row pins a listed history that declares
/// a violation of the row's obligation under its rule, names a rule of the
/// catalog, and names zero or more profiles, each listed as live, as
/// recovery, or as a history that expects a pass. It is the only row for
/// each of its profiles under its obligation and rule. A sound table yields
/// an empty list.
pub fn defects(table: &[Row], listing: &Listing, rules: &Rules) -> Vec<String> {
    table
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            let mut found = Vec::new();
            match listing.profile(row.pin).map(|pin| &pin.fails) {
                None => found.push(format!("pin {} is not listed", row.pin)),
                Some(Some(Fails::Violation(code, rule)))
                    if *code == row.obligation && rule == row.rule => {}
                Some(Some(Fails::Violation(code, rule))) => found.push(format!(
                    "pin {} declares obligation {code} under rule {rule:?}",
                    row.pin
                )),
                Some(Some(Fails::Unsuccessful(_))) => {
                    found.push(format!("pin {} declares an unsuccessful ending", row.pin))
                }
                Some(None) => found.push(format!("pin {} declares no failure", row.pin)),
            }
            if !rules.rules.iter().any(|rule| rule.text == row.rule) {
                found.push(format!("rule {:?} is not in the rule catalog", row.rule));
            }
            for profile in row.profiles {
                match listing.profile(profile) {
                    None => found.push(format!("profile {profile} is not listed")),
                    Some(listed) if listed.class == Class::Control => {
                        found.push(format!("profile {profile} is a control"));
                    }
                    Some(listed) if listed.fails.is_some() => {
                        found.push(format!("profile {profile} declares a failure"));
                    }
                    Some(_) => {}
                }
            }
            for (other, shared) in table.iter().enumerate().filter(|&(other, shared)| {
                other != index && shared.obligation == row.obligation && shared.rule == row.rule
            }) {
                let common = row
                    .profiles
                    .iter()
                    .find(|profile| shared.profiles.contains(profile));
                if let Some(profile) = common {
                    found.push(format!(
                        "row {other} also explains obligation {} under this rule in {profile}",
                        row.obligation
                    ));
                }
            }
            (!found.is_empty()).then(|| {
                format!(
                    "row {index} (issue #{}, pin {}): {}",
                    row.issue,
                    row.pin,
                    found.join("; ")
                )
            })
        })
        .collect()
}
