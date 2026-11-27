//! [`Plan`] reads a push's ref lines one at a time and keeps, in first-seen order, each tip's checks, the
//! scan ranges, the tips whose chaos records are guarded and the commits the push may send.

use std::ffi::{OsStr, OsString};
use std::fmt;

use crate::environ::Environ;
use crate::git::{git, push_environ};
use crate::text::{Text, words};

use super::guard::{account_numbers, pushed_records, record_pathspecs, tip_records};
use super::reads::{
    ZERO, changes_ignore, comparison_base, destination_refs, holds_check, links, sources,
};
use super::table::{
    GAMEDAY_OWN, HOST_STOP_OWN, JUDGES_SOURCES, chaos_change, gameday_input, host_stop_input,
};
use super::{Check, Failure, Held, Members, argument, checks_for, short};

/// The note of a ref line with no comparison base; `Display` writes
/// `<tip>: no comparison base; weakened-test scan skipped`, the tip cut to twelve code points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped(Text);

impl fmt::Display for Skipped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: no comparison base; weakened-test scan skipped",
            short(&self.0)
        )
    }
}

/// The decisions for one push so far. Every Git read starts in [`push_environ`], built once at [`Plan::new`].
#[derive(Debug)]
pub struct Plan {
    environ: Environ,
    tracked: Vec<OsString>,
    planned: Vec<(Text, Vec<Check>)>,
    scans: Vec<(Text, Text)>,
    guarded: Vec<Text>,
    pushed: Vec<Text>,
}

impl Plan {
    /// `new` starts the plan of a push to `destination`, the hook's first argument. A nonempty name reads
    /// `git remote` for the remotes whose refs [`destination_refs`] weighs.
    ///
    /// # Errors
    ///
    /// The read of `git remote` fails.
    pub fn new(destination: &OsStr) -> Result<Self, Failure> {
        let environ = push_environ();
        let name = Text::from_os(destination);
        let remotes: Vec<Text> = if name.is_empty() {
            Vec::new()
        } else {
            words(&git(&environ, &["remote"])?)
                .map(Text::from)
                .collect()
        };
        let tracked = destination_refs(&name, &remotes)
            .iter()
            .map(argument)
            .collect();
        Ok(Self {
            environ,
            tracked,
            planned: Vec::new(),
            scans: Vec::new(),
            guarded: Vec::new(),
            pushed: Vec::new(),
        })
    }

    /// `environ` is the environment of the plan's Git reads, which the scan and the checks start in too.
    pub fn environ(&self) -> &Environ {
        &self.environ
    }

    /// `scans` are the (base, tip) pairs the weakened-test scan reads, in first-seen order, each once.
    pub fn scans(&self) -> &[(Text, Text)] {
        &self.scans
    }

    /// `checks` returns each tip that needs a check, in first-seen order, with its checks in run order.
    pub fn checks(&self) -> Vec<(&Text, Vec<Check>)> {
        self.planned
            .iter()
            .filter(|(_, checks)| !checks.is_empty())
            .map(|(tip, checks)| {
                let mut ordered = checks.clone();
                ordered.sort_unstable();
                (tip, ordered)
            })
            .collect()
    }

    /// `line` adds one ref line, as the hook's caller decoded it from its input. A line with no comparison
    /// base gives `note` its [`Skipped`] note once the base and the links registry are read, before the
    /// line's later reads.
    ///
    /// Each Git read runs in the order and under the conditions stated here, so a failed read ends the push
    /// with that read's text: the comparison base, the links registry, and then either the presence at the
    /// tip of the contract (twice), the replay after a held contract, the judges' test, the game-day and the
    /// host stop self-tests, or the changed paths, the Verus inventory, the changed Rust files, the judges'
    /// test where a source it reads changed, the replay, and each self-test where an input of it other than
    /// its own scripts changed. Then the commits under the record directories that the tip reaches and the
    /// destination is not known to hold. A plan that returned an error holds part of that line and serves
    /// no push.
    ///
    /// # Errors
    ///
    /// A line that is not blank and has other than four fields is [`Failure::Malformed`], and a failed read
    /// is its error.
    pub fn line(&mut self, line: &OsStr, note: impl FnOnce(Skipped)) -> Result<(), Failure> {
        let text = Text::from_os(line);
        if text.strip().is_empty() {
            return Ok(());
        }
        let [_, local, _, remote] =
            <[Text; 4]>::try_from(text.split()).map_err(|_| Failure::Malformed(text.clone()))?;
        if local.to_str() == Some(ZERO) {
            return Ok(());
        }
        let base = comparison_base(&self.environ, &local, &remote)?;
        let links = links(&self.environ, &local)?;
        let (checks, guard) = match &base {
            None => {
                note(Skipped(local.clone()));
                (unbased_checks(&self.environ, &local, links.as_ref())?, true)
            }
            Some(base) => {
                let pair = (base.clone(), local.clone());
                if !self.scans.contains(&pair) {
                    self.scans.push(pair);
                }
                let paths = changed_paths(&self.environ, base, &local)?;
                let checks = based_checks(&self.environ, base, &local, &paths, links.as_ref())?;
                (checks, chaos_change(&paths))
            }
        };
        if guard && !self.guarded.contains(&local) {
            self.guarded.push(local.clone());
        }
        let known = base.as_ref() == Some(&remote);
        for commit in self.record_commits(&local, known.then_some(&remote))? {
            if !self.pushed.contains(&commit) {
                self.pushed.push(commit);
            }
        }
        let planned = match self.planned.iter().position(|(tip, _)| *tip == local) {
            Some(at) => &mut self.planned[at].1,
            None => {
                self.planned.push((local, Vec::new()));
                &mut self.planned.last_mut().expect("a tip was just added").1
            }
        };
        for check in checks {
            if !planned.contains(&check) {
                planned.push(check);
            }
        }
        Ok(())
    }

    /// `record_commits` lists the commits under the record directories that `local` reaches and the
    /// destination is not known to hold: those the remote-tracking refs of the destination reach, and `held`
    /// and its ancestors, the remote commit of a line whose comparison base it is.
    fn record_commits(&self, local: &Text, held: Option<&Text>) -> Result<Vec<Text>, Failure> {
        let mut args = vec![
            OsString::from("rev-list"),
            "--full-history".into(),
            argument(local),
        ];
        if held.is_some() || !self.tracked.is_empty() {
            args.push("--not".into());
            args.extend(held.map(argument));
            args.extend(self.tracked.iter().cloned());
        }
        args.push("--".into());
        args.extend(record_pathspecs());
        Ok(words(&git(&self.environ, &args)?).map(Text::from).collect())
    }

    /// `guard` returns the chaos record guard's failures in order: each guarded tip's refused entries, then
    /// the refused records of the pushed commits, then each record read that holds what may be an AWS
    /// account number, is not JSON or cannot be read.
    ///
    /// # Errors
    ///
    /// A failed Git read, and a tree entry or a raw diff record of another form than Git's manual gives.
    pub fn guard(&self) -> Result<Vec<String>, Failure> {
        let mut failures = Vec::new();
        let mut records = Vec::new();
        for commit in &self.guarded {
            let (found, held) = tip_records(&self.environ, commit)?;
            failures.extend(found);
            records.extend(held);
        }
        let (found, held) = pushed_records(&self.environ, &self.pushed)?;
        failures.extend(found);
        records.extend(held);
        failures.extend(account_numbers(&self.environ, &records)?);
        Ok(failures)
    }
}

/// `changed_paths` lists the paths that differ between `base` and `local`, each named from the top level.
fn changed_paths(environ: &Environ, base: &Text, local: &Text) -> Result<Vec<String>, Failure> {
    let listed = git(
        environ,
        &[
            OsString::from("diff"),
            "--no-renames".into(),
            "--no-relative".into(),
            "--ignore-submodules=none".into(),
            "--name-only".into(),
            "-z".into(),
            argument(base),
            argument(local),
        ],
    )?;
    Ok(listed
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

/// `unbased_checks` are the checks of a tip with no comparison base: every check, the links checks unless
/// the tip holds neither the registry nor its check, and each check that asks for a file only where the tip
/// holds it, the replay only beside the contract.
fn unbased_checks(
    environ: &Environ,
    local: &Text,
    links: Option<&Members>,
) -> Result<Vec<Check>, Failure> {
    let mut checks = vec![Check::SelectTests, Check::Admit, Check::Reconcile];
    if links.is_none_or(|links| !links.is_empty()) {
        checks.extend([Check::Links, Check::LinksSelfTest]);
    }
    if holds_check(environ, local, Check::Contract)? {
        checks.push(Check::Contract);
    }
    if holds_check(environ, local, Check::Contract)? && holds_check(environ, local, Check::Replay)?
    {
        checks.push(Check::Replay);
    }
    for check in [Check::Judges, Check::Gameday, Check::HostStop] {
        if holds_check(environ, local, check)? {
            checks.push(check);
        }
    }
    Ok(checks)
}

/// `based_checks` are the checks `paths`, changed from `base` to `local`, require. It asks whether the tip
/// holds a check's file only where a change to that check's inputs makes the answer count.
fn based_checks(
    environ: &Environ,
    base: &Text,
    local: &Text,
    paths: &[String],
    links: Option<&Members>,
) -> Result<Vec<Check>, Failure> {
    let changed = |list: &[&str]| paths.iter().any(|path| list.contains(&path.as_str()));
    let any = |test: fn(&str) -> bool| paths.iter().any(|path| test(path));
    let sources = sources(environ, local)?;
    let ignore_changed = changes_ignore(environ, base, local, paths)?;
    let held = Held {
        judges: changed(&JUDGES_SOURCES) && holds_check(environ, local, Check::Judges)?,
        replay: holds_check(environ, local, Check::Replay)?,
        gameday: !changed(&GAMEDAY_OWN)
            && any(gameday_input)
            && holds_check(environ, local, Check::Gameday)?,
        host_stop: !changed(&HOST_STOP_OWN)
            && any(host_stop_input)
            && holds_check(environ, local, Check::HostStop)?,
    };
    Ok(checks_for(
        paths,
        sources.as_ref(),
        links,
        ignore_changed,
        held,
    ))
}
