//! [`Plan`] reads a push's ref lines one at a time and keeps, in first-seen order, each tip's checks, the
//! scan ranges, the tips whose chaos records are guarded and the commits the push may send.

use std::ffi::{OsStr, OsString};
use std::fmt;

use crate::environ::Environ;
use crate::git::{git, push_environ};
use crate::text::{Text, words};

use super::guard::{RECORD_DIRS, account_numbers, pushed_records, tip_records};
use super::reads::{
    ZERO, changes_ignore, comparison_base, destination_refs, holds, links, sources,
};
use super::table::{
    GAMEDAY_OWN, HOST_STOP_OWN, JUDGES_SOURCES, chaos_change, gameday_input, host_stop_input,
};
use super::{Check, Failure, Held, ORDER, checks_for, short};

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

/// `argument` is `text` as a Git argument.
fn argument(text: &Text) -> OsString {
    text.to_os()
        .expect("a ref line and a remote's name are read from bytes, which they encode")
}

/// `record_pathspecs` names each record directory from the top level.
fn record_pathspecs() -> impl Iterator<Item = OsString> {
    RECORD_DIRS
        .iter()
        .map(|dir| OsString::from(format!(":(top){dir}")))
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

    /// `line` adds one ref line. A line with no comparison base returns its [`Skipped`] note.
    ///
    /// Each Git read runs in the order and under the conditions stated here, so a failed read ends the push
    /// with that read's text: the comparison base, the links registry, and then either the presence at the
    /// tip of the contract (twice), the replay after a held contract, the judges' test, the game-day and the
    /// host stop self-tests, or the changed paths, the Verus inventory, the changed Rust files, the judges'
    /// test where a source it reads changed, the replay, and each self-test where an input of it other than
    /// its own scripts changed. Then the commits under the record directories that the tip reaches and the
    /// destination is not known to hold.
    ///
    /// # Errors
    ///
    /// A line that is not blank and has other than four fields is [`Failure::Malformed`], and a failed read
    /// is its error.
    pub fn line(&mut self, line: &OsStr) -> Result<Option<Skipped>, Failure> {
        let text = Text::from_os(line);
        if text.strip().is_empty() {
            return Ok(None);
        }
        let [_, local, _, remote] =
            <[Text; 4]>::try_from(text.split()).map_err(|_| Failure::Malformed(text.clone()))?;
        if local.to_str() == Some(ZERO) {
            return Ok(None);
        }
        let environ = &self.environ;
        let base = comparison_base(environ, &local, &remote)?;
        let links = links(environ, &local)?;
        let mut skipped = None;
        let (checks, guard) = match &base {
            None => {
                skipped = Some(Skipped(local.clone()));
                let mut checks = vec![Check::SelectTests, Check::Admit, Check::Reconcile];
                if links.as_ref().is_none_or(|links| !links.is_empty()) {
                    checks.extend([Check::Links, Check::LinksSelfTest]);
                }
                let held = |check: Check| {
                    holds(
                        environ,
                        &local,
                        ORDER[check as usize]
                            .held
                            .expect("the check names the file it asks for"),
                    )
                };
                if held(Check::Contract)? {
                    checks.push(Check::Contract);
                }
                if held(Check::Contract)? && held(Check::Replay)? {
                    checks.push(Check::Replay);
                }
                for check in [Check::Judges, Check::Gameday, Check::HostStop] {
                    if held(check)? {
                        checks.push(check);
                    }
                }
                (checks, true)
            }
            Some(base) => {
                let pair = (base.clone(), local.clone());
                if !self.scans.contains(&pair) {
                    self.scans.push(pair);
                }
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
                        argument(&local),
                    ],
                )?;
                let paths: Vec<String> = listed
                    .split('\0')
                    .filter(|path| !path.is_empty())
                    .map(str::to_owned)
                    .collect();
                let changed =
                    |list: &[&str]| paths.iter().any(|path| list.contains(&path.as_str()));
                let any = |test: fn(&str) -> bool| paths.iter().any(|path| test(path));
                let sources = sources(environ, &local)?;
                let ignore_changed = changes_ignore(environ, base, &local, &paths)?;
                let held = |check: Check| {
                    holds(
                        environ,
                        &local,
                        ORDER[check as usize]
                            .held
                            .expect("the check names the file it asks for"),
                    )
                };
                let held = Held {
                    judges: changed(&JUDGES_SOURCES) && held(Check::Judges)?,
                    replay: held(Check::Replay)?,
                    gameday: !changed(&GAMEDAY_OWN) && any(gameday_input) && held(Check::Gameday)?,
                    host_stop: !changed(&HOST_STOP_OWN)
                        && any(host_stop_input)
                        && held(Check::HostStop)?,
                };
                let checks = checks_for(
                    &paths,
                    sources.as_ref(),
                    links.as_ref(),
                    ignore_changed,
                    held,
                );
                (checks, chaos_change(&paths))
            }
        };
        if guard && !self.guarded.contains(&local) {
            self.guarded.push(local.clone());
        }
        let mut args = vec![
            OsString::from("rev-list"),
            "--full-history".into(),
            argument(&local),
        ];
        let remote_known = base.as_ref() == Some(&remote);
        if remote_known || !self.tracked.is_empty() {
            args.push("--not".into());
            if remote_known {
                args.push(argument(&remote));
            }
            args.extend(self.tracked.iter().cloned());
        }
        args.push("--".into());
        args.extend(record_pathspecs());
        for commit in words(&git(&self.environ, &args)?) {
            let commit = Text::from(commit);
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
        Ok(skipped)
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
