//! The runner's `state.json`: the stored assignment's digest, the current
//! root and every root this runner keeps. [`load`] refuses a record whose
//! format is not 1, whose assignment is no SHA-256, whose current root is
//! not recorded, whose root has a malformed identity or a key other than
//! its campaign, or whose root is marked deleting while it is current or
//! its confirmation is unfinished. [`save`] writes any [`State`] within
//! [`BOUND`] and checks none of these rules; the runner keeps them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const BOUND: u64 = 16 << 20;

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub format: u32,
    #[serde(deserialize_with = "present")]
    pub assignment: Option<String>,
    #[serde(deserialize_with = "present")]
    pub current: Option<String>,
    pub roots: BTreeMap<String, Root>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Retry {
    /// The boot id of the boot whose clock `until_ms` reads.
    pub boot: String,
    /// The `CLOCK_BOOTTIME` instant, in milliseconds, before which the
    /// root's next sweep waits. It holds only on the boot named by `boot`.
    pub until_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub name: String,
    pub instance: String,
    pub nonce: String,
    pub build: String,
    pub counts: BTreeMap<String, u64>,
    pub confirm_slots: u64,
    pub stints: u64,
    pub failures: u32,
    pub cpu_usec: u64,
    pub capacity_usec: u64,
    pub alarm: bool,
    pub confirmation: Confirmation,
    /// Set before a confirm starts and cleared when one ends with no
    /// admitted job left, so a set flag means a confirmation may still have
    /// unfinished work; it does not prove that admitted jobs exist.
    pub pending: bool,
    #[serde(deserialize_with = "present")]
    pub retry: Option<Retry>,
    /// The root is retired. The mark is final: it stays, also across
    /// restarts, until the root's directory, its upload copies and its
    /// confirmation cgroups are removed, and no later check of the root's
    /// evidence clears it. An absent field reads as false.
    #[serde(default)]
    pub deleting: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase", tag = "state", content = "reason")]
pub enum Confirmation {
    Idle,
    Backlog(String),
    Held(String),
    Failed(String),
}

impl Confirmation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Backlog(_) => "backlog",
            Self::Held(_) => "held",
            Self::Failed(_) => "failed",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Idle => None,
            Self::Backlog(reason) | Self::Held(reason) | Self::Failed(reason) => Some(reason),
        }
    }
}

impl Root {
    pub fn campaign(&self) -> String {
        format!("{}.{}.{}", self.name, self.instance, self.nonce)
    }

    fn check(&self, key: &str) -> Result<(), String> {
        if !crate::assignment::is_name(&self.name)
            || !crate::instance::is_instance_id(&self.instance)
            || !crate::file::is_hex(&self.nonce, 32)
            || !crate::file::is_sha256(&self.build)
            || self.confirm_slots == 0
        {
            return Err(format!("root {key:?} has a malformed identity"));
        }
        if self.campaign() != key {
            return Err(format!(
                "root {key:?} records campaign {:?}",
                self.campaign()
            ));
        }
        Ok(())
    }
}

pub fn path(state: &Path) -> PathBuf {
    state.join("state.json")
}

pub fn assignments(state: &Path) -> PathBuf {
    state.join("assignments")
}

pub fn assignment_path(state: &Path, digest: &str) -> PathBuf {
    assignments(state).join(format!("{digest}.json"))
}

pub fn roots(state: &Path) -> PathBuf {
    state.join("roots")
}

fn check(state: &State) -> Result<(), String> {
    if state.format != 1 {
        return Err(format!("format {} is not 1", state.format));
    }
    if let Some(digest) = &state.assignment
        && !crate::file::is_sha256(digest)
    {
        return Err(format!("assignment {digest:?} is no SHA-256"));
    }
    if let Some(current) = &state.current
        && !state.roots.contains_key(current)
    {
        return Err(format!("the current root {current:?} is not recorded"));
    }
    for (key, root) in &state.roots {
        root.check(key)?;
        let retirable = state.current.as_deref() != Some(key.as_str())
            && root.confirmation == Confirmation::Idle
            && !root.pending;
        if root.deleting && !retirable {
            return Err(format!(
                "root {key:?} is marked for deletion while it is current or its confirmation \
                 is unfinished"
            ));
        }
    }
    Ok(())
}

pub fn load(state: &Path) -> Result<State, String> {
    let path = path(state);
    match crate::file::read(&path, BOUND) {
        Ok(None) => Ok(State {
            format: 1,
            ..State::default()
        }),
        Ok(Some(bytes)) => {
            let loaded: State = serde_json::from_slice(&bytes)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            check(&loaded).map_err(|error| format!("{}: {error}", path.display()))?;
            Ok(loaded)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Replaces `state.json` with `value`, refusing an encoding past
/// [`BOUND`]. The rules [`load`] checks are left to the caller.
pub fn save(state: &Path, value: &State) -> Result<(), String> {
    crate::file::save_json(&path(state), value, BOUND)
}

#[cfg(test)]
mod tests {
    use super::{Confirmation, Root, State};

    fn root() -> Root {
        Root {
            name: "sim".into(),
            instance: "i-0123abcd".into(),
            nonce: "00".repeat(16),
            build: crate::file::sha256(b"b"),
            counts: [("watchdog".to_owned(), 900)].into(),
            confirm_slots: 8,
            stints: 3,
            failures: 1,
            cpu_usec: 10,
            capacity_usec: 20,
            alarm: false,
            confirmation: Confirmation::Held("a reason".into()),
            pending: true,
            retry: Some(super::Retry {
                boot: "a-boot".into(),
                until_ms: 5,
            }),
            deleting: false,
        }
    }

    use crate::file::scratch;

    #[test]
    fn a_saved_state_loads_as_it_was() {
        let dir = scratch("state");
        assert_eq!(super::load(&dir).expect("an empty state").format, 1);
        let mut state = super::load(&dir).expect("an empty state");
        let root = root();
        assert_eq!(
            root.campaign(),
            format!("sim.i-0123abcd.{}", "00".repeat(16))
        );
        state.current = Some(root.campaign());
        state.roots.insert(root.campaign(), root);
        super::save(&dir, &state).expect("it saves");
        assert_eq!(super::load(&dir).expect("it loads"), state);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_root_recorded_without_a_deletion_mark_loads_unmarked() {
        let dir = scratch("state-unmarked");
        let root = root();
        let state = State {
            format: 1,
            assignment: None,
            current: Some(root.campaign()),
            roots: [(root.campaign(), root)].into(),
        };
        let mut value = serde_json::to_value(&state).expect("it encodes");
        let roots = value["roots"].as_object_mut().expect("roots");
        let recorded = roots.values_mut().next().expect("a root");
        recorded
            .as_object_mut()
            .expect("a root")
            .remove("deleting")
            .expect("the mark");
        std::fs::write(super::path(&dir), value.to_string()).expect("it is written");
        assert_eq!(super::load(&dir), Ok(state));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn an_inconsistent_state_is_refused() {
        let dir = scratch("state-refused");
        let valid = || {
            let root = root();
            State {
                format: 1,
                assignment: Some(crate::file::sha256(b"a")),
                current: Some(root.campaign()),
                roots: [(root.campaign(), root)].into(),
            }
        };
        type Change = fn(&mut State);
        let changes: [Change; 8] = [
            |state| state.current = Some("sim.i-0123abcd.other".into()),
            |state| {
                let root = state.roots.values_mut().next().expect("a root");
                root.deleting = true;
            },
            |state| {
                state.current = None;
                let root = state.roots.values_mut().next().expect("a root");
                root.deleting = true;
            },
            |state| {
                let root = state.roots.values_mut().next().expect("a root");
                root.nonce = "../../../etc".into();
            },
            |state| {
                let root = state.roots.values_mut().next().expect("a root");
                root.nonce = "11".repeat(16);
            },
            |state| {
                let root = state.roots.values_mut().next().expect("a root");
                root.instance = "host".into();
            },
            |state| {
                let root = state.roots.values_mut().next().expect("a root");
                root.confirm_slots = 0;
            },
            |state| state.assignment = Some("../x".into()),
        ];
        for change in changes {
            let mut state = valid();
            change(&mut state);
            let bytes = serde_json::to_vec(&state).expect("it encodes");
            std::fs::write(super::path(&dir), bytes).expect("it is written");
            assert!(super::load(&dir).is_err(), "{state:?} is refused");
        }
        for field in ["pending", "retry", "confirmation"] {
            let mut value = serde_json::to_value(valid()).expect("it encodes");
            let roots = value["roots"].as_object_mut().expect("roots");
            let root = roots.values_mut().next().expect("a root");
            root.as_object_mut().expect("a root").remove(field);
            std::fs::write(super::path(&dir), value.to_string()).expect("it is written");
            assert!(super::load(&dir).is_err(), "a root without {field}");
        }
        for field in ["assignment", "current"] {
            let mut value = serde_json::to_value(valid()).expect("it encodes");
            value.as_object_mut().expect("a state").remove(field);
            std::fs::write(super::path(&dir), value.to_string()).expect("it is written");
            assert!(super::load(&dir).is_err(), "a state without {field}");
        }
        let mut empty = serde_json::to_value(valid()).expect("it encodes");
        empty["assignment"] = serde_json::Value::Null;
        empty["current"] = serde_json::Value::Null;
        std::fs::write(super::path(&dir), empty.to_string()).expect("it is written");
        assert!(
            super::load(&dir).is_ok(),
            "null assignment and current load"
        );
        type Identity = fn(&mut Root);
        let identities: [Identity; 4] = [
            |root| root.name = "a.b".into(),
            |root| root.instance = "i-NOTHEX".into(),
            |root| root.nonce = "zz".repeat(16),
            |root| root.build = "short".into(),
        ];
        for change in identities {
            let mut root = root();
            change(&mut root);
            let state = State {
                format: 1,
                assignment: None,
                current: Some(root.campaign()),
                roots: [(root.campaign(), root)].into(),
            };
            let bytes = serde_json::to_vec(&state).expect("it encodes");
            std::fs::write(super::path(&dir), bytes).expect("it is written");
            assert!(super::load(&dir).is_err(), "{state:?} is refused");
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_state_past_its_bound_is_refused_and_the_old_one_loads() {
        let dir = scratch("state-bound");
        let mut state = super::load(&dir).expect("an empty state");
        super::save(&dir, &state).expect("it saves");
        let mut root = root();
        root.counts = [("x".repeat(super::BOUND as usize), 1)].into();
        state.roots.insert(root.campaign(), root);
        assert!(super::save(&dir, &state).is_err());
        assert!(super::load(&dir).expect("the old state").roots.is_empty());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
