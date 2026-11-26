//! Successful [`Assignment::parse`] calls return positive limits, with
//! `batch`, `wall` and `stint` bounded by [`SECONDS_MAX`], `processes` by
//! [`PROCESSES_MAX`], each profile a single file name of at most
//! [`PROFILE_MAX`] bytes, the joined profiles and each `KEY=COUNT` at
//! most [`ARGUMENT_MAX`] bytes, and the sweep arguments they make at most
//! [`ARGUMENTS_MAX`] bytes of `execve` space together.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::build::Commit;

pub const BOUND: u64 = 1 << 20;
pub const COPY_BOUND: u64 = BOUND + 4096;
pub const SECONDS_MAX: u64 = 4_294_967_295;
pub const PROCESSES_MAX: u64 = 4 * 1024 * 1024;
pub const PROFILE_MAX: usize = 242;
pub const ARGUMENT_MAX: usize = 131_071;
/// The `execve` space the assignment's sweep arguments take at most: each
/// argument's bytes, its NUL and its pointer, for the joined profiles and
/// for each count's `--set` and `KEY=COUNT`. It is half the 2 MiB that the
/// default 8 MiB stack limit gives `execve`, which leaves room for the fixed
/// arguments, the paths and the environment.
pub const ARGUMENTS_MAX: usize = 1 << 20;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub format: u32,
    pub name: String,
    pub profiles: Vec<String>,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
    pub batch: u64,
    pub wall: u64,
    pub memory: u64,
    pub processes: u64,
    pub stint: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub document: Document,
    pub commit: Commit,
}

pub fn is_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

impl Document {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let document: Self =
            serde_json::from_slice(bytes).map_err(|error| format!("the assignment: {error}"))?;
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<(), String> {
        if self.format != 1 {
            return Err(format!("assignment format {} is not 1", self.format));
        }
        if !is_name(&self.name) {
            return Err(format!(
                "assignment name {:?} is not 1 to 64 letters, digits, '-' or '_'",
                self.name
            ));
        }
        if self.profiles.is_empty() {
            return Err("the assignment lists no profile".into());
        }
        for profile in &self.profiles {
            if profile.is_empty()
                || profile.len() > PROFILE_MAX
                || profile == "."
                || profile == ".."
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b',' && byte != b'/')
            {
                return Err(format!(
                    "assignment profile {profile:?} is not 1 to {PROFILE_MAX} printable ASCII \
                     bytes without ',' or '/'"
                ));
            }
        }
        let joined = self.profiles.iter().map(String::len).sum::<usize>() + self.profiles.len() - 1;
        if joined > ARGUMENT_MAX {
            return Err(format!(
                "the assignment's profiles join to {joined} bytes, past the {ARGUMENT_MAX} of \
                 one argument"
            ));
        }
        // Each argument takes its bytes, its NUL and its pointer of execve
        // space.
        let cost = |bytes: usize| bytes + 1 + std::mem::size_of::<usize>();
        let mut arguments = cost(joined);
        for (key, count) in &self.counts {
            if key == "root" {
                return Err("assignment count \"root\" names the sweep root and is refused".into());
            }
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'=')
            {
                return Err(format!(
                    "assignment count {key:?} is not printable ASCII without '='"
                ));
            }
            let argument = key.len() + 1 + count.to_string().len();
            if argument > ARGUMENT_MAX {
                return Err(format!(
                    "an assignment count's KEY=COUNT holds {argument} bytes, past the \
                     {ARGUMENT_MAX} of one argument"
                ));
            }
            arguments += cost("--set".len()) + cost(argument);
        }
        if arguments > ARGUMENTS_MAX {
            return Err(format!(
                "the assignment's sweep arguments take {arguments} bytes of execve space, past \
                 {ARGUMENTS_MAX}"
            ));
        }
        for (field, value, max) in [
            ("batch", self.batch, SECONDS_MAX),
            ("wall", self.wall, SECONDS_MAX),
            ("memory", self.memory, u64::MAX),
            ("processes", self.processes, PROCESSES_MAX),
            ("stint", self.stint, SECONDS_MAX),
        ] {
            if !(1..=max).contains(&value) {
                return Err(format!("assignment {field} {value} is not 1 to {max}"));
            }
        }
        Ok(())
    }
}

impl Assignment {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let assignment: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("the stored assignment: {error}"))?;
        assignment.document.validate()?;
        assignment
            .commit
            .validate()
            .map_err(|error| format!("the stored assignment: {error}"))?;
        Ok(assignment)
    }

    pub fn build(&self) -> &str {
        &self.commit.build
    }

    pub fn binds(&self, root: &crate::state::Root) -> bool {
        self.commit.build == root.build
            && self.document.name == root.name
            && self.document.counts == root.counts
    }
}

#[cfg(test)]
mod tests {
    use super::{Assignment, Document};

    pub(crate) fn text() -> String {
        r#"{"format":1,"name":"sim","profiles":["a","a","b"],
        "counts":{"watchdog":900},"batch":30,"wall":600,"memory":2147483648,
        "processes":64,"stint":3600}"#
            .to_owned()
    }

    #[test]
    fn an_assignment_keeps_repeated_profiles_and_refuses_bad_fields() {
        let document = Document::parse(text().as_bytes()).expect("it parses");
        assert_eq!(document.profiles, ["a", "a", "b"]);
        assert_eq!(document.counts["watchdog"], 900);
        let long = format!(r#"["{}"]"#, "p".repeat(super::PROFILE_MAX + 1));
        for (from, to) in [
            (r#""format":1"#, r#""format":2"#),
            (r#""name":"sim""#, r#""name":"a.b""#),
            (r#"["a","a","b"]"#, "[]"),
            (r#"["a","a","b"]"#, r#"["a,b"]"#),
            (r#"["a","a","b"]"#, r#"["a/b"]"#),
            (r#"["a","a","b"]"#, r#"[".."]"#),
            (r#"["a","a","b"]"#, long.as_str()),
            (r#""stint":3600"#, r#""stint":0"#),
            (r#""stint":3600"#, r#""stint":4294967296"#),
            (r#""stint":3600"#, r#""stint":18446744073709551615"#),
            (r#""wall":600"#, r#""wall":4294967296"#),
            (r#""batch":30"#, r#""batch":0"#),
            (r#""memory":2147483648"#, r#""memory":0"#),
            (r#""processes":64"#, r#""processes":4194305"#),
            (r#""stint":3600"#, r#""stint":3600,"extra":1"#),
            (r#""stint":3600"#, r#""stint":3600,"build":"x""#),
            (r#""watchdog":900"#, r#""root":1"#),
        ] {
            let changed = text().replace(from, to);
            assert!(
                Document::parse(changed.as_bytes()).is_err(),
                "{from} -> {to} is refused"
            );
        }
        let edge = text()
            .replace(r#""stint":3600"#, r#""stint":4294967295"#)
            .replace(r#""processes":64"#, r#""processes":4194304"#);
        assert!(
            Document::parse(edge.as_bytes()).is_ok(),
            "the largest values"
        );
    }

    #[test]
    fn a_stored_copy_round_trips_and_refuses_a_bad_commit_record() {
        let digest = crate::file::sha256(b"x");
        let commit = crate::build::Commit {
            format: 1,
            commit: "a".repeat(40),
            build: digest.clone(),
            campaign: digest,
        };
        let copy = Assignment {
            document: Document::parse(text().as_bytes()).expect("parses"),
            commit,
        };
        let bytes = serde_json::to_vec(&copy).expect("serializes");
        assert_eq!(Assignment::parse(&bytes).expect("parses"), copy);
        let mut bad = copy.clone();
        bad.commit.build = "../x".into();
        let bytes = serde_json::to_vec(&bad).expect("serializes");
        let error = Assignment::parse(&bytes).expect_err("a traversal build");
        assert!(error.contains("build"), "{error}");
    }

    #[test]
    fn an_assignment_whose_sweep_argument_passes_131071_bytes_is_refused() {
        let profile = format!("\"{}\"", "p".repeat(super::PROFILE_MAX));
        let profiles = |count: usize| {
            let list = format!("[{}]", vec![profile.as_str(); count].join(","));
            text().replace(r#"["a","a","b"]"#, &list)
        };
        assert!(
            Document::parse(profiles(539).as_bytes()).is_ok(),
            "539 profiles join to 130976 bytes"
        );
        assert!(
            Document::parse(profiles(540).as_bytes()).is_err(),
            "540 profiles join to 131219 bytes"
        );
        let count = |key: usize| {
            let key = format!("\"{}\":1", "k".repeat(key));
            text().replace(r#""watchdog":900"#, &key)
        };
        assert!(
            Document::parse(count(131_069).as_bytes()).is_ok(),
            "a key=count of 131071 bytes"
        );
        assert!(
            Document::parse(count(131_070).as_bytes()).is_err(),
            "a key=count of 131072 bytes"
        );
    }

    #[test]
    fn an_assignment_whose_sweep_arguments_pass_their_execve_budget_is_refused() {
        // One profile `a` takes 1 + 1 + 8 bytes; a count `KEY=1` with a key of
        // k bytes takes 6 + 8 for `--set` and k + 3 + 8 for itself, so the
        // 8321 counts of 100-byte keys take 1040125 bytes.
        assert_eq!(std::mem::size_of::<usize>(), 8);
        let counts = |last: usize| {
            let mut counts: Vec<String> = (0..8_321)
                .map(|index| format!("\"{index:0100}\":1"))
                .collect();
            counts.push(format!("\"{}\":1", "x".repeat(last)));
            let document = text()
                .replace(r#""watchdog":900"#, &counts.join(","))
                .replace(r#"["a","a","b"]"#, r#"["a"]"#);
            Document::parse(document.as_bytes())
        };
        assert!(counts(8_416).is_ok(), "arguments of exactly 1048576 bytes");
        let refused = counts(8_417).expect_err("arguments of 1048577 bytes");
        assert!(refused.contains("1048577"), "{refused}");
    }
}
