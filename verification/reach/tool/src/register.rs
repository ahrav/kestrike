//! Invariant: `Register::read` of `render`'s output gives back an equal
//! register. `render` writes each `Reason` and each `Row` on a separate
//! line, with fields in declaration order.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The states of a row.
pub const STATES: [&str; 4] = ["reached", "unreached", "unplaced", "unmeasured"];

/// The `measured` classes of an `unreached` row and of a reason row.
pub const MEASURED: [&str; 3] = ["file-not-run", "function-not-entered", "not-constructed"];

/// The `cause` values of an `unplaced` row.
pub const CAUSES: [&str; 3] = ["no-site", "no-region", "unplaceable"];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub commit: String,
    pub toolchain: String,
    pub flags: String,
    pub build: String,
    pub worker: String,
    pub profiles: Vec<String>,
    pub roots: String,
    /// `counts` maps profile names to count overrides.
    pub counts: BTreeMap<String, String>,
    pub no_pass: Vec<String>,
    #[serde(default)]
    pub tool: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Totals {
    pub rows: u64,
    pub reached: u64,
    pub unreached: u64,
    pub unplaced: u64,
    pub file_not_run: u64,
    pub function_not_entered: u64,
    pub not_constructed: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Live {
    pub unplaced: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub id: String,
    pub measured: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<(String, String)>,
    /// `kind` classifies what rows citing this reason lack.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// `missing` names what rows citing this reason lack.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub missing: String,
    /// `sentence` is the tool's own text field: deserialization requires
    /// it, and `measure` writes it empty on a new reason and keeps it on an
    /// earlier one. The hand-written text of a reason is `missing`.
    pub sentence: String,
}

/// `present` reads a field that, when the register holds it, holds a value;
/// `null` is refused, so a row field the state forbids cannot pass as
/// absent.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    #[serde(rename = "enum")]
    pub enum_path: String,
    pub variant: String,
    /// Each construction site as its file, function and form.
    pub sites: Vec<(String, String, String)>,
    pub state: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub count: Option<u64>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub measured: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub cause: Option<String>,
}

impl Row {
    pub fn key(&self) -> (&str, &str) {
        (&self.enum_path, &self.variant)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub run: Run,
    pub totals: Totals,
    pub live: Live,
    pub reasons: Vec<Reason>,
    pub rows: Vec<Row>,
}

impl Register {
    /// # Errors
    ///
    /// If `text` fails to deserialize as a `Register`, `read` prefixes the
    /// parser's message with `register: `; a `null` field is a parse
    /// error. It also returns an error for a repeated row or reason id, an
    /// unknown state, class or cause, a row whose fields differ from its
    /// state's set, a `reached` row whose count is zero, an `unreached` row
    /// whose count is positive, and an `unreached` row whose reason is no
    /// reason row of its class.
    pub fn read(text: &str) -> Result<Self, String> {
        let register: Self =
            serde_json::from_str(text).map_err(|error| format!("register: {error}"))?;
        register.validate()?;
        Ok(register)
    }

    fn validate(&self) -> Result<(), String> {
        let mut ids = BTreeMap::new();
        for reason in &self.reasons {
            if ids
                .insert(reason.id.as_str(), reason.measured.as_str())
                .is_some()
                || !MEASURED.contains(&reason.measured.as_str())
            {
                return Err(format!(
                    "register: the reason row {} is repeated or has an unknown class",
                    reason.id
                ));
            }
        }
        let mut keys = BTreeSet::new();
        for row in &self.rows {
            let name = format!("{}::{}", row.enum_path, row.variant);
            if !keys.insert(row.key()) {
                return Err(format!("register: a second row for {name}"));
            }
            if !STATES.contains(&row.state.as_str()) {
                return Err(format!(
                    "register: the row {name} has the unknown state {}",
                    row.state
                ));
            }
            let measured = row.measured.as_deref();
            let cause = row.cause.as_deref();
            let fits = match row.state.as_str() {
                "reached" => {
                    row.count.is_some_and(|count| count > 0)
                        && measured.is_none()
                        && row.reason.is_none()
                        && cause.is_none()
                }
                "unreached" => {
                    row.count == Some(0)
                        && measured.is_some_and(|measured| MEASURED.contains(&measured))
                        && row
                            .reason
                            .as_deref()
                            .is_some_and(|id| ids.get(id).copied() == measured)
                        && cause.is_none()
                }
                "unplaced" => {
                    row.count.is_none()
                        && measured.is_none()
                        && row.reason.is_none()
                        && cause.is_some_and(|cause| CAUSES.contains(&cause))
                }
                "unmeasured" => {
                    row.count.is_none()
                        && measured.is_none()
                        && row.reason.is_none()
                        && cause.is_none()
                }
                _ => false,
            };
            if !fits {
                return Err(format!(
                    "register: the row {name} has state {} with fields that do not fit it",
                    row.state
                ));
            }
        }
        Ok(())
    }

    pub fn render(&self) -> String {
        let mut out = String::from("{\n");
        out.push_str(&format!("\"run\": {},\n", json(&self.run)));
        out.push_str(&format!("\"totals\": {},\n", json(&self.totals)));
        out.push_str(&format!("\"live\": {},\n", json(&self.live)));
        out.push_str("\"reasons\": [\n");
        out.push_str(&lines(self.reasons.iter().map(json)));
        out.push_str("],\n\"rows\": [\n");
        out.push_str(&lines(self.rows.iter().map(json)));
        out.push_str("]\n}\n");
        out
    }
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("a register value encodes")
}

fn lines(items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.collect();
    let mut out = items.join(",\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}
