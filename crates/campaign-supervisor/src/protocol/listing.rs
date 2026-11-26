//! The capability listing `--capabilities` prints: the listing, summary
//! and manifest versions, each manifest key's form, the recorder
//! constraints, the order of the held bounds, every admitted profile with
//! its class and held bounds, the topology of a history that composes
//! more than the fixed one, the failure of each history that expects no
//! pass, the profile family, the branch milestones
//! (fixed names and family patterns) and branch bounds, the fixed
//! topology and each cluster profile's declaration.
//!
//! The version, held, family, branch and topology lines appear once each,
//! with the capability and summary versions this parser reads; a
//! `version` key's form names the manifest line's version, and each
//! profile's and the family's held bounds name the held line's keys in its
//! order. The family's name ends in its `WORDS` pattern, its words are
//! distinct and hold no `-`, each word applies at most once and its members
//! are live, or control when planted. At least one key, constraint,
//! profile, milestone and cluster line appear; no name, key, field or field
//! value is empty, no two keys, constraints, profiles, milestones,
//! cluster lines or `fails` lines share a name, no declaration repeats a field, and every
//! cluster line names a listed profile, a `clients` count and `owners` and
//! `keys` ranges `LOW..HIGH` whose low end is at most its high end. The
//! parser rejects a cluster line if its profile declares its own topology.
//!
//! The parser reads capability versions 1 to 5. A history profile
//! line of version 2 or later may end with its own `owners=N clients=M`
//! after its held bounds; a version 1 profile line ends with its held
//! bounds, so every version 1 profile runs the fixed topology or its
//! cluster declaration. Version 3 prints the lines of version 2, and its
//! worker also has the rule catalog form. Version 4 adds one `fails` line
//! for each history that expects no pass: `NAME violation CODE RULE`,
//! where `CODE` is the obligation's code in a failure identity, or
//! `NAME unsuccessful WITNESS`, whose first 41 bytes, the most a summary
//! prints of a rule, are printable ASCII. Each names a listed history whose expected
//! ending is the line's, every such history has one, and an earlier
//! version prints none.
//!
//! At `summary: 1`, capability version 5 requires `windows` alongside
//! `stages` and `limits` in a recovery census.
//!
//! Output cut at a line boundary inside the trailing cluster lines still
//! parses with fewer clusters, so a listing counts only as the complete
//! output of a worker that exited with its documented status.

use std::collections::HashSet;

use super::Error;
use super::pairs::{Pairs, count, counts, fill, owned, repeated, words};
use super::summary::SUMMARY;

/// The capability listing version the worker crate prints.
pub const CAPABILITIES: u32 = 5;

/// The first capability version requiring window rows with a recovery stage census.
pub(super) const CRASH_WINDOWS: u32 = 5;

/// The first capability version whose worker has the rule catalog form.
pub const RULE_CATALOG: u32 = 3;

/// The first capability version whose listing declares the failure of
/// each history that expects no pass.
pub const DECLARED_FAILURES: u32 = 4;

const OLDEST_CAPABILITIES: u32 = 1;

/// The listing a worker's `--capabilities` prints; [`Listing::parse`]
/// holds its grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The capability listing version the worker printed.
    pub capabilities: u32,
    /// The summary format the worker prints, [`SUMMARY`].
    pub summary: u32,
    /// The manifest version the worker reads.
    pub manifest: u32,
    pub keys: Vec<Key>,
    pub constraints: Vec<String>,
    /// The keys a profile's held bounds name, in order.
    pub held: Vec<String>,
    pub profiles: Vec<Profile>,
    pub family: Family,
    /// The `milestone:` values in listing order: fixed milestone names,
    /// such as `pending-put`, and family patterns, such as `turn-N`, whose
    /// `N` a branch replaces with a decimal; a pattern itself names no
    /// milestone a branch accepts.
    pub milestones: Vec<String>,
    /// The most suffixes, and siblings per suffix, a branch takes; a
    /// branch requests between 1 and each bound.
    pub max_suffixes: u32,
    pub max_siblings: u32,
    pub topology: Fixed,
    /// Each cluster profile's ranges, dimensions and minima.
    pub clusters: Vec<Declared>,
}

/// An owner and client count: the fixed topology of every profile without
/// a cluster declaration or a topology of its own, or a history's own,
/// which a summary's `owners` and `clients` lines print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixed {
    pub owners: u64,
    pub clients: u64,
}

/// A manifest key and the form its value takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub name: String,
    pub form: Form,
}

/// The form a manifest key's value takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// The manifest version, which must equal this value.
    Version(u32),
    /// Printable text.
    Text,
    /// A SHA-256 digest as 64 lowercase hexadecimal digits.
    Sha256,
    /// A count between `min` and `max` inclusive.
    Count { min: u64, max: u64 },
}

/// A profile admission accepts by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub class: Class,
    /// How a composed history declares it ends; only a history has one.
    pub expected: Option<Expected>,
    pub support: String,
    pub campaign: String,
    /// The least count admission accepts for each held key, in order.
    pub held: Vec<(String, u64)>,
    /// The owner and client counts a history composes in place of the
    /// fixed topology, when it declares its own.
    pub topology: Option<Fixed>,
    /// The failure a history that expects no pass declares, in a listing
    /// of version [`DECLARED_FAILURES`] or later.
    pub fails: Option<Fails>,
}

impl Profile {
    /// Whether this is a history that expects no pass and declares no
    /// failure, which a sweep cannot judge.
    pub(crate) fn undeclared_history(&self) -> bool {
        self.class == Class::History
            && self.expected != Some(Expected::Pass)
            && self.fails.is_none()
    }
}

/// The failure a run of a history that expects no pass ends in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fails {
    /// A violation of the obligation a failure identity names with this
    /// code, under this rule.
    Violation(u8, String),
    /// An unsuccessful ending under this witness or premise.
    Unsuccessful(String),
}

impl Fails {
    /// The expected ending this failure is.
    fn expected(&self) -> Expected {
        match self {
            Self::Violation(..) => Expected::Violation,
            Self::Unsuccessful(_) => Expected::Unsuccessful,
        }
    }
}

words! {
    /// What a profile's runs exercise.
    Class {
        /// A live scenario whose pass earns credit.
        Live = "live",
        /// A planted defect the checks must catch.
        Control = "control",
        /// A recovery scenario judged by its campaign ledger.
        Recovery = "recovery",
        /// A composed history that declares how it ends.
        History = "history",
    }
}

words! {
    /// How a composed history declares it ends.
    Expected {
        /// The history passes.
        Pass = "pass",
        /// The history ends in a violation.
        Violation = "violation",
        /// The history ends unsuccessful.
        Unsuccessful = "unsuccessful",
    }
}

/// The profile family: each name of its prefix followed by one or more of
/// its words joined by `-`, each word at most once, is a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    /// The family line, named by its pattern such as `settled-WORDS`.
    pub declared: Declared,
    /// The pattern less its `WORDS`, such as `settled-`.
    pub prefix: String,
    pub words: Vec<String>,
    /// The least count admission accepts for each held key, in order.
    pub held: Vec<(String, u64)>,
}

/// A listing line of a name and its `key=value` fields, each key once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

impl Listing {
    /// The listing `text` prints.
    ///
    /// # Errors
    ///
    /// [`Error::Torn`] for output cut short; [`Error::Unpaired`] for a line
    /// or declaration field without its separator; [`Error::Missing`] for
    /// an absent once-printed line or a list with no line;
    /// [`Error::Repeated`] for a once-printed line, a name or a field
    /// printed twice; [`Error::Unknown`] for a line of another key;
    /// [`Error::Value`] for a value outside its form, among them a
    /// capability or summary version this parser does not read; and
    /// [`Error::Inconsistent`] for lines that disagree. A `fails` line in
    /// a listing below version [`DECLARED_FAILURES`] is a line of another
    /// key, and a history of that version or later that expects no pass
    /// and has no `fails` line lacks it.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        let capabilities = lines.take("capabilities", count_u32)?;
        if !(OLDEST_CAPABILITIES..=CAPABILITIES).contains(&capabilities) {
            return Err(Error::Value("capabilities"));
        }
        if lines.take("summary", count_u32)? != SUMMARY {
            return Err(Error::Value("summary"));
        }
        let (max_suffixes, max_siblings) = lines.take("branch", branch)?;
        let family = lines.one("family")?;
        let (family, rest) = family.split_once(' ').unwrap_or((family, ""));
        let mut listing = Self {
            capabilities,
            summary: SUMMARY,
            manifest: lines.take("manifest", count_u32)?,
            keys: named(lines.every("key"), "key", key)?,
            constraints: distinct(lines.every("constraint"), "constraint")?,
            held: distinct(lines.one("held")?.split(',').collect(), "held")?,
            profiles: named(lines.every("profile"), "profile", profile)?,
            family: self::family(declared(family, rest, "family")?)?,
            milestones: distinct(lines.every("milestone"), "milestone")?,
            max_suffixes,
            max_siblings,
            topology: lines.take("topology", fixed)?,
            clusters: named(lines.every("cluster"), "cluster", declared)?,
        };
        if capabilities >= DECLARED_FAILURES {
            for (name, fails) in named(lines.every("fails"), "fails", fails)? {
                let history = listing
                    .profiles
                    .iter_mut()
                    .find(|profile| profile.name == name)
                    .ok_or(Error::Inconsistent("a fails line names no listed profile"))?;
                if history.expected != Some(fails.expected()) {
                    return Err(Error::Inconsistent(
                        "a fails line names another ending than its profile expects",
                    ));
                }
                history.fails = Some(fails);
            }
            if listing.profiles.iter().any(Profile::undeclared_history) {
                return Err(Error::Missing("fails"));
            }
        }
        lines.finish()?;
        let required = [
            ("key", listing.keys.is_empty()),
            ("constraint", listing.constraints.is_empty()),
            ("profile", listing.profiles.is_empty()),
            ("milestone", listing.milestones.is_empty()),
            ("cluster", listing.clusters.is_empty()),
        ];
        if let Some((key, _)) = required.into_iter().find(|(_, empty)| *empty) {
            return Err(Error::Missing(key));
        }
        if capabilities == OLDEST_CAPABILITIES
            && listing
                .profiles
                .iter()
                .any(|profile| profile.topology.is_some())
        {
            return Err(Error::Value("profile"));
        }
        if listing
            .keys
            .iter()
            .any(|key| matches!(key.form, Form::Version(version) if version != listing.manifest))
        {
            return Err(Error::Inconsistent(
                "a version key's form names another manifest version",
            ));
        }
        let held_keys = |held: &[(String, u64)]| held.iter().map(|(key, _)| key).eq(&listing.held);
        if !held_keys(&listing.family.held) {
            return Err(Error::Inconsistent(
                "the family's held bounds name other keys than the held line",
            ));
        }
        if listing
            .profiles
            .iter()
            .any(|profile| !held_keys(&profile.held))
        {
            return Err(Error::Inconsistent(
                "a profile's held bounds name other keys than the held line",
            ));
        }
        for cluster in &listing.clusters {
            let Some(profile) = listing.profile(&cluster.name) else {
                return Err(Error::Inconsistent(
                    "a cluster line names no listed profile",
                ));
            };
            if profile.topology.is_some() {
                return Err(Error::Inconsistent(
                    "a cluster line names a profile with its own topology",
                ));
            }
            cluster.clients()?;
            cluster.owners()?;
            cluster.keys()?;
        }
        Ok(listing)
    }

    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|profile| profile.name == name)
    }

    /// Whether admission accepts the profile `name`: a listed profile, or
    /// a member of the family, whose name replaces the pattern's `WORDS`
    /// with one or more of its `words` joined by `-`, each at most once.
    pub fn admits(&self, name: &str) -> bool {
        if self.profile(name).is_some() {
            return true;
        }
        let Some(joined) = name.strip_prefix(self.family.prefix.as_str()) else {
            return false;
        };
        let mut seen = HashSet::new();
        joined
            .split('-')
            .all(|word| self.family.words.iter().any(|known| known == word) && seen.insert(word))
    }

    pub fn cluster(&self, name: &str) -> Option<&Declared> {
        self.clusters.iter().find(|cluster| cluster.name == name)
    }
}

/// A canonical count that fits in a `u32`.
fn count_u32(text: &str, key: &'static str) -> Result<u32, Error> {
    u32::try_from(count(text, key)?).map_err(|_| Error::Value(key))
}

/// `values`, refusing an empty or a repeated one.
fn distinct(values: Vec<&str>, key: &'static str) -> Result<Vec<String>, Error> {
    unique(&values, key, key)?;
    Ok(values.into_iter().map(ToOwned::to_owned).collect())
}

/// Refuses an empty value in `values` as [`Error::Value`] for `key`, and
/// a repeated one as [`Error::Repeated`] for `entry` and the value.
fn unique(values: &[&str], key: &'static str, entry: &str) -> Result<(), Error> {
    if values.iter().any(|value| value.is_empty()) {
        return Err(Error::Value(key));
    }
    match repeated(values) {
        Some(value) => Err(Error::Repeated(format!("{entry} {value}"))),
        None => Ok(()),
    }
}

/// `values`, each a name before its first space and the rest after it,
/// refusing a repeated name.
fn named<T>(
    values: Vec<&str>,
    key: &'static str,
    make: fn(&str, &str, &'static str) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let split: Vec<(&str, &str)> = values
        .iter()
        .map(|value| value.split_once(' ').unwrap_or((value, "")))
        .collect();
    let names: Vec<&str> = split.iter().map(|(name, _)| *name).collect();
    unique(&names, key, key)?;
    split
        .into_iter()
        .map(|(name, rest)| make(name, rest, key))
        .collect()
}

fn key(name: &str, form: &str, key: &'static str) -> Result<Key, Error> {
    let form = match (form, form.strip_prefix("version=")) {
        ("text", _) => Form::Text,
        ("sha256", _) => Form::Sha256,
        (_, Some(value)) => Form::Version(count_u32(value, key)?),
        _ => {
            let [min, max] = counts(form, "count min={} max={}", key)?;
            Form::Count { min, max }
        }
    };
    Ok(Key {
        name: name.to_owned(),
        form,
    })
}

fn profile(name: &str, rest: &str, key: &'static str) -> Result<Profile, Error> {
    let [class, rest] = fill(rest, "class={} {}", key)?;
    let class = Class::parse(class, key)?;
    let (expected, rest) = match rest.strip_prefix("expected=") {
        Some(_) => {
            let [expected, rest] = fill(rest, "expected={} {}", key)?;
            (Some(Expected::parse(expected, key)?), rest)
        }
        None => (None, rest),
    };
    if expected.is_some() != (class == Class::History) {
        return Err(Error::Inconsistent(
            "only a history profile declares its expected ending",
        ));
    }
    let [support, campaign, rest] = fill(rest, "support={} campaign={} held={}", key)?;
    let (held, topology) = match rest.split_once(' ') {
        Some((held, composed)) => {
            let [owners, clients] = counts(composed, "owners={} clients={}", key)?;
            (held, Some(Fixed { owners, clients }))
        }
        None => (rest, None),
    };
    if topology.is_some() && class != Class::History {
        return Err(Error::Inconsistent(
            "only a history profile declares its own topology",
        ));
    }
    Ok(Profile {
        name: name.to_owned(),
        class,
        expected,
        support: owned(support, key)?,
        campaign: owned(campaign, key)?,
        held: held_bounds(held, key)?,
        topology,
        fails: None,
    })
}

/// The history `name` and the failure the rest of its `fails` line
/// declares: `violation`, the obligation's code from 1 to 255 and the
/// rule, or `unsuccessful` and the witness.
fn fails(name: &str, rest: &str, key: &'static str) -> Result<(String, Fails), Error> {
    let (ending, text) = rest.split_once(' ').ok_or(Error::Value(key))?;
    let fails = match Expected::parse(ending, key)? {
        Expected::Pass => return Err(Error::Value(key)),
        Expected::Violation => {
            let (code, rule) = text.split_once(' ').ok_or(Error::Value(key))?;
            let obligation = u8::try_from(count(code, key)?).map_err(|_| Error::Value(key))?;
            if obligation == 0 {
                return Err(Error::Value(key));
            }
            Fails::Violation(obligation, owned(rule, key)?)
        }
        Expected::Unsuccessful => {
            let witness = owned(text, key)?;
            if !witness
                .as_bytes()
                .iter()
                .take(41)
                .all(|byte| (b' '..=b'~').contains(byte))
            {
                return Err(Error::Value(key));
            }
            Fails::Unsuccessful(witness)
        }
    };
    Ok((owned(name, key)?, fails))
}

/// Held bounds `KEY=LEAST,...`, each key named.
fn held_bounds(text: &str, key: &'static str) -> Result<Vec<(String, u64)>, Error> {
    let bound = |bound: &str| {
        let [held, least] = fill(bound, "{}={}", key)?;
        Ok((owned(held, key)?, count(least, key)?))
    };
    text.split(',').map(bound).collect()
}

/// A declaration's name and its `key=value` fields, each field and value
/// nonempty and each field once.
fn declared(name: &str, rest: &str, key: &'static str) -> Result<Declared, Error> {
    let name = owned(name, key)?;
    let fields = rest
        .split(' ')
        .map(|field| match field.split_once('=') {
            Some((field, value)) if !field.is_empty() && !value.is_empty() => Ok((field, value)),
            Some(_) => Err(Error::Value(key)),
            None if field.is_empty() => Err(Error::Value(key)),
            None => Err(Error::Unpaired(field.to_owned())),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let names: Vec<&str> = fields.iter().map(|(field, _)| *field).collect();
    unique(&names, key, &format!("{key} field"))?;
    let fields = fields
        .into_iter()
        .map(|(field, value)| (field.to_owned(), value.to_owned()))
        .collect();
    Ok(Declared { name, fields })
}

/// The family `declared`: its name ends in `WORDS`, its distinct `words`
/// and its `held` bounds are present, its `each` policy is the
/// at-most-once rule [`Listing::admits`] applies, and its `class` is the
/// live-or-control rule a member's summary is judged by.
fn family(declared: Declared) -> Result<Family, Error> {
    let key = "family";
    let (
        Some(prefix),
        Some(words),
        Some(held),
        Some("at-most-once"),
        Some("live,control-when-planted"),
    ) = (
        declared.name.strip_suffix("WORDS"),
        declared.field("words"),
        declared.field("held"),
        declared.field("each"),
        declared.field("class"),
    )
    else {
        return Err(Error::Value(key));
    };
    let (prefix, words, held) = (
        prefix.to_owned(),
        distinct(words.split(',').collect(), key)?,
        held_bounds(held, key)?,
    );
    // A member's name joins its words with `-`, so a word holding one
    // could never be read back.
    if words.iter().any(|word| word.contains('-')) {
        return Err(Error::Value(key));
    }
    Ok(Family {
        declared,
        prefix,
        words,
        held,
    })
}

impl Declared {
    /// The value of the field `key`.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == key)
            .map(|(_, value)| value.as_str())
    }

    /// The client count a cluster declaration's `clients` field fixes,
    /// which a cluster summary's `clients` line prints.
    ///
    /// # Errors
    ///
    /// [`Error::Value`] for a missing field or one that is no count.
    pub fn clients(&self) -> Result<u64, Error> {
        self.field("clients")
            .ok_or(Error::Value("cluster"))
            .and_then(|clients| count(clients, "cluster"))
    }

    /// The inclusive owner range `LOW..HIGH` a cluster declaration's
    /// `owners` field fixes, which a cluster run draws its owners from.
    ///
    /// # Errors
    ///
    /// [`Error::Value`] for a missing field, one that is no range of two
    /// counts, or one whose low end exceeds its high end.
    pub fn owners(&self) -> Result<(u64, u64), Error> {
        self.range("owners")
    }

    /// The inclusive key range `LOW..HIGH` a cluster declaration's `keys`
    /// field fixes; a run draws its key count from it, raised to its owner
    /// count.
    ///
    /// # Errors
    ///
    /// As [`Declared::owners`].
    pub fn keys(&self) -> Result<(u64, u64), Error> {
        self.range("keys")
    }

    fn range(&self, key: &str) -> Result<(u64, u64), Error> {
        let field = self.field(key).ok_or(Error::Value("cluster"))?;
        let [low, high] = counts(field, "{}..{}", "cluster")?;
        if low > high {
            return Err(Error::Value("cluster"));
        }
        Ok((low, high))
    }
}

fn fixed(text: &str, key: &'static str) -> Result<Fixed, Error> {
    let [owners, clients] = counts(
        text,
        "owners={} clients={} configurable=no; cluster profiles draw theirs",
        key,
    )?;
    Ok(Fixed { owners, clients })
}

/// The branch line's `suffixes=1..N siblings=1..M`.
fn branch(text: &str, key: &'static str) -> Result<(u32, u32), Error> {
    let [suffixes, siblings] = fill(text, "suffixes=1..{} siblings=1..{}", key)?;
    Ok((count_u32(suffixes, key)?, count_u32(siblings, key)?))
}
