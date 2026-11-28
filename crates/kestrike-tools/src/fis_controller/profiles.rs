//! The checks of the FIS profiles file, which declares each profile the controller can run, and of the
//! profiles and the episode name one run chooses from it.

use std::cmp::Ordering;

use super::constants::{ATTACHMENT_MODES, NAME_MAX, TAG_VALUE_MAX};
use super::error::Rejected;
use super::operator::Operator;
use super::seconds::Seconds;
use crate::hardware_lane::episode_name;
use crate::json::{Object, Value};
use crate::python::repr;
use crate::text::{Text, text};

/// The action whose profiles hold direction flags and a latency.
const LATENCY_ACTION: &str = "aws:ebs:volume-io-latency";

/// The mode of a profile that admits exactly the one declared attachment.
const MULTI_ATTACH_ONE: &str = ATTACHMENT_MODES[1];

/// `check_manifest` admits a profiles file whose every profile the controller can run as declared. It
/// visits the profiles in document order and, in each, checks in this order: the profile's name, one
/// plain file name component, since the campaign appends it to the episode name the marks, the receipt
/// and the observer log are named after; its `attachment`, one of [`ATTACHMENT_MODES`]; its `action`, in
/// the file's `eligible_types` as Python's `in` finds it there; and for the latency action, its `read` and
/// `write`, each a boolean, at least one of them true, and its `latency_ms`, a whole number that is no
/// boolean.
///
/// # Errors
///
/// The first failed check. Before it, in the order the checks read them: a file that holds no object
/// under `profiles`, a profile that is no object, a file without `eligible_types`, an action that
/// `eligible_types` cannot be searched for, and an absent action that `eligible_types` lists as null.
pub fn check_manifest(manifest: &Value) -> Result<(), Rejected> {
    for (name, profile) in profiles(manifest)?.iter() {
        if let Err(error) = episode_name(name) {
            let sentence = error
                .sentence()
                .map_or_else(|| Text::from(error.to_string()), Clone::clone);
            return Err(Rejected::new(text!("manifest profile ", sentence)));
        }
        let Value::Object(fields) = profile else {
            return Err(Rejected::new(text!(
                "manifest profile ",
                name.repr(),
                " is not an object"
            )));
        };
        if !is_mode(fields.get("attachment")) {
            return Err(unknown_mode(name, fields.get("attachment")));
        }
        let action = fields.get("action");
        if !listed(name, action, eligible(manifest)?)? {
            return Err(Rejected::new(text!(
                "manifest profile ",
                name.repr(),
                " names action ",
                shown(action),
                ", which the manifest's eligible_types does not list"
            )));
        }
        match action {
            Some(Value::String(action)) if *action == LATENCY_ACTION => {}
            Some(_) => continue,
            None => {
                return Err(Rejected::new(text!(
                    "manifest profile ",
                    name.repr(),
                    " holds no action"
                )));
            }
        }
        let mut enabled = false;
        for key in ["read", "write"] {
            match fields.get(key) {
                Some(Value::Bool(flag)) => enabled |= *flag,
                other => {
                    return Err(Rejected::new(text!(
                        "manifest profile ",
                        name.repr(),
                        " has ",
                        key,
                        " ",
                        shown(other),
                        ", not a JSON boolean"
                    )));
                }
            }
        }
        if !enabled {
            return Err(Rejected::new(text!(
                "manifest profile ",
                name.repr(),
                " enables no direction; the template takes 100 percent of the direction under test"
            )));
        }
        let latency = fields.get("latency_ms");
        if !matches!(latency, Some(Value::Integer(_))) {
            return Err(Rejected::new(text!(
                "manifest profile ",
                name.repr(),
                " has latency_ms ",
                shown(latency),
                ", not a whole number of milliseconds"
            )));
        }
    }
    Ok(())
}

/// `check_attachments` admits a choice of profiles one volume can serve: profiles of one attachment mode,
/// since a volume's Multi-Attach setting admits one, and, for the mode `multi-attach-one`, a contract that
/// declares exactly one instance for each of its volumes, in the order of `volumes`.
///
/// # Errors
///
/// Profiles of two modes, with the modes sorted, then the first volume of a `multi-attach-one` choice with
/// other than one declared instance; before them a file that holds no object under `profiles`, or a name
/// of `names` that is no profile of it or whose profile holds no string under `attachment`.
pub fn check_attachments(
    manifest: &Value,
    names: &[Text],
    operator: &Operator,
) -> Result<(), Rejected> {
    let mut modes: Vec<&Text> = Vec::new();
    for name in names {
        let attachment = match chosen(manifest, name)? {
            Value::Object(fields) => fields.get("attachment"),
            _ => None,
        };
        match attachment {
            Some(Value::String(mode)) => modes.push(mode),
            other => return Err(unknown_mode(name, other)),
        }
    }
    modes.sort();
    modes.dedup();
    if modes.len() > 1 {
        let modes = Value::Array(modes.into_iter().cloned().map(Value::String).collect());
        return Err(Rejected::new(text!(
            "the chosen profiles name the attachment modes ",
            repr(&modes),
            "; one volume serves one mode"
        )));
    }
    if !matches!(modes.as_slice(), [mode] if **mode == MULTI_ATTACH_ONE) {
        return Ok(());
    }
    for volume in operator.volumes() {
        let instances = operator
            .attachments()
            .iter()
            .find(|(named, _)| named == volume)
            .map_or(&[][..], |(_, instances)| instances.as_slice());
        if instances.len() != 1 {
            let instances = Value::Array(instances.iter().cloned().map(Value::String).collect());
            return Err(Rejected::new(text!(
                "attachments declares ",
                repr(&instances),
                " for ",
                volume,
                "; a multi-attach-one profile takes exactly one instance"
            )));
        }
    }
    Ok(())
}

/// `check_episode` admits an episode name whose derived names fit their limits. The campaign's episode is
/// `{episode}-{profile}`; with the file's longest profile name, the template's `episode` tag fits
/// [`TAG_VALUE_MAX`] characters, and the receipt's temporary file
/// `fis-{profile}-{episode}-{profile}.json.partial`, the longest derived file name, fits [`NAME_MAX`]
/// characters. Lengths count code points.
///
/// # Errors
///
/// The tag's overflow, then the receipt name's; before them a file that holds no object under `profiles`
/// or one that declares no profile.
pub fn check_episode(episode: &Text, manifest: &Value) -> Result<(), Rejected> {
    let widest = profiles(manifest)?
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .ok_or_else(|| Rejected::new(Text::from("the FIS profiles file declares no profile")))?;
    let tag = episode.len() + 1 + widest;
    if tag > TAG_VALUE_MAX {
        return Err(Rejected::new(text!(
            "episode ",
            episode.repr(),
            " is ",
            tag - TAG_VALUE_MAX,
            " characters too long for the template's episode tag"
        )));
    }
    let receipt = "fis-".len() + widest + 1 + episode.len() + 1 + widest + ".json.partial".len();
    if receipt > NAME_MAX {
        return Err(Rejected::new(text!(
            "episode ",
            episode.repr(),
            " is ",
            receipt - NAME_MAX,
            " characters too long for the receipt file name derived from it"
        )));
    }
    Ok(())
}

/// The profiles the file declares, in document order.
///
/// # Errors
///
/// A file that is no object or holds no object under `profiles`.
pub(super) fn profiles(manifest: &Value) -> Result<&Object, Rejected> {
    match manifest {
        Value::Object(file) => match file.get("profiles") {
            Some(Value::Object(profiles)) => Ok(profiles),
            _ => Err(Rejected::new(Text::from(
                "the FIS profiles file holds no object under profiles",
            ))),
        },
        _ => Err(Rejected::new(Text::from(
            "the FIS profiles file is not an object",
        ))),
    }
}

/// The profile `name` of the file.
///
/// # Errors
///
/// A file that holds no object under `profiles`, or no profile under `name`.
pub(super) fn chosen<'a>(manifest: &'a Value, name: &Text) -> Result<&'a Value, Rejected> {
    profiles(manifest)?.get_text(name).ok_or_else(|| {
        Rejected::new(text!(
            "the FIS profiles file declares no profile ",
            name.repr()
        ))
    })
}

/// The file's `eligible_types`.
///
/// # Errors
///
/// A file that is no object or holds no `eligible_types`.
fn eligible(manifest: &Value) -> Result<&Value, Rejected> {
    match manifest {
        Value::Object(file) => file.get("eligible_types").ok_or_else(|| {
            Rejected::new(Text::from("the FIS profiles file holds no eligible_types"))
        }),
        _ => Err(Rejected::new(Text::from(
            "the FIS profiles file is not an object",
        ))),
    }
}

/// Whether the profile `name`'s `action`, `None` where absent, is in `eligible`: a key of an object, an
/// item of an array equal to it, or a substring of a string.
///
/// # Errors
///
/// An action that is an array or an object where `eligible` is an object, an action that is no string
/// where it is a string, and an `eligible` that is a number, a boolean or null.
fn listed(name: &Text, action: Option<&Value>, eligible: &Value) -> Result<bool, Rejected> {
    let absent = Value::Null;
    let action = action.unwrap_or(&absent);
    let unlisted = || {
        Rejected::new(text!(
            "manifest profile ",
            name.repr(),
            " names action ",
            repr(action),
            ", which the manifest's eligible_types does not list"
        ))
    };
    match (eligible, action) {
        (Value::Object(types), Value::String(action)) => Ok(types.get_text(action).is_some()),
        (Value::Object(_), Value::Array(_) | Value::Object(_)) => Err(unlisted()),
        (Value::Object(_), _) => Ok(false),
        (Value::Array(types), _) => Ok(types.iter().any(|listed| equal(listed, action))),
        (Value::String(types), Value::String(action)) => Ok(substring(types, action)),
        (Value::String(_), _) => Err(Rejected::new(text!(
            "manifest profile ",
            name.repr(),
            " names action ",
            repr(action),
            ", which is no string to find in the manifest's eligible_types"
        ))),
        _ => Err(Rejected::new(text!(
            "the manifest's eligible_types ",
            repr(eligible),
            " lists no action"
        ))),
    }
}

/// Python's `left == right` for decoded values: numbers by value, exact across whole numbers, floats and
/// booleans, with `nan` equal to nothing; arrays by their items in order; objects by their members in
/// any order; and strings and null by themselves.
fn equal(left: &Value, right: &Value) -> bool {
    match (Seconds::of(left), Seconds::of(right)) {
        (Some(left), Some(right)) => left.order(&right) == Some(Ordering::Equal),
        (None, None) => match (left, right) {
            (Value::Array(left), Value::Array(right)) => {
                left.len() == right.len() && left.iter().zip(right).all(|(l, r)| equal(l, r))
            }
            (Value::Object(left), Value::Object(right)) => {
                left.len() == right.len()
                    && left.iter().all(|(key, value)| {
                        right.get_text(key).is_some_and(|other| equal(value, other))
                    })
            }
            _ => left == right,
        },
        _ => false,
    }
}

fn substring(text: &Text, part: &Text) -> bool {
    let hay: Vec<u32> = text.code_points().collect();
    let needle: Vec<u32> = part.code_points().collect();
    needle.is_empty()
        || hay
            .windows(needle.len())
            .any(|window| window == needle.as_slice())
}

fn is_mode(attachment: Option<&Value>) -> bool {
    matches!(attachment, Some(Value::String(mode)) if ATTACHMENT_MODES.iter().any(|known| *mode == *known))
}

fn unknown_mode(name: &Text, attachment: Option<&Value>) -> Rejected {
    let modes = Value::Array(
        ATTACHMENT_MODES
            .iter()
            .map(|mode| Value::String(Text::from(*mode)))
            .collect(),
    );
    Rejected::new(text!(
        "manifest profile ",
        name.repr(),
        " declares attachment mode ",
        shown(attachment),
        "; the controller implements ",
        repr(&modes)
    ))
}

/// Python's `repr` of a member read with `get`, `None` for an absent one.
fn shown(member: Option<&Value>) -> String {
    member.map_or_else(|| "None".to_owned(), repr)
}
