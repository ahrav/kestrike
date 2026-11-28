//! The checks of the FIS profiles file, which declares each profile the controller can run, and of the
//! profiles and the episode name one run chooses from it. [`check_manifest`] admits the file as a
//! [`Manifest`], which the checks of a run's choice take.

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

/// A FIS profiles file that [`check_manifest`] admits: an object whose `profiles` is an object of
/// profiles, each an object whose `attachment` is one of [`ATTACHMENT_MODES`].
#[derive(Clone, Copy, Debug)]
pub struct Manifest<'a> {
    profiles: &'a Object,
}

impl<'a> Manifest<'a> {
    /// The declared profiles, in document order.
    pub fn profiles(&self) -> &'a Object {
        self.profiles
    }

    /// The profile `name`.
    ///
    /// # Errors
    ///
    /// A name the file declares no profile under.
    pub fn profile(&self, name: &Text) -> Result<&'a Value, Rejected> {
        self.profiles.get_text(name).ok_or_else(|| {
            Rejected::new(text!(
                "the FIS profiles file declares no profile ",
                name.repr()
            ))
        })
    }
}

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
/// under `profiles`, a profile that is no object, a file without `eligible_types`, an `eligible_types`
/// that is no object, array or string, an action that is no string where `eligible_types` is a string,
/// and an absent action that `eligible_types` lists as null.
pub fn check_manifest(manifest: &Value) -> Result<Manifest<'_>, Rejected> {
    let Value::Object(file) = manifest else {
        return Err(Rejected::new(Text::from(
            "the FIS profiles file is not an object",
        )));
    };
    let Some(Value::Object(profiles)) = file.get("profiles") else {
        return Err(Rejected::new(Text::from(
            "the FIS profiles file holds no object under profiles",
        )));
    };
    for (name, profile) in profiles.iter() {
        if let Err(error) = episode_name(name) {
            let sentence = error
                .sentence()
                .map_or_else(|| Text::from(error.to_string()), Clone::clone);
            return Err(Rejected::new(text!("manifest profile ", sentence)));
        }
        let Value::Object(fields) = profile else {
            return Err(of_profile(name, " is not an object"));
        };
        if !is_mode(fields.get("attachment")) {
            return Err(unknown_mode(name, fields.get("attachment")));
        }
        let action = fields.get("action");
        let eligible = file.get("eligible_types").ok_or_else(|| {
            Rejected::new(Text::from("the FIS profiles file holds no eligible_types"))
        })?;
        if !listed(name, action, eligible)? {
            return Err(of_profile(
                name,
                text!(
                    " names action ",
                    shown(action),
                    ", which the manifest's eligible_types does not list"
                ),
            ));
        }
        match action {
            Some(Value::String(action)) if *action == LATENCY_ACTION => {}
            Some(_) => continue,
            None => return Err(of_profile(name, " holds no action")),
        }
        let mut enabled = false;
        for key in ["read", "write"] {
            match fields.get(key) {
                Some(Value::Bool(flag)) => enabled |= *flag,
                other => {
                    return Err(of_profile(
                        name,
                        text!(" has ", key, " ", shown(other), ", not a JSON boolean"),
                    ));
                }
            }
        }
        if !enabled {
            return Err(of_profile(
                name,
                " enables no direction; the template takes 100 percent of the direction under test",
            ));
        }
        let latency = fields.get("latency_ms");
        if !matches!(latency, Some(Value::Integer(_))) {
            return Err(of_profile(
                name,
                text!(
                    " has latency_ms ",
                    shown(latency),
                    ", not a whole number of milliseconds"
                ),
            ));
        }
    }
    Ok(Manifest { profiles })
}

/// `check_attachments` admits a choice of profiles one volume can serve: profiles of one attachment mode,
/// since a volume's Multi-Attach setting admits one, and, for the mode `multi-attach-one`, a contract that
/// declares exactly one instance for each of its volumes, in the order of `volumes`.
///
/// # Errors
///
/// A name of `names` the file declares no profile under; then profiles of two modes, with the modes
/// sorted; then the first volume of a `multi-attach-one` choice with other than one declared instance.
pub fn check_attachments(
    manifest: &Manifest<'_>,
    names: &[Text],
    operator: &Operator,
) -> Result<(), Rejected> {
    let mut modes: Vec<&Text> = Vec::new();
    for name in names {
        modes.push(mode(manifest.profile(name)?));
    }
    modes.sort();
    modes.dedup();
    if modes.len() > 1 {
        return Err(Rejected::new(text!(
            "the chosen profiles name the attachment modes ",
            texts_repr(modes),
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
            return Err(Rejected::new(text!(
                "attachments declares ",
                texts_repr(instances),
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
/// A file that declares no profile; then the tag's overflow; then the receipt name's.
pub fn check_episode(episode: &Text, manifest: &Manifest<'_>) -> Result<(), Rejected> {
    let widest = manifest
        .profiles()
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

/// The member `key` of a profile.
///
/// # Errors
///
/// A profile that is no object or holds no `key`.
pub(super) fn member<'a>(profile: &'a Value, key: &str) -> Result<&'a Value, Rejected> {
    match profile {
        Value::Object(fields) => fields.get(key),
        _ => None,
    }
    .ok_or_else(|| Rejected::new(text!("a FIS profile holds no ", key)))
}

/// The attachment mode of a profile that [`check_manifest`] admitted.
fn mode(profile: &Value) -> &Text {
    match profile {
        Value::Object(fields) => match fields.get("attachment") {
            Some(Value::String(mode)) => mode,
            _ => unreachable!("an admitted profile declares one of ATTACHMENT_MODES"),
        },
        _ => unreachable!("an admitted profile is an object"),
    }
}

/// Whether the profile `name`'s `action`, `None` where absent, is in `eligible`: a key of an object, an
/// item of an array that [`same_item`] finds equal to it, or a substring of a string. An action that is
/// an array or an object is no key of an object.
///
/// # Errors
///
/// An action that is no string where `eligible` is a string, and an `eligible` that is a number, a
/// boolean or null.
fn listed(name: &Text, action: Option<&Value>, eligible: &Value) -> Result<bool, Rejected> {
    let absent = Value::Null;
    let action = action.unwrap_or(&absent);
    match (eligible, action) {
        (Value::Object(types), Value::String(action)) => Ok(types.get_text(action).is_some()),
        (Value::Object(_), _) => Ok(false),
        (Value::Array(types), _) => Ok(types.iter().any(|listed| same_item(listed, action))),
        (Value::String(types), Value::String(action)) => Ok(substring(types, action)),
        (Value::String(_), _) => Err(of_profile(
            name,
            text!(
                " names action ",
                repr(action),
                ", which is no string to find in the manifest's eligible_types"
            ),
        )),
        _ => Err(Rejected::new(text!(
            "the manifest's eligible_types ",
            repr(eligible),
            " lists no action"
        ))),
    }
}

/// Python's `==` between decoded values as `in` and a list's `==` apply it, which take an item that is
/// the same object as equal first: numbers are equal by value, exactly across whole numbers, floats and
/// booleans, and two `nan` are equal, since the decoder gives every `nan` of a document as one object;
/// arrays are equal by their items in order, objects by their members in any order, and strings and null
/// by themselves.
fn same_item(left: &Value, right: &Value) -> bool {
    match (Seconds::of(left), Seconds::of(right)) {
        (Some(Seconds::Real(left)), Some(Seconds::Real(right))) if left.is_nan() => right.is_nan(),
        (Some(left), Some(right)) => left.order(&right) == Some(Ordering::Equal),
        (None, None) => match (left, right) {
            (Value::Array(left), Value::Array(right)) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| same_item(left, right))
            }
            (Value::Object(left), Value::Object(right)) => {
                left.len() == right.len()
                    && left.iter().all(|(key, value)| {
                        right
                            .get_text(key)
                            .is_some_and(|other| same_item(value, other))
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
    let modes: Vec<Text> = ATTACHMENT_MODES.iter().copied().map(Text::from).collect();
    of_profile(
        name,
        text!(
            " declares attachment mode ",
            shown(attachment),
            "; the controller implements ",
            texts_repr(&modes)
        ),
    )
}

/// The rejection `manifest profile '<name>'` and `rest`.
fn of_profile(name: &Text, rest: impl crate::text::Piece) -> Rejected {
    Rejected::new(text!("manifest profile ", name.repr(), rest))
}

/// Python's `repr` of a member read with `get`, `None` for an absent one.
fn shown(member: Option<&Value>) -> String {
    member.map_or_else(|| "None".to_owned(), repr)
}

/// Python's `repr` of a list of strings.
pub(super) fn texts_repr<'a>(texts: impl IntoIterator<Item = &'a Text>) -> String {
    repr(&Value::Array(
        texts.into_iter().cloned().map(Value::String).collect(),
    ))
}
