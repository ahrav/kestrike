//! The check of the operator contract, which names the account, the region, the role, the volumes under
//! test with their instances, the effect timeout and the stop alarms, and the contract it admits.

use super::constants::OPERATOR_KEYS;
use super::error::Rejected;
use crate::json::{Integer, Object, Value};
use crate::python::{repr, texts_repr, type_name};
use crate::text::{Text, text};

/// An operator contract that [`check_operator`] admits: its strings, its lists of strings, its map from
/// volume to instances in document order, and its effect timeout, a whole number above zero.
#[derive(Clone, Debug, PartialEq)]
pub struct Operator {
    account: Text,
    region: Text,
    role_arn: Text,
    volumes: Vec<Text>,
    attachments: Vec<(Text, Vec<Text>)>,
    effect_timeout_seconds: Integer,
    stop_alarms: Vec<Text>,
}

impl Operator {
    pub fn account(&self) -> &Text {
        &self.account
    }

    pub fn region(&self) -> &Text {
        &self.region
    }

    pub fn role_arn(&self) -> &Text {
        &self.role_arn
    }

    pub fn volumes(&self) -> &[Text] {
        &self.volumes
    }

    /// Each volume the contract declares instances for, with those instances.
    pub fn attachments(&self) -> &[(Text, Vec<Text>)] {
        &self.attachments
    }

    pub fn effect_timeout_seconds(&self) -> &Integer {
        &self.effect_timeout_seconds
    }

    pub fn stop_alarms(&self) -> &[Text] {
        &self.stop_alarms
    }
}

/// `strings` holds for an array whose every item is a string, an empty one included.
pub fn strings(value: &Value) -> bool {
    string_items(value).is_some()
}

/// The strings of an array whose every item is a string, and none for any other value.
fn string_items(value: &Value) -> Option<Vec<Text>> {
    let Value::Array(items) = value else {
        return None;
    };
    items
        .iter()
        .map(|item| match item {
            Value::String(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// `check_operator` admits a decoded operator contract whose keys are [`OPERATOR_KEYS`] and whose fields
/// have the documented shapes.
///
/// # Errors
///
/// The first of these, in this order: a contract that is no object; other keys than [`OPERATOR_KEYS`];
/// an `account`, a `region` or a `role_arn`, in that order, that is no string; a `role_arn` that is no IAM
/// role ARN, six fields split at `:` of which the first is `arn`, the second is not empty, the third is
/// `iam`, the fourth is empty and the sixth starts with `role/`; `volumes`, then `stop_alarms`, that is no
/// list of strings; `attachments` that is no object of lists of strings; and an
/// `effect_timeout_seconds` that is no whole number above zero, a boolean included.
pub fn check_operator(operator: &Value) -> Result<Operator, Rejected> {
    let Value::Object(contract) = operator else {
        return Err(Rejected::new(text!(
            "the operator contract is ",
            type_name(operator),
            ", not an object"
        )));
    };
    let keyed = contract.len() == OPERATOR_KEYS.len()
        && contract
            .iter()
            .all(|(key, _)| OPERATOR_KEYS.iter().any(|name| *key == *name));
    if !keyed {
        let mut keys: Vec<&Text> = contract.iter().map(|(key, _)| key).collect();
        keys.sort();
        return Err(Rejected::new(text!(
            "operator contract keys ",
            texts_repr(keys)
        )));
    }
    let account = string_field(contract, "account")?;
    let region = string_field(contract, "region")?;
    let role_arn = string_field(contract, "role_arn")?;
    if !is_role_arn(&role_arn) {
        return Err(Rejected::new(text!(
            "role_arn ",
            role_arn.repr(),
            " is not an IAM role ARN; the target ARNs take its partition"
        )));
    }
    let volumes = string_list(contract, "volumes")?;
    let stop_alarms = string_list(contract, "stop_alarms")?;
    let attachments = match field(contract, "attachments") {
        Value::Object(map) => map
            .iter()
            .map(|(volume, instances)| Some((volume.clone(), string_items(instances)?)))
            .collect::<Option<Vec<_>>>(),
        _ => None,
    };
    let Some(attachments) = attachments else {
        return Err(Rejected::new(text!(
            "attachments ",
            repr(field(contract, "attachments")),
            " is not a map from volume ID to a list of instance IDs"
        )));
    };
    let effect_timeout_seconds = match field(contract, "effect_timeout_seconds") {
        Value::Integer(effect) if *effect > Integer::from(0u64) => effect.clone(),
        other => {
            return Err(Rejected::new(text!(
                "effect_timeout_seconds ",
                repr(other),
                " is not a positive whole number of seconds"
            )));
        }
    };
    Ok(Operator {
        account,
        region,
        role_arn,
        volumes,
        attachments,
        effect_timeout_seconds,
        stop_alarms,
    })
}

/// The member `name` of a contract whose keys are [`OPERATOR_KEYS`].
fn field<'a>(contract: &'a Object, name: &str) -> &'a Value {
    contract
        .get(name)
        .expect("the contract holds every key of OPERATOR_KEYS")
}

fn string_field(contract: &Object, name: &str) -> Result<Text, Rejected> {
    match field(contract, name) {
        Value::String(value) => Ok(value.clone()),
        other => Err(Rejected::new(text!(
            name,
            " ",
            repr(other),
            " is not a string"
        ))),
    }
}

fn string_list(contract: &Object, name: &str) -> Result<Vec<Text>, Rejected> {
    let value = field(contract, name);
    string_items(value)
        .ok_or_else(|| Rejected::new(text!(name, " ", repr(value), " is not a list of strings")))
}

/// Whether `role_arn` is six fields split at `:` of which the first is `arn`, the second is not empty,
/// the third is `iam`, the fourth is empty and the sixth starts with `role/`.
fn is_role_arn(role_arn: &Text) -> bool {
    let codes: Vec<u32> = role_arn.code_points().collect();
    let fields: Vec<&[u32]> = codes.split(|&code| code == u32::from(':')).collect();
    let spells = |field: &[u32], word: &str| field.iter().copied().eq(word.chars().map(u32::from));
    fields.len() == 6
        && spells(fields[0], "arn")
        && spells(fields[2], "iam")
        && fields[3].is_empty()
        && !fields[1].is_empty()
        && fields[5].len() >= "role/".len()
        && spells(&fields[5][.."role/".len()], "role/")
}
