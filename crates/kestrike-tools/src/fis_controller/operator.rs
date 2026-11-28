//! The check of the operator contract, which names the account, the region, the role, the volumes under
//! test with their instances, the effect timeout and the stop alarms, and the contract it admits.

use super::constants::OPERATOR_KEYS;
use super::error::Rejected;
use crate::json::{Integer, Object, Value};
use crate::python::repr;
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
    matches!(value, Value::Array(items) if items.iter().all(|item| matches!(item, Value::String(_))))
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
        let keys = Value::Array(keys.into_iter().cloned().map(Value::String).collect());
        return Err(Rejected::new(text!("operator contract keys ", repr(&keys))));
    }
    let mut texts = Vec::new();
    for name in ["account", "region", "role_arn"] {
        match field(contract, name) {
            Value::String(value) => texts.push(value.clone()),
            other => {
                return Err(Rejected::new(text!(
                    name,
                    " ",
                    repr(other),
                    " is not a string"
                )));
            }
        }
    }
    let [account, region, role_arn]: [Text; 3] = texts.try_into().expect("three names were read");
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
        Value::Object(map) if map.iter().all(|(_, instances)| strings(instances)) => map
            .iter()
            .map(|(volume, instances)| (volume.clone(), texts_of(instances)))
            .collect(),
        other => {
            return Err(Rejected::new(text!(
                "attachments ",
                repr(other),
                " is not a map from volume ID to a list of instance IDs"
            )));
        }
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

fn string_list(contract: &Object, name: &str) -> Result<Vec<Text>, Rejected> {
    let value = field(contract, name);
    if strings(value) {
        Ok(texts_of(value))
    } else {
        Err(Rejected::new(text!(
            name,
            " ",
            repr(value),
            " is not a list of strings"
        )))
    }
}

/// The strings of an array that [`strings`] admits.
fn texts_of(value: &Value) -> Vec<Text> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(text) => Some(text.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn is_role_arn(role_arn: &Text) -> bool {
    let codes: Vec<u32> = role_arn.code_points().collect();
    let fields: Vec<Text> = codes
        .split(|&code| code == u32::from(':'))
        .map(|field| {
            Text::from_code_points(field.iter().copied()).expect("a text's code points form a text")
        })
        .collect();
    fields.len() == 6
        && fields[0] == "arn"
        && fields[2] == "iam"
        && fields[3].is_empty()
        && !fields[1].is_empty()
        && fields[5].starts_with(&Text::from("role/"))
}

/// The name Python gives the type of the decoded value.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "dict",
        Value::Array(_) => "list",
        Value::String(_) => "str",
        Value::Integer(_) => "int",
        Value::Float(_) => "float",
        Value::Bool(_) => "bool",
        Value::Null => "NoneType",
    }
}
