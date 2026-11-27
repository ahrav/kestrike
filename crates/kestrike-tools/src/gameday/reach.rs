//! The reach oracle's conditions that stand before the stop, read from the roles mark and the package.

use super::constants::{MIN_OWNED, MIN_STOOD};
use super::refusal::said;
use crate::json::{Object, Value};
use crate::text::Text;

/// `roles_reach` lists the reach's unmet pre-stop conditions: the target owns fewer than [`MIN_OWNED`]
/// shards or stands by for fewer than [`MIN_STOOD`], and for each owned shard in the package's order, its
/// standby is missing or is the target, has no state read, reports the target's instance, or reads
/// other than `running` and `healthy`. An empty list means the conditions are met.
///
/// # Panics
///
/// When `p` has not passed [`check_package`](super::check_package) or `roles` does not conform to the
/// schema of `injection/roles.json` under the package's names.
pub fn roles_reach(roles: &Object, p: &Object) -> Vec<Text> {
    let target = text(member(object(member(p, "target")), "host"));
    let instance = text(member(object(member(p, "target")), "instance"));
    let shards = object(member(roles, "shards"));
    let standbys = object(member(roles, "standbys"));
    let version = |shard: &Text| {
        object(
            shards
                .get(shard.to_str().expect("a shard name is ASCII"))
                .expect("the roles name each shard"),
        )
    };
    let shard_keys: Vec<&Text> = match member(p, "shards") {
        Value::Array(items) => items.iter().map(text).collect(),
        _ => unreachable!("the package's shards are a list"),
    };
    let is_target = |value: &Value| matches!(value, Value::String(host) if host == target);
    let owned: Vec<&Text> = shard_keys
        .iter()
        .copied()
        .filter(|s| is_target(member(version(s), "owner")))
        .collect();
    let stood = shard_keys
        .iter()
        .filter(|s| is_target(member(version(s), "standby")))
        .count();
    let mut unmet = Vec::new();
    if owned.len() < MIN_OWNED {
        unmet.push(said!(
            "the target owns ",
            owned.len().to_string(),
            " shards, fewer than ",
            MIN_OWNED.to_string()
        ));
    }
    if stood < MIN_STOOD {
        unmet.push(said!(
            "the target stands by for ",
            stood.to_string(),
            " shards, fewer than ",
            MIN_STOOD.to_string()
        ));
    }
    for s in owned {
        let standby = match member(version(s), "standby") {
            Value::String(host) if host != target => host,
            _ => {
                unmet.push(said!(
                    "owned shard ",
                    s,
                    " names no standby other than the target"
                ));
                continue;
            }
        };
        let Some(state) = standbys.get(standby.to_str().expect("a host name holds no surrogate"))
        else {
            unmet.push(said!(
                "standby host ",
                standby,
                " of ",
                s,
                " has no instance state and host report read before the stop"
            ));
            continue;
        };
        let state = object(state);
        let (read, report) = (
            text(member(state, "instance_state")),
            text(member(state, "host_report")),
        );
        if text(member(state, "instance")) == instance {
            unmet.push(said!(
                "standby host ",
                standby,
                " of ",
                s,
                " reports the target's instance ",
                instance
            ));
        } else if *read != "running" || *report != "healthy" {
            unmet.push(said!(
                "standby host ",
                standby,
                " of ",
                s,
                " reads ",
                read,
                " and ",
                report
            ));
        }
    }
    unmet
}

fn member<'a>(object: &'a Object, key: &str) -> &'a Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("the checked object holds {key}"))
}

fn object(value: &Value) -> &Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("the checked value is an object"),
    }
}

fn text(value: &Value) -> &Text {
    match value {
        Value::String(text) => text,
        _ => panic!("the checked value is a string"),
    }
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod tests;
