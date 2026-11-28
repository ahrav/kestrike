//! The reach oracle's conditions that stand before the stop, read from the roles mark and the package.

use super::constants::{MIN_OWNED, MIN_STOOD};
use super::refusal::said;
use super::schema::{checked_list, checked_member as member, checked_object, checked_text, string};
use crate::json::{Object, Value};
use crate::text::Text;

/// `roles_reach` lists the reach's unmet pre-stop conditions: the target owns fewer than two
/// shards or stands by for fewer than one, and for each owned shard in the package's order, its
/// standby is missing or is the target, has no state read, reports the target's instance, or reads
/// other than `running` and `healthy`. An empty list means the conditions are met.
///
/// # Panics
///
/// When `p` has not passed [`check_package`](super::check_package) or `roles` does not conform to the
/// schema of `injection/roles.json` under the package's names.
pub fn roles_reach(roles: &Object, p: &Object) -> Vec<Text> {
    let target = checked_object(member(p, "target"));
    let (target, instance) = (
        checked_text(member(target, "host")),
        checked_text(member(target, "instance")),
    );
    let shards = checked_object(member(roles, "shards"));
    let standbys = checked_object(member(roles, "standbys"));
    let version = |shard: &Text| {
        let shard = shard.to_str().expect("a shard name is ASCII");
        checked_object(member(shards, shard))
    };
    let is_target = |value: &Value| string(value) == Some(target);
    let listed: Vec<&Text> = checked_list(member(p, "shards"))
        .iter()
        .map(checked_text)
        .collect();
    let owned: Vec<&Text> = listed
        .iter()
        .copied()
        .filter(|s| is_target(member(version(s), "owner")))
        .collect();
    let stood = listed
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
        let standby = match string(member(version(s), "standby")) {
            Some(host) if host != target => host,
            _ => {
                unmet.push(said!(
                    "owned shard ",
                    s,
                    " names no standby other than the target"
                ));
                continue;
            }
        };
        let host = said!("standby host ", standby, " of ", s);
        let read = standby.to_str().and_then(|name| standbys.get(name));
        let Some(state) = read.map(checked_object) else {
            unmet.push(said!(
                host,
                " has no instance state and host report read before the stop"
            ));
            continue;
        };
        let state_of = |key: &str| checked_text(member(state, key));
        let (running, report) = (state_of("instance_state"), state_of("host_report"));
        if state_of("instance") == instance {
            unmet.push(said!(host, " reports the target's instance ", instance));
        } else if *running != "running" || *report != "healthy" {
            unmet.push(said!(host, " reads ", running, " and ", report));
        }
    }
    unmet
}

#[cfg(test)]
#[path = "reach_tests.rs"]
mod tests;
