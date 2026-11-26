//! Client acceptance, judged under the premise that every row of a history
//! belongs to one shard. Each client instance keeps one high-water, at least
//! the highest tag it accepted. A client compares a response's tag with its
//! high-water at receipt, accepts only a tag at or above it, and raises the
//! high-water before it surfaces the response; the recorded high-water
//! never falls. A rejected response leaves the high-water unchanged.
//! A restarted client is a new instance whose high-water starts absent. The
//! key model judges a rejected response as the server's answer.

use std::collections::HashMap;

use super::ids::{ClientId, Tenure};
use super::obligation::Obligation;
use super::row::Row;
use super::rules::{Rule, holds};
use super::tenure::ActivationLog;
use super::verdict::Violation;

/// A client's high-water at a response's receipt and whether it accepted
/// the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Acceptance {
    pub(crate) high_water: Option<Tenure>,
    pub(crate) accepted: bool,
}

pub(crate) fn judge_clients(rows: &[&Row], log: &ActivationLog) -> Result<(), Violation> {
    if !holds(Rule::HighWater) {
        return Ok(());
    }
    let mut received: Vec<(&Row, ClientId, Acceptance)> = rows
        .iter()
        .filter_map(|&row| Some((row, row.client?, row.acceptance?)))
        .collect();
    received.sort_by_key(|(row, _, _)| row.responded);
    let mut highest: HashMap<ClientId, Tenure> = HashMap::new();
    for (row, client, acceptance) in received {
        let fail = |rule| Violation {
            obligation: Obligation::History,
            op: row.op,
            rule,
        };
        let running = highest.get(&client).copied();
        if acceptance.high_water < running {
            return Err(fail("a client's recorded high-water fell"));
        }
        let mut raised = acceptance.high_water;
        if acceptance.accepted {
            let tag = log.tag(row);
            if Some(tag) < raised {
                return Err(fail(
                    "a client accepted a response tagged below its high-water",
                ));
            }
            raised = raised.max(Some(tag));
        }
        if let Some(raised) = raised {
            highest.insert(client, raised);
        }
    }
    Ok(())
}
