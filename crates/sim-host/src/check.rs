//! `sim-host check`: the host partition the runner would use and the
//! refusals that would block it. The worker count is the online CPUs less
//! the confirm slots, the sweep controller and the system cores, from 1 to
//! [`WORKERS_MAX`]; the memory demand adds the workers' assigned memory,
//! one [`CONFIRM_SHARE_MEMORY`] per confirm slot and one more for triage,
//! and the system reserve.

use std::path::Path;

use serde_json::{Value, json};

use crate::assignment::Document;

pub const CONFIRM_SHARE_MEMORY: u64 = 2 << 30;
pub const WORKERS_MAX: u64 = 1024;

pub fn workers(online: u64, confirm_slots: u64, system_cores: u64) -> Option<u64> {
    let reserved = confirm_slots.checked_add(1)?.checked_add(system_cores)?;
    online
        .checked_sub(reserved)
        .filter(|workers| (1..=WORKERS_MAX).contains(workers))
}

pub struct Inputs<'a> {
    pub assignment: &'a Document,
    pub unit: &'a Path,
    pub confirm_slots: u64,
    pub system_cores: u64,
    pub system_memory: u64,
    pub online: u64,
    pub usable: u64,
    pub memory: u64,
    pub instance: Result<String, String>,
    pub metadata: String,
}

pub fn memory_demand(inputs: &Inputs, workers: u64) -> u64 {
    demand(
        workers,
        inputs.assignment.memory,
        inputs.confirm_slots,
        inputs.system_memory,
    )
}

pub fn demand(workers: u64, memory: u64, confirm_slots: u64, system_memory: u64) -> u64 {
    let worker_memory = workers.saturating_mul(memory);
    let confirm_memory = confirm_slots
        .saturating_add(1)
        .saturating_mul(CONFIRM_SHARE_MEMORY);
    worker_memory
        .saturating_add(confirm_memory)
        .saturating_add(system_memory)
}

pub fn judge(inputs: &Inputs) -> (u8, Value) {
    let mut refusals = Vec::new();
    if let Err(error) = &inputs.instance {
        refusals.push(format!("no instance id: {error}"));
    }
    let workers = workers(inputs.online, inputs.confirm_slots, inputs.system_cores);
    if workers.is_none() {
        refusals.push(format!(
            "{} online CPUs leave no worker count from 1 to {WORKERS_MAX} beside {} confirm \
             slots, the sweep controller and {} system cores",
            inputs.online, inputs.confirm_slots, inputs.system_cores
        ));
    }
    if inputs.usable < inputs.online {
        refusals.push(format!(
            "the partition takes all {} online CPUs and the runner may use {}",
            inputs.online, inputs.usable
        ));
    }
    let demand = memory_demand(inputs, workers.unwrap_or(0));
    if demand > inputs.memory {
        refusals.push(format!(
            "workers, confirmation and the system reserve need {demand} bytes of memory and \
             the host has {}",
            inputs.memory
        ));
    }
    match crate::cgroup::missing_controllers(inputs.unit) {
        Ok(missing) if missing.is_empty() => {}
        Ok(missing) => refusals.push(format!(
            "{} does not delegate {}",
            inputs.unit.display(),
            missing.join(", ")
        )),
        Err(error) => refusals.push(format!("{}: {error}", inputs.unit.display())),
    }
    for path in crate::cgroup::unwritable(inputs.unit) {
        refusals.push(format!("this user may not write {}", path.display()));
    }
    let limits = crate::cgroup::limits(inputs.unit)
        .unwrap_or_else(|error| vec![format!("{}: {error}", inputs.unit.display())]);
    refusals.extend(limits.iter().cloned());
    let report = json!({
        "instance": inputs.instance.as_ref().ok(),
        "metadata": inputs.metadata,
        "online_cpus": inputs.online,
        "usable_cpus": inputs.usable,
        "confirm_slots": inputs.confirm_slots,
        "system_cores": inputs.system_cores,
        "system_memory": inputs.system_memory,
        "workers": workers,
        "memory": inputs.memory,
        "memory_demand": demand,
        "cgroup": inputs.unit,
        "ancestor_limits": limits,
        "refusals": refusals,
    });
    (if refusals.is_empty() { 0 } else { 2 }, report)
}

#[cfg(test)]
mod tests {
    use super::Inputs;

    #[test]
    fn workers_take_the_cpus_the_reserve_leaves() {
        assert_eq!(super::workers(192, 8, 3), Some(180));
        assert_eq!(super::workers(12, 8, 3), None);
        assert_eq!(super::workers(13, 8, 3), Some(1));
        assert_eq!(super::workers(4, u64::MAX, 0), None);
        assert_eq!(super::workers(1026, 1, 0), Some(1024));
        assert_eq!(super::workers(1027, 1, 0), None);
    }

    #[test]
    fn memory_demand_counts_every_term_at_the_boundary() {
        let unit = crate::file::scratch("check");
        std::fs::write(unit.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(unit.join("cgroup.procs"), "").expect("procs");
        std::fs::write(unit.join("cgroup.subtree_control"), "").expect("control");
        let text = format!(
            r#"{{"format":1,"name":"sim","profiles":["a"],"batch":30,
            "wall":600,"memory":{},"processes":64,"stint":60}}"#,
            2u64 << 30
        );
        let assignment =
            crate::assignment::Document::parse(text.as_bytes()).expect("an assignment");
        let inputs = |memory| Inputs {
            assignment: &assignment,
            unit: &unit,
            confirm_slots: 2,
            system_cores: 0,
            system_memory: 1 << 30,
            online: 8,
            usable: 8,
            memory,
            instance: Ok("i-0123abcd".into()),
            metadata: "test".into(),
        };
        let fits = (5 * 2 + 3 * 2 + 1) << 30;
        let (code, report) = super::judge(&inputs(fits));
        assert_eq!(code, 0, "{report:#}");
        assert_eq!(report["workers"], 5);
        assert_eq!(report["memory_demand"], fits);
        let (code, report) = super::judge(&inputs(fits - 1));
        assert_eq!(code, 2, "{report:#}");
        std::fs::write(unit.join("cgroup.controllers"), "cpu memory").expect("controllers");
        let (code, report) = super::judge(&inputs(fits));
        assert_eq!(code, 2);
        assert!(
            report["refusals"][0]
                .as_str()
                .expect("a refusal")
                .contains("delegate pids"),
            "{report:#}"
        );
        std::fs::remove_dir_all(&unit).expect("cleanup");
    }
}
