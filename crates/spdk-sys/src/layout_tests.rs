//! Compares named structures' layouts and the listed enums' size and alignment
//! between Rust and the C shim compiled with the install's own headers and flags.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::layout_table::RUST_LAYOUTS;
use crate::{spdk_sys_layout, spdk_sys_layout_table};

const BINDINGS: &str = include_str!(concat!(env!("SPDK_SYS_GENERATED"), "/bindings.rs"));

type Key = (String, Option<String>);

fn c_layouts() -> BTreeMap<Key, (usize, usize, usize)> {
    let mut count = 0;
    // SAFETY: the table is a static array of `count` entries whose strings are static literals.
    let table: &[spdk_sys_layout] = unsafe {
        let base = spdk_sys_layout_table(&mut count);
        core::slice::from_raw_parts(base, count)
    };
    let text = |p: *const core::ffi::c_char| {
        // SAFETY: non-null entries point at NUL-terminated static literals.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string())
    };
    table
        .iter()
        .map(|e| {
            (
                (text(e.type_name).unwrap(), text(e.field_name)),
                (e.size, e.align, e.offset),
            )
        })
        .collect()
}

#[test]
fn every_named_structure_matches_the_c_compiler_layout() {
    let c = c_layouts();
    assert_eq!(
        c.len(),
        RUST_LAYOUTS.len(),
        "the C and Rust tables list different entries"
    );
    let mut mismatches = Vec::new();
    for &(ty, field, size, align, offset) in RUST_LAYOUTS {
        let key = (ty.to_string(), field.map(str::to_string));
        match c.get(&key) {
            Some(&found) if found == (size, align, offset) => {}
            other => mismatches.push((key, other.copied(), (size, align, offset))),
        }
    }
    assert!(
        mismatches.is_empty(),
        "layout mismatches (key, C, Rust): {mismatches:?}"
    );
}

#[test]
fn reservation_layouts_and_controller_exhid_match_the_pinned_abi() {
    for (ty, size, align) in [
        ("spdk_nvme_reservation_register_data", 16, 8),
        ("spdk_nvme_reservation_acquire_data", 16, 8),
        ("spdk_nvme_reservation_status_data", 24, 1),
        ("spdk_nvme_reservation_status_extended_data", 64, 1),
        ("spdk_nvme_registered_ctrlr_extended_data", 64, 1),
        ("spdk_nvme_reservation_type", 4, 4),
        ("spdk_nvme_reservation_register_action", 4, 4),
        ("spdk_nvme_reservation_register_cptpl", 4, 4),
        ("spdk_nvme_reservation_acquire_action", 4, 4),
        ("spdk_nvme_status_code_type", 4, 4),
        ("spdk_nvme_generic_command_status_code", 4, 4),
    ] {
        assert!(
            RUST_LAYOUTS.contains(&(ty, None, size, align, 0)),
            "{ty} must have a layout row with size {size} and alignment {align}"
        );
    }
    for (ty, fields) in [
        (
            "spdk_nvme_reservation_register_data",
            &[("crkey", 0), ("nrkey", 8)][..],
        ),
        (
            "spdk_nvme_reservation_acquire_data",
            &[("crkey", 0), ("prkey", 8)][..],
        ),
        (
            "spdk_nvme_reservation_status_data",
            &[("gen_", 0), ("rtype", 4), ("regctl", 5), ("ptpls", 9)][..],
        ),
        (
            "spdk_nvme_reservation_status_extended_data",
            &[("data", 0), ("reserved", 24)][..],
        ),
        (
            "spdk_nvme_registered_ctrlr_extended_data",
            &[("cntlid", 0), ("rcsts", 2), ("rkey", 8), ("hostid", 16)][..],
        ),
        ("spdk_nvme_ctrlr_opts", &[("extended_host_id", 554)][..]),
    ] {
        for &(field, offset) in fields {
            assert!(
                RUST_LAYOUTS.contains(&(ty, Some(field), 0, 0, offset)),
                "{ty}.{field} must have an offset row at {offset}"
            );
        }
    }
    assert_eq!(
        crate::spdk_nvme_ctrlr_opts::default()
            .extended_host_id
            .len(),
        16
    );
    assert_eq!(
        crate::spdk_nvme_registered_ctrlr_extended_data::default()
            .hostid
            .len(),
        16
    );
}

#[test]
fn the_tables_cover_the_mbuf_and_every_named_binding() {
    let bindings = BINDINGS;
    let named: Vec<&str> = bindings
        .split("pub struct ")
        .skip(1)
        .chain(bindings.split("pub union ").skip(1))
        .filter_map(|rest| rest.split([' ', '<']).next())
        .filter(|name| !name.contains("__") && !name.starts_with('_'))
        .collect();
    let listed: Vec<&str> = RUST_LAYOUTS
        .iter()
        .filter(|e| e.1.is_none())
        .map(|e| e.0)
        .collect();
    let incomplete: Vec<&str> = bindings
        .split("pub struct ")
        .skip(1)
        .filter_map(|rest| {
            let (name, body) = rest.split_once(' ')?;
            (body.starts_with("{\n    pub _address: u8,\n}")
                || body.starts_with("{\n    _unused: [u8; 0],\n}"))
            .then_some(name)
        })
        .collect();
    for name in &named {
        assert!(
            incomplete.contains(name) || listed.contains(name),
            "{name} has no layout entry"
        );
    }
    for field in [
        "buf_addr", "buf_iova", "data_off", "refcnt", "nb_segs", "ol_flags", "pkt_len", "data_len",
        "pool", "next",
    ] {
        assert!(
            RUST_LAYOUTS.iter().any(|e| e.0 == "rte_mbuf"
                && e.1
                    .is_some_and(|path| path.rsplit('.').next() == Some(field))),
            "rte_mbuf field {field} has no offset entry"
        );
    }
}
