use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::String;
use std::vec::Vec;
use std::{format, fs};

use crate::select::{Install, OUTPUTS, recorded};

const GENERATOR_DIGEST: &str = "// Generator digest: ";

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn installs() -> Vec<Install> {
    let installs = recorded(&crate_dir().join("src/generated")).unwrap();
    assert!(
        !installs.is_empty(),
        "src/generated/installs holds no record"
    );
    installs
}

fn outputs() -> Vec<PathBuf> {
    let mut outputs: Vec<PathBuf> = fs::read_dir(crate_dir().join("src/generated").join(OUTPUTS))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    outputs.sort();
    assert!(!outputs.is_empty(), "src/generated/outputs holds no output");
    outputs
}

fn script(name: &str, arg: Option<&Path>) -> String {
    let output = Command::new(crate_dir().join("native").join(name))
        .args(arg)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native/{name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[test]
// The connect-time host identifier comes from `extended_host_id` in controller options.
fn every_output_exposes_register_report_acquire_and_their_types() {
    for dir in outputs() {
        let bindings = fs::read_to_string(dir.join("bindings.rs")).unwrap();
        let mut commands: Vec<_> = bindings
            .split("pub fn ")
            .skip(1)
            .filter_map(|rest| rest.split_once('(').map(|(name, _)| name))
            .filter(|name| name.starts_with("spdk_nvme_ns_cmd_reservation_"))
            .collect();
        commands.sort_unstable();
        assert_eq!(
            commands,
            [
                "spdk_nvme_ns_cmd_reservation_acquire",
                "spdk_nvme_ns_cmd_reservation_register",
                "spdk_nvme_ns_cmd_reservation_report",
            ],
            "{} reservation command surface",
            dir.display()
        );
        let mut types: Vec<_> = bindings
            .lines()
            .filter_map(|line| {
                line.strip_prefix("pub struct ")
                    .or_else(|| line.strip_prefix("pub union "))
                    .or_else(|| line.strip_prefix("pub type "))
            })
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|name| {
                name.starts_with("spdk_nvme_reservation_")
                    || name.starts_with("spdk_nvme_registered_ctrlr_")
            })
            .collect();
        types.sort_unstable();
        assert_eq!(
            types,
            [
                "spdk_nvme_registered_ctrlr_extended_data",
                "spdk_nvme_registered_ctrlr_extended_data__bindgen_ty_1",
                "spdk_nvme_reservation_acquire_action",
                "spdk_nvme_reservation_acquire_data",
                "spdk_nvme_reservation_register_action",
                "spdk_nvme_reservation_register_cptpl",
                "spdk_nvme_reservation_register_data",
                "spdk_nvme_reservation_status_data",
                "spdk_nvme_reservation_status_extended_data",
                "spdk_nvme_reservation_type",
            ],
            "{} reservation type surface",
            dir.display()
        );
        for name in [
            "spdk_nvme_reservation_type",
            "spdk_nvme_reservation_register_action",
            "spdk_nvme_reservation_register_cptpl",
            "spdk_nvme_reservation_acquire_action",
            "spdk_nvme_status_code_type",
            "spdk_nvme_generic_command_status_code",
        ] {
            assert!(
                bindings.contains(&format!("pub type {name} = ::core::ffi::c_uint;")),
                "{} lacks constified enum {name}",
                dir.display()
            );
        }
        assert!(bindings.contains("pub extended_host_id: [u8; 16usize]"));
        let surface = |prefix: &str| {
            let mut names: Vec<_> = bindings
                .split("pub fn ")
                .skip(1)
                .filter_map(|rest| rest.split_once('(').map(|(name, _)| name))
                .filter_map(|name| name.strip_prefix(prefix))
                .collect();
            names.sort_unstable();
            names
        };
        assert_eq!(
            surface("spdk_sys_"),
            [
                "layout_table",
                "nvme_cc_en_mask",
                "nvme_csts_rdy_mask",
                "registry_query",
                "rte_errno",
                "rte_errno_clear",
                "rte_eth_rx_burst",
                "rte_eth_tx_burst",
                "rte_eth_tx_prepare",
                "rte_ipv4_cksum",
                "rte_ipv4_phdr_cksum",
                "rte_ipv4_udptcp_cksum",
                "rte_lcore_id",
                "rte_library_matches_headers",
                "rte_mbuf_data_iova",
                "rte_mbuf_data_iova_default",
                "rte_mbuf_refcnt_read",
                "rte_mbuf_refcnt_update",
                "rte_mbuf_set_tx_offload",
                "rte_mempool_get_priv",
                "rte_pktmbuf_alloc",
                "rte_pktmbuf_alloc_bulk",
                "rte_pktmbuf_chain",
                "rte_pktmbuf_free",
                "rte_pktmbuf_free_seg",
                "rte_pktmbuf_mtod",
            ],
            "{} shim surface",
            dir.display()
        );
        assert_eq!(
            surface("spdk_nvme_ctrlr_cmd_"),
            ["get_feature", "get_log_page"],
            "{} controller command surface",
            dir.display()
        );
        assert!(
            surface("spdk_nvme_ctrlr_")
                .iter()
                .all(|name| !name.starts_with("reset") && !name.starts_with("reconnect")),
            "{} exposes a controller reset or reconnect, after which the host ID is unconfirmed",
            dir.display()
        );
    }
}

#[test]
fn reservation_constants_keep_the_pinned_encodings() {
    use crate::*;

    assert_eq!(
        spdk_nvme_reservation_type_SPDK_NVME_RESERVE_EXCLUSIVE_ACCESS,
        2
    );
    assert_eq!(
        spdk_nvme_reservation_register_action_SPDK_NVME_RESERVE_REGISTER_KEY,
        0
    );
    assert_eq!(
        spdk_nvme_reservation_register_action_SPDK_NVME_RESERVE_REPLACE_KEY,
        2
    );
    assert_eq!(
        spdk_nvme_reservation_register_cptpl_SPDK_NVME_RESERVE_PTPL_NO_CHANGES,
        0
    );
    assert_eq!(
        spdk_nvme_reservation_register_cptpl_SPDK_NVME_RESERVE_PTPL_CLEAR_POWER_ON,
        2
    );
    assert_eq!(
        spdk_nvme_reservation_register_cptpl_SPDK_NVME_RESERVE_PTPL_PERSIST_POWER_LOSS,
        3
    );
    assert_eq!(
        spdk_nvme_reservation_acquire_action_SPDK_NVME_RESERVE_ACQUIRE,
        0
    );
    assert_eq!(
        spdk_nvme_reservation_acquire_action_SPDK_NVME_RESERVE_PREEMPT,
        1
    );
    assert_eq!(
        spdk_nvme_reservation_acquire_action_SPDK_NVME_RESERVE_PREEMPT_ABORT,
        2
    );
    assert_eq!(spdk_nvme_status_code_type_SPDK_NVME_SCT_GENERIC, 0);
    assert_eq!(
        spdk_nvme_generic_command_status_code_SPDK_NVME_SC_RESERVATION_CONFLICT,
        0x83
    );
    assert_eq!(
        spdk_nvme_generic_command_status_code_SPDK_NVME_SC_ABORTED_PREEMPT,
        0x1b
    );
}

#[test]
fn extended_controller_status_accessors_preserve_the_packed_byte() {
    use crate::{__BindgenBitfieldUnit, spdk_nvme_registered_ctrlr_extended_data__bindgen_ty_1};

    type Status = spdk_nvme_registered_ctrlr_extended_data__bindgen_ty_1;
    for byte in 0..=u8::MAX {
        let status = Status {
            _bitfield_1: __BindgenBitfieldUnit::new([byte]),
        };
        assert_eq!(status.status(), byte & 1);
        assert_eq!(status.reserved1(), byte >> 1);
        let mut changed = Status {
            _bitfield_1: __BindgenBitfieldUnit::new([!byte]),
        };
        // SAFETY: `status` is initialized one-byte storage; `changed` is
        // initialized, writable one-byte storage whose access is exclusive.
        unsafe {
            assert_eq!(Status::status_raw(&raw const status), byte & 1);
            assert_eq!(Status::reserved1_raw(&raw const status), byte >> 1);
            Status::set_status_raw(&raw mut changed, byte & 1);
        }
        assert_eq!(
            changed._bitfield_1,
            __BindgenBitfieldUnit::new([(!byte & 0xfe) | (byte & 1)])
        );
        // SAFETY: `changed` remains initialized, writable one-byte storage
        // whose access is exclusive.
        unsafe { Status::set_reserved1_raw(&raw mut changed, byte >> 1) };
        assert_eq!(changed._bitfield_1, status._bitfield_1);
        changed._bitfield_1 = __BindgenBitfieldUnit::new([!byte]);
        changed.set_status(byte & 1);
        assert_eq!(
            changed._bitfield_1,
            __BindgenBitfieldUnit::new([(!byte & 0xfe) | (byte & 1)])
        );
        changed.set_reserved1(byte >> 1);
        assert_eq!(changed._bitfield_1, status._bitfield_1);
        assert_eq!(
            Status::new_bitfield_1(byte & 1, byte >> 1),
            status._bitfield_1
        );
        changed.set_status(byte & 1);
        assert_eq!(changed._bitfield_1, status._bitfield_1);
        changed.set_reserved1(byte >> 1);
        assert_eq!(changed._bitfield_1, status._bitfield_1);
        // SAFETY: `changed` is initialized, writable one-byte storage whose
        // access is exclusive.
        unsafe { Status::set_status_raw(&raw mut changed, byte & 1) };
        assert_eq!(changed._bitfield_1, status._bitfield_1);
        // SAFETY: `changed` remains initialized, writable one-byte storage
        // whose access is exclusive.
        unsafe { Status::set_reserved1_raw(&raw mut changed, byte >> 1) };
        assert_eq!(changed._bitfield_1, status._bitfield_1);
    }
}

#[test]
fn extended_report_header_defaults_to_zero() {
    let report = crate::spdk_nvme_reservation_status_extended_data::default();
    // Copy multibyte fields by value because the packed header has byte alignment.
    let (generation, controllers, reserved1) =
        (report.data.gen_, report.data.regctl, report.data.reserved1);
    assert_eq!((generation, controllers, reserved1), (0, 0, 0));
    assert_eq!((report.data.rtype, report.data.ptpls), (0, 0));
    assert_eq!(report.data.reserved, [0; 14]);
    assert_eq!(report.reserved, [0; 40]);
}

#[test]
fn reservation_commands_link_with_the_pinned_signatures() {
    use crate::*;
    use core::ffi::{c_int, c_void};

    let register: unsafe extern "C" fn(
        *mut spdk_nvme_ns,
        *mut spdk_nvme_qpair,
        *mut spdk_nvme_reservation_register_data,
        bool,
        spdk_nvme_reservation_register_action,
        spdk_nvme_reservation_register_cptpl,
        spdk_nvme_cmd_cb,
        *mut c_void,
    ) -> c_int = spdk_nvme_ns_cmd_reservation_register;
    let acquire: unsafe extern "C" fn(
        *mut spdk_nvme_ns,
        *mut spdk_nvme_qpair,
        *mut spdk_nvme_reservation_acquire_data,
        bool,
        spdk_nvme_reservation_acquire_action,
        spdk_nvme_reservation_type,
        spdk_nvme_cmd_cb,
        *mut c_void,
    ) -> c_int = spdk_nvme_ns_cmd_reservation_acquire;
    let report: unsafe extern "C" fn(
        *mut spdk_nvme_ns,
        *mut spdk_nvme_qpair,
        *mut c_void,
        u32,
        spdk_nvme_cmd_cb,
        *mut c_void,
    ) -> c_int = spdk_nvme_ns_cmd_reservation_report;
    let _ = core::hint::black_box((register, acquire, report));
}

#[test]
// The generated declaration coerces to the pinned parameter and return types, and taking its address links the
// symbol from the SPDK archives.
fn get_feature_links_with_the_pinned_signature() {
    use crate::*;
    use core::ffi::{c_int, c_void};

    let get_feature: unsafe extern "C" fn(
        *mut spdk_nvme_ctrlr,
        u8,
        u32,
        *mut c_void,
        u32,
        spdk_nvme_cmd_cb,
        *mut c_void,
    ) -> c_int = spdk_nvme_ctrlr_cmd_get_feature;
    let _ = core::hint::black_box(get_feature);
}

#[test]
fn every_output_records_the_current_generator_digest() {
    let current = script("generator-digest.sh", None);
    let mut stale = Vec::new();
    for output in outputs() {
        let path = output.join("bindings.rs");
        let bindings = fs::read_to_string(&path).unwrap();
        let recorded = bindings
            .lines()
            .find_map(|line| line.strip_prefix(GENERATOR_DIGEST));
        if recorded != Some(current.as_str()) {
            stale.push(format!("{}: {recorded:?}", path.display()));
        }
    }
    assert!(
        stale.is_empty(),
        "bindings generated from other inputs than the current {current}; \
         run crates/spdk-sys/regenerate.sh on a host of each install: {stale:?}"
    );
}

#[test]
fn the_output_digest_counts_file_boundaries() {
    let out = Path::new(env!("OUT_DIR")).join("output-digest");
    let digest = |name: &str, bindings: &str, layout: &str| {
        let dir = out.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bindings.rs"), bindings).unwrap();
        fs::write(dir.join("layout.inc"), layout).unwrap();
        fs::write(dir.join("layout_table.rs"), "e\n").unwrap();
        script("output-digest.sh", Some(&dir))
    };
    assert_ne!(
        digest("plain", "ab\n", "cd\n"),
        digest("shifted", "ab\ncd", "\n"),
        "the two outputs hold the same bytes split at another boundary"
    );
}

const CLOSURE_FIXTURE: &str = "# 1 \"<built-in>\" 1\n#define __FIXTURE_PREDEFINED 7\n# 1 \"fixture.h\" 2\n\
    #define ROOT 1\n#define BASE (ROOT)\n#define UNUSED 2\n#define WANT_SUM (BASE + 1)\n\
    int declaration;\n#undef UNUSED\n#define PACK 1\n#pragma pack(push, PACK)\n\
    #define PASTE(a, b) a ## b\n#define PART_ONE 3\n#define WANT_PASTED PASTE(PART_, ONE)";

const CC: &[&str] = &["cc", "-E", "-P", "-w", "-x", "c", "-"];

fn closure(header: &Path, output: &Path, allowlist: &str, cpp: &[&str]) -> std::process::Output {
    let _ = fs::remove_file(output);
    Command::new("python3")
        .arg(crate_dir().join("native/macro_closure.py"))
        .arg(header)
        .arg(output)
        .arg(allowlist)
        .args(cpp)
        .output()
        .unwrap()
}

fn closure_dir(name: &str) -> (PathBuf, PathBuf) {
    let dir = Path::new(env!("OUT_DIR")).join("macro-closure").join(name);
    fs::create_dir_all(&dir).unwrap();
    let header = dir.join("all.h");
    fs::write(&header, CLOSURE_FIXTURE).unwrap();
    (dir, header)
}

#[test]
fn the_macro_closure_keeps_reached_definitions_every_undef_and_pragma_operands_in_place() {
    let (dir, header) = closure_dir("kept");
    let kept = dir.join("kept.h");
    let run = closure(&header, &kept, "^(WANT_SUM)$", CC);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        fs::read_to_string(&kept).unwrap(),
        "# 1 \"<built-in>\" 1\n\n# 1 \"fixture.h\" 2\n#define ROOT 1\n#define BASE (ROOT)\n\n\
         #define WANT_SUM (BASE + 1)\nint declaration;\n#undef UNUSED\n#define PACK 1\n#pragma pack(push, PACK)\n\n\n"
    );
    assert_eq!(
        fs::read_to_string(&kept).unwrap().split('\n').count(),
        CLOSURE_FIXTURE.split('\n').count(),
        "the output numbers every line as the header does"
    );
}

#[test]
fn the_macro_closure_refuses_a_pasted_name_it_drops_and_keeps_one_it_reaches() {
    let (dir, header) = closure_dir("pasted");
    let pasted = dir.join("pasted.h");
    let run = closure(&header, &pasted, "^(WANT_.*)$", CC);
    assert!(
        !run.status.success(),
        "WANT_PASTED expands to PART_ONE's value only while PART_ONE is defined"
    );
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("kept definitions: ['\"WANT_PASTED\" PART_ONE']")
            && stderr.contains("all definitions: ['\"WANT_PASTED\" 3']"),
        "{stderr}"
    );
    assert!(!pasted.exists());

    let accepted = dir.join("accepted.h");
    let run = closure(&header, &accepted, "^(WANT_.*|PART_ONE)$", CC);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(fs::read_to_string(&accepted).unwrap().ends_with(
        "#define PASTE(a, b) a ## b\n#define PART_ONE 3\n#define WANT_PASTED PASTE(PART_, ONE)"
    ));
}

#[test]
fn the_macro_closure_fails_closed_on_a_failed_preprocessor_an_empty_allowlist_and_a_counter() {
    let (dir, header) = closure_dir("refused");
    let output = dir.join("refused.h");
    let run = closure(&header, &output, "^(WANT_SUM)$", &["false"]);
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("the preprocessor failed"));
    assert!(!output.exists());

    let run = closure(&header, &output, "^(WANT_NOTHING)$", CC);
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("matches the allowlist"));
    assert!(!output.exists());

    let counted = dir.join("counted.h");
    fs::write(
        &counted,
        "# 1 \"fixture.h\"\n#define TICK __COUNTER__\n#define WANT_TICK (TICK + 1)\n",
    )
    .unwrap();
    let run = closure(&counted, &output, "^(WANT_TICK)$", CC);
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("TICK names __COUNTER__"));
    assert!(!output.exists());
}

#[test]
fn every_record_names_an_output_and_every_output_is_named() {
    let installs = installs();
    let outputs = outputs();
    for install in &installs {
        assert!(
            outputs
                .iter()
                .any(|output| output.file_name().unwrap() == install.output.as_str()),
            "{} names the output {}, which src/generated/outputs lacks",
            install.record.display(),
            install.output
        );
    }
    for output in &outputs {
        let name = output.file_name().unwrap().to_str().unwrap();
        assert!(
            installs.iter().any(|install| install.output == name),
            "no install record names {}; regenerate.sh removes an unnamed output",
            output.display()
        );
        assert_eq!(
            script("output-digest.sh", Some(output)),
            name,
            "{} is named for other files than it holds",
            output.display()
        );
    }
}

#[test]
fn the_pins_name_each_recorded_digest_under_its_own_label() {
    let bindings = include_str!(concat!(env!("SPDK_SYS_GENERATED"), "/bindings.rs"));
    let install = include_str!(env!("SPDK_SYS_INSTALL"));
    let recorded = |text: &'static str, prefix: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
    };
    let header = recorded(install, "Header digest: ");
    let generator = recorded(bindings, GENERATOR_DIGEST);
    assert_ne!(header, generator, "the two inputs share one digest");
    let pins = crate::PINS;
    assert!(
        pins.contains(&format!("header digest {header}, ")),
        "{pins} names no header digest {header}"
    );
    assert!(
        pins.ends_with(&format!("generator digest {generator}.")),
        "{pins} names no generator digest {generator}"
    );
}

/// Every generated output, not only the one this host selects, carries the
/// typed namespace Identify structure and its named fields in both layout
/// tables; each install's C/Rust comparison runs on a host of that install.
#[test]
fn every_output_lays_out_the_namespace_identify_fields() {
    let mut missing = Vec::new();
    for dir in outputs() {
        let rust = fs::read_to_string(dir.join("layout_table.rs")).unwrap();
        let c = fs::read_to_string(dir.join("layout.inc")).unwrap();
        for field in [
            "nsze", "nsfeat", "nlbaf", "flbas", "nawun", "nawupf", "nacwu", "nabsn", "nabo",
            "nabspf", "noiob", "lbaf",
        ] {
            let c_row = format!("{{\"spdk_nvme_ns_data\", \"{field}\", 0, 0, offsetof(");
            let rust_row = format!("offset_of!(spdk_nvme_ns_data, {field})");
            if !c.contains(&c_row) || !rust.contains(&rust_row) {
                missing.push(format!("{}: {field}", dir.display()));
            }
        }
    }
    assert!(missing.is_empty(), "missing layout rows: {missing:?}");
}
