//! Records the compiler that built the crate, so the hashing audit test can
//! name the toolchain whose `RandomState` it certified, and sets
//! `cfg(kestrike_asan)` for a build under address sanitizer, whose
//! tests then include the capture-cell lifetime control that needs its
//! reports, and `cfg(kestrike_tsan)` for a build under thread sanitizer,
//! whose tests then include the gate's planted race that needs its reports.

use std::process::Command;

fn main() {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "rustc version unavailable".to_owned());
    println!("cargo::rustc-env=KESTRIKE_RUSTC_VERSION={version}");
    println!("cargo::rerun-if-env-changed=RUSTC");
    println!("cargo::rustc-check-cfg=cfg(kestrike_asan)");
    println!("cargo::rustc-check-cfg=cfg(kestrike_tsan)");
    let sanitizers = std::env::var("CARGO_CFG_SANITIZE").unwrap_or_default();
    for sanitizer in sanitizers.split(',') {
        match sanitizer {
            "address" => println!("cargo::rustc-cfg=kestrike_asan"),
            "thread" => println!("cargo::rustc-cfg=kestrike_tsan"),
            _ => {}
        }
    }
}
