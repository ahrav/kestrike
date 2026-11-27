//! Keep `tools!` entries sorted by tool name.

use std::ffi::OsString;
use std::path::Path;

pub type Entry = fn(&Path, &[OsString]) -> u8;

macro_rules! tools {
    ($($name:literal => $module:ident,)*) => {
        $(pub mod $module;)*

        pub const NAMES: &[&str] = &[$($name),*];

        pub fn entry(name: &str) -> Option<Entry> {
            match name {
                $($name => Some($module::run),)*
                _ => None,
            }
        }
    };
}

tools! {
    "escrow_fixtures" => escrow_fixtures,
    "gate_fixtures" => gate_fixtures,
    "marklog_fixtures" => marklog_fixtures,
}
