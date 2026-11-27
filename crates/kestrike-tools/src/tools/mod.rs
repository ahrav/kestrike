//! A tool is a module under this directory, `<module>.rs` or `<module>/mod.rs`, whose root holds
//! `pub const NAME: &str` and `pub fn run`. The file included from `OUT_DIR` declares every tool module and
//! calls `tools!` with them.
//!
//! [`NAMES`] ascends by the names' bytes. Two tools of one name fail the build at [`entry`].

use std::ffi::OsString;
use std::path::Path;

pub type Entry = fn(&Path, &[OsString]) -> u8;

macro_rules! tools {
    ($($module:ident),* $(,)?) => {
        /// Every tool's name, in ascending order of bytes.
        pub const NAMES: &[&str] = &sorted([$($module::NAME),*]);

        /// Two modules with one `NAME` make the later arm unreachable, so `#[deny(unreachable_patterns)]`
        /// turns a name collision into a build error.
        #[deny(unreachable_patterns)]
        pub fn entry(name: &str) -> Option<Entry> {
            match name {
                $($module::NAME => Some($module::run),)*
                _ => None,
            }
        }
    };
}

include!(concat!(env!("OUT_DIR"), "/tools.rs"));

/// `sorted` returns `names` in ascending order of their bytes; it runs while the crate compiles.
const fn sorted<const N: usize>(mut names: [&'static str; N]) -> [&'static str; N] {
    let mut at = 1;
    while at < N {
        let mut place = at;
        while place > 0 && precedes(names[place], names[place - 1]) {
            let moved = names[place];
            names[place] = names[place - 1];
            names[place - 1] = moved;
            place -= 1;
        }
        at += 1;
    }
    names
}

/// `precedes` is `a < b` for `str`, computed byte by byte so that constant evaluation runs it.
const fn precedes(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut at = 0;
    while at < a.len() && at < b.len() {
        if a[at] != b[at] {
            return a[at] < b[at];
        }
        at += 1;
    }
    a.len() < b.len()
}

#[cfg(test)]
#[path = "../tools_tests.rs"]
mod tests;
