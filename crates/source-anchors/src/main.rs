//! Lists the declarations of one Rust source file for
//! `scripts/measurement-frame.py`, which resolves a frame source's
//! `{path, symbol}` anchor against them, and for
//! `scripts/sizing-worksheet.py`, which evaluates a structural input's
//! constant from them.
//!
//! The file arrives on standard input. Each output line is
//! `<build>\t<kind>\t<text>`:
//!
//! - `build` is `production` when the declaration exists in a build without
//!   `test`, and `gated` when one of its attributes, or one of an enclosing
//!   item's, removes it from every such build ([`gating`]).
//! - `kind` is `item`, `field`, `variant`, `module` for a `mod name;` line
//!   among the file's own items, declaring an out-of-line child module, or
//!   `value` for the initializer of the `const` listed on the line before.
//! - `text` is the declaration's visibility, keyword and name
//!   (`pub(crate) fn moved`), a named field's visibility and name
//!   (`pub held_units`), a variant's name, or a `const`'s text, ` = ` and its
//!   initializer rendered as integer arithmetic
//!   (`pub const IO_UNIT = 4096`). A `value` line exists only for a `const`
//!   whose initializer renders as integer arithmetic ([`value`]).
//!
//! Exit 0 lists the file. Exit 2 reports, on standard error, a file that is
//! unreadable or that does not parse as Rust, and lists nothing.

mod gating;
mod listing;
mod value;

use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut source = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut source) {
        eprintln!("source-anchors: standard input is unreadable: {error}");
        return ExitCode::from(2);
    }
    match listing::declarations(&source) {
        Ok(declarations) => {
            for declaration in declarations {
                println!("{declaration}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("source-anchors: the source does not parse as Rust: {error}");
            ExitCode::from(2)
        }
    }
}
