//! A GenMC case build compiles the kernel package's files and the production files they include via
//! `#[path]`; [`sources::package_sources`] lists those files.

pub mod case;
pub mod correspondence;
pub mod evidence;
pub mod refusal;
pub mod sources;
pub mod transcription;

pub use sources::{
    INCLUDED, WALK_DEPTH, bodies, code, is_file, lexeme_text, no_nul, normalized, package_sources,
    read_source, read_text, under_target, walk,
};
