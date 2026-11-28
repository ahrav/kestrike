//! The rules by which a red-green run judges a regression test: a red base leg, where the test fails with an
//! expected text, and a green head leg, where it passes.

pub mod evidence;
pub mod expected;
pub mod options;
pub mod reasons;
pub mod record;
pub mod runner;
pub mod tree;

pub use evidence::STREAMS;
