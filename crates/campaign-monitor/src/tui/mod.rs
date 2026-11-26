//! The terminal monitor. `event_loop` registers the signal listener before
//! the terminal session starts, so SIGTERM, SIGHUP and SIGINT always end
//! the loop through the session's restore.

mod bindings;
pub mod event_loop;
pub mod keymap;
pub mod term;
pub mod text;
pub mod theme;

pub use event_loop::run;
