//! The cut core enumerates recovery cuts as plain data from a workload's
//! descriptor. `sim::cut_guard_tests` holds these sources to the standard
//! library, `sha2` and their own modules, and flags any form that passes
//! caller behavior into the core.

mod descriptor;
mod enumerate;
mod identity;

pub(crate) use self::descriptor::{Child, Descriptor, Point, Reach, State, Unit};
pub(crate) use self::enumerate::{MaskError, Refusal, enumerate, plan};
pub(crate) use self::identity::{Boundary, Class, Cut, Site, registry, registry_hash};
