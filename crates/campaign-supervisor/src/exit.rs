//! The process exit codes of every command family the `campaign` binary
//! runs, as one exhaustive enumeration. Each family keeps its own table, so
//! a code means one thing within its family.
//!
//! ```compile_fail,E0603
//! let gate = campaign_supervisor::exit::Gate(());
//! ```

/// One process exit, tagged by the command family that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// A `sim` launcher subcommand's exit.
    Sim(Sim),
    /// A supervisor subcommand's exit.
    Supervisor(Supervisor),
    /// A gate's failure before it executes its program.
    Gate(Gate),
}

macro_rules! sim_exits {
    ($($(#[$doc:meta])* $variant:ident => $code:literal, $name:literal;)+) => {
        /// The `sim` launcher's exits.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Sim { $($(#[$doc])* $variant,)+ }
        impl Sim {
            /// The class's name, as an artifact record names it.
            pub fn name(self) -> &'static str { match self { $(Self::$variant => $name,)+ } }
            fn code(self) -> u8 { match self { $(Self::$variant => $code,)+ } }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            pub(crate) fn from_code(code: u64) -> Option<Self> {
                match code { $($code => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

sim_exits! {
    /// 0: the result counts; for `sim archive`, the archive is published
    /// and verified.
    Counts => 0, "counts";
    /// 1: the run completed with a result that earns no credit.
    Complete => 1, "complete";
    /// 2: refused arguments or inputs.
    Rejected => 2, "rejected";
    /// 3: the archive build failed.
    BuildFailure => 3, "build-failure";
    /// 4: the run ended without a complete result; for `sim archive`, a
    /// closing checkout probe failed, a build input or output changed or vanished during the command, the
    /// output directory could not be created or removed, a write failed, a
    /// host fault such as `EIO` failed a check, the loader listing passed
    /// its deadline, or the published archive failed its verification, so
    /// the archive earns no use.
    Incomplete => 4, "incomplete";
    /// 5: a signal stopped the run.
    Interrupted => 5, "interrupted";
    /// 6: the run outlived its watchdog.
    Watchdog => 6, "watchdog";
}

/// The supervisor's exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    /// 0: the command did what it promises.
    Success,
    /// 1: the command reached a verdict other than success, for a command
    /// whose contract reports one.
    Verdict,
    /// 2: the command refused its arguments or an input record.
    Rejected,
    /// 3: another controller holds the state directory's lock.
    Busy,
    /// 4: a record, the state directory or the store is held, an admission
    /// limit such as the scan bound or `backlog` holds, or the store is
    /// poisoned. After a scan-bound hold `dispatch` starts nothing more;
    /// after a `backlog` hold it starts no more jobs and keeps starting
    /// triage steps. Either way it finishes and records the attempts it
    /// was running. A poisoned store writes nothing more.
    Held,
}

/// A gate failure from the custody or hardware command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate(());

/// The opening of the line the `gate` subcommand writes to standard error
/// for a failure before exec, ahead of the error.
#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
pub(crate) const GATE_LINE: &str = "campaign gate: ";

/// Whether `code` is the exit code a `gate` ends with when it fails before
/// it executes its program. A program the gate executed can end with the
/// same code, so [`gate_failed`] also requires the gate's line, and a
/// caller inspects that line only when this holds. Code outside this
/// module tests an exit code through this function, so among the crate's
/// production sources only this module and the binary's dispatch name
/// [`Gate`].
#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
pub(crate) fn gate_code(code: Option<i32>) -> bool {
    code == Some(i32::from(Gate::CODE))
}

/// Whether a process that exited with `code`, and whose captured output
/// opens with the line `first`, bears the signature of a `gate` that failed
/// before it executed its program: the gate's exit code and a first line
/// that opens with [`GATE_LINE`]. A sweep's replay passes the first line of
/// the worker's standard error pipe, and the fuzz driver the first line of
/// the job log, which holds standard output and standard error.
#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
pub(crate) fn gate_failed(code: Option<i32>, first: &str) -> bool {
    gate_code(code) && first.starts_with(GATE_LINE)
}

impl Gate {
    pub const CODE: u8 = 125;

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn hardware(args: &[std::ffi::OsString]) -> Exit {
        let Err(error) = crate::hardware::gate(args);
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "campaign hardware gate: {error}");
        Exit::Gate(Self(()))
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn run(args: &[std::ffi::OsString]) -> Exit {
        let Err(error) = crate::custody::gate::run(args);
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{GATE_LINE}{error}");
        Exit::Gate(Self(()))
    }
}

impl Exit {
    /// The process exit code.
    pub fn code(self) -> u8 {
        match self {
            Self::Sim(sim) => sim.code(),
            Self::Supervisor(supervisor) => match supervisor {
                Supervisor::Success => 0,
                Supervisor::Verdict => 1,
                Supervisor::Rejected => 2,
                Supervisor::Busy => 3,
                Supervisor::Held => 4,
            },
            Self::Gate(Gate(())) => Gate::CODE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Exit, GATE_LINE, Gate, Sim, Supervisor, gate_code, gate_failed};

    /// Each family's table holds its documented codes, and 125 comes only
    /// from the gate, so no launcher or supervisor exit collides with it.
    #[test]
    fn each_family_maps_to_its_table_and_only_the_gate_exits_125() {
        let sim = [
            (Sim::Counts, 0),
            (Sim::Complete, 1),
            (Sim::Rejected, 2),
            (Sim::BuildFailure, 3),
            (Sim::Incomplete, 4),
            (Sim::Interrupted, 5),
            (Sim::Watchdog, 6),
        ];
        let supervisor = [
            (Supervisor::Success, 0),
            (Supervisor::Verdict, 1),
            (Supervisor::Rejected, 2),
            (Supervisor::Busy, 3),
            (Supervisor::Held, 4),
        ];
        for (exit, code) in sim {
            assert_eq!(Exit::Sim(exit).code(), code, "{exit:?}");
        }
        for (exit, code) in supervisor {
            assert_eq!(Exit::Supervisor(exit).code(), code, "{exit:?}");
        }
        assert_eq!(Exit::Gate(Gate(())).code(), 125);
        assert_eq!(Gate::CODE, 125);
    }

    /// Only an exit with the gate's code matches, and a gate failure needs
    /// both that code and a first line that opens with the gate's own. With
    /// the gate's code, a line that holds the same text after other text,
    /// the hardware gate's opening, and the opening without its closing
    /// space are each refused, as is the opening after one space; the
    /// opening alone is accepted.
    #[test]
    fn a_gate_failure_needs_the_gates_code_and_its_line() {
        let gate = Some(i32::from(Gate::CODE));
        assert!(gate_code(gate));
        for other in [None, Some(0), Some(1), Some(124), Some(126), Some(-125)] {
            assert!(!gate_code(other), "{other:?}");
            assert!(!gate_failed(other, GATE_LINE), "{other:?}");
        }
        assert!(gate_failed(gate, &format!("{GATE_LINE}no such program")));
        assert!(!gate_failed(gate, "worker: exited 125"));
        assert!(!gate_failed(gate, ""));
        assert!(!gate_failed(
            gate,
            &format!("worker: {GATE_LINE}no such program")
        ));
        assert!(!gate_failed(gate, "campaign hardware gate: no such device"));
        assert!(!gate_failed(gate, &format!(" {GATE_LINE}no such program")));
        assert!(gate_failed(gate, GATE_LINE));
        assert!(!gate_failed(gate, GATE_LINE.trim_end()));
    }
}
