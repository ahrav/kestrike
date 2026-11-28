//! [`Starts`], the plane's case starts: each start hands out the next case a test holds, and is
//! logged with its words, its added environment and whether it passed the host reservation.

use std::collections::VecDeque;
use std::io;

use kestrike_tools::fis_controller::Launch;

use super::case::Case;
use super::clock::Clock;

/// One start the plane was asked for.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Started {
    pub(crate) words: Vec<String>,
    pub(crate) environment: Vec<(String, String)>,
    pub(crate) reserved: bool,
}

/// The cases still to hand out and the starts asked for.
#[derive(Default)]
pub(crate) struct Starts {
    cases: VecDeque<Case>,
    pub(crate) log: Vec<Started>,
}

impl Starts {
    /// Adds a case on `clock` that the next start hands out.
    ///
    /// # Panics
    ///
    /// Where the case reads another clock than the plane's.
    pub(crate) fn hold(&mut self, clock: &Clock, case: Case) {
        assert!(
            case.clock().same(clock),
            "a held case reads the plane's clock"
        );
        self.cases.push_back(case);
    }

    /// Logs the start and hands out the next case held, or fails with `ENOENT` where none is held.
    pub(crate) fn start(&mut self, launch: &Launch<'_>) -> io::Result<Case> {
        let lossy = |word: &std::ffi::OsString| word.to_string_lossy().into_owned();
        self.log.push(Started {
            words: launch.words.iter().map(lossy).collect(),
            environment: launch
                .environment
                .iter()
                .map(|(name, value)| (lossy(name), lossy(value)))
                .collect(),
            reserved: launch.reservation.is_some(),
        });
        self.cases
            .pop_front()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }
}
