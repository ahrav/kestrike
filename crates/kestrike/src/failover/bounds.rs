//! The validated bounds of the serving core. The caller supplies every bound; construction refuses a zero bound and a serving window at or below the Report period plus the Report deadline plus the clock error, so a belief taken from one Report outlives the next Report's deadline.

/// The most recorded pairs a volume record holds. A Report that lists every recorded pair is conclusive only under
/// a registrant bound `N_reg` of at least this value.
pub const MAX_REGISTRANTS: usize = 8;

/// A bound the caller supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Parameter {
    /// `N_reg`: the most registrants a Report may carry before its holding is inconclusive; [`Bounds::covers_recorded_pairs`] states when the registrant rule reads a higher count as a second registrant.
    RegistrantMax,
    /// `N_retry`: construction requires it to be positive.
    RetryMax,
    /// `delta`: the serving window after a Report's submission.
    Window,
    /// `T_report`: the time by which a Report must be certified after its submission.
    ReportDeadline,
    /// `P_report`: the period between Report submissions.
    ReportPeriod,
}

/// Why the bounds were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundsError {
    Zero(Parameter),
    /// A timing sum exceeds its counter's range.
    Overflow,
    /// `delta` is at most `P_report + T_report + tau`, which is `needed_above`.
    WindowTooShort {
        window: u64,
        needed_above: u64,
    },
}

/// The bounds, held only in a validated instance. Times share one caller-chosen unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bounds {
    registrant_max: u32,
    retry_max: u32,
    window: u64,
    report_deadline: u64,
    report_period: u64,
}

impl Bounds {
    /// Validates `N_reg`, `N_retry`, `delta`, `T_report`, `P_report` and the clock error `tau`. A zero refuses in the order [`Parameter`] lists the bounds; `tau` may be zero.
    pub fn new(
        registrant_max: u32,
        retry_max: u32,
        window: u64,
        report_deadline: u64,
        report_period: u64,
        clock_error: u64,
    ) -> Result<Self, BoundsError> {
        let zero = [
            (u64::from(registrant_max), Parameter::RegistrantMax),
            (u64::from(retry_max), Parameter::RetryMax),
            (window, Parameter::Window),
            (report_deadline, Parameter::ReportDeadline),
            (report_period, Parameter::ReportPeriod),
        ];
        if let Some((_, parameter)) = zero.into_iter().find(|(value, _)| *value == 0) {
            return Err(BoundsError::Zero(parameter));
        }
        let needed_above = report_period
            .checked_add(report_deadline)
            .and_then(|sum| sum.checked_add(clock_error))
            .ok_or(BoundsError::Overflow)?;
        if window <= needed_above {
            return Err(BoundsError::WindowTooShort {
                window,
                needed_above,
            });
        }
        Ok(Self {
            registrant_max,
            retry_max,
            window,
            report_deadline,
            report_period,
        })
    }

    pub fn registrant_max(&self) -> u32 {
        self.registrant_max
    }

    /// Whether a Report listing every recorded pair of a volume record is conclusive: `N_reg` is at least
    /// [`MAX_REGISTRANTS`]. Under a smaller bound, [`Report::registrants`](super::evidence::Report::registrants)
    /// reads an over-bound Report as no observation when the caller read no volume record, or when the recorded pairs
    /// and the own pair account for every listed pair and the count; every other over-bound Report is `Excess`. The
    /// second case needs a parse under reservation limits above `N_reg`: attach requires the two equal, and the
    /// parser then refuses the count before reading the entries, which [`NotSole::unparsed`](super::evidence::NotSole::unparsed)
    /// keeps `Excess` unless the volume record is unread.
    pub fn covers_recorded_pairs(&self) -> bool {
        usize::try_from(self.registrant_max).is_ok_and(|max| max >= MAX_REGISTRANTS)
    }

    /// The most recorded pairs an enrollment under this bound leaves in a volume record: `MAX_REGISTRANTS`, or
    /// `N_reg` when that is smaller.
    pub fn pair_cap(&self) -> usize {
        usize::try_from(self.registrant_max).map_or(MAX_REGISTRANTS, |max| max.min(MAX_REGISTRANTS))
    }

    pub fn retry_max(&self) -> u32 {
        self.retry_max
    }

    pub fn report_period(&self) -> u64 {
        self.report_period
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    pub fn report_deadline(&self) -> u64 {
        self.report_deadline
    }
}
