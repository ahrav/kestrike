//! Report snapshots and the admitted-registrant check over one Report, with the sole-registrant check as its case over no recorded pair.
//!
//! A Report's holding registrants group into pairs by (EXHID, key); a Report whose header names more registrants than `N_reg`, or a count its entries do not match, holds no trusted holding. The registrant check reads a mismatched count as no observation, and an over-bound count as a second registrant or as no observation by the rule [`Bounds::covers_recorded_pairs`] states. Registrants that hold nothing, a stale registration of an earlier controller included, leave the holding unchanged.
//!
//! ADMITTED-REGISTRANTS: [`Report::registrants`] admits the own pair as the holder and each recorded pair as a non-holding registrant. Any holder other than the own pair refuses, recorded or not. A refusal that a recorded pair could explain yields no observation when the caller read no recorded pairs, and an over-bound count yields no observation under a bound below `MAX_REGISTRANTS` when the recorded pairs and the own pair account for every listed pair and the count; every other refusal keeps its trigger. [`NotSole::unparsed`] applies the same rule to a parse refusal, whose entries are unread. [`Report::sole`] applies the rule over an empty recorded set. `Report::census` makes one pass over the entries for the own pair. `Report::verdict`, `Report::holding_of` and, in `storage::device`, `own_record`, `held_by_recorded`, `unheld_among_recorded` and the preempt constructors read its `Census`, or a copy with `unknown` overridden, and iterate no entry for the hold test. [`Report::holding`] iterates the entries itself, and so does the ended preempt's target test, `EndedPreempt::target`, over the entries under its key.

use super::bounds::Bounds;
use super::identity::{Exhid, Key};

/// The NVMe status code of a reservation conflict.
pub const RESERVATION_CONFLICT: u16 = 0x83;
/// The NVMe status code of a command aborted by a Preempt-and-Abort.
pub const PREEMPT_ABORTED: u16 = 0x1b;

/// The reservation a Report shows: type 2, Exclusive Access, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservationType {
    None,
    ExclusiveAccess,
}

/// The (EXHID, key) pair one registrant carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pair {
    pub exhid: Exhid,
    pub key: Key,
}

/// One registered-controller entry of an extended Report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Registrant {
    pub cntlid: u16,
    pub pair: Pair,
    /// The reservation status bit: this controller's host holds the reservation.
    pub holder: bool,
}

/// One extended Report as the parser delivers it. `submitted_at` is the host's clock when it submitted the Report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report<'a> {
    /// Elapsed-clock sample taken before submission, in the unit of [`Bounds`]. The clock counts suspend, or the caller invalidates its belief before resuming operations. Each process uses its own clock origin.
    pub submitted_at: u64,
    pub rtype: ReservationType,
    /// The registrant count the Report header states.
    pub regctl: u32,
    pub entries: &'a [Registrant],
}

/// Who holds the reservation according to one Report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Holding {
    /// No registrant holds, or the Report shows no reservation.
    Nobody,
    /// Every holding registrant carries this pair.
    One(Pair),
    /// Holding registrants carry two or more pairs.
    Several,
    /// The header names more than `N_reg` registrants or a count other than the entries, so no entry is trusted.
    Inconclusive,
}

/// What one pass over a Report's entries shows for an own pair and the pairs a caller admits beside it, built by
/// [`Report::census`] in that one pass. The judgments taken from it iterate no further entry, so they share that pass;
/// the ended preempt's target test, `EndedPreempt::target`, scans the entries under its key besides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Census {
    /// The number of entries that carry the own host ID.
    pub(crate) own_host: u32,
    /// An entry carries the own host ID under a key other than the own key.
    pub(crate) rekeyed: bool,
    /// An entry of the own pair holds.
    pub(crate) held: bool,
    /// The first holding pair other than the own pair, in entry order, and whether the caller admits it.
    pub(crate) foreign: Option<(Pair, bool)>,
    /// Holding entries carry a second pair other than the own pair.
    pub(crate) several: bool,
    /// An entry carries a pair that is neither the own pair nor admitted.
    pub(crate) unknown: bool,
}

/// The first item at or after `*from` that `matches`, or failing that the first before it; `*from` then names the
/// position after the match. A lookup without a match visits every item and leaves `*from` unchanged. Lookups that
/// arrive in the order of `items` each resume where the last one ended, so key-ordered entries that each match their
/// own item of a key-ordered set take one pass over both. When each lookup matches at most one item, lookups in any
/// order find the same items.
#[inline]
pub(crate) fn find_from<'t, T>(
    items: &'t [T],
    from: &mut usize,
    matches: impl Fn(&T) -> bool,
) -> Option<&'t T> {
    let mut at = *from;
    for _ in 0..items.len() {
        if at >= items.len() {
            at = 0;
        }
        let item = &items[at];
        at += 1;
        if matches(item) {
            *from = at;
            return Some(item);
        }
    }
    None
}

impl Report<'_> {
    /// Whether the header's count is within `N_reg` and equals the entries, so the entries are trusted.
    pub(crate) fn counted(&self, bounds: &Bounds) -> bool {
        self.regctl <= bounds.registrant_max() && self.entries.len() == self.regctl as usize
    }

    pub fn holding(&self, bounds: &Bounds) -> Holding {
        if !self.counted(bounds) {
            return Holding::Inconclusive;
        }
        if self.rtype == ReservationType::None {
            return Holding::Nobody;
        }
        let mut holders = self.entries.iter().filter(|entry| entry.holder);
        let Some(first) = holders.next() else {
            return Holding::Nobody;
        };
        if holders.all(|entry| entry.pair == first.pair) {
            Holding::One(first.pair)
        } else {
            Holding::Several
        }
    }

    /// The census of the entries for `own`. `admits` is called once for each entry of another pair, in entry order,
    /// and returns whether the caller admits that pair as a registrant.
    #[inline]
    pub(crate) fn census(&self, own: Pair, mut admits: impl FnMut(&Pair) -> bool) -> Census {
        let mut census = Census {
            own_host: 0,
            rekeyed: false,
            held: false,
            foreign: None,
            several: false,
            unknown: false,
        };
        for entry in self.entries {
            let own_host = entry.pair.exhid == own.exhid;
            census.own_host += u32::from(own_host);
            if own_host && entry.pair.key == own.key {
                census.held |= entry.holder;
                continue;
            }
            census.rekeyed |= own_host;
            let admitted = admits(&entry.pair);
            census.unknown |= !admitted;
            if entry.holder {
                match census.foreign {
                    None => census.foreign = Some((entry.pair, admitted)),
                    Some((first, _)) => census.several |= first != entry.pair,
                }
            }
        }
        census
    }

    /// [`Report::holding`] read from `census`, the census of the entries for `own`.
    pub(crate) fn holding_of(&self, census: &Census, own: Pair, bounds: &Bounds) -> Holding {
        if !self.counted(bounds) {
            return Holding::Inconclusive;
        }
        if self.rtype == ReservationType::None {
            return Holding::Nobody;
        }
        match (census.held, census.foreign) {
            (false, None) => Holding::Nobody,
            (true, None) => Holding::One(own),
            (false, Some((holder, _))) if !census.several => Holding::One(holder),
            _ => Holding::Several,
        }
    }
}

/// Why a Report refuses the own pair as the holder of a type-2 reservation; each variant but `Unreadable` is a retirement trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotSole {
    /// The header count exceeds `N_reg`, and the recorded pairs cannot account for the registrants.
    Excess,
    /// The Report is no observation: its count does not match its entries, its count exceeds `N_reg` while the
    /// recorded pairs may account for the registrants, or the caller read no volume record and a non-holding
    /// registrant is neither the own pair nor known to be recorded.
    Unreadable,
    /// The Report shows no type-2 reservation.
    ReservationType,
    /// More than one inspected entry carries the own host ID, as the verdict judges it; the parser's refusal of one
    /// own-host entry under another key (`ReportError::OwnHostIdKey`) and the authority's census of a second own
    /// record map to it as well.
    DuplicateOwnRecord,
    /// An entry of a pair other than the own pair holds the reservation, recorded or not.
    ForeignHolder,
    /// An entry of a pair that is neither the own pair nor a recorded pair is registered.
    ForeignRegistrant,
    /// The own entry is absent or does not hold.
    NotHolder,
}

impl NotSole {
    /// Returns whether the refusal rests on an observed registrant set.
    pub fn observed(self) -> bool {
        match self {
            Self::Unreadable => false,
            Self::Excess
            | Self::ReservationType
            | Self::DuplicateOwnRecord
            | Self::ForeignHolder
            | Self::ForeignRegistrant
            | Self::NotHolder => true,
        }
    }

    /// ADMITTED-REGISTRANTS over the refusal of a parse whose entries are unread, with `recorded` as in
    /// [`Report::registrants`]. The parser refuses a count above the reservation limits, which attach holds equal to
    /// `N_reg`, as [`NotSole::Excess`] before reading the entries, so no listed pair is shown recorded: the refusal
    /// stands, except that it is [`NotSole::Unreadable`] when the caller read no recorded pairs and
    /// [`Bounds::covers_recorded_pairs`] fails. Every other refusal is unchanged.
    pub fn unparsed<'r>(
        self,
        recorded: Option<impl IntoIterator<Item = &'r Pair>>,
        bounds: &Bounds,
    ) -> Self {
        match self {
            Self::Excess if recorded.is_none() && !bounds.covers_recorded_pairs() => {
                Self::Unreadable
            }
            refusal => refusal,
        }
    }
}

impl Report<'_> {
    /// Checks that the Report's count is conclusive and that it shows `own` as the one registrant and the holder of
    /// a type-2 reservation, with the own host ID on one entry: [`Report::registrants`] over no recorded pair.
    ///
    /// # Errors
    ///
    /// The first failure in [`NotSole`]'s variant order.
    pub fn sole(&self, own: Pair, bounds: &Bounds) -> Result<(), NotSole> {
        self.registrants(own, Some(&[]), bounds)
    }

    /// ADMITTED-REGISTRANTS over `recorded`, the recorded pairs of the volume record the caller read, or `None` when it read none. The Report passes when the own pair holds a type-2 reservation, the own host ID is on one entry, and every other registrant holds nothing and carries a recorded pair.
    ///
    /// A count above `N_reg` yields [`NotSole::Excess`] when [`Bounds::covers_recorded_pairs`] holds, or when `recorded` is `Some` and either a listed pair falls outside the recorded pairs plus `own` or the count exceeds that set's size; otherwise it yields [`NotSole::Unreadable`]. The count comparison assumes one controller per pair. Such a Report reaches this rule parsed only under reservation limits above `N_reg`; see [`Bounds::covers_recorded_pairs`].
    ///
    /// # Errors
    ///
    /// The first failure in [`NotSole`]'s variant order, except that the `Unreadable` of an unknown non-holding
    /// registrant under an unread volume record follows `NotHolder`.
    pub fn registrants(
        &self,
        own: Pair,
        recorded: Option<&[Pair]>,
        bounds: &Bounds,
    ) -> Result<(), NotSole> {
        let census = self.census(own, |pair| {
            recorded.is_some_and(|pairs| pairs.iter().any(|recorded| recorded == pair))
        });
        self.verdict(&census, own, recorded.map(<[Pair]>::iter), bounds)
    }

    /// The verdict of [`Report::registrants`] read from `census`, the census of the entries for `own` that admits
    /// the pairs of `recorded`, or no pair when `recorded` is `None`.
    pub(crate) fn verdict<'r>(
        &self,
        census: &Census,
        own: Pair,
        recorded: Option<impl Iterator<Item = &'r Pair> + Clone>,
        bounds: &Bounds,
    ) -> Result<(), NotSole> {
        let read = recorded.is_some();
        if self.regctl > bounds.registrant_max() {
            let conclusive = bounds.covers_recorded_pairs()
                || recorded.is_some_and(|mut pairs| {
                    let len = pairs.clone().count();
                    let admitted = len + usize::from(!pairs.any(|pair| *pair == own));
                    census.unknown || self.regctl as usize > admitted
                });
            return Err(if conclusive {
                NotSole::Excess
            } else {
                NotSole::Unreadable
            });
        }
        if self.entries.len() != self.regctl as usize {
            return Err(NotSole::Unreadable);
        }
        if self.rtype != ReservationType::ExclusiveAccess {
            return Err(NotSole::ReservationType);
        }
        // In a complete ExclusiveAccess Report, own is the sole holder when at least one entry holds and every
        // holder entry belongs to own.
        if census.own_host > 1 {
            return Err(NotSole::DuplicateOwnRecord);
        }
        if census.foreign.is_some() {
            return Err(NotSole::ForeignHolder);
        }
        if census.unknown && read {
            return Err(NotSole::ForeignRegistrant);
        }
        if !census.held {
            return Err(NotSole::NotHolder);
        }
        if census.unknown {
            return Err(NotSole::Unreadable);
        }
        Ok(())
    }
}
