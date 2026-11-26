//! Suspicion tags a host observation generation; `arbiter::Observation` states when a nominating caller opens a
//! newer one.
//! Observed windows contribute failure evidence. Gaps retain the empty, stalled
//! and declared counts and existing suspicion, and reset exit progress and
//! heartbeat flags. A peer holds a declared suspicion once `D` observed windows
//! admitted a heartbeat and every heartbeat admitted since the last healthy one
//! reported the peer unhealthy; a window with no heartbeat keeps that count, and
//! a healthy heartbeat, in an observed window or a gap, ends it and turns a
//! declared suspicion gray. A declared reading needs a closed window that
//! admitted a heartbeat and whose every admitted heartbeat reported the peer
//! unhealthy.
//! `beat` is the authenticated host heartbeat and `host` the observer's host
//! detector, which admits heartbeats into these windows, records indirect probe
//! votes and publishes named-target nominations. `probe` is the authenticated
//! indirect probe request and reply that hosts' agents exchange for those votes.

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod beat;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod host;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod probe;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "detect_host_tests.rs"]
pub(crate) mod tests;

/// The host detector's observation generation tags local suspicion and probe votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObservationGeneration(pub u64);

/// Detector timing and the AZ-wide peer-table bound, in one clock unit.
#[derive(Debug, Clone, Copy)]
pub struct DetectBounds {
    /// `h`: logical window duration.
    pub h: u64,
    /// `D`: consecutive observed failure windows before suspicion.
    pub d: u32,
    /// `tau`: clock-error bound in the caller's time unit.
    pub tau: u64,
    /// Heartbeat delivery and scheduling jitter bound.
    pub jitter: u64,
    /// `G_peer`: new-peer grace duration.
    pub peer_grace: u64,
    /// `E`: consecutive observed recovery windows needed for exit.
    pub exit_windows: u32,
    /// `T_dwell`: minimum suspicion duration before exit.
    pub dwell: u64,
    /// Maximum hosts tracked at once; the peer table reserves this many slots
    /// and refills a slot `untrack` vacated.
    pub hosts: usize,
}

/// Invalid bounds, table exhaustion or an early, reversed or misaligned window close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectRefusal {
    Window,
    Threshold,
    Timing,
    Grace,
    Exit,
    Dwell,
    Hosts,
    PeerLimit,
    Allocation,
    Time,
}

impl DetectBounds {
    /// Checks `d * h > tau + jitter + h`, positive limits, `d >= 2` and `dwell >= h`.
    pub fn validate(self) -> Result<Self, DetectRefusal> {
        if self.h == 0 {
            return Err(DetectRefusal::Window);
        }
        if self.d < 2 {
            return Err(DetectRefusal::Threshold);
        }
        let threshold = self
            .h
            .checked_mul(u64::from(self.d))
            .ok_or(DetectRefusal::Timing)?;
        let margin = self
            .tau
            .checked_add(self.jitter)
            .and_then(|v| v.checked_add(self.h))
            .ok_or(DetectRefusal::Timing)?;
        if threshold <= margin {
            return Err(DetectRefusal::Timing);
        }
        if self.peer_grace == 0 {
            return Err(DetectRefusal::Grace);
        }
        if self.exit_windows == 0 {
            return Err(DetectRefusal::Exit);
        }
        if self.dwell < self.h {
            return Err(DetectRefusal::Dwell);
        }
        if self.hosts == 0 {
            return Err(DetectRefusal::Hosts);
        }
        Ok(self)
    }
}

/// Silence, stalled progress and a declared hold require different exit evidence. A suspicion's kind is the
/// peer's retained state; a window close, [`host::Watch::liveness`](host::Watch::liveness) and the arbiter's input
/// can read it as another kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// `D` observed windows with no heartbeat. It ends after the exit count of windows with a healthy heartbeat
    /// plus the dwell. At that exit the suspicion turns gray if the stalled count is at least `D`. A window with no
    /// heartbeat restarts the exit count; a window whose every heartbeat reports the peer unhealthy keeps it.
    Silent,
    /// DEAD evidence the arbiter nominates only on counted votes of two observer classes: an observed stall, where
    /// heartbeats arrive and progress does not, and every declared suspicion or reading that has lost its
    /// freshness: a declared suspicion after a healthy heartbeat, a declared suspicion read in a window without a
    /// declaring heartbeat, and declared evidence under the observer's brake on correlated declarations.
    Gray,
    /// `D` observed windows admitted a heartbeat and every heartbeat admitted since the last healthy one reported
    /// the peer unhealthy. A reading carries it only for a closed window that admitted a heartbeat and no healthy
    /// one; a window with no heartbeat reads it gray, or silent once the empty count reaches `D`. A healthy
    /// heartbeat turns the suspicion gray, and the gray exit rule then ends it on progress.
    Declared,
}

impl Failure {
    /// Whether the arbiter nominates on this kind only with counted votes of two observer classes.
    pub fn needs_second_class(self) -> bool {
        match self {
            Failure::Gray => true,
            Failure::Silent | Failure::Declared => false,
        }
    }
}

/// A suspicion tied to the tracked peer's observation generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suspicion {
    pub generation: ObservationGeneration,
    pub failure: Failure,
    pub since: u64,
}

/// Only Dead contributes negative liveness evidence; probe exhaustion returns Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    Dead(Suspicion),
    Unknown,
}

/// One peer's counters; sequence and progress advance independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    generation: ObservationGeneration,
    tracked_since: u64,
    window_at: u64,
    sequence: Option<u64>,
    progress: Option<u64>,
    seen: bool,
    progressed: bool,
    /// The open window admitted a heartbeat that reported the peer healthy.
    affirmed: bool,
    empty: u32,
    stalled: u32,
    /// Observed windows that admitted a heartbeat and no healthy one since the last healthy heartbeat.
    declared: u32,
    /// The last close read a declared failure, before any exhaustion mask, and no heartbeat admitted since reported
    /// the peer healthy.
    declares: bool,
    /// A heartbeat reporting the peer healthy turned the held suspicion from declared to gray.
    demoted: bool,
    exit: u32,
    suspicion: Option<Suspicion>,
}

impl Peer {
    /// Starts observations for one authenticated host boot and observation generation.
    pub fn new(generation: ObservationGeneration, now: u64) -> Self {
        Self {
            generation,
            tracked_since: now,
            window_at: now,
            sequence: None,
            progress: None,
            seen: false,
            progressed: false,
            affirmed: false,
            empty: 0,
            stalled: 0,
            declared: 0,
            declares: false,
            demoted: false,
            exit: 0,
            suspicion: None,
        }
    }

    /// Starts fresh same-boot observations while retaining sequence and progress
    /// high-water. The caller supplies a newer observation generation and a
    /// local time at or above the last close; refusal preserves the peer.
    pub fn retrack(
        &mut self,
        generation: ObservationGeneration,
        now: u64,
    ) -> Result<(), DetectRefusal> {
        self.admit(generation, now)?;
        *self = Self {
            sequence: self.sequence,
            progress: self.progress,
            ..Self::new(generation, now)
        };
        Ok(())
    }

    /// Starts observations of this host's next boot, whose sequence and progress
    /// restart from zero. The caller supplies a newer observation generation and
    /// a local time at or above the last close; refusal preserves the peer.
    pub fn reboot(
        &mut self,
        generation: ObservationGeneration,
        now: u64,
    ) -> Result<(), DetectRefusal> {
        self.admit(generation, now)?;
        *self = Self::new(generation, now);
        Ok(())
    }

    fn admit(&self, generation: ObservationGeneration, now: u64) -> Result<(), DetectRefusal> {
        if generation <= self.generation || now < self.window_at {
            return Err(DetectRefusal::Time);
        }
        Ok(())
    }

    pub fn generation(&self) -> ObservationGeneration {
        self.generation
    }

    pub fn tracked_since(&self) -> u64 {
        self.tracked_since
    }

    pub fn window_at(&self) -> u64 {
        self.window_at
    }

    pub fn sequence(&self) -> Option<u64> {
        self.sequence
    }

    pub fn suspicion(&self) -> Option<Suspicion> {
        self.suspicion
    }

    /// Whether the last close read a declared failure, exhaustion aside, and no heartbeat admitted since reported the
    /// peer healthy: a fresh declared reading.
    pub fn declares(&self) -> bool {
        self.declares
    }

    /// A declaration stands from its first declared reading and persists across windows the peer's heartbeat
    /// misses, where [`Peer::declares`] is false. A heartbeat reporting the peer healthy ends it. `D` consecutive
    /// observed windows with no heartbeat suspend it until the peer's next heartbeat.
    pub fn stands_declared(&self, b: &DetectBounds) -> bool {
        self.suspicion
            .is_some_and(|s| s.failure == Failure::Declared)
            && !self.affirmed
            && self.empty < b.d
    }

    /// Whether the peer is leaving a declared hold on healthy heartbeats that progress: its declared suspicion
    /// stands and the open window admitted a healthy heartbeat and progress, or a healthy heartbeat turned that
    /// suspicion gray and every observed window closed since has progressed. A window without progress and an
    /// unobserved close end it until the next observed window that progresses.
    pub fn recovers(&self) -> bool {
        match self.suspicion.map(|s| s.failure) {
            Some(Failure::Declared) => self.affirmed && self.progressed,
            Some(Failure::Gray) => self.demoted && self.exit > 0,
            _ => false,
        }
    }

    /// The window flags and the declared count, for the model replay.
    #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn declared_state(&self) -> (bool, u32) {
        (self.affirmed, self.declared)
    }

    /// Whether `D` consecutive empty or stalled windows stand, the counts at which an observed close outside
    /// new-peer grace sets a suspicion. Inside the grace, and after an unobserved close, they stand with none set.
    pub fn failing(&self, b: &DetectBounds) -> bool {
        self.empty >= b.d || self.stalled >= b.d
    }

    /// The caller supplies an authenticated, assignment-named heartbeat from this boot and the sender's health bit.
    /// A duplicate preserves every field, including the window's seen and affirmed flags.
    pub fn heartbeat(&mut self, sequence: u64, progress: u64, healthy: bool) {
        if self.sequence.is_some_and(|old| sequence <= old) {
            return;
        }
        self.sequence = Some(sequence);
        self.seen = true;
        self.affirmed |= healthy;
        #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
        let healthy = healthy && !tests::plant("stale-declared");
        self.declares &= !healthy;
        self.empty = 0;
        if self.progress.is_none_or(|old| progress > old) {
            self.progress = Some(progress);
            self.progressed = true;
            self.stalled = 0;
        }
    }

    /// Close an observed logical window exactly `h` after the last accepted close
    /// or construction time. A gap (`observed=false`) closes at least `h` later
    /// and reanchors the boundary. Time-range refusal preserves the peer.
    /// Exhaustion masks the result as Unknown while counters still advance.
    pub fn window(
        &mut self,
        b: &DetectBounds,
        now: u64,
        observed: bool,
        exhausted: bool,
    ) -> Result<Liveness, DetectRefusal> {
        self.close(&b.validate()?, now, observed, exhausted)
    }

    /// The caller validates `b` before calling `close`.
    fn close(
        &mut self,
        b: &DetectBounds,
        now: u64,
        observed: bool,
        exhausted: bool,
    ) -> Result<Liveness, DetectRefusal> {
        let elapsed = now.checked_sub(self.window_at).ok_or(DetectRefusal::Time)?;
        if elapsed < b.h || (observed && elapsed != b.h) {
            return Err(DetectRefusal::Time);
        }
        self.window_at = now;
        // The window admitted a heartbeat and every admitted one reported the peer unhealthy.
        let declaring = self.seen && !self.affirmed;
        // A healthy heartbeat, in an observed window or a gap, ends the declared count and turns a declared
        // suspicion gray, whose exit needs progress.
        if self.affirmed {
            self.declared = 0;
            if let Some(s) = &mut self.suspicion
                && s.failure == Failure::Declared
            {
                s.failure = Failure::Gray;
                self.demoted = true;
            }
        }
        if observed {
            self.empty = if self.seen {
                0
            } else {
                self.empty.saturating_add(1)
            };
            self.stalled = if self.progressed {
                0
            } else {
                self.stalled.saturating_add(1)
            };
            // A window with no heartbeat keeps the count: heartbeats that straddle window edges leave some windows
            // empty, and only a healthy heartbeat ends a declaration.
            if declaring {
                self.declared = self.declared.saturating_add(1);
            }
            let declares = declaring && self.declared >= b.d;
            #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
            let declares = declares && !tests::plant("declared-as-gray");
            if now - self.tracked_since >= b.peer_grace {
                if let Some(s) = &mut self.suspicion {
                    if declares {
                        // A declaration at the onset count relabels any held suspicion before its exit is judged.
                        s.failure = Failure::Declared;
                        self.exit = 0;
                        self.demoted = false;
                    } else {
                        // For a silent suspicion, windows whose every heartbeat reports the peer unhealthy
                        // preserve `exit`, so healthy windows separated by them count toward `exit_windows`.
                        let nonempty = match s.failure {
                            Failure::Silent => self.seen && self.affirmed,
                            Failure::Gray => self.progressed,
                            Failure::Declared => false,
                        };
                        if nonempty {
                            self.exit = self.exit.saturating_add(1);
                        } else if !(s.failure == Failure::Silent && declaring) {
                            self.exit = 0;
                        }
                        if nonempty && self.exit >= b.exit_windows && now - s.since >= b.dwell {
                            self.suspicion = (s.failure == Failure::Silent && self.stalled >= b.d)
                                .then_some(Suspicion {
                                    failure: Failure::Gray,
                                    ..*s
                                });
                            self.exit = 0;
                            self.demoted = false;
                        }
                    }
                } else if declares || self.empty >= b.d || self.stalled >= b.d {
                    // A declaring window admitted a heartbeat, so its empty count is 0.
                    self.suspicion = Some(Suspicion {
                        generation: self.generation,
                        failure: if declares {
                            Failure::Declared
                        } else if self.empty >= b.d {
                            Failure::Silent
                        } else {
                            Failure::Gray
                        },
                        since: now,
                    });
                }
            }
        } else {
            self.exit = 0;
        }
        self.seen = false;
        self.progressed = false;
        self.affirmed = false;
        let reading = self.suspicion.map(|mut s| {
            if self.empty >= b.d {
                s.failure = Failure::Silent;
            } else if s.failure == Failure::Declared && !declaring {
                s.failure = Failure::Gray;
            }
            s
        });
        self.declares = reading.is_some_and(|s| s.failure == Failure::Declared);
        Ok(if exhausted {
            Liveness::Unknown
        } else {
            reading.map_or(Liveness::Alive, Liveness::Dead)
        })
    }
}

/// A handle to one tracked slot. `track` issues each handle with a fresh
/// incarnation, so a handle held across `untrack` reaches no later occupant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSlot {
    index: usize,
    incarnation: u64,
}

struct Slot {
    incarnation: u64,
    peer: Option<Peer>,
}

/// A peer table reserves exactly the validated AZ host maximum. `track` fills
/// the lowest vacant slot before reserving a new one.
pub struct Detector {
    bounds: DetectBounds,
    slots: Vec<Slot>,
    issued: u64,
}

impl Detector {
    pub fn new(bounds: DetectBounds) -> Result<Self, DetectRefusal> {
        let bounds = bounds.validate()?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(bounds.hosts)
            .map_err(|_| DetectRefusal::Allocation)?;
        Ok(Self {
            bounds,
            slots,
            issued: 0,
        })
    }
    /// Tracks one authenticated host observation generation. `PeerLimit` when
    /// every slot is occupied or the incarnation counter is exhausted.
    pub fn track(
        &mut self,
        generation: ObservationGeneration,
        now: u64,
    ) -> Result<PeerSlot, DetectRefusal> {
        let vacant = self.slots.iter().position(|slot| slot.peer.is_none());
        if vacant.is_none() && self.slots.len() >= self.bounds.hosts {
            return Err(DetectRefusal::PeerLimit);
        }
        let incarnation = self.issued;
        self.issued = self.issued.checked_add(1).ok_or(DetectRefusal::PeerLimit)?;
        let slot = Slot {
            incarnation,
            peer: Some(Peer::new(generation, now)),
        };
        let index = match vacant {
            Some(index) => {
                self.slots[index] = slot;
                index
            }
            None => {
                self.slots.push(slot);
                self.slots.len() - 1
            }
        };
        Ok(PeerSlot { index, incarnation })
    }
    fn slot(&mut self, handle: PeerSlot) -> Option<&mut Slot> {
        self.slots
            .get_mut(handle.index)
            .filter(|slot| slot.incarnation == handle.incarnation)
    }
    fn tracked(&mut self, handle: PeerSlot) -> Option<&mut Peer> {
        self.slot(handle)?.peer.as_mut()
    }
    /// Vacates the slot; the handle and every copy of it reach nothing afterwards.
    pub fn untrack(&mut self, handle: PeerSlot) -> Option<()> {
        self.slot(handle)?.peer.take().map(|_| ())
    }
    pub fn peer(&self, handle: PeerSlot) -> Option<&Peer> {
        self.slots
            .get(handle.index)
            .filter(|slot| slot.incarnation == handle.incarnation)?
            .peer
            .as_ref()
    }
    pub fn heartbeat(
        &mut self,
        handle: PeerSlot,
        sequence: u64,
        progress: u64,
        healthy: bool,
    ) -> Option<()> {
        self.tracked(handle)
            .map(|peer| peer.heartbeat(sequence, progress, healthy))
    }
    pub fn retrack(
        &mut self,
        handle: PeerSlot,
        generation: ObservationGeneration,
        now: u64,
    ) -> Option<Result<(), DetectRefusal>> {
        self.tracked(handle)
            .map(|peer| peer.retrack(generation, now))
    }
    pub fn reboot(
        &mut self,
        handle: PeerSlot,
        generation: ObservationGeneration,
        now: u64,
    ) -> Option<Result<(), DetectRefusal>> {
        self.tracked(handle)
            .map(|peer| peer.reboot(generation, now))
    }
    /// Closes a tracked peer's window under this table's validated bounds.
    pub fn window(
        &mut self,
        handle: PeerSlot,
        now: u64,
        observed: bool,
        exhausted: bool,
    ) -> Option<Result<Liveness, DetectRefusal>> {
        let bounds = &self.bounds;
        self.slots
            .get_mut(handle.index)
            .filter(|slot| slot.incarnation == handle.incarnation)?
            .peer
            .as_mut()
            .map(|peer| peer.close(bounds, now, observed, exhausted))
    }
    pub fn bounds(&self) -> &DetectBounds {
        &self.bounds
    }
}

#[cfg(kani)]
mod window_kani;
