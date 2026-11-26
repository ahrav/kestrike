//! Kani proof of the loop's two loss verdicts, [`host_evidence`](super::evidence::host_evidence) and
//! [`volume_health`](super::evidence::volume_health), against reference predicates that restate
//! LOST-NEEDS-TWO-CLASSES and LOSS-NEEDS-EVIDENCE condition by condition:
//!
//! - A host the directory retired is `Lost`, whatever its other evidence. Instance evidence is a listing that shows
//!   the instance, or one or more complete listings that leave it out. Any other host without instance evidence is
//!   `Unknown`, a fresh advance included. With instance evidence, a fresh advance gives `Conflict` beside an ended,
//!   stopping, stopped or absent instance and `Live` otherwise; without one, the host is `Lost` exactly when the
//!   silence exceeds the silent window and the instance is ended, stopping or stopped for the stopped dwell, impaired
//!   for the impaired dwell, or absent from `max(1, absent_ticks)` complete listings. An absence counted over zero
//!   complete listings is no instance evidence and reads `Unknown`, fresh advance or not. Silence with a running
//!   instance whose checks show no impaired dwell, and silence without instance evidence, are never `Lost`.
//! - A volume is `Lost` exactly when its listing shows state `error` with a status value in at least
//!   `max(loss_ticks, LOSS_TICKS_MIN)` consecutive observations, so one observation never makes it lost.
//!
//! Bounds: both verdicts are loop-free and the proofs run at Kani's default unwinding over one call each. Every
//! window, dwell, silence, tick count and loss count is any value of its type, so the host proof covers rules that
//! zone validation refuses, such as a zero window or a fresh window above the silent one; every directory state,
//! instance state, status check, listed volume state and volume status takes each of its values.

#[cfg(kani)]
mod verification {
    use super::super::directory::DirectoryState;
    use super::super::evidence::{
        HostEvidence, HostRule, InstanceEvidence, InstanceState, LOSS_TICKS_MIN, ListedVolumeState,
        Silence, StatusCheck, VolumeCondition, VolumeStatus, host_evidence, volume_health,
    };
    use crate::failover::loss::Health;

    fn directory_state() -> DirectoryState {
        let state = match kani::any::<u8>() % 3 {
            0 => DirectoryState::Active,
            1 => DirectoryState::Draining,
            _ => DirectoryState::Retired,
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match state {
            DirectoryState::Active | DirectoryState::Draining | DirectoryState::Retired => state,
        }
    }

    fn instance_state() -> InstanceState {
        let state = match kani::any::<u8>() % 6 {
            0 => InstanceState::Pending,
            1 => InstanceState::Running,
            2 => InstanceState::Stopping,
            3 => InstanceState::Stopped,
            4 => InstanceState::ShuttingDown,
            _ => InstanceState::Terminated,
        };
        match state {
            InstanceState::Pending
            | InstanceState::Running
            | InstanceState::Stopping
            | InstanceState::Stopped
            | InstanceState::ShuttingDown
            | InstanceState::Terminated => state,
        }
    }

    fn status_check() -> StatusCheck {
        let check = match kani::any::<u8>() % 5 {
            0 => StatusCheck::Ok,
            1 => StatusCheck::Impaired,
            2 => StatusCheck::InsufficientData,
            3 => StatusCheck::Initializing,
            _ => StatusCheck::NotApplicable,
        };
        match check {
            StatusCheck::Ok
            | StatusCheck::Impaired
            | StatusCheck::InsufficientData
            | StatusCheck::Initializing
            | StatusCheck::NotApplicable => check,
        }
    }

    fn instance_evidence() -> InstanceEvidence {
        let evidence = match kani::any::<u8>() % 3 {
            0 => InstanceEvidence::Unlisted,
            1 => InstanceEvidence::Absent { ticks: kani::any() },
            _ => InstanceEvidence::Listed {
                state: instance_state(),
                checks: status_check(),
                stopped_us: kani::any(),
                impaired_us: kani::any(),
            },
        };
        match evidence {
            InstanceEvidence::Unlisted
            | InstanceEvidence::Absent { .. }
            | InstanceEvidence::Listed { .. } => evidence,
        }
    }

    fn listed_volume_state() -> ListedVolumeState {
        let state = match kani::any::<u8>() % 6 {
            0 => ListedVolumeState::Creating,
            1 => ListedVolumeState::Available,
            2 => ListedVolumeState::InUse,
            3 => ListedVolumeState::Deleting,
            4 => ListedVolumeState::Deleted,
            _ => ListedVolumeState::Error,
        };
        match state {
            ListedVolumeState::Creating
            | ListedVolumeState::Available
            | ListedVolumeState::InUse
            | ListedVolumeState::Deleting
            | ListedVolumeState::Deleted
            | ListedVolumeState::Error => state,
        }
    }

    fn volume_status() -> VolumeStatus {
        let status = match kani::any::<u8>() % 4 {
            0 => VolumeStatus::Ok,
            1 => VolumeStatus::Warning,
            2 => VolumeStatus::Impaired,
            _ => VolumeStatus::InsufficientData,
        };
        match status {
            VolumeStatus::Ok
            | VolumeStatus::Warning
            | VolumeStatus::Impaired
            | VolumeStatus::InsufficientData => status,
        }
    }

    /// The windows of a [`HostRule`], by name.
    #[derive(Clone, Copy)]
    struct Windows {
        fresh_us: u64,
        silent_us: u64,
        stopped_dwell_us: u64,
        impaired_dwell_us: u64,
        absent_ticks: u32,
    }

    /// The instance classes LOST-NEEDS-TWO-CLASSES names, as one instance evidence shows them under the windows.
    #[derive(Default)]
    struct Classes {
        listed: bool,
        ended: bool,
        stopping: bool,
        stopped_long: bool,
        impaired_long: bool,
        absent: bool,
        absent_long: bool,
    }

    /// The host verdict LOST-NEEDS-TWO-CLASSES states, over the same inputs as `host_evidence`.
    fn reference_host(
        windows: Windows,
        directory: DirectoryState,
        silence: Silence,
        instance: InstanceEvidence,
    ) -> HostEvidence {
        let shown = match instance {
            InstanceEvidence::Unlisted | InstanceEvidence::Absent { ticks: 0 } => {
                Classes::default()
            }
            InstanceEvidence::Absent { ticks } => Classes {
                listed: true,
                absent: true,
                absent_long: ticks >= windows.absent_ticks,
                ..Classes::default()
            },
            InstanceEvidence::Listed {
                state: lifecycle,
                checks,
                stopped_us,
                impaired_us,
            } => {
                let stopping =
                    lifecycle == InstanceState::Stopping || lifecycle == InstanceState::Stopped;
                Classes {
                    listed: true,
                    ended: lifecycle == InstanceState::ShuttingDown
                        || lifecycle == InstanceState::Terminated,
                    stopping,
                    stopped_long: stopping && stopped_us >= windows.stopped_dwell_us,
                    impaired_long: checks == StatusCheck::Impaired
                        && impaired_us >= windows.impaired_dwell_us,
                    ..Classes::default()
                }
            }
        };
        let fresh = silence.advanced && silence.silent_us <= windows.fresh_us;
        let corroborated =
            shown.ended || shown.stopped_long || shown.impaired_long || shown.absent_long;
        if directory == DirectoryState::Retired {
            HostEvidence::Lost
        } else if !shown.listed {
            HostEvidence::Unknown
        } else if fresh && (shown.ended || shown.stopping || shown.absent) {
            HostEvidence::Conflict
        } else if fresh {
            HostEvidence::Live
        } else if silence.silent_us > windows.silent_us && corroborated {
            HostEvidence::Lost
        } else {
            HostEvidence::Unknown
        }
    }

    /// Over one call with every rule, directory state, silence and instance evidence: `host_evidence` returns the
    /// reference verdict, and a `Lost` verdict of a host the directory keeps comes with silence above the silent
    /// window, no fresh advance and one of the four instance classes that corroborate it. Bounds: one loop-free
    /// call at the default unwinding.
    #[kani::proof]
    fn the_host_verdict_answers_as_the_reference_predicate() {
        let windows = Windows {
            fresh_us: kani::any(),
            silent_us: kani::any(),
            stopped_dwell_us: kani::any(),
            impaired_dwell_us: kani::any(),
            absent_ticks: kani::any(),
        };
        let rule = HostRule::new(
            windows.fresh_us,
            windows.silent_us,
            windows.stopped_dwell_us,
            windows.impaired_dwell_us,
            windows.absent_ticks,
        );
        let directory = directory_state();
        let silence = Silence {
            advanced: kani::any(),
            silent_us: kani::any(),
        };
        let instance = instance_evidence();
        let verdict = host_evidence(&rule, directory, silence, instance);
        assert_eq!(
            verdict,
            reference_host(windows, directory, silence, instance)
        );
        let kept = directory != DirectoryState::Retired;
        let lost_kept = verdict == HostEvidence::Lost && kept;
        let lifecycle = |first: InstanceState, second: InstanceState| match instance {
            InstanceEvidence::Listed { state, .. } => state == first || state == second,
            InstanceEvidence::Unlisted | InstanceEvidence::Absent { .. } => false,
        };
        let (stopped_long, impaired_long) = match instance {
            InstanceEvidence::Listed {
                checks,
                stopped_us,
                impaired_us,
                ..
            } => (
                stopped_us >= windows.stopped_dwell_us,
                checks == StatusCheck::Impaired && impaired_us >= windows.impaired_dwell_us,
            ),
            InstanceEvidence::Unlisted | InstanceEvidence::Absent { .. } => (false, false),
        };
        kani::cover!(verdict == HostEvidence::Lost && !kept);
        kani::cover!(
            kept && verdict == HostEvidence::Unknown
                && silence.advanced
                && silence.silent_us <= windows.fresh_us
                && matches!(instance, InstanceEvidence::Absent { ticks: 0 })
        );
        kani::cover!(verdict == HostEvidence::Live);
        kani::cover!(verdict == HostEvidence::Conflict);
        kani::cover!(verdict == HostEvidence::Unknown && silence.silent_us > windows.silent_us);
        kani::cover!(lost_kept && matches!(instance, InstanceEvidence::Absent { .. }));
        kani::cover!(
            lost_kept
                && lifecycle(InstanceState::ShuttingDown, InstanceState::Terminated)
                && !impaired_long
        );
        kani::cover!(
            lost_kept
                && lifecycle(InstanceState::Stopping, InstanceState::Stopped)
                && stopped_long
                && !impaired_long
        );
        kani::cover!(
            lost_kept
                && matches!(
                    instance,
                    InstanceEvidence::Listed {
                        checks: StatusCheck::Impaired,
                        state: InstanceState::Running,
                        ..
                    }
                )
        );
        if lost_kept {
            // "silence alone never makes a host lost"
            assert!(silence.silent_us > windows.silent_us);
            assert!(!(silence.advanced && silence.silent_us <= windows.fresh_us));
            assert!(!matches!(instance, InstanceEvidence::Unlisted));
            if let InstanceEvidence::Absent { ticks } = instance {
                assert!(ticks >= windows.absent_ticks.max(1));
            }
            if let InstanceEvidence::Listed {
                state: lifecycle,
                checks,
                stopped_us,
                impaired_us,
            } = instance
            {
                assert!(
                    matches!(
                        lifecycle,
                        InstanceState::ShuttingDown | InstanceState::Terminated
                    ) || (matches!(lifecycle, InstanceState::Stopping | InstanceState::Stopped)
                        && stopped_us >= windows.stopped_dwell_us)
                        || (checks == StatusCheck::Impaired
                            && impaired_us >= windows.impaired_dwell_us)
                );
            }
        }
    }

    /// Over one call with every listed condition or none, error run and loss count: `volume_health` returns the
    /// reference health, and a `Lost` volume shows state `error` with a status value after at least two and at least
    /// `loss_ticks` consecutive observations. Bounds: one loop-free call at the default unwinding.
    #[kani::proof]
    fn the_volume_verdict_answers_as_the_reference_predicate() {
        let condition = kani::any::<bool>().then(|| VolumeCondition {
            state: listed_volume_state(),
            status: volume_status(),
        });
        let (errors, loss_ticks): (u32, u32) = (kani::any(), kani::any());
        let health = volume_health(condition, errors, loss_ticks);
        let reference = match condition {
            None => None,
            Some(condition) if condition.status == VolumeStatus::InsufficientData => None,
            Some(condition) => Some(
                if condition.state == ListedVolumeState::Error
                    && errors >= loss_ticks
                    && errors >= LOSS_TICKS_MIN
                {
                    Health::Lost
                } else if condition.status == VolumeStatus::Ok
                    && (condition.state == ListedVolumeState::Available
                        || condition.state == ListedVolumeState::InUse)
                {
                    Health::Available
                } else {
                    Health::Impaired
                },
            ),
        };
        assert_eq!(health, reference);
        kani::cover!(health == Some(Health::Lost) && loss_ticks < LOSS_TICKS_MIN);
        kani::cover!(health == Some(Health::Lost) && loss_ticks > LOSS_TICKS_MIN);
        kani::cover!(health == Some(Health::Available));
        kani::cover!(
            health == Some(Health::Impaired)
                && condition.is_some_and(|c| c.state == ListedVolumeState::Error)
        );
        kani::cover!(health.is_none() && condition.is_some());
        if health == Some(Health::Lost) {
            // "one observation never makes a volume lost"
            assert!(errors >= 2 && errors >= loss_ticks);
            assert!(
                condition.is_some_and(|c| c.state == ListedVolumeState::Error
                    && c.status != VolumeStatus::InsufficientData)
            );
        }
    }
}
