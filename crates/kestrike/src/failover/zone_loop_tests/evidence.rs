use std::collections::BTreeSet;
use std::num::NonZeroU64;

use crate::failover::attachments::Unlisted;
use crate::failover::loss::Health;
use crate::failover::records::{ERA, VolumeId};
use crate::failover::report::tests as report_tests;
use crate::failover::report::{BOOTS, BuildIdentity, Gauge, HostReport, Reader, ReportKey, Writer};
use crate::failover::sim::host;
use crate::failover::standbys::Zone as ZoneNumber;
use crate::failover::standbys::tests::report_of;
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::directory::{Directory, DirectoryState, ReconcilerProjection};
use crate::failover::zone_loop::evidence::*;

use super::config::{bounds, config_of};
use super::directory::{directory, instance, listing, report_keys};

const S: u64 = 1_000_000;
const TICK: u64 = 10 * S;
const START: u64 = 1_000 * S;

fn report(writer: u64, sequence: u64) -> HostReport {
    let mut report = report_of(host(writer), Gauge::Unavailable, Gauge::Unavailable);
    report.sequence = sequence;
    report
}

fn listed(number: u64, state: InstanceState, checks: StatusCheck) -> Instance {
    Instance {
        instance: instance(number),
        state,
        system_check: StatusCheck::Ok,
        instance_check: checks,
    }
}

fn running(number: u64) -> Instance {
    listed(number, InstanceState::Running, StatusCheck::Ok)
}

fn stopped(number: u64) -> Instance {
    listed(number, InstanceState::Stopped, StatusCheck::NotApplicable)
}

fn impaired(number: u64) -> Instance {
    listed(number, InstanceState::Running, StatusCheck::Impaired)
}

fn terminated(number: u64) -> Instance {
    listed(
        number,
        InstanceState::Terminated,
        StatusCheck::NotApplicable,
    )
}

/// Distinct tick counts and dwell times let tests detect swapped thresholds.
fn custom_bounds() -> ZoneBounds {
    let mut config = config_of(8);
    config.absent_ticks = 3;
    config.loss_ticks = 4;
    config.stopped_dwell_us = 200 * S;
    config.impaired_dwell_us = 120 * S;
    config.validate().unwrap()
}

fn paced_bounds() -> ZoneBounds {
    let mut config = config_of(8);
    config.report_period_us = 20 * S;
    config.tick_us = 5 * S;
    config.fresh_periods = 4;
    config.silent_periods = 5;
    config.validate().unwrap()
}

struct Zone {
    rule: HostRule,
    directory: Directory<ReconcilerProjection>,
    reports: ReportMemory,
    instances: InstanceMemory,
    tick: u64,
}

impl Zone {
    fn with(bounds: &ZoneBounds, directory: Directory<ReconcilerProjection>) -> Self {
        let mut reports = ReportMemory::default();
        reports.track(&directory, START);
        Self {
            rule: HostRule::of(bounds),
            directory,
            reports,
            instances: InstanceMemory::new(bounds),
            tick: 0,
        }
    }

    fn of(directory: Directory<ReconcilerProjection>) -> Self {
        Self::with(&bounds(), directory)
    }

    fn new() -> Self {
        Self::of(directory(1, 1))
    }

    fn redirect(&mut self, directory: Directory<ReconcilerProjection>, now_us: u64) {
        self.reports.track(&directory, now_us);
        self.directory = directory;
    }

    fn report(&mut self, sequence: u64, now_us: u64) {
        self.reports.accepted(report(1, sequence), now_us);
    }

    fn observe(
        &mut self,
        listing: Result<&[Instance], Unlisted>,
        now_us: u64,
    ) -> Result<(), Unlisted> {
        self.tick += 1;
        (self.instances).observe(&self.directory, listing, self.tick, now_us)
    }

    fn list(&mut self, listing: Result<&[Instance], Unlisted>, now_us: u64) {
        let failed = listing.is_err();
        assert_eq!(self.observe(listing, now_us).is_err(), failed);
    }

    fn relist(&mut self, listing: &[Instance], now_us: u64) {
        let tick = self.tick;
        (self.instances)
            .observe(&self.directory, Ok(listing), tick, now_us)
            .unwrap();
    }

    fn hold(&mut self, listing: &[Instance], from_us: u64, to_us: u64) {
        let mut now_us = from_us;
        while now_us < to_us {
            self.list(Ok(listing), now_us);
            now_us += TICK;
        }
        self.list(Ok(listing), to_us);
    }

    fn evidence(&self, number: u64) -> InstanceEvidence {
        self.instances.evidence(host(number), self.tick)
    }

    fn verdict(&self, now_us: u64) -> HostEvidence {
        self.verdict_of(1, now_us)
    }

    fn verdict_of(&self, number: u64, now_us: u64) -> HostEvidence {
        self.verdict_by(host_evidence, number, now_us)
    }

    fn verdict_by(&self, verdict: Verdict, number: u64, now_us: u64) -> HostEvidence {
        let state = self.directory.host(host(number)).unwrap().state;
        let silence = self.reports.silence(host(number), now_us);
        verdict(&self.rule, state, silence, self.evidence(number))
    }
}

type Verdict = fn(&HostRule, DirectoryState, Silence, InstanceEvidence) -> HostEvidence;

fn renamed(hosts: u64) -> Directory<ReconcilerProjection> {
    let mut renamed = listing(hosts, 1);
    renamed.version = 2;
    renamed.hosts[0].instance = instance(9);
    let keys = report_keys(&renamed);
    Directory::new(renamed, keys).unwrap()
}

fn silence(advanced: bool, silent_us: u64) -> Silence {
    Silence {
        advanced,
        silent_us,
    }
}

#[test]
fn an_advanced_report_inside_the_fresh_window_is_live() {
    let mut zone = Zone::new();
    zone.report(7, START + S);
    zone.list(Ok(&[running(1)]), START + S);
    assert_eq!(zone.verdict(START + S), HostEvidence::Unknown);
    zone.report(8, START + 10 * S);
    zone.hold(&[running(1)], START + 10 * S, START + 40 * S);
    assert_eq!(zone.verdict(START + 40 * S), HostEvidence::Live);
    zone.list(Ok(&[running(1)]), START + 41 * S);
    assert_eq!(zone.verdict(START + 41 * S), HostEvidence::Unknown);
    zone.report(8, START + 41 * S);
    assert_eq!(zone.verdict(START + 41 * S), HostEvidence::Unknown);
}

#[test]
fn an_earlier_report_of_the_current_boot_extends_no_freshness() {
    let mut zone = Zone::new();
    zone.report(7, START);
    zone.report(8, START + S);
    zone.report(7, START + 50 * S);
    zone.report(8, START + 50 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 50 * S),
        silence(true, 49 * S)
    );
    zone.list(Ok(&[running(1)]), START + 50 * S);
    assert_eq!(zone.verdict(START + 50 * S), HostEvidence::Unknown);
}

#[test]
fn a_new_boot_at_the_same_sequence_is_an_advance() {
    let mut zone = Zone::new();
    zone.report(3, START);
    let mut rebooted = report(1, 3);
    rebooted.writer.boot = [0x5c; 16];
    zone.reports.accepted(rebooted.clone(), START + 50 * S);
    zone.list(Ok(&[running(1)]), START + 50 * S);
    assert_eq!(zone.verdict(START + 50 * S), HostEvidence::Live);
}

#[test]
fn a_report_of_a_superseded_boot_is_no_advance_and_the_live_boot_advances_again() {
    let mut zone = Zone::new();
    zone.report(1, START);
    let mut rebooted = report(1, 1);
    rebooted.writer.boot = [0x5c; 16];
    zone.reports.accepted(rebooted.clone(), START + S);
    let stamped = silence(true, 49 * S);
    assert_eq!(zone.reports.silence(host(1), START + 50 * S), stamped);
    zone.report(2, START + 50 * S);
    assert_eq!(zone.reports.silence(host(1), START + 50 * S), stamped);
    zone.report(2, START + 55 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 55 * S),
        silence(true, 54 * S)
    );
    rebooted.sequence = 2;
    zone.reports.accepted(rebooted.clone(), START + 60 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 60 * S),
        silence(true, 0)
    );
    rebooted.sequence = 3;
    zone.reports.accepted(rebooted.clone(), START + 70 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 70 * S),
        silence(true, 0)
    );
    zone.report(3, START + 80 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 80 * S),
        silence(true, 10 * S)
    );
}

#[test]
fn a_higher_sequence_of_another_earlier_boot_moves_the_returning_mark() {
    let mut zone = Zone::new();
    let of_boot = |boot: u8, sequence: u64| {
        let mut report = report(1, sequence);
        report.writer.boot = [boot; 16];
        report
    };
    zone.reports.accepted(of_boot(1, 1), START);
    zone.reports.accepted(of_boot(2, 1), START + S);
    zone.reports.accepted(of_boot(3, 1), START + 2 * S);
    zone.reports.accepted(of_boot(1, 2), START + 10 * S);
    zone.reports.accepted(of_boot(2, 2), START + 20 * S);
    zone.reports.accepted(of_boot(1, 3), START + 30 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 30 * S),
        silence(true, 28 * S)
    );
    zone.reports.accepted(of_boot(1, 4), START + 40 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 40 * S),
        silence(true, 0)
    );
}

/// A report the memory already recorded, of a superseded boot or of the current one, leaves the memory as it was.
/// A recorded earlier boot's first higher sequence marks it returning and keeps the current boot, the held report
/// and the last stamp; repeats of recorded reports keep the mark, and the returning boot's next higher sequence
/// makes it current and holds its report.
#[test]
fn a_report_the_memory_already_recorded_keeps_the_current_boot_and_the_held_report() {
    let mut zone = Zone::new();
    zone.report(1, START);
    let mut rebooted = report(1, 1);
    rebooted.writer.boot = [0x5c; 16];
    zone.reports.accepted(rebooted.clone(), START + S);
    zone.report(2, START + 50 * S);
    let first_boot = report(1, 2).writer.boot;
    let held = |zone: &Zone| {
        let latest = zone.reports.latest(host(1));
        latest.map(|report| (report.writer.boot, report.sequence))
    };
    let unchanged = |zone: &Zone| {
        assert_eq!(held(zone), Some(([0x5c; 16], 1)));
        assert_eq!(zone.reports.answered_us(host(1), START + 60 * S), 10 * S);
        assert_eq!(
            zone.reports.silence(host(1), START + 60 * S),
            silence(true, 59 * S)
        );
    };
    unchanged(&zone);
    zone.reports.accepted(rebooted, START + 55 * S);
    unchanged(&zone);
    zone.report(1, START + 56 * S);
    unchanged(&zone);
    zone.report(2, START + 57 * S);
    unchanged(&zone);
    zone.report(3, START + 60 * S);
    assert_eq!(held(&zone), Some((first_boot, 3)));
    assert_eq!(
        zone.reports.silence(host(1), START + 60 * S),
        silence(true, 0)
    );
}

struct Sealer {
    writer: Writer,
    elapsed_us: u64,
}

const KEY: [u8; 32] = [0x2d; 32];

impl Sealer {
    fn new() -> Self {
        let period = NonZeroU64::new(TICK).unwrap();
        Self {
            writer: Writer::new(host(1), &KEY, period).unwrap(),
            elapsed_us: 0,
        }
    }

    fn seal(&mut self, sealed_at_us: u64) -> Vec<u8> {
        let build = BuildIdentity {
            era: ERA,
            digest: None,
        };
        let state = report_tests::unobserved(build, report_tests::unavailable_headroom());
        let bytes = self.writer.seal(&state, &[], sealed_at_us, self.elapsed_us);
        self.elapsed_us += TICK;
        bytes.unwrap()
    }
}

fn intake(reader: &mut Reader, reports: &mut ReportMemory, bytes: &[u8], now_us: u64) {
    let accepted = reader.accept(bytes, |_| Some(ReportKey::derive(&KEY)));
    reports.accepted(accepted.unwrap(), now_us);
}

#[test]
fn a_delayed_report_of_another_boot_stamps_once_and_the_live_boot_stamps_again() {
    let mut reports = ReportMemory::default();
    reports.track(&directory(1, 1), START);
    let mut reader = Reader::default();
    let (mut live, mut stale) = (Sealer::new(), Sealer::new());
    let old = stale.seal(1_000);
    intake(&mut reader, &mut reports, &live.seal(2_000), START + S);
    intake(&mut reader, &mut reports, &live.seal(2_001), START + 10 * S);
    assert_eq!(
        reports.silence(host(1), START + 20 * S),
        silence(true, 10 * S)
    );
    intake(&mut reader, &mut reports, &old, START + 20 * S);
    assert_eq!(reports.silence(host(1), START + 20 * S), silence(true, 0));
    intake(&mut reader, &mut reports, &live.seal(2_002), START + 30 * S);
    assert_eq!(
        reports.silence(host(1), START + 30 * S),
        silence(true, 10 * S)
    );
    intake(&mut reader, &mut reports, &live.seal(2_003), START + 40 * S);
    assert_eq!(reports.silence(host(1), START + 40 * S), silence(true, 0));
}

/// Reports from the current boot keep the host live past the silent window and the impaired dwell even when
/// reports from the earlier boot arrive between them.
#[test]
fn reports_alternating_between_two_recorded_boots_keep_the_host_live() {
    let mut zone = Zone::new();
    let mut reader = Reader::default();
    let (mut earlier, mut current) = (Sealer::new(), Sealer::new());
    intake(&mut reader, &mut zone.reports, &earlier.seal(1_000), START);
    intake(
        &mut reader,
        &mut zone.reports,
        &current.seal(2_000),
        START + S,
    );
    let mut now_us = START + S;
    for period in 1..=20 {
        now_us = START + period * TICK;
        let delayed = earlier.seal(1_000 + period);
        intake(&mut reader, &mut zone.reports, &delayed, now_us);
        now_us += S;
        let live = current.seal(2_000 + period);
        intake(&mut reader, &mut zone.reports, &live, now_us);
        zone.list(Ok(&[impaired(1)]), now_us);
    }
    assert_eq!(zone.verdict(now_us), HostEvidence::Live);
    assert_eq!(zone.reports.silence(host(1), now_us), silence(true, 0));
}

#[test]
fn a_boot_beyond_the_recorded_boots_drops_the_oldest() {
    let mut reports = ReportMemory::default();
    reports.track(&directory(1, 1), START);
    let mut reader = Reader::default();
    let mut sealers: Vec<Sealer> = (0..=BOOTS).map(|_| Sealer::new()).collect();
    let mut now = START;
    for (boot, sealer) in (0u64..).zip(sealers.iter_mut()) {
        now += TICK;
        intake(&mut reader, &mut reports, &sealer.seal(1_000 + boot), now);
    }
    assert_eq!(reports.silence(host(1), now), silence(true, 0));
    now += TICK;
    let first = sealers[0].seal(9_000);
    intake(&mut reader, &mut reports, &first, now);
    assert_eq!(reports.silence(host(1), now), silence(true, 0));
    now += TICK;
    let latest = sealers[BOOTS].seal(9_001);
    intake(&mut reader, &mut reports, &latest, now);
    assert_eq!(reports.silence(host(1), now), silence(true, TICK));
    now += TICK;
    let latest = sealers[BOOTS].seal(9_002);
    intake(&mut reader, &mut reports, &latest, now);
    assert_eq!(reports.silence(host(1), now), silence(true, 0));
}

#[test]
fn a_late_first_report_restarts_the_silent_window() {
    let mut zone = Zone::new();
    let late = START + 200 * S;
    zone.hold(&[terminated(1)], late - 10 * S, late);
    assert_eq!(zone.verdict(late), HostEvidence::Lost);
    zone.report(1, late);
    assert_eq!(zone.reports.silence(host(1), late), silence(false, 0));
    assert_eq!(zone.verdict(late), HostEvidence::Unknown);
    zone.hold(&[terminated(1)], late, late + 60 * S);
    assert_eq!(zone.verdict(late + 60 * S), HostEvidence::Unknown);
    zone.list(Ok(&[terminated(1)]), late + 61 * S);
    assert_eq!(zone.verdict(late + 61 * S), HostEvidence::Lost);
    zone.report(2, late + 62 * S);
    zone.list(Ok(&[terminated(1)]), late + 62 * S);
    assert_eq!(zone.verdict(late + 62 * S), HostEvidence::Conflict);
}

/// A delayed report of a superseded boot raises that boot's sequence high-water and leaves the latest report the
/// current boot's, the one whose advance the silence reads, so the advance stamp and the report it belongs to stay
/// paired.
#[test]
fn a_superseded_boot_s_report_leaves_the_current_boot_s_report_latest() {
    let mut zone = Zone::new();
    zone.report(1, START);
    let mut rebooted = report(1, 1);
    rebooted.writer.boot = [0x5c; 16];
    zone.reports.accepted(rebooted.clone(), START + S);
    let stamped = zone.reports.silence(host(1), START + 10 * S);
    let mut delayed = report(1, 7);
    delayed.host.detector.self_suspect_us = Some(9);
    zone.reports.accepted(delayed.clone(), START + 10 * S);
    let latest = zone.reports.latest(host(1)).unwrap();
    assert_eq!((latest.writer.boot, latest.sequence), ([0x5c; 16], 1));
    assert_eq!(zone.reports.silence(host(1), START + 10 * S), stamped);
}

/// A late report of a boot the memory never recorded becomes the current boot, and the boot that keeps advancing
/// takes the current place back on its second rise with no current-boot advance between, so the latest report
/// and the silence follow the running boot again.
#[test]
fn the_boot_that_keeps_advancing_becomes_current_again() {
    let mut zone = Zone::new();
    zone.report(1, START);
    let mut running = report(1, 1);
    running.writer.boot = [0x5c; 16];
    zone.reports.accepted(running.clone(), START + S);
    let mut stray = report(1, 9);
    stray.writer.boot = [0x7d; 16];
    zone.reports.accepted(stray.clone(), START + 2 * S);
    running.sequence = 2;
    zone.reports.accepted(running.clone(), START + 40 * S);
    assert_eq!(
        zone.reports.latest(host(1)).unwrap().writer.boot,
        [0x7d; 16],
        "one rise is a contender"
    );
    running.sequence = 3;
    zone.reports.accepted(running.clone(), START + 50 * S);
    let latest = zone.reports.latest(host(1)).unwrap();
    assert_eq!((latest.writer.boot, latest.sequence), ([0x5c; 16], 3));
    assert_eq!(zone.reports.silence(host(1), START + 50 * S).silent_us, 0);
}

fn reboot_is_unknown(verdict: Verdict) -> bool {
    let mut zone = Zone::new();
    zone.report(1, START);
    zone.report(2, START + 10 * S);
    zone.list(Ok(&[running(1)]), START + 100 * S);
    zone.verdict_by(verdict, 1, START + 100 * S) == HostEvidence::Unknown
}

#[test]
fn a_rebooting_host_with_a_running_instance_is_unknown() {
    assert!(reboot_is_unknown(host_evidence));
}

#[test]
fn negative_control_a_verdict_on_silence_alone_fails_the_reboot_case() {
    fn silence_alone(
        rule: &HostRule,
        state: DirectoryState,
        silence: Silence,
        instance: InstanceEvidence,
    ) -> HostEvidence {
        match silence.silent_us > 60 * S {
            true => HostEvidence::Lost,
            false => host_evidence(rule, state, silence, instance),
        }
    }
    assert!(!reboot_is_unknown(silence_alone));
}

#[test]
fn a_terminated_instance_is_lost_when_silent_and_a_conflict_when_reporting() {
    let mut zone = Zone::new();
    zone.report(1, START);
    zone.report(2, START + S);
    zone.list(Ok(&[terminated(1)]), START + 2 * S);
    assert_eq!(zone.verdict(START + 2 * S), HostEvidence::Conflict);
    zone.hold(&[terminated(1)], START + 2 * S, START + 40 * S);
    assert_eq!(zone.verdict(START + 40 * S), HostEvidence::Unknown);
    zone.hold(&[terminated(1)], START + 40 * S, START + 61 * S);
    assert_eq!(zone.verdict(START + 61 * S), HostEvidence::Unknown);
    zone.list(Ok(&[terminated(1)]), START + 62 * S);
    assert_eq!(zone.verdict(START + 62 * S), HostEvidence::Lost);
}

#[test]
fn stopped_and_impaired_instances_are_lost_only_past_their_dwells() {
    let mut zone = Zone::new();
    zone.hold(&[stopped(1)], START + 100 * S, START + 399 * S);
    assert_eq!(zone.verdict(START + 399 * S), HostEvidence::Unknown);
    zone.list(Ok(&[stopped(1)]), START + 400 * S);
    assert_eq!(zone.verdict(START + 400 * S), HostEvidence::Lost);
    zone.list(Ok(&[running(1)]), START + 410 * S);
    zone.list(Ok(&[stopped(1)]), START + 420 * S);
    assert_eq!(zone.verdict(START + 420 * S), HostEvidence::Unknown);

    let mut zone = Zone::new();
    zone.hold(&[impaired(1)], START + 100 * S, START + 279 * S);
    assert_eq!(zone.verdict(START + 279 * S), HostEvidence::Unknown);
    zone.list(Ok(&[impaired(1)]), START + 280 * S);
    assert_eq!(zone.verdict(START + 280 * S), HostEvidence::Lost);
    zone.list(Ok(&[running(1)]), START + 290 * S);
    zone.list(Ok(&[impaired(1)]), START + 300 * S);
    assert_eq!(zone.verdict(START + 300 * S), HostEvidence::Unknown);

    // The impaired dwell of an instance that was stopped before starts at its first impaired listing.
    let mut zone = Zone::new();
    zone.hold(&[stopped(1)], START + 100 * S, START + 200 * S);
    zone.hold(&[impaired(1)], START + 210 * S, START + 389 * S);
    assert_eq!(zone.verdict(START + 389 * S), HostEvidence::Unknown);
    zone.list(Ok(&[impaired(1)]), START + 390 * S);
    assert_eq!(zone.verdict(START + 390 * S), HostEvidence::Lost);
}

#[test]
fn the_stopped_dwell_spans_stopping_then_stopped_and_restarts_on_a_second_stop() {
    let mut zone = Zone::new();
    let stopping = [listed(
        1,
        InstanceState::Stopping,
        StatusCheck::NotApplicable,
    )];
    zone.hold(&stopping, START + 100 * S, START + 150 * S);
    zone.hold(&[stopped(1)], START + 160 * S, START + 399 * S);
    assert_eq!(zone.verdict(START + 399 * S), HostEvidence::Unknown);
    zone.list(Ok(&[stopped(1)]), START + 400 * S);
    assert_eq!(zone.verdict(START + 400 * S), HostEvidence::Lost);
    zone.list(Ok(&stopping), START + 410 * S);
    let restarted = InstanceEvidence::Listed {
        state: InstanceState::Stopping,
        checks: StatusCheck::NotApplicable,
        stopped_us: 0,
        impaired_us: 0,
    };
    assert_eq!(zone.evidence(1), restarted);
    assert_eq!(zone.verdict(START + 410 * S), HostEvidence::Unknown);
}

#[test]
fn either_status_check_impaired_starts_the_impaired_dwell() {
    let ok = StatusCheck::Ok;
    let bad = StatusCheck::Impaired;
    for (system_check, instance_check) in [(bad, ok), (ok, bad)] {
        let sick = Instance {
            instance: instance(1),
            state: InstanceState::Running,
            system_check,
            instance_check,
        };
        assert_eq!(sick.checks(), StatusCheck::Impaired);
        let mut zone = Zone::new();
        zone.hold(&[sick], START + 100 * S, START + 280 * S);
        assert_eq!(zone.verdict(START + 280 * S), HostEvidence::Lost);
    }
    let folds = [
        (ok, ok, ok),
        (ok, StatusCheck::Initializing, StatusCheck::Initializing),
        (
            StatusCheck::InsufficientData,
            ok,
            StatusCheck::InsufficientData,
        ),
        (bad, bad, bad),
    ];
    for (system_check, instance_check, checks) in folds {
        let seen = Instance {
            instance: instance(1),
            state: InstanceState::Running,
            system_check,
            instance_check,
        };
        assert_eq!(seen.checks(), checks);
    }
}

#[test]
fn a_failed_listing_restarts_every_dwell() {
    let mut zone = Zone::new();
    let sick = [listed(1, InstanceState::Stopped, StatusCheck::Impaired)];
    zone.hold(&sick, START + 100 * S, START + 380 * S);
    zone.list(Err(Unlisted), START + 390 * S);
    assert_eq!(zone.verdict(START + 390 * S), HostEvidence::Unknown);
    zone.list(Ok(&sick), START + 400 * S);
    assert_eq!(zone.verdict(START + 400 * S), HostEvidence::Unknown);
    zone.hold(&sick, START + 400 * S, START + 579 * S);
    assert_eq!(zone.verdict(START + 579 * S), HostEvidence::Unknown);
    zone.list(Ok(&sick), START + 580 * S);
    assert_eq!(zone.verdict(START + 580 * S), HostEvidence::Lost);
}

#[test]
fn recurring_listing_failures_hold_a_stopped_host_unknown_until_a_clean_dwell() {
    let mut zone = Zone::new();
    let mut now = START + 100 * S;
    for _ in 0..20 {
        zone.hold(&[stopped(1)], now, now + 200 * S);
        assert_eq!(zone.verdict(now + 200 * S), HostEvidence::Unknown);
        zone.list(Err(Unlisted), now + 210 * S);
        now += 220 * S;
    }
    zone.hold(&[stopped(1)], now, now + 300 * S);
    assert_eq!(zone.verdict(now + 300 * S), HostEvidence::Lost);
}

#[test]
fn a_directory_naming_another_instance_restarts_its_dwells() {
    let mut zone = Zone::new();
    let stopped_one = [listed(1, InstanceState::Stopped, StatusCheck::Ok)];
    zone.hold(&stopped_one, START + 100 * S, START + 390 * S);
    zone.redirect(renamed(1), START + 390 * S);
    let stopped_nine = [listed(9, InstanceState::Stopped, StatusCheck::Ok)];
    zone.list(Ok(&stopped_nine), START + 400 * S);
    let first = InstanceEvidence::Listed {
        state: InstanceState::Stopped,
        checks: StatusCheck::Ok,
        stopped_us: 0,
        impaired_us: 0,
    };
    assert_eq!(zone.evidence(1), first);
    zone.hold(&stopped_nine, START + 400 * S, START + 460 * S);
    assert_eq!(zone.verdict(START + 460 * S), HostEvidence::Unknown);
    zone.hold(&stopped_nine, START + 460 * S, START + 700 * S);
    assert_eq!(zone.verdict(START + 700 * S), HostEvidence::Lost);
}

#[test]
fn a_listing_gap_restarts_dwells_and_a_tick_without_a_listing_has_no_evidence() {
    let gap = 2 * TICK;
    let mut zone = Zone::new();
    zone.hold(&[stopped(1)], START + 100 * S, START + 380 * S);
    zone.list(Ok(&[stopped(1)]), START + 380 * S + gap);
    assert_eq!(zone.verdict(START + 400 * S), HostEvidence::Lost);

    let mut zone = Zone::new();
    zone.hold(&[stopped(1)], START + 100 * S, START + 380 * S);
    zone.list(Ok(&[stopped(1)]), START + 380 * S + gap + 1);
    assert_eq!(zone.verdict(START + 400 * S + 1), HostEvidence::Unknown);

    let mut zone = Zone::new();
    zone.hold(&[stopped(1)], START + 100 * S, START + 400 * S);
    assert_eq!(zone.verdict(START + 400 * S), HostEvidence::Lost);
    zone.tick += 1;
    assert_eq!(zone.evidence(1), InstanceEvidence::Unlisted);
    assert_eq!(zone.verdict(START + 410 * S), HostEvidence::Unknown);
}

#[test]
fn a_second_listing_in_one_tick_counts_no_further_absence() {
    let mut zone = Zone::new();
    let now = START + 100 * S;
    zone.list(Ok(&[]), now);
    zone.relist(&[], now);
    zone.relist(&[], now + S);
    assert_eq!(zone.evidence(1), InstanceEvidence::Absent { ticks: 1 });
    assert_eq!(zone.verdict(now + S), HostEvidence::Unknown);
    zone.list(Ok(&[]), now + TICK);
    assert_eq!(zone.verdict(now + TICK), HostEvidence::Lost);
    zone.relist(&[running(1)], now + TICK);
    assert_eq!(zone.verdict(now + TICK), HostEvidence::Unknown);
}

#[test]
fn a_renamed_host_waits_the_silent_window_again() {
    let mut zone = Zone::new();
    zone.report(1, START);
    zone.report(2, START + S);
    zone.redirect(renamed(1), START + 500 * S);
    zone.list(Ok(&[]), START + 500 * S);
    zone.list(Ok(&[]), START + 510 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 510 * S),
        silence(false, 10 * S)
    );
    assert_eq!(zone.verdict(START + 510 * S), HostEvidence::Unknown);
}

#[test]
fn an_instance_absent_from_consecutive_complete_listings_is_lost_when_silent() {
    let mut zone = Zone::new();
    let now = START + 100 * S;
    zone.list(Ok(&[]), now);
    assert_eq!(zone.verdict(now), HostEvidence::Unknown);
    zone.list(Err(Unlisted), now + S);
    zone.list(Ok(&[]), now + 2 * S);
    assert_eq!(zone.verdict(now + 2 * S), HostEvidence::Unknown);
    zone.list(Ok(&[]), now + 3 * S);
    assert_eq!(zone.verdict(now + 3 * S), HostEvidence::Lost);
}

#[test]
fn a_listing_that_shows_the_instance_restarts_its_absence_count() {
    let mut zone = Zone::new();
    let now = START + 100 * S;
    zone.list(Ok(&[running(1)]), now);
    zone.list(Ok(&[]), now + TICK);
    let once = InstanceEvidence::Absent { ticks: 1 };
    assert_eq!(zone.evidence(1), once);
    assert_eq!(zone.verdict(now + TICK), HostEvidence::Unknown);
    zone.list(Ok(&[]), now + 2 * TICK);
    assert_eq!(zone.verdict(now + 2 * TICK), HostEvidence::Lost);
    zone.list(Ok(&[running(1)]), now + 3 * TICK);
    zone.list(Ok(&[]), now + 4 * TICK);
    assert_eq!(zone.evidence(1), once);
    assert_eq!(zone.verdict(now + 4 * TICK), HostEvidence::Unknown);

    let mut zone = Zone::new();
    zone.hold(&[stopped(1)], now, now + 290 * S);
    zone.list(Ok(&[]), now + 300 * S);
    assert_eq!(zone.evidence(1), once);
    assert_eq!(zone.verdict(now + 300 * S), HostEvidence::Unknown);
}

#[test]
fn a_host_the_directory_adds_waits_the_silent_window_from_its_tracking() {
    let mut zone = Zone::new();
    let added = START + 1_000 * S;
    zone.redirect(directory(2, 1), added);
    zone.hold(&[running(1)], added, added + 10 * S);
    assert_eq!(zone.verdict_of(2, added + 10 * S), HostEvidence::Unknown);
    zone.hold(&[running(1)], added + 10 * S, added + 60 * S);
    assert_eq!(zone.verdict_of(2, added + 60 * S), HostEvidence::Unknown);
    zone.list(Ok(&[running(1)]), added + 61 * S);
    assert_eq!(zone.verdict_of(2, added + 61 * S), HostEvidence::Lost);
}

#[test]
fn a_re_tracked_host_keeps_its_baseline_and_its_reports() {
    let mut zone = Zone::new();
    zone.report(1, START + S);
    zone.redirect(directory(1, 1), START + 10 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 10 * S),
        silence(false, 9 * S)
    );
    zone.report(2, START + 20 * S);
    zone.redirect(directory(1, 1), START + 30 * S);
    assert_eq!(
        zone.reports.silence(host(1), START + 30 * S),
        silence(true, 10 * S)
    );
}

#[test]
fn a_host_of_another_zone_has_no_instance_or_report_evidence() {
    let mut foreign = listing(2, 1);
    foreign.hosts[1].placement.zone = ZoneNumber(2);
    let keys = report_keys(&foreign);
    let mut zone = Zone::of(Directory::new(foreign, keys).unwrap());
    let now = START + 900 * S;
    zone.hold(&[running(1), running(2)], START, now - TICK);
    zone.reports.accepted(report(2, 1), now - TICK);
    zone.reports.accepted(report(2, 2), now);
    zone.list(Ok(&[running(1), running(2)]), now);
    assert_eq!(zone.evidence(2), InstanceEvidence::Unlisted);
    assert_eq!(zone.reports.silence(host(2), now), silence(false, 0));
    assert_eq!(zone.verdict_of(2, now), HostEvidence::Unknown);
}

#[test]
fn each_host_is_judged_by_its_own_instance_in_any_listing_order() {
    for listing in [[terminated(2), running(1)], [running(1), terminated(2)]] {
        let mut zone = Zone::of(directory(2, 1));
        zone.list(Ok(&listing), START + 100 * S);
        assert_eq!(zone.verdict_of(1, START + 100 * S), HostEvidence::Unknown);
        assert_eq!(zone.verdict_of(2, START + 100 * S), HostEvidence::Lost);
    }
}

#[test]
fn differing_rows_for_a_tracked_instance_make_the_listing_unusable_in_either_order() {
    for conflict in [[terminated(1), stopped(1)], [stopped(1), terminated(1)]] {
        let mut zone = Zone::of(directory(2, 1));
        zone.hold(&[stopped(1), stopped(2)], START + 100 * S, START + 390 * S);
        let mut listing = conflict.to_vec();
        listing.push(stopped(2));
        assert_eq!(zone.observe(Ok(&listing), START + 400 * S), Err(Unlisted));
        assert_eq!(zone.evidence(1), InstanceEvidence::Unlisted);
        assert_eq!(zone.evidence(2), InstanceEvidence::Unlisted);
        assert_eq!(zone.verdict(START + 400 * S), HostEvidence::Unknown);
        zone.list(Ok(&[stopped(1), stopped(2)]), START + 410 * S);
        let restarted = InstanceEvidence::Listed {
            state: InstanceState::Stopped,
            checks: StatusCheck::NotApplicable,
            stopped_us: 0,
            impaired_us: 0,
        };
        assert_eq!(zone.evidence(2), restarted);
        assert_eq!(zone.verdict_of(2, START + 410 * S), HostEvidence::Unknown);
    }
    let mut zone = Zone::new();
    zone.list(Ok(&[terminated(1), terminated(1)]), START + 100 * S);
    assert_eq!(zone.verdict(START + 100 * S), HostEvidence::Lost);
    for untracked in [[running(7), terminated(7)], [terminated(7), running(7)]] {
        let mut zone = Zone::new();
        let mut listing = untracked.to_vec();
        listing.push(terminated(1));
        zone.list(Ok(&listing), START + 100 * S);
        assert_eq!(zone.verdict(START + 100 * S), HostEvidence::Lost);
    }
}

#[test]
fn a_failed_listing_gives_unknown_at_any_silence_and_beside_a_fresh_report() {
    for silent in [100, 10_000, 1_000_000] {
        let mut zone = Zone::new();
        let now = START + silent * S;
        zone.list(Ok(&[terminated(1)]), now - TICK);
        assert_eq!(zone.verdict(now - TICK), HostEvidence::Lost);
        zone.list(Err(Unlisted), now);
        assert_eq!(zone.verdict(now), HostEvidence::Unknown);
    }

    let mut zone = Zone::new();
    zone.list(Ok(&[running(1)]), START + S);
    zone.report(40, START + S);
    assert_eq!(zone.verdict(START + S), HostEvidence::Unknown);
    zone.report(41, START + 2 * S);
    zone.list(Ok(&[running(1)]), START + 2 * S);
    assert_eq!(zone.verdict(START + 2 * S), HostEvidence::Live);
    zone.report(42, START + 3 * S);
    zone.list(Err(Unlisted), START + 3 * S);
    assert_eq!(zone.verdict(START + 3 * S), HostEvidence::Unknown);
}

#[test]
fn configured_dwells_and_counts_decide_the_verdicts() {
    let custom = custom_bounds();
    let mut zone = Zone::with(&custom, directory(1, 1));
    zone.hold(&[stopped(1)], START + 100 * S, START + 299 * S);
    assert_eq!(zone.verdict(START + 299 * S), HostEvidence::Unknown);
    zone.list(Ok(&[stopped(1)]), START + 300 * S);
    assert_eq!(zone.verdict(START + 300 * S), HostEvidence::Lost);

    let mut zone = Zone::with(&custom, directory(1, 1));
    zone.hold(&[impaired(1)], START + 100 * S, START + 219 * S);
    assert_eq!(zone.verdict(START + 219 * S), HostEvidence::Unknown);
    zone.list(Ok(&[impaired(1)]), START + 220 * S);
    assert_eq!(zone.verdict(START + 220 * S), HostEvidence::Lost);

    let mut zone = Zone::with(&custom, directory(1, 1));
    zone.hold(&[], START + 100 * S, START + 110 * S);
    assert_eq!(zone.verdict(START + 110 * S), HostEvidence::Unknown);
    zone.list(Ok(&[]), START + 120 * S);
    assert_eq!(zone.verdict(START + 120 * S), HostEvidence::Lost);

    let mut memory = VolumeMemory::new(&custom);
    let error = [(
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    )];
    for tick in 0..3 {
        observe(&mut memory, &error, tick);
        assert_eq!(memory.health(volume(1), tick), Some(Health::Impaired));
    }
    observe(&mut memory, &error, 3);
    assert_eq!(memory.health(volume(1), 3), Some(Health::Lost));
}

#[test]
fn configured_report_windows_and_listing_gap_decide_the_verdicts() {
    let paced = paced_bounds();
    let step = 5 * S;
    let mut zone = Zone::with(&paced, directory(1, 1));
    zone.report(1, START);
    zone.report(2, START + step);
    zone.list(Ok(&[running(1)]), START + step + 80 * S);
    assert_eq!(zone.verdict(START + step + 80 * S), HostEvidence::Live);
    assert_eq!(
        zone.verdict(START + step + 80 * S + 1),
        HostEvidence::Unknown
    );
    zone.list(Ok(&[terminated(1)]), START + step + 100 * S);
    assert_eq!(zone.verdict(START + step + 100 * S), HostEvidence::Unknown);
    assert_eq!(zone.verdict(START + step + 100 * S + 1), HostEvidence::Lost);

    let mut zone = Zone::with(&paced, directory(1, 1));
    zone.list(Ok(&[]), START + 200 * S);
    zone.list(Ok(&[]), START + 200 * S + 2 * step);
    assert_eq!(zone.verdict(START + 200 * S + 2 * step), HostEvidence::Lost);
    let mut zone = Zone::with(&paced, directory(1, 1));
    zone.list(Ok(&[]), START + 200 * S);
    zone.list(Ok(&[]), START + 200 * S + 2 * step + 1);
    assert_eq!(
        zone.verdict(START + 200 * S + 2 * step + 1),
        HostEvidence::Unknown
    );

    let error = [(
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    )];
    let mut memory = VolumeMemory::new(&paced);
    memory.observe(Ok(&error), 1, START).unwrap();
    memory.observe(Ok(&error), 2, START + 2 * step).unwrap();
    assert_eq!(memory.health(volume(1), 2), Some(Health::Lost));
    let mut memory = VolumeMemory::new(&paced);
    memory.observe(Ok(&error), 1, START).unwrap();
    memory.observe(Ok(&error), 2, START + 2 * step + 1).unwrap();
    assert_eq!(memory.health(volume(1), 2), Some(Health::Impaired));
}

const STATES: [InstanceState; 6] = [
    InstanceState::Pending,
    InstanceState::Running,
    InstanceState::Stopping,
    InstanceState::Stopped,
    InstanceState::ShuttingDown,
    InstanceState::Terminated,
];
const CHECKS: [StatusCheck; 5] = [
    StatusCheck::Ok,
    StatusCheck::Impaired,
    StatusCheck::InsufficientData,
    StatusCheck::Initializing,
    StatusCheck::NotApplicable,
];
const SILENT: Silence = Silence {
    advanced: true,
    silent_us: u64::MAX,
};
const FRESH: Silence = Silence {
    advanced: true,
    silent_us: 0,
};

#[test]
fn every_instance_state_and_check_gives_its_verdict_when_silent_and_when_fresh() {
    let rule = HostRule::of(&bounds());
    let config = bounds().config().clone();
    let judge = |silence, instance| host_evidence(&rule, DirectoryState::Active, silence, instance);
    for state in STATES {
        for checks in CHECKS {
            let ended = matches!(
                state,
                InstanceState::ShuttingDown | InstanceState::Terminated
            );
            let stopping = matches!(state, InstanceState::Stopping | InstanceState::Stopped);
            let impaired = checks == StatusCheck::Impaired;
            let at = |stopped_us, impaired_us| InstanceEvidence::Listed {
                state,
                checks,
                stopped_us,
                impaired_us,
            };
            let short = at(config.stopped_dwell_us - 1, config.impaired_dwell_us - 1);
            let dwelt = at(config.stopped_dwell_us, config.impaired_dwell_us);
            let lost_short = match ended {
                true => HostEvidence::Lost,
                false => HostEvidence::Unknown,
            };
            assert_eq!(judge(SILENT, short), lost_short, "{state:?} {checks:?}");
            let lost_dwelt = match ended || stopping || impaired {
                true => HostEvidence::Lost,
                false => HostEvidence::Unknown,
            };
            assert_eq!(judge(SILENT, dwelt), lost_dwelt, "{state:?} {checks:?}");
            let conflict = match ended || stopping {
                true => HostEvidence::Conflict,
                false => HostEvidence::Live,
            };
            assert_eq!(judge(FRESH, dwelt), conflict, "{state:?} {checks:?}");
            assert_eq!(judge(FRESH, short), conflict, "{state:?} {checks:?}");
        }
    }
    for ticks in [1, 2] {
        let absent = InstanceEvidence::Absent { ticks };
        assert_eq!(judge(FRESH, absent), HostEvidence::Conflict);
    }
    let once = InstanceEvidence::Absent { ticks: 1 };
    assert_eq!(judge(SILENT, once), HostEvidence::Unknown);
    let twice = InstanceEvidence::Absent { ticks: 2 };
    assert_eq!(judge(SILENT, twice), HostEvidence::Lost);
    let none = InstanceEvidence::Absent { ticks: 0 };
    for silence in [FRESH, SILENT] {
        for instance in [InstanceEvidence::Unlisted, none] {
            assert_eq!(judge(silence, instance), HostEvidence::Unknown);
        }
    }
}

#[test]
fn a_zero_absence_count_acts_as_one() {
    let rule = HostRule::new(30 * S, 60 * S, 300 * S, 180 * S, 0);
    let judge = |silence, ticks| {
        let absent = InstanceEvidence::Absent { ticks };
        host_evidence(&rule, DirectoryState::Active, silence, absent)
    };
    assert_eq!(judge(SILENT, 0), HostEvidence::Unknown);
    assert_eq!(judge(FRESH, 0), HostEvidence::Unknown);
    assert_eq!(judge(SILENT, 1), HostEvidence::Lost);
    assert_eq!(judge(FRESH, 1), HostEvidence::Conflict);
}

#[test]
fn a_retired_host_is_lost_and_silence_without_instance_evidence_never_is() {
    let rule = HostRule::of(&bounds());
    let retired = host_evidence(
        &rule,
        DirectoryState::Retired,
        FRESH,
        InstanceEvidence::Unlisted,
    );
    assert_eq!(retired, HostEvidence::Lost);
    let mut quiet = vec![
        InstanceEvidence::Unlisted,
        InstanceEvidence::Absent { ticks: 1 },
    ];
    for state in [InstanceState::Pending, InstanceState::Running] {
        for checks in CHECKS
            .into_iter()
            .filter(|&checks| checks != StatusCheck::Impaired)
        {
            quiet.push(InstanceEvidence::Listed {
                state,
                checks,
                stopped_us: u64::MAX,
                impaired_us: u64::MAX,
            });
        }
    }
    for state in [DirectoryState::Active, DirectoryState::Draining] {
        for &instance in &quiet {
            assert_eq!(
                host_evidence(&rule, state, SILENT, instance),
                HostEvidence::Unknown
            );
        }
    }
    let ended = InstanceEvidence::Listed {
        state: InstanceState::Terminated,
        checks: StatusCheck::NotApplicable,
        stopped_us: 0,
        impaired_us: 0,
    };
    let serving = InstanceEvidence::Listed {
        state: InstanceState::Running,
        checks: StatusCheck::Ok,
        stopped_us: 0,
        impaired_us: 0,
    };
    let draining =
        |silence, instance| host_evidence(&rule, DirectoryState::Draining, silence, instance);
    assert_eq!(draining(SILENT, ended), HostEvidence::Lost);
    assert_eq!(draining(FRESH, ended), HostEvidence::Conflict);
    assert_eq!(draining(FRESH, serving), HostEvidence::Live);
}

fn volume(n: u8) -> VolumeId {
    VolumeId::new(&format!("vol-{n:02x}")).unwrap()
}

fn condition(state: ListedVolumeState, status: VolumeStatus) -> VolumeCondition {
    VolumeCondition { state, status }
}

fn named(volumes: &[u8]) -> BTreeSet<VolumeId> {
    volumes.iter().map(|&n| volume(n)).collect()
}

fn at(tick: u64) -> u64 {
    START + tick * TICK
}

fn observe(memory: &mut VolumeMemory, listing: &[(VolumeId, VolumeCondition)], tick: u64) {
    memory.observe(Ok(listing), tick, at(tick)).unwrap();
}

#[test]
fn a_volume_is_lost_only_after_consecutive_complete_error_observations() {
    let mut memory = VolumeMemory::new(&bounds());
    let error = [(
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    )];
    observe(&mut memory, &error, 0);
    assert_eq!(memory.health(volume(1), 0), Some(Health::Impaired));
    assert_eq!(memory.observe(Err(Unlisted), 1, at(1)), Err(Unlisted));
    assert_eq!(memory.health(volume(1), 1), None);
    observe(&mut memory, &error, 2);
    assert_eq!(memory.health(volume(1), 2), Some(Health::Impaired));
    observe(&mut memory, &error, 3);
    assert_eq!(memory.health(volume(1), 3), Some(Health::Lost));
    let unsure = [(
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::InsufficientData),
    )];
    observe(&mut memory, &unsure, 4);
    assert_eq!(memory.health(volume(1), 4), None);
    observe(&mut memory, &error, 5);
    assert_eq!(memory.health(volume(1), 5), Some(Health::Impaired));
    observe(&mut memory, &[], 6);
    observe(&mut memory, &error, 7);
    assert_eq!(memory.health(volume(1), 7), Some(Health::Impaired));
    observe(&mut memory, &error, 10);
    assert_eq!(memory.health(volume(1), 10), Some(Health::Impaired));
    assert_eq!(memory.health(volume(1), 11), None);
}

#[test]
fn a_second_listing_in_one_tick_extends_no_error_run() {
    let mut memory = VolumeMemory::new(&bounds());
    let error = [(
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    )];
    observe(&mut memory, &error, 0);
    memory.observe(Ok(&error), 0, at(0)).unwrap();
    memory.observe(Ok(&error), 0, at(0) + S).unwrap();
    assert_eq!(memory.health(volume(1), 0), Some(Health::Impaired));
    observe(&mut memory, &error, 1);
    assert_eq!(memory.health(volume(1), 1), Some(Health::Lost));
    let serving = [(
        volume(1),
        condition(ListedVolumeState::InUse, VolumeStatus::Ok),
    )];
    assert!(memory.erring(volume(1), 1));
    memory.observe(Ok(&serving), 1, at(1) + S).unwrap();
    assert_eq!(memory.health(volume(1), 1), Some(Health::Available));
    assert!(!memory.erring(volume(1), 1));
    memory.observe(Ok(&error), 1, at(1) + 2 * S).unwrap();
    assert_eq!(memory.health(volume(1), 1), Some(Health::Impaired));
    assert!(!memory.erring(volume(1), 1));
    observe(&mut memory, &error, 2);
    assert!(memory.erring(volume(1), 2));
}

#[test]
fn a_valued_contrary_observation_breaks_an_error_run() {
    let mut memory = VolumeMemory::new(&bounds());
    let error = (
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    );
    let serving = (
        volume(1),
        condition(ListedVolumeState::InUse, VolumeStatus::Ok),
    );
    let impaired = (
        volume(1),
        condition(ListedVolumeState::InUse, VolumeStatus::Impaired),
    );
    observe(&mut memory, &[error], 0);
    observe(&mut memory, &[serving], 1);
    observe(&mut memory, &[error], 2);
    assert_eq!(memory.health(volume(1), 2), Some(Health::Impaired));
    observe(&mut memory, &[error], 3);
    assert_eq!(memory.health(volume(1), 3), Some(Health::Lost));
    observe(&mut memory, &[impaired], 4);
    observe(&mut memory, &[error], 5);
    assert_eq!(memory.health(volume(1), 5), Some(Health::Impaired));
}

#[test]
fn one_error_observation_is_never_lost_whatever_the_loss_count() {
    for status in [
        VolumeStatus::Ok,
        VolumeStatus::Warning,
        VolumeStatus::Impaired,
    ] {
        let error = Some(condition(ListedVolumeState::Error, status));
        for loss_ticks in [0, 1, 2] {
            assert_eq!(volume_health(error, 0, loss_ticks), Some(Health::Impaired));
            assert_eq!(volume_health(error, 1, loss_ticks), Some(Health::Impaired));
            assert_eq!(volume_health(error, 2, loss_ticks), Some(Health::Lost));
        }
        assert_eq!(volume_health(error, 2, 3), Some(Health::Impaired));
        assert_eq!(volume_health(error, 3, 3), Some(Health::Lost));
    }
}

#[test]
fn volume_status_and_state_map_to_health() {
    let states = [
        ListedVolumeState::Creating,
        ListedVolumeState::Available,
        ListedVolumeState::InUse,
        ListedVolumeState::Deleting,
        ListedVolumeState::Deleted,
        ListedVolumeState::Error,
    ];
    let statuses = [
        VolumeStatus::Ok,
        VolumeStatus::Warning,
        VolumeStatus::Impaired,
        VolumeStatus::InsufficientData,
    ];
    for state in states {
        for status in statuses {
            for errors in [0, 1, 2, 9] {
                let serving = matches!(
                    state,
                    ListedVolumeState::Available | ListedVolumeState::InUse
                );
                let expected = if status == VolumeStatus::InsufficientData {
                    None
                } else if state == ListedVolumeState::Error && errors >= 2 {
                    Some(Health::Lost)
                } else if serving && status == VolumeStatus::Ok {
                    Some(Health::Available)
                } else {
                    Some(Health::Impaired)
                };
                let health = volume_health(Some(condition(state, status)), errors, 2);
                assert_eq!(health, expected, "{state:?} {status:?} {errors}");
            }
        }
    }
    let pinned = [
        (
            ListedVolumeState::InUse,
            VolumeStatus::Ok,
            Some(Health::Available),
        ),
        (
            ListedVolumeState::Available,
            VolumeStatus::Warning,
            Some(Health::Impaired),
        ),
        (
            ListedVolumeState::Creating,
            VolumeStatus::Ok,
            Some(Health::Impaired),
        ),
        (
            ListedVolumeState::Deleted,
            VolumeStatus::Ok,
            Some(Health::Impaired),
        ),
        (
            ListedVolumeState::Error,
            VolumeStatus::Ok,
            Some(Health::Impaired),
        ),
        (
            ListedVolumeState::Error,
            VolumeStatus::InsufficientData,
            None,
        ),
    ];
    for (state, status, health) in pinned {
        assert_eq!(volume_health(Some(condition(state, status)), 1, 2), health);
    }
    let error = Some(condition(ListedVolumeState::Error, VolumeStatus::Ok));
    assert_eq!(volume_health(error, 2, 2), Some(Health::Lost));
    assert_eq!(volume_health(None, 5, 2), None);
}

#[test]
fn a_volume_without_a_value_makes_the_zone_view_incomplete() {
    let listing = [
        (
            volume(1),
            condition(ListedVolumeState::InUse, VolumeStatus::Ok),
        ),
        (
            volume(2),
            condition(ListedVolumeState::InUse, VolumeStatus::Impaired),
        ),
        (
            volume(3),
            condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData),
        ),
    ];
    let mut memory = VolumeMemory::new(&bounds());
    observe(&mut memory, &listing, 0);
    let judged = memory.judge(volume(1), &named(&[1, 2, 3, 4]), 0);
    assert_eq!(
        judged,
        VolumeJudgement {
            health: Some(Health::Available),
            others: 1,
            complete: false,
            streak: 0,
            confirmed: false,
        }
    );
    assert!(!memory.judge(volume(1), &named(&[1, 2, 3]), 0).complete);
    let whole = memory.judge(volume(1), &named(&[1, 2]), 0);
    assert!(whole.complete);
    assert_eq!(whole.others, 1);
    let skipped = memory.judge(volume(1), &named(&[1, 2]), 1);
    assert_eq!((skipped.health, skipped.complete), (None, false));

    let mut memory = VolumeMemory::new(&bounds());
    observe(&mut memory, &listing, 0);
    assert_eq!(memory.observe(Err(Unlisted), 1, at(1)), Err(Unlisted));
    let failed = memory.judge(volume(1), &named(&[1, 2]), 1);
    assert_eq!((failed.health, failed.complete), (None, false));
    let sole = memory.judge(volume(1), &named(&[1]), 1);
    assert_eq!((sole.health, sole.complete), (None, false));
}

#[test]
fn a_lost_volume_counts_other_lost_volumes_and_not_itself() {
    let mut memory = VolumeMemory::new(&bounds());
    let listing = [
        (
            volume(1),
            condition(ListedVolumeState::Error, VolumeStatus::Impaired),
        ),
        (
            volume(2),
            condition(ListedVolumeState::Error, VolumeStatus::Impaired),
        ),
        (
            volume(3),
            condition(ListedVolumeState::InUse, VolumeStatus::Ok),
        ),
    ];
    observe(&mut memory, &listing, 0);
    observe(&mut memory, &listing, 1);
    let all = named(&[1, 2, 3]);
    let judged = memory.judge(volume(1), &all, 1);
    assert_eq!(
        judged,
        VolumeJudgement {
            health: Some(Health::Lost),
            others: 1,
            complete: true,
            streak: 0,
            confirmed: false,
        }
    );
    assert_eq!(memory.judge(volume(3), &all, 1).others, 2);
    assert_eq!(memory.judge(volume(1), &named(&[1]), 1).others, 0);
}

#[test]
fn a_lost_volume_is_judged_against_each_kind_of_neighbor() {
    let error = condition(ListedVolumeState::Error, VolumeStatus::Impaired);
    let neighbors = [
        (None, 0, false),
        (
            Some(condition(
                ListedVolumeState::InUse,
                VolumeStatus::InsufficientData,
            )),
            0,
            false,
        ),
        (
            Some(condition(ListedVolumeState::Creating, VolumeStatus::Ok)),
            1,
            true,
        ),
        (
            Some(condition(ListedVolumeState::Deleted, VolumeStatus::Ok)),
            1,
            true,
        ),
        (
            Some(condition(
                ListedVolumeState::Available,
                VolumeStatus::Impaired,
            )),
            1,
            true,
        ),
        (
            Some(condition(ListedVolumeState::Available, VolumeStatus::Ok)),
            0,
            true,
        ),
    ];
    for (neighbor, others, complete) in neighbors {
        let mut memory = VolumeMemory::new(&bounds());
        let mut listing = vec![(volume(1), error)];
        listing.extend(neighbor.map(|neighbor| (volume(2), neighbor)));
        observe(&mut memory, &listing, 0);
        observe(&mut memory, &listing, 1);
        let judged = memory.judge(volume(1), &named(&[1, 2]), 1);
        let expected = VolumeJudgement {
            health: Some(Health::Lost),
            others,
            complete,
            streak: 0,
            confirmed: false,
        };
        assert_eq!(judged, expected, "{neighbor:?}");
    }
}

#[test]
fn differing_rows_for_one_volume_make_the_listing_unusable_in_either_order() {
    let error = (
        volume(1),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    );
    let serving = (
        volume(1),
        condition(ListedVolumeState::InUse, VolumeStatus::Ok),
    );
    let other = (
        volume(2),
        condition(ListedVolumeState::Error, VolumeStatus::Impaired),
    );
    for conflict in [[serving, error], [error, serving]] {
        let mut memory = VolumeMemory::new(&bounds());
        observe(&mut memory, &[error, other], 0);
        let mut listing = conflict.to_vec();
        listing.push(other);
        assert_eq!(memory.observe(Ok(&listing), 1, at(1)), Err(Unlisted));
        let judged = memory.judge(volume(1), &named(&[1, 2]), 1);
        assert_eq!((judged.health, judged.complete), (None, false));
        assert_eq!(memory.health(volume(2), 1), None);
        observe(&mut memory, &[error, other], 2);
        assert_eq!(memory.health(volume(1), 2), Some(Health::Impaired));
        assert_eq!(memory.health(volume(2), 2), Some(Health::Impaired));
    }
    let mut memory = VolumeMemory::new(&bounds());
    observe(&mut memory, &[error, error], 0);
    assert_eq!(memory.health(volume(1), 0), Some(Health::Impaired));
    observe(&mut memory, &[error], 1);
    assert_eq!(memory.health(volume(1), 1), Some(Health::Lost));
}

#[test]
fn report_memory_drops_the_hosts_the_directory_leaves_out() {
    let mut reports = ReportMemory::default();
    reports.track(&directory(2, 1), START);
    for writer in [1, 2] {
        reports.accepted(report(writer, 1), START);
    }
    for writer in [1, 2] {
        reports.accepted(report(writer, 2), START + S);
    }
    reports.track(&directory(1, 1), START + S);
    assert!(reports.silence(host(1), START + S).advanced);
    assert_eq!(reports.silence(host(2), START + 100 * S), silence(false, 0));
}

#[test]
fn report_memory_holds_no_report_of_an_instance_the_directory_replaced() {
    let mut reports = ReportMemory::default();
    reports.track(&directory(1, 1), START);
    reports.accepted(report(1, 1), START);
    assert_eq!(reports.latest(host(1)).map(|held| held.sequence), Some(1));
    let mut renamed = listing(1, 1);
    renamed.hosts[0].instance = instance(9);
    let keys = report_keys(&renamed);
    let renamed = Directory::<ReconcilerProjection>::new(renamed, keys).unwrap();
    reports.track(&renamed, START + S);
    assert!(reports.latest(host(1)).is_none());
}

#[test]
fn judging_every_volume_at_once_leaves_each_shards_own_volumes_out() {
    let error = condition(ListedVolumeState::Error, VolumeStatus::Impaired);
    let listing = [
        (volume(1), error),
        (
            volume(2),
            condition(ListedVolumeState::InUse, VolumeStatus::Ok),
        ),
        (
            volume(3),
            condition(ListedVolumeState::InUse, VolumeStatus::Warning),
        ),
        (
            volume(4),
            condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData),
        ),
        (
            volume(5),
            condition(ListedVolumeState::Creating, VolumeStatus::Ok),
        ),
    ];
    let mut memory = VolumeMemory::new(&bounds());
    memory.observe(Ok(&listing), 0, at(0)).unwrap();
    memory.observe(Ok(&listing), 1, at(1)).unwrap();
    let judged = |health, others, complete| VolumeJudgement {
        health,
        others,
        complete,
        streak: 0,
        confirmed: false,
    };
    let own = |volumes: &[u8]| named(volumes);
    let subjects = [
        (volume(1), own(&[1])),
        (volume(1), own(&[1, 5])),
        (volume(4), own(&[4])),
        (volume(2), own(&[2])),
        (volume(7), own(&[7])),
    ];
    let expected = [
        judged(Some(Health::Lost), 2, false),
        judged(Some(Health::Lost), 1, false),
        judged(None, 3, true),
        judged(Some(Health::Available), 3, false),
        judged(None, 3, false),
    ];
    let set = named(&[1, 2, 3, 4, 5]);
    assert_eq!(memory.judge_each(&subjects, &set, 1), expected);
    let alone = memory.judge(volume(4), &named(&[4]), 1);
    assert_eq!(alone, judged(None, 0, true));
    let peer = memory.judge(volume(2), &named(&[2, 4]), 1);
    assert_eq!(peer, judged(Some(Health::Available), 0, false));
    assert_eq!(memory.observe(Err(Unlisted), 2, at(2)), Err(Unlisted));
    let failed = memory.judge_each(&[(volume(2), own(&[2]))], &named(&[2]), 2);
    assert_eq!(failed, [judged(None, 0, false)]);
}

#[test]
fn an_adverse_relist_in_one_tick_starts_no_count() {
    let mut zone = Zone::new();
    let now = START + 100 * S;
    zone.list(Ok(&[running(1)]), now);
    zone.relist(&[], now + S);
    assert_eq!(zone.evidence(1), InstanceEvidence::Absent { ticks: 0 });
    zone.list(Ok(&[]), now + TICK);
    assert_eq!(zone.evidence(1), InstanceEvidence::Absent { ticks: 1 });
    assert_eq!(zone.verdict(now + TICK), HostEvidence::Unknown);
    zone.list(Ok(&[]), now + 2 * TICK);
    assert_eq!(zone.verdict(now + 2 * TICK), HostEvidence::Lost);

    let error = condition(ListedVolumeState::Error, VolumeStatus::Impaired);
    let serving = condition(ListedVolumeState::InUse, VolumeStatus::Ok);
    let mut memory = VolumeMemory::new(&bounds());
    memory
        .observe(Ok(&[(volume(1), serving)]), 1, at(1))
        .unwrap();
    memory
        .observe(Ok(&[(volume(1), error)]), 1, at(1) + S)
        .unwrap();
    assert_eq!(memory.health(volume(1), 1), Some(Health::Impaired));
    memory.observe(Ok(&[(volume(1), error)]), 2, at(2)).unwrap();
    assert_eq!(memory.health(volume(1), 2), Some(Health::Impaired));
    memory.observe(Ok(&[(volume(1), error)]), 3, at(3)).unwrap();
    assert_eq!(memory.health(volume(1), 3), Some(Health::Lost));
}

/// Only the first complete listing in a tick can count toward an instance absence or a volume error run. A later
/// `Err(Unlisted)` in that tick leaves the tick spent.
#[test]
fn a_listing_after_a_failed_one_in_a_spent_tick_starts_no_count() {
    let mut zone = Zone::new();
    let now = START + 100 * S;
    zone.list(Ok(&[running(1)]), now);
    let failed = (zone.instances).observe(&zone.directory, Err(Unlisted), zone.tick, now + S);
    assert_eq!(failed, Err(Unlisted));
    zone.relist(&[], now + 2 * S);
    assert_eq!(zone.evidence(1), InstanceEvidence::Absent { ticks: 0 });
    zone.list(Ok(&[]), now + TICK);
    assert_eq!(zone.evidence(1), InstanceEvidence::Absent { ticks: 1 });
    assert_eq!(zone.verdict(now + TICK), HostEvidence::Unknown);
    zone.list(Ok(&[]), now + 2 * TICK);
    assert_eq!(zone.verdict(now + 2 * TICK), HostEvidence::Lost);

    let error = condition(ListedVolumeState::Error, VolumeStatus::Impaired);
    let serving = condition(ListedVolumeState::InUse, VolumeStatus::Ok);
    let mut memory = VolumeMemory::new(&bounds());
    memory
        .observe(Ok(&[(volume(1), serving)]), 1, at(1))
        .unwrap();
    assert_eq!(memory.observe(Err(Unlisted), 1, at(1) + S), Err(Unlisted));
    memory
        .observe(Ok(&[(volume(1), error)]), 1, at(1) + 2 * S)
        .unwrap();
    assert_eq!(memory.health(volume(1), 1), Some(Health::Impaired));
    memory.observe(Ok(&[(volume(1), error)]), 2, at(2)).unwrap();
    assert_eq!(memory.health(volume(1), 2), Some(Health::Impaired));
    memory.observe(Ok(&[(volume(1), error)]), 3, at(3)).unwrap();
    assert_eq!(memory.health(volume(1), 3), Some(Health::Lost));
}

#[test]
fn the_first_complete_listing_of_a_tick_counts_after_a_failed_one() {
    let mut zone = Zone::new();
    let now = START + 100 * S;
    zone.list(Err(Unlisted), now);
    zone.relist(&[], now + S);
    assert_eq!(zone.evidence(1), InstanceEvidence::Absent { ticks: 1 });
    zone.list(Ok(&[]), now + TICK);
    assert_eq!(zone.verdict(now + TICK), HostEvidence::Lost);

    let error = condition(ListedVolumeState::Error, VolumeStatus::Impaired);
    let mut memory = VolumeMemory::new(&bounds());
    assert_eq!(memory.observe(Err(Unlisted), 1, at(1)), Err(Unlisted));
    memory
        .observe(Ok(&[(volume(1), error)]), 1, at(1) + S)
        .unwrap();
    assert_eq!(memory.health(volume(1), 1), Some(Health::Impaired));
    memory.observe(Ok(&[(volume(1), error)]), 2, at(2)).unwrap();
    assert_eq!(memory.health(volume(1), 2), Some(Health::Lost));
}

#[test]
fn the_answered_window_holds_loss_to_its_configured_bound() {
    let rule = HostRule::new(80 * S, 100 * S, 300 * S, 180 * S, 2);
    let terminated = InstanceEvidence::Listed {
        state: InstanceState::Terminated,
        checks: StatusCheck::Ok,
        stopped_us: 0,
        impaired_us: 0,
    };
    let silent = silence(true, 500 * S);
    for state in [DirectoryState::Active, DirectoryState::Draining] {
        assert_eq!(
            host_evidence(&rule, state, silent, terminated),
            HostEvidence::Lost
        );
        let at = |answered_us| tick_evidence(&rule, state, silent, answered_us, terminated);
        assert_eq!(at(0), HostEvidence::Unknown, "{state:?}");
        assert_eq!(at(100 * S), HostEvidence::Unknown, "{state:?}");
        assert_eq!(at(100 * S + 1), HostEvidence::Lost, "{state:?}");
    }
    let retired = |answered_us| {
        tick_evidence(
            &rule,
            DirectoryState::Retired,
            silent,
            answered_us,
            terminated,
        )
    };
    assert_eq!(
        (retired(0), retired(100 * S)),
        (HostEvidence::Lost, HostEvidence::Lost)
    );
    let fresh = silence(true, 10 * S);
    let live = tick_evidence(&rule, DirectoryState::Active, fresh, 0, terminated);
    assert_eq!(live, HostEvidence::Conflict);
}

/// The run of complete views keeps a repeat's value within a tick, extends on the next tick, restarts after a gap
/// or a change of active volume, and confirms a loss after `needed` views. A confirmation carries to the next tick
/// of the same lost volume; one first earned on a tick does not survive an incomplete repeat of that tick.
#[test]
fn a_view_run_counts_numbered_ticks_of_one_active_volume() {
    let a = VolumeId::new("vol-0a").unwrap();
    let b = VolumeId::new("vol-0b").unwrap();
    let run = |active, tick, views, confirmed, entered| ViewRun {
        active,
        tick,
        views,
        confirmed,
        entered,
    };
    let next =
        |prior, active, tick, complete, lost| ViewRun::next(prior, active, tick, complete, lost, 2);
    let one = run(Some(a), 5, 1, false, false);
    assert_eq!(next(None, a, 5, true, false), one, "a first view");
    assert_eq!(
        next(Some(one), a, 5, true, false).views,
        1,
        "a repeat inside the tick"
    );
    let two = run(Some(a), 6, 2, true, false);
    assert_eq!(next(Some(one), a, 6, true, true), two, "the next tick");
    assert_eq!(
        next(Some(one), a, 6, true, false),
        run(Some(a), 6, 2, false, false),
        "a full run, not lost"
    );
    assert_eq!(
        next(Some(one), a, 7, true, true),
        run(Some(a), 7, 1, false, false),
        "after a gap"
    );
    let incomplete = run(Some(a), 6, 0, false, false);
    assert_eq!(
        next(Some(one), a, 6, false, true),
        incomplete,
        "an incomplete view"
    );
    let zero = run(Some(a), 5, 0, false, false);
    assert_eq!(
        next(Some(zero), a, 5, true, false).views,
        0,
        "a complete retry after an incomplete call"
    );
    let unjudged = Some(ViewRun::unjudged(5));
    assert_eq!(
        next(unjudged, a, 5, true, false).views,
        0,
        "a retry after an unjudged call"
    );
    assert_eq!(
        next(unjudged, a, 6, true, false).views,
        1,
        "after an unjudged tick"
    );
    assert_eq!(
        next(Some(one), b, 5, true, false).views,
        0,
        "another volume inside the tick"
    );
    assert_eq!(
        next(Some(one), b, 6, true, true),
        run(Some(b), 6, 1, false, false),
        "another volume"
    );
    let earned = next(Some(two), a, 6, false, true);
    assert_eq!(
        earned,
        run(Some(a), 6, 0, false, false),
        "earned on the tick, then incomplete"
    );
    assert_eq!(
        next(Some(two), a, 6, true, true),
        two,
        "a complete repeat keeps it"
    );
    let carried = next(Some(two), a, 7, false, true);
    assert_eq!(
        carried,
        run(Some(a), 7, 0, true, true),
        "carried to the next tick"
    );
    assert_eq!(
        next(Some(carried), a, 7, false, true),
        carried,
        "an incomplete repeat of a carried tick"
    );
    assert!(
        !next(Some(two), a, 7, false, false).confirmed,
        "no longer lost"
    );
    assert!(!next(Some(two), a, 8, false, true).confirmed, "after a gap");
    assert!(
        !next(Some(two), b, 7, false, true).confirmed,
        "another volume"
    );
    let saturated = run(Some(a), 5, u32::MAX, true, false);
    assert_eq!(next(Some(saturated), a, 6, true, true).views, u32::MAX);
    let refused = ViewRun::unjudged(two.tick);
    assert_eq!(
        next(Some(refused), a, 6, true, true).views,
        0,
        "a retry after a failed directory read"
    );
    assert_eq!(
        next(Some(refused), a, 7, true, true),
        run(Some(a), 7, 1, false, false)
    );
}

/// `instance_down` reads an ended instance as down at once, a stopping or stopped one from its dwell on, and an
/// absence from `absent_ticks` listings on; a running instance, impaired or not, no evidence and a shorter absence or
/// stop read not down.
#[test]
fn instance_down_reads_each_instance_evidence_at_its_threshold() {
    let rule = HostRule::of(&bounds());
    let config = bounds().config().clone();
    let listed = |state, checks, stopped_us| InstanceEvidence::Listed {
        state,
        checks,
        stopped_us,
        impaired_us: config.impaired_dwell_us,
    };
    let dwell = config.stopped_dwell_us;
    let cases = [
        (InstanceEvidence::Unlisted, false),
        (InstanceEvidence::Absent { ticks: 0 }, false),
        (
            InstanceEvidence::Absent {
                ticks: config.absent_ticks - 1,
            },
            false,
        ),
        (
            InstanceEvidence::Absent {
                ticks: config.absent_ticks,
            },
            true,
        ),
        (listed(InstanceState::Running, StatusCheck::Ok, 0), false),
        (
            listed(InstanceState::Running, StatusCheck::Impaired, 0),
            false,
        ),
        (
            listed(InstanceState::Terminated, StatusCheck::NotApplicable, 0),
            true,
        ),
        (
            listed(InstanceState::ShuttingDown, StatusCheck::NotApplicable, 0),
            true,
        ),
        (
            listed(
                InstanceState::Stopped,
                StatusCheck::NotApplicable,
                dwell - 1,
            ),
            false,
        ),
        (
            listed(InstanceState::Stopped, StatusCheck::NotApplicable, dwell),
            true,
        ),
        (
            listed(
                InstanceState::Stopping,
                StatusCheck::NotApplicable,
                dwell - 1,
            ),
            false,
        ),
        (
            listed(InstanceState::Stopping, StatusCheck::NotApplicable, dwell),
            true,
        ),
    ];
    for (evidence, down) in cases {
        assert_eq!(instance_down(&rule, evidence), down, "{evidence:?}");
    }
}

/// `answers_no_probe` reads a down instance as answering no probe whatever its report, and a running instance from
/// the tick its checks have been impaired for `impaired_dwell_us` while its report has been silent past `silent_us`
/// with no unanswered read inside `silent_us`. Impaired checks under a publishing report, a silent report under
/// passing checks, and each value one step short of its threshold leave the host able to answer.
#[test]
fn answers_no_probe_reads_a_down_instance_or_dwelt_impairment_under_a_silent_report() {
    let rule = HostRule::of(&bounds());
    let config = bounds().config().clone();
    let (dwell, silent) = (config.impaired_dwell_us, bounds().silent_us());
    let running = |checks, impaired_us| InstanceEvidence::Listed {
        state: InstanceState::Running,
        checks,
        stopped_us: 0,
        impaired_us,
    };
    let terminated = InstanceEvidence::Listed {
        state: InstanceState::Terminated,
        checks: StatusCheck::NotApplicable,
        stopped_us: 0,
        impaired_us: 0,
    };
    let quiet = |advanced, silent_us| Silence {
        advanced,
        silent_us,
    };
    let impaired = running(StatusCheck::Impaired, dwell);
    let cases = [
        (terminated, quiet(true, 0), 0, true),
        (impaired, quiet(true, silent + 1), silent + 1, true),
        (impaired, quiet(false, silent + 1), silent + 1, true),
        (impaired, quiet(true, silent), silent + 1, false),
        (impaired, quiet(true, silent + 1), silent, false),
        (impaired, quiet(true, 0), 0, false),
        (
            running(StatusCheck::Impaired, dwell - 1),
            quiet(true, silent + 1),
            silent + 1,
            false,
        ),
        (
            running(StatusCheck::Ok, dwell),
            quiet(true, silent + 1),
            silent + 1,
            false,
        ),
        (
            InstanceEvidence::Unlisted,
            quiet(true, silent + 1),
            silent + 1,
            false,
        ),
    ];
    for (instance, silence, answered_us, expected) in cases {
        assert_eq!(
            answers_no_probe(&rule, silence, answered_us, instance),
            expected,
            "{instance:?} {silence:?} answered {answered_us}"
        );
    }
}
