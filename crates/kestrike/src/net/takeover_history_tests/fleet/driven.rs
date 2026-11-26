use super::oracles::{Judged, Watched};
use super::*;
use crate::failover::evidence::NotSole;
use crate::failover::fresh::tests::registrant;
use crate::failover::restart::Check;
use crate::failover::route::{FrameKind, HolderFrame};
use crate::failover::takeover::tests::Card;
use crate::net::link::{Faults, network};
use crate::net::owner_tests::{client_config, configured_client};
use crate::net::ownership::ActivatedEpoch;
use crate::storage::RefusalReason;

struct Driven<'c, 'w> {
    fleet: Fleet<'c>,
    live: Live<'w>,
    draws: Draws,
    spare: Vec<(&'w Grounds, &'w Pools<'w>)>,
}

impl Driven<'_, '_> {
    fn crash(&mut self, at: usize) {
        let ground = self.spare.remove(0);
        let recovered = (self.fleet).recover(&mut self.live, ground, (at, true), &mut self.draws);
        recovered.expect("a crash episode that stops on no wait");
    }

    fn turns(&mut self, rounds: u64) {
        for _ in 0..rounds {
            self.fleet.turn(&mut self.live);
        }
    }

    fn shard(&self, at: usize) -> String {
        format!("shard {}", self.fleet.cells[at].placement.shard.get())
    }

    fn held_by_another_volume(&self, at: usize) -> Vec<crate::failover::evidence::Registrant> {
        let foreign = self.fleet.cells[(at + 1) % self.fleet.cells.len()].pair;
        vec![
            registrant(foreign, 1, true),
            registrant(self.fleet.cells[at].pair, 2, false),
        ]
    }

    fn raise_route(&self, at: usize, kind: FrameKind) {
        let cell = &self.fleet.cells[at];
        let shard = cell.placement.shard;
        let Some(HighWater::Bound(bound)) = cell.world.routes.route(shard) else {
            panic!("cell {at} serves on a bound route");
        };
        let later = crate::net::ownership::Tenure {
            epoch: ActivatedEpoch::new(bound.epoch.get() + 2).expect("a later epoch"),
            ..bound
        };
        let frame = HolderFrame {
            tenure: later,
            kind,
        };
        let raised = cell.world.routes.observe(shard, frame);
        let expected = match kind {
            FrameKind::Ready => HighWater::Bound(later),
            _ => HighWater::Candidate(later),
        };
        assert_eq!(raised, Some(expected));
    }

    fn record_later_attempt(&self, at: usize) {
        let cell = &self.fleet.cells[at];
        let key = Key::Shard(cell.placement.shard);
        let stored = self.fleet.store.0.borrow().current(&key).cloned();
        let item = stored.expect("a stored shard record");
        let later = ShardRecord {
            attempts: cell.decoded(&item).attempts + 1,
            ..cell.decoded(&item)
        };
        let write = Write::Exact {
            expect: item.version,
            value: later.encode(),
        };
        let committed = Store::write(&mut self.fleet.store.clone(), &key, &write);
        assert!(matches!(committed, Outcome::Committed(_)));
    }

    fn conditions(&self, at: usize) -> [bool; 5] {
        let serving = self.live[at].as_ref().expect("a live tenure");
        let authority = serving.owner.authority_report();
        let cell = &self.fleet.cells[at];
        let route = cell.world.routes.route(cell.placement.shard);
        [
            authority.state == State::Serving,
            authority.report_age_us.is_some_and(|age| age < WINDOW),
            serving.owner.readiness() == Readiness::Live,
            serving.client.state() == SessionState::Active,
            matches!(route, Some(HighWater::Bound(_))),
        ]
    }

    fn lose_device(&mut self, at: usize) {
        let serving = self.live[at].as_ref().expect("a live tenure");
        serving.registry.borrow_mut().refuse = Some(RefusalReason::DeviceGone);
        self.turns(1);
    }

    fn replace_client(&mut self, at: usize) {
        let (grounds, pools) = self.spare.remove(0);
        let routes = Arc::clone(&self.fleet.cells[at].world.routes);
        let (client_end, _, _) = network(64, 8384, 21, [Faults::default(); 2]);
        let nonce = |nonce: &mut [u8; 16]| {
            nonce[..2].copy_from_slice(&[u8::MAX, 2]);
            Ok(())
        };
        let client = configured_client(
            0,
            client_config(0),
            &pools.client,
            &grounds.releases,
            client_end,
            Box::default(),
            nonce,
            routes,
        );
        self.live[at].as_mut().expect("a live tenure").client = client;
        self.turns(1);
    }

    fn assert_serves(&self, at: usize) {
        let serving = self.live[at].as_ref().expect("a live tenure");
        assert_eq!(serving.owner.authority_report().state, State::Serving);
        assert_eq!(serving.owner.readiness(), Readiness::Live);
        assert_eq!(serving.client.state(), SessionState::Active);
    }

    fn judged(mut self) -> Report {
        for (cell, serving) in self.fleet.cells.iter_mut().zip(&self.live) {
            if let Some(serving) = serving {
                cell.close(serving, true);
            }
        }
        let decisions = self.draws.decisions();
        let tape = self.draws.finish().expect("a recorded tape");
        self.fleet.report(&self.live, decisions, tape)
    }
}

fn driven<R>(
    config: &Config,
    (boot, again): (&[usize], &[usize]),
    prepare: impl FnOnce(&mut Fleet<'_>),
    body: impl for<'w> FnOnce(Driven<'_, 'w>) -> R,
) -> R {
    let mut draws = Draws::record(config.root);
    let mut fleet = Fleet::seeded(config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    prepare(&mut fleet);
    let slots = boot.iter().chain(again);
    let grounds: Vec<Grounds> = slots
        .map(|&at| Grounds::over(storage_shared(1, fleet.share(at))))
        .collect();
    let pools: Vec<Pools<'_>> = grounds.iter().map(Pools::new).collect();
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let _inline = Inline::set();
    for (slot, &at) in boot.iter().enumerate() {
        let ground = (&grounds[slot], &pools[slot]);
        let booted = fleet.recover(&mut live, ground, (at, false), &mut draws);
        booted.expect("a boot that stops on no wait");
    }
    let spare = (boot.len()..grounds.len())
        .map(|slot| (&grounds[slot], &pools[slot]))
        .collect();
    body(Driven {
        fleet,
        live,
        draws,
        spare,
    })
}

const ALL: [usize; 6] = [0, 1, 2, 3, 4, 5];

fn six() -> Config {
    Config::six(1)
}

/// The six-host run driven through the round loop's own steps, every shard booted and crashed once, earns credit
/// with six crashes and no takeover. Each shard's Report tally counts exactly the Reports its table logged while
/// one of its tenures served: every shard restarts on its own host, so its table holds the Reports its pair issued
/// over the whole run, of which each incarnation's fence (a restart's two Reports) precedes its tenure, and one
/// Report a foreign pair logs on s3's table while its restarted tenure serves counts once more there. The account
/// takes no tenure's start mark, so a tally that summed the table's count at each close, or that started a tenure's
/// count before its fence, differs from it.
#[test]
fn the_same_steps_with_no_fault_earn_credit() {
    const FOREIGN: usize = 3;
    let fence = restart_tests::FULL
        .iter()
        .filter(|c| **c == "report")
        .count();
    let (report, logged) = driven(
        &six(),
        (&ALL, &ALL),
        |_| {},
        |mut fleet| {
            for at in ALL {
                fleet.crash(at);
            }
            let foreign = fleet.fleet.cells[(FOREIGN + 1) % ALL.len()].pair;
            {
                let mut table = fleet.fleet.cells[FOREIGN].world.reservation.borrow_mut();
                let report = crate::storage::ReservationCommand::Report { not_before: 0 };
                table.log.push(report);
                table.issuers.push(foreign);
            }
            fleet.turns(4);
            let logged: Vec<(usize, usize)> = (fleet.fleet.cells.iter())
                .map(|cell| {
                    let table = cell.world.reservation.borrow();
                    let others = (table.issuers.iter())
                        .filter(|by| **by != cell.pair)
                        .count();
                    (table.reports_by(cell.pair), others)
                })
                .collect();
            (fleet.judged(), logged)
        },
    );
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
    assert_eq!((report.crashes, report.takeovers), (6, 0));
    for (at, shard) in report.shards.iter().enumerate() {
        let (own, others) = logged[at];
        let name = format!("shard {}", shard.placement.shard.get());
        assert_eq!(shard.recoveries.len(), 2, "{name}");
        assert_eq!(others, usize::from(at == FOREIGN), "{name}");
        assert_eq!(
            shard.reports,
            own - fence * shard.recoveries.len() + others,
            "{name}: {own} own Reports, {others} foreign"
        );
    }
}

#[test]
fn a_refused_restart_reports_its_blocker_and_its_flip_request_fails_the_volume_check() {
    let report = driven(
        &six(),
        (&ALL, &[3]),
        |_| {},
        |mut fleet| {
            let held = fleet.held_by_another_volume(3);
            fleet.fleet.cells[3].world.reservation.borrow_mut().entries = held;
            fleet.crash(3);
            assert!(fleet.live[3].is_none());
            // The incarnation's refusal reads as the class `NotHolding`, which covers several causes, and the
            // assertions after the run check that class and the flip request. This replay checks the planted
            // table: `Restart::run` over a card on the cell's records and reservation table, with `restart_of`'s
            // empty peers and fixture bounds, reads `ForeignHolder`. The fencer reads the same table shape in the
            // row `unrecorded holder` of `host::fencer_tests::the_restart_rows_agree_between_the_card_and_the_fencer`.
            let cell = &fleet.fleet.cells[3];
            let member = fleet.fleet.topology.members[cell.placement.owner];
            let holder = holder_on(cell.placement.volume, cell.owner, member.instance);
            let mut card = Card::new(cell.pair, &cell.world.reservation);
            let mut client = crate::storage::store_tests::client(&fleet.fleet.store);
            let restart = restart_tests::restart_of(cell.placement.shard, holder);
            let refused = restart.run(&mut client, &cell.local, &mut card);
            let cause = refused.err().map(|refused| refused.check);
            assert_eq!(cause, Some(Check::NotHolding(NotSole::ForeignHolder)));
            fleet.judged()
        },
    );
    let shard = &report.shards[3];
    assert_eq!(shard.blockers, ["NotHolding"]);
    assert_eq!(shard.recoveries.len(), 1, "the boot alone recovered");
    let flip = Verdict::Fail(
        "a recovery requested a flip with no volume lost",
        "1 requests".into(),
    );
    assert_eq!(report.verdicts.keeps_volume, flip);
    assert_eq!(report.verdicts.settles, Verdict::Pass, "a blocker settles");
    assert_eq!(report.credit(), flip);
}

#[test]
fn a_tenure_whose_report_shows_a_foreign_holder_withdraws_and_requests_a_flip() {
    let (report, shard) = driven(
        &six(),
        (&ALL, &[0]),
        |_| {},
        |mut fleet| {
            fleet.crash(0);
            let held = fleet.held_by_another_volume(1);
            let serving = fleet.live[1].as_ref().expect("a live tenure");
            serving.registry.borrow_mut().entries = held;
            fleet.turns(WINDOW / ROUND_US + 2);
            let serving = fleet.live[1].as_ref().expect("a live tenure");
            let authority = serving.owner.authority_report();
            assert_eq!(authority.state, State::Withdrawn);
            assert!(authority.flip.is_some());
            let shard = fleet.shard(1);
            (fleet.judged(), shard)
        },
    );
    let flip = Verdict::Fail(
        "a recovery requested a flip with no volume lost",
        "1 requests".into(),
    );
    assert_eq!(report.verdicts.keeps_volume, flip);
    let withdrawn = Verdict::Fail(
        "a tenure that no fault deposed stopped serving",
        format!("{shard} 1 tenures"),
    );
    assert_eq!(report.verdicts.settles, withdrawn);
}

type Fault = fn(&mut Driven<'_, '_>);

#[test]
fn a_shard_that_lacks_one_condition_of_a_served_shard_is_not_served() {
    let every = [true; 5];
    let without = |at: usize| {
        let mut held = every;
        held[at] = false;
        held
    };
    let faults: [(&str, Fault, [bool; 5]); 7] = [
        (
            "an expired Report window",
            |fleet| {
                let serving = fleet.live[2].as_mut().expect("a live tenure");
                serving.pause(WINDOW / ROUND_US + 1);
            },
            without(1),
        ),
        (
            "a device that is gone",
            |fleet| fleet.lose_device(2),
            without(2),
        ),
        (
            "a client with no session",
            |fleet| fleet.replace_client(2),
            without(3),
        ),
        (
            "a route raised past the tenure",
            |fleet| {
                fleet.raise_route(2, FrameKind::Candidate);
                fleet.turns(2);
            },
            without(4),
        ),
        (
            "a record at a later attempt",
            |fleet| fleet.record_later_attempt(2),
            every,
        ),
        (
            "a record and a route at a later tenure",
            |fleet| {
                fleet.record_later_attempt(2);
                fleet.raise_route(2, FrameKind::Ready);
            },
            every,
        ),
        (
            "a route bound to a later tenure",
            |fleet| fleet.raise_route(2, FrameKind::Ready),
            every,
        ),
    ];
    let settled = |fault: Option<Fault>| {
        driven(
            &six(),
            (&ALL, &[0, 2]),
            |_| {},
            |mut fleet| {
                fleet.crash(0);
                if let Some(fault) = fault {
                    fault(&mut fleet);
                }
                let (held, shard) = (fleet.conditions(2), fleet.shard(2));
                (fleet.judged().verdicts.settles, held, shard)
            },
        )
    };
    for (name, fault, expected) in faults {
        let (settles, held, shard) = settled(Some(fault));
        assert_eq!(held, expected, "{name}");
        assert_eq!(
            settles,
            Verdict::Fail(
                "a shard neither serves with a standby nor reports a blocker",
                shard
            ),
            "{name}"
        );
    }
    let (settles, held, _) = settled(None);
    assert_eq!((settles, held), (Verdict::Pass, every));
}

#[test]
fn a_recovery_takes_longer_the_more_owners_its_hosts_share_divides_over() {
    let recovered = |owners: u32| {
        let config = six();
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        let share = HostShare {
            bytes: 24_576,
            owners,
            ..fleet.share(0)
        };
        let grounds = Grounds::over(storage_shared(1, share));
        let pools = Pools::new(&grounds);
        let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
        let _inline = Inline::set();
        let booted = fleet.recover(&mut live, (&grounds, &pools), (0, false), &mut draws);
        assert_eq!(booted, Ok(()));
        let recovery = fleet.cells[0].recoveries[0];
        assert_eq!(recovery.share, share);
        assert_eq!(recovery.sweep, Some((8, 8)));
        let owner = &live[0].as_ref().expect("the recovered tenure").owner;
        let saturated = owner.recovery_report().io_saturated_windows;
        assert!(saturated > 0, "{owners} owners: the share bounds the load");
        recovery.rounds
    };
    let rounds = [1, 2, 3].map(recovered);
    assert!(rounds[0] < rounds[1] && rounds[1] < rounds[2], "{rounds:?}");
}

#[test]
fn a_get_the_client_refuses_for_its_route_settles_unserved_and_fails_the_untouched_check() {
    let (report, shard) = driven(
        &six(),
        (&ALL, &[]),
        |_| {},
        |mut fleet| {
            fleet.raise_route(2, FrameKind::Candidate);
            fleet.fleet.send(&mut fleet.live, 2, 1, Purpose::Neighbour);
            assert!(fleet.fleet.flights.is_empty(), "the client sent nothing");
            let settled: Vec<(usize, bool)> = (fleet.fleet.neighbours.iter())
                .map(|settled| (settled.at, settled.served))
                .collect();
            assert_eq!(settled, [(2, false)]);
            let shard = fleet.shard(2);
            (fleet.judged(), shard)
        },
    );
    let refused = Verdict::Fail(
        "an untouched shard did not serve a request its object's bytes",
        shard,
    );
    assert_eq!(report.verdicts.untouched, refused);
}

#[test]
fn a_store_request_a_tenure_that_stops_or_a_moved_route_on_an_untouched_shard_fails_the_run() {
    let quiet = (false, false);
    let faults: [(&str, Fault, (bool, bool), &str); 4] = [
        (
            "a store read of a coverage page",
            |fleet| {
                let key = Key::Page(fleet.fleet.cells[2].placement.shard, 0);
                let read = Store::read(&mut fleet.fleet.store.clone(), &key);
                assert!(read.is_ok());
            },
            (true, false),
            "an untouched shard's records took a store request other than its own record views",
        ),
        (
            "a tenure that ended",
            |fleet| {
                let ended = fleet.live[2].take().expect("a live tenure");
                fleet.fleet.cells[2].close(&ended, true);
            },
            (false, true),
            "an untouched shard changed its tenure",
        ),
        (
            "a tenure that lost its reservation",
            |fleet| {
                let reservation = &fleet.fleet.cells[2].world.reservation;
                reservation.borrow_mut().entries.clear();
                fleet.turns(WINDOW / ROUND_US + 2);
                let serving = fleet.live[2].as_ref().expect("a live tenure");
                let state = serving.owner.authority_report().state;
                assert_eq!(state, State::Withdrawn);
            },
            (false, true),
            "an untouched shard changed its tenure",
        ),
        (
            "a raised route",
            |fleet| {
                fleet.raise_route(2, FrameKind::Candidate);
                fleet.turns(2);
                fleet.assert_serves(2);
            },
            (false, true),
            "an untouched shard changed its tenure",
        ),
    ];
    let watched = |fault: Option<Fault>| {
        driven(
            &six(),
            (&ALL, &[]),
            |_| {},
            |mut fleet| {
                let crashed = fleet.fleet.crash(&mut fleet.live, 0, &mut fleet.draws);
                let episode = crashed.expect("a recorded episode");
                assert!(episode.dropped);
                if let Some(fault) = fault {
                    fault(&mut fleet);
                }
                fleet.fleet.watch(&fleet.live, &episode);
                let rows: Vec<Watched> = fleet.fleet.watched.clone();
                let shard = fleet.shard(2);
                (rows, shard, fleet.judged().verdicts.untouched)
            },
        )
    };
    for (name, fault, changed, rule) in faults {
        let (rows, shard, untouched) = watched(Some(fault));
        let flags: Vec<(bool, bool)> = (rows.iter())
            .map(|watch| (watch.requested, watch.moved))
            .collect();
        assert_eq!(flags, [quiet, changed, quiet, quiet, quiet], "{name}");
        assert_eq!(untouched, Verdict::Fail(rule, shard), "{name}");
    }
    let (rows, _, untouched) = watched(None);
    assert_eq!(rows.len(), 5, "every shard that served at the crash");
    assert!(rows.iter().all(|watch| !watch.requested && !watch.moved));
    assert_eq!(
        untouched,
        Verdict::Unrun("no request reached an untouched shard during a recovery")
    );
}

/// A tenure that serves through another shard's crash and whose serving duties take no turn for one view period
/// fails the untouched check by the reads rule: its records took no view where the period holds one. The same
/// rounds with every tenure's duties running fail no rule.
#[test]
fn an_untouched_tenure_whose_duties_take_no_turn_for_a_view_period_fails_the_reads_rule() {
    let watched = |stopped: bool| {
        driven(
            &six(),
            (&ALL, &[]),
            |_| {},
            |mut fleet| {
                let crashed = fleet.fleet.crash(&mut fleet.live, 0, &mut fleet.draws);
                let episode = crashed.expect("a recorded episode");
                if stopped {
                    let serving = fleet.live[2].as_mut().expect("a live tenure");
                    assert!(serving.duties.take().is_some(), "the tenure ran duties");
                }
                fleet.turns(oracles::VIEW_ROUNDS);
                fleet.assert_serves(2);
                fleet.fleet.watch(&fleet.live, &episode);
                let views: Vec<u64> = (fleet.fleet.watched.iter())
                    .map(|watch| watch.views.shard)
                    .collect();
                let shard = fleet.shard(2);
                (views, shard, fleet.judged().verdicts.untouched)
            },
        )
    };
    let (views, shard, untouched) = watched(true);
    assert_eq!(views, [1, 0, 1, 1, 1]);
    let rounds = oracles::VIEW_ROUNDS;
    let at = format!("{shard} reads volume 0 shard 0 other 0 over {rounds} rounds");
    let reads = "an untouched shard's reads were other than one volume-record and one shard-record read a view period";
    assert_eq!(untouched, Verdict::Fail(reads, at));
    let (views, _, untouched) = watched(false);
    assert_eq!(views, [1; 5]);
    assert_eq!(
        untouched,
        Verdict::Unrun("no request reached an untouched shard during a recovery")
    );
}

/// The workload's FILL steps the tenure with its serving duties, one duty turn after each owner poll: a record view
/// that falls due at the fill's first poll is submitted on that poll, and one more each view period the fill spans.
#[test]
fn the_workload_s_fill_takes_a_duty_turn_after_each_owner_poll() {
    let (polls, views) = driven(
        &Config::host_loss(1),
        (&[0], &[]),
        |_| {},
        |mut fleet| {
            let serving = fleet.live[0].as_mut().expect("a live tenure");
            assert!(duties_opened(serving), "the duties' open");
            let viewed = |fleet: &Fleet<'_>| fleet.duty_views(0).volume;
            // Turns up to the one that submits a view, then the turns before the next view falls due.
            let mut before = viewed(&fleet.fleet);
            for _ in 0..=oracles::VIEW_ROUNDS {
                assert_eq!(actors::duties(serving), None);
                if viewed(&fleet.fleet) > before {
                    break;
                }
                before = viewed(&fleet.fleet);
            }
            assert_eq!(viewed(&fleet.fleet), before + 1, "a view was submitted");
            for _ in 1..oracles::VIEW_ROUNDS {
                assert_eq!(actors::duties(serving), None);
            }
            let (turn, before) = (serving.turn, viewed(&fleet.fleet));
            let n = fleet.fleet.config.shape.objects + 1;
            assert!(filled(&mut fleet.fleet.cells[0].world, serving, n));
            (serving.turn - turn, viewed(&fleet.fleet) - before)
        },
    );
    assert!(polls >= 1, "the fill polled the owner");
    assert_eq!(
        views,
        polls.div_ceil(oracles::VIEW_ROUNDS),
        "record views over the fill's {polls} owner polls"
    );
}

#[test]
fn a_get_counts_inside_the_window_until_the_recovering_session_is_active() {
    let inside = driven(
        &six(),
        (&[0], &[]),
        |_| {},
        |mut fleet| {
            for recovering in [None, Some(0)] {
                (fleet.fleet.window, fleet.fleet.recovering) = (true, recovering);
                fleet.fleet.send(&mut fleet.live, 0, 1, Purpose::Neighbour);
                fleet.fleet.drain(&mut fleet.live).expect("a served GET");
            }
            let rows = fleet.fleet.neighbours.iter();
            rows.map(|settled| (settled.served, settled.inside))
                .collect::<Vec<_>>()
        },
    );
    assert_eq!(inside, [(true, true), (true, false)]);
}

#[test]
fn a_complete_read_of_other_bytes_is_not_served_and_violates_the_history() {
    let swap = |fleet: &mut Fleet<'_>| {
        let cell = &mut fleet.cells[0];
        let named = cell.world.a.named;
        let other = crate::oracle::Label(99);
        cell.world.a = tenure_a_on(cell.placement.shard, 8, |n| {
            content(n, if n == 1 { other } else { first(n) })
        });
        assert_eq!(cell.world.a.named, named, "the record names the capture");
    };
    let (judged, report) = driven(&six(), (&ALL, &[]), swap, |fleet| {
        (fleet.fleet.cells[0].judged(), fleet.judged())
    });
    let rule = "a complete read returned bytes other than the label's content";
    assert_eq!(judged, Judged::Violated(rule));
    assert_eq!(report.shards[0].recoveries[0].sweep, Some((8, 7)));
    let unserved = Verdict::Fail(
        "a retained entry was not served its exact bytes at the recovered tenure",
        "shard 1 served 7 of 8".into(),
    );
    assert_eq!(report.verdicts.retained, unserved);
}

#[test]
fn a_tenure_that_reads_nothing_leaves_its_retained_set_never_served() {
    let rest = [1, 2, 3, 4, 5];
    let (judged, report) = driven(
        &six(),
        (&rest, &[0]),
        |_| {},
        |mut fleet| {
            let ground = fleet.spare.remove(0);
            let restarted = fleet.fleet.restart(&mut fleet.live, ground, (0, false));
            assert!(matches!(restarted, Ok(Some(_))), "{restarted:?}");
            let ended = fleet.live[0].take().expect("the restarted tenure");
            fleet.fleet.cells[0].close(&ended, true);
            drop(ended);
            (fleet.fleet.cells[0].judged(), fleet.judged())
        },
    );
    assert_eq!(judged, Judged::Unserved(NEVER_SERVED));
    assert_eq!(
        report.verdicts.retained,
        Verdict::Unrun("the retained-set sweep did not run")
    );
}

#[test]
fn a_recovery_reports_its_rounds_from_the_crash_its_owners_peak_and_its_storages_share() {
    let config = six();
    let mut draws = Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    let odd = HostShare {
        owners: 7,
        ..fleet.share(1)
    };
    assert_ne!(odd, fleet.share(1));
    let grounds = [fleet.share(0), odd].map(|share| Grounds::over(storage_shared(1, share)));
    let pools = [Pools::new(&grounds[0]), Pools::new(&grounds[1])];
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let _inline = Inline::set();

    let restarted = fleet.restart(&mut live, (&grounds[0], &pools[0]), (0, false));
    assert!(matches!(restarted, Ok(Some(_))), "{restarted:?}");
    let restart_rounds = fleet.round;
    let recovered = fleet.recover(&mut live, (&grounds[1], &pools[1]), (1, false), &mut draws);
    assert_eq!(recovered, Ok(()));
    let recovery = fleet.cells[1].recoveries[0];
    assert_eq!(recovery.rounds, restart_rounds + DOWN_ROUNDS);
    for serving in live.iter().flatten() {
        assert_eq!(serving.turn, fleet.round, "one round clock");
    }
    let owner = &live[1].as_ref().expect("the recovered tenure").owner;
    let peak = owner.recovery_report().io_peak_bytes;
    assert!(peak > 0);
    assert_eq!(recovery.peak_bytes, peak);
    assert_eq!(recovery.share, odd);
}

/// Across one tenure's FILL and acknowledged INVALIDATE, the requests on its shard's records are those of its
/// serving duties alone, and `Cell::page_key`, which keys the coverage page of a held INVALIDATE, sends none: it
/// reads the cell's seeded page count and returns the key the stored shard record gives. The request count the
/// untouched-shard rule samples stays equal across both. The test calls `Cell::page_key` itself; the acknowledged
/// INVALIDATE takes the branch of `Fleet::acknowledge` that keys no page.
#[test]
fn an_acknowledged_invalidate_takes_no_store_request_beyond_its_duties() {
    driven(
        &six(),
        (&ALL, &[]),
        |_| {},
        |mut fleet| {
            let fill = fleet.fleet.config.shape.objects + 1;
            let before = fleet.fleet.hosts_requests(2);
            let acknowledged = fleet.fleet.acknowledge(&mut fleet.live, 2, (fill, 1));
            assert!(acknowledged, "the FILL and the INVALIDATE");
            let page = fleet.fleet.cells[2].page_key(1);
            assert_eq!(fleet.fleet.hosts_requests(2), before);
            // The world's key reads the stored shard record through a store client, one counted request.
            assert_eq!(page, fleet.fleet.cells[2].world.page_key(1));
            assert_eq!(fleet.fleet.hosts_requests(2), before + 1);
        },
    );
}

/// A torn-down tenure's device is sampled once its drain ends. The tenure is torn down with a GET's medium read on
/// its device, which the drain executes: the tenure's last `Commands` step then counts every command the device
/// accepted, and a capture that passed its bound during the drain marks the shard's step list overflowed, which the
/// ownership verdict reads as truncated evidence.
#[test]
fn a_teardown_samples_the_tenures_device_after_its_drain() {
    use crate::oracle::ownership::Step;
    use crate::storage::Operation;
    driven(
        &six(),
        (&ALL, &[]),
        |_| {},
        |mut fleet| {
            let mut serving = fleet.live[2].take().expect("a live tenure");
            let _get = serving.send(object_key(1));
            let mut rounds = 0;
            while serving.control.outstanding() == 0 {
                assert!(rounds < 16, "the GET reads the medium");
                serving.step();
                rounds += 1;
            }
            let (control, tenure) = (serving.control.clone(), serving.tenure);
            let steps = std::rc::Rc::clone(&fleet.fleet.cells[2].world.steps);
            fleet.fleet.cells[2].close(&serving, true);
            assert!(
                !steps.borrow().overflowed,
                "no capture overflow before the drain"
            );
            // The capture holds its bound from here, so the drain's first captured event overflows it.
            control.set_capture_bound(control.capture().events.len());
            let listed = steps.borrow().list.len();
            assert!(serving.tear_down(TEARDOWN_ROUNDS), "the owner shut down");
            assert_eq!(control.outstanding(), 0, "the drain executed the read");
            let accepted = control.accepted(Operation::Read) + control.accepted(Operation::Write);
            let steps = steps.borrow();
            assert_eq!(steps.list.len(), listed + 1, "one step for the drain");
            let sampled = matches!(
                steps.list.last(),
                Some(Step::Commands { tenure: of, accepted: count, succeeded })
                    if *of == tenure && *count == accepted as u64 && succeeded.is_empty()
            );
            assert!(sampled, "{:?}", steps.list.last());
            assert!(steps.overflowed, "the drain's capture overflow");
        },
    );
}

/// A turn whose duties withdrew the tenure gives the ownership monitor the count at the withdrawal. The duties read
/// a record that names a later tenure and withdraw the authority after the turn's `Commands` step: that turn emits a
/// second `Commands` step and the tenure's `Withdrawn` step, and the teardown of its `Deposed` exit adds the drain's
/// `Commands` step, which the monitor judges against the count at the withdrawal. `Fleet::tear_down` lists the
/// tenure torn down and counts no withdrawal for it.
#[test]
fn a_turn_whose_duties_withdrew_the_tenure_notes_the_withdrawal_before_the_teardowns_drain() {
    use crate::oracle::ownership::Step;
    driven(
        &six(),
        (&ALL, &[]),
        |_| {},
        |mut fleet| {
            fleet.record_later_attempt(2);
            let mut serving = fleet.live[2].take().expect("a live tenure");
            let steps = std::rc::Rc::clone(&fleet.fleet.cells[2].world.steps);
            let (mut rounds, mut listed) = (0, 0);
            while serving.duty_exit.is_none() {
                assert!(rounds < 64, "the duties read the later tenure");
                listed = steps.borrow().list.len();
                let _ = super::actors::duties(&mut serving);
                rounds += 1;
            }
            assert_eq!(serving.duty_exit, Some(crate::host::Exit::Deposed));
            let tenure = serving.tenure;
            assert!(fleet.fleet.tear_down(2, serving), "the owner shut down");
            let shard = fleet.fleet.cells[2].placement.shard.get();
            assert_eq!(fleet.fleet.torn, [(shard, tenure, true)]);
            assert_eq!(
                fleet.fleet.cells[2].withdrawals, 0,
                "its exit judges a torn-down tenure"
            );
            let steps = steps.borrow();
            let [
                Step::Commands { tenure: polled, .. },
                Step::Commands {
                    tenure: sampled,
                    accepted: before,
                    ..
                },
                Step::Withdrawn { tenure: withdrawn },
                Step::Commands {
                    tenure: drained,
                    accepted: after,
                    ..
                },
            ] = &steps.list[listed..]
            else {
                panic!("{:?}", &steps.list[listed..]);
            };
            assert_eq!([*polled, *sampled, *withdrawn, *drained], [tenure; 4]);
            assert_eq!(before, after, "the drain accepted no command");
        },
    );
}

/// A published capture's `Captured` rows name the entries its checkpoint holds, whatever the tenure's resident set
/// is when the World observes the publication. s0's boot tenure runs its duties under a capture policy, with no
/// observation after its turns, until the shard record names a checkpoint the history holds no capture of. An
/// INVALIDATE's hold then removes object 1 from the resident set, and the observation that follows records the
/// checkpoint's members, object 1 among them, each on its own payload unit.
#[test]
fn a_published_capture_records_its_checkpoints_entries_after_the_resident_set_changed() {
    use super::super::{CUT, Event, hold};
    use crate::storage::warm_sim::row_unit;
    driven(
        &Config::host_loss(1),
        (&[0], &[]),
        |fleet| fleet.capturing = vec![0],
        |mut fleet| {
            let serving = fleet.live[0].as_mut().expect("a live tenure");
            let world = &mut fleet.fleet.cells[0].world;
            assert!(duties_opened(serving), "the duties' open");
            let unrecorded = |world: &super::super::World| {
                let named = world.checkpoint_named();
                named.filter(|named| world.cuts.iter().all(|(of, _)| of != named))
            };
            for _ in 0..4 * OPEN_ROUNDS {
                if unrecorded(world).is_some() {
                    break;
                }
                assert_eq!(actors::duties(serving), None);
            }
            let named = unrecorded(world).expect("the duties published a checkpoint");
            // The members before the hold, read from the tenure's slots and not through the checkpoint's decode.
            let members: Vec<(u8, (u32, u32))> = (serving.resident().into_iter().enumerate())
                .map(|(index, (fingerprint, unit))| {
                    let n = world.resident_object(serving, fingerprint).n;
                    (n, (row_unit(named, index), unit as u32))
                })
                .collect();
            let mut objects: Vec<u8> = members.iter().map(|&(n, _)| n).collect();
            objects.sort_unstable();
            assert_eq!(objects, [1, 2, 3, 4, 5, 6, 7, 8], "the seeded objects");
            assert_eq!(hold(serving, 1), Ok(true), "the hold removed object 1");
            let before = world.events.len();
            note_capture(world, serving);
            let cut = world.cut_named().expect("the record names a checkpoint");
            assert_ne!(cut, CUT, "the published checkpoint has a cut of its own");
            let captured: Vec<(u8, (u32, u32))> = (world.events[before..].iter())
                .filter_map(|event| match event {
                    Event::Captured {
                        n, units, cut: of, ..
                    } if *of == cut => Some((*n, *units)),
                    _ => None,
                })
                .collect();
            assert_eq!(captured, members, "checkpoint {named:?}");
        },
    );
}

/// A hold's attempt count is the volume's count since its host booted, completed recoveries included. s0's owner
/// recovers s0 at boot and serves; its next incarnation holds on a bump whose reply is unknown while the host stays
/// up. The hold then reads two attempts, the boot recovery and the refused restart, and a later incarnation that
/// holds reads three.
#[test]
fn a_hold_after_a_recovery_that_served_counts_both_attempts() {
    use crate::failover::report::RecoveryRefusal;
    use crate::failover::restart::{Check, Refused};
    use crate::storage::store::StoreError;
    driven(
        &Config::host_loss(1),
        (&[0], &[]),
        |_| {},
        |mut fleet| {
            let fleet = &mut fleet.fleet;
            let member = fleet.cells[0].holder;
            let target = crate::failover::retire::Target::of(&fleet.record_now(0));
            let refusal = RecoveryRefusal::from(&Refused {
                check: Check::Bump(StoreError::Unknown),
                flip: None,
                recovery: Some(target),
            });
            let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
            for attempts in [2, 3] {
                fleet.held(0, member, super::volumes::Held::of_restart(Some(refusal)));
                let (_, held, _) = fleet.holds(&live, member).next().expect("the hold");
                assert_eq!(held.status().recovery(0).attempts, Some(attempts));
            }
        },
    );
}
