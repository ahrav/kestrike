use crate::failover::attachments::{InstanceId, Mismatch, Peer, check};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{NotSole, Pair, Registrant, Report, ReservationType};
use crate::failover::evidence_tests::{bounds, entry, pair, report};
use crate::failover::flip::flipped;
use crate::failover::poll::{Holder, Reads, Verdict, fresh, owner_listing, poll, spare};
use crate::failover::records::{
    AttachmentEvent, CreationSource, ERA, EventKind, Host, Layout, LayoutRefusal, Lineage,
    Modification, Record, RecordedPair, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::retire::{Admitted, Retirement, Role, Stale, Target, Trigger};
use crate::storage::store::{Key, Refusal, StoreError};
use crate::storage::store_tests::{client, record, seeded, shard};

const FOREIGN: &str = "i-0fffffffffffffff0";

pub(crate) fn listed(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

pub(crate) fn owner() -> Holder {
    Holder {
        volume: record().active,
        host: record().owner,
        instance: InstanceId::new("i-0123456789abcdef0").unwrap(),
    }
}

fn standby() -> Holder {
    let (volume, host) = record().spare.unwrap();
    Holder {
        volume,
        host,
        instance: InstanceId::new("i-0aaaaaaaaaaaaaaa0").unwrap(),
    }
}

pub(crate) fn volume(state: VolumeState, host: Host) -> VolumeRecord {
    VolumeRecord {
        volume: record().active,
        state,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout: Layout {
            units: 64,
            slots: 3,
            slot_units: 3,
            entries: 64,
        },
        next: 1,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: vec![AttachmentEvent {
            seq: 0,
            kind: EventKind::Attach,
            host,
            era: ERA,
            instance: None,
        }],
    }
}

fn idle() -> VolumeRecord {
    VolumeRecord {
        volume: standby().volume,
        ..volume(VolumeState::Fresh, standby().host)
    }
}

pub(crate) fn serving() -> ShardRecord {
    ShardRecord {
        attempts: 1,
        ..record()
    }
}

fn retired(holder: &Holder, role: Role, target: Target, trigger: Trigger) -> Verdict {
    Verdict::Retire(Retirement::new(holder.volume, role, target, trigger).unwrap())
}

fn polled(
    holder: &Holder,
    target: Target,
    report: Result<(), NotSole>,
    reads: &Reads<'_>,
) -> Verdict {
    let entries = [entry(1, own_pair(), true)];
    let held = crate::failover::evidence_tests::report(&entries);
    poll(
        holder,
        target,
        own_pair(),
        report.map(|()| &held),
        reads,
        &wide(),
    )
}

pub(crate) fn with_events(record: &VolumeRecord, events: &[(EventKind, Host)]) -> VolumeRecord {
    let mut rebuilt = VolumeRecord {
        forced: false,
        next: 0,
        events: Vec::new(),
        ..record.clone()
    };
    for &(kind, host) in events {
        rebuilt.push(kind, host, ERA);
    }
    rebuilt
}

fn below_floor(record: &VolumeRecord) -> VolumeRecord {
    VolumeRecord {
        layout: Layout {
            units: 9,
            ..record.layout
        },
        ..record.clone()
    }
}

const BELOW_FLOOR: Trigger = Trigger::Layout(LayoutRefusal::BelowFloor {
    units: 9,
    floor: 10,
});

#[test]
fn listing_matches_only_the_desired_instance() {
    let own = InstanceId::new("i-0123456789abcdef0").unwrap();
    assert_eq!(
        InstanceId::new("i-01234567").map(|id| id.as_str().len()),
        Some(10)
    );
    for bad in [
        "i-0123",
        "i-012345678",
        "i-0123456789abcdef",
        "i-0123456g",
        "i-",
        "i-0123456789ABCDEF0",
        "vol-01234567",
        "i-0123456789abcdef01",
    ] {
        assert_eq!(InstanceId::new(bad), None, "{bad}");
    }
    assert_eq!(check(&listed(&[own.as_str()]), &own, &[]), Ok(()));
    for bad in ["I-0123456789ABCDEF0", "i-0123456789abcdef0 ", "garbage", ""] {
        let foreign = Err(Mismatch::Foreign(bad.to_owned()));
        assert_eq!(check(&listed(&[bad]), &own, &[]), foreign, "{bad:?}");
        assert_eq!(
            check(&listed(&[own.as_str(), bad]), &own, &[]),
            foreign,
            "{bad:?}"
        );
    }
    assert_eq!(
        check(&listed(&[own.as_str(), own.as_str(), FOREIGN]), &own, &[]),
        Err(Mismatch::Foreign(FOREIGN.to_owned())),
        "a foreign record names the first mismatch before the duplicate"
    );
    assert_eq!(
        check(&listed(&[own.as_str(), own.as_str()]), &own, &[]),
        Err(Mismatch::Duplicate)
    );
    assert_eq!(check(&[], &own, &[]), Err(Mismatch::Missing));
    assert!(!Mismatch::Missing.retires());
    assert!(Mismatch::Duplicate.retires());
}

#[test]
fn listing_matches_only_an_id_of_the_same_length() {
    let short = InstanceId::new("i-01234567").unwrap();
    let long = InstanceId::new("i-0123456789abcdef0").unwrap();
    assert_eq!(check(&listed(&["i-01234567"]), &short, &[]), Ok(()));
    assert_eq!(check(&listed(&["i-0123456789abcdef0"]), &long, &[]), Ok(()));
    for (desired, bad) in [
        (&short, "i-0123456789abcdef0"),
        (&short, "i-01234567 "),
        (&short, "i-0123456"),
        (&short, "i-01234568"),
        (&long, "i-01234567"),
        (&long, "i-0123456789abcdef"),
        (&long, "i-0123456789abcdef1"),
    ] {
        assert_eq!(
            check(&listed(&[bad]), desired, &[]),
            Err(Mismatch::Foreign(bad.to_owned())),
            "{bad:?} against {}",
            desired.as_str()
        );
    }
}

#[test]
fn partial_reads_retire_only_on_a_trigger_they_show() {
    let holder = owner();
    let shard = serving();
    let target = Target::of(&shard);
    let clean = volume(VolumeState::Active, holder.host);
    let own = listed(&[holder.instance.as_str()]);
    let foreign = listed(&[holder.instance.as_str(), FOREIGN]);
    let full = Reads {
        shard: Some(&shard),
        volume: Some(&clean),
        listed: Some(&own),
        peers: &[],
    };
    assert_eq!(polled(&holder, target, Ok(()), &full), Verdict::Continue);
    let other_volume = VolumeRecord {
        volume: VolumeId::new("vol-0c").unwrap(),
        ..clean.clone()
    };
    for reads in [
        Reads {
            listed: None,
            ..full
        },
        Reads {
            listed: Some(&[]),
            ..full
        },
        Reads {
            shard: None,
            ..full
        },
        Reads {
            volume: None,
            ..full
        },
        Reads {
            volume: Some(&other_volume),
            ..full
        },
    ] {
        assert_eq!(polled(&holder, target, Ok(()), &reads), Verdict::Unobserved);
    }
    assert_eq!(
        polled(&holder, target, Err(NotSole::Unreadable), &full),
        Verdict::Unobserved
    );
    let alone = Reads {
        listed: Some(&foreign),
        ..Reads::default()
    };
    assert_eq!(
        polled(&holder, target, Err(NotSole::Unreadable), &alone),
        retired(
            &holder,
            Role::Active,
            target,
            Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))
        )
    );
    let modified = VolumeRecord {
        modification: Some(Modification::InProgress),
        ..clean.clone()
    };
    let forced = with_events(
        &clean,
        &[
            (EventKind::Attach, holder.host),
            (EventKind::Force, holder.host),
        ],
    );
    let mut compacted = clean.clone();
    compacted.events[0].seq = 1;
    compacted.next = 2;
    for (with_compacted, with_clean) in [
        (
            Reads {
                volume: Some(&compacted),
                ..full
            },
            Reads {
                volume: Some(&clean),
                ..full
            },
        ),
        (
            Reads {
                volume: Some(&compacted),
                shard: None,
                ..full
            },
            Reads {
                volume: Some(&clean),
                shard: None,
                ..full
            },
        ),
    ] {
        assert_eq!(
            polled(&holder, target, Err(NotSole::Unreadable), &with_compacted),
            polled(&holder, target, Err(NotSole::Unreadable), &with_clean),
            "a compacted history is no trigger at E > 0: {with_compacted:?}"
        );
    }
    for (record, trigger) in [
        (&modified, Trigger::Modification),
        (&forced, Trigger::Events),
        (&below_floor(&clean), BELOW_FLOOR),
    ] {
        for reads in [
            Reads {
                volume: Some(record),
                ..full
            },
            Reads {
                volume: Some(record),
                listed: None,
                ..full
            },
            Reads {
                volume: Some(record),
                shard: None,
                ..full
            },
        ] {
            assert_eq!(
                polled(&holder, target, Err(NotSole::Unreadable), &reads),
                retired(&holder, Role::Active, target, trigger.clone()),
                "{reads:?}"
            );
        }
    }
    assert_eq!(
        polled(
            &holder,
            target,
            Err(NotSole::ForeignHolder),
            &Reads {
                listed: None,
                ..full
            }
        ),
        retired(
            &holder,
            Role::Active,
            target,
            Trigger::Report(NotSole::ForeignHolder)
        )
    );
    for state in [VolumeState::Retired, VolumeState::Deleted] {
        let gone = below_floor(&volume(state, holder.host));
        assert_eq!(
            polled(
                &holder,
                target,
                Ok(()),
                &Reads {
                    shard: None,
                    volume: Some(&gone),
                    listed: Some(&foreign),
                    peers: &[],
                }
            ),
            Verdict::Deposed,
            "a volume recorded {state:?} was flipped away from"
        );
    }
}

#[test]
fn poll_retires_on_every_report_refusal_and_listing_mismatch() {
    let holder = owner();
    let shard = serving();
    let target = Target::of(&shard);
    let clean = volume(VolumeState::Active, holder.host);
    let own = listed(&[holder.instance.as_str()]);
    let full = Reads {
        shard: Some(&shard),
        volume: Some(&clean),
        listed: Some(&own),
        peers: &[],
    };
    for refusal in [
        NotSole::Excess,
        NotSole::ReservationType,
        NotSole::DuplicateOwnRecord,
        NotSole::ForeignHolder,
        NotSole::ForeignRegistrant,
        NotSole::NotHolder,
    ] {
        assert_eq!(
            polled(&holder, target, Err(refusal), &full),
            retired(&holder, Role::Active, target, Trigger::Report(refusal))
        );
    }
    let duplicate = listed(&[holder.instance.as_str(), holder.instance.as_str()]);
    let foreign = listed(&[holder.instance.as_str(), FOREIGN]);
    let modified = VolumeRecord {
        modification: Some(Modification::InProgress),
        ..clean.clone()
    };
    assert_eq!(
        polled(
            &holder,
            target,
            Ok(()),
            &Reads {
                listed: Some(&duplicate),
                ..full
            }
        ),
        retired(
            &holder,
            Role::Active,
            target,
            Trigger::Attachment(Mismatch::Duplicate)
        )
    );
    assert_eq!(
        polled(
            &holder,
            target,
            Err(NotSole::ForeignHolder),
            &Reads {
                listed: Some(&foreign),
                volume: Some(&modified),
                ..full
            }
        ),
        retired(
            &holder,
            Role::Active,
            target,
            Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))
        )
    );
    assert_eq!(
        polled(
            &holder,
            target,
            Err(NotSole::ForeignHolder),
            &Reads {
                volume: Some(&modified),
                ..full
            }
        ),
        retired(
            &holder,
            Role::Active,
            target,
            Trigger::Report(NotSole::ForeignHolder)
        )
    );
}

/// The driver's read of the poll's listing check returns the result the poll judged: a clean listing reads `Ok`, each
/// listing that retires reads the mismatch of the poll's attachment trigger, a bound standby the volume record shows
/// unattached reads foreign, and reads without a listing read `None`.
#[test]
fn owner_listing_reads_the_check_the_poll_judged() {
    let holder = owner();
    let shard = serving();
    let target = Target::of(&shard);
    let clean = volume(VolumeState::Active, holder.host);
    let peer = Peer {
        host: standby().host,
        instance: standby().instance,
    };
    let peers = [peer];
    let own = listed(&[holder.instance.as_str()]);
    let full = Reads {
        shard: Some(&shard),
        volume: Some(&clean),
        listed: Some(&own),
        peers: &peers,
    };
    assert_eq!(owner_listing(&holder, &full), Some(Ok(())));
    assert_eq!(polled(&holder, target, Ok(()), &full), Verdict::Continue);
    let duplicate = listed(&[holder.instance.as_str(), holder.instance.as_str()]);
    let foreign = listed(&[holder.instance.as_str(), FOREIGN]);
    let unattached = listed(&[holder.instance.as_str(), peer.instance.as_str()]);
    for (listing, mismatch) in [
        (&duplicate, Mismatch::Duplicate),
        (&foreign, Mismatch::Foreign(FOREIGN.to_owned())),
        (
            &unattached,
            Mismatch::Foreign(peer.instance.as_str().to_owned()),
        ),
    ] {
        let reads = Reads {
            listed: Some(listing),
            ..full
        };
        assert_eq!(owner_listing(&holder, &reads), Some(Err(mismatch.clone())));
        assert_eq!(
            polled(&holder, target, Ok(()), &reads),
            retired(&holder, Role::Active, target, Trigger::Attachment(mismatch))
        );
    }
    let unlisted = Reads {
        listed: None,
        ..full
    };
    assert_eq!(owner_listing(&holder, &unlisted), None);
    assert_eq!(
        polled(&holder, target, Ok(()), &unlisted),
        Verdict::Unobserved
    );
}

#[test]
fn sole_tells_an_excess_count_from_a_count_that_disagrees_with_the_entries() {
    let own = pair(1, 1, 1);
    let bounds = bounds();
    let entries: Vec<_> = (0..5)
        .map(|at| entry(at, pair(at as u8 + 1, 1, 1), at == 0))
        .collect();
    let report = |regctl: u32, entries| Report {
        submitted_at: 0,
        rtype: ReservationType::ExclusiveAccess,
        regctl,
        entries,
    };
    assert!(entries.len() as u32 > bounds.registrant_max());
    assert_eq!(
        report(entries.len() as u32, &entries).sole(own, &bounds),
        Err(NotSole::Excess)
    );
    assert_eq!(
        report(2, &entries[..1]).sole(own, &bounds),
        Err(NotSole::Unreadable)
    );
    assert_eq!(
        report(9, &entries[..4]).sole(own, &bounds),
        Err(NotSole::Excess),
        "an over-bound header with its bounded prefix of entries shows a second registrant"
    );
    assert_eq!(report(1, &entries[..1]).sole(own, &bounds), Ok(()));
}

#[test]
fn volume_record_contradictions_retire_each_role() {
    let holder = owner();
    let shard = serving();
    let target = Target::of(&shard);
    let clean = volume(VolumeState::Active, holder.host);
    let own = listed(&[holder.instance.as_str()]);
    let full = Reads {
        shard: Some(&shard),
        volume: Some(&clean),
        listed: Some(&own),
        peers: &[],
    };
    let at_zero = Reads {
        shard: Some(&record()),
        ..full
    };
    let retired_record = volume(VolumeState::Retired, holder.host);
    assert_eq!(
        polled(
            &holder,
            target,
            Ok(()),
            &Reads {
                volume: Some(&retired_record),
                ..full
            }
        ),
        retired(&holder, Role::Active, target, Trigger::VolumeState)
    );
    assert_eq!(
        fresh(
            &holder,
            &Reads {
                volume: Some(&retired_record),
                ..at_zero
            }
        ),
        retired(
            &holder,
            Role::Active,
            Target::of(&record()),
            Trigger::VolumeState
        )
    );
    let retired_and_forced = with_events(
        &retired_record,
        &[
            (EventKind::Attach, holder.host),
            (EventKind::Force, holder.host),
        ],
    );
    let forced_and_modified = VolumeRecord {
        state: VolumeState::Active,
        modification: Some(Modification::InProgress),
        ..retired_and_forced.clone()
    };
    let modified_below_floor = VolumeRecord {
        modification: Some(Modification::InProgress),
        ..below_floor(&clean)
    };
    for (record, trigger) in [
        (&retired_and_forced, Trigger::VolumeState),
        (&forced_and_modified, Trigger::Events),
        (&modified_below_floor, Trigger::Modification),
    ] {
        assert_eq!(
            polled(
                &holder,
                target,
                Ok(()),
                &Reads {
                    volume: Some(record),
                    ..full
                }
            ),
            retired(&holder, Role::Active, target, trigger),
            "the state precedes the events, which precede a modification"
        );
    }
    let other = standby().host;
    // Each row's flag enrolls every live host, so only the `MAX_ATTACHED` bound retires the four-attach row.
    for (events, enroll_all) in [
        (&[][..], false),
        (&[(EventKind::Attach, other)], false),
        (&[(EventKind::Detach, holder.host)], false),
        (&[(EventKind::Force, holder.host)], false),
        (
            &[
                (EventKind::Attach, holder.host),
                (EventKind::Attach, other),
                (EventKind::Attach, Host::new(other.get() + 1).unwrap()),
                (EventKind::Attach, Host::new(other.get() + 2).unwrap()),
            ],
            true,
        ),
    ] {
        let mut listed_events = with_events(&clean, events);
        if enroll_all {
            listed_events.pairs = events
                .iter()
                .zip(1..)
                .map(|(&(_, host), at)| RecordedPair {
                    host,
                    pair: pair(at, 1, u32::from(at)),
                    attach: u32::from(at) - 1,
                })
                .collect();
        }
        assert_eq!(
            polled(
                &holder,
                target,
                Ok(()),
                &Reads {
                    volume: Some(&listed_events),
                    ..full
                }
            ),
            retired(&holder, Role::Active, target, Trigger::Events),
            "{events:?}"
        );
        assert_eq!(
            fresh(
                &holder,
                &Reads {
                    volume: Some(&listed_events),
                    ..at_zero
                }
            ),
            retired(
                &holder,
                Role::Active,
                Target::of(&record()),
                Trigger::Events
            ),
            "{events:?}"
        );
    }
    let two = with_events(
        &clean,
        &[(EventKind::Attach, holder.host), (EventKind::Attach, other)],
    );
    assert_eq!(
        fresh(
            &holder,
            &Reads {
                volume: Some(&two),
                ..at_zero
            }
        ),
        retired(
            &holder,
            Role::Active,
            Target::of(&record()),
            Trigger::Events
        ),
        "the fresh check admits the owner's one attach alone"
    );

    let standby = standby();
    let own_spare = listed(&[standby.instance.as_str()]);
    let spare_reads = Reads {
        shard: Some(&record()),
        volume: None,
        listed: Some(&own_spare),
        peers: &[],
    };
    let base = idle();
    let spare_retired = |trigger| retired(&standby, Role::Spare, Target::of(&record()), trigger);
    for (bad, trigger) in [
        (
            VolumeRecord {
                state: VolumeState::Active,
                ..base.clone()
            },
            Trigger::VolumeState,
        ),
        (
            VolumeRecord {
                state: VolumeState::Retired,
                ..base.clone()
            },
            Trigger::VolumeState,
        ),
        (
            with_events(&base, &[(EventKind::Attach, holder.host)]),
            Trigger::Events,
        ),
        (
            VolumeRecord {
                modification: Some(Modification::InProgress),
                ..base.clone()
            },
            Trigger::Modification,
        ),
        (below_floor(&base), BELOW_FLOOR),
    ] {
        assert_eq!(
            spare(
                &standby,
                &Reads {
                    volume: Some(&bad),
                    ..spare_reads
                }
            ),
            spare_retired(trigger),
            "{bad:?}"
        );
    }
}

#[test]
fn a_check_outside_its_role_or_tenure_requests_nothing() {
    let holder = owner();
    let shard = serving();
    let target = Target::of(&shard);
    let clean = volume(VolumeState::Active, holder.host);
    let foreign = listed(&[holder.instance.as_str(), FOREIGN]);
    let full = Reads {
        shard: Some(&shard),
        volume: Some(&clean),
        listed: Some(&foreign),
        peers: &[],
    };
    let bumped = ShardRecord {
        attempts: 2,
        ..shard
    };
    assert_eq!(
        polled(
            &holder,
            target,
            Err(NotSole::ForeignHolder),
            &Reads {
                shard: Some(&bumped),
                ..full
            }
        ),
        Verdict::Deposed,
        "a deposed owner requests nothing"
    );
    assert_eq!(
        fresh(&holder, &full),
        Verdict::Deposed,
        "the fresh path runs only at E = 0"
    );
    let other_owner = ShardRecord {
        owner: standby().host,
        ..record()
    };
    let other_active = ShardRecord {
        active: VolumeId::new("vol-0c").unwrap(),
        ..record()
    };
    let moved = flipped(&record()).unwrap();
    for shard in [&other_owner, &other_active, &moved] {
        assert_eq!(
            fresh(
                &holder,
                &Reads {
                    shard: Some(shard),
                    ..full
                }
            ),
            Verdict::Deposed,
            "{shard:?}"
        );
    }
    assert_eq!(
        spare(
            &holder,
            &Reads {
                shard: Some(&record()),
                ..full
            }
        ),
        Verdict::Deposed,
        "the active volume is no spare"
    );
    let standby = standby();
    let rehomed = ShardRecord {
        spare: Some((standby.volume, holder.host)),
        ..record()
    };
    let replaced = ShardRecord {
        spare: Some((VolumeId::new("vol-0c").unwrap(), standby.host)),
        ..record()
    };
    let dropped = ShardRecord {
        spare: None,
        ..record()
    };
    for shard in [&rehomed, &replaced, &dropped] {
        assert_eq!(
            spare(
                &standby,
                &Reads {
                    shard: Some(shard),
                    volume: Some(&idle()),
                    listed: Some(&foreign),
                    peers: &[],
                }
            ),
            Verdict::Deposed,
            "{shard:?}"
        );
    }
}

#[test]
fn fresh_continues_only_at_attempt_zero_on_a_full_observation() {
    let holder = owner();
    let clean = volume(VolumeState::Active, holder.host);
    let own = listed(&[holder.instance.as_str()]);
    let foreign = listed(&[holder.instance.as_str(), FOREIGN]);
    let at_zero = Reads {
        shard: Some(&record()),
        volume: Some(&clean),
        listed: Some(&own),
        peers: &[],
    };
    assert_eq!(fresh(&holder, &at_zero), Verdict::Continue);
    for reads in [
        Reads {
            volume: None,
            ..at_zero
        },
        Reads {
            listed: None,
            ..at_zero
        },
        Reads {
            listed: Some(&[]),
            ..at_zero
        },
        Reads {
            shard: None,
            ..at_zero
        },
        Reads {
            shard: None,
            listed: Some(&foreign),
            ..at_zero
        },
    ] {
        assert_eq!(fresh(&holder, &reads), Verdict::Unobserved, "{reads:?}");
    }
    assert_eq!(
        fresh(
            &holder,
            &Reads {
                listed: Some(&foreign),
                ..at_zero
            }
        ),
        retired(
            &holder,
            Role::Active,
            Target::of(&record()),
            Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))
        )
    );
}

/// The spare and fresh checks admit the holder's one record alone. An instance that another host's attach or ended
/// entry binds in the volume record is a peer only of the owner's poll, so a listing that shows it retires either
/// check on `Attachment(Foreign)`, the listing's trigger, before the volume record's events are judged.
#[test]
fn the_spare_and_fresh_checks_admit_no_instance_an_entry_binds() {
    let other = Host::new(owner().host.get() + 100).unwrap();
    let bind_other = |record: &VolumeRecord, kind: EventKind| {
        let mut next = record.clone();
        next.push(EventKind::Attach, other, ERA).unwrap();
        let entry = next.events.last_mut().unwrap();
        entry.instance = Some(InstanceId::new(FOREIGN).unwrap());
        entry.kind = kind;
        assert_eq!(
            <VolumeRecord as Record>::decode(&Record::encode(&next)),
            Ok(next.clone())
        );
        next
    };
    for kind in [EventKind::Attach, EventKind::Ended] {
        let standby = standby();
        let idle = bind_other(&idle(), kind);
        let listing = listed(&[standby.instance.as_str(), FOREIGN]);
        assert_eq!(
            spare(
                &standby,
                &Reads {
                    shard: Some(&record()),
                    volume: Some(&idle),
                    listed: Some(&listing),
                    peers: &[],
                }
            ),
            retired(
                &standby,
                Role::Spare,
                Target::of(&record()),
                Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))
            ),
            "{kind:?}: the spare check"
        );
        let holder = owner();
        let active = bind_other(&volume(VolumeState::Active, holder.host), kind);
        let listing = listed(&[holder.instance.as_str(), FOREIGN]);
        assert_eq!(
            fresh(
                &holder,
                &Reads {
                    shard: Some(&record()),
                    volume: Some(&active),
                    listed: Some(&listing),
                    peers: &[],
                }
            ),
            retired(
                &holder,
                Role::Active,
                Target::of(&record()),
                Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))
            ),
            "{kind:?}: the fresh check"
        );
        assert_eq!(
            unbound_verdict(&active, &[OWN, FOREIGN], &registered(&[(own_pair(), true)])),
            Verdict::Continue,
            "{kind:?}: the owner's poll admits the entry's instance"
        );
    }
}

#[test]
fn spare_check_retires_only_on_a_trigger() {
    let standby = standby();
    let own = listed(&[standby.instance.as_str()]);
    let foreign = listed(&[standby.instance.as_str(), FOREIGN]);
    let idle = idle();
    let reads = Reads {
        shard: Some(&record()),
        volume: Some(&idle),
        listed: Some(&own),
        peers: &[],
    };
    assert_eq!(spare(&standby, &reads), Verdict::Continue);
    let other_fresh = VolumeRecord {
        volume: VolumeId::new("vol-0c").unwrap(),
        ..idle.clone()
    };
    for unobserved in [
        Reads {
            listed: Some(&[]),
            ..reads
        },
        Reads {
            shard: None,
            ..reads
        },
        Reads {
            shard: None,
            listed: Some(&foreign),
            ..reads
        },
        Reads {
            volume: Some(&other_fresh),
            ..reads
        },
    ] {
        assert_eq!(
            spare(&standby, &unobserved),
            Verdict::Unobserved,
            "{unobserved:?}"
        );
    }
    assert_eq!(
        spare(
            &standby,
            &Reads {
                listed: Some(&foreign),
                ..reads
            }
        ),
        retired(
            &standby,
            Role::Spare,
            Target::of(&record()),
            Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned()))
        )
    );
}

#[test]
fn retirement_requires_a_trigger_that_shows_evidence() {
    let target = Target::of(&record());
    let volume = record().active;
    for trigger in [
        Trigger::Attachment(Mismatch::Missing),
        Trigger::Report(NotSole::Unreadable),
    ] {
        assert_eq!(
            Retirement::new(volume, Role::Active, target, trigger.clone()),
            None,
            "{trigger:?}"
        );
    }
    let request = Retirement::new(volume, Role::Active, target, Trigger::Events).unwrap();
    assert_eq!(request.trigger(), &Trigger::Events);
}

#[test]
fn stale_retirement_refused() {
    let read = record();
    let (spare, _) = read.spare.unwrap();
    let request = |volume: VolumeId, role, target| {
        Retirement::new(
            volume,
            role,
            target,
            Trigger::Attachment(Mismatch::Duplicate),
        )
        .unwrap()
    };
    let target = Target::of(&read);
    assert_eq!(
        request(read.active, Role::Active, target).admit(&read),
        Ok(Admitted::Flip)
    );
    assert_eq!(
        request(spare, Role::Spare, target).admit(&read),
        Ok(Admitted::DropSpare)
    );
    let bumped = ShardRecord {
        attempts: 1,
        ..read
    };
    assert_eq!(
        request(read.active, Role::Active, target).admit(&bumped),
        Err(Stale::Target)
    );
    let flipped = flipped(&read).unwrap();
    assert_eq!(
        request(spare, Role::Spare, Target::of(&flipped)).admit(&flipped),
        Err(Stale::Volume),
        "a spare request never flips the volume the spare became"
    );
    assert_eq!(
        request(read.active, Role::Spare, target).admit(&read),
        Err(Stale::Volume)
    );
    let other = VolumeId::new("vol-0c").unwrap();
    assert_eq!(
        request(other, Role::Active, target).admit(&read),
        Err(Stale::Volume)
    );
    assert_eq!(
        request(other, Role::Active, target).admit(&bumped),
        Err(Stale::Target),
        "a stale target precedes a stale volume"
    );
}

#[test]
fn retirement_write_conditions_on_the_admitting_read() {
    let store = seeded();
    let mut reconciler = client(&store);
    let mut owner = client(&store);
    let key = Key::Shard(shard());
    let before = reconciler.read::<ShardRecord>(key).unwrap();
    let request = Retirement::new(
        before.value().active,
        Role::Active,
        Target::of(before.value()),
        Trigger::Events,
    )
    .unwrap();
    let (spare, _) = before.value().spare.unwrap();
    let removal = Retirement::new(
        spare,
        Role::Spare,
        Target::of(before.value()),
        Trigger::Events,
    )
    .unwrap();
    let current = owner.read::<ShardRecord>(key).unwrap();
    owner.bump(&current).unwrap();
    assert_eq!(
        reconciler.retire(&before, &removal),
        Err(StoreError::Refused(Refusal::Condition)),
        "a write on the read before the bump refuses on its condition"
    );
    let after = reconciler.read::<ShardRecord>(key).unwrap();
    for stale in [&request, &removal] {
        assert_eq!(
            reconciler.retire(&after, stale),
            Err(StoreError::Stale(Stale::Target)),
            "the current read refuses the request computed before the bump"
        );
    }
    assert_eq!(reconciler.read::<ShardRecord>(key).unwrap(), after);

    let drop = Retirement::new(
        spare,
        Role::Spare,
        Target::of(after.value()),
        Trigger::Events,
    )
    .unwrap();
    assert!(reconciler.retire(&after, &drop).is_ok());
    let dropped = reconciler.read::<ShardRecord>(key).unwrap();
    assert_eq!(
        *dropped.value(),
        ShardRecord {
            spare: None,
            ..*after.value()
        }
    );
    assert!(
        matches!(reconciler.flip(&dropped), Err(StoreError::Flip(_))),
        "a flip needs a spare"
    );
}

#[test]
fn the_client_refuses_an_admitted_active_retirement_and_writes_nothing() {
    let store = seeded();
    let mut reconciler = client(&store);
    let key = Key::Shard(shard());
    let read = reconciler.read::<ShardRecord>(key).unwrap();
    let request = Retirement::new(
        read.value().active,
        Role::Active,
        Target::of(read.value()),
        Trigger::Events,
    )
    .unwrap();
    assert!(read.value().spare.is_some(), "premise: a flip has a spare");
    assert_eq!(
        request.admit(read.value()),
        Ok(Admitted::Flip),
        "premise: the read admits the request as a flip"
    );
    let commits = store.0.borrow().commit_count(&key);
    assert_eq!(
        reconciler.retire(&read, &request).map(drop),
        Err(StoreError::Stale(Stale::Volume)),
        "the client's retirement write serves no active request"
    );
    assert_eq!(store.0.borrow().commit_count(&key), commits);
    assert!(store.0.borrow().flips.is_empty());
    assert_eq!(reconciler.read::<ShardRecord>(key).unwrap(), read);
}

const OWN: &str = "i-0123456789abcdef0";
const STANDBY: &str = "i-0bbbbbbbbbbbbbbb0";
const SECOND: &str = "i-0ccccccccccccccc0";

pub(crate) fn wide() -> Bounds {
    Bounds::new(8, 2, 100, 10, 20, 5).unwrap()
}

pub(crate) fn own_pair() -> Pair {
    pair(1, 1, 1)
}

pub(crate) fn own_entry() -> Registrant {
    entry(1, own_pair(), true)
}

pub(crate) fn report_of(entries: &[Registrant]) -> Report<'_> {
    report(entries)
}

pub(crate) fn standby_pair() -> Pair {
    pair(2, 1, 2)
}

fn second_pair() -> Pair {
    pair(3, 1, 3)
}

fn unknown_pair() -> Pair {
    pair(9, 1, 9)
}

fn standby_host() -> Host {
    Host::new(record().owner.get() + 100).unwrap()
}

fn second_standby() -> Host {
    Host::new(record().owner.get() + 101).unwrap()
}

fn peers() -> [Peer; 2] {
    [
        Peer {
            host: standby_host(),
            instance: InstanceId::new(STANDBY).unwrap(),
        },
        Peer {
            host: second_standby(),
            instance: InstanceId::new(SECOND).unwrap(),
        },
    ]
}

pub(crate) fn enrolled(record: &VolumeRecord, pairs: &[(Host, Pair, u32)]) -> VolumeRecord {
    VolumeRecord {
        pairs: pairs
            .iter()
            .map(|&(host, pair, attach)| RecordedPair { host, pair, attach })
            .collect(),
        ..record.clone()
    }
}

/// The owner's volume with a standby attached after it and both pairs enrolled.
fn with_standby() -> VolumeRecord {
    let host = owner().host;
    enrolled(
        &with_events(
            &volume(VolumeState::Active, host),
            &[
                (EventKind::Attach, host),
                (EventKind::Attach, standby_host()),
            ],
        ),
        &[(host, own_pair(), 0), (standby_host(), standby_pair(), 1)],
    )
}

fn registered(pairs: &[(Pair, bool)]) -> Vec<Registrant> {
    pairs
        .iter()
        .enumerate()
        .map(|(at, &(pair, holder))| entry(at as u16 + 1, pair, holder))
        .collect()
}

/// The owner's verdict over `volume`, `listing` and a Report of `entries`, with every peer bound.
fn owner_verdict(
    volume: Option<&VolumeRecord>,
    listing: &[&str],
    entries: &[Registrant],
) -> Verdict {
    owner_verdict_under(&serving(), volume, listing, entries, &wide())
}

fn owner_verdict_under(
    shard: &ShardRecord,
    volume: Option<&VolumeRecord>,
    listing: &[&str],
    entries: &[Registrant],
    bounds: &Bounds,
) -> Verdict {
    owner_verdict_of(shard, volume, listing, &report(entries), bounds)
}

fn owner_verdict_of(
    shard: &ShardRecord,
    volume: Option<&VolumeRecord>,
    listing: &[&str],
    report: &Report<'_>,
    bounds: &Bounds,
) -> Verdict {
    let listing = listed(listing);
    let peers = peers();
    let reads = Reads {
        shard: Some(shard),
        volume,
        listed: Some(&listing),
        peers: &peers,
    };
    poll(
        &owner(),
        Target::of(&serving()),
        own_pair(),
        Ok(report),
        &reads,
        bounds,
    )
}

fn owner_retired(trigger: Trigger) -> Verdict {
    retired(&owner(), Role::Active, Target::of(&serving()), trigger)
}

/// The owner keeps serving over its enrolled standby's attach event, listing and registration.
#[test]
fn an_enrolled_standby_keeps_the_owner_serving() {
    let volume = with_standby();
    let entries = registered(&[(own_pair(), true), (standby_pair(), false)]);
    assert_eq!(
        report(&entries).registrants(own_pair(), Some(&volume.recorded_pairs()), &wide()),
        Ok(())
    );
    assert_eq!(
        owner_verdict(Some(&volume), &[OWN, STANDBY], &entries),
        Verdict::Continue
    );
}

/// A missing own listing is no observation, and a duplicated own listing, two records of the own host ID and a
/// detached owner each retire. An owner whose entry is ended withdraws with no request, and an earlier entry of the
/// owner's host or a numbering gap beside its live attach changes no verdict.
#[test]
fn missing_and_duplicate_own_records_refuse() {
    let own = owner().instance;
    let volume = with_standby();
    let serving_report = registered(&[(own_pair(), true), (standby_pair(), false)]);
    assert_eq!(
        owner_verdict(Some(&volume), &[STANDBY], &serving_report),
        Verdict::Unobserved
    );
    assert_eq!(
        owner_verdict(
            Some(&volume),
            &[own.as_str(), own.as_str(), STANDBY],
            &serving_report
        ),
        owner_retired(Trigger::Attachment(Mismatch::Duplicate))
    );
    let both = [own.as_str(), STANDBY];
    let alias = Pair {
        key: unknown_pair().key,
        ..own_pair()
    };
    assert_eq!(
        owner_verdict(
            Some(&volume),
            &both,
            &registered(&[(own_pair(), true), (alias, false)])
        ),
        owner_retired(Trigger::Report(NotSole::DuplicateOwnRecord))
    );
    let detached = with_events(
        &volume,
        &[
            (EventKind::Attach, owner().host),
            (EventKind::Attach, standby_host()),
            (EventKind::Detach, owner().host),
        ],
    );
    assert_eq!(
        owner_verdict(Some(&detached), &both, &serving_report),
        owner_retired(Trigger::Events)
    );
    let reattached = with_events(
        &volume,
        &[
            (EventKind::Attach, owner().host),
            (EventKind::Attach, standby_host()),
            (EventKind::Detach, owner().host),
            (EventKind::Attach, owner().host),
        ],
    );
    assert_eq!(
        owner_verdict(Some(&reattached), &both, &serving_report),
        Verdict::Withdraw,
        "the owner's pair pins its host's detached attach beside a later live attach"
    );
    let mut enrolled_again = reattached.clone();
    let live = enrolled_again.live(owner().host).unwrap();
    for recorded in &mut enrolled_again.pairs {
        if recorded.host == owner().host {
            recorded.attach = live;
        }
    }
    assert_eq!(
        owner_verdict(Some(&enrolled_again), &both, &serving_report),
        Verdict::Continue,
        "an earlier entry of the owner's host beside its live attach, which pins the owner's pair"
    );
    let mut ended = volume.clone();
    ended.events[0].kind = EventKind::Ended;
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&ended)),
        Ok(ended.clone())
    );
    assert_eq!(
        owner_verdict(Some(&ended), &both, &serving_report),
        Verdict::Withdraw,
        "an ended entry of the owner's host withdraws with no request"
    );
    let gap = VolumeRecord {
        next: volume.next + 1,
        ..volume.clone()
    };
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&gap)),
        Ok(gap.clone())
    );
    assert_eq!(
        owner_verdict(Some(&gap), &both, &serving_report),
        Verdict::Continue,
        "a numbering gap behind event 0"
    );
    assert_eq!(
        owner_verdict(Some(&volume), &both, &serving_report),
        Verdict::Continue
    );
}

/// When the volume record is unread, the extra registrant could be an enrolled standby, so `owner_verdict` returns
/// `Verdict::Unobserved`, and a foreign holder could be a recorded attachment, so the owner withdraws with no request
/// until a poll that reads the volume record decides.
#[test]
fn an_unknown_registrant_retires_and_an_unread_record_keeps_conclusive_refusals() {
    let volume = with_standby();
    let both = [OWN, STANDBY];
    let registrant = registered(&[(own_pair(), true), (unknown_pair(), false)]);
    let holder = registered(&[(own_pair(), false), (unknown_pair(), true)]);
    assert_eq!(
        owner_verdict(Some(&volume), &both, &registrant),
        owner_retired(Trigger::Report(NotSole::ForeignRegistrant))
    );
    assert_eq!(
        owner_verdict(Some(&volume), &both, &holder),
        owner_retired(Trigger::Report(NotSole::ForeignHolder))
    );
    assert_eq!(
        owner_verdict(None, &[OWN], &registrant),
        Verdict::Unobserved
    );
    assert_eq!(owner_verdict(None, &[OWN], &holder), Verdict::Withdraw);
    let alias = Pair {
        key: unknown_pair().key,
        ..own_pair()
    };
    assert_eq!(
        owner_verdict(
            None,
            &[OWN],
            &registered(&[(own_pair(), true), (alias, false)])
        ),
        owner_retired(Trigger::Report(NotSole::DuplicateOwnRecord)),
        "a second own record is a conclusive refusal under an unread volume record"
    );
    let lone = registered(&[(alias, true)]);
    let beside = registered(&[(alias, false), (unknown_pair(), true)]);
    for (entries, row) in [
        (&lone, "a lone holding alias"),
        (&beside, "a non-holding alias beside a foreign holder"),
    ] {
        assert_eq!(
            owner_verdict(None, &[OWN], entries),
            owner_retired(Trigger::Report(NotSole::ForeignHolder)),
            "{row}: the own host ID under another key retires under an unread volume record"
        );
    }
}

/// A listing passes when it holds the own instance once and each admitted peer at most once, in any order; a
/// foreign entry names the first mismatch, then a duplicate, then a missing own record.
#[test]
fn listing_admits_each_admitted_instance_once() {
    let own = owner().instance;
    let peer = InstanceId::new(STANDBY).unwrap();
    let admitted = [peer];
    for listing in [
        &[own.as_str()][..],
        &[own.as_str(), STANDBY],
        &[STANDBY, own.as_str()],
    ] {
        assert_eq!(
            check(&listed(listing), &own, &admitted),
            Ok(()),
            "{listing:?}"
        );
    }
    for (listing, mismatch) in [
        (
            &[own.as_str(), own.as_str(), FOREIGN][..],
            Mismatch::Foreign(FOREIGN.to_owned()),
        ),
        (&[FOREIGN], Mismatch::Foreign(FOREIGN.to_owned())),
        (&[own.as_str(), STANDBY, STANDBY], Mismatch::Duplicate),
        (&[STANDBY, own.as_str(), own.as_str()], Mismatch::Duplicate),
        (&[STANDBY, own.as_str(), STANDBY], Mismatch::Duplicate),
        (&[own.as_str(), STANDBY, own.as_str()], Mismatch::Duplicate),
        (
            &[STANDBY, own.as_str(), STANDBY, FOREIGN],
            Mismatch::Foreign(FOREIGN.to_owned()),
        ),
        (&[STANDBY], Mismatch::Missing),
    ] {
        assert_eq!(
            check(&listed(listing), &own, &admitted),
            Err(mismatch),
            "{listing:?}"
        );
    }
    assert_eq!(
        check(&listed(&[own.as_str(), STANDBY]), &own, &[]),
        Err(Mismatch::Foreign(STANDBY.to_owned())),
        "an instance outside the admitted peers is foreign"
    );
}

#[test]
fn listing_compares_every_byte_of_either_length() {
    for (own, peer) in [("i-01234567", "i-89abcdef"), (OWN, STANDBY)] {
        let (own_id, peer_id) = (
            InstanceId::new(own).unwrap(),
            InstanceId::new(peer).unwrap(),
        );
        assert_eq!(check(&listed(&[own, peer]), &own_id, &[peer_id]), Ok(()));
        for name in [own, peer] {
            for at in 0..name.len() {
                let mut bytes = name.as_bytes().to_vec();
                bytes[at] = if bytes[at] == b'f' { b'e' } else { b'f' };
                let changed = String::from_utf8(bytes).unwrap();
                assert_eq!(
                    check(core::slice::from_ref(&changed), &own_id, &[peer_id]),
                    Err(Mismatch::Foreign(changed.clone())),
                    "{changed} against {name}"
                );
            }
        }
    }
}

#[test]
fn the_owner_poll_judges_its_reads_without_allocating() {
    let holder = owner();
    let shard = serving();
    let volume = with_standby();
    let listing = listed(&[OWN, STANDBY]);
    let peers = peers();
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(&volume),
        listed: Some(&listing),
        peers: &peers,
    };
    let serving_entries = registered(&[(own_pair(), true), (standby_pair(), false)]);
    let unknown_entries = registered(&[(own_pair(), true), (unknown_pair(), false)]);
    let (clean, unknown) = (report(&serving_entries), report(&unknown_entries));
    for (what, judged, expected) in [
        ("clean", Ok(&clean), Verdict::Continue),
        (
            "unknown registrant",
            Ok(&unknown),
            owner_retired(Trigger::Report(NotSole::ForeignRegistrant)),
        ),
        (
            "refused parse",
            Err(NotSole::Excess),
            owner_retired(Trigger::Report(NotSole::Excess)),
        ),
    ] {
        let allocations = crate::instrument::allocations();
        let verdict = poll(
            &holder,
            Target::of(&shard),
            own_pair(),
            judged,
            &reads,
            &wide(),
        );
        assert_eq!(crate::instrument::allocations(), allocations, "{what}");
        assert_eq!(verdict, expected, "{what}");
    }
}

/// A listing outside the admitted set retires: a bound peer whose host never attached, an unbound instance, and any
/// peer at the spare and fresh checks, which admit the holder's own attachment alone. A bound peer under an unread
/// volume record is no observation.
#[test]
fn a_listing_outside_the_admitted_set_retires_the_owners_volume() {
    let own = owner().instance;
    let entries = registered(&[(own_pair(), true)]);
    let alone = enrolled(
        &volume(VolumeState::Active, owner().host),
        &[(owner().host, own_pair(), 0)],
    );
    let both = [own.as_str(), STANDBY];
    assert_eq!(
        owner_verdict(Some(&alone), &both, &entries),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned())))
    );
    assert_eq!(
        owner_verdict(Some(&with_standby()), &[own.as_str(), FOREIGN], &entries),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned())))
    );
    assert_eq!(owner_verdict(None, &both, &entries), Verdict::Unobserved);

    let peers = peers();
    let standby = standby();
    let spare_listing = listed(&[standby.instance.as_str(), STANDBY]);
    let idle = idle();
    assert_eq!(
        spare(
            &standby,
            &Reads {
                shard: Some(&record()),
                volume: Some(&idle),
                listed: Some(&spare_listing),
                peers: &peers,
            }
        ),
        retired(
            &standby,
            Role::Spare,
            Target::of(&record()),
            Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned()))
        )
    );
    let fresh_listing = listed(&both);
    let clean = volume(VolumeState::Active, owner().host);
    assert_eq!(
        fresh(
            &owner(),
            &Reads {
                shard: Some(&record()),
                volume: Some(&clean),
                listed: Some(&fresh_listing),
                peers: &peers,
            }
        ),
        retired(
            &owner(),
            Role::Active,
            Target::of(&record()),
            Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned()))
        )
    );
}

/// A standby detached or force detached stays listed and registered under its recorded pair, and the owner keeps
/// serving; an unrecorded pair from the same host retires.
#[test]
fn a_detached_standby_stays_admitted_until_its_pair_leaves() {
    let both = [OWN, STANDBY];
    for kind in [EventKind::Detach, EventKind::Force] {
        let detached = with_marked_standby(kind);
        assert_eq!(
            owner_verdict(
                Some(&detached),
                &both,
                &registered(&[(own_pair(), true), (standby_pair(), false)])
            ),
            Verdict::Continue,
            "{kind:?}"
        );
        let rekeyed = Pair {
            key: unknown_pair().key,
            ..standby_pair()
        };
        assert_eq!(
            owner_verdict(
                Some(&detached),
                &both,
                &registered(&[(own_pair(), true), (rekeyed, false)])
            ),
            owner_retired(Trigger::Report(NotSole::ForeignRegistrant)),
            "{kind:?}"
        );
    }
}

/// Three live attachments across a planned handoff keep the owner serving; a fourth live attach or a fourth, unbound
/// listed instance retires.
#[test]
fn a_transient_third_attachment_keeps_the_owner_serving() {
    let host = owner().host;
    let events = [
        (EventKind::Attach, host),
        (EventKind::Attach, standby_host()),
        (EventKind::Attach, second_standby()),
    ];
    let three = enrolled(
        &with_events(&volume(VolumeState::Active, host), &events),
        &[
            (host, own_pair(), 0),
            (standby_host(), standby_pair(), 1),
            (second_standby(), second_pair(), 2),
        ],
    );
    let entries = registered(&[
        (own_pair(), true),
        (standby_pair(), false),
        (second_pair(), false),
    ]);
    let listing = [OWN, STANDBY, SECOND];
    assert_eq!(
        owner_verdict(Some(&three), &listing, &entries),
        Verdict::Continue
    );
    let mut crowded = events.to_vec();
    crowded.push((
        EventKind::Attach,
        Host::new(second_standby().get() + 1).unwrap(),
    ));
    let mut four = VolumeRecord {
        pairs: three.pairs.clone(),
        ..with_events(&three, &crowded)
    };
    four.pairs.push(RecordedPair {
        host: Host::new(second_standby().get() + 1).unwrap(),
        pair: pair(4, 1, 4),
        attach: 3,
    });
    assert_eq!(
        owner_verdict(Some(&four), &listing, &entries),
        owner_retired(Trigger::Events),
        "a fourth enrolled live attach exceeds MAX_ATTACHED"
    );
    assert_eq!(
        owner_verdict(Some(&three), &[OWN, STANDBY, SECOND, FOREIGN], &entries),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned())))
    );
}

/// A recorded holder, of a live attach or an ended one, beside only recorded registrants, withdraws the owner with no
/// request while the shard record holds the owner's target, under a clean or an unread listing, as does any holder
/// under an unread volume record. The other sources still judge: a foreign listing and each volume-record trigger
/// retire. An unrecorded holder and an unrecorded registrant retire with the alarm, and the poll is deposed once the
/// shard record holds any later tenure, whichever host it names.
#[test]
fn a_recorded_holder_holds_while_the_shard_record_holds_the_owners_target() {
    let entries = registered(&[(own_pair(), false), (standby_pair(), true)]);
    assert_eq!(
        owner_verdict(Some(&with_standby()), &[OWN, STANDBY], &entries),
        Verdict::Withdraw
    );
    let unrecorded = registered(&[(own_pair(), false), (unknown_pair(), true)]);
    assert_eq!(
        owner_verdict(Some(&with_standby()), &[OWN, STANDBY], &unrecorded),
        owner_retired(Trigger::Report(NotSole::ForeignHolder)),
        "an unrecorded holder retires with the alarm"
    );
    assert_eq!(
        owner_verdict(None, &[OWN, STANDBY], &entries),
        Verdict::Withdraw,
        "without the volume record the holder may be recorded: withdraw, and a later poll decides"
    );
    let modified = VolumeRecord {
        modification: Some(Modification::InProgress),
        ..with_standby()
    };
    let below = below_floor(&with_standby());
    let retired_volume = VolumeRecord {
        state: VolumeState::Retired,
        ..with_standby()
    };
    let mut detached_owner = with_standby();
    detached_owner.push(EventKind::Detach, owner().host, ERA);
    for (volume, trigger) in [
        (&modified, Trigger::Modification),
        (&below, BELOW_FLOOR),
        (&retired_volume, Trigger::VolumeState),
        (&detached_owner, Trigger::Events),
    ] {
        assert_eq!(
            owner_verdict(Some(volume), &[OWN, STANDBY], &entries),
            owner_retired(trigger),
            "the hold leaves the volume-record triggers in force"
        );
    }
    let with_stranger = registered(&[
        (own_pair(), false),
        (standby_pair(), true),
        (unknown_pair(), false),
    ]);
    assert_eq!(
        owner_verdict(Some(&with_standby()), &[OWN, STANDBY], &with_stranger),
        owner_retired(Trigger::Report(NotSole::ForeignHolder)),
        "a recorded holder beside an unrecorded registrant retires"
    );
    assert_eq!(
        owner_verdict(Some(&with_standby()), &[OWN, FOREIGN], &entries),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned())))
    );
    // The standby detached after enrolling: its pair stays recorded and its attach is ended, and the recorded holder
    // still withdraws the owner with no request.
    let mut detached = with_standby();
    detached.push(EventKind::Detach, standby_host(), ERA);
    assert_eq!(
        owner_verdict(Some(&detached), &[OWN], &entries),
        Verdict::Withdraw,
        "a holder recorded for an ended attach withdraws"
    );
    // Without the listing the recorded holder still withdraws the owner; a later poll's listing decides between
    // hold and retirement.
    let volume = with_standby();
    let peers = peers();
    let report = report(&entries);
    let reads = Reads {
        shard: Some(&serving()),
        volume: Some(&volume),
        listed: None,
        peers: &peers,
    };
    assert_eq!(
        poll(
            &owner(),
            Target::of(&serving()),
            own_pair(),
            Ok(&report),
            &reads,
            &wide()
        ),
        Verdict::Withdraw,
        "a recorded holder under an unread listing withdraws"
    );
    let successor = ShardRecord {
        owner: standby_host(),
        attempts: 2,
        ..serving()
    };
    assert_eq!(
        owner_verdict_under(
            &successor,
            Some(&with_standby()),
            &[OWN, FOREIGN],
            &entries,
            &wide()
        ),
        Verdict::Deposed
    );
    let third = ShardRecord {
        owner: Host::new(second_standby().get() + 7).unwrap(),
        attempts: 2,
        ..serving()
    };
    assert_eq!(
        owner_verdict_under(&third, Some(&with_standby()), &[OWN], &entries, &wide()),
        Verdict::Deposed,
        "a later tenure of a third host"
    );
}

/// NO-HOLDER-HOLD: a Report with nobody holding, with no reservation or no holding entry, beside the own pair and
/// recorded registrants withdraws the owner with no request, since a registration that ended without a preempt shows
/// no volume loss. An unrecorded registrant and a second own record keep the Report's trigger and retire.
/// An unread volume record defers the decision on a Report with nobody holding and one own record under the own key
/// until a poll reads the record.
#[test]
fn nobody_holding_beside_recorded_registrants_withdraws_with_no_request() {
    let verdict =
        |volume: Option<&VolumeRecord>, listing: &[&str], entries: &[Registrant], rtype| {
            let report = Report {
                rtype,
                ..report(entries)
            };
            owner_verdict_of(&serving(), volume, listing, &report, &wide())
        };
    let volume = with_standby();
    let both = [OWN, STANDBY];
    let unheld = registered(&[(own_pair(), false), (standby_pair(), false)]);
    let none = ReservationType::None;
    let exclusive = ReservationType::ExclusiveAccess;
    for (entries, rtype) in [
        (unheld.clone(), exclusive),
        (registered(&[(standby_pair(), false)]), exclusive),
        (registered(&[(own_pair(), true)]), none),
        (Vec::new(), none),
    ] {
        assert_eq!(
            verdict(Some(&volume), &both, &entries, rtype),
            Verdict::Withdraw,
            "{entries:?} under {rtype:?}"
        );
    }
    let stranger = registered(&[(own_pair(), false), (unknown_pair(), false)]);
    assert_eq!(
        verdict(Some(&volume), &both, &stranger, exclusive),
        owner_retired(Trigger::Report(NotSole::ForeignRegistrant)),
        "an unrecorded registrant retires with the alarm"
    );
    assert_eq!(
        verdict(Some(&volume), &both, &stranger, none),
        owner_retired(Trigger::Report(NotSole::ReservationType)),
        "an unrecorded registrant beside no reservation retires with the alarm"
    );
    for (entries, rtype) in [
        (registered(&[(own_pair(), false)]), exclusive),
        (registered(&[(own_pair(), true)]), none),
        (Vec::new(), exclusive),
        (unheld.clone(), exclusive),
        (
            registered(&[(own_pair(), false), (unknown_pair(), false)]),
            none,
        ),
    ] {
        assert_eq!(
            verdict(None, &both, &entries, rtype),
            Verdict::Withdraw,
            "an unread volume record holds until a poll that reads it: {entries:?} under {rtype:?}"
        );
    }
    let twice = registered(&[(own_pair(), false), (own_pair(), false)]);
    let alias = registered(&[(
        Pair {
            key: unknown_pair().key,
            ..own_pair()
        },
        false,
    )]);
    // (Report, rtype, the trigger under the read volume record, the trigger under an unread one)
    let rows = [
        (
            &twice,
            none,
            NotSole::ReservationType,
            NotSole::ReservationType,
        ),
        (
            &twice,
            exclusive,
            NotSole::DuplicateOwnRecord,
            NotSole::DuplicateOwnRecord,
        ),
        (
            &alias,
            none,
            NotSole::ReservationType,
            NotSole::ReservationType,
        ),
        (
            &alias,
            exclusive,
            NotSole::ForeignRegistrant,
            NotSole::NotHolder,
        ),
    ];
    for (entries, rtype, read, unread) in rows {
        for (volume, refusal) in [(Some(&volume), read), (None, unread)] {
            assert_eq!(
                verdict(volume, &both, entries, rtype),
                owner_retired(Trigger::Report(refusal)),
                "a second own record or a lone own-host-ID alias keeps the trigger under {rtype:?}, volume record \
                 read {}",
                volume.is_some()
            );
        }
    }
    assert_eq!(
        verdict(Some(&volume), &[OWN, FOREIGN], &unheld, exclusive),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned())))
    );
    let modified = VolumeRecord {
        modification: Some(Modification::InProgress),
        ..with_standby()
    };
    assert_eq!(
        verdict(Some(&modified), &both, &unheld, exclusive),
        owner_retired(Trigger::Modification)
    );
}

/// An enrolled standby the caller has not bound is admitted by the events and the Report, but its listed instance is
/// foreign and retires; with its instance unlisted the owner keeps serving.
#[test]
fn an_enrolled_standby_outside_the_bound_peers_retires_only_on_its_listing() {
    let holder = owner();
    let shard = serving();
    let volume = with_standby();
    let entries = registered(&[(own_pair(), true), (standby_pair(), false)]);
    let report = report(&entries);
    for (listing, verdict) in [
        (
            listed(&[OWN, STANDBY]),
            owner_retired(Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned()))),
        ),
        (listed(&[OWN]), Verdict::Continue),
    ] {
        let reads = Reads {
            shard: Some(&shard),
            volume: Some(&volume),
            listed: Some(&listing),
            peers: &[],
        };
        assert_eq!(
            poll(
                &holder,
                Target::of(&shard),
                own_pair(),
                Ok(&report),
                &reads,
                &wide()
            ),
            verdict
        );
    }
}

/// A standby that detached and re-attached keeps only its earlier attach's pair, which enrolls nothing for its live
/// attach: unbound, the owner retires with `Events`; bound as a peer, its pending enrollment keeps the owner serving.
#[test]
fn a_reattached_standby_with_only_its_earlier_pair_needs_its_binding() {
    let holder = owner();
    let shard = serving();
    let reattached = with_events(
        &with_standby(),
        &[
            (EventKind::Attach, holder.host),
            (EventKind::Attach, standby_host()),
            (EventKind::Detach, standby_host()),
            (EventKind::Attach, standby_host()),
        ],
    );
    let listing = listed(&[OWN]);
    let entries = [own_entry()];
    let report = report(&entries);
    let peers = peers();
    for (bound, verdict) in [
        (&[][..], owner_retired(Trigger::Events)),
        (&peers[..], Verdict::Continue),
    ] {
        let reads = Reads {
            shard: Some(&shard),
            volume: Some(&reattached),
            listed: Some(&listing),
            peers: bound,
        };
        assert_eq!(
            poll(
                &holder,
                Target::of(&shard),
                own_pair(),
                Ok(&report),
                &reads,
                &wide()
            ),
            verdict
        );
    }
}

/// Every owner poll across a standby's attach, enrollment, registration, force detach and deregistration continues,
/// so none of these host-side steps requests a retirement; the fresh check still retires on a standby's event.
#[test]
fn standby_enrollment_and_loss_request_no_retirement() {
    let host = owner().host;
    let own = owner().instance;
    let attached = enrolled(&with_standby(), &[(host, own_pair(), 0)]);
    let forced = with_marked_standby(EventKind::Force);
    let alone = registered(&[(own_pair(), true)]);
    let both_registered = registered(&[(own_pair(), true), (standby_pair(), false)]);
    let both = [own.as_str(), STANDBY];
    for (stage, volume, listing, entries) in [
        ("attach recorded", &attached, &both[..], &alone),
        ("pair enrolled", &with_standby(), &both, &alone),
        ("registered", &with_standby(), &both, &both_registered),
        ("force detached", &forced, &both, &both_registered),
        ("registration gone", &forced, &[own.as_str()], &alone),
    ] {
        assert_eq!(
            owner_verdict(Some(volume), listing, entries),
            Verdict::Continue,
            "{stage}"
        );
    }
    let only_own = listed(&[own.as_str()]);
    let attached_alone = enrolled(&with_standby(), &[(host, own_pair(), 0)]);
    let shard = serving();
    assert_eq!(
        poll(
            &owner(),
            Target::of(&shard),
            own_pair(),
            Ok(&report(&alone)),
            &Reads {
                shard: Some(&shard),
                volume: Some(&attached_alone),
                listed: Some(&only_own),
                peers: &[],
            },
            &wide(),
        ),
        owner_retired(Trigger::Events),
        "a live attach of a host neither bound nor enrolled"
    );
    assert_eq!(
        fresh(
            &owner(),
            &Reads {
                shard: Some(&record()),
                volume: Some(&with_standby()),
                listed: Some(&only_own),
                peers: &peers(),
            }
        ),
        retired(
            &owner(),
            Role::Active,
            Target::of(&record()),
            Trigger::Events
        )
    );
}

/// An over-bound Report under `N_reg` below `MAX_REGISTRANTS` retires when a listed registrant is unrecorded or the
/// count exceeds the recorded pairs with the own pair, and is no observation when they account for it or the volume
/// record is unread; a parse refusal of an over-bound count is no observation only with the volume record unread, and
/// a bound at the cap keeps every over-bound count conclusive.
#[test]
fn a_report_beyond_n_reg_retires_unless_the_recorded_pairs_account_for_it() {
    let host = owner().host;
    let narrow = Bounds::new(2, 2, 100, 10, 20, 5).unwrap();
    assert!(!narrow.covers_recorded_pairs() && wide().covers_recorded_pairs());
    let owner_only = enrolled(&volume(VolumeState::Active, host), &[(host, own_pair(), 0)]);
    let events = [
        (EventKind::Attach, host),
        (EventKind::Attach, standby_host()),
        (EventKind::Attach, second_standby()),
    ];
    let three = enrolled(
        &with_events(&volume(VolumeState::Active, host), &events),
        &[
            (host, own_pair(), 0),
            (standby_host(), standby_pair(), 1),
            (second_standby(), second_pair(), 2),
        ],
    );
    let unknowns = registered(&[
        (own_pair(), true),
        (unknown_pair(), false),
        (pair(10, 1, 10), false),
    ]);
    let recorded = registered(&[
        (own_pair(), true),
        (standby_pair(), false),
        (second_pair(), false),
    ]);
    let one_unknown = registered(&[
        (own_pair(), true),
        (standby_pair(), false),
        (unknown_pair(), false),
    ]);
    let listing = [OWN, STANDBY, SECOND];
    assert_eq!(
        owner_verdict_under(&serving(), Some(&owner_only), &[OWN], &unknowns, &narrow),
        owner_retired(Trigger::Report(NotSole::Excess)),
        "an owner-only record and an over-bound Report"
    );
    assert_eq!(
        owner_verdict_under(&serving(), Some(&three), &listing, &recorded, &narrow),
        Verdict::Unobserved,
        "every listed registrant recorded"
    );
    assert_eq!(
        owner_verdict_under(&serving(), Some(&three), &listing, &one_unknown, &narrow),
        owner_retired(Trigger::Report(NotSole::Excess)),
        "one listed registrant unrecorded"
    );
    assert_eq!(
        owner_verdict_under(&serving(), None, &[OWN], &recorded, &narrow),
        Verdict::Unobserved,
        "an unread record under a bound below the cap"
    );
    let doubled = registered(&[
        (own_pair(), true),
        (standby_pair(), false),
        (second_pair(), false),
        (standby_pair(), false),
    ]);
    assert_eq!(
        owner_verdict_under(&serving(), Some(&three), &listing, &doubled, &narrow),
        owner_retired(Trigger::Report(NotSole::Excess)),
        "every listed registrant recorded and a count above the recorded pairs"
    );
    let holder = owner();
    let shard = serving();
    let own_listing = listed(&[OWN]);
    for (volume, verdict) in [
        (None, Verdict::Unobserved),
        (
            Some(&three),
            owner_retired(Trigger::Report(NotSole::Excess)),
        ),
    ] {
        let reads = Reads {
            shard: Some(&shard),
            volume,
            listed: Some(&own_listing),
            peers: &[],
        };
        assert_eq!(
            poll(
                &holder,
                Target::of(&shard),
                own_pair(),
                Err(NotSole::Excess),
                &reads,
                &narrow
            ),
            verdict,
            "a parse refusal of an over-bound count, read volume record {}",
            volume.is_some()
        );
        assert_eq!(
            poll(
                &holder,
                Target::of(&shard),
                own_pair(),
                Err(NotSole::Excess),
                &reads,
                &wide()
            ),
            owner_retired(Trigger::Report(NotSole::Excess)),
            "a parse refusal under a bound at the cap"
        );
    }
    let crowd: Vec<_> = (0..9)
        .map(|at| entry(at, pair(at as u8 + 1, 1, at as u32 + 1), at == 0))
        .collect();
    for read in [Some(&three), None] {
        assert_eq!(
            owner_verdict_under(&serving(), read, &[OWN], &crowd, &wide()),
            owner_retired(Trigger::Report(NotSole::Excess)),
            "a bound at the cap"
        );
    }
}

/// The owner's verdict over `volume`, `listing` and a Report of `entries` with no caller-bound peer, so every
/// admitted instance comes from the volume record's entries.
fn unbound_verdict(volume: &VolumeRecord, listing: &[&str], entries: &[Registrant]) -> Verdict {
    let shard = serving();
    unbound_poll(
        Some(&shard),
        Some(volume),
        Target::of(&shard),
        listing,
        entries,
    )
}

/// The owner's live attach at entry 0 with its pair, and the standby's entry 1 ended with its instance and, when
/// `paired`, its pair still recorded: a format-3 record, since format 2 holds no ended entry.
fn with_ended_standby(paired: bool) -> VolumeRecord {
    let mut record = with_standby();
    record.events[1].kind = EventKind::Ended;
    record.events[1].instance = Some(InstanceId::new(STANDBY).unwrap());
    if !paired {
        record
            .pairs
            .retain(|recorded| recorded.host != standby_host());
        record.fence = (u64::from(serving().generation.get() as u32) << 32) | 2;
    }
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&record)),
        Ok(record.clone())
    );
    record
}

/// ENDED-NEVER-RETIRES at the owner's poll: an ended entry's listed instance, its recorded pair registered and not
/// holding, and a late Register under its key after the pair dropped each keep the owner serving with no caller-bound
/// peer. Controls: the same listing without the entry's instance retires on `Attachment(Foreign)`, and a registrant
/// under a key no ended entry carries retires on `ForeignRegistrant`.
#[test]
fn an_ended_attach_is_expected_state_at_the_owners_poll() {
    let paired = with_ended_standby(true);
    let dropped = with_ended_standby(false);
    let standby_registered = registered(&[(own_pair(), true), (standby_pair(), false)]);
    let alone = registered(&[(own_pair(), true)]);
    assert_eq!(
        unbound_verdict(&paired, &[OWN, STANDBY], &alone),
        Verdict::Continue,
        "an ended entry's instance is still listed"
    );
    assert_eq!(
        unbound_verdict(&paired, &[OWN, STANDBY], &standby_registered),
        Verdict::Continue,
        "an ended entry's recorded pair is registered and does not hold"
    );
    assert_eq!(
        dropped.registrant(&standby_pair()),
        crate::failover::records::Registration::Ended
    );
    assert_eq!(
        unbound_verdict(&dropped, &[OWN, STANDBY], &standby_registered),
        Verdict::Continue,
        "a late Register under a dropped ended key"
    );
    let mut unbound = paired.clone();
    unbound.events[1].instance = None;
    assert_eq!(
        unbound_verdict(&unbound, &[OWN, STANDBY], &alone),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned()))),
        "control: the admitted peers without the ended entry's instance"
    );
    let stranger = registered(&[(own_pair(), true), (unknown_pair(), false)]);
    assert_eq!(
        dropped.registrant(&unknown_pair()),
        crate::failover::records::Registration::Unknown
    );
    assert_eq!(
        unbound_verdict(&dropped, &[OWN, STANDBY], &stranger),
        owner_retired(Trigger::Report(NotSole::ForeignRegistrant)),
        "control: a registrant the record classes unknown"
    );
}

/// RECORDED-HOLDER-HOLD over an ended entry: its recorded pair holding withdraws the owner with no request, while a
/// holder under a dropped ended key keeps the unrecorded-holder outcome. An instance that no retained entry binds, a
/// gone entry's included, retires on `Attachment(Foreign)` as before.
#[test]
fn an_ended_holder_withdraws_and_an_unbound_instance_retires() {
    let paired = with_ended_standby(true);
    let dropped = with_ended_standby(false);
    let standby_holds = registered(&[(own_pair(), false), (standby_pair(), true)]);
    assert_eq!(
        unbound_verdict(&paired, &[OWN, STANDBY], &standby_holds),
        Verdict::Withdraw,
        "a recorded ended pair holds"
    );
    assert_eq!(
        unbound_verdict(&dropped, &[OWN, STANDBY], &standby_holds),
        owner_retired(Trigger::Report(NotSole::ForeignHolder)),
        "a holder under a dropped ended key"
    );
    let alone = registered(&[(own_pair(), true)]);
    assert_eq!(
        unbound_verdict(&paired, &[OWN, SECOND], &alone),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(SECOND.to_owned()))),
        "an instance of no retained entry"
    );
    let mut gone = dropped.clone();
    gone.events[1].kind = EventKind::Gone;
    assert_eq!(
        unbound_verdict(&gone, &[OWN, STANDBY], &alone),
        owner_retired(Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned()))),
        "a gone entry's instance listed again"
    );
}

/// ENDED-GRANTS-NOTHING at the owner's poll: an ended or gone own entry under a shard record that names the owner
/// withdraws with no request. Control: a format-2 detach of the owner, which the events rule judges, retires on
/// `Trigger::Events`.
#[test]
fn an_owner_whose_own_entry_ended_withdraws_with_no_request() {
    let alone = registered(&[(own_pair(), true)]);
    let mut ended = volume(VolumeState::Active, owner().host);
    ended.pairs = vec![RecordedPair {
        host: owner().host,
        pair: own_pair(),
        attach: 0,
    }];
    ended.events[0].kind = EventKind::Ended;
    assert_eq!(unbound_verdict(&ended, &[OWN], &alone), Verdict::Withdraw);
    let mut gone = ended.clone();
    gone.pairs.clear();
    gone.fence = (u64::from(serving().generation.get() as u32) << 32) | 2;
    gone.events[0].kind = EventKind::Gone;
    assert_eq!(unbound_verdict(&gone, &[OWN], &alone), Verdict::Withdraw);
    let mut detached = volume(VolumeState::Active, owner().host);
    detached.push(EventKind::Detach, owner().host, ERA);
    assert_eq!(
        unbound_verdict(&detached, &[OWN], &alone),
        owner_retired(Trigger::Events),
        "control: the events rule alone"
    );
}

/// OWNER-EVENTS keeps no uncompacted-history clause: a record whose next number lies above its retained entries
/// passes the owner's poll at `E > 0`. Control: the same record under the clause the poll keeps at `E = 0` retires on
/// `Trigger::Events`.
#[test]
fn a_record_with_removed_entries_passes_the_owners_poll() {
    let alone = registered(&[(own_pair(), true)]);
    let mut removed = volume(VolumeState::Active, owner().host);
    removed.events[0].seq = 5;
    removed.next = 6;
    removed.pairs = vec![RecordedPair {
        host: owner().host,
        pair: own_pair(),
        attach: 5,
    }];
    assert!(!removed.uncompacted());
    assert_eq!(unbound_verdict(&removed, &[OWN], &alone), Verdict::Continue);
    let unbumped = record();
    let listing = listed(&[OWN]);
    let reads = Reads {
        shard: Some(&unbumped),
        volume: Some(&removed),
        listed: Some(&listing),
        peers: &[],
    };
    assert_eq!(
        poll(
            &owner(),
            Target::of(&unbumped),
            own_pair(),
            Ok(&report(&alone)),
            &reads,
            &wide()
        ),
        retired(
            &owner(),
            Role::Active,
            Target::of(&unbumped),
            Trigger::Events
        ),
        "control: the uncompacted-history clause"
    );
}

/// The owner's verdict over `shard`, `volume`, `listing` and a Report of `entries` under `target`, with no
/// caller-bound peer.
fn unbound_poll(
    shard: Option<&ShardRecord>,
    volume: Option<&VolumeRecord>,
    target: Target,
    listing: &[&str],
    entries: &[Registrant],
) -> Verdict {
    let listing = listed(listing);
    let reads = Reads {
        shard,
        volume,
        listed: Some(&listing),
        peers: &[],
    };
    poll(
        &owner(),
        target,
        own_pair(),
        Ok(&report(entries)),
        &reads,
        &wide(),
    )
}

/// An entry's instance binding admits that instance only in a poll that read this volume's record: with no
/// caller-bound peer, the listed instance of an ended entry keeps the owner serving under the record, and the same
/// listing retires on `Attachment(Foreign)` under an unread volume record and under another volume's record.
#[test]
fn an_entry_bound_instance_is_admitted_only_under_a_read_volume_record() {
    let paired = with_ended_standby(true);
    let alone = registered(&[(own_pair(), true)]);
    let shard = serving();
    let target = Target::of(&shard);
    let listing = [OWN, STANDBY];
    assert_eq!(
        unbound_poll(Some(&shard), Some(&paired), target, &listing, &alone),
        Verdict::Continue
    );
    let other = VolumeRecord {
        volume: VolumeId::new("vol-0c").unwrap(),
        ..paired.clone()
    };
    for (what, volume) in [
        ("an unread volume record", None),
        ("another volume's record", Some(&other)),
    ] {
        assert_eq!(
            unbound_poll(Some(&shard), volume, target, &listing, &alone),
            owner_retired(Trigger::Attachment(Mismatch::Foreign(STANDBY.to_owned()))),
            "{what}"
        );
    }
}

/// The owner's events rule follows its target whether or not the poll read the shard record: at `E = 0` an ended
/// own entry and a compacted history retire on `Trigger::Events` either way. At `E > 0` without the shard read an
/// ended or gone own entry withdraws, and a compacted history with a live own attach is no trigger.
#[test]
fn the_owners_events_rule_follows_its_target_with_or_without_the_shard_read() {
    let alone = registered(&[(own_pair(), true)]);
    let own_at = |attach: u32| RecordedPair {
        host: owner().host,
        pair: own_pair(),
        attach,
    };
    let mut ended = volume(VolumeState::Active, owner().host);
    ended.pairs = vec![own_at(0)];
    ended.events[0].kind = EventKind::Ended;
    let mut gone = ended.clone();
    gone.pairs.clear();
    gone.events[0].kind = EventKind::Gone;
    let mut removed = volume(VolumeState::Active, owner().host);
    removed.events[0].seq = 5;
    removed.next = 6;
    removed.pairs = vec![own_at(5)];
    let unbumped = record();
    let first = Target::of(&unbumped);
    for (what, record) in [
        ("an ended own entry", &ended),
        ("a compacted history", &removed),
    ] {
        for shard in [Some(&unbumped), None] {
            assert_eq!(
                unbound_poll(shard, Some(record), first, &[OWN], &alone),
                retired(&owner(), Role::Active, first, Trigger::Events),
                "{what} at E = 0, shard read {}",
                shard.is_some()
            );
        }
    }
    let target = Target::of(&serving());
    for (what, record, verdict) in [
        ("an ended own entry", &ended, Verdict::Withdraw),
        ("a gone own entry", &gone, Verdict::Withdraw),
        ("a compacted history", &removed, Verdict::Unobserved),
    ] {
        assert_eq!(
            unbound_poll(None, Some(record), target, &[OWN], &alone),
            verdict,
            "{what} at E > 0 without the shard read"
        );
    }
}

/// An ended own entry withdraws only when no earlier source retires: a foreign listed instance retires on
/// `Attachment(Foreign)` and an unknown registrant on `ForeignRegistrant`, as for a live own entry.
#[test]
fn an_ended_owner_still_retires_on_an_earlier_trigger() {
    let mut ended = volume(VolumeState::Active, owner().host);
    ended.pairs = vec![RecordedPair {
        host: owner().host,
        pair: own_pair(),
        attach: 0,
    }];
    ended.events[0].kind = EventKind::Ended;
    let live = enrolled(
        &volume(VolumeState::Active, owner().host),
        &[(owner().host, own_pair(), 0)],
    );
    let alone = registered(&[(own_pair(), true)]);
    let stranger = registered(&[(own_pair(), true), (unknown_pair(), false)]);
    for record in [&ended, &live] {
        assert_eq!(
            unbound_verdict(record, &[OWN, FOREIGN], &alone),
            owner_retired(Trigger::Attachment(Mismatch::Foreign(FOREIGN.to_owned())))
        );
        assert_eq!(
            unbound_verdict(record, &[OWN], &stranger),
            owner_retired(Trigger::Report(NotSole::ForeignRegistrant))
        );
    }
}

/// OWNER-EVENTS over a live attach of another host with no enrolled pair: an entry that binds its instance passes with
/// no caller-bound peer, whether or not the listing shows that instance; the twin entry that binds none retires on
/// `Trigger::Events`.
#[test]
fn a_live_attach_that_binds_its_instance_passes_owner_events_unbound() {
    let mut bound = with_standby();
    bound
        .pairs
        .retain(|recorded| recorded.host != standby_host());
    bound.events[1].instance = Some(InstanceId::new(STANDBY).unwrap());
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&bound)),
        Ok(bound.clone())
    );
    let alone = registered(&[(own_pair(), true)]);
    assert_eq!(
        unbound_verdict(&bound, &[OWN, STANDBY], &alone),
        Verdict::Continue
    );
    assert_eq!(unbound_verdict(&bound, &[OWN], &alone), Verdict::Continue);
    let mut unbound = bound;
    unbound.events[1].instance = None;
    assert_eq!(
        unbound_verdict(&unbound, &[OWN], &alone),
        owner_retired(Trigger::Events),
        "control: the entry binds no instance"
    );
}

/// The owner's volume, the standby's entry 1 ended with its pair dropped, and a second standby attached at entry 2 with
/// its instance and its pair enrolled.
fn with_ended_standby_and_second() -> VolumeRecord {
    let mut record = with_ended_standby(false);
    let at = record
        .push(EventKind::Attach, second_standby(), ERA)
        .unwrap();
    record.events[2].instance = Some(InstanceId::new(SECOND).unwrap());
    record.pairs.push(RecordedPair {
        host: second_standby(),
        pair: second_pair(),
        attach: at,
    });
    record
}

/// NO-HOLDER-HOLD and RECORDED-HOLDER-HOLD beside a late Register under a dropped ended key: nobody holding, or a
/// recorded pair of another host holding, withdraws the owner with no request. The same Reports with an unknown pair
/// in place of the late one retire, on `ForeignRegistrant` with nobody holding and on `ForeignHolder` beside the
/// recorded holder.
#[test]
fn the_holds_admit_a_late_register_under_an_ended_key() {
    let record = with_ended_standby_and_second();
    assert_eq!(
        record.registrant(&standby_pair()),
        crate::failover::records::Registration::Ended
    );
    assert_eq!(
        record.registrant(&unknown_pair()),
        crate::failover::records::Registration::Unknown
    );
    let listing = [OWN, STANDBY, SECOND];
    for (late, nobody, holder) in [
        (standby_pair(), Verdict::Withdraw, Verdict::Withdraw),
        (
            unknown_pair(),
            owner_retired(Trigger::Report(NotSole::ForeignRegistrant)),
            owner_retired(Trigger::Report(NotSole::ForeignHolder)),
        ),
    ] {
        let unheld = registered(&[(own_pair(), false), (late, false)]);
        assert_eq!(
            unbound_verdict(&record, &listing, &unheld),
            nobody,
            "{late:?}"
        );
        let held = registered(&[(own_pair(), false), (second_pair(), true), (late, false)]);
        assert_eq!(
            unbound_verdict(&record, &listing, &held),
            holder,
            "{late:?}"
        );
    }
}

/// An over-bound Report under `N_reg` below `MAX_REGISTRANTS` whose registrants the recorded pairs and a late Register
/// under a dropped ended key account for is no observation; an unknown pair in the late one's place retires on
/// `Excess`.
#[test]
fn an_over_bound_report_counts_a_late_register_under_an_ended_key() {
    let narrow = Bounds::new(2, 2, 100, 10, 20, 5).unwrap();
    let record = with_ended_standby_and_second();
    let listing = listed(&[OWN, STANDBY, SECOND]);
    let shard = serving();
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(&record),
        listed: Some(&listing),
        peers: &[],
    };
    for (late, verdict) in [
        (standby_pair(), Verdict::Unobserved),
        (
            unknown_pair(),
            owner_retired(Trigger::Report(NotSole::Excess)),
        ),
    ] {
        let entries = registered(&[(own_pair(), true), (second_pair(), false), (late, false)]);
        assert_eq!(
            poll(
                &owner(),
                Target::of(&shard),
                own_pair(),
                Ok(&report(&entries)),
                &reads,
                &narrow
            ),
            verdict,
            "{late:?}"
        );
    }
}

/// A host whose own pair pins its live attach after an earlier entry of the host ended or went keeps serving, and a
/// pair that pins the earlier entry beside the later live attach withdraws with no request (ENDED-GRANTS-NOTHING).
#[test]
fn an_own_pair_pinning_an_earlier_attach_withdraws_beside_a_later_live_one() {
    let alone = registered(&[(own_pair(), true)]);
    for earlier in [EventKind::Ended, EventKind::Gone] {
        let mut record = volume(VolumeState::Active, owner().host);
        record.events[0].kind = earlier;
        let at = record.push(EventKind::Attach, owner().host, ERA).unwrap();
        record.pairs = vec![RecordedPair {
            host: owner().host,
            pair: own_pair(),
            attach: at,
        }];
        assert!(!record.ended(owner().host), "{earlier:?}");
        assert_eq!(
            unbound_verdict(&record, &[OWN], &alone),
            Verdict::Continue,
            "{earlier:?}: the own pair pins the later live attach"
        );
        if earlier == EventKind::Ended {
            record.pairs[0].attach = 0;
            assert_eq!(
                unbound_verdict(&record, &[OWN], &alone),
                Verdict::Withdraw,
                "the own pair pins the ended entry"
            );
        }
    }
}

/// A format-2 detach or force event after the owner's ended entry leaves that entry the one judged: the owner
/// withdraws with no request.
#[test]
fn a_detach_after_an_ended_own_entry_still_withdraws() {
    let alone = registered(&[(own_pair(), true)]);
    for later in [EventKind::Detach, EventKind::Force] {
        let mut record = volume(VolumeState::Active, owner().host);
        record.pairs = vec![RecordedPair {
            host: owner().host,
            pair: own_pair(),
            attach: 0,
        }];
        record.events[0].kind = EventKind::Ended;
        record.push(later, owner().host, ERA);
        assert_eq!(
            <VolumeRecord as Record>::decode(&Record::encode(&record)),
            Ok(record.clone()),
            "{later:?}"
        );
        assert!(record.ended(owner().host));
        assert_eq!(
            unbound_verdict(&record, &[OWN], &alone),
            Verdict::Withdraw,
            "{later:?}"
        );
    }
}

/// A pair under a key a recorded legacy pair holds, with another host ID, is no ended attach's registrant even when the
/// key's number is an ended entry: the record classes it `Unknown` and the poll retires on `ForeignRegistrant`, while
/// the recorded legacy pair itself listed beside the owner keeps it serving.
#[test]
fn a_second_host_id_under_a_recorded_key_is_unknown() {
    let mut record = enrolled(
        &volume(VolumeState::Active, owner().host),
        &[(owner().host, own_pair(), 0)],
    );
    record.push(EventKind::Ended, second_standby(), ERA);
    let at = record.push(EventKind::Attach, standby_host(), ERA).unwrap();
    let legacy = Pair {
        key: crate::failover::records::attachment_key(1).unwrap(),
        ..standby_pair()
    };
    record.pairs.push(RecordedPair {
        host: standby_host(),
        pair: legacy,
        attach: at,
    });
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&record)),
        Ok(record.clone())
    );
    let impostor = Pair {
        key: legacy.key,
        ..unknown_pair()
    };
    assert_eq!(
        record.registrant(&impostor),
        crate::failover::records::Registration::Unknown
    );
    assert_eq!(
        unbound_verdict(
            &record,
            &[OWN],
            &registered(&[(own_pair(), true), (impostor, false)])
        ),
        owner_retired(Trigger::Report(NotSole::ForeignRegistrant)),
        "another host ID under the recorded legacy key"
    );
    assert_eq!(
        unbound_verdict(
            &record,
            &[OWN],
            &registered(&[(own_pair(), true), (legacy, false)])
        ),
        Verdict::Continue,
        "the recorded legacy pair itself"
    );
}

/// The owner's own pair, dropped from the record after its entry ended or went, withdraws beside a later live attach
/// of its host with or without the shard read, also when the record holds that live attach's own enrolled pair. The
/// own pair recorded for the live attach keeps the owner serving.
#[test]
fn a_dropped_own_pair_withdraws_beside_a_later_live_attach() {
    let alone = registered(&[(own_pair(), true)]);
    let shard = serving();
    let target = Target::of(&shard);
    for earlier in [EventKind::Ended, EventKind::Gone] {
        let mut record = volume(VolumeState::Active, owner().host);
        record.events[0].kind = earlier;
        let at = record.push(EventKind::Attach, owner().host, ERA).unwrap();
        assert_eq!(
            crate::failover::records::attachment_seq(own_pair().key),
            Some(0)
        );
        for (shard, verdict) in [(Some(&shard), Verdict::Withdraw), (None, Verdict::Withdraw)] {
            assert_eq!(
                unbound_poll(shard, Some(&record), target, &[OWN], &alone),
                verdict,
                "{earlier:?}, shard read {}",
                shard.is_some()
            );
        }
        if earlier == EventKind::Gone {
            let mut shed = record.clone();
            shed.events.remove(0);
            assert_eq!(shed.succeeds(&record), Ok(()));
            assert_eq!((shed.live(owner().host), shed.next), (Some(at), at + 1));
            for (shard, verdict) in [
                (Some(&shard), Verdict::Continue),
                (None, Verdict::Unobserved),
            ] {
                assert_eq!(
                    unbound_poll(shard, Some(&shed), target, &[OWN], &alone),
                    verdict,
                    "format 2 expresses the record, shard read {}",
                    shard.is_some()
                );
            }
            shed.events[0].instance = Some(InstanceId::new(OWN).unwrap());
            assert_eq!(shed.succeeds(&record), Ok(()));
            for shard in [Some(&shard), None] {
                assert_eq!(
                    unbound_poll(shard, Some(&shed), target, &[OWN], &alone),
                    Verdict::Withdraw,
                    "the gone entry removed beside a bound attach, shard read {}",
                    shard.is_some()
                );
            }
        }
        let enrolled = Pair {
            key: crate::failover::records::attachment_key(at).unwrap(),
            ..own_pair()
        };
        record.pairs = vec![RecordedPair {
            host: owner().host,
            pair: enrolled,
            attach: at,
        }];
        for shard in [Some(&shard), None] {
            assert_eq!(
                unbound_poll(shard, Some(&record), target, &[OWN], &alone),
                Verdict::Withdraw,
                "{earlier:?}: the later attach's own enrolled pair leaves the dropped pair unrecorded, shard read {}",
                shard.is_some()
            );
        }
        record.pairs = vec![RecordedPair {
            host: owner().host,
            pair: own_pair(),
            attach: at,
        }];
        assert_eq!(
            unbound_poll(Some(&shard), Some(&record), target, &[OWN], &alone),
            Verdict::Continue,
            "{earlier:?}: the own pair pins the live attach"
        );
        assert_eq!(
            unbound_poll(None, Some(&record), target, &[OWN], &alone),
            Verdict::Unobserved,
            "{earlier:?}: the own pair pins the live attach, no shard read"
        );
        if earlier == EventKind::Ended {
            record.pairs[0].attach = 0;
            assert_eq!(
                unbound_poll(None, Some(&record), target, &[OWN], &alone),
                Verdict::Withdraw,
                "the own pair pins the ended entry, no shard read"
            );
        }
    }
}

/// The census and the over-bound count admit the same pairs: a pair under a dropped ended key that holds is outside
/// both, so an over-bound Report whose count the admitted pairs would match with that pair still retires on `Excess`.
#[test]
fn an_over_bound_report_with_an_ended_key_holder_retires_on_excess() {
    let narrow = Bounds::new(2, 2, 100, 10, 20, 5).unwrap();
    let third = Host::new(record().owner.get() + 102).unwrap();
    let mut record = with_ended_standby_and_second();
    let at = record.push(EventKind::Attach, third, ERA).unwrap();
    record.pairs.push(RecordedPair {
        host: third,
        pair: pair(4, 1, at + 1),
        attach: at,
    });
    let listing = listed(&[OWN, STANDBY, SECOND]);
    let shard = serving();
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(&record),
        listed: Some(&listing),
        peers: &[],
    };
    for (holds, verdict) in [
        (true, owner_retired(Trigger::Report(NotSole::Excess))),
        (false, Verdict::Unobserved),
    ] {
        let entries = registered(&[
            (own_pair(), true),
            (standby_pair(), holds),
            (second_pair(), false),
        ]);
        assert_eq!(
            poll(
                &owner(),
                Target::of(&shard),
                own_pair(),
                Ok(&report(&entries)),
                &reads,
                &narrow
            ),
            verdict,
            "the late pair holds: {holds}"
        );
    }
}

/// The owner's and both standbys' attaches, each with its pair, and the entries of the two standbys ended: a format-3
/// record whose two ended pairs stay recorded.
fn with_two_ended_standbys() -> VolumeRecord {
    let host = owner().host;
    let mut record = enrolled(
        &with_events(
            &volume(VolumeState::Active, host),
            &[
                (EventKind::Attach, host),
                (EventKind::Attach, standby_host()),
                (EventKind::Attach, second_standby()),
            ],
        ),
        &[
            (host, own_pair(), 0),
            (standby_host(), standby_pair(), 1),
            (second_standby(), second_pair(), 2),
        ],
    );
    record.events[1].kind = EventKind::Ended;
    record.events[2].kind = EventKind::Ended;
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&record)),
        Ok(record.clone())
    );
    record
}

/// `reclaim` over a Report of `pairs` and `volume`. Where the Report shows the own pair as the sole holder, the key
/// `reclaim` names is one `EndedPreempt::resolve` admits over the same Report and record.
fn reclaimed(volume: &VolumeRecord, pairs: &[(Pair, bool)]) -> crate::failover::poll::Reclaim {
    let entries = registered(pairs);
    let report = report(&entries);
    let decided = crate::failover::poll::reclaim(&report, volume, &wide());
    let alone = pairs.contains(&(own_pair(), true))
        && pairs
            .iter()
            .all(|&(pair, holds)| !holds || pair == own_pair());
    if let (Some(key), true) = (decided.preempt, alone) {
        assert_eq!(
            crate::storage::EndedPreempt::resolve(&report, volume, key, own_pair(), &wide())
                .map(crate::storage::EndedPreempt::ended),
            Ok(key),
            "resolve admits the key reclaim names: {pairs:?}"
        );
    }
    if !decided.dropped.is_empty() {
        let session = (u64::from(serving().generation.get() as u32) << 32) | 2;
        let next = volume
            .dropped(&decided.dropped, session)
            .expect("dropped builds the drop reclaim names");
        assert_eq!(next.succeeds(volume), Ok(()), "{pairs:?}");
        let kept: Vec<Pair> = (volume.recorded())
            .filter(|held| !decided.dropped.contains(*held))
            .copied()
            .collect();
        assert_eq!(
            next.recorded_pairs(),
            kept,
            "exactly the named pairs leave: {pairs:?}"
        );
    }
    decided
}

fn reclaim_of(preempt: Option<Pair>, dropped: &[Pair]) -> crate::failover::poll::Reclaim {
    crate::failover::poll::Reclaim {
        preempt: preempt.map(|pair| pair.key),
        dropped: dropped.to_vec(),
    }
}

/// A pair of another host ID under `of`'s key.
fn alias(of: Pair) -> Pair {
    Pair {
        exhid: pair(7, 1, 1).exhid,
        ..of
    }
}

/// The owner's attach, the first standby's attach ended with its pair dropped, and the second standby's live attach
/// whose recorded pair carries the key the first standby's entry derives: a retained pair enrolled under a key no
/// entry of its own derives.
fn with_live_pair_under_an_ended_key() -> VolumeRecord {
    let mut record = with_two_ended_standbys();
    record.events[2].kind = EventKind::Attach;
    record
        .pairs
        .retain(|recorded| recorded.host != standby_host());
    for recorded in &mut record.pairs {
        if recorded.host == second_standby() {
            recorded.pair.key = standby_pair().key;
        }
    }
    record.fence = (u64::from(serving().generation.get() as u32) << 32) | 2;
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&record)),
        Ok(record.clone())
    );
    record
}

/// The owner's attach, the first standby's attach ended with its pair recorded under `key`, and the second
/// standby's live attach with no enrolled pair: a retained ended pair under a key KEY-PER-ATTACH gives the
/// unenrolled live attach, or a number at or past `next`.
fn with_ended_pair_under(key: crate::failover::identity::Key) -> VolumeRecord {
    let mut record = with_two_ended_standbys();
    record.events[2].kind = EventKind::Attach;
    record
        .pairs
        .retain(|recorded| recorded.host != second_standby());
    for recorded in &mut record.pairs {
        if recorded.host == standby_host() {
            recorded.pair.key = key;
        }
    }
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&record)),
        Ok(record.clone())
    );
    record
}

/// The standby's recorded pair pinning its attach, after which a format-2 detach or force detach of its host marks
/// it: a pair that pins no ended entry.
fn with_marked_standby(kind: EventKind) -> VolumeRecord {
    let record = with_events(
        &with_standby(),
        &[
            (EventKind::Attach, owner().host),
            (EventKind::Attach, standby_host()),
            (kind, standby_host()),
        ],
    );
    assert_eq!(
        <VolumeRecord as Record>::decode(&Record::encode(&record)),
        Ok(record.clone())
    );
    record
}

/// EndOrder in `reclaim`: over a Report that lists the ended standby's key, registered and not holding, `rule` names
/// no pair to drop.
fn assert_a_listed_ended_pair_stays(
    rule: impl Fn(&Report<'_>, &VolumeRecord, &Bounds) -> crate::failover::poll::Reclaim,
) {
    let entries = registered(&[(own_pair(), true), (standby_pair(), false)]);
    let decided = rule(&report(&entries), &with_ended_standby(true), &wide());
    assert_eq!(
        decided.dropped,
        Vec::new(),
        "a pair whose key the Report lists stays recorded"
    );
}

/// Negative control for EndOrder: a rule that drops every ended pair, whatever the Report lists, drops the pair of a
/// key that is still registered.
#[test]
#[should_panic(expected = "a pair whose key the Report lists stays recorded")]
fn negative_control_a_rule_that_drops_every_ended_pair_drops_a_listed_one() {
    assert_a_listed_ended_pair_stays(|_, volume, _| crate::failover::poll::Reclaim {
        preempt: None,
        dropped: volume.ended_pairs().map(|held| held.pair).collect(),
    });
}

/// ENDED-PREEMPT and EndOrder in `reclaim`: an ended entry's recorded pair registered and not holding is named for
/// the preempt and not dropped; after a Report without its key it is dropped and nothing is preempted. A late
/// Register under a dropped ended key is preempted with no drop, and an ended pair that never registered, as for a
/// standby that never took over, drops with no preempt. Of two registered ended keys one, the smaller, is named in
/// either entry order; the other waits for a later Report. A key is named only when every registrant under it is
/// tied to an ended entry and none holds, so a holding registrant under the smaller key names the larger. A record of
/// live entries only, a holding ended pair, a key a live recorded pair carries, a pair pinning a detached attach and
/// an inconclusive count name nothing, and no outcome names the own key or a live pair.
#[test]
fn reclaim_preempts_one_registered_ended_key_and_drops_only_pairs_the_report_does_not_list() {
    assert_a_listed_ended_pair_stays(crate::failover::poll::reclaim);
    let paired = with_ended_standby(true);
    let dropped = with_ended_standby(false);
    let own = (own_pair(), true);
    assert_eq!(
        reclaimed(&paired, &[own, (standby_pair(), false)]),
        reclaim_of(Some(standby_pair()), &[]),
        "a registered ended pair is preempted first"
    );
    assert_eq!(
        reclaimed(&paired, &[own]),
        reclaim_of(None, &[standby_pair()]),
        "a Report without its key drops it; a standby that never took over drops with no preempt"
    );
    assert_eq!(
        reclaimed(&dropped, &[own, (standby_pair(), false)]),
        reclaim_of(Some(standby_pair()), &[]),
        "a late Register under a dropped ended key"
    );
    let late_other = alias(standby_pair());
    assert_eq!(
        reclaimed(&paired, &[own, (late_other, false)]),
        reclaim_of(Some(late_other), &[]),
        "another host ID under the ended key keeps the pair until the key is absent"
    );
    for entries in [
        [own, (standby_pair(), false), (late_other, false)],
        [own, (late_other, false), (standby_pair(), false)],
        [own, (standby_pair(), false), (standby_pair(), false)],
    ] {
        assert_eq!(
            reclaimed(&paired, &entries),
            reclaim_of(Some(standby_pair()), &[]),
            "two ended registrants under one key name it once: {entries:?}"
        );
    }
    for entries in [
        [own, (standby_pair(), false), (late_other, true)],
        [own, (late_other, true), (standby_pair(), false)],
        [own, (standby_pair(), false), (standby_pair(), true)],
    ] {
        assert_eq!(
            reclaimed(&paired, &entries),
            reclaim_of(None, &[]),
            "a holding registrant under the key excludes it: {entries:?}"
        );
    }
    let two = with_two_ended_standbys();
    for entries in [
        [own, (second_pair(), false), (standby_pair(), false)],
        [own, (standby_pair(), false), (second_pair(), false)],
    ] {
        assert_eq!(
            reclaimed(&two, &entries),
            reclaim_of(Some(standby_pair()), &[]),
            "one key per poll, the smaller, whatever the entry order: {entries:?}"
        );
    }
    assert_eq!(
        reclaimed(
            &two,
            &[
                own,
                (standby_pair(), false),
                (alias(standby_pair()), true),
                (second_pair(), false)
            ]
        ),
        reclaim_of(Some(second_pair()), &[]),
        "a holding registrant under the smaller key names the larger"
    );
    assert_eq!(
        reclaimed(&two, &[own, (second_pair(), false)]),
        reclaim_of(Some(second_pair()), &[standby_pair()]),
        "the second key on a later poll, beside the first pair's drop"
    );
    assert_eq!(
        reclaimed(&two, &[own]),
        reclaim_of(None, &[standby_pair(), second_pair()])
    );
    let live = with_standby();
    for entries in [
        vec![own, (standby_pair(), false)],
        vec![own],
        vec![(own_pair(), false), (standby_pair(), true)],
    ] {
        assert_eq!(
            reclaimed(&live, &entries),
            reclaim_of(None, &[]),
            "{entries:?}"
        );
    }
    assert_eq!(
        reclaimed(&paired, &[(own_pair(), false), (standby_pair(), true)]),
        reclaim_of(None, &[]),
        "an ended pair that holds is neither preempted nor dropped"
    );
    let shared = with_live_pair_under_an_ended_key();
    let legacy = Pair {
        key: standby_pair().key,
        ..second_pair()
    };
    for entries in [
        vec![own, (standby_pair(), false)],
        vec![own, (standby_pair(), false), (legacy, false)],
        vec![own, (legacy, false), (standby_pair(), false)],
    ] {
        assert_eq!(
            reclaimed(&shared, &entries),
            reclaim_of(None, &[]),
            "a key a live recorded pair carries, listed or not: {entries:?}"
        );
    }
    for kind in [EventKind::Detach, EventKind::Force] {
        let marked = with_marked_standby(kind);
        for entries in [vec![own, (standby_pair(), false)], vec![own]] {
            assert_eq!(
                reclaimed(&marked, &entries),
                reclaim_of(None, &[]),
                "{kind:?}: a pair pinning a marked attach pins no ended entry: {entries:?}"
            );
        }
    }
    for key in [second_pair().key, pair(2, 1, 4).key] {
        let open = with_ended_pair_under(key);
        let ended = Pair {
            key,
            ..standby_pair()
        };
        assert_eq!(
            reclaimed(&open, &[own, (ended, false)]),
            reclaim_of(None, &[]),
            "a retained ended pair under a key a live or unallocated number derives: {key:?}"
        );
        assert_eq!(
            reclaimed(
                &open,
                &[own, (ended, false), (alias(standby_pair()), false)]
            ),
            reclaim_of(Some(standby_pair()), &[]),
            "the ended entry's own derived key stays eligible beside it: {key:?}"
        );
    }
    let entries = registered(&[own, (second_pair(), false)]);
    let twin = crate::failover::poll::reclaim(&report(&entries), &two, &wide());
    assert_eq!(
        twin,
        reclaim_of(Some(second_pair()), &[standby_pair()]),
        "the conclusive twin names both halves"
    );
    let mismatched = Report {
        regctl: 3,
        ..report(&entries)
    };
    assert_eq!(
        crate::failover::poll::reclaim(&mismatched, &two, &wide()),
        reclaim_of(None, &[]),
        "a count other than the entries is no evidence of an absent key"
    );
    let crowded = registered(&[
        own,
        (second_pair(), false),
        (second_pair(), false),
        (second_pair(), false),
        (second_pair(), false),
        (second_pair(), false),
        (second_pair(), false),
        (second_pair(), false),
        (second_pair(), false),
    ]);
    let roomy = Bounds::new(16, 2, 100, 10, 20, 5).unwrap();
    assert_eq!(
        crate::failover::poll::reclaim(&report(&crowded), &two, &roomy),
        reclaim_of(Some(second_pair()), &[standby_pair()]),
        "the conclusive twin of nine entries under a wider bound"
    );
    assert_eq!(
        crate::failover::poll::reclaim(&report(&crowded), &two, &wide()),
        reclaim_of(None, &[]),
        "a count above the bound is no evidence of an absent key"
    );
}

/// ENDED-PREEMPT and EndedPreemptSparesLiveAttach in `EndedPreempt::resolve`: it admits a registered ended key that
/// does not hold, a recorded ended pair's and a late Register's, two ended registrants under one key included, and
/// refuses a Report the own pair does not hold alone (an inconclusive or over-bound count and no reservation
/// included), a second record carrying the own host ID, the own key, an unregistered key, a key a live recorded pair
/// carries (listed or not, in either entry order, and the pair of an attach a format-2 detach or force detach marks),
/// and a key the record ties to no entry.
#[test]
fn an_ended_preempt_resolves_only_a_registered_ended_key_beside_the_own_sole_holder() {
    use crate::storage::{EndedPreempt, EndedRefusal};
    let resolve_in = |report: &Report<'_>, volume: &VolumeRecord, target: Pair, bounds: &Bounds| {
        EndedPreempt::resolve(report, volume, target.key, own_pair(), bounds)
            .map(|preempt| (preempt.pair(), preempt.ended()))
    };
    let resolve = |volume: &VolumeRecord, pairs: &[(Pair, bool)], target: Pair| {
        resolve_in(&report(&registered(pairs)), volume, target, &wide())
    };
    let paired = with_ended_standby(true);
    let dropped = with_ended_standby(false);
    let own = (own_pair(), true);
    let standby = (standby_pair(), false);
    let admitted = Ok((own_pair(), standby_pair().key));
    assert_eq!(resolve(&paired, &[own, standby], standby_pair()), admitted);
    assert_eq!(resolve(&dropped, &[own, standby], standby_pair()), admitted);
    assert_eq!(
        resolve(
            &paired,
            &[own, (alias(standby_pair()), false), standby],
            standby_pair()
        ),
        admitted,
        "two ended registrants under one key"
    );
    let rekeyed = Pair {
        key: pair(1, 1, 7).key,
        ..own_pair()
    };
    let shared = with_live_pair_under_an_ended_key();
    let legacy = Pair {
        key: standby_pair().key,
        ..second_pair()
    };
    let detached = with_marked_standby(EventKind::Detach);
    let forced = with_marked_standby(EventKind::Force);
    let under_live = Pair {
        key: second_pair().key,
        ..standby_pair()
    };
    let live_derived = with_ended_pair_under(under_live.key);
    let under_future = Pair {
        key: pair(2, 1, 4).key,
        ..standby_pair()
    };
    let future_derived = with_ended_pair_under(under_future.key);
    let retained_pair = Pair {
        key: pair(2, 6, 2).key,
        ..standby_pair()
    };
    let mut retained = with_ended_standby(true);
    for recorded in &mut retained.pairs {
        if recorded.host == standby_host() {
            recorded.pair = retained_pair;
        }
    }
    assert_eq!(
        resolve(&retained, &[own, (retained_pair, false)], retained_pair),
        Ok((own_pair(), retained_pair.key)),
        "a recorded ended pair under a retained key alone"
    );
    let twin = pair(8, 2, 2);
    assert_eq!(
        twin.key.incarnation(),
        standby_pair().key.incarnation(),
        "the twin carries the ended key's incarnation under another epoch"
    );
    assert_eq!(
        resolve(&paired, &[own, standby, (twin, false)], standby_pair()),
        admitted,
        "an unknown registrant of the same incarnation under another epoch is not under the key"
    );
    assert_eq!(
        resolve(&paired, &[own, standby, (twin, true)], standby_pair()),
        Err(EndedRefusal::NotSoleHolder),
        "the twin holding beside the own pair"
    );
    for (what, volume, pairs, target, refusal) in [
        (
            "the own pair does not hold",
            &paired,
            vec![(own_pair(), false), standby],
            standby_pair(),
            EndedRefusal::NotSoleHolder,
        ),
        (
            "the target holds",
            &paired,
            vec![(own_pair(), false), (standby_pair(), true)],
            standby_pair(),
            EndedRefusal::NotSoleHolder,
        ),
        (
            "the target holds beside the own pair",
            &paired,
            vec![own, (standby_pair(), true)],
            standby_pair(),
            EndedRefusal::NotSoleHolder,
        ),
        (
            "a second record with the own host ID",
            &paired,
            vec![own, (rekeyed, false), standby],
            standby_pair(),
            EndedRefusal::OwnRecord,
        ),
        (
            "the own key",
            &paired,
            vec![own, standby],
            own_pair(),
            EndedRefusal::Own,
        ),
        (
            "an unregistered key",
            &paired,
            vec![own],
            standby_pair(),
            EndedRefusal::Unregistered,
        ),
        (
            "a key only a registrant of another epoch shares the incarnation of",
            &paired,
            vec![own, (twin, false)],
            standby_pair(),
            EndedRefusal::Unregistered,
        ),
        (
            "a live entry's key",
            &with_standby(),
            vec![own, standby],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "a late Register under a key a live recorded pair carries, the pair unlisted",
            &shared,
            vec![own, standby],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "the late Register listed first",
            &shared,
            vec![own, standby, (legacy, false)],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "the live pair listed first",
            &shared,
            vec![own, (legacy, false), standby],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "a pair pinning an attach a detach marks",
            &detached,
            vec![own, standby],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "a pair pinning an attach a force detach marks",
            &forced,
            vec![own, standby],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "a retained ended pair under an unenrolled live attach's derived key",
            &live_derived,
            vec![own, (under_live, false)],
            under_live,
            EndedRefusal::Live,
        ),
        (
            "a retained ended pair under a key a number at or past next derives",
            &future_derived,
            vec![own, (under_future, false)],
            under_future,
            EndedRefusal::Live,
        ),
        (
            "an unknown alias under a live recorded pair's key, the pair listed after it",
            &with_standby(),
            vec![own, (alias(standby_pair()), false), standby],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "an unknown alias under a live recorded pair's key, the pair unlisted",
            &with_standby(),
            vec![own, (alias(standby_pair()), false)],
            standby_pair(),
            EndedRefusal::Live,
        ),
        (
            "an unregistered key a live recorded pair carries",
            &with_standby(),
            vec![own],
            standby_pair(),
            EndedRefusal::Unregistered,
        ),
        (
            "an unknown alias beside a recorded ended pair under a retained key, the pair first",
            &retained,
            vec![own, (retained_pair, false), (alias(retained_pair), false)],
            retained_pair,
            EndedRefusal::Unknown,
        ),
        (
            "an unknown alias beside a recorded ended pair under a retained key, the alias first",
            &retained,
            vec![own, (alias(retained_pair), false), (retained_pair, false)],
            retained_pair,
            EndedRefusal::Unknown,
        ),
        (
            "a key of another epoch the record ties to no entry",
            &paired,
            vec![own, standby, (pair(9, 2, 9), false)],
            pair(9, 2, 9),
            EndedRefusal::Unknown,
        ),
        (
            "an unrecorded key a number past next derives",
            &paired,
            vec![own, standby, (unknown_pair(), false)],
            unknown_pair(),
            EndedRefusal::Live,
        ),
    ] {
        assert_eq!(resolve(volume, &pairs, target), Err(refusal), "{what}");
    }
    let entries = registered(&[own, standby]);
    let conclusive = report(&entries);
    assert_eq!(
        resolve_in(&conclusive, &paired, standby_pair(), &wide()),
        admitted,
        "the conclusive twin"
    );
    for (what, refused) in [
        (
            "a count above the entries",
            Report {
                regctl: 3,
                ..conclusive
            },
        ),
        (
            "no reservation with the own holder bit set",
            Report {
                rtype: ReservationType::None,
                ..conclusive
            },
        ),
    ] {
        assert_eq!(
            resolve_in(&refused, &paired, standby_pair(), &wide()),
            Err(EndedRefusal::NotSoleHolder),
            "{what}"
        );
    }
    let crowded = registered(&[
        own, standby, standby, standby, standby, standby, standby, standby, standby,
    ]);
    let roomy = Bounds::new(16, 2, 100, 10, 20, 5).unwrap();
    assert_eq!(
        resolve_in(&report(&crowded), &paired, standby_pair(), &roomy),
        admitted,
        "nine entries under a wider bound"
    );
    assert_eq!(
        resolve_in(&report(&crowded), &paired, standby_pair(), &wide()),
        Err(EndedRefusal::NotSoleHolder),
        "a count above the bound"
    );
}
