use super::inputs::{Inputs, fresh, peers, reads, restart, takeover};
use crate::failover::attachments::{Mismatch, Peer};
use crate::failover::detect::tests::clock;
use crate::failover::fresh::tests::{fresh_of, registrant};
use crate::failover::poll::{self, Verdict};
use crate::failover::poll_tests::{report_of, with_events};
use crate::failover::records::{
    ERA, EventKind, Host, Record, RecordedPair, VolumeId, VolumeRecord,
};
use crate::failover::restart::tests::{
    self as restart_tests, Card, FULL, host as owner_host, own, sample, shard_now, shard_record,
    store,
};
use crate::failover::restart::{Check, Refused, Restart};
use crate::failover::retire::{Target, Trigger};
use crate::failover::takeover;
use crate::failover::takeover::tests::{
    self as takeover_tests, a_holds_c_registered, b_host, b_pair, c_host, c_pair, card_after_cas,
    holder_of, instance_of, lineage, silent_owners, stored_c, takeover_of, watch_of, with_c,
    with_c_and_b,
};
use crate::storage::ReservationLimits;
use crate::storage::gate_fixture::{bounds_of, limits};
use crate::storage::store_tests::{client, shard};

pub(super) fn inputs_of(host: Host) -> Inputs {
    Inputs::new(shard(), holder_of(host), bounds_of(limits()), limits(), 4).unwrap()
}

fn peer(host: Host) -> Peer {
    Peer {
        host,
        instance: instance_of(host),
    }
}

fn resolved(host: Host, volume: &VolumeRecord) -> Vec<Peer> {
    peers(&holder_of(host), volume, |host| Some(instance_of(host))).unwrap()
}

fn without_b(host: Host, volume: &VolumeRecord) -> Vec<Peer> {
    without(b_host(), host, volume)
}

fn without(unresolved: Host, host: Host, volume: &VolumeRecord) -> Vec<Peer> {
    peers(&holder_of(host), volume, |host| {
        (host != unresolved).then(|| instance_of(host))
    })
    .unwrap()
}

/// B's attachment follows A's and C's and precedes B's pair enrollment.
fn b_unenrolled() -> VolumeRecord {
    VolumeRecord {
        pairs: with_c().pairs,
        ..with_c_and_b()
    }
}

/// Each attached host other than the holder's becomes a peer with its resolved instance, in attach order, which
/// differs from host order when B attaches before C; a host whose instance does not resolve is left out, before or
/// after a resolved one. B stays a peer when the retained history opens with B's detach, as a compaction leaves it,
/// and holds B's reattach.
#[test]
fn peers_bind_every_other_attached_host_the_lookup_resolves() {
    let volume = with_c_and_b();
    assert_eq!(
        resolved(owner_host(), &volume),
        [peer(c_host()), peer(b_host())]
    );
    assert_eq!(
        resolved(c_host(), &volume),
        [peer(owner_host()), peer(b_host())]
    );
    let b_first = lineage(&[(b_host(), b_pair()), (c_host(), c_pair())]);
    assert_eq!(
        resolved(owner_host(), &b_first),
        [peer(b_host()), peer(c_host())]
    );
    assert_eq!(without_b(owner_host(), &volume), [peer(c_host())]);
    assert_eq!(without(c_host(), owner_host(), &volume), [peer(b_host())]);
    let mut reattached = VolumeRecord {
        next: volume.next,
        events: Vec::new(),
        pairs: Vec::new(),
        ..volume.clone()
    };
    reattached.push(EventKind::Detach, b_host(), ERA);
    for recorded in volume
        .pairs
        .iter()
        .filter(|recorded| recorded.host != owner_host())
    {
        let attach = reattached
            .push(EventKind::Attach, recorded.host, ERA)
            .unwrap();
        reattached.pairs.push(RecordedPair {
            attach,
            ..*recorded
        });
    }
    assert!(!reattached.uncompacted());
    assert_eq!(
        VolumeRecord::decode(&reattached.encode()),
        Ok(reattached.clone())
    );
    assert_eq!(
        resolved(owner_host(), &reattached),
        [peer(c_host()), peer(b_host())]
    );
}

/// `volume` with the latest entry of `host` moved to `kind`, binding `instance`.
fn entry_of(
    volume: &VolumeRecord,
    host: Host,
    kind: EventKind,
    instance: Option<crate::failover::attachments::InstanceId>,
) -> VolumeRecord {
    let mut volume = volume.clone();
    let event = volume
        .events
        .iter_mut()
        .rfind(|event| event.host == host)
        .unwrap();
    event.kind = kind;
    event.instance = instance;
    volume
}

/// An entry that binds an instance gives the judges that instance, so its host is no peer; an ended entry that binds
/// none keeps its host bound for the listing while the record holds it ended; a gone entry binds its host to
/// nothing, over a record the decoder reads.
#[test]
fn peers_bind_only_the_hosts_whose_attach_or_ended_entries_bind_no_instance() {
    let volume = with_c_and_b();
    let bound = entry_of(
        &volume,
        b_host(),
        EventKind::Attach,
        Some(instance_of(b_host())),
    );
    assert_eq!(resolved(owner_host(), &bound), [peer(c_host())]);
    let ended = entry_of(&volume, c_host(), EventKind::Ended, None);
    assert_eq!(
        resolved(owner_host(), &ended),
        [peer(c_host()), peer(b_host())]
    );
    let ended_bound = entry_of(
        &volume,
        c_host(),
        EventKind::Ended,
        Some(instance_of(c_host())),
    );
    assert_eq!(resolved(owner_host(), &ended_bound), [peer(b_host())]);
    for instance in [None, Some(instance_of(c_host()))] {
        let mut gone = entry_of(&volume, c_host(), EventKind::Gone, instance);
        gone.pairs.retain(|recorded| recorded.host != c_host());
        assert_eq!(
            <VolumeRecord as Record>::decode(&Record::encode(&gone)),
            Ok(gone.clone()),
            "{instance:?}"
        );
        assert_eq!(
            resolved(owner_host(), &gone),
            [peer(b_host())],
            "{instance:?}"
        );
    }
}

/// A record of another volume than the holder's yields no peers.
#[test]
fn peers_refuse_another_volumes_record() {
    let other = VolumeRecord {
        volume: VolumeId::new("vol-0c").unwrap(),
        ..with_c_and_b()
    };
    assert_eq!(
        peers(&holder_of(owner_host()), &other, |host| Some(instance_of(
            host
        ))),
        None
    );
}

/// `Inputs::new` refuses limits whose registrant count or Report deadline differs from the bounds'.
#[test]
fn inputs_refuse_limits_the_bounds_disagree_with() {
    let bounds = bounds_of(limits());
    let build = |limits| Inputs::new(shard(), holder_of(owner_host()), bounds, limits, 4);
    assert!(build(limits()).is_some());
    let registrants = limits().registrants();
    for count in [registrants - 1, registrants + 1] {
        let count = ReservationLimits::new(count, 2, 100, 100).unwrap();
        assert!(build(count).is_none(), "{count:?}");
    }
    for deadline in [99, 101] {
        let deadline = ReservationLimits::new(registrants, 2, deadline, 100).unwrap();
        assert!(build(deadline).is_none(), "{deadline:?}");
    }
}

/// [`fresh`] carries the checked inputs into the fresh activation unchanged.
#[test]
fn the_fresh_activation_takes_the_checked_inputs() {
    assert_eq!(
        format!("{:?}", fresh(&inputs_of(owner_host()))),
        format!("{:?}", fresh_of(shard(), holder_of(owner_host())))
    );
}

/// [`restart`] carries the checked inputs and the caller's peers into the restart unchanged, and [`takeover`] builds
/// the takeover of the revalidated witness's target over that restart, compared here with an empty peer slice.
#[test]
fn the_restart_and_the_takeover_take_the_checked_inputs_and_the_peers() {
    let bound = resolved(owner_host(), &with_c_and_b());
    assert_eq!(bound.len(), 2);
    let expected = Restart {
        peers: &bound,
        ..restart_tests::restart_of(shard(), holder_of(owner_host()))
    };
    assert_eq!(
        format!("{:?}", restart(&inputs_of(owner_host()), &bound)),
        format!("{expected:?}")
    );

    let record = takeover_tests::shard_record();
    let mut watch = watch_of(&[record], 3);
    let (published, _) = silent_owners(&mut watch, 40);
    let store = store(record, with_c());
    let witness = watch
        .revalidate(&published[0], 40, clock(40), true)
        .unwrap();
    let built = takeover(&inputs_of(c_host()), &[], &witness, 40).unwrap();
    assert_eq!(
        format!("{built:?}"),
        format!("{:?}", takeover_of(&store, c_host()))
    );
}

/// B detached or force detached after attaching stays bound, so the owner's poll over [`reads`] admits B's
/// instance that the listing still shows; leaving B unbound retires on it as a foreign attachment.
#[test]
fn a_detached_peer_stays_bound_for_the_listing() {
    let record = shard_record(4);
    let entries = [registrant(own(), 1, true)];
    let report = report_of(&entries);
    let listed =
        [owner_host(), c_host(), b_host()].map(|host| instance_of(host).as_str().to_owned());
    for kind in [EventKind::Detach, EventKind::Force] {
        let mut volume = with_c_and_b();
        volume.push(kind, b_host(), ERA);
        let verdict = |peers: &[Peer]| {
            poll::poll(
                &holder_of(owner_host()),
                Target::of(&record),
                own(),
                Ok(&report),
                &reads(Some(&record), Some(&volume), Some(&listed), peers),
                &bounds_of(limits()),
            )
        };
        let bound = resolved(owner_host(), &volume);
        assert_eq!(bound, [peer(c_host()), peer(b_host())], "{kind:?}");
        assert_eq!(verdict(&bound), Verdict::Continue, "{kind:?}");
        let Verdict::Retire(retirement) = verdict(&without_b(owner_host(), &volume)) else {
            panic!("an unbound listed attachment retires: {kind:?}");
        };
        assert_eq!(
            retirement.trigger(),
            &Trigger::Attachment(Mismatch::Foreign(instance_of(b_host()).as_str().to_owned())),
            "{kind:?}"
        );
    }
}

/// B's format-2 attach and detach, then a newer attach of B that binds B's instance, moved to `kind`: the newest
/// attachment entry of B decides its peer, so the older unbound attach binds no peer. Ended, the entry admits B's
/// listed instance with no peer and the owner keeps serving; gone, the listing of B's instance retires the owner's poll
/// on `Attachment(Foreign)`.
#[test]
fn the_newest_attachment_entry_of_a_host_decides_its_peer() {
    let record = shard_record(4);
    let entries = [registrant(own(), 1, true)];
    let report = report_of(&entries);
    let listed =
        [owner_host(), c_host(), b_host()].map(|host| instance_of(host).as_str().to_owned());
    for kind in [EventKind::Ended, EventKind::Gone] {
        let mut volume = with_events(
            &b_unenrolled(),
            &[
                (EventKind::Attach, owner_host()),
                (EventKind::Attach, c_host()),
                (EventKind::Attach, b_host()),
                (EventKind::Detach, b_host()),
                (EventKind::Attach, b_host()),
            ],
        );
        let newest = volume.events.last_mut().unwrap();
        newest.kind = kind;
        newest.instance = Some(instance_of(b_host()));
        assert_eq!(
            <VolumeRecord as Record>::decode(&Record::encode(&volume)),
            Ok(volume.clone()),
            "{kind:?}"
        );
        let bound = resolved(owner_host(), &volume);
        assert_eq!(bound, [peer(c_host())], "{kind:?}");
        let verdict = poll::poll(
            &holder_of(owner_host()),
            Target::of(&record),
            own(),
            Ok(&report),
            &reads(Some(&record), Some(&volume), Some(&listed), &bound),
            &bounds_of(limits()),
        );
        if kind == EventKind::Ended {
            assert_eq!(verdict, Verdict::Continue);
            continue;
        }
        let Verdict::Retire(retirement) = verdict else {
            panic!("a gone attachment's listed instance retires");
        };
        assert_eq!(
            retirement.trigger(),
            &Trigger::Attachment(Mismatch::Foreign(instance_of(b_host()).as_str().to_owned()))
        );
    }
}

/// Resolving B's instance lets [`restart`] proceed while B's pair enrollment is pending.
#[test]
fn a_restart_over_the_computed_peers_admits_a_bound_unenrolled_attach() {
    let pending = VolumeRecord {
        pairs: restart_tests::volume_record().pairs,
        ..lineage(&[(b_host(), b_pair())])
    };
    let bound = resolved(owner_host(), &pending);
    let store_of = || store(shard_record(4), pending.clone());
    let reached = store_of();
    let mut card = Card::new();
    let restarted = restart(&inputs_of(owner_host()), &bound)
        .run(&mut client(&reached), &sample(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    assert_eq!(shard_now(&reached).attempts, 5);
    assert_eq!(restarted.into_parts().2, (vec![own()], 0));

    let unbound = without_b(owner_host(), &pending);
    let refusing = store_of();
    let before = shard_now(&refusing);
    let mut card = Card::new();
    let refused = restart(&inputs_of(owner_host()), &unbound)
        .run(&mut client(&refusing), &sample(), &mut card)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Volume(Trigger::Events),
            flip: Some(Target::of(&shard_record(4))),
            recovery: None,
        }
    );
    assert!(card.log.is_empty());
    assert_eq!(shard_now(&refusing), before);
}

#[test]
fn the_poll_admits_a_bound_peer_and_retires_on_an_unbound_recorded_attach() {
    let volume = b_unenrolled();
    let record = shard_record(4);
    let entries = [registrant(own(), 1, true)];
    let report = report_of(&entries);
    let listed =
        [owner_host(), c_host(), b_host()].map(|host| instance_of(host).as_str().to_owned());
    let verdict = |listed: Option<&[String]>, peers: &[Peer]| {
        poll::poll(
            &holder_of(owner_host()),
            Target::of(&record),
            own(),
            Ok(&report),
            &reads(Some(&record), Some(&volume), listed, peers),
            &bounds_of(limits()),
        )
    };
    let bound = resolved(owner_host(), &volume);
    assert_eq!(verdict(Some(&listed), &bound), Verdict::Continue);
    assert_eq!(verdict(None, &bound), Verdict::Unobserved);

    let unbound = without_b(owner_host(), &volume);
    let Verdict::Retire(retirement) = verdict(Some(&listed), &unbound) else {
        panic!("an unbound listed attachment retires");
    };
    assert_eq!(
        retirement.trigger(),
        &Trigger::Attachment(Mismatch::Foreign(instance_of(b_host()).as_str().to_owned()))
    );
    let Verdict::Retire(retirement) = verdict(None, &unbound) else {
        panic!("an unbound recorded attach retires under an unread listing");
    };
    assert_eq!(retirement.trigger(), &Trigger::Events);
}

/// Resolving B's instance lets [`takeover`] proceed while B's pair enrollment is pending.
#[test]
fn a_takeover_over_the_computed_peers_admits_a_bound_unenrolled_attach() {
    let record = takeover_tests::shard_record();
    let mut watch = watch_of(&[record], 3);
    let (published, _) = silent_owners(&mut watch, 40);
    let nominated = published[0];
    let volume = b_unenrolled();
    let store = store(record, volume.clone());

    let unbound = without_b(c_host(), &volume);
    let mut card = card_after_cas(&store, c_pair(), c_host(), &a_holds_c_registered());
    let witness = watch.revalidate(&nominated, 40, clock(40), true).unwrap();
    let refused = takeover(&inputs_of(c_host()), &unbound, &witness, 40)
        .unwrap()
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (takeover::Check::Volume(Trigger::Events), None)
    );
    assert!(card.log.is_empty());
    assert_eq!(shard_now(&store), record);

    let bound = resolved(c_host(), &volume);
    let build = |now| takeover(&inputs_of(c_host()), &bound, &witness, now);
    assert!(
        watch.revalidate(&nominated, 40, clock(40), false).is_none(),
        "an unhealthy observer mints no witness"
    );
    assert!(build(witness.until_us).is_none(), "an expired witness");
    let mut card = card_after_cas(&store, c_pair(), c_host(), &a_holds_c_registered());
    build(40)
        .unwrap()
        .run(&mut client(&store), &stored_c(), &mut card)
        .unwrap();
    assert_eq!(card.log, FULL);
    assert_eq!(shard_now(&store).owner, c_host());
}
