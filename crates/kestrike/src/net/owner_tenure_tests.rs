use super::*;
use crate::failover::identity::Exhid;
use crate::failover::records::{
    CreationSource, Layout, Lineage, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::serving::{Cause, Event, State, Token};
use crate::net::owner_tests::PRINCIPALS;
use crate::net::owner_view::tenure_of;
use crate::net::ownership::{
    ActivatedEpoch, OwnershipBody, Shard, ShardGeneration, Tenure, Validity,
    VolumeState as WireState,
};
use crate::net::put_tests::{Scene, request, scene};
use crate::storage::store::{Key as StoreKey, Read, sim::Shared};

impl<'a, P: Platform, D: Disk, T: Datagrams<'a>> Owner<'_, 'a, '_, P, D, T> {
    /// Reverses, in place, the order of the held INVALIDATEs on the coverage page of `key`, leaving every other held
    /// entry where it stands, and returns how many it reversed; 0 when no fencing is installed. The coverage keeps each
    /// entry as its hold merged it, so the next write of that page alone merges the page's entries in reversed order.
    pub(crate) fn reverse_held_on_page(&mut self, key: &[u8; 32]) -> usize {
        let Some(pages) = self.coverage.as_ref().map(|fencing| fencing.pages()) else {
            return 0;
        };
        let on = page_of(key, pages);
        let at: Vec<usize> = (0..self.invalidations.len())
            .filter(|&i| page_of(&self.invalidations[i].0.0, pages) == on)
            .collect();
        for (k, &i) in at.iter().enumerate().take(at.len() / 2) {
            self.invalidations.swap(i, at[at.len() - 1 - k]);
        }
        at.len()
    }
}

/// `tenure` two activated epochs higher, the next activation of its generation.
fn two_above(tenure: Tenure) -> Tenure {
    Tenure {
        epoch: ActivatedEpoch::new(tenure.epoch.get() + 2).unwrap(),
        ..tenure
    }
}

pub(crate) fn token(scene: &Scene<'_, '_>) -> Token {
    scene.owner.volume.serving_token().unwrap()
}

pub(crate) fn serve_at(scene: &mut Scene<'_, '_>, generation: u64, attempts: u32) {
    (scene.owner.volume).serve_tenure(crate::storage::session_at(generation, attempts));
    scene.owner.observe_authority(scene.turn * 100);
    scene.reopen(0);
}

fn inject_query(scene: &mut Scene<'_, '_>, kind: Kind, high: Option<Tenure>, authentic: bool) {
    inject_query_from(scene, 0, kind, high, authentic);
}

fn inject_query_from(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    kind: Kind,
    high: Option<Tenure>,
    authentic: bool,
) {
    let body = query_body(kind, token(scene).shard, high);
    let header = session_header(scene, peer, kind, body.len());
    inject_sealed_from(scene, peer, &header, &body, authentic);
}

/// The encoded body of a question of `kind` about `shard` that names `high` as the asker's highest tenure.
pub(crate) fn query_body(
    kind: Kind,
    shard: Shard,
    high: Option<Tenure>,
) -> [u8; OwnershipBody::FIXED_LEN] {
    let query = OwnershipBody {
        shard,
        volume: None,
        tenure: high,
        report_age_us: 0,
        responder: None,
        validity: Validity::new(0).unwrap(),
    };
    let mut body = [0; OwnershipBody::FIXED_LEN];
    query.encode(kind, &mut body).unwrap();
    body
}

/// A version 3 header of `kind` carrying peer `peer`'s session fields and a body of `len` bytes.
pub(crate) fn session_header(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    kind: Kind,
    len: usize,
) -> Header {
    let base = scene.get(peer, 0, 0);
    Header {
        datagram_len: len as u32,
        principal: base.principal,
        key_epoch: base.key_epoch,
        owner_nonce: base.owner_nonce,
        client_nonce: base.client_nonce,
        sequence: base.sequence,
        epoch: base.epoch,
        ..super::super::serve::header(kind, 0, [0; 32])
    }
}

fn inject_sealed(scene: &mut Scene<'_, '_>, header: &Header, body: &[u8], authentic: bool) {
    inject_sealed_from(scene, 0, header, body, authentic);
}

fn inject_sealed_from(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    header: &Header,
    body: &[u8],
    authentic: bool,
) {
    let datagram = sealed(
        scene,
        peer,
        header,
        body,
        authentic,
        Direction::ClientToOwner,
    );
    scene.nets[peer].borrow_mut().inject(1, &datagram);
}

/// The datagram of `header` and `body` tagged under peer `peer`'s key for `direction`, its tag broken unless
/// `authentic`.
fn sealed(
    scene: &Scene<'_, '_>,
    peer: usize,
    header: &Header,
    body: &[u8],
    authentic: bool,
    direction: Direction,
) -> Vec<u8> {
    let mut encoded = [0; HEADER_LEN];
    encode(scene.owner.crc, header, [body, &[]], &mut encoded).unwrap();
    let mut digest = [0; 16];
    let input = scene.rings[peer]
        .mac_input(
            PeerId(0),
            &encoded,
            [body, &[]],
            (scene.owner.config.endpoint, direction),
            &mut digest,
        )
        .unwrap();
    let mut tag = scene.rings[peer].tag(PeerId(0), &input).unwrap();
    if !authentic {
        tag[0] ^= 1;
    }
    seal(&mut encoded, tag);
    let mut datagram = encoded.to_vec();
    datagram.extend_from_slice(body);
    datagram
}

fn controls(scene: &mut Scene<'_, '_>) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    let crc = scene.owner.crc;
    scene.nets[0].borrow_mut().retain(0, |bytes| {
        if parse(crc, bytes, false)
            .is_ok_and(|f| f.header().kind.is_ownership() || f.header().kind == Kind::Ready)
        {
            replies.push(bytes.to_vec());
            false
        } else {
            true
        }
    });
    replies
}

pub(crate) fn shard_at(token: Token, generation: u64, attempts: u32) -> ShardRecord {
    ShardRecord {
        shard: token.shard,
        generation: ShardGeneration::new(generation).unwrap(),
        attempts,
        ..crate::storage::store_tests::record()
    }
}

pub(crate) fn volume_record(name: &str, state: VolumeState) -> VolumeRecord {
    VolumeRecord {
        volume: VolumeId::new(name).unwrap(),
        state,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout: Layout {
            units: 64,
            slots: 3,
            slot_units: 2,
            entries: 41,
        },
        next: 0,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: Vec::new(),
    }
}

pub(crate) fn observe(
    scene: &mut Scene<'_, '_>,
    shard: Option<ShardRecord>,
    volume: Option<VolumeRecord>,
    exhid: Exhid,
) {
    let binding = shard.map(|record| (record.owner, exhid));
    observe_bound(scene, shard, volume, binding);
}

fn observe_bound(
    scene: &mut Scene<'_, '_>,
    shard: Option<ShardRecord>,
    volume: Option<VolumeRecord>,
    binding: Option<(crate::failover::records::Host, Exhid)>,
) {
    let (shard_read, volume_read) = reads(shard, volume);
    scene.owner.observe_shard_view(
        VolumeId::new("vol-0a").unwrap(),
        shard_read.as_ref(),
        volume_read.as_ref(),
        binding,
        scene.turn * 100,
    );
}

fn reads(
    shard: Option<ShardRecord>,
    volume: Option<VolumeRecord>,
) -> (Option<Read<ShardRecord>>, Option<Read<VolumeRecord>>) {
    let store = Shared::new();
    let mut client = crate::storage::store_tests::client(&store);
    let shard_read = shard.map(|record| client.create_shard(record).unwrap());
    let volume_read = volume.map(|record| {
        client
            .create(StoreKey::Volume(record.volume), record)
            .unwrap()
    });
    (shard_read, volume_read)
}

/// Direct observation updates the ownership view while preserving the authority's report.
fn observe_view(
    scene: &mut Scene<'_, '_>,
    shard: Option<ShardRecord>,
    volume: Option<VolumeRecord>,
) -> Option<Cause> {
    let binding = shard.map(|record| (record.owner, token(scene).exhid));
    let (shard_read, volume_read) = reads(shard, volume);
    let now_us = scene.turn * 100;
    let owner = &mut scene.owner;
    owner.ownership_view.observe(
        owner.volume.tenure(),
        VolumeId::new("vol-0a").unwrap(),
        shard_read.as_ref(),
        volume_read.as_ref(),
        binding,
        now_us,
    )
}

fn view_bits(scene: &Scene<'_, '_>) -> u8 {
    let token = token(scene);
    let owner = &scene.owner;
    let admitted = owner
        .volume
        .admit_authority(crate::failover::serving::Operation::Read, Some(token))
        .is_ok();
    owner
        .ownership_view
        .body(token, owner.volume.authority_report(), admitted)
        .validity
        .bits()
}

fn install_view(scene: &mut Scene<'_, '_>) {
    let token = token(scene);
    install_view_at(scene, token);
}

fn install_view_at(scene: &mut Scene<'_, '_>, token: Token) {
    let record = shard_at(token, token.generation.get(), token.epoch.get() / 2);
    observe(
        scene,
        Some(record),
        Some(volume_record("vol-0a", VolumeState::Active)),
        token.exhid,
    );
}

struct Holder {
    bits: u8,
    volume: Option<(String, WireState)>,
    tenure: Option<Tenure>,
}

fn holder(scene: &mut Scene<'_, '_>, queries: usize) -> Holder {
    scene.owner.sessions.end_sessions();
    for _ in 0..queries {
        inject_query(scene, Kind::WhoHolds, None, true);
    }
    scene.polls(1);
    scene.nets[0].borrow_mut().clear(1);
    scene.turns(2);
    let replies = controls(scene);
    assert_eq!(
        replies.len(),
        1,
        "one bootstrap-class answer per shard turn"
    );
    let frame = parse(scene.owner.crc, &replies[0], false).unwrap();
    assert_eq!(frame.header().kind, Kind::Holder);
    let body = OwnershipBody::decode(Kind::Holder, frame.raw_body()).unwrap();
    Holder {
        bits: body.validity.bits(),
        volume: body.volume.map(|v| (v.name.to_owned(), v.state)),
        tenure: body.tenure,
    }
}

fn withdrawn(scene: &Scene<'_, '_>) -> bool {
    scene.owner.authority_report().withdrawal.is_some()
}

fn pending<P: Platform, D: Disk, T>(owner: &Owner<'_, '_, '_, P, D, T>) -> u32 {
    for (at, slot) in owner.ownership.iter().enumerate() {
        assert_eq!(
            owner.ownership_queued[at / 64] >> (at % 64) & 1 == 1,
            slot.is_some(),
            "peer {at}'s queued bit matches its slot"
        );
    }
    let occupied = owner.ownership.iter().flatten().count() as u32;
    let bits: u32 = owner
        .ownership_queued
        .iter()
        .map(|word| word.count_ones())
        .sum();
    assert_eq!(bits, occupied, "bits past the last peer stay clear");
    assert_eq!(
        owner.ownership_waiting, occupied,
        "the waiting count equals the pending replies"
    );
    occupied
}

fn send_error(scene: &mut Scene<'_, '_>, token: Token, epoch: u64, request: u64) -> u64 {
    let owner = &mut scene.owner;
    let frame = Out {
        peer: PeerId(0),
        epoch,
        header: Header {
            status: Status::Missing as u16,
            ..super::super::serve::header(Kind::Error, request, [0; 32])
        },
        payload: [Payload::EMPTY, Payload::EMPTY],
        body_crc: 0,
        digest: None,
    };
    let sent = owner.report.sent;
    let mut sender = Sender {
        volume: &owner.volume,
        token: Some(token),
        crc: owner.crc,
        ring: &owner.ring,
        sessions: &mut owner.sessions,
        endpoint: owner.config.endpoint,
        transport: &mut owner.transport,
        headers: &mut owner.headers,
        exhausted: &mut owner.exhausted,
        report: &mut owner.report,
    };
    sender.send(&mut std::iter::once(frame));
    owner.report.sent - sent
}

fn ready_for(scene: &Scene<'_, '_>, tenure: Tenure) -> Bootstrap {
    let peer = PeerId(0);
    let active = scene.owner.sessions.active(peer).unwrap();
    let (owner_nonce, client_nonce) = scene.owner.sessions.nonces(peer).unwrap();
    Bootstrap {
        tenure: Some(tenure),
        peer,
        kind: Kind::Ready,
        owner_nonce,
        client_nonce,
        epoch: active.epoch,
        caps: active.caps,
        sequence: 1,
    }
}

#[test]
fn ready_and_frames_need_current_token() {
    scene(&PRINCIPALS, |mut scene| {
        let token = token(&scene);
        let epoch = scene.owner.sessions.active(PeerId(0)).unwrap().epoch;
        assert_eq!(send_error(&mut scene, token, epoch, 1), 1);
        scene.owner.volume.serve_later_tenure();
        assert_eq!(
            send_error(&mut scene, token, epoch, 2),
            0,
            "the encoder requires the exact current token"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let old = tenure_of(token(&scene));
        assert!(scene.owner.reply(ready_for(&scene, old)));
        scene.owner.volume.serve_later_tenure();
        let sent = scene.owner.report.sent;
        assert!(scene.owner.send_replies(0).is_some());
        assert_eq!(scene.owner.report.sent, sent);
        assert_eq!(scene.owner.waiting, 0, "the READY slot is released");
        assert!(scene.owner.replies.iter().all(Option::is_none));
    });
    scene(&PRINCIPALS, |mut scene| {
        let peer = PeerId(0);
        let token = token(&scene);
        let ready = ready_for(&scene, tenure_of(token));
        assert!(scene.owner.reply(ready));
        assert!(scene.owner.send_replies(0).is_some());
        scene.turns(2);
        let ready_bytes = controls(&mut scene);
        let frame = parse(scene.owner.crc, &ready_bytes[0], false).unwrap();
        assert_eq!(
            crate::net::ownership::ReadyBody::decode(frame.raw_body())
                .unwrap()
                .tenure,
            tenure_of(token)
        );
        assert!(scene.owner.reply(ready));
        (scene.owner.volume).authority_event(Event::Expire { now: 0 });
        let sent = scene.owner.report.sent;
        assert_eq!(scene.owner.send_replies(0), None);
        assert_eq!(scene.owner.report.sent, sent);
        (scene.owner).authority_event(Event::Withdraw(Cause::Flipped), scene.turn * 100);
        assert!(scene.owner.sessions.active(peer).is_none());
        assert_eq!(scene.owner.waiting, 0);
    });
}

fn in_flight(scene: &mut Scene<'_, '_>) -> (Header, Header) {
    let get = scene.get(0, request(0, 8), 44);
    scene.inject(0, &get);
    let begin = scene.frame(1, Kind::PutBegin, request(1, 3), 5, |header| {
        header.remaining_ms = 10_000;
        header.offset = 4;
    });
    scene.inject(1, &begin);
    for net in &scene.nets {
        net.borrow_mut().advance(scene.turn);
    }
    scene.owner.receive_batch(scene.turn * 100);
    assert_eq!(scene.owner.report.dropped, 0);
    (get, begin)
}

#[test]
fn tenure_change_ends_sessions() {
    scene(&PRINCIPALS, |mut scene| {
        let (get, begin) = in_flight(&mut scene);
        let sent = scene.owner.report.sent;
        scene.owner.send_batch(scene.turn * 100);
        assert!(scene.owner.report.sent >= sent + 2);
        assert!(scene.sent(0).iter().any(|h| h.request == get.request));
        assert!(scene.sent(1).iter().any(|h| h.request == begin.request));
    });
    scene(&PRINCIPALS, |mut scene| {
        let old = token(&scene);
        let (get, begin) = in_flight(&mut scene);
        let sent = scene.owner.report.sent;
        scene.owner.volume.serve_later_tenure();
        let new = token(&scene);
        assert_eq!(old.generation, new.generation, "a T6 rerun keeps g");
        assert!(new.epoch > old.epoch);
        scene.owner.send_batch(scene.turn * 100);
        assert_eq!(
            scene.owner.report.sent, sent,
            "old GET and PUT replies cannot use the successor token"
        );
        scene.owner.observe_authority(scene.turn * 100);
        assert_eq!(scene.owner.sessions.active(PeerId(0)), None);
        assert_eq!(scene.owner.sessions.active(PeerId(1)), None);
        assert_eq!(scene.owner.waiting, 0);
        scene.reopen(0);
        assert_eq!(scene.owner.sessions.tenure(PeerId(0)), Some(tenure_of(new)));
        scene.turns(4);
        assert!(scene.sent(0).iter().all(|h| h.request != get.request));
        assert!(scene.sent(1).iter().all(|h| h.request != begin.request));
        let new_epoch = scene.owner.sessions.active(PeerId(0)).unwrap().epoch;
        assert_ne!(new_epoch, get.epoch);
        assert_eq!(send_error(&mut scene, new, get.epoch, get.request), 0);
        assert_eq!(
            send_error(&mut scene, new, new_epoch, get.request),
            1,
            "only the old session stamp keeps the reply off the successor session"
        );
    });
}

#[test]
fn repeat_confirm_keeps_its_bound_tenure() {
    scene(&PRINCIPALS, |mut scene| {
        let peer = PeerId(0);
        let bound = scene.owner.sessions.tenure(peer).unwrap();
        let caps = scene.owner.sessions.active(peer).unwrap().caps.body();
        let confirm = |scene: &mut Scene<'_, '_>, sequence: u64| {
            let base = scene.get(0, 0, 0);
            let header = Header {
                principal: base.principal,
                key_epoch: base.key_epoch,
                owner_nonce: base.owner_nonce,
                client_nonce: base.client_nonce,
                epoch: base.epoch,
                sequence,
                datagram_len: caps.len() as u32,
                ..super::super::serve::header(Kind::Confirm, 0, [0; 32])
            };
            inject_sealed(scene, &header, &caps, true);
            scene.nets[0].borrow_mut().advance(scene.turn);
            scene.owner.receive_batch(scene.turn * 100);
        };
        confirm(&mut scene, 100);
        assert_eq!(
            scene.owner.replies[0].and_then(|reply| reply.tenure),
            Some(bound),
            "a repeat CONFIRM under its tenure is answered"
        );
        scene.owner.replies[0] = None;
        scene.owner.waiting = 0;
        scene.owner.volume.serve_later_tenure();
        confirm(&mut scene, 101);
        assert!(scene.owner.replies[0].is_none());
        assert_eq!(scene.owner.sessions.tenure(peer), Some(bound));
    });
}

#[test]
fn holder_reply_from_shard_view() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let own = tenure_of(token(&scene));
        let answer = holder(&mut scene, 20);
        assert_eq!(answer.bits, Validity::ALL);
        assert_eq!(answer.volume, Some(("vol-0a".into(), WireState::Active)));
        assert_eq!(answer.tenure, Some(own));
    });
    for ((generation, attempts), foreign) in [
        ((2, 0), false),
        ((1, 5), false),
        ((2, 0), true),
        ((1, 5), true),
    ] {
        scene(&PRINCIPALS, |mut scene| {
            serve_at(&mut scene, 2, 1);
            let token = token(&scene);
            let record = shard_at(token, generation, attempts);
            let exhid = if foreign {
                Exhid::new([55; 16]).unwrap()
            } else {
                token.exhid
            };
            observe(
                &mut scene,
                Some(record),
                Some(volume_record("vol-0a", VolumeState::Active)),
                exhid,
            );
            assert!(
                withdrawn(&scene),
                "a view below the tenure is a regression, whichever host it names"
            );
            let answer = holder(&mut scene, 1);
            assert_eq!(answer.bits, 0, "a stale view grants no authority");
            assert_ne!(answer.tenure, Some(tenure_of(token)));
        });
    }
    for above in [0, 1] {
        scene(&PRINCIPALS, |mut scene| {
            serve_at(&mut scene, 2, 1);
            let token = token(&scene);
            let record = ShardRecord {
                owner: crate::failover::records::Host::new(99).unwrap(),
                ..shard_at(token, 2, token.epoch.get() / 2 + above)
            };
            observe(
                &mut scene,
                Some(record),
                Some(volume_record("vol-0a", VolumeState::Active)),
                Exhid::new([55; 16]).unwrap(),
            );
            assert!(
                withdrawn(&scene),
                "another host at or above the tenure deposes it"
            );
            assert_eq!(holder(&mut scene, 1).bits, 0);
        });
    }
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let old = token(&scene);
        serve_at(&mut scene, 1, old.epoch.get() / 2);
        let new = token(&scene);
        let current = shard_at(new, 1, new.epoch.get() / 2);
        observe(
            &mut scene,
            Some(current),
            Some(volume_record("vol-0a", VolumeState::Active)),
            new.exhid,
        );
        assert_eq!(
            holder(&mut scene, 1).bits,
            Validity::ALL,
            "a view of the new tenure"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let old = token(&scene);
        serve_at(&mut scene, 1, old.epoch.get() / 2);
        let new = token(&scene);
        install_view_at(&mut scene, old);
        assert!(
            withdrawn(&scene),
            "the old tenure's record is a regression for the new tenure"
        );
        let answer = holder(&mut scene, 1);
        assert_eq!(
            answer.bits, 0,
            "a view of the replaced tenure grants no authority"
        );
        assert_ne!(answer.tenure, Some(tenure_of(new)));
    });
    scene(&PRINCIPALS, |mut scene| {
        let token = token(&scene);
        let newer = shard_at(token, token.generation.get(), token.epoch.get() / 2 + 1);
        observe(
            &mut scene,
            Some(newer),
            Some(volume_record("vol-0a", VolumeState::Active)),
            token.exhid,
        );
        assert!(withdrawn(&scene));
        install_view(&mut scene);
        let answer = holder(&mut scene, 1);
        assert_eq!(answer.bits, 0);
        assert_eq!(
            answer.tenure.map(|tenure| tenure.epoch.get()),
            Some(token.epoch.get() + 2),
            "a regressed read leaves the newer record in the view"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        (scene.owner.volume).authority_event(Event::Expire { now: 0 });
        assert_eq!(holder(&mut scene, 1).bits, 0, "a lapsed Report");
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let exhid = token(&scene).exhid;
        observe(&mut scene, None, None, exhid);
        assert_eq!(
            holder(&mut scene, 1).bits,
            Validity::ALL,
            "a store outage after a current view is no evidence"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let exhid = token(&scene).exhid;
        observe(&mut scene, None, None, exhid);
        assert_eq!(
            holder(&mut scene, 1).bits,
            0,
            "a store outage before any view grants no authority"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let token = token(&scene);
        let record = shard_at(token, token.generation.get(), token.epoch.get() / 2);
        let active = volume_record("vol-0a", VolumeState::Active);
        observe(&mut scene, Some(record), None, token.exhid);
        assert_eq!(
            holder(&mut scene, 1).bits,
            0,
            "a confirming shard read alone sets no view"
        );
        observe(&mut scene, None, Some(active.clone()), token.exhid);
        assert_eq!(
            holder(&mut scene, 1).bits,
            0,
            "a confirming volume read alone sets no view"
        );
        observe(&mut scene, Some(record), Some(active), token.exhid);
        assert_eq!(
            holder(&mut scene, 1).bits,
            Validity::ALL,
            "both reads returned set the view"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let exhid = token(&scene).exhid;
        observe(
            &mut scene,
            None,
            Some(volume_record("vol-0a", VolumeState::Active)),
            exhid,
        );
        assert_eq!(
            holder(&mut scene, 1).bits,
            Validity::ALL,
            "a failed shard read alone leaves the view"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let token = token(&scene);
        let record = shard_at(token, token.generation.get(), token.epoch.get() / 2);
        observe(&mut scene, Some(record), None, token.exhid);
        assert_eq!(
            holder(&mut scene, 1).bits,
            Validity::ALL,
            "a failed volume read alone leaves the view"
        );
        observe(
            &mut scene,
            Some(record),
            Some(volume_record("vol-0b", VolumeState::Active)),
            token.exhid,
        );
        assert_eq!(
            holder(&mut scene, 1).bits,
            0,
            "a read of another volume's record clears the view"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let token = token(&scene);
        let record = shard_at(token, token.generation.get(), token.epoch.get() / 2);
        observe(
            &mut scene,
            Some(record),
            Some(volume_record("vol-0a", VolumeState::Fresh)),
            token.exhid,
        );
        assert_eq!(
            holder(&mut scene, 1).bits,
            Validity::ALL,
            "the shard record makes a Fresh own volume active"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let token = token(&scene);
        let record = shard_at(token, token.generation.get(), token.epoch.get() / 2);
        observe_bound(
            &mut scene,
            Some(record),
            Some(volume_record("vol-0a", VolumeState::Active)),
            None,
        );
        let answer = holder(&mut scene, 1);
        assert_eq!(answer.bits, Validity::ALL, "the session names its own host");
        assert_eq!(answer.tenure, Some(tenure_of(token)));
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let token = token(&scene);
        let mut flipped = shard_at(token, token.generation.get() + 1, 0);
        let (spare, host) = flipped.spare.take().unwrap();
        (flipped.active, flipped.owner) = (spare, host);
        let successor = Exhid::new([66; 16]).unwrap();
        observe(
            &mut scene,
            Some(flipped),
            Some(volume_record("vol-0a", VolumeState::Retired)),
            successor,
        );
        assert!(withdrawn(&scene));
        let answer = holder(&mut scene, 1);
        assert_eq!(answer.bits, 0);
        assert_eq!(answer.volume, Some(("vol-0a".into(), WireState::Retired)));
        let newer = answer.tenure.unwrap();
        assert!(newer.generation > token.generation);
        assert_eq!(newer.host, successor, "do not route: the newer owner");
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let token = token(&scene);
        let successor = ShardRecord {
            active: VolumeId::new("vol-0b").unwrap(),
            spare: None,
            ..shard_at(token, token.generation.get() + 1, 1)
        };
        let attachment = Exhid::new([67; 16]).unwrap();
        observe(&mut scene, Some(successor), None, attachment);
        assert!(withdrawn(&scene));
        let newer = holder(&mut scene, 1).tenure.unwrap();
        assert_eq!(
            newer.host, attachment,
            "a same-host successor names its own attachment"
        );
        observe_bound(&mut scene, Some(successor), None, None);
        assert_eq!(
            holder(&mut scene, 1).tenure.map(|tenure| tenure.host),
            Some(attachment),
            "a repeated record keeps its binding"
        );
    });
}

#[test]
fn shard_view_judges_reads_against_the_session() {
    use crate::failover::records::Host;
    use crate::net::owner_view::OwnerView;
    let session = crate::storage::session_at(2, 1);
    let target = session.target();
    let at = |generation: u64, attempts: u32| ShardRecord {
        generation: ShardGeneration::new(generation).unwrap(),
        attempts,
        ..crate::storage::store_tests::record()
    };
    let own = at(target.generation.get(), target.attempts);
    let shard = |record: ShardRecord| {
        crate::storage::store_tests::client(&Shared::new())
            .create_shard(record)
            .unwrap()
    };
    let volume = |state: VolumeState| {
        crate::storage::store_tests::client(&Shared::new())
            .create(StoreKey::Volume(own.active), volume_record("vol-0a", state))
            .unwrap()
    };
    let active = volume(VolumeState::Active);
    let flipped = Some(Cause::Flipped);

    let mut view = OwnerView::default();
    let foreign = ShardRecord {
        shard: Shard::new(own.shard.get() + 1).unwrap(),
        ..at(9, 9)
    };
    assert_eq!(
        view.observe(&session, own.active, Some(&shard(foreign)), None, None, 0),
        None
    );
    let later = at(target.generation.get() + 1, 0);
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(later)),
            Some(&active),
            None,
            0
        ),
        flipped,
        "another shard's record sets no watermark, and a flip deposes without a token"
    );

    let mut view = OwnerView::default();
    assert_eq!(
        view.observe(
            &session,
            own.active,
            None,
            Some(&volume(VolumeState::Retired)),
            None,
            0
        ),
        flipped,
        "a retired own volume deposes before any shard read"
    );

    let mut view = OwnerView::default();
    let elsewhere = ShardRecord {
        owner: Host::new(99).unwrap(),
        ..own
    };
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(elsewhere)),
            Some(&active),
            None,
            0
        ),
        flipped,
        "the session's tenure under another host deposes without a binding"
    );

    let mut view = OwnerView::default();
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(own)),
            Some(&active),
            None,
            0
        ),
        None
    );
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(at(target.generation.get(), 0))),
            Some(&volume(VolumeState::Retired)),
            None,
            0,
        ),
        flipped,
        "a retired own volume outranks a regressed shard read, so the machine records the later tenure"
    );
    assert_eq!(
        view.observe(&session, own.active, None, None, None, 0),
        flipped,
        "a regressed shard read keeps the paired retirement"
    );

    let mut view = OwnerView::default();
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(own)),
            Some(&active),
            None,
            0
        ),
        None
    );
    let successor = ShardRecord {
        active: VolumeId::new("vol-0b").unwrap(),
        spare: None,
        ..later
    };
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(successor)),
            Some(&active),
            None,
            0
        ),
        flipped
    );
    assert_eq!(
        view.observe(&session, own.active, None, None, None, 0),
        flipped,
        "a flip to another volume retires the own volume"
    );

    let mut view = OwnerView::default();
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(at(target.generation.get(), 0))),
            Some(&active),
            None,
            0
        ),
        Some(Cause::Regression),
        "a record below the session is a regression"
    );

    let mut view = OwnerView::default();
    let elsewhere = ShardRecord {
        active: VolumeId::new("vol-0b").unwrap(),
        spare: None,
        ..own
    };
    assert_eq!(
        view.observe(
            &session,
            own.active,
            Some(&shard(elsewhere)),
            Some(&active),
            None,
            0
        ),
        flipped,
        "the session's tenure naming another active volume deposes"
    );

    let mut view = OwnerView::default();
    let foreign = crate::storage::store_tests::client(&Shared::new())
        .create(
            StoreKey::Volume(VolumeId::new("vol-0f").unwrap()),
            volume_record("vol-0f", VolumeState::Retired),
        )
        .unwrap();
    assert_eq!(
        view.observe(&session, own.active, None, Some(&foreign), None, 0),
        None,
        "another volume's record counts as unread"
    );
    assert_eq!(
        view.observe(
            &session,
            own.active,
            None,
            Some(&volume(VolumeState::Retired)),
            None,
            0
        ),
        flipped
    );
}

#[test]
fn shard_view_reads_only_the_own_volume() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let token = token(&scene);
        let record = shard_at(token, token.generation.get(), token.epoch.get() / 2);
        observe(
            &mut scene,
            Some(record),
            Some(volume_record("vol-0c", VolumeState::Retired)),
            token.exhid,
        );
        assert!(
            !withdrawn(&scene),
            "a predecessor's retirement deposes nothing"
        );
        let neighbor = ShardRecord {
            shard: Shard::new(token.shard.get() + 1).unwrap(),
            active: VolumeId::new("vol-0d").unwrap(),
            ..record
        };
        observe(
            &mut scene,
            Some(neighbor),
            Some(volume_record("vol-0d", VolumeState::Retired)),
            token.exhid,
        );
        assert!(
            !withdrawn(&scene),
            "a neighbor's retirement deposes nothing"
        );
        install_view(&mut scene);
        let answer = holder(&mut scene, 1);
        assert_eq!(answer.bits, Validity::ALL);
        assert_eq!(answer.volume, Some(("vol-0a".into(), WireState::Active)));
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let token = token(&scene);
        observe(
            &mut scene,
            Some(shard_at(
                token,
                token.generation.get(),
                token.epoch.get() / 2,
            )),
            Some(volume_record("vol-0a", VolumeState::Retired)),
            token.exhid,
        );
        assert!(withdrawn(&scene));
        serve_at(&mut scene, 2, 0);
        let token = self::token(&scene);
        let record = ShardRecord {
            active: VolumeId::new("vol-0b").unwrap(),
            spare: None,
            ..shard_at(token, 2, token.epoch.get() / 2)
        };
        observe(
            &mut scene,
            Some(record),
            Some(volume_record("vol-0b", VolumeState::Active)),
            token.exhid,
        );
        assert!(withdrawn(&scene), "the attached volume stays retired");
        let answer = holder(&mut scene, 1);
        assert_eq!(answer.bits, 0);
        assert_eq!(
            answer.volume,
            Some(("vol-0a".into(), WireState::Retired)),
            "an owner's attached volume is fixed for its life"
        );
    });
}

#[test]
fn holder_age_tracks_serving_clock_at_encoding() {
    struct Clock;
    impl crate::storage::ServingClock for Clock {
        fn now_us(&self) -> Option<u64> {
            Some(20)
        }
    }
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        scene.owner.set_serving_clock(Box::new(Clock));
        inject_query(&mut scene, Kind::WhoHolds, None, true);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert_eq!(scene.owner.send_ownership(0), Some(1));
        scene.nets[0].borrow_mut().advance(scene.turn + 4);
        let replies = controls(&mut scene);
        let frame = parse(scene.owner.crc, &replies[0], false).unwrap();
        let body = OwnershipBody::decode(Kind::Holder, frame.raw_body()).unwrap();
        assert_eq!(body.report_age_us, 20);
        assert_eq!(body.validity.bits(), Validity::ALL);
    });
}

#[test]
fn wrong_owner_above_high_water() {
    let at = |generation: u64, epoch: u32, host: Exhid| Tenure {
        generation: ShardGeneration::new(generation).unwrap(),
        epoch: ActivatedEpoch::new(epoch).unwrap(),
        host,
    };
    let host = crate::storage::gate_fixture::own().exhid;
    for (high, authentic, answered) in [
        (Some(at(2, 100, host)), true, true),
        (Some(at(3, 4, host)), true, true),
        (None, true, true),
        (Some(at(3, 4, host)), false, false),
        (Some(at(3, 6, host)), true, false),
        (Some(at(3, 8, host)), true, false),
        (Some(at(4, 0, host)), true, false),
    ] {
        scene(&PRINCIPALS, |mut scene| {
            serve_at(&mut scene, 3, 2);
            install_view(&mut scene);
            let own = tenure_of(token(&scene));
            assert_eq!((own.generation.get(), own.epoch.get()), (3, 6));
            inject_query(&mut scene, Kind::Probe, high, authentic);
            scene.turns(4);
            let replies = controls(&mut scene);
            assert_eq!(replies.len(), usize::from(answered), "{high:?} {authentic}");
            if let Some(bytes) = replies.first() {
                let frame = parse(scene.owner.crc, bytes, false).unwrap();
                assert_eq!(frame.header().kind, Kind::WrongOwner);
                scene.rings[0]
                    .authenticate(
                        &frame,
                        PeerId(0),
                        scene.owner.config.endpoint,
                        Direction::OwnerToClient,
                    )
                    .unwrap();
                let body = OwnershipBody::decode(Kind::WrongOwner, frame.raw_body()).unwrap();
                assert_eq!(body.tenure, Some(own));
            }
        });
    }
}

#[test]
fn a_probe_counts_under_the_check_that_refused_it() {
    let host = crate::storage::gate_fixture::own().exhid;
    let own = Tenure {
        generation: ShardGeneration::new(3).unwrap(),
        epoch: ActivatedEpoch::new(6).unwrap(),
        host,
    };
    // The last row names another shard and another session epoch: the shard
    // check runs first and names the reason.
    for (high, authentic, epoch, foreign, reason) in [
        (None, true, 0, false, None),
        (None, false, 0, false, Some(DropReason::Unauthenticated)),
        (None, true, 2, false, Some(DropReason::Session)),
        (Some(own), true, 0, false, Some(DropReason::Declined)),
        (None, true, 2, true, Some(DropReason::Declined)),
    ] {
        scene(&PRINCIPALS, |mut scene| {
            serve_at(&mut scene, 3, 2);
            install_view(&mut scene);
            assert_eq!(tenure_of(token(&scene)), own, "premise: the owner's tenure");
            let shard = token(&scene).shard;
            let query = OwnershipBody {
                shard: if foreign {
                    Shard::new(shard.get() + 1).unwrap()
                } else {
                    shard
                },
                volume: None,
                tenure: high,
                report_age_us: 0,
                responder: None,
                validity: Validity::new(0).unwrap(),
            };
            let mut body = [0; OwnershipBody::FIXED_LEN];
            query.encode(Kind::Probe, &mut body).unwrap();
            let mut header = session_header(&mut scene, 0, Kind::Probe, body.len());
            header.epoch += epoch;
            let before = scene.owner.report();
            inject_sealed_from(&mut scene, 0, &header, &body, authentic);
            scene.polls(1);
            let after = scene.owner.report();
            assert_eq!(
                crate::net::attribution_tests::moved(&before, &after),
                [(reason, 1)],
                "{reason:?}"
            );
            assert_eq!(
                crate::net::attribution_tests::accounted(&after),
                None,
                "{reason:?}"
            );
        });
    }
}

/// An authentic HELLO recast to version 2 reaches the owner and is dropped at parse as an unknown version: the
/// peer's bootstrap state, the session report and the reply queue are unchanged and nothing is sent. The same HELLO
/// at version 3 takes a fresh pending handshake and queues its CHALLENGE.
#[test]
fn a_version_2_hello_is_refused_before_any_session_change() {
    scene(&PRINCIPALS, |mut scene| {
        let peer = PeerId(0);
        let hello = Header {
            owner_nonce: [0; 16],
            epoch: 0,
            sequence: 1 << 20,
            ..session_header(&mut scene, 0, Kind::Hello, crate::net::BOOTSTRAP_BODY_LEN)
        };
        let body = scene.owner.config.caps.body();
        let v3 = sealed(&scene, 0, &hello, &body, true, Direction::ClientToOwner);
        let v2 = crate::net::frame_tests::recast_to_version_2(
            &scene.rings[0],
            PeerId(0),
            scene.owner.config.endpoint,
            &v3,
            Direction::ClientToOwner,
        );
        assert_eq!(
            parse(scene.owner.crc, &v2, false).err(),
            Some(crate::net::FrameError::Version { found: 2 })
        );
        let view = scene.owner.sessions.view(peer);
        let sessions = scene.owner.sessions.report();
        let (received, dropped, sent) = (
            scene.owner.report.received,
            scene.owner.report.dropped,
            scene.owner.report.sent,
        );
        let waiting = scene.owner.waiting;
        scene.nets[0].borrow_mut().inject(1, &v2);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert_eq!(
            (scene.owner.report.received, scene.owner.report.dropped),
            (received + 1, dropped + 1),
            "the version 2 HELLO reaches the owner and is dropped"
        );
        assert_eq!(scene.owner.sessions.view(peer), view);
        assert_eq!(scene.owner.sessions.report(), sessions);
        assert_eq!(scene.owner.waiting, waiting);
        assert_eq!(scene.owner.report.sent, sent);
        scene.nets[0].borrow_mut().inject(1, &v3);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert_eq!(
            scene.owner.waiting,
            waiting + 1,
            "the version 3 HELLO's CHALLENGE is queued"
        );
        assert_ne!(scene.owner.sessions.view(peer).pending, view.pending);
    });
}

/// An authentic Heartbeat naming a higher tenure, recast to version 2, reaches the client and is dropped at parse:
/// the shard route stays Bound to the session's tenure and the session stays active. The same Heartbeat at version 3
/// raises the route to a Candidate of the higher tenure.
#[test]
fn a_version_2_ownership_reply_leaves_the_client_route_and_session_unchanged() {
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let above = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..two_above(own)
        };
        let reply = OwnershipBody {
            shard,
            volume: Some(crate::net::ownership::Volume {
                name: "vol-0123456789abcdef0",
                state: WireState::Active,
            }),
            tenure: Some(above),
            report_age_us: 0,
            responder: Some(own.host),
            validity: Validity::new(Validity::ALL).unwrap(),
        };
        let mut body = vec![0; reply.encoded_len()];
        reply.encode(Kind::Heartbeat, &mut body).unwrap();
        let mut header = session_header(&mut scene, 0, Kind::Heartbeat, body.len());
        header.sequence = scene.owner.sessions.next_sequence(PeerId(0)).unwrap();
        let v3 = sealed(&scene, 0, &header, &body, true, Direction::OwnerToClient);
        let v2 = crate::net::frame_tests::recast_to_version_2(
            &scene.rings[0],
            PeerId(0),
            scene.owner.config.endpoint,
            &v3,
            Direction::OwnerToClient,
        );
        assert_eq!(
            parse(scene.owner.crc, &v2, false).err(),
            Some(crate::net::FrameError::Version { found: 2 })
        );
        let active = scene.clients[0].session_epoch();
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(own))
        );
        scene.nets[0].borrow_mut().inject(0, &v2);
        scene.nets[0].borrow_mut().advance(scene.turn);
        let report = scene.clients[0].poll(scene.turn * 100);
        assert_eq!((report.received, report.dropped), (1, 1));
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(own)),
            "the version 2 reply leaves the route Bound"
        );
        assert_eq!(scene.clients[0].session_epoch(), active);
        scene.nets[0].borrow_mut().inject(0, &v3);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Candidate(above)),
            "the version 3 reply raises the route"
        );
    });
}

/// An owner started before the fencing boundary holds no token; the crossing issues the token for the own host, and
/// the reply to the client's HELLO, sent before it, waits in the owner's reply queue.
#[test]
fn the_fencing_boundary_issues_the_own_token_with_the_hellos_reply_queued() {
    use crate::net::fetch::Releases;
    use crate::net::link::{Faults, network};
    use crate::storage::owner_fixture::{BUFFER, DEPTH, Device, TICK, arena, device_with, storage};
    let own = crate::storage::gate_fixture::own().exhid;
    let storage = storage(8);
    let buffers = arena(8);
    let receive = crate::net::owner_tests::pool();
    let client_pool = crate::net::owner_tests::pool();
    let releases = Releases::new(4, &mut crate::storage::EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
    let (disk, control) = device_with(7, BUFFER);
    let volume = crate::storage::Volume::attach(
        &storage,
        &buffers,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture_pre_boundary(),
        DEPTH,
        TICK,
        &mut crate::storage::EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    assert!(
        volume.serving_token().is_none(),
        "no token before the boundary"
    );
    let (mut owner, control) = crate::net::put_tests::start_on(
        Device { volume, control },
        &storage,
        &receive,
        vec![owner_end],
        (crate::net::owner_tests::OWNER, &[]),
        |bytes| {
            *bytes = [77; 16];
            Ok(())
        },
    )
    .unwrap();
    let mut client = crate::net::owner_tests::client(0, &client_pool, &releases, client_end);
    client.session(0);
    for turn in 0..80 {
        client.poll(turn * 100);
        net.borrow_mut().advance(turn);
        owner.poll(turn * 100);
        control.tick(64);
    }
    let token = owner
        .volume
        .serving_token()
        .expect("the crossing issues the token");
    assert_eq!(token.exhid, own);
    assert_eq!(owner.waiting, 1, "the HELLO's reply is queued");
}

/// What keeps the owner from answering a question of [`each_question_of_an_adjacent_pair_counts_once_under_its_own_reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flaw {
    /// Nothing: the owner answers it.
    Sound,
    /// Its magic changed after sealing, so the frame parse refuses it.
    Magic,
    /// It names the key epoch after the ring's, which the ring refuses before it computes a tag.
    KeyEpoch,
    /// Its tag is broken.
    Tag,
    /// It names the session epoch two above its peer's, which the session table refuses when it admits a PROBE.
    Session,
    /// The transport reports it as from no configured peer.
    Stranger,
    /// The transport reports it truncated.
    Truncated,
    /// The transport counts it and leaves its slot empty.
    Vacant,
}

impl Flaw {
    /// How the transport reports the datagram, when the flaw is the transport's report of it.
    fn relabel(self) -> Option<crate::net::owner_tests::Relabel> {
        use crate::net::owner_tests::Relabel;
        match self {
            Self::Stranger => Some(Relabel::Stranger),
            Self::Truncated => Some(Relabel::Truncated),
            Self::Vacant => Some(Relabel::Vacant),
            Self::Sound | Self::Magic | Self::KeyEpoch | Self::Tag | Self::Session => None,
        }
    }
}

/// The datagram of a question of `kind` from `peer` about the owner's shard, with `flaw`, and the sequence it carries.
fn question(scene: &mut Scene<'_, '_>, peer: usize, kind: Kind, flaw: Flaw) -> (Vec<u8>, u64) {
    let body = query_body(kind, token(scene).shard, None);
    let mut header = session_header(scene, peer, kind, body.len());
    match flaw {
        Flaw::KeyEpoch => header.key_epoch += 1,
        Flaw::Session => header.epoch += 2,
        Flaw::Sound | Flaw::Magic | Flaw::Tag | Flaw::Stranger | Flaw::Truncated | Flaw::Vacant => {
        }
    }
    let mut datagram = sealed(
        scene,
        peer,
        &header,
        &body,
        flaw != Flaw::Tag,
        Direction::ClientToOwner,
    );
    if flaw == Flaw::Magic {
        datagram[0] ^= 1;
    }
    (datagram, header.sequence)
}

/// Two ownership questions adjacent in one receive batch each count once, as handled or under the reason of the
/// first check that question failed, and the owner queues an answer for exactly the peers whose question it
/// handled. Each row gives the two questions in batch order, the counters that moved, and whether peer 0 and
/// peer 1 hold a queued answer. A queued answer carries the sequence of its peer's earliest sound question, so
/// the owner answers the two in batch order. The rows cover a pair the owner answers, with a WHO HOLDS or a PROBE first; a
/// second question of a peer whose answer is already queued; a question of either position that fails the frame
/// parse, names a key epoch the ring refuses, or carries a broken tag, beside one the owner answers; two flawed
/// questions that fail different checks; a PROBE the session table refuses; two broken tags; a question of either
/// position that the transport reports as from no configured peer or as truncated; and a question followed by an
/// empty slot.
#[test]
fn each_question_of_an_adjacent_pair_counts_once_under_its_own_reason() {
    use Flaw::{KeyEpoch, Magic, Session, Sound, Stranger, Tag, Truncated, Vacant};
    use Kind::{Probe, WhoHolds};
    type Row = (
        [(usize, Kind, Flaw); 2],
        &'static [(Option<DropReason>, u64)],
        [bool; 2],
    );
    let rows: [Row; 17] = [
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, Sound)],
            &[(None, 2)],
            [true, true],
        ),
        (
            [(0, Probe, Sound), (1, WhoHolds, Sound)],
            &[(None, 2)],
            [true, true],
        ),
        (
            [(0, WhoHolds, Sound), (0, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::Declined), 1)],
            [true, false],
        ),
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, Magic)],
            &[(None, 1), (Some(DropReason::Malformed), 1)],
            [true, false],
        ),
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, KeyEpoch)],
            &[(None, 1), (Some(DropReason::Unauthenticated), 1)],
            [true, false],
        ),
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, Tag)],
            &[(None, 1), (Some(DropReason::Unauthenticated), 1)],
            [true, false],
        ),
        (
            [(0, WhoHolds, Magic), (1, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::Malformed), 1)],
            [false, true],
        ),
        (
            [(0, WhoHolds, KeyEpoch), (1, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::Unauthenticated), 1)],
            [false, true],
        ),
        (
            [(0, WhoHolds, Tag), (1, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::Unauthenticated), 1)],
            [false, true],
        ),
        (
            [(0, WhoHolds, Magic), (1, WhoHolds, KeyEpoch)],
            &[
                (Some(DropReason::Malformed), 1),
                (Some(DropReason::Unauthenticated), 1),
            ],
            [false, false],
        ),
        (
            [(0, Probe, Session), (1, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::Session), 1)],
            [false, true],
        ),
        (
            [(0, WhoHolds, Tag), (1, WhoHolds, Tag)],
            &[(Some(DropReason::Unauthenticated), 2)],
            [false, false],
        ),
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, Stranger)],
            &[(None, 1), (Some(DropReason::NoPeer), 1)],
            [true, false],
        ),
        (
            [(0, WhoHolds, Stranger), (1, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::NoPeer), 1)],
            [false, true],
        ),
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, Truncated)],
            &[(None, 1), (Some(DropReason::Truncated), 1)],
            [true, false],
        ),
        (
            [(0, WhoHolds, Truncated), (1, WhoHolds, Sound)],
            &[(None, 1), (Some(DropReason::Truncated), 1)],
            [false, true],
        ),
        (
            [(0, WhoHolds, Sound), (1, WhoHolds, Vacant)],
            &[(None, 1), (Some(DropReason::Vacant), 1)],
            [true, false],
        ),
    ];
    for (pair, moved, answered) in rows {
        scene(&PRINCIPALS, |mut scene| {
            serve_at(&mut scene, 3, 2);
            install_view(&mut scene);
            let before = scene.owner.report();
            let mut sequences = [0; 2];
            for (position, (peer, kind, flaw)) in pair.into_iter().enumerate() {
                let (datagram, sequence) = question(&mut scene, peer, kind, flaw);
                sequences[position] = sequence;
                scene.nets[peer].borrow_mut().inject(1, &datagram);
                if let Some(relabel) = flaw.relabel() {
                    crate::net::owner_tests::RELABEL
                        .with(|relabels| relabels.borrow_mut().push((position, relabel)));
                }
            }
            for net in &scene.nets {
                net.borrow_mut().advance(scene.turn);
            }
            scene.owner.receive_batch(scene.turn * 100);
            let after = scene.owner.report();
            assert_eq!(
                after.received - before.received,
                2,
                "premise: one batch holds both questions: {pair:?}"
            );
            assert_eq!(
                crate::net::attribution_tests::moved(&before, &after),
                moved,
                "{pair:?}"
            );
            assert_eq!(
                crate::net::attribution_tests::accounted(&after),
                None,
                "{pair:?}"
            );
            let earliest_sound = |peer: usize| {
                let asked = pair.iter().zip(sequences);
                asked
                    .filter(|((from, _, flaw), _)| *from == peer && *flaw == Sound)
                    .map(|(_, sequence)| sequence)
                    .next()
            };
            assert_eq!(
                [0, 1].map(|peer| scene.owner.ownership[peer].map(|(header, _)| header.sequence)),
                [0, 1].map(|peer| earliest_sound(peer).filter(|_| answered[peer])),
                "{pair:?}"
            );
        });
    }
}

#[test]
fn ownership_replies_wait_per_peer_in_rotation() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        inject_query_from(&mut scene, 0, Kind::WhoHolds, None, true);
        inject_query_from(&mut scene, 1, Kind::WhoHolds, None, true);
        for net in &scene.nets {
            net.borrow_mut().advance(scene.turn);
        }
        scene.owner.receive_batch(scene.turn * 100);
        assert!(
            scene.owner.ownership.iter().all(Option::is_some),
            "a second peer's query waits beside the first"
        );
        assert_eq!(pending(&scene.owner), 2);
        assert_eq!(scene.owner.send_ownership(0), Some(1));
        assert!(
            scene.owner.ownership[0].is_none() && scene.owner.ownership[1].is_some(),
            "the reply at the cursor goes first"
        );
        assert_eq!(pending(&scene.owner), 1);
        assert_eq!(scene.owner.send_ownership(0), Some(1));
        assert!(scene.owner.ownership.iter().all(Option::is_none));
        assert_eq!(pending(&scene.owner), 0);
        assert_eq!(scene.owner.send_ownership(0), Some(0));
    });
}

#[test]
fn a_blocked_ownership_reply_stays_queued() {
    use crate::net::link::{LinkLimits, UNBOUNDED};
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        inject_query(&mut scene, Kind::WhoHolds, None, true);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert_eq!(pending(&scene.owner), 1);
        scene.nets[0].borrow_mut().set_limits(LinkLimits {
            copy_bytes: 0,
            ..UNBOUNDED
        });
        let sent = scene.owner.report.sent;
        assert_eq!(scene.owner.send_ownership(scene.turn * 100), None);
        assert_eq!(scene.owner.report.sent, sent);
        assert_eq!(
            pending(&scene.owner),
            1,
            "a reply the transport blocks stays queued for the next turn"
        );
        scene.nets[0].borrow_mut().set_limits(UNBOUNDED);
        assert_eq!(scene.owner.send_ownership(scene.turn * 100), Some(1));
        assert_eq!(scene.owner.report.sent, sent + 1);
        assert_eq!(pending(&scene.owner), 0);
    });
}

#[test]
fn wrong_owner_sequence_exhaustion_retires_the_peer() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        inject_query(&mut scene, Kind::Probe, None, true);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert!(scene.owner.ownership[0].is_some());
        assert_eq!(scene.owner.waiting, 0);
        let own = tenure_of(token(&scene));
        scene.owner.replies[0] = Some(ready_for(&scene, own));
        scene.owner.waiting += 1;
        scene.owner.exhaust_sends(PeerId(0));
        assert_eq!(scene.owner.send_ownership(scene.turn * 100), Some(0));
        assert!(scene.owner.sessions.active(PeerId(0)).is_none());
        assert!(
            scene.owner.replies[0].is_none() && scene.owner.waiting == 0,
            "the exhausted session's peer retires"
        );
        assert_eq!(pending(&scene.owner), 0);
    });
}

#[test]
fn pending_ownership_replies_end_with_their_peer_or_tenure() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        inject_query(&mut scene, Kind::WhoHolds, None, true);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert!(scene.owner.ownership[0].is_some());
        scene.owner.retire_peer(PeerId(0), scene.turn * 100, None);
        assert!(
            scene.owner.ownership[0].is_none(),
            "retirement clears the peer's ownership reply"
        );
        assert_eq!(pending(&scene.owner), 0);
    });
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        inject_query(&mut scene, Kind::Probe, None, true);
        scene.nets[0].borrow_mut().advance(scene.turn);
        scene.owner.receive_batch(scene.turn * 100);
        assert!(scene.owner.ownership[0].is_some());
        let sent = scene.owner.report.sent;
        scene.owner.volume.serve_later_tenure();
        assert_eq!(scene.owner.send_ownership(scene.turn * 100), Some(0));
        assert_eq!(
            scene.owner.report.sent, sent,
            "a WrongOwner bound to a replaced tenure is not sent"
        );
        assert!(scene.owner.ownership[0].is_none());
        assert_eq!(pending(&scene.owner), 0);
    });
}

#[test]
fn ownership_and_bootstrap_replies_alternate_in_a_one_send_control_half() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        scene.owner.config.batch = 2;
        let own = tenure_of(token(&scene));
        scene.owner.replies[0] = Some(ready_for(&scene, own));
        scene.owner.waiting += 1;
        for turn in 0..2 {
            inject_query(&mut scene, Kind::WhoHolds, None, true);
            scene.nets[0].borrow_mut().advance(scene.turn + turn);
            scene.owner.receive_batch(scene.turn * 100);
            assert!(scene.owner.ownership[0].is_some());
            scene.owner.send_batch(scene.turn * 100);
        }
        assert!(
            scene.owner.replies[0].is_none(),
            "a refilled ownership slot leaves the bootstrap reply its turn"
        );
    });
}

fn inject_reply(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    kind: Kind,
    reply: OwnershipBody<'_>,
    authentic: bool,
) {
    let mut body = vec![0; reply.encoded_len()];
    reply.encode(kind, &mut body).unwrap();
    let mut header = session_header(scene, peer, kind, body.len());
    // The owner's next send sequence under the peer's session, so the client's replay window sees the frame once.
    if let Ok(sequence) = scene.owner.sessions.next_sequence(PeerId(peer as u16)) {
        header.sequence = sequence;
    }
    inject_reply_under(scene, peer, &header, &body, authentic);
}

/// Delivers an ownership reply of `header` and `body` to client `peer`.
fn inject_reply_under(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    header: &Header,
    body: &[u8],
    authentic: bool,
) {
    let datagram = sealed(
        scene,
        peer,
        header,
        body,
        authentic,
        Direction::OwnerToClient,
    );
    scene.nets[peer].borrow_mut().inject(0, &datagram);
    scene.turns(4);
}

#[test]
fn ownership_frames_move_the_client_route() {
    use super::super::client::GetRefused;
    use super::super::fetch::Outcome;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let reply = |tenure: Tenure, bits: u8| OwnershipBody {
            shard,
            volume: Some(crate::net::ownership::Volume {
                name: "vol-0123456789abcdef0",
                state: WireState::Active,
            }),
            tenure: Some(tenure),
            report_age_us: 0,
            responder: Some(own.host),
            validity: Validity::new(bits).unwrap(),
        };
        let serving = Validity::REPORT | Validity::SERVING | Validity::LIVE;
        let unrouted = |scene: &mut Scene<'_, '_>| {
            let now = scene.turn * 100;
            scene.clients[0].poll(now);
            let key = crate::net::owner_tests::key(9);
            scene.clients[0].get(key, 0, 1 << 20, now, 30_000_000)
        };
        assert_eq!(scene.read(0, 9, 0).0, Some(Outcome::Missing));
        inject_reply(&mut scene, 0, Kind::WrongOwner, reply(own, serving), true);
        assert_eq!(
            scene.read(0, 9, 0).0,
            Some(Outcome::Missing),
            "a WrongOwner at the high-water leaves the route"
        );
        inject_reply(
            &mut scene,
            0,
            Kind::Holder,
            reply(own, Validity::REPORT),
            true,
        );
        assert_eq!(
            scene.read(0, 9, 0).0,
            Some(Outcome::Missing),
            "an invalid-flag Holder names no session and keeps the binding"
        );
        inject_reply(
            &mut scene,
            0,
            Kind::WrongOwner,
            reply(own, Validity::REPORT),
            true,
        );
        assert_eq!(
            unrouted(&mut scene),
            Err(GetRefused::Unrouted),
            "an invalid-flag WrongOwner of the session withdraws its binding"
        );
        serve_at(&mut scene, 3, 3);
        let rerun = tenure_of(token(&scene));
        assert_eq!(
            scene.read(0, 9, 0).0,
            Some(Outcome::Missing),
            "READY at a higher tenure binds the route"
        );
        let above = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..two_above(rerun)
        };
        inject_reply(
            &mut scene,
            0,
            Kind::WrongOwner,
            reply(above, serving),
            false,
        );
        assert_eq!(
            scene.read(0, 9, 0).0,
            Some(Outcome::Missing),
            "an unauthenticated WrongOwner leaves the route"
        );
        inject_reply(&mut scene, 0, Kind::WrongOwner, reply(above, serving), true);
        assert_eq!(
            unrouted(&mut scene),
            Err(GetRefused::Unrouted),
            "a WrongOwner above the high-water redirects the shard"
        );
    });
}

#[test]
fn clients_share_one_high_water_and_withhold_requests() {
    use super::super::client::{GetRefused, PutRefused};
    use super::super::fetch::Outcome;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        scene.reopen(1);
        let own = tenure_of(token(&scene));
        for reader in [0, 1] {
            assert_eq!(scene.read(reader, 9, 0).0, Some(Outcome::Missing));
        }
        let now = scene.turn * 100;
        let in_flight = scene.clients[0]
            .get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 30_000_000)
            .unwrap();
        let other = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..own
        };
        assert!(
            !scene.clients[1]
                .routes()
                .admit(token(&scene).shard, other, || None),
            "another host's response at the session's (g, a) through the second client's table"
        );
        let now = scene.turn * 100;
        let client = &mut scene.clients[0];
        assert_eq!(
            client.get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 30_000_000),
            Err(GetRefused::Unrouted),
            "the first client sees the Conflict the second raised"
        );
        assert_eq!(
            client.put(
                crate::net::owner_tests::key(6),
                crate::storage::CacheVersion(0),
                now,
                30_000_000
            ),
            Err(PutRefused::Unrouted)
        );
        assert_eq!(
            client.invalidate(crate::net::owner_tests::key(6), 0, 1),
            Err(PutRefused::Unrouted)
        );
        assert_eq!(client.refusals().unrouted, 1);
        client.poll(now);
        assert_eq!(
            client.outcome(in_flight),
            Some(Outcome::Failed(Status::SessionMismatch)),
            "the GET admitted before the Conflict ends unsent"
        );
        assert!(client.retire(in_flight));
        assert!(
            scene.nets[0].borrow().peek(1).is_none(),
            "Conflict sends zero requests"
        );
        serve_at(&mut scene, 3, 3);
        assert_eq!(
            scene.read(0, 9, 0).0,
            Some(Outcome::Missing),
            "a higher tenure clears the Conflict"
        );
    });
}

/// An INVALIDATE past the send sequence ends the session, so the session's GET ends `SessionMismatch` with it.
#[test]
fn an_invalidate_past_the_send_sequence_ends_the_sessions_gets() {
    use super::super::client::PutRefused;
    use super::super::fetch::Outcome;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        scene.reopen(1);
        let now = scene.turn * 100;
        let client = &mut scene.clients[0];
        let live = client
            .get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 30_000_000)
            .unwrap();
        client
            .sessions_mut()
            .set_send(crate::net::datagram::PeerId(0), u64::MAX);
        assert_eq!(
            client.invalidate(crate::net::owner_tests::key(6), 0, 1),
            Err(PutRefused::RequestPressure)
        );
        assert_eq!(
            client.outcome(live),
            Some(Outcome::Failed(Status::SessionMismatch)),
            "the spent sequence ends the session's GET"
        );
    });
}

#[test]
fn a_response_below_the_high_water_is_discarded_at_its_last_byte() {
    use super::super::fetch::Outcome;
    use crate::net::geometry::FRAGMENT_LEN;
    use crate::net::put_tests::upload_within;
    for fragments in [1, 6] {
        scene(&PRINCIPALS, |mut scene| {
            let object = crate::net::owner_tests::payload(fragments * FRAGMENT_LEN as usize, 7);
            let (at, serial) = upload_within(&mut scene, &object, 60_000);
            for index in 0..fragments as u32 {
                let (header, body) = scene.fragment(at, serial, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
                scene.turns(2);
            }
            scene.turns(20);
            assert_eq!(
                scene.read(0, 5, 0),
                (Some(Outcome::Complete), object.clone())
            );
            let shard = token(&scene).shard;
            let above = two_above(tenure_of(token(&scene)));
            let id = scene.clients[0]
                .get(
                    crate::net::owner_tests::key(5),
                    0,
                    1 << 20,
                    scene.turn * 100,
                    30_000_000,
                )
                .unwrap();
            if fragments == 1 {
                scene.clients[0].poll(scene.turn * 100);
                scene.turns(20);
                assert!(scene.clients[0].routes().admit(shard, above, || None));
                let report = scene.clients[0].poll(scene.turn * 100);
                assert!(
                    report.unrouted >= 1,
                    "the route refuses the answer: {report:?}"
                );
                assert!(scene.clients[0].take(id).is_none());
                assert_eq!(
                    scene.clients[0].outcome(id),
                    Some(Outcome::Failed(Status::SessionMismatch)),
                    "the COMPLETE below the high-water decides nothing"
                );
                return;
            }
            let mut bytes = Vec::new();
            let mut raised = false;
            while scene.clients[0].outcome(id).is_none() {
                assert!(scene.turn < 10_000, "the GET ends");
                let now = scene.turn * 100;
                scene.clients[0].poll(now);
                scene.turns(1);
                while let Some(fragment) = scene.clients[0].take(id) {
                    bytes.extend_from_slice(fragment.bytes());
                }
                if !bytes.is_empty() && !raised {
                    assert!(
                        scene.clients[0].routes().admit(shard, above, || None),
                        "another session admits a response of a higher tenure"
                    );
                    raised = true;
                    scene.turns(20);
                    let report = scene.clients[0].poll(scene.turn * 100);
                    assert!(
                        report.unrouted >= 1,
                        "the route refuses the rest of the response: {report:?}"
                    );
                }
            }
            assert!(raised);
            assert!(bytes.len() < object.len(), "{} bytes surfaced", bytes.len());
            assert_eq!(
                scene.clients[0].outcome(id),
                Some(Outcome::Incomplete(Status::SessionMismatch))
            );
        });
    }
}

/// A higher tenure that another session raised refuses the frames of a GET already answered, and a READY below the
/// high-water binds a session the route refuses.
#[test]
fn routes_refuse_response_frames_and_ready_below_the_high_water() {
    use super::super::client::GetRefused;
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let above = two_above(own);
        let now = scene.turn * 100;
        let key = crate::net::owner_tests::key(9);
        let id = scene.clients[0]
            .get(key, 0, 1 << 20, now, 30_000_000)
            .unwrap();
        scene.clients[0].poll(now);
        scene.turns(20);
        assert!(scene.clients[0].routes().admit(shard, above, || None));
        let report = scene.clients[0].poll(scene.turn * 100);
        assert!(
            report.unrouted >= 1,
            "the route refuses the answer: {report:?}"
        );
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(Outcome::Failed(Status::SessionMismatch)),
            "the refused answer decides nothing"
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(above)),
            "a refused frame leaves the route"
        );
        assert!(scene.clients[0].retire(id));
        scene.open(0);
        assert_eq!(
            scene.clients[0].state(),
            super::super::client::SessionState::Active
        );
        let now = scene.turn * 100;
        assert_eq!(
            scene.clients[0].get(key, 0, 1 << 20, now, 30_000_000),
            Err(GetRefused::Unrouted),
            "a READY below the high-water binds a session the route refuses"
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(above))
        );
    });
}

/// A GET whose deadline has come times out before the turn's frames reach the route, and its late answer leaves the
/// route unchanged.
#[test]
fn an_expired_get_times_out_before_its_late_answer() {
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 1_000)
            .unwrap();
        scene.clients[0].poll(now);
        scene.turns(20);
        let report = scene.clients[0].poll(scene.turn * 100);
        assert!(
            report.received >= 1,
            "the answer arrives in the deciding poll"
        );
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(Outcome::Failed(Status::TimedOut))
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(own))
        );
    });
}

/// Heartbeat and ProbeReply raise the shard high-water to a higher tenure they name.
#[test]
fn heartbeat_and_probe_reply_raise_the_high_water() {
    use crate::failover::route::HighWater;
    for kind in [Kind::Heartbeat, Kind::ProbeReply] {
        scene(&PRINCIPALS, |mut scene| {
            serve_at(&mut scene, 3, 2);
            let own = tenure_of(token(&scene));
            let shard = token(&scene).shard;
            let above = Tenure {
                host: Exhid::new([0xA5; 16]).unwrap(),
                ..two_above(own)
            };
            let body = OwnershipBody {
                shard,
                volume: Some(crate::net::ownership::Volume {
                    name: "vol-0123456789abcdef0",
                    state: WireState::Active,
                }),
                tenure: Some(above),
                report_age_us: 0,
                responder: Some(own.host),
                validity: Validity::new(Validity::ALL).unwrap(),
            };
            let confirming = OwnershipBody {
                tenure: Some(own),
                ..body
            };
            inject_reply(&mut scene, 0, kind, confirming, true);
            let report = scene.clients[0].poll(scene.turn * 100);
            assert_eq!(
                (report.dropped, report.unrouted),
                (0, 0),
                "a frame confirming the bound tenure, {kind:?}"
            );
            assert_eq!(
                scene.clients[0].routes().route(shard),
                Some(HighWater::Bound(own)),
                "{kind:?}"
            );
            inject_reply(&mut scene, 0, kind, body, true);
            let report = scene.clients[0].poll(scene.turn * 100);
            assert_eq!(report.unrouted, 0, "{kind:?}");
            assert_eq!(
                scene.clients[0].routes().route(shard),
                Some(HighWater::Candidate(above)),
                "{kind:?}"
            );
        });
    }
}

/// A higher tenure that another session raised refuses the INVALIDATED of an acknowledged INVALIDATE.
#[test]
fn an_invalidated_below_the_shard_high_water_is_dropped() {
    scene(&PRINCIPALS, |mut scene| {
        let store = crate::storage::store_tests::seeded_under(scene.owner.tenure());
        let (fencing, mut client) =
            crate::net::put_tests::fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let object = crate::net::owner_tests::payload(100, 2);
        let serial = crate::net::put_tests::ready_named(&mut scene, request(1, 1), 5, &object);
        assert_eq!(
            crate::net::put_tests::finish_named(&mut scene, request(1, 1), serial, 5, &object),
            None
        );
        scene.clients[0]
            .invalidate(crate::net::owner_tests::key(5), 3, 5)
            .unwrap();
        scene.turns(4);
        let mut acknowledged = Vec::new();
        scene
            .owner
            .cover_pending(&mut client, &mut acknowledged, 0)
            .unwrap();
        assert_eq!(
            acknowledged,
            [(
                crate::net::owner_tests::key(5),
                crate::net::put_tests::versions(3, 5)
            )]
        );
        scene.turns(4);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let above = two_above(own);
        assert!(scene.clients[0].routes().admit(shard, above, || None));
        let report = scene.clients[0].poll(scene.turn * 100);
        assert!(
            report.unrouted >= 1,
            "the route refuses the INVALIDATED: {report:?}"
        );
        assert_eq!(scene.clients[0].take_invalidated(), None);
    });
}

/// A route raised above the session's tenure ends an in-flight upload and refuses the owner's reply to it.
#[test]
fn a_raised_route_ends_uploads_and_refuses_their_replies() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(
                crate::net::owner_tests::key(6),
                crate::storage::CacheVersion(0),
                now,
                30_000_000,
            )
            .unwrap();
        scene.clients[0].poll(now);
        let bytes = scene.nets[0]
            .borrow()
            .peek(1)
            .expect("the BEGIN toward the owner");
        let begin = crate::net::frame::parse(crate::storage::Crc32c::detect(), &bytes, false)
            .unwrap()
            .header();
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let above = two_above(own);
        assert!(scene.clients[0].routes().admit(shard, above, || None));
        scene.clients[0].poll(now);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(crate::net::upload::UploadOutcome::Unknown),
            "the withheld upload ends"
        );
        scene.turns(4);
        let report = scene.clients[0].poll(scene.turn * 100);
        assert!(
            report.unrouted >= 1,
            "the route refuses the reply: {report:?}"
        );
        let (error, _) = crate::net::frame_tests::put_frame(Kind::PutError, &begin);
        let error = Header {
            sequence: 1 << 40,
            ..error
        };
        let datagram = sealed(&scene, 0, &error, &[], true, Direction::OwnerToClient);
        scene.nets[0].borrow_mut().inject(0, &datagram);
        scene.turns(1);
        let report = scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            report.unrouted, 1,
            "the route refuses the terminal PUT ERROR"
        );
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(crate::net::upload::UploadOutcome::Unknown),
            "a refused PUT ERROR settles nothing"
        );
    });
}

/// A READY at a higher tenure clears a withheld session, so the next raise ends that session's requests again.
#[test]
fn a_higher_ready_clears_withholding() {
    use super::super::fetch::Outcome;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let other = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..own
        };
        assert!(!scene.clients[1].routes().admit(shard, other, || None));
        scene.clients[0].poll(scene.turn * 100);
        serve_at(&mut scene, 3, 3);
        let rerun = tenure_of(token(&scene));
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 30_000_000)
            .expect("the READY at a higher tenure clears withholding");
        scene.clients[0].poll(now);
        assert!(
            scene.clients[1]
                .routes()
                .admit(shard, two_above(rerun), || None)
        );
        scene.clients[0].poll(now);
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(Outcome::Failed(Status::SessionMismatch))
        );
    });
}

/// A retirement that names no tenure reaches a Conflict route through the receiving session's bound tenure.
#[test]
fn a_tenureless_retirement_uses_the_bound_tenure() {
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let other = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..own
        };
        assert!(!scene.clients[0].routes().admit(shard, other, || None));
        let retired = OwnershipBody {
            shard,
            volume: Some(crate::net::ownership::Volume {
                name: "vol-0123456789abcdef0",
                state: WireState::Retired,
            }),
            tenure: None,
            report_age_us: 0,
            responder: Some(own.host),
            validity: Validity::new(0).unwrap(),
        };
        inject_reply(&mut scene, 0, Kind::Holder, retired, true);
        scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Dark {
                generation: own.generation,
                epoch: own.epoch,
            })
        );
    });
}

#[test]
fn a_recovered_owner_rebinds_its_tenure_for_every_sharing_client() {
    use super::super::client::GetRefused;
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        for reader in [0, 1] {
            assert_eq!(scene.read(reader, 9, 0).0, Some(Outcome::Missing));
        }
        scene.reopen(0);
        inject_query(&mut scene, Kind::WhoHolds, None, true);
        scene.turns(4);
        let queued = queued_ownership(&mut scene);
        assert!(
            queued.contains(&(Kind::Holder, 0)),
            "the owner with no shard view answers with a Holder asserting nothing: {queued:?}"
        );
        let report = scene.clients[0].poll(scene.turn * 100);
        assert!(report.received > 0, "the Holder arrives: {report:?}");
        assert_eq!(report.unrouted, 0, "the owner's Holder merges: {report:?}");
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(own)),
            "the Holder of an owner with no shard view names no tenure, so it merges nothing and the binding stays"
        );
        inject_query(&mut scene, Kind::Probe, None, true);
        scene.turns(4);
        let now = scene.turn * 100;
        let report = scene.clients[0].poll(now);
        assert_eq!(
            report.unrouted, 0,
            "the owner's WrongOwner merges: {report:?}"
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Candidate(own)),
            "the WrongOwner of an owner with no shard view withdraws the binding"
        );
        scene.clients[1].poll(now);
        for client in [0, 1] {
            assert_eq!(
                scene.clients[client].get(
                    crate::net::owner_tests::key(9),
                    0,
                    1 << 20,
                    now,
                    30_000_000
                ),
                Err(GetRefused::Unrouted),
                "client {client} withholds its requests"
            );
        }
        install_view(&mut scene);
        scene.open(0);
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(own)),
            "the READY at the recovered tenure binds the route"
        );
        scene.refresh(0);
        assert_eq!(scene.read(0, 9, 0).0, Some(Outcome::Missing));
        scene.clients[1].poll(scene.turn * 100);
        assert_eq!(
            scene.read(1, 9, 0).0,
            Some(Outcome::Missing),
            "the sharing client resumes without a handshake"
        );
    });
}

/// An authenticated invalid-flag WrongOwner naming peer 0's session and tenure `own`, under the owner's next send
/// sequence of that session.
fn session_withdrawal(scene: &mut Scene<'_, '_>, own: Tenure) -> (Header, Vec<u8>) {
    peer_withdrawal(scene, 0, own)
}

/// [`session_withdrawal`] for client `peer`'s session.
fn peer_withdrawal(scene: &mut Scene<'_, '_>, peer: usize, own: Tenure) -> (Header, Vec<u8>) {
    let reply = OwnershipBody {
        shard: token(scene).shard,
        volume: Some(crate::net::ownership::Volume {
            name: "vol-0123456789abcdef0",
            state: WireState::Active,
        }),
        tenure: Some(own),
        report_age_us: 0,
        responder: Some(own.host),
        validity: Validity::new(Validity::REPORT).unwrap(),
    };
    let mut body = vec![0; reply.encoded_len()];
    reply.encode(Kind::WrongOwner, &mut body).unwrap();
    let mut header = session_header(scene, peer, Kind::WrongOwner, body.len());
    header.sequence = (scene.owner.sessions)
        .next_sequence(PeerId(peer as u16))
        .unwrap();
    (header, body)
}

/// The route after the owner seals a not-serving WrongOwner at sequence `n` of client 0's session, answers a GET
/// under later sequences, and the WrongOwner reaches the client after that answer.
fn overtaken_withdrawal(scene: &mut Scene<'_, '_>) -> Option<crate::failover::route::HighWater> {
    use super::super::fetch::Outcome;
    serve_at(scene, 3, 2);
    let own = tenure_of(token(scene));
    let (overtaken, body) = session_withdrawal(scene, own);
    assert_eq!(
        scene.read(0, 9, 0).0,
        Some(Outcome::Missing),
        "the client admits the owner's later answer first"
    );
    inject_reply_under(scene, 0, &overtaken, &body, true);
    scene.clients[0].poll(scene.turn * 100);
    scene.clients[0].routes().route(token(scene).shard)
}

/// WITHDRAWAL-NEEDS-SESSION over the wire. A not-serving WrongOwner that a later answer of its session overtook
/// keeps the binding. The session's newest one withdraws it. A copy delivered after its own session's response bound
/// the tenure again, a newer frame of a session whose binding admission another session's READY at the Bound tenure
/// followed, frames of an earlier session's nonces and epoch, and those frames at a client of another boot nonce keep
/// the binding, and a WrongOwner outside any session moves no session counter.
#[test]
fn a_copied_overtaken_or_earlier_session_withdrawal_keeps_the_binding() {
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        let overtaken = overtaken_withdrawal(&mut scene);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        assert_eq!(
            overtaken,
            Some(HighWater::Bound(own)),
            "an older not-serving frame that arrives after a later answer of its session"
        );
        let route = |scene: &mut Scene<'_, '_>| {
            scene.clients[0].poll(scene.turn * 100);
            scene.clients[0].routes().route(shard)
        };
        let (first, body) = session_withdrawal(&mut scene, own);
        let (before_rebind, _) = session_withdrawal(&mut scene, own);
        inject_reply_under(&mut scene, 0, &first, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Candidate(own)),
            "the session's newest withdrawal"
        );
        use crate::net::client::route::Binder;
        let template = scene.get(0, 0, 0);
        let session = Binder::new(template.client_nonce, template.epoch);
        assert!(
            scene.clients[0].routes().admit(shard, own, || session),
            "a response of the copy's own session binds the tenure again"
        );
        inject_reply_under(&mut scene, 0, &first, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "a copy is no newer than itself, though its session made the latest binding admission"
        );
        assert!(
            (scene.clients[0].routes()).ready(shard, own, Binder::new([9; 16], 1)),
            "another session's READY at the Bound tenure is the latest binding admission"
        );
        inject_reply_under(&mut scene, 0, &before_rebind, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "a frame of a session whose binding admission another session's followed cannot undo that binding"
        );
        let (unseen, _) = session_withdrawal(&mut scene, own);
        scene.reopen(0);
        assert_eq!(route(&mut scene), Some(HighWater::Bound(own)));
        for (header, name) in [(first, "a copy"), (unseen, "an unseen frame")] {
            inject_reply_under(&mut scene, 0, &header, &body, true);
            assert_eq!(
                route(&mut scene),
                Some(HighWater::Bound(own)),
                "{name} of the earlier session's nonces and epoch"
            );
        }
        let mut rebooted = scene.spare.take().unwrap();
        std::mem::swap(&mut scene.clients[0], &mut rebooted);
        let counters = scene.clients[0].session_report();
        inject_reply_under(&mut scene, 0, &unseen, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Candidate(own)),
            "a WrongOwner before any session raises the route as a discovery hint"
        );
        assert_eq!(
            scene.clients[0].session_report(),
            counters,
            "and counts as no refused session frame"
        );
        scene.reopen(0);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "the rebooted client's READY binds its own table"
        );
        for header in [first, unseen] {
            inject_reply_under(&mut scene, 0, &header, &body, true);
            assert_eq!(
                route(&mut scene),
                Some(HighWater::Bound(own)),
                "a frame of the earlier boot's session"
            );
        }
        let (current, body) = session_withdrawal(&mut scene, own);
        inject_reply_under(&mut scene, 0, &current, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Candidate(own)),
            "the rebooted client's own session withdraws"
        );
    });
}

/// WITHDRAWAL-NEEDS-SESSION across the sessions that share one route, while the route stays Bound. A sharing
/// client's READY is a binding admission: a not-serving frame the owner sealed for the first session before that
/// READY keeps the binding, and the sharing client, which never moved the route, withdraws with its own newest frame.
/// A client that reopens its session at the same tenure withdraws with the new session's newest frame. The session
/// whose READY another READY followed cannot withdraw; its client regains the withdrawal only through a new session.
#[test]
fn a_ready_on_a_bound_route_moves_the_withdrawal_to_its_session() {
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        serve_at(&mut scene, 3, 2);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let route = |scene: &mut Scene<'_, '_>| {
            for client in &mut scene.clients {
                client.poll(scene.turn * 100);
            }
            scene.clients[0].routes().route(shard)
        };
        assert_eq!(route(&mut scene), Some(HighWater::Bound(own)));
        let (older, body) = session_withdrawal(&mut scene, own);
        scene.reopen(1);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "the sharing client's READY leaves the route Bound"
        );
        inject_reply_under(&mut scene, 0, &older, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "a READY followed by an older not-serving frame of the first session"
        );
        let (current, _) = session_withdrawal(&mut scene, own);
        inject_reply_under(&mut scene, 0, &current, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "the first session cannot order its frame after the sharing READY"
        );
        let (sharing, body) = peer_withdrawal(&mut scene, 1, own);
        inject_reply_under(&mut scene, 1, &sharing, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Candidate(own)),
            "the sharing client's newest frame withdraws the route it did not move"
        );
        scene.reopen(0);
        assert_eq!(route(&mut scene), Some(HighWater::Bound(own)));
        scene.reopen(0);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Bound(own)),
            "the client reopens its session on the Bound route"
        );
        let (reopened, body) = session_withdrawal(&mut scene, own);
        inject_reply_under(&mut scene, 0, &reopened, &body, true);
        assert_eq!(
            route(&mut scene),
            Some(HighWater::Candidate(own)),
            "the reopened session's newest frame withdraws"
        );
    });
}

/// A response is a binding admission when it moves the route to Bound. A GET answer that reaches client 1 after client
/// 0's session withdrew the shared route binds it again under client 1's session: client 0's next withdrawal then
/// keeps the binding, and client 1's newest withdrawal takes it.
#[test]
fn a_response_that_rebinds_a_withdrawn_route_moves_the_withdrawal_to_its_session() {
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        for reader in [1, 0] {
            assert_eq!(scene.read(reader, 9, 0).0, Some(Outcome::Missing));
        }
        scene.reopen(0);
        let now = scene.turn * 100;
        let id = scene.clients[1]
            .get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 30_000_000)
            .unwrap();
        scene.clients[1].poll(now);
        scene.turns(4);
        assert_eq!(
            scene.clients[1].outcome(id),
            None,
            "the answer waits on the link"
        );
        let route = |scene: &mut Scene<'_, '_>, client: usize| {
            scene.clients[client].poll(scene.turn * 100);
            scene.clients[client].routes().route(shard)
        };
        let (withdrawal, body) = session_withdrawal(&mut scene, own);
        inject_reply_under(&mut scene, 0, &withdrawal, &body, true);
        assert_eq!(
            route(&mut scene, 0),
            Some(HighWater::Candidate(own)),
            "client 0's session made the latest binding admission and withdraws"
        );
        assert_eq!(
            route(&mut scene, 1),
            Some(HighWater::Bound(own)),
            "client 1's answer binds the withdrawn route again"
        );
        assert_eq!(scene.clients[1].outcome(id), Some(Outcome::Missing));
        let (withdrawal, body) = session_withdrawal(&mut scene, own);
        inject_reply_under(&mut scene, 0, &withdrawal, &body, true);
        assert_eq!(
            route(&mut scene, 0),
            Some(HighWater::Bound(own)),
            "client 0's newest withdrawal keeps the binding client 1's answer made"
        );
        let (withdrawal, body) = peer_withdrawal(&mut scene, 1, own);
        inject_reply_under(&mut scene, 1, &withdrawal, &body, true);
        assert_eq!(
            route(&mut scene, 1),
            Some(HighWater::Candidate(own)),
            "client 1's newest withdrawal takes it"
        );
    });
}

/// Negative control for WITHDRAWAL-NEEDS-SESSION. The plant makes the client count every WrongOwner as its session's
/// newest frame. The withdrawal that a later answer overtook then unbinds the serving tenure, which is the
/// `Bound` assertion of `a_copied_overtaken_or_earlier_session_withdrawal_keeps_the_binding` failing.
#[test]
fn negative_control_an_unordered_withdrawal_unbinds_a_serving_tenure() {
    use super::super::client::UNORDERED_WITHDRAWALS;
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        UNORDERED_WITHDRAWALS.set(true);
        let overtaken = overtaken_withdrawal(&mut scene);
        UNORDERED_WITHDRAWALS.set(false);
        let own = tenure_of(token(&scene));
        assert_eq!(
            overtaken,
            Some(HighWater::Candidate(own)),
            "a withdrawal its session overtook unbinds a serving tenure"
        );
    });
}

/// A successor that retained the volume takes the shard record at the same generation. The deposed owner withdraws on
/// observing it, requests no flip then or after a later Report trigger, and answers WhoHolds with the volume still
/// active and the successor's tenure. The client ends the deposed tenure's undecided GET at that route, keeps the
/// generation lit, and binds the successor's READY.
#[test]
fn a_same_generation_successor_deposes_without_a_retirement_frame_or_a_flip() {
    use super::super::fetch::Outcome;
    use crate::failover::evidence::NotSole;
    use crate::failover::route::HighWater;
    use crate::failover::serving::ReportTrigger;
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let old = token(&scene);
        let shard = old.shard;
        assert_eq!(scene.read(0, 9, 0).0, Some(Outcome::Missing));
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .get(crate::net::owner_tests::key(9), 0, 1 << 20, now, 30_000_000)
            .unwrap();
        let attachment = Exhid::new([0xA5; 16]).unwrap();
        let record = ShardRecord {
            owner: crate::failover::records::Host::new(99).unwrap(),
            ..shard_at(old, old.generation.get(), old.epoch.get() / 2 + 1)
        };
        observe(
            &mut scene,
            Some(record),
            Some(volume_record("vol-0a", VolumeState::Active)),
            attachment,
        );
        let report = scene.owner.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Withdrawn, Some(Cause::Flipped), None)
        );
        let trigger = ReportTrigger::new(NotSole::ForeignHolder).unwrap();
        let now = scene.turn * 100;
        (scene.owner).authority_event(Event::Withdraw(Cause::Report(trigger)), now);
        let report = scene.owner.authority_report();
        assert_eq!(
            (report.withdrawal, report.flip),
            (Some(Cause::Flipped), None),
            "the successor's reservation requests no flip of the stale tenure"
        );
        let successor = Tenure {
            generation: old.generation,
            epoch: ActivatedEpoch::new(old.epoch.get() + 2).unwrap(),
            host: attachment,
        };
        inject_query(&mut scene, Kind::WhoHolds, None, true);
        scene.turns(4);
        scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Candidate(successor)),
            "the deposed owner names the active volume's successor and retires nothing"
        );
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(Outcome::Failed(Status::SessionMismatch)),
            "the deposed tenure's GET ends undecided"
        );
        assert!(
            (scene.clients[0].routes()).ready(
                shard,
                successor,
                crate::net::client::route::Binder::new([0xA5; 16], 1)
            ),
            "the successor's READY binds at the shared generation"
        );
    });
}

/// A page write of the deposed tenure that reaches the store after the successor fenced the page fails its
/// condition. The owner withdraws in that call, drops the reply it had buffered, ends its sessions, acknowledges no
/// held INVALIDATE, and requests no flip then or after a later Report trigger.
#[test]
fn a_page_write_across_a_successor_fence_withdraws_in_that_call_without_a_flip() {
    use crate::failover::evidence::NotSole;
    use crate::failover::serving::ReportTrigger;
    use crate::net::put_tests::fenced_coverage;
    use crate::storage::WorkBudget;
    use crate::storage::page_coverage::{Fencing, Interval, Progress, Withdraw};
    use crate::storage::store_tests::{client, record_under, seeded_under};
    scene(&PRINCIPALS, |mut scene| {
        let store = seeded_under(scene.owner.tenure());
        let (fencing, mut tenure) = fenced_coverage(&store, scene.owner.tenure());
        scene.owner.install_coverage(fencing).unwrap();
        let mut budget = WorkBudget::new(1 << 12);
        let versions = Interval::new(
            crate::storage::CacheVersion(1),
            crate::storage::CacheVersion(1),
        )
        .unwrap();
        (scene.owner)
            .invalidate_interval(&crate::net::owner_tests::key(1), versions, 4, &mut budget)
            .unwrap();
        let next = crate::storage::next_session();
        assert_eq!(
            next.generation(),
            scene.owner.tenure().generation(),
            "the successor shares the generation"
        );
        let record = record_under(&next);
        let mut successor = Fencing::new(&record, &next, 4).unwrap();
        let mut other = client(&store);
        for at in 0..record.pages.get() {
            assert!((0..8).any(|_| successor.fence(&mut other, at) == Ok(Progress::Done)));
        }
        let own = tenure_of(token(&scene));
        let ready = ready_for(&scene, own);
        assert!(scene.owner.reply(ready));
        assert_eq!(scene.owner.waiting, 1, "a reply waits for the next send");
        let sent = scene.owner.report.sent;
        let mut acknowledged = Vec::new();
        let now = scene.turn * 100;
        let withdrawn = (scene.owner).cover_pending(&mut tenure, &mut acknowledged, now);
        assert!(
            matches!(withdrawn, Err(Withdraw::NewerFence { .. })),
            "{withdrawn:?}"
        );
        assert!(acknowledged.is_empty());
        assert_eq!(scene.owner.waiting, 0, "the buffered reply is dropped");
        assert_eq!(scene.owner.session_epoch(PeerId(0)), None);
        let trigger = ReportTrigger::new(NotSole::ForeignHolder).unwrap();
        (scene.owner).authority_event(Event::Withdraw(Cause::Report(trigger)), now);
        let report = scene.owner.authority_report();
        assert!(
            matches!(report.withdrawal, Some(Cause::NewerFence { .. })) && report.flip.is_none(),
            "{report:?}"
        );
        scene.polls(4);
        assert_eq!(
            scene.owner.report.sent, sent,
            "PR-TEN-4: nothing follows the observation"
        );
    });
}

/// A response of the deposed tenure is in flight when the client's route rises to the same-generation successor:
/// the deposed owner's own frame names the successor while fragments of its answer are still arriving. The client
/// refuses every later frame of that response, its last included, ends the GET `SessionMismatch` with fewer bytes
/// than the object, and holds the successor's candidate route with the generation lit.
#[test]
fn a_deposed_tenures_response_in_flight_at_the_route_upgrade_is_refused_to_its_end() {
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    use crate::net::geometry::FRAGMENT_LEN;
    use crate::net::put_tests::upload_within;
    scene(&PRINCIPALS, |mut scene| {
        let object = crate::net::owner_tests::payload(6 * FRAGMENT_LEN as usize, 7);
        let (at, serial) = upload_within(&mut scene, &object, 60_000);
        for index in 0..6 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
            scene.turns(2);
        }
        scene.turns(20);
        let old = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let successor = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..two_above(old)
        };
        let deposed = OwnershipBody {
            shard,
            volume: Some(crate::net::ownership::Volume {
                name: "vol-0123456789abcdef0",
                state: WireState::Active,
            }),
            tenure: Some(successor),
            report_age_us: 0,
            responder: Some(old.host),
            validity: Validity::new(0).unwrap(),
        };
        let id = scene.clients[0]
            .get(
                crate::net::owner_tests::key(5),
                0,
                1 << 20,
                scene.turn * 100,
                30_000_000,
            )
            .unwrap();
        let mut bytes = Vec::new();
        let mut refused = 0;
        let mut upgraded = false;
        while scene.clients[0].outcome(id).is_none() {
            assert!(scene.turn < 10_000, "the GET ends");
            let report = scene.clients[0].poll(scene.turn * 100);
            refused += u32::from(upgraded) * report.unrouted;
            scene.turns(1);
            while let Some(fragment) = scene.clients[0].take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
            if !bytes.is_empty() && !upgraded {
                inject_reply(&mut scene, 0, Kind::Holder, deposed, true);
                upgraded = true;
            }
        }
        assert!(upgraded, "the route rose while the response was in flight");
        assert!(
            refused >= 1,
            "the route refuses the response frames that arrive after the upgrade"
        );
        assert!(bytes.len() < object.len(), "{} bytes surfaced", bytes.len());
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(Outcome::Incomplete(Status::SessionMismatch))
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Candidate(successor)),
            "the generation stays lit for the successor"
        );
    });
}

/// A read that returned a value beside a store outage still judges the view: another volume's record or another
/// shard's record clears it, though the outage lost the other read, and neither withdraws the tenure.
#[test]
fn a_returned_read_that_contradicts_the_view_clears_it_beside_an_outage() {
    for foreign_volume in [true, false] {
        scene(&PRINCIPALS, |mut scene| {
            install_view(&mut scene);
            assert_eq!(holder(&mut scene, 1).bits, Validity::ALL);
            let token = token(&scene);
            if foreign_volume {
                let other = volume_record("vol-0b", VolumeState::Active);
                observe(&mut scene, None, Some(other), token.exhid);
            } else {
                let other = ShardRecord {
                    shard: Shard::new(token.shard.get() + 1).unwrap(),
                    ..shard_at(token, token.generation.get(), token.epoch.get() / 2)
                };
                observe(&mut scene, Some(other), None, token.exhid);
            }
            assert!(!withdrawn(&scene), "foreign volume {foreign_volume}");
            assert_eq!(
                holder(&mut scene, 1).bits,
                0,
                "foreign volume {foreign_volume}: the returned read clears the view"
            );
        });
    }
}

/// An accepted shard read that names another volume active contradicts the serving judgment and clears it whatever
/// the volume read returned (obligation `tenure-bound-owner-sessions`; the doc on `OwnerView::fresh`). The read
/// deposes the tenure, so the stale judgment shows only after a same-process tenure replacement: the next tenure's
/// shard read alone, with the volume read lost, then asserts no validity bit.
#[test]
fn a_shard_read_naming_another_active_volume_clears_the_judgment_without_a_volume_read() {
    for volume_returned in [true, false] {
        scene(&PRINCIPALS, |mut scene| {
            install_view(&mut scene);
            let old = token(&scene);
            let elsewhere = ShardRecord {
                active: VolumeId::new("vol-0b").unwrap(),
                spare: None,
                ..shard_at(old, old.generation.get(), old.epoch.get() / 2)
            };
            observe(
                &mut scene,
                Some(elsewhere),
                volume_returned.then(|| volume_record("vol-0a", VolumeState::Active)),
                old.exhid,
            );
            assert!(
                withdrawn(&scene),
                "the session's tenure under another volume deposes"
            );
            serve_at(&mut scene, old.generation.get() + 1, 0);
            let new = token(&scene);
            observe(
                &mut scene,
                Some(shard_at(new, new.generation.get(), new.epoch.get() / 2)),
                None,
                new.exhid,
            );
            assert_eq!(
                holder(&mut scene, 1).bits,
                0,
                "volume read returned in the contradicting observation: {volume_returned}"
            );
        });
    }
}

#[test]
fn a_shard_read_alone_naming_the_own_volume_again_grants_no_bit_after_a_contradicting_read() {
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let serving = token(&scene);
        let own = shard_at(serving, serving.generation.get(), serving.epoch.get() / 2);
        let elsewhere = ShardRecord {
            active: VolumeId::new("vol-0b").unwrap(),
            spare: None,
            ..own
        };
        assert_eq!(view_bits(&scene), Validity::ALL);
        assert_eq!(
            observe_view(&mut scene, Some(elsewhere), None),
            Some(Cause::Flipped)
        );
        assert_eq!(view_bits(&scene), 0, "the record names another volume");
        assert_eq!(observe_view(&mut scene, Some(own), None), None);
        assert!(!withdrawn(&scene), "the authority's report is preserved");
        assert_eq!(
            view_bits(&scene),
            0,
            "the shard read alone names the own volume again"
        );
        let active = volume_record("vol-0a", VolumeState::Active);
        assert_eq!(observe_view(&mut scene, Some(own), Some(active)), None);
        assert_eq!(view_bits(&scene), Validity::ALL, "both reads returned");
    });
}

/// `Validity::LIVE` asserts that the last observation in which both reads returned a value named the reply's tenure
/// (obligation `tenure-bound-owner-sessions`). The view is fresh under the serving tenure, the storage tenure is
/// replaced in the same process by the generation's next activation, and one shard read names that activation over
/// the own volume while the volume read returns no value, before or after the replacement. No observation in which
/// both reads returned named the new tenure, so its Holder answer asserts no validity bit. The observation of the
/// new tenure in which both reads return is the sibling, and it restores every bit.
#[test]
fn a_shard_read_alone_naming_the_next_activation_grants_no_bit_to_the_new_tenure() {
    let mut answers = Vec::new();
    for read_first in [false, true] {
        scene(&PRINCIPALS, |mut scene| {
            install_view(&mut scene);
            let old = token(&scene);
            assert_eq!(holder(&mut scene, 1).bits, Validity::ALL);
            let attempts = old.epoch.get() / 2;
            let next = shard_at(old, old.generation.get(), attempts + 1);
            if read_first {
                observe(&mut scene, Some(next), None, old.exhid);
            }
            serve_at(&mut scene, old.generation.get(), attempts);
            let new = token(&scene);
            assert_eq!(new.epoch.get() / 2, attempts + 1);
            if !read_first {
                assert_eq!(holder(&mut scene, 1).bits, 0, "the old tenure's view");
                observe(&mut scene, Some(next), None, new.exhid);
            }
            let alone = holder(&mut scene, 1);
            assert_eq!(alone.tenure, Some(tenure_of(new)));
            observe(
                &mut scene,
                Some(next),
                Some(volume_record("vol-0a", VolumeState::Active)),
                new.exhid,
            );
            let both = holder(&mut scene, 1).bits;
            answers.push((read_first, alone.bits, both));
        });
    }
    assert_eq!(
        answers,
        [(false, 0, Validity::ALL), (true, 0, Validity::ALL)],
        "(read first, bits after the shard read alone, bits after both reads)"
    );
}

/// The ownership frames queued toward client 0, as kind and validity bits, left queued for the client.
fn queued_ownership(scene: &mut Scene<'_, '_>) -> Vec<(Kind, u8)> {
    let crc = scene.owner.crc;
    let mut queued = Vec::new();
    scene.nets[0].borrow_mut().retain(0, |bytes| {
        if let Ok(frame) = parse(crc, bytes, false) {
            let kind = frame.header().kind;
            if let Ok(body) = OwnershipBody::decode(kind, frame.raw_body()) {
                queued.push((kind, body.validity.bits()));
            }
        }
        true
    });
    queued
}

/// WITHHOLD-IS-AVAILABILITY over the wire: a failed store read leaves the owner's view current, so under a one-sided
/// store partition the withhold alone clears the serving and liveness bits. The PROBE answer before the withhold
/// asserts both and keeps the route Bound; the answer after it clears both and withdraws the route.
#[test]
fn a_withheld_owner_clears_serving_and_liveness_and_its_probe_answer_withdraws_the_route() {
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    use crate::failover::withhold::{M_US, W_US};
    struct Clock(std::rc::Rc<std::cell::Cell<u64>>);
    impl crate::storage::ServingClock for Clock {
        fn now_us(&self) -> Option<u64> {
            Some(self.0.get())
        }
    }
    let asserted = Validity::SERVING | Validity::LIVE;
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        assert_eq!(scene.read(0, 9, 0).0, Some(Outcome::Missing));
        scene.reopen(0);
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        (scene.owner).set_serving_clock(Box::new(Clock(std::rc::Rc::clone(&time))));
        let now = scene.turn * 100;
        (scene.owner).authority_event(Event::Refresh { at: 0 }, now);
        observe(&mut scene, None, None, own.host);
        (scene.owner).authority_event(Event::ReadFailed { sent_at: 1 }, now);
        time.set(W_US + 1);
        for withheld in [false, true] {
            if withheld {
                let now = scene.turn * 100;
                let peer = Event::Peer {
                    read_at: Some(M_US + 2),
                };
                (scene.owner).authority_event(peer, now);
            }
            let report = scene.owner.authority_report();
            assert_eq!(
                (report.state, report.withdrawal, report.withheld),
                (State::Serving, None, withheld)
            );
            inject_query(&mut scene, Kind::Probe, None, true);
            scene.turns(4);
            let queued = queued_ownership(&mut scene);
            let bits = queued
                .iter()
                .find(|(kind, _)| *kind == Kind::WrongOwner)
                .map(|&(_, bits)| bits & asserted);
            let expected = if withheld { 0 } else { asserted };
            assert_eq!(bits, Some(expected), "withheld {withheld}: {queued:?}");
            let report = scene.clients[0].poll(scene.turn * 100);
            assert!(report.received > 0, "withheld {withheld}: {report:?}");
            assert_eq!(report.unrouted, 0, "withheld {withheld}: {report:?}");
            let expected = if withheld {
                HighWater::Candidate(own)
            } else {
                HighWater::Bound(own)
            };
            assert_eq!(
                scene.clients[0].routes().route(shard),
                Some(expected),
                "withheld {withheld}"
            );
        }
    });
}

/// The completion boundary of a deposed tenure's response: every START and DATA frame arrives while the old route is
/// Bound, and the successor's Holder arrives just before the held COMPLETE in one receive batch. The route refuses that
/// COMPLETE, so the GET ends `Incomplete(SessionMismatch)` and never completes under the deposed tenure.
#[test]
fn a_complete_that_arrives_after_the_route_upgrade_is_refused() {
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    use crate::net::geometry::FRAGMENT_LEN;
    use crate::net::put_tests::upload_within;
    scene(&PRINCIPALS, |mut scene| {
        let object = crate::net::owner_tests::payload(6 * FRAGMENT_LEN as usize, 7);
        let (at, serial) = upload_within(&mut scene, &object, 60_000);
        for index in 0..6 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
            scene.turns(2);
        }
        scene.turns(20);
        let old = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        let id = scene.clients[0]
            .get(
                crate::net::owner_tests::key(5),
                0,
                1 << 20,
                scene.turn * 100,
                30_000_000,
            )
            .unwrap();
        let crc = scene.owner.crc;
        let mut complete = None;
        let mut bytes = Vec::new();
        while complete.is_none() {
            assert!(scene.turn < 10_000, "the owner sends the COMPLETE");
            scene.clients[0].poll(scene.turn * 100);
            scene.turns(1);
            while let Some(fragment) = scene.clients[0].take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
            scene.nets[0].borrow_mut().retain(0, |datagram| {
                let held = parse(crc, datagram, false)
                    .is_ok_and(|frame| frame.header().kind == Kind::Complete);
                if held {
                    complete = Some(datagram.to_vec());
                }
                !held
            });
        }
        for _ in 0..8 {
            scene.nets[0].borrow_mut().advance(scene.turn);
            scene.clients[0].poll(scene.turn * 100);
            while let Some(fragment) = scene.clients[0].take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
        }
        assert_eq!(
            scene.clients[0].outcome(id),
            None,
            "the GET waits on its COMPLETE"
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Bound(old))
        );
        assert_eq!(
            bytes, object,
            "every DATA frame arrived under the bound route"
        );
        let successor = Tenure {
            host: Exhid::new([0xA5; 16]).unwrap(),
            ..two_above(old)
        };
        let deposed = OwnershipBody {
            shard,
            volume: Some(crate::net::ownership::Volume {
                name: "vol-0123456789abcdef0",
                state: WireState::Active,
            }),
            tenure: Some(successor),
            report_age_us: 0,
            responder: Some(old.host),
            validity: Validity::new(0).unwrap(),
        };
        let mut body = vec![0; deposed.encoded_len()];
        deposed.encode(Kind::Holder, &mut body).unwrap();
        let mut header = session_header(&mut scene, 0, Kind::Holder, body.len());
        header.sequence = scene.owner.sessions.next_sequence(PeerId(0)).unwrap();
        let holder = sealed(&scene, 0, &header, &body, true, Direction::OwnerToClient);
        {
            let mut link = scene.nets[0].borrow_mut();
            link.inject(0, &holder);
            link.inject(0, &complete.unwrap());
            link.advance(scene.turn + 4);
        }
        let report = scene.clients[0].poll(scene.turn * 100);
        assert_eq!(
            report.unrouted, 1,
            "the route refuses the held COMPLETE: {report:?}"
        );
        assert_eq!(
            scene.clients[0].outcome(id),
            Some(Outcome::Incomplete(Status::SessionMismatch))
        );
        assert_eq!(
            scene.clients[0].routes().route(shard),
            Some(HighWater::Candidate(successor))
        );
    });
}

/// A store outage after a current shard view is no deposition and no withdrawal. Reads that return no value and a
/// failed-read mark leave the tenure Serving with no flip request, the reply buffered before them is sent, and the
/// owner's Holder and its WrongOwner on the session still assert serving, so the client's route stays Bound.
#[test]
fn a_store_outage_keeps_the_tenure_serving_and_its_route_bound() {
    use super::super::fetch::Outcome;
    use crate::failover::route::HighWater;
    scene(&PRINCIPALS, |mut scene| {
        install_view(&mut scene);
        let own = tenure_of(token(&scene));
        let shard = token(&scene).shard;
        assert_eq!(scene.read(0, 9, 0).0, Some(Outcome::Missing));
        // Client 0's READY is the route's latest binding admission, so a not-serving answer to its PROBE would
        // withdraw the route.
        scene.reopen(0);
        let ready = ready_for(&scene, own);
        assert!(scene.owner.reply(ready));
        let sent = scene.owner.report.sent;
        for _ in 0..2 {
            observe(&mut scene, None, None, own.host);
            let now = scene.turn * 100;
            (scene.owner).authority_event(Event::ReadFailed { sent_at: now }, now);
        }
        let report = scene.owner.authority_report();
        assert_eq!(
            (report.state, report.withdrawal, report.flip),
            (State::Serving, None, None)
        );
        assert_eq!(scene.owner.waiting, 1, "the reply stays buffered");
        scene.polls(1);
        assert!(
            scene.owner.report.sent > sent,
            "the outage withholds no reply"
        );
        for (kind, answer) in [
            (Kind::WhoHolds, Kind::Holder),
            (Kind::Probe, Kind::WrongOwner),
        ] {
            inject_query(&mut scene, kind, None, true);
            scene.turns(4);
            let queued = queued_ownership(&mut scene);
            assert!(
                queued.contains(&(answer, Validity::ALL)),
                "{kind:?}: the owner answers with a {answer:?} asserting serving: {queued:?}"
            );
            let report = scene.clients[0].poll(scene.turn * 100);
            assert!(report.received > 0, "{kind:?}: {report:?}");
            assert_eq!(report.unrouted, 0, "{kind:?}: {report:?}");
            assert_eq!(
                scene.clients[0].routes().route(shard),
                Some(HighWater::Bound(own)),
                "the answer to {kind:?} during the outage keeps the binding"
            );
        }
    });
}
