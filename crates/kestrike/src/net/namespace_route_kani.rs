//! Kani proof that the owner's request namespace routes a frame to a request
//! or a retained row only under that request's own peer, wire slot,
//! generation and operation, the owner-namespace half of the clause "a frame,
//! release or retain reaches a request only under its peer, wire slot,
//! generation and operation; an operation mismatch counts WrongOperation" of
//! the obligation record `wire-identity-bounds-every-effect`, checked against
//! the production [`Namespace`](super::namespace::Namespace) and its packed
//! wire-slot words.
//!
//! Bounds: two peers, one wire slot each, a request table of two slots with a
//! peer share of two, and [`STEPS`] steps, so the proof runs at an unwinding
//! of `STEPS + 1`. Each step is a symbolic choice of admission, settlement,
//! drain and unbind, release, row retention or a routed frame, by a symbolic
//! peer, with a symbolic generation in `0..=GENERATION_LIMIT`, a symbolic
//! operation and a symbolic choice among the handles admitted so far. A
//! final symbolic frame is then looked up and routed. Session retirement and
//! the client board are outside the proof.

#[cfg(kani)]
mod verification {
    use crate::storage::EngineBudget;

    use super::super::datagram::PeerId;
    use super::super::namespace::{Cached, Namespace, Operated, Operation, Route};
    use super::super::requests::{GENERATION_LIMIT, RequestId, RequestTable};

    /// Steps of one symbolic history.
    const STEPS: usize = 3;

    /// A record or row standing for one request: the peer that admitted or
    /// settled it, its wire ID and its operation.
    #[derive(Clone, Copy)]
    struct Tagged {
        peer: u16,
        wire: u64,
        operation: Operation,
    }

    impl Operated for Tagged {
        fn operation(&self) -> Operation {
            self.operation
        }
    }

    fn operation() -> Operation {
        if kani::any() {
            Operation::Put
        } else {
            Operation::Get
        }
    }

    fn peer() -> PeerId {
        PeerId(u16::from(kani::any::<bool>()))
    }

    /// A wire identity on wire slot 0 with a symbolic generation.
    fn wire() -> RequestId {
        let generation: u64 = kani::any();
        kani::assume(generation <= GENERATION_LIMIT);
        RequestId::from_wire(generation)
    }

    fn row(peer: PeerId, wire: RequestId) -> Cached<Tagged> {
        Cached {
            epoch: 1,
            expires_us: kani::any(),
            outcome: Tagged {
                peer: peer.0,
                wire: wire.wire(),
                operation: operation(),
            },
        }
    }

    /// After every history of [`STEPS`] symbolic steps over two peers, a
    /// symbolic frame that routes `Same` with a live request names a record
    /// its own peer admitted under the frame's exact wire ID and operation,
    /// and a retained row it reaches has the frame's operation; a frame whose
    /// route is `WrongOperation` names the slot's watermark, and routing it
    /// moves the wrong-operation count by one and leaves the census and the
    /// slot unchanged, every field of a retained row included.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_frame_reaches_only_its_own_peers_request_of_its_identity_and_operation() {
        let mut names = Namespace::<Tagged, Tagged>::new(
            RequestTable::new(2, 2, 2),
            1,
            &mut EngineBudget::new(1 << 16),
        )
        .unwrap();
        let mut handles = [RequestId::from_wire(0); STEPS];
        let mut count = 0;
        for _ in 0..STEPS {
            let pick: usize = kani::any();
            kani::assume(pick < STEPS);
            let handle = handles[pick];
            let peer = peer();
            let wire = wire();
            match kani::any::<u8>() {
                0 => {
                    let operation = operation();
                    let record = Tagged {
                        peer: peer.0,
                        wire: wire.wire(),
                        operation,
                    };
                    if let Ok(id) = names.admit(peer, wire, || record) {
                        handles[count] = id;
                        count += 1;
                    }
                }
                1 => {
                    let cached = if kani::any() {
                        Some(row(peer, wire))
                    } else {
                        None
                    };
                    names.settle(peer, wire, cached);
                }
                2 => {
                    if names.begin_drain(handle) {
                        names.unbind(peer, 0, handle);
                    }
                }
                3 => {
                    names.release(handle, peer, 0);
                }
                4 => {
                    names.route(peer, wire, operation());
                }
                _ => {
                    names.retain(peer, 0, handle, row(peer, wire));
                }
            }
        }
        let (peer, wire, operation) = (peer(), wire(), operation());
        let watermark = names.slot(peer, 0).unwrap().watermark;
        match names.lookup(peer, wire, operation) {
            Route::Same { active, cached } => {
                if let Some(id) = active {
                    let record = names.table().get(id).expect("a bound handle is live");
                    assert!(
                        record.peer == peer.0
                            && record.wire == wire.wire()
                            && record.operation == operation,
                        "a frame reaches a request of another identity or operation"
                    );
                    kani::cover!(true, "a frame reaches its live request");
                }
                if let Some(row) = cached {
                    assert!(
                        row.outcome.operation == operation,
                        "a frame reaches a row of another operation"
                    );
                    kani::cover!(true, "a frame reaches its retained row");
                }
                assert_eq!(watermark, Some(wire.generation()));
            }
            Route::WrongOperation => {
                assert_eq!(watermark, Some(wire.generation()));
                let (census, wrong) = (names.census(), names.wrong_operation());
                let before = names.slot(peer, 0).unwrap();
                assert!(matches!(
                    names.route(peer, wire, operation),
                    Route::WrongOperation
                ));
                let after = names.slot(peer, 0).unwrap();
                let row_kept = match (before.cached, after.cached) {
                    (None, None) => true,
                    (Some(kept), Some(read)) => {
                        let Cached {
                            epoch,
                            expires_us,
                            outcome:
                                Tagged {
                                    peer: owner,
                                    wire: identity,
                                    operation: kind,
                                },
                        } = kept;
                        read.epoch == epoch
                            && read.expires_us == expires_us
                            && read.outcome.peer == owner
                            && read.outcome.wire == identity
                            && read.outcome.operation == kind
                    }
                    _ => false,
                };
                assert!(
                    names.wrong_operation() == wrong + 1
                        && names.census() == census
                        && after.watermark == before.watermark
                        && after.active == before.active
                        && row_kept
                        && after.refused == before.refused,
                    "a wrong-operation frame changes more than its count"
                );
                kani::cover!(true, "a frame names another operation");
                kani::cover!(
                    before.cached.is_some(),
                    "a frame names another operation at a slot that holds a row"
                );
            }
            Route::Older => {
                assert!(watermark.is_some_and(|mark| wire.generation() < mark));
                kani::cover!(true, "a frame names an older generation");
            }
            Route::Fresh => {
                assert!(watermark.is_none_or(|mark| wire.generation() > mark));
            }
            Route::Outside => unreachable!("wire slot 0 of peers 0 and 1 lies inside"),
        }
    }
}
