//! Kani proof that the owner's request namespace admits each wire identity at
//! most once per session, the clause "each wire identity admits at most once
//! per session" of the obligation record
//! `exact-identity-gates-every-owner-mutation` and `OneAdmission` of
//! `tla/Identity.tla`, checked here against the production
//! [`Namespace`](super::namespace::Namespace) rather than the model.
//!
//! Bounds: one peer, one wire slot, a request table of two slots with a peer
//! share of two, and [`STEPS`] steps, so the proof runs at an unwinding of
//! `STEPS + 1`. Each step is a symbolic choice of admission, settlement,
//! drain and unbind, release or row retention, with a symbolic generation
//! in `0..=GENERATION_LIMIT`, a symbolic operation and a symbolic choice
//! among the handles admitted so far. Session retirement is outside the
//! proof: it starts a new session, in which a generation may admit again.

#[cfg(kani)]
mod verification {
    use crate::storage::EngineBudget;

    use super::super::datagram::PeerId;
    use super::super::namespace::{Cached, Namespace, Operated, Operation, Refusal};
    use super::super::requests::{GENERATION_LIMIT, RequestId, RequestTable};

    /// Steps of one symbolic history.
    const STEPS: usize = 4;

    /// A record or row standing for one request of its operation.
    #[derive(Clone, Copy)]
    struct Tagged(Operation);

    impl Operated for Tagged {
        fn operation(&self) -> Operation {
            self.0
        }
    }

    fn operation() -> Operation {
        if kani::any() {
            Operation::Put
        } else {
            Operation::Get
        }
    }

    /// A wire identity on wire slot 0 with a symbolic generation.
    fn wire() -> RequestId {
        let generation: u64 = kani::any();
        kani::assume(generation <= GENERATION_LIMIT);
        RequestId::from_wire(generation)
    }

    fn row() -> Cached<Tagged> {
        Cached {
            epoch: 1,
            expires_us: kani::any(),
            outcome: Tagged(operation()),
        }
    }

    /// Over every history of [`STEPS`] symbolic steps on one wire slot, no
    /// generation is admitted twice: each successful admission's generation
    /// differs from every earlier successful admission's.
    #[kani::proof]
    #[kani::unwind(5)]
    fn each_wire_identity_admits_at_most_once_per_session() {
        let peer = PeerId(0);
        let mut names = Namespace::<Tagged, Tagged>::new(
            RequestTable::new(2, 1, 2),
            1,
            &mut EngineBudget::new(1 << 16),
        )
        .unwrap();
        let mut admitted = [0u64; STEPS];
        let mut handles = [RequestId::from_wire(0); STEPS];
        let (mut count, mut stale, mut readmitted) = (0, false, false);
        let mut unbound = false;
        for _ in 0..STEPS {
            let pick: usize = kani::any();
            kani::assume(pick < STEPS);
            let handle = handles[pick];
            match kani::any::<u8>() {
                0 => {
                    let wire = wire();
                    let op = operation();
                    match names.admit(peer, wire, || Tagged(op)) {
                        Ok(id) => {
                            let generation = wire.generation();
                            for earlier in &admitted[..count] {
                                assert!(
                                    *earlier != generation,
                                    "a wire identity admitted twice in one session"
                                );
                            }
                            readmitted |= unbound;
                            admitted[count] = generation;
                            handles[count] = id;
                            count += 1;
                        }
                        Err(Refusal::Stale) => stale = true,
                        Err(_) => {}
                    }
                }
                1 => {
                    let wire = wire();
                    let cached = if kani::any() { Some(row()) } else { None };
                    names.settle(peer, wire, cached);
                }
                2 => {
                    if names.begin_drain(handle) {
                        names.unbind(peer, 0, handle);
                        unbound = true;
                    }
                }
                3 => {
                    names.release(handle, peer, 0);
                }
                _ => {
                    names.retain(peer, 0, handle, row());
                }
            }
        }
        kani::cover!(count >= 2, "two admissions on one wire slot");
        kani::cover!(stale, "an admission refused as stale");
        kani::cover!(readmitted, "an admission after an unbind");
    }
}
