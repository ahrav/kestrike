//! Kani proof of the client namespace's admission refusals, the clause of
//! the obligation record `client-uploads-refuse-the-clients-own-get-locally`
//! that a refused admission leaves the census and the next wire generation
//! unchanged, and that at the client namespace a refusal for an exhausted
//! generation fires before the wire slots and the table are consulted and
//! stays distinct from a table refusal; checked against the production
//! [`ClientNamespace`](super::client_namespace::ClientNamespace) over its
//! release board.
//!
//! Bounds: a board of two slots whose last wire generation is a symbolic
//! value of at most 3, a request table of two slots over two peers with a
//! peer share of two, and four steps ([`STEPS`]), so the proof runs at an
//! unwinding of five; three admissions and a refusal fit in four steps, and a
//! fifth step is not checked. Each step is a symbolic admission, by a symbolic peer
//! under a symbolic wire-slot cap of 0 through 2 and a symbolic operation,
//! or the release of a symbolic choice among the handles admitted so far.

#[cfg(kani)]
mod verification {
    use crate::storage::EngineBudget;

    use super::super::client_namespace::{ClientNamespace, ClientRecord, IdentityPressure};
    use super::super::datagram::PeerId;
    use super::super::fetch::Releases;
    use super::super::namespace::{Operated, Operation};
    use super::super::requests::{RequestId, RequestPressure, RequestTable};

    /// Steps of one symbolic history.
    const STEPS: usize = 4;

    struct Record {
        operation: Operation,
        peer: PeerId,
        wire: u64,
    }

    impl Operated for Record {
        fn operation(&self) -> Operation {
            self.operation
        }
    }

    impl ClientRecord for Record {
        fn peer(&self) -> PeerId {
            self.peer
        }

        fn wire(&self) -> u64 {
            self.wire
        }

        fn handed(&self) -> u32 {
            0
        }
    }

    /// Over every history of [`STEPS`] symbolic steps: an admission refused
    /// leaves the next wire generation and the census unchanged, and it is
    /// refused `Generations` exactly when the board has issued its last
    /// generation, whatever the wire slots and the table hold; an admission
    /// that succeeds carries the board's next generation and advances it by
    /// one.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_refusal_keeps_the_generation_and_the_census_and_exhaustion_refuses_first() {
        let last: u64 = kani::any();
        kani::assume(last <= 3);
        let mut budget = EngineBudget::new(1 << 16);
        let releases = Releases::with_generation_limit(2, last, &mut budget).unwrap();
        let mut requests =
            ClientNamespace::<Record>::new(RequestTable::new(2, 2, 2), &releases, &mut budget)
                .unwrap();
        let mut handles = [RequestId::from_wire(0); STEPS];
        let mut count = 0;
        let (mut exhausted, mut by_table, mut by_slots) = (false, false, false);
        for _ in 0..STEPS {
            if kani::any() {
                let pick: usize = kani::any();
                kani::assume(pick < count);
                requests.release(handles[pick]);
                continue;
            }
            let peer = PeerId(u16::from(kani::any::<bool>()));
            let cap: u32 = kani::any();
            kani::assume(cap <= 2);
            let operation = if kani::any() {
                Operation::Put
            } else {
                Operation::Get
            };
            let (next, census) = (releases.next_generation(), requests.table().census());
            let mut issued = None;
            let admitted = requests.admit(peer, cap, |wire| {
                issued = Some(wire);
                Record {
                    operation,
                    peer,
                    wire,
                }
            });
            match admitted {
                Ok(id) => {
                    let wire = issued.expect("an admission builds its record");
                    let generation = RequestId::from_wire(wire).generation();
                    assert!(
                        next == Some(generation),
                        "an admission carries the board's next generation"
                    );
                    assert!(
                        releases.next_generation() == (generation < last).then_some(generation + 1),
                        "an admission advances the board by one"
                    );
                    handles[count] = id;
                    count += 1;
                }
                Err(refusal) => {
                    assert!(
                        releases.next_generation() == next && requests.table().census() == census,
                        "a refusal changes the generation counter or the census"
                    );
                    assert!(
                        (refusal == IdentityPressure::Generations) == next.is_none(),
                        "an exhausted board refuses first and only as Generations"
                    );
                    exhausted |= refusal == IdentityPressure::Generations && census.live() > 0;
                    by_table |= refusal == IdentityPressure::Requests(RequestPressure::Table);
                    by_slots |= refusal == IdentityPressure::Requests(RequestPressure::Peer);
                }
            }
        }
        kani::cover!(count >= 3, "three admissions");
        kani::cover!(exhausted, "an exhausted board beside a live request");
        kani::cover!(by_table, "a table refusal");
        kani::cover!(by_slots, "a wire-slot refusal");
    }
}
