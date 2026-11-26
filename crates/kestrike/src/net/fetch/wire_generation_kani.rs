//! Kani proof of the release board's wire-generation counter: over three
//! consecutive admissions, [`Releases::next_generation`](super::Releases)
//! answers each generation at most once, in increasing order and never past
//! the board's last, and once it refuses it keeps refusing. Every generation
//! it answers fits the wire ID's generation field, so two requests of one
//! board carry different wire IDs whatever slots they take.
//!
//! Bounds: a board of one request slot whose next and last generations are
//! symbolic `u64`s, the last at most `GENERATION_LIMIT - 1`, the largest a
//! board is built with outside tests. Three admission steps follow, each a
//! `next_generation` call and, when it answers, the `issue` that records it;
//! the wire slot is a symbolic `u16`. The constructor's loops over the one
//! slot and the one mark word, and the walk over the three steps, unwind at most four times. The proof covers
//! the board's counter and not the namespace's refusals, which read the
//! counter and issue nothing.

#[cfg(kani)]
mod verification {
    use super::super::{EngineBudget, GENERATION_LIMIT, Releases, RequestId};

    /// The admission steps the proof takes.
    const STEPS: usize = 3;

    /// One admission: the generation the board answers, recorded as issued to the request in table slot 0.
    fn admit(board: &Releases) -> Option<u64> {
        let generation = board.next_generation()?;
        board.issue(generation, RequestId::from_wire(generation));
        Some(generation)
    }

    /// Over one symbolic counter state: each answered generation lies at or above the starting counter and at most the
    /// board's last, a later answer exceeds every earlier one, a refusal is followed only by refusals, the board's last
    /// generation is followed by a refusal, and a wire ID built from an answered generation under any slot decodes to
    /// that slot and generation.
    #[kani::proof]
    #[kani::unwind(4)]
    fn the_board_issues_each_wire_generation_once_in_order_and_refuses_after_its_last() {
        let last: u64 = kani::any();
        kani::assume(last < GENERATION_LIMIT);
        let mut budget = EngineBudget::new(usize::MAX);
        let Ok(board) = Releases::with_generation_limit(1, last, &mut budget) else {
            unreachable!("the budget holds a one-slot board");
        };
        let start: u64 = kani::any();
        board.next_wire.set(start);
        let slot: u16 = kani::any();

        let issued = [admit(&board), admit(&board), admit(&board)];
        kani::cover!(issued[0].is_none());
        kani::cover!(issued[0] == Some(last) && start > 0);
        kani::cover!(issued[STEPS - 1].is_some());
        kani::cover!(issued[1] == Some(last));

        let mut previous: Option<u64> = None;
        let mut refused = false;
        let mut step = 0;
        while step < STEPS {
            match issued[step] {
                Some(generation) => {
                    assert!(!refused, "a board that refused issues nothing later");
                    assert!(
                        (start..=last).contains(&generation),
                        "an issued generation lies between the counter and the board's last"
                    );
                    assert!(
                        previous.is_none_or(|previous| previous < generation),
                        "issued generations strictly increase"
                    );
                    assert!(
                        previous != Some(last),
                        "the board refuses after its last generation"
                    );
                    let id = RequestId::from_wire(u64::from(slot) << 48 | generation);
                    assert!(
                        id.slot() == slot && id.generation() == generation,
                        "an issued generation fits the wire ID beside any slot"
                    );
                    previous = Some(generation);
                }
                None => refused = true,
            }
            step += 1;
        }
        assert_eq!(
            issued[0].is_some(),
            start <= last,
            "the board refuses exactly when its counter passed its last generation"
        );
    }
}
