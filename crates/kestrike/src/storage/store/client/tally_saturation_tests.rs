//! The tally's saturating counts: a cell at `u64::MAX` stays there, and a total whose sum passes `u64::MAX` reads
//! `u64::MAX`.

use super::{Key, RecordClass, Tallied, Tally};

#[test]
fn a_count_at_its_limit_and_a_total_past_it_saturate() {
    let mut tally = Tally::default();
    tally.0[RecordClass::Page as usize][Tallied::Unknown as usize] = u64::MAX;
    tally.add(
        &Key::Page(crate::storage::store_tests::shard(), 0),
        Tallied::Unknown,
    );
    assert_eq!(tally.get(RecordClass::Page, Tallied::Unknown), u64::MAX);
    tally.add(
        &Key::Shard(crate::storage::store_tests::shard()),
        Tallied::Unknown,
    );
    assert_eq!(tally.get(RecordClass::Shard, Tallied::Unknown), 1);
    assert_eq!(tally.total(Tallied::Unknown), u64::MAX);
    assert_eq!(tally.total(Tallied::Unavailable), 0);
}
