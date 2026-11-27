use crate::tools::{NAMES, entry};

#[test]
fn the_tool_table_is_sorted_and_every_name_has_an_entry() {
    assert!(NAMES.is_sorted(), "{NAMES:?}");
    assert!(
        NAMES.windows(2).all(|pair| pair[0] < pair[1]),
        "two tools share a name: {NAMES:?}"
    );
    assert!(NAMES.iter().all(|name| entry(name).is_some()));
    assert!(entry("check").is_none());
    // Out-of-order input covers a swap, the first differing byte and a name that is a prefix of another.
    assert_eq!(
        super::sorted(["b", "ab", "a_", "a", ""]),
        ["", "a", "a_", "ab", "b"]
    );
    // The aliases put fixture names in reverse order so the `NAMES` assertion distinguishes fixture-name
    // order from invocation order.
    mod sample {
        use super::super::{Entry, escrow_fixtures as zeta, gate_fixtures as alpha, sorted};
        tools!(alpha, zeta);
    }
    assert_eq!(sample::NAMES, ["escrow_fixtures", "gate_fixtures"]);
    assert!(sample::entry("gate_fixtures").is_some());
}
