use crate::tools::{NAMES, entry};

#[test]
fn the_tool_table_is_sorted_and_every_name_has_an_entry() {
    assert!(NAMES.is_sorted(), "{NAMES:?}");
    assert!(NAMES.iter().all(|name| entry(name).is_some()));
    assert!(entry("check").is_none());
    // Out-of-order input covers a swap, the first differing byte and a name that is a prefix of another.
    assert_eq!(super::sorted(["b", "ab", "a_", "a", ""]), ["", "a", "a_", "ab", "b"]);
}
