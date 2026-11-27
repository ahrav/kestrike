use std::ffi::OsString;

use crate::environ::{Environ, get, set};

fn environ(pairs: &[(&str, &str)]) -> Environ {
    pairs
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect()
}

/// `get` reads the first variable of a name and `None` for an absent one; `set` removes every variable of
/// the name and appends one, keeping the others in order.
#[test]
fn set_replaces_every_variable_of_its_name_and_get_reads_the_first() {
    let mut env = environ(&[("A", "1"), ("B", "2"), ("A", "3"), ("C", "")]);
    assert_eq!(get(&env, "A"), Some(&OsString::from("1")));
    assert_eq!(get(&env, "C"), Some(&OsString::new()));
    assert_eq!(get(&env, "D"), None);
    set(&mut env, "A", OsString::from("4"));
    assert_eq!(env, environ(&[("B", "2"), ("C", ""), ("A", "4")]));
    set(&mut env, "D", OsString::from("5"));
    assert_eq!(get(&env, "D"), Some(&OsString::from("5")));
}
