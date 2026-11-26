use super::fixture::{Case, name};
use super::{Error, Store};
use crate::step::{self, Script, Step};
use std::fs;

#[test]
fn census_counts_nested_store_housekeeping_and_tolerates_a_vanished_staging_entry() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("nested")).unwrap();
    let nested = Store::open(&case.state.join("nested")).unwrap();
    nested
        .create_once(nested.root(), &name("evidence"), b"captured evidence")
        .unwrap();
    drop(nested);
    let expected = fs::read(case.state.join(".state")).unwrap().len() as u64
        + fs::read(case.state.join("nested/.state")).unwrap().len() as u64
        + b"captured evidence".len() as u64;
    let usage = store.usage(10).unwrap();
    assert_eq!(usage.bytes, expected);
    assert_eq!(usage.inodes, 6);
    let vanished = case.state.join("nested/.staging/transient");
    fs::write(&vanished, b"staged output").unwrap();
    step::install(Some(Script::default()));
    let baseline = store.usage(10).unwrap();
    let trace = step::install(None).unwrap();
    assert_eq!(baseline.inodes, 7);
    assert_eq!(baseline.bytes, expected + b"staged output".len() as u64);
    let lists = trace.reached.iter().filter(|at| **at == Step::List).count();
    let remove = vanished.clone();
    let mut listed = 0;
    let removed = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = removed.clone();
    step::install(Some(Script {
        observe: Some(Box::new(move |at| {
            if at == Step::List {
                listed += 1;
            }
            if listed == lists && at == Step::Open && remove.exists() {
                fs::remove_file(&remove).unwrap();
                observed.set(true);
            }
        })),
        ..Script::default()
    }));
    let usage = store.usage(10).unwrap();
    step::install(None);
    assert!(removed.get());
    assert!(!vanished.exists());
    assert_eq!(usage.bytes, expected);
    assert_eq!(usage.inodes, 6);
    assert!(matches!(store.usage(5), Err(Error::ScanBound)));
}
