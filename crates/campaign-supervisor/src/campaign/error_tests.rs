use super::Error;

#[test]
fn input_path_preserves_store_identity_and_host_faults() {
    let replaced = Error::input_path(crate::store::Error::Replaced);
    assert!(matches!(
        replaced,
        Error::Store(crate::store::Error::Replaced)
    ));
    assert_eq!(replaced.held_code(), "store");
    assert_eq!(replaced.exit(), crate::exit::Supervisor::Held);
    let io = Error::input_path(crate::store::Error::Io(std::io::Error::from_raw_os_error(
        libc::EIO,
    )));
    assert!(matches!(io, Error::Store(crate::store::Error::Io(_))));
    assert!(io.host_fault());
    assert_eq!(io.held_code(), "store");
    assert_eq!(io.exit(), crate::exit::Supervisor::Held);
    assert!(matches!(
        Error::input_path(crate::store::Error::Refused(
            crate::store::Refusal::Unmarked
        )),
        Error::Rejected(_)
    ));
}

#[test]
fn every_descriptor_error_wrapper_names_the_limit() {
    for errno in [libc::EMFILE, libc::EIO] {
        let io = || std::io::Error::from_raw_os_error(errno);
        let cases = [
            (
                Error::Store(crate::store::Error::Io(io())),
                crate::store::Error::Io(io()).to_string(),
            ),
            (
                Error::Store(crate::store::Error::Unreadable(
                    crate::store::Unreadable::Io(io()),
                )),
                crate::store::Error::Unreadable(crate::store::Unreadable::Io(io())).to_string(),
            ),
            (
                Error::Unreadable(crate::store::Unreadable::Io(io())),
                crate::store::Unreadable::Io(io()).to_string(),
            ),
            (
                Error::Record(crate::record::Held::Unreadable(
                    crate::store::Unreadable::Io(io()),
                )),
                crate::record::Held::Unreadable(crate::store::Unreadable::Io(io())).to_string(),
            ),
        ];
        for (error, original) in cases {
            let expected = if errno == libc::EMFILE {
                format!("descriptor limit reached (RLIMIT_NOFILE): {}", io())
            } else {
                original
            };
            assert_eq!(error.to_string(), expected);
        }
    }
}

#[test]
fn custody_refusals_preserve_rejection_and_hold_classes() {
    for error in [
        crate::custody::Error::Held("charged"),
        crate::custody::Error::Io(std::io::Error::from_raw_os_error(libc::EIO)),
    ] {
        let error = Error::custody(error);
        assert!(matches!(error, Error::Custody(_)));
        assert!(crate::campaign::triage::global(&error));
    }
    assert!(matches!(
        Error::custody(crate::custody::Error::Rejected("invalid limits")),
        Error::Rejected(_)
    ));
    assert!(matches!(
        Error::custody(crate::custody::Error::Store(crate::store::Error::Poisoned)),
        Error::Store(crate::store::Error::Poisoned)
    ));
    assert!(matches!(
        Error::custody(crate::custody::Error::Record(crate::record::Held::Mismatch)),
        Error::Record(crate::record::Held::Mismatch)
    ));
    assert!(matches!(
        Error::from(crate::custody::Error::Rejected("invalid limits")),
        Error::Rejected(reason) if reason == "custody rejected: invalid limits"
    ));
    assert!(matches!(
        Error::from(crate::custody::Error::Held("charged")),
        Error::Held(reason) if reason == "custody held: charged"
    ));
    assert!(matches!(
        Error::from(crate::custody::Error::Store(crate::store::Error::Poisoned)),
        Error::Store(crate::store::Error::Poisoned)
    ));
}

/// Capture's findings hold converts to the campaign bound hold with the
/// same text, exit and code, so every findings path prints one hold.
#[test]
fn custody_bound_converts_to_the_campaign_bound_hold() {
    let custody = crate::custody::Error::Bound {
        root: "findings".to_owned(),
        entries: Some(7),
        bound: 7,
    };
    let text = custody.to_string();
    assert_eq!(custody.exit(), crate::exit::Supervisor::Held);
    let error = Error::from(custody);
    assert!(matches!(
        &error,
        Error::Bound { root, entries: Some(7), bound: 7 } if root == "findings"
    ));
    assert_eq!(error.to_string(), text);
    assert_eq!(
        text,
        "findings holds 7 entries at bound 7; collect or shard"
    );
}

/// Every bound constructor exits held, reports `scan-bound` and is a global
/// triage error; a listing error other than the bound keeps its store form.
#[test]
fn a_bound_hold_exits_held_and_is_global() {
    for error in [
        Error::bound("jobs", 3),
        Error::over("jobs"),
        Error::listing("jobs", crate::store::Error::ScanBound),
        Error::Store(crate::store::Error::ScanBound),
    ] {
        assert!(error.at_scan_bound(), "{error}");
        assert_eq!(error.exit(), crate::exit::Supervisor::Held, "{error}");
        assert_eq!(error.held_code(), "scan-bound", "{error}");
        assert!(crate::campaign::triage::global(&error), "{error}");
    }
    assert_eq!(
        Error::bound("jobs", 3).to_string(),
        format!(
            "jobs holds 3 entries at bound {0}; collect or shard",
            crate::scan_bound()
        )
    );
    assert_eq!(
        Error::over("jobs").to_string(),
        format!(
            "jobs holds more than {0} entries at bound {0}; collect or shard",
            crate::scan_bound()
        )
    );
    let passed = Error::listing("jobs", crate::store::Error::Poisoned);
    assert!(matches!(
        passed,
        Error::Store(crate::store::Error::Poisoned)
    ));
    assert!(!passed.at_scan_bound());
}

#[test]
fn custody_host_fault_conversion_preserves_global_policy() {
    for errno in [libc::EIO, libc::EMFILE] {
        let error = Error::from(crate::custody::Error::Io(
            std::io::Error::from_raw_os_error(errno),
        ));
        assert!(crate::campaign::triage::global(&error));
        assert!(matches!(
            error,
            Error::Store(crate::store::Error::Unreadable(_))
        ));
    }
    let error = Error::from(crate::custody::Error::Io(
        std::io::Error::from_raw_os_error(libc::EACCES),
    ));
    assert!(!crate::campaign::triage::global(&error));
    assert!(matches!(error, Error::Held(_)));
}

/// Projection propagates a scan bound in either form and records every
/// other recoverable failure as a held row.
#[test]
fn projection_propagates_both_scan_bound_forms() {
    for error in [
        Error::Store(crate::store::Error::ScanBound),
        Error::over("jobs"),
    ] {
        let text = error.to_string();
        let mut rows = Vec::new();
        let propagated = super::super::projection::held(&mut rows, "jobs", error).unwrap_err();
        assert_eq!(propagated.to_string(), text);
        assert!(rows.is_empty());
    }
    let mut rows = Vec::new();
    super::super::projection::held(&mut rows, "jobs", Error::Held("held".into())).unwrap();
    assert_eq!(rows.len(), 1);
}
