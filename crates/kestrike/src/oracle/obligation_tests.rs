//! The obligation table carries every field for each of the eight
//! obligations and names only well-formed property identifiers.

use std::collections::HashSet;

use super::obligation::{
    Family, HANDOFF_ALIASES, OBLIGATIONS, Obligation, PROPOSED_RECORDS, PUT_RECORDS, PropertyId,
};

#[test]
fn every_obligation_has_every_table_field() {
    let aliases = [
        "O-BYTES",
        "O-HISTORY",
        "O-CUSTODY",
        "O-RESOURCES",
        "O-RESTART",
        "O-PROGRESS",
        "O-ISOLATION",
        "O-CONTAIN",
    ];
    for (obligation, alias) in Obligation::ALL.into_iter().zip(aliases) {
        let spec = obligation.spec();
        assert_eq!(spec.obligation, obligation);
        assert_eq!(spec.alias, alias);
        for (name, text) in [
            ("rule", spec.rule),
            ("operation path", spec.operation_path),
            ("checkpoint", spec.checkpoint),
            ("counterexample owner", spec.counterexample_owner),
        ] {
            assert!(!text.trim().is_empty(), "{alias} {name}");
        }
        for (name, list) in [
            ("permitted", spec.permitted),
            ("forbidden", spec.forbidden),
            ("premises", spec.premises),
            ("coverage", spec.coverage),
            ("fault witness", spec.fault_witness),
        ] {
            assert!(!list.is_empty(), "{alias} {name}");
            assert!(list.iter().all(|s| !s.trim().is_empty()), "{alias} {name}");
        }
        assert!(spec.premises.contains(&"one episode"), "{alias}");
    }
}

#[test]
fn coverage_names_only_well_formed_property_identifiers() {
    for spec in &OBLIGATIONS {
        let mut seen = HashSet::new();
        for id in spec.coverage {
            assert!(PropertyId::parse(id).is_some(), "{}: {id}", spec.alias);
            assert!(seen.insert(*id), "{}: duplicate {id}", spec.alias);
        }
        assert!(PropertyId::parse(spec.alias).is_none(), "{}", spec.alias);
    }
    for text in [
        "O-BYTES", "P-E-1", "P-E-001", "P-X-01", "P-N-00", "P-E-4a", "p-e-01", "P-N-011",
        "P-N-1111",
    ] {
        assert_eq!(PropertyId::parse(text), None, "{text}");
    }
    assert_eq!(
        PropertyId::parse("P-E-09"),
        Some(PropertyId {
            family: Family::E,
            number: 9,
        })
    );
    assert_eq!(
        PropertyId::parse("P-N-134"),
        Some(PropertyId {
            family: Family::N,
            number: 134,
        })
    );
}

#[test]
fn each_proposed_record_is_well_formed_and_covers_its_obligation() {
    let mut seen = HashSet::new();
    for (id, slug, obligation) in PROPOSED_RECORDS {
        assert!(PropertyId::parse(id).is_some(), "{id}");
        assert!(seen.insert(*id), "duplicate {id}");
        assert!(is_slug(slug), "{id}: {slug}");
        if let Some(obligation) = obligation {
            assert!(
                obligation.spec().coverage.contains(id),
                "{id} under {obligation:?}"
            );
        }
    }
}

#[test]
fn checker_location_and_evidence_label_follow_the_obligation() {
    use super::obligation::CheckerLocation::{Global, PerKey};
    use super::obligation::EvidenceLabel::{Abstract, Live, Qualified};
    let live: &[_] = &[Live];
    let expected = [
        (Obligation::Bytes, PerKey, live),
        (Obligation::History, PerKey, live),
        (Obligation::Custody, Global, live),
        (Obligation::Resources, Global, live),
        (Obligation::Restart, PerKey, &[Abstract, Qualified]),
        (Obligation::Progress, Global, live),
        (Obligation::Isolation, Global, live),
        (Obligation::Contain, PerKey, live),
    ];
    for (obligation, checker, evidence) in expected {
        assert_eq!(obligation.spec().checker, checker, "{obligation:?}");
        assert_eq!(obligation.spec().evidence, evidence, "{obligation:?}");
    }
}

fn is_slug(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[test]
fn every_put_record_is_well_formed_and_covered() {
    let covered: HashSet<&str> = OBLIGATIONS
        .iter()
        .flat_map(|spec| spec.coverage.iter().copied())
        .collect();
    let mut seen = HashSet::new();
    for (id, name) in PUT_RECORDS {
        assert!(PropertyId::parse(id).is_some(), "{id}");
        assert!(seen.insert(*id), "duplicate {id}");
        assert!(covered.contains(id), "{id}");
        assert!(is_slug(name), "{id}: {name}");
    }
}

#[test]
fn handoff_aliases_name_uncovered_put_subclaims_without_an_identifier() {
    assert!(!HANDOFF_ALIASES.is_empty());
    let mut seen = HashSet::new();
    for (alias, subclaim, _) in HANDOFF_ALIASES {
        assert!(is_slug(alias), "{alias}");
        assert!(alias.starts_with("put-"), "{alias}");
        assert!(seen.insert(*alias), "duplicate {alias}");
        assert_eq!(PropertyId::parse(alias), None, "{alias}");
        assert!(!subclaim.trim().is_empty(), "{alias}");
    }
}
