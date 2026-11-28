use super::check_correspondence;
use crate::genmc::case::tests::{case_of, declaration, root};
use crate::genmc::refusal::Error;
use crate::genmc::transcription::{check_transcription, transcription_drift};
use crate::json::{Text, Value, parse};

fn edited(change: impl FnOnce(&mut Value)) -> Value {
    let mut declared = declaration();
    change(&mut declared);
    declared
}

fn refusal(declared: &Value) -> String {
    match check_correspondence(&root(), declared) {
        Err(Error::Refusal(refusal)) => refusal.reason().to_owned(),
        other => panic!("a refusal, not {other:?}"),
    }
}

#[test]
fn the_declaration_at_the_head_passes_both_checks() {
    let declared = declaration();
    assert!(check_correspondence(&root(), &declared).is_ok());
    assert!(check_transcription(&root(), &declared).is_ok());
}

#[test]
fn a_case_agrees_with_the_outcome_of_every_litmus_test_it_names() {
    let undeclared = edited(|declared| {
        case_of(declared, "join-production").insert(
            "litmus",
            parse(r#"["F0-fill-terminal-production", "no-such-test"]"#).expect("JSON"),
        );
    });
    assert_eq!(
        refusal(&undeclared),
        "join-production names an undeclared litmus test among \
         ['F0-fill-terminal-production', 'no-such-test']"
    );
    let other_kind = edited(|declared| {
        case_of(declared, "join-production")
            .insert("litmus", parse(r#"["L0-no-fences"]"#).expect("JSON"));
    });
    assert_eq!(
        refusal(&other_kind),
        "join-production is declared positive and its litmus tests ['L0-no-fences'] are \
         ['Sometimes']"
    );
    let mixed = edited(|declared| {
        case_of(declared, "join-relaxeddepart").insert(
            "litmus",
            parse(r#"["L0-no-fences", "L1-both-fences"]"#).expect("JSON"),
        );
    });
    assert_eq!(
        refusal(&mixed),
        "join-relaxeddepart is declared violation and its litmus tests ['L0-no-fences', \
         'L1-both-fences'] are ['Sometimes', 'Never']"
    );
    let unlisted = edited(|declared| {
        case_of(declared, "join-production").remove("litmus");
    });
    assert_eq!(refusal(&unlisted), "join-production names no litmus list");
}

fn binding<'v>(declared: &'v mut Value, id: &str) -> &'v mut crate::json::Object {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Array(bindings)) = declared.get_mut("bindings") else {
        panic!("the declaration holds bindings");
    };
    bindings
        .iter_mut()
        .find_map(|entry| match entry {
            Value::Object(entry) if entry.get("id") == Some(&Value::String(id.into())) => {
                Some(entry)
            }
            _ => None,
        })
        .expect("the binding is declared")
}

fn site<'v>(entry: &'v mut crate::json::Object, side: &str) -> &'v mut crate::json::Object {
    let Some(Value::Object(site)) = entry.get_mut(side) else {
        panic!("the binding has the side");
    };
    site
}

fn strengths_of(declared: &mut Value) -> &mut Vec<Value> {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Array(strengths)) = declared.get_mut("strengths") else {
        panic!("the declaration holds strengths");
    };
    strengths
}

fn strength(declared: &mut Value) -> &mut crate::json::Object {
    let Some(Value::Object(strength)) = strengths_of(declared).first_mut() else {
        panic!("the declaration holds a strength");
    };
    strength
}

/// The drift of the grace kernel's binding entries once no declared strength defines their constants.
fn undefined(package: &str) -> Vec<String> {
    let kernel = format!("{package}/src/grace_kernel.rs");
    let mut drift: Vec<String> = [
        ("claim-load", "CLAIM_LOAD"),
        ("claim-raise", "CLAIM_RAISE"),
        ("pass-bound-load", "BOUND_LOAD"),
        ("sequence-first-load", "OBSERVE"),
        ("sequence-commit", "COMMIT"),
    ]
    .iter()
    .map(|(id, constant)| {
        format!(
            "{id}: the kernel names S::{constant}, which no declared strength of {kernel} defines"
        )
    })
    .collect();
    drift.push(
        "retain-current-load: the kernel anchor entry sequence-first-load was not located".into(),
    );
    drift
}

fn json(text: &str) -> Value {
    parse(text).expect("JSON")
}

#[test]
fn one_drifted_binding_of_each_kind_is_correspondence_drift() {
    let package = "verification/genmc/packages/kernels";
    #[rustfmt::skip]
    let rows: Vec<(&str, Value, Vec<String>)> = vec![
        ("load", edited(|d| binding(d, "claim-load").insert("orderings", json(r#"["Acquire"]"#))), vec![
            "claim-load: the production orderings are ['SeqCst'], bound ['Acquire']".into(),
            "claim-load: the kernel orderings are ['SeqCst'], bound ['Acquire']".into(),
        ]),
        ("rmw", edited(|d| site(binding(d, "claim-raise"), "production").insert("call", json(r#""bound.load""#))), vec![
            "claim-raise: the production bound.load is no rmw".into(),
            "claim-load: the production anchor entry claim-raise was not located".into(),
        ]),
        ("call", edited(|d| site(binding(d, "claim-before-pin"), "kernel").insert("scope", json(r#"["fn absent"]"#))), vec![
            format!("claim-before-pin: the kernel scope fn absent in {package}/src/grace_kernel.rs appears 0 times"),
            "sequence-first-load: the kernel anchor entry claim-before-pin was not located".into(),
        ]),
        ("store", edited(|d| site(binding(d, "sequence-odd-store"), "production")
            .insert("file", json(r#""crates/kestrike/src/lib.rs""#))), vec![
            "sequence-odd-store: crates/kestrike/src/lib.rs is not among the transcribed files".into(),
            "sequence-odd-fence: the production anchor entry sequence-odd-store was not located".into(),
        ]),
        ("fence", edited(|d| binding(d, "sequence-odd-fence").insert("operands", json(r#"["x"]"#))), vec![
            "sequence-odd-fence: the production W::fence_release operands are [[]], bound ['x']".into(),
            "sequence-odd-store: the production anchor entry sequence-odd-fence was not located".into(),
        ]),
        ("cas", edited(|d| site(binding(d, "anchored-park"), "production").insert("before", json(r#"["no such text"]"#))), vec![
            "anchored-park: the production anchor 'no such text' appears 0 times in its scope".into(),
        ]),
        ("unknown", edited(|d| binding(d, "claim-load").insert("kind", json(r#""swap""#))), vec![
            "claim-load: unknown kind 'swap'".into(),
            "claim-raise: the kernel anchor entry claim-load was not located".into(),
            "claim-raise: the production anchor entry claim-load was not located".into(),
            format!("{package}/src/grace_kernel.rs transcribes CLAIM_LOAD in its strength and no binding entry binds it"),
        ]),
        ("impl", edited(|d| strength(d).insert("impl", json(r#""impl ModelStrength for Nothing""#))), {
            let mut drift = vec!["src/grace_kernel.rs declares impl ModelStrength for Nothing 0 times".to_owned()];
            drift.extend(undefined(package));
            drift
        }),
        ("strength", edited(|d| { strengths_of(d).clear(); }), undefined(package)),
        ("among", edited(|d| site(binding(d, "claim-load"), "production").insert("among", json("2"))), vec![
            "claim-load: the production bound.load appears 1 times in fn register".into(),
            "claim-raise: the production anchor entry claim-load was not located".into(),
        ]),
        ("scope", edited(|d| site(binding(d, "claim-raise"), "production").insert("scope", json("[]"))), vec![
            "claim-load: the production anchor entry claim-raise sits in another scope".into(),
            "claim-raise: the production anchor entry claim-load sits in another scope".into(),
        ]),
        ("relation", edited(|d| {
            let production = site(binding(d, "claim-load"), "production");
            let before = production.remove("before").expect("the site has anchors");
            production.insert("after", before);
        }), vec![
            "claim-load: the production operation no longer comes after 'claim-raise'".into(),
            "claim-load: the production operation no longer comes after 'Ok(Registration {'".into(),
        ]),
        ("before", edited(|d| { site(binding(d, "claim-raise"), "production").insert("before", json(r#"["claim-load"]"#)); }), vec![
            "claim-raise: the production operation no longer comes before 'claim-load'".into(),
        ]),
        ("load call", edited(|d| site(binding(d, "claim-load"), "production").insert("call", json(r#""bound.store""#))), vec![
            "claim-load: the production bound.store is no load".into(),
            "claim-raise: the production anchor entry claim-load was not located".into(),
        ]),
        ("store call", edited(|d| site(binding(d, "sequence-odd-store"), "production").insert("call", json(r#""word.load""#))), vec![
            "sequence-odd-store: the production word.load is no store".into(),
            "sequence-odd-fence: the production anchor entry sequence-odd-store was not located".into(),
        ]),
        ("cas call", edited(|d| site(binding(d, "anchored-park"), "production").insert("call", json(r#""slot_word.swap""#))), vec![
            "anchored-park: the production slot_word.swap is no cas".into(),
            "anchored-park-load: the production anchor entry anchored-park was not located".into(),
        ]),
        ("fence call", edited(|d| site(binding(d, "sequence-odd-fence"), "production").insert("call", json(r#""W::store""#))), vec![
            "sequence-odd-fence: the production W::store is no fence".into(),
            "sequence-odd-store: the production anchor entry sequence-odd-fence was not located".into(),
        ]),
        ("failure ordering", edited(|d| binding(d, "anchored-park").insert("orderings", json(r#"["AcqRel", "Acquire"]"#))), vec![
            "anchored-park: the production orderings are ['AcqRel', 'Relaxed'], bound ['AcqRel', 'Acquire']".into(),
            "anchored-park: the kernel orderings are ['AcqRel', 'Relaxed'], bound ['AcqRel', 'Acquire']".into(),
        ]),
        ("bound text", edited(|d| binding(d, "claim-load").insert("orderings", json(r#""Acquire""#))), vec![
            "claim-load: the production orderings are ['SeqCst'], bound Acquire".into(),
            "claim-load: the kernel orderings are ['SeqCst'], bound Acquire".into(),
        ]),
    ];
    for (kind, declared, drift) in rows {
        assert_eq!(
            transcription_drift(&declared, &root()).expect("the sources read"),
            drift,
            "{kind}"
        );
        match check_transcription(&root(), &declared) {
            Err(Error::Refusal(refusal)) => assert_eq!(
                (refusal.reason(), refusal.completion()),
                (
                    format!("correspondence drift: {}", drift.join("; ")).as_str(),
                    "correspondence drift"
                ),
                "{kind}"
            ),
            other => panic!("{kind}: a refusal, not {other:?}"),
        }
    }
}

/// An empty scope header is the whole file, which the drift line names `the file`.
#[test]
fn an_empty_scope_is_the_file() {
    let declared = edited(|d| {
        site(binding(d, "claim-load"), "production").insert("scope", json(r#"[""]"#));
    });
    let drift = transcription_drift(&declared, &root()).expect("the sources read");
    let scope = "claim-load: the production scope the file in crates/kestrike/src/storage/register.rs appears ";
    assert_eq!(drift.len(), 2, "{drift:?}");
    assert!(
        drift[0].starts_with(scope) && drift[0].ends_with(" times"),
        "{drift:?}"
    );
    assert_eq!(
        drift[1],
        "claim-raise: the production anchor entry claim-load was not located"
    );
}

#[test]
fn a_site_whose_matching_count_is_zero_has_no_occurrence_to_read() {
    let declared = edited(|d| {
        let production = site(binding(d, "claim-load"), "production");
        production.insert("matching", json("0"));
        production.insert("operands", json(r#"["x"]"#));
    });
    assert!(matches!(
        transcription_drift(&declared, &root()),
        Err(Error::Index(_))
    ));
}

#[test]
fn cases_are_judged_in_code_point_order_and_litmus_tests_need_an_object() {
    let surrogate = Text::from_code_points([0xd800]).expect("a code point");
    let declared = edited(|d| {
        let Value::Object(object) = d else {
            panic!("the declaration is an object");
        };
        let mut cases = crate::json::Object::new();
        cases.insert(surrogate.clone(), json(r#"{"expect": "positive"}"#));
        cases.insert("a", json(r#"{"expect": "positive"}"#));
        object.insert("cases", Value::Object(cases));
    });
    assert_eq!(refusal(&declared), "a names no litmus list");
    let scratch = crate::paths::tests::Scratch::new("litmus-shape");
    std::fs::create_dir_all(scratch.0.join("verification/rc11")).expect("the directory is made");
    std::fs::write(
        scratch.0.join("verification/rc11/expected.json"),
        r#"{"tests": []}"#,
    )
    .expect("the list writes");
    let unnamed = json(r#"{"cases": {"c": {"expect": "positive", "litmus": []}}}"#);
    assert!(check_correspondence(&scratch.0, &unnamed).is_ok());
    let numbered = json(r#"{"cases": {"c": {"expect": "positive", "litmus": [1]}}}"#);
    assert!(matches!(
        check_correspondence(&scratch.0, &numbered),
        Err(Error::Type(_))
    ));
}
