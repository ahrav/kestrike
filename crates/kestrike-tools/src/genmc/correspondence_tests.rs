use super::check_correspondence;
use crate::genmc::case::tests::{declaration, root};
use crate::genmc::refusal::Error;
use crate::genmc::transcription::{check_transcription, transcription_drift};
use crate::json::{Value, parse};

fn edited(change: impl FnOnce(&mut Value)) -> Value {
    let mut declared = declaration();
    change(&mut declared);
    declared
}

fn case_of<'v>(declared: &'v mut Value, name: &str) -> &'v mut crate::json::Object {
    let Value::Object(declared) = declared else {
        panic!("the declaration is an object");
    };
    let Some(Value::Object(cases)) = declared.get_mut("cases") else {
        panic!("the declaration holds cases");
    };
    let Some(Value::Object(case)) = cases.get_mut(name) else {
        panic!("the case is declared");
    };
    case
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
