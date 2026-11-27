//! The checks of a run's first step that read the catalog and the package: GD-2's entry with the texts
//! this controller was written from, and the package against its approval, its windows and the
//! declared set at the run's start.

use super::checked::{get, number_at, object_at, text, text_at};
use super::constants::{ACTION, RESTORATION, SKEW_SECONDS};
use super::forms::{instance_id, iso_time};
use super::number::Number;
use super::operator::Operator;
use super::words::sentence;
use crate::gameday::{
    FleetBounds, Names, Refusal, check_package, encodable, gd2_entry, need, parsed,
};
use crate::json::{Object, Value};
use crate::python::{hexdigest, repr};
use crate::text::Text;

/// GD-2's entry of a catalog that [`gd2_of`] admitted: the judge's texts, this controller's injection
/// action and its restoration class with steps that are a plain text.
#[derive(Clone, Copy, Debug)]
pub struct Gd2<'a>(&'a Object);

impl<'a> Gd2<'a> {
    /// The entry as the catalog holds it.
    pub fn entry(&self) -> &'a Object {
        self.0
    }

    /// GD-2's guardrail texts, in the catalog's order.
    pub fn guardrails(&self) -> Vec<&'a Text> {
        super::checked::list(get(self.0, "guardrail"))
            .iter()
            .map(text)
            .collect()
    }

    /// The restoration steps, a text with a UTF-8 form.
    pub fn steps(&self) -> &'a str {
        text_at(object_at(self.0, "restoration"), "steps")
            .to_str()
            .expect("the check made the steps encodable")
    }
}

/// `gd2_of` is GD-2's entry of the decoded catalog while its injection action and its restoration
/// are the ones this controller was written for.
///
/// # Errors
///
/// Each refusal of [`gd2_entry`]; `GD-2's injection action differs from the action this controller was
/// written for`; `GD-2's restoration is not of class persistent-manual with its steps` for another
/// class, or steps that are no text, blank, or hold a lone surrogate.
pub fn gd2_of(catalog: &Value) -> Result<Gd2<'_>, Refusal> {
    let gd2 = gd2_entry(catalog)?;
    let action = matches!(gd2.get("injection"), Some(Value::Object(injection))
        if is(injection.get("action"), ACTION));
    need(action, || {
        sentence!("GD-2's injection action differs from the action this controller was written for")
    })?;
    let restored = matches!(gd2.get("restoration"), Some(Value::Object(restoration))
        if is(restoration.get("class"), RESTORATION)
            && matches!(restoration.get("steps"), Some(Value::String(steps))
                if !steps.strip().is_empty() && encodable(steps)));
    need(restored, || {
        sentence!(
            "GD-2's restoration is not of class ",
            RESTORATION,
            " with its steps"
        )
    })?;
    Ok(Gd2(gd2))
}

fn is(value: Option<&Value>, text: &str) -> bool {
    matches!(value, Some(Value::String(found)) if *found == text)
}

/// The package a run stops for, as [`check_run`] admitted it.
#[derive(Clone, Debug)]
pub struct Run {
    package: Object,
    names: Names,
    package_sha256: String,
    instance: Text,
}

impl Run {
    /// The package object, of kind `staging`.
    pub fn package(&self) -> &Object {
        &self.package
    }

    /// The names the package's other files are read against.
    pub fn names(&self) -> &Names {
        &self.names
    }

    /// The SHA-256 of the package's bytes, which the approval names.
    pub fn package_sha256(&self) -> &str {
        &self.package_sha256
    }

    /// The package's target instance, which the approval names.
    pub fn instance(&self) -> &Text {
        &self.instance
    }
}

/// `check_run` checks the package's bytes `raw` for a run whose wall-clock start is `now`: the package
/// as the judge checks it, with the list bounds `bounds` reads, of kind `staging`, approved by its
/// digest and its target instance together, approved past the run's deadline by [`SKEW_SECONDS`] at
/// least, and with the run from `now` to its deadline after the baseline window and inside the run
/// window, its target in the declared set.
///
/// # Errors
///
/// The first refusal in this order: each of [`parsed`] under `package.json`; `the package is no object`;
/// each of [`check_package`]; a kind other than `staging`; a target instance that is no instance ID;
/// another package digest; another instance; an approval that lapses within [`SKEW_SECONDS`] after the
/// deadline; a start inside the baseline window; a run outside the run window; a target outside the
/// declared set.
pub fn check_run(
    raw: &[u8],
    operator: &Operator,
    now: Number,
    bounds: &FleetBounds,
) -> Result<Run, Refusal> {
    let Value::Object(p) = parsed(raw, &Text::from("package.json"))? else {
        return Err(Refusal::new(sentence!("the package is no object")));
    };
    let names = check_package(&p, bounds)?;
    let kind = text_at(&p, "kind");
    need(*kind == "staging", || {
        sentence!(
            "the package is of kind ",
            kind,
            ": only a staging run stops an instance"
        )
    })?;
    let (package_sha256, approval) = (hexdigest(raw), operator.approval());
    let instance = instance_id(
        get(object_at(&p, "target"), "instance"),
        &Text::from("the package's target instance"),
    )?;
    let end = now.plus(operator.deadline_seconds());
    need(
        *approval.package_sha256() == package_sha256.as_str(),
        || sentence!("the approval names another package digest"),
    )?;
    need(*approval.instance() == instance, || {
        sentence!(
            "the approval names instance ",
            approval.instance(),
            ", not the target ",
            instance
        )
    })?;
    let lapse = iso_time(
        &Value::String(approval.not_after().clone()),
        &Text::from("approval not_after"),
    )?;
    need(
        end.plus(Number::from(SKEW_SECONDS)) <= Number::from(lapse),
        || {
            sentence!(
                "the approval lapses at ",
                approval.not_after(),
                ", less than ",
                SKEW_SECONDS.to_string(),
                " s after the run's deadline"
            )
        },
    )?;
    let (baseline, run) = (object_at(&p, "baseline"), object_at(&p, "run"));
    need(number_at(baseline, "end") <= now, || {
        sentence!(
            "the run's start ",
            now,
            " lies inside the package's baseline window ",
            repr(get(&p, "baseline"))
        )
    })?;
    need(
        number_at(run, "start") <= now && end <= number_at(run, "end"),
        || {
            sentence!(
                "the run from ",
                now,
                " to its deadline ",
                end,
                " lies outside the package's run window ",
                repr(get(&p, "run"))
            )
        },
    )?;
    need(operator.instances().contains(&instance), || {
        sentence!("the target ", instance, " is outside the declared set")
    })?;
    Ok(Run {
        package: p,
        names,
        package_sha256,
        instance,
    })
}
