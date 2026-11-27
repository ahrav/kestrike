use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::fixtures::{self, Model, Style, Trace, case};
use crate::json::{Integer, Object, Value};
use crate::python;

pub(crate) const MODEL: Model = Model {
    tool: "marklog_fixtures",
    about: "Watermark-log model traces for the replay against the file log: the directed recipes and seeded runs of `step`.",
    name: "marklog",
    style: Style::Format,
    limit: Duration::from_secs(120),
};

pub const STEPS: usize = 14;
const RECIPE_SEED: u64 = 0x6b00;
pub const SEEDS: [u64; 6] = [0x6b01, 0x6b02, 0x6b03, 0x6b05, 0x6b08, 0x6b0d];

#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 6] = [
    ("partly_landed", &[
        "read(Set(1))", "read(Set(2))", "write(1)", "write(2)", "crash(Set(1, 2), Set(2))", "read(Set(1, 2))",
    ]),
    ("whole_replacement", &["read(Set(3))", "crash(Set(1, 2), Set())", "read(Set(1, 2))"]),
    ("out_of_key_order", &["read(Set(2))", "read(Set(1))", "restart", "write(2)", "read(Set(2))"]),
    ("raise_after_whole", &[
        "read(Set(1, 2))", "write(1)", "read(Set(1))", "write(2)", "read(Set(2, 3))", "restart",
        "read(Set(1, 2, 3))",
    ]),
    ("crashes", &[
        "read(Set(2))", "write(2)", "crash(Set(2), Set())", "crash(Set(2), Set(2))", "write(2)",
        "crash(Set(1, 2), Set(2))", "read(Set(1, 2))", "read(Set(1, 2, 3))",
    ]),
    ("whole_then_in_place", &[
        "crash(Set(1, 2, 3), Set(1, 2, 3))", "read(Set(1, 2, 3))", "write(1)", "write(2)", "write(3)",
        "read(Set(3, 2, 1))", "restart", "read(Set(1))",
    ]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let directed = RECIPES
        .iter()
        .map(|&(name, recipe)| trace(name.to_owned(), RECIPE_SEED, Some(recipe)));
    let seeded = SEEDS
        .iter()
        .map(|&seed| trace(format!("step_{seed:x}"), seed, None));
    let traces: Vec<Trace> = directed.chain(seeded).collect();
    fixtures::write(&MODEL, top, args, &traces, calls)
}

fn trace(name: String, seed: u64, recipe: Option<&'static [&'static str]>) -> Trace {
    Trace::new(name, seed, recipe, STEPS, case::marklog, Vec::new())
}

/// Each state after the first records `call` as the action from `marklogCase::marklog::ev.act` followed by its
/// arguments.
fn calls(data: &mut Object, trace: &Trace) -> Result<(), String> {
    let Some(Value::Array(states)) = data.get_mut("states") else {
        return Err("'states' is a JSON value other than an array".to_owned());
    };
    for (at, state) in states.iter_mut().skip(1).enumerate() {
        let Value::Object(state) = state else {
            return Err(format!(
                "state {}: a JSON value other than an object",
                at + 1
            ));
        };
        let value = call(state, trace.recipe().map(|recipe| recipe[at]))?;
        state.insert("call", value);
    }
    Ok(())
}

fn call(state: &Object, text: Option<&str>) -> Result<Value, String> {
    let act = member(get(state, "marklogCase::marklog::ev")?, "act")?.clone();
    let mut call = vec![act.clone()];
    if let Some(text) = text {
        let sets = sets(text);
        if sets.is_empty() {
            call.extend(numbers(text).into_iter().map(Value::Integer));
        } else {
            call.extend(sets.into_iter().map(|inner| {
                let mut pages = numbers(inner);
                pages.sort();
                Value::Array(pages.into_iter().map(Value::Integer).collect())
            }));
        }
        return Ok(Value::Array(call));
    }
    let picks = get(state, "mbt::nondetPicks")?;
    let names: &[&str] = match &act {
        Value::String(act) if *act == "read" => &["batch"],
        Value::String(act) if *act == "crash" => &["batch", "landed"],
        Value::String(act) if *act == "write" => &["k"],
        Value::String(act) if *act == "restart" => &[],
        _ => {
            return Err(format!(
                "the action {} has no recorded picks",
                crate::json::text(&act)
            ));
        }
    };
    for &name in names {
        let value = member(member(picks, name)?, "value")?;
        call.push(if name == "k" {
            Value::Integer(python::int(member(value, "#bigint")?)?)
        } else {
            pages(value)?
        });
    }
    Ok(Value::Array(call))
}

fn get<'a>(object: &'a Object, key: &str) -> Result<&'a Value, String> {
    object.get(key).ok_or_else(|| format!("no key '{key}'"))
}

fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    match value {
        Value::Object(object) => get(object, key),
        _ => Err(format!(
            "a JSON value other than an object where '{key}' belongs"
        )),
    }
}

fn pages(value: &Value) -> Result<Value, String> {
    let items: &[Value] = match member(value, "#set")? {
        Value::Array(items) => items,
        Value::Object(object) if object.is_empty() => &[],
        Value::String(text) if text.is_empty() => &[],
        _ => return Err("'#set' holds items other than objects".to_owned()),
    };
    let mut pages = items
        .iter()
        .map(|page| python::int(member(page, "#bigint")?))
        .collect::<Result<Vec<_>, _>>()?;
    pages.sort();
    Ok(Value::Array(
        pages.into_iter().map(Value::Integer).collect(),
    ))
}

fn sets(text: &str) -> Vec<&str> {
    let mut sets = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("Set(") {
        let inner = &rest[start + 4..];
        let Some(end) = inner.find(')') else {
            break;
        };
        sets.push(&inner[..end]);
        rest = &inner[end + 1..];
    }
    sets
}

fn numbers(text: &str) -> Vec<Integer> {
    text.split(|character: char| !character.is_ascii_digit())
        .filter(|digits| !digits.is_empty())
        .map(|digits| Integer::from_digits(false, digits).expect("the run is ASCII digits"))
        .collect()
}
