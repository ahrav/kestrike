//! Each public function returns Quint module text that imports its model with the supplied constants. For a
//! directed trace the text adds the action `recipe`, which restricts each turn to the recipe's action at that
//! turn. The text equals what `inputs` of `quint/escrow_check.py`, `quint/gate_check.py` and
//! `quint/marklog_check.py` returns for a case without mutations or extra text.

use std::fmt::Write;

/// `escrow` emits one branch per distinct action in first-appearance order; each branch matches every turn
/// assigned to that action.
pub fn escrow(bound: usize, volume: &str, recipe: Option<&[&str]>) -> String {
    format!(
        "module escrowCase {{\n  import escrow(BOUND = {bound}, VOLUME = {volume}).* from \"./escrow\"\n{}}}\n",
        grouped(recipe)
    )
}

pub fn gate(bound: usize, recipe: Option<&[&str]>) -> String {
    format!(
        "module gateCase {{\n  import gate(BOUND = {bound}).* from \"./gate\"\n{}}}\n",
        grouped(recipe)
    )
}

pub fn marklog(bound: usize, recipe: Option<&[&str]>) -> String {
    let mut extra = String::new();
    if let Some(recipe) = recipe.filter(|recipe| !recipe.is_empty()) {
        extra.push_str("  action recipe = any {\n");
        for (turn, action) in recipe.iter().enumerate() {
            writeln!(extra, "    all {{ turn == {turn}, {action} }},")
                .expect("a String takes every write");
        }
        extra.push_str("  }\n");
    }
    format!(
        "module marklogCase {{\n  import marklog(BOUND = {bound}).* from \"./marklog\"\n{extra}}}\n"
    )
}

fn grouped(recipe: Option<&[&str]>) -> String {
    let Some(recipe) = recipe.filter(|recipe| !recipe.is_empty()) else {
        return String::new();
    };
    let mut picks: Vec<(&str, Vec<String>)> = Vec::new();
    for (turn, &action) in recipe.iter().enumerate() {
        match picks.iter_mut().find(|(known, _)| *known == action) {
            Some((_, turns)) => turns.push(turn.to_string()),
            None => picks.push((action, vec![turn.to_string()])),
        }
    }
    let mut extra = String::from("  action recipe = any {\n");
    for (action, turns) in picks {
        writeln!(
            extra,
            "    all {{ Set({}).contains(turn), {action} }},",
            turns.join(", ")
        )
        .expect("a String takes every write");
    }
    extra.push_str("  }\n");
    extra
}
