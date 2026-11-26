//! Turns the `CASE` environment variable into the cfgs that select one
//! case. GenMC runs `cargo build` itself and links every bitcode file under
//! the package, so each case is its own build with exactly one `main`.
//!
//! A case is a qualification case by name, `credit-<strength>-<state>` or
//! `grace<readers>-<strength>`, `cutoff-<order>`, `cutoff-<witness>`,
//! `cutoff-refusalkeeps`, `terminal-<fence>`, `terminal-observed` or
//! `join-<seam>`.

const QUALIFICATION: &[&str] = &[
    "sb_sc",
    "sb_prior_rmw",
    "sb_relaxed",
    "intrinsic_boundaries",
    "wrap_falsifier",
];
const CREDIT_STRENGTHS: &[&str] = &["seq", "fenced", "nopark", "noclear"];
const CREDIT_STATES: &[&str] = &["empty", "stale", "pool1", "two"];
const GRACE_STRENGTHS: &[&str] = &[
    "seq",
    "fenced",
    "weakpin",
    "readeralone",
    "claimmisencoded",
    "weakretire",
    "weakcertify",
    "bumprelaxed",
    "startrelaxed",
];
const GRACE_READERS: &[&str] = &["1", "2"];
const CUTOFF_ORDERS: &[&str] = &["pinfirst", "cutofffirst"];
const CUTOFF_WITNESSES: &[&str] = &["admitted", "refused"];
const CUTOFF_REFUSALS: &[&str] = &["keeps"];
const TERMINAL_FENCES: &[&str] = &["own", "none"];
const TERMINAL_WITNESSES: &[&str] = &["observed"];
const JOIN_SEAMS: &[&str] = &[
    "production",
    "relaxedobserve",
    "relaxeddepart",
    "earlydetach",
    "ignoresobservers",
];

fn values(list: &[&str]) -> String {
    list.iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(",")
}

fn main() {
    println!("cargo:rerun-if-env-changed=CASE");
    // The terminal kernel includes `index::sequence`, whose Loom binding is
    // behind `cfg(all(test, loom))`; declaring the name keeps that cfg known
    // to the checker's build.
    println!("cargo:rustc-check-cfg=cfg(loom)");
    let strengths: Vec<&str> = CREDIT_STRENGTHS
        .iter()
        .chain(GRACE_STRENGTHS)
        .copied()
        .collect();
    for (name, list) in [
        ("case", QUALIFICATION),
        (
            "kernel",
            &[
                "qualification",
                "credit",
                "cutoff",
                "grace",
                "terminal",
                "join",
            ][..],
        ),
        ("strength", &strengths[..]),
        ("state", CREDIT_STATES),
        ("readers", GRACE_READERS),
        ("order", CUTOFF_ORDERS),
        (
            "witness",
            &[CUTOFF_WITNESSES, TERMINAL_WITNESSES].concat()[..],
        ),
        ("refusal", CUTOFF_REFUSALS),
        ("fence", TERMINAL_FENCES),
        ("seam", JOIN_SEAMS),
    ] {
        println!(
            "cargo:rustc-check-cfg=cfg({name}, values({}))",
            values(list)
        );
    }
    let case = std::env::var("CASE").expect("CASE names the case to build");
    let parts: Vec<&str> = case.split('-').collect();
    let cfgs = match parts[..] {
        [name] if QUALIFICATION.contains(&name) => {
            vec![("kernel", "qualification"), ("case", name)]
        }
        ["credit", strength, state]
            if CREDIT_STRENGTHS.contains(&strength) && CREDIT_STATES.contains(&state) =>
        {
            vec![
                ("kernel", "credit"),
                ("strength", strength),
                ("state", state),
            ]
        }
        [grace, strength]
            if grace
                .strip_prefix("grace")
                .is_some_and(|readers| GRACE_READERS.contains(&readers))
                && GRACE_STRENGTHS.contains(&strength) =>
        {
            vec![
                ("kernel", "grace"),
                ("strength", strength),
                ("readers", &grace["grace".len()..]),
            ]
        }
        ["cutoff", order] if CUTOFF_ORDERS.contains(&order) => {
            vec![("kernel", "cutoff"), ("order", order)]
        }
        ["cutoff", witness] if CUTOFF_WITNESSES.contains(&witness) => vec![
            ("kernel", "cutoff"),
            ("order", "pinfirst"),
            ("witness", witness),
        ],
        ["cutoff", "refusalkeeps"] => vec![
            ("kernel", "cutoff"),
            ("order", "pinfirst"),
            ("refusal", "keeps"),
        ],
        ["terminal", fence] if TERMINAL_FENCES.contains(&fence) => {
            vec![("kernel", "terminal"), ("fence", fence)]
        }
        ["terminal", witness] if TERMINAL_WITNESSES.contains(&witness) => vec![
            ("kernel", "terminal"),
            ("fence", "own"),
            ("witness", witness),
        ],
        ["join", seam] if JOIN_SEAMS.contains(&seam) => {
            vec![("kernel", "join"), ("seam", seam)]
        }
        _ => panic!("CASE {case} names no case"),
    };
    for (name, value) in cfgs {
        println!("cargo:rustc-cfg={name}=\"{value}\"");
    }
}
