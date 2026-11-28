//! The schemas of the package and of each file of the evidence layout, in the layout's order.

use super::constants::{CAUSES, KINDS, OUTCOMES, PACKAGE};
use super::schema::{Each, Scalar, Schema};

const fn s(scalar: Scalar) -> Schema {
    Schema::scalar(scalar)
}

const fn maybe(scalar: Scalar) -> Schema {
    Schema::nullable(scalar)
}

pub(super) const WINDOW: Schema =
    Schema::Object(&[("start", s(Scalar::Time)), ("end", s(Scalar::Time))]);

/// The fields of a shard's version, which a record line holds beside its time.
pub const VERSION_FIELDS: [(&str, Schema); 5] = [
    ("owner", s(Scalar::Host)),
    ("standby", maybe(Scalar::Host)),
    ("generation", s(Scalar::Generation)),
    ("volume", s(Scalar::Name)),
    ("attempts", s(Scalar::Attempts)),
];

/// The schema of one shard's version: its owner, its standby or null, its generation, its volume and its
/// attempts.
pub const VERSION: Schema = Schema::Object(&VERSION_FIELDS);

/// The schema of a stop request: the instance, the time and the identity that asked. The stop mark is one
/// request, and the stopped mark holds one as its `request`.
pub const REQUEST: Schema = Schema::Object(&[
    ("instance", s(Scalar::Name)),
    ("time", s(Scalar::Time)),
    ("identity", s(Scalar::Name)),
]);

/// The package without its optional `note`.
pub(super) const PACKAGE_SCHEMA: Schema = Schema::Object(&[
    ("id", Schema::Member(&[PACKAGE])),
    ("kind", Schema::Member(&[KINDS[0].0, KINDS[1].0])),
    ("revision", s(Scalar::Commit)),
    ("date", s(Scalar::Date)),
    ("clock", s(Scalar::Name)),
    (
        "target",
        Schema::Object(&[("host", s(Scalar::Host)), ("instance", s(Scalar::Name))]),
    ),
    ("hosts", Schema::List(&s(Scalar::Name))),
    ("shards", Schema::List(&s(Scalar::FileName))),
    (
        "witness",
        Schema::List(&Schema::Object(&[
            ("key", s(Scalar::Name)),
            ("shard", s(Scalar::Shard)),
            ("sha256", s(Scalar::Digest)),
        ])),
    ),
    ("baseline", WINDOW),
    ("run", WINDOW),
    ("interval", s(Scalar::Positive)),
    ("reconciler_principal", s(Scalar::Name)),
    (
        "working_budgets",
        Schema::Each(Each {
            keys: "budget",
            value: &s(Scalar::Positive),
            exact: false,
        }),
    ),
    (
        "outside",
        Schema::Each(Each {
            keys: "observation",
            value: &s(Scalar::Name),
            exact: false,
        }),
    ),
    ("clock_error_seconds", s(Scalar::Nonnegative)),
]);

/// Each file of the layout but `package.json` and `records/<shard>.jsonl`, with its schema and whether
/// it is optional.
///
/// A `.json` file's schema applies to the one value [`parsed`](super::parsed) returns. A `.jsonl` file's
/// schema applies to each line of the list it returns, checked under `<rel> line <n>` from 1. The names
/// are those [`check_package`](super::check_package) returns, with two more kinds the caller adds for the
/// files that read them: `observed`, the files the package requires to be observed, which
/// `coverage.json` keys, and `sealed`, which `injection/collected.json` keys: the `observed` files,
/// `coverage.json`, and each `injection/` file of the layout but `injection/collected.json`, an optional
/// mark named whether or not it stands.
pub static LAYOUT: [(&str, Schema, bool); 13] = [
    (
        "injection/roles.json",
        Schema::Object(&[
            ("package_sha256", s(Scalar::Digest)),
            ("time", s(Scalar::Time)),
            (
                "shards",
                Schema::Each(Each {
                    keys: "shard",
                    value: &VERSION,
                    exact: true,
                }),
            ),
            (
                "standbys",
                Schema::Each(Each {
                    keys: "host",
                    value: &Schema::Object(&[
                        ("instance", s(Scalar::Name)),
                        ("instance_state", s(Scalar::Name)),
                        ("host_report", s(Scalar::Name)),
                    ]),
                    exact: false,
                }),
            ),
        ]),
        false,
    ),
    ("injection/stop.json", REQUEST, true),
    (
        "injection/stopped.json",
        Schema::Object(&[
            ("instance", s(Scalar::Name)),
            ("state", s(Scalar::Name)),
            ("time", s(Scalar::Time)),
            ("request", REQUEST),
        ]),
        true,
    ),
    (
        "injection/abort.json",
        Schema::Object(&[
            ("cause", Schema::Member(&CAUSES)),
            ("guardrail", maybe(Scalar::Guardrail)),
            ("time", s(Scalar::Time)),
            ("detail", maybe(Scalar::Name)),
        ]),
        true,
    ),
    (
        "injection/restoration.json",
        Schema::Object(&[
            ("instance", s(Scalar::Name)),
            ("state", s(Scalar::Name)),
            ("time", s(Scalar::Time)),
            ("reviewed_sha256", maybe(Scalar::Digest)),
        ]),
        true,
    ),
    (
        "injection/collected.json",
        Schema::Object(&[
            ("time", s(Scalar::Time)),
            (
                "files",
                Schema::Each(Each {
                    keys: "sealed",
                    value: &s(Scalar::Digest),
                    exact: false,
                }),
            ),
        ]),
        false,
    ),
    (
        "records/receipts.jsonl",
        Schema::Object(&[
            ("time", s(Scalar::Time)),
            ("shard", s(Scalar::Shard)),
            ("principal", s(Scalar::Name)),
        ]),
        false,
    ),
    (
        "activations.jsonl",
        Schema::Object(&[
            ("host", s(Scalar::Host)),
            (
                "activations",
                Schema::List(&Schema::Object(&[
                    ("shard", s(Scalar::Shard)),
                    ("generation", s(Scalar::Generation)),
                    ("attempt", s(Scalar::Epoch)),
                    ("time", s(Scalar::Time)),
                ])),
            ),
        ]),
        false,
    ),
    (
        "witness.jsonl",
        Schema::Object(&[
            ("key", s(Scalar::Key)),
            ("host", s(Scalar::Host)),
            ("time", s(Scalar::Time)),
            ("outcome", Schema::Member(&OUTCOMES)),
            ("sha256", maybe(Scalar::Digest)),
        ]),
        false,
    ),
    (
        "origin.jsonl",
        Schema::Object(&[("time", s(Scalar::Time)), ("key", s(Scalar::Name))]),
        false,
    ),
    (
        "provider.jsonl",
        Schema::OneOf(&[
            &[
                ("event", Schema::Member(&["volume"])),
                ("volume", s(Scalar::Name)),
                ("time", s(Scalar::Time)),
            ],
            &[
                ("event", Schema::Member(&["CreateVolume"])),
                ("principal", s(Scalar::Name)),
                ("time", s(Scalar::Time)),
            ],
        ]),
        false,
    ),
    (
        "blockers.jsonl",
        Schema::Object(&[
            ("shard", s(Scalar::Shard)),
            ("time", s(Scalar::Time)),
            ("name", s(Scalar::Name)),
        ]),
        false,
    ),
    (
        "coverage.json",
        Schema::Each(Each {
            keys: "observed",
            value: &Schema::Object(&[
                ("from", s(Scalar::Time)),
                ("to", s(Scalar::Time)),
                ("lines", s(Scalar::Count)),
            ]),
            exact: true,
        }),
        false,
    ),
];

/// The schema of the layout's file `rel` and whether the file is optional, read as [`LAYOUT`] states.
pub fn layout(rel: &str) -> Option<(&'static Schema, bool)> {
    LAYOUT
        .iter()
        .find(|(name, _, _)| *name == rel)
        .map(|(_, schema, optional)| (schema, *optional))
}

#[cfg(test)]
#[path = "layout_tests.rs"]
mod tests;
