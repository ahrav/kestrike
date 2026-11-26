//! Golden vectors for the identity derivations. Every expected value below
//! is the output of the sorted-key compact JSON encoding and SHA-256
//! derivations over the same frozen inputs, so a change to the canonical
//! form, the seed or the suffix derivation changes a pinned value.

use super::identity::{root, seed};
use super::{Digest, Experiment, Job, ManifestError, Pins, Text, suffix_root};

pub(super) fn text(text: &str) -> Text {
    Text::new(text).expect("the test text is printable ASCII")
}

/// The experiment of the pinned vector: profile `upload` of campaign `c1`,
/// six counts, no cluster entry.
pub(super) fn pinned() -> Experiment {
    Experiment {
        target: None,
        calibration_scope: None,
        attempts: 3,
        campaign: text("c1"),
        capabilities: text("1"),
        class: Some(text("live")),
        counts: [
            ("bytes", 9600),
            ("every", 5),
            ("pending", 3),
            ("records", 80),
            ("ring", 2),
            ("turns", 7),
        ]
        .into_iter()
        .map(|(key, value)| (text(key), value))
        .collect(),
        format: 1,
        generator: None,
        manifest_version: text("2"),
        minima: None,
        pins: Pins {
            build: text(&"b".repeat(64)),
            executable: text(&"e".repeat(64)),
            platform: text("x86_64-linux"),
            toolchain: text("rustc 1.99.0"),
        },
        profile: text("upload"),
        run: 0,
    }
}

/// How many named keys lead every manifest key list.
pub(super) const NAMED: usize = 9;

/// The pinned experiment's manifest keys: the [`NAMED`] keys in schema
/// order, then its counts in byte order.
pub(super) const PINNED_KEYS: [&str; 15] = [
    "version",
    "profile",
    "root",
    "executable",
    "toolchain",
    "build",
    "platform",
    "cpu",
    "scenario",
    "bytes",
    "every",
    "pending",
    "records",
    "ring",
    "turns",
];

const PINNED: &str = concat!(
    r#"{"attempts":3,"campaign":"c1","capabilities":"1","class":"live","#,
    r#""counts":{"bytes":9600,"every":5,"pending":3,"records":80,"ring":2,"turns":7},"#,
    r#""format":1,"generator":null,"manifest_version":"2","minima":null,"#,
    r#""pins":{"build":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
    r#""executable":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","#,
    r#""platform":"x86_64-linux","toolchain":"rustc 1.99.0"},"profile":"upload","run":0}"#,
);

fn digest(hex: &str) -> Digest {
    Digest::parse(hex).expect("the test digest is 64 lowercase hex digits")
}

/// The pinned job id derives the pinned seed, and the experiment's
/// canonical bytes are exactly the sorted-key compact form with `null`
/// for its absent cluster fields.
#[test]
fn the_pinned_vector_reproduces() {
    let experiment = pinned();
    assert_eq!(
        serde_json::to_string(&experiment).expect("the experiment encodes"),
        PINNED
    );
    let id = experiment.id();
    assert_eq!(
        id.digest(),
        digest("dede8442617896e012b3588170f0d42d2f5811b975f42335d570713f2a93aeaf")
    );
    assert_eq!(seed(&id), 15296928082430272672);
}

/// The two printable bytes JSON escapes, `"` and `\`, encode as `\"` and
/// `\\` and keep their golden identity.
#[test]
fn escaped_text_keeps_its_identity() {
    let mut experiment = pinned();
    experiment.campaign = text(r#"a "q" \ p/~"#);
    let encoded = serde_json::to_string(&experiment).expect("the experiment encodes");
    assert!(
        encoded.contains(r#""campaign":"a \"q\" \\ p/~""#),
        "{encoded}"
    );
    let id = experiment.id();
    assert_eq!(
        id.digest(),
        digest("81a72611697395ff4dc6129447a397983eb4dca4f3b188d9270508a8e130860f")
    );
    assert_eq!(seed(&id), 678775026103470092);
}

/// A zero draw becomes root 1, and every other draw is its own root, so a
/// root seed is never 0.
#[test]
fn a_zero_seed_draw_maps_to_one() {
    assert_eq!(root(&digest(&"0".repeat(64))), 1);
    let five = format!("05{}", "0".repeat(62));
    assert_eq!(root(&digest(&five)), 5);
    let top = format!("{}{}", "f".repeat(16), "0".repeat(48));
    assert_eq!(root(&digest(&top)), u64::MAX);
}

/// Decoding the experiment from an object whose keys, the counts' keys
/// included, come in another order leaves the identity unchanged.
#[test]
fn insertion_order_leaves_the_identity_unchanged() {
    let permuted = concat!(
        r#"{"run":0,"profile":"upload","pins":{"toolchain":"rustc 1.99.0","#,
        r#""platform":"x86_64-linux","#,
        r#""executable":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","#,
        r#""build":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"#,
        r#""minima":null,"manifest_version":"2","generator":null,"format":1,"#,
        r#""counts":{"turns":7,"ring":2,"records":80,"pending":3,"every":5,"bytes":9600},"#,
        r#""class":"live","capabilities":"1","campaign":"c1","attempts":3}"#,
    );
    let decoded: Experiment = serde_json::from_str(permuted).expect("the experiment decodes");
    assert_eq!(decoded.id(), pinned().id());
}

/// Integers above 2^53, up to `u64::MAX`, encode exactly and keep their
/// golden identity.
#[test]
fn integers_above_two_to_the_53_keep_their_identity() {
    let mut experiment = cluster_broad();
    experiment.run = u64::MAX;
    experiment.counts.insert(text("records"), (1 << 53) + 1);
    let encoded = serde_json::to_string(&experiment).expect("the experiment encodes");
    assert!(
        encoded.contains(r#""records":9007199254740993,"#),
        "{encoded}"
    );
    assert!(
        encoded.ends_with(r#""run":18446744073709551615}"#),
        "{encoded}"
    );
    let id = experiment.id();
    assert_eq!(
        id.digest(),
        digest("9a07cee97cbc9e95c84785634175e6fdb3aee9e6a31c4c3a0da4e4739ac64a0e")
    );
    assert_eq!(seed(&id), 12573832755821780090);
}

/// The suffix roots of root 100 are the ones the worker derives for a
/// branch of that bundle, and the extremes of both inputs are pinned.
#[test]
fn suffix_roots_are_pinned() {
    assert_eq!(
        [0, 1, 2].map(|suffix| suffix_root(100, suffix)),
        [
            16568251442118978808,
            11517070665970554291,
            7260244781729437368
        ]
    );
    assert_eq!(suffix_root(u64::MAX, u32::MAX), 4337201392000254740);
    assert_eq!(suffix_root(1, 7), 10716238063166293816);
}

/// The worker's manifest keys in schema order.
const KEYS: [&str; 37] = [
    "version",
    "profile",
    "root",
    "executable",
    "toolchain",
    "build",
    "platform",
    "cpu",
    "scenario",
    "turns",
    "same_time",
    "no_progress",
    "actors",
    "disk_depth",
    "scripted",
    "link_copy_bytes",
    "tx_slots",
    "rules",
    "taps",
    "captures",
    "audit_records",
    "registry",
    "upload_attempts",
    "source_bytes",
    "slots",
    "restarts",
    "bundles",
    "suffix_depth",
    "suffix_children",
    "suffix_faults",
    "suffix_advances",
    "pending",
    "ring",
    "records",
    "bytes",
    "every",
    "watchdog",
];

/// Profile `upload` at every default count, as admission freezes it.
fn upload() -> Experiment {
    let counts = [
        ("turns", 20000),
        ("same_time", 400),
        ("no_progress", 5000),
        ("actors", 16),
        ("disk_depth", 8),
        ("scripted", 32),
        ("link_copy_bytes", 1048576),
        ("tx_slots", 1024),
        ("rules", 32),
        ("taps", 8),
        ("captures", 4096),
        ("audit_records", 65536),
        ("registry", 4096),
        ("upload_attempts", 2),
        ("source_bytes", 65536),
        ("slots", 1),
        ("restarts", 1),
        ("bundles", 1),
        ("suffix_depth", 2),
        ("suffix_children", 3),
        ("suffix_faults", 12),
        ("suffix_advances", 16),
        ("pending", 64),
        ("ring", 64),
        ("records", 1000000),
        ("bytes", 48000000),
        ("every", 256),
        ("watchdog", 600),
    ];
    Experiment {
        target: None,
        calibration_scope: None,
        counts: counts
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
        ..pinned()
    }
}

/// Profile `cluster-broad`: `upload` with 26 actors and its cluster
/// generator and minima.
pub(super) fn cluster_broad() -> Experiment {
    let mut experiment = upload();
    experiment.profile = text("cluster-broad");
    experiment.counts.insert(text("actors"), 26);
    experiment.generator = Some(text("1"));
    experiment.minima = Some(text("published:6,hits:6"));
    experiment
}

const UPLOAD_MANIFEST: &str = "version = 2\nprofile = upload\nroot = 14398109801961875368\n\
executable = eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n\
toolchain = rustc 1.99.0\n\
build = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
platform = x86_64-linux\ncpu = unrecorded\nscenario = base\nturns = 20000\nsame_time = 400\n\
no_progress = 5000\nactors = 16\ndisk_depth = 8\nscripted = 32\nlink_copy_bytes = 1048576\n\
tx_slots = 1024\nrules = 32\ntaps = 8\ncaptures = 4096\naudit_records = 65536\nregistry = 4096\n\
upload_attempts = 2\nsource_bytes = 65536\nslots = 1\nrestarts = 1\nbundles = 1\n\
suffix_depth = 2\nsuffix_children = 3\nsuffix_faults = 12\nsuffix_advances = 16\npending = 64\n\
ring = 64\nrecords = 1000000\nbytes = 48000000\nevery = 256\nwatchdog = 600\n";

/// Profile `upload`'s job derives the golden identity, seed and manifest
/// bytes, every schema key in order with its frozen value, and the
/// manifest digest is the SHA-256 of those bytes.
#[test]
fn one_profiles_manifest_bytes_match_the_golden_fixture() {
    let (job, manifest) = Job::derive(upload(), &KEYS).expect("the keys fit the experiment");
    assert_eq!(manifest, UPLOAD_MANIFEST);
    assert_eq!(
        job.id().digest(),
        digest("e60b39e072f349b4b7fc10f358dfca9b32a1f0dc2473ad95f47058e2e4f11cd3")
    );
    assert_eq!(job.seed(), 14398109801961875368);
    assert_eq!(
        job.manifest_sha256(),
        digest("980b4f278589289de443063148a36c567ba15d02983bc433b490be739851799e")
    );
    assert_eq!(job.experiment(), &upload());
    assert_eq!(job.manifest(&KEYS).as_deref(), Ok(UPLOAD_MANIFEST));
    let (cluster, _) = Job::derive(cluster_broad(), &KEYS).expect("the keys fit the experiment");
    assert_eq!(
        (cluster.id().digest(), cluster.seed()),
        (
            digest("8cba1044df322bd718cd6a757f6a6a33728ed2c3415807921bc13e7c7e7cc096"),
            11156545743760105655
        )
    );
    assert_eq!(
        cluster.manifest_sha256(),
        digest("25e0a6c7764a38830ab913f1e157dffe31c97b81fb8994aa1c56866188a8421c")
    );
}

/// A key list that misses a value key, names a key with no value, repeats
/// a key, or orders the keys into other bytes than the job's digest
/// derives no manifest, each with its own error, through both
/// [`Job::derive`] and [`Job::manifest`]; a named key overrides a count of
/// the same name.
#[test]
fn a_manifest_needs_each_value_key_exactly_once() {
    let (job, _) = Job::derive(upload(), &KEYS).expect("the keys fit the experiment");
    let unfilled = |key: &str| Err(ManifestError::Unfilled(key.to_owned()));
    let extra = [&KEYS[..], &["extra"]].concat();
    let repeated = [&KEYS[..], &["turns"]].concat();
    for (keys, refused) in [
        (
            &KEYS[..36],
            Err(ManifestError::Unlisted(vec![KEYS[36].to_owned()])),
        ),
        (&extra[..], unfilled("extra")),
        (&repeated[..], unfilled("turns")),
        (
            &KEYS[1..],
            Err(ManifestError::Unlisted(vec!["version".to_owned()])),
        ),
    ] {
        assert_eq!(job.manifest(keys), refused);
        assert_eq!(Job::derive(upload(), keys).map(drop), refused.map(drop));
    }
    let mut swapped = KEYS;
    swapped.swap(NAMED, NAMED + 1);
    assert_eq!(job.manifest(&swapped), Err(ManifestError::Digest));
    assert!(Job::derive(upload(), &swapped).is_ok());
    let mut shadowed = upload();
    shadowed.counts.insert(text("profile"), 9);
    let (_, manifest) = Job::derive(shadowed, &KEYS).expect("the keys fit the experiment");
    assert!(manifest.contains("profile = upload\n"), "{manifest}");
    assert!(!manifest.contains("profile = 9"), "{manifest}");
}

/// Text admits exactly the bytes 0x20 to 0x7e.
#[test]
fn text_admits_only_printable_ascii() {
    for refused in ["é", "a\nb", "\t", "\u{1f}", "\u{7f}", "\0"] {
        assert_eq!(Text::new(refused), None, "{refused:?}");
    }
    for admitted in ["", " ", "~", "a \"quoted\" \\ path/"] {
        assert_eq!(
            Text::new(admitted).as_ref().map(Text::as_str),
            Some(admitted)
        );
    }
}

/// Decoding refuses the text and digests that construction refuses, so
/// a typed decode outside the codec's scan admits no other bytes.
#[test]
fn text_and_digests_are_refused_at_decode_as_at_construction() {
    for refused in [
        r#""\u00e9""#,
        r#""a\nb""#,
        r#""\u001f""#,
        r#""\u007f""#,
        r#""\u0000""#,
    ] {
        assert!(serde_json::from_str::<Text>(refused).is_err(), "{refused}");
    }
    let admitted: Text = serde_json::from_str(r#""a b""#).expect("printable text decodes");
    assert_eq!(admitted.as_str(), "a b");
    let hex = "ab".repeat(32);
    assert!(Digest::parse(&hex).is_some());
    let decoded: Digest = serde_json::from_str(&format!(r#""{hex}""#)).expect("the digest decodes");
    assert_eq!(decoded.to_string(), hex);
    for refused in [
        hex.to_uppercase(),
        hex[..63].to_owned(),
        format!("{hex}0"),
        format!("{hex}ab"),
        format!("g{}", &hex[1..]),
        String::new(),
    ] {
        assert_eq!(Digest::parse(&refused), None, "{refused:?}");
        assert!(serde_json::from_str::<Digest>(&format!(r#""{refused}""#)).is_err());
    }
}
