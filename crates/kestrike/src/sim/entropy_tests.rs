//! Endpoint and index identity from recorded entropy: an owner's boot nonce
//! and the routes of fixed keys in its index, and a client's boot nonce,
//! drawn through the choice contract from one root, equal a pinned identity
//! in every fresh process and replay from their tape.

use std::cell::Cell;

use crate::net::EntropyError;
use crate::net::entropy_tests::{client_nonce, owner_identity};

use super::choice::{ChoiceError, Chooser, Defect, Site};
use super::entropy::{DrawRefusal, key_pair, key_pair_site, nonce, nonce_site};

/// The root every identity case draws from.
pub(crate) const ROOT: u64 = 0x5EED_0000_0000_0002;

const OWNER: u16 = 1;
const CLIENT: u16 = 2;

/// The sites an identity draws at: the owner's nonce and key pair sites,
/// then the client's nonce site.
const SITES: [Site; 3] = [nonce_site(OWNER), key_pair_site(OWNER), nonce_site(CLIENT)];

/// The identity `ROOT` gives. By the choice contract's definition each nonce
/// and the key pair are the SplitMix64 words seeded by SHA-256 over the
/// derivation separator, `ROOT` and the draw's identity; each fingerprint is
/// the SipHash-1-3 word of its key under that pair, and each shard, bucket
/// and tag is the index's cut of that word.
pub(crate) const PINNED: &str = concat!(
    "owner 208174fa76d22614d2bc8b012e31d52b routes 0:0:a7e4:89bc30f90",
    "f7d4fc8,0:1:f614:70a6a84cd815ec29,0:1:e8d1:4ac36312ea15d1a3,0:0:",
    "3421:d3eb895433c86842 client 295d89703b8df9285bec5db496e0565a",
);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The endpoint and index identity `chooser`'s draws give, as one line: the
/// owner's boot nonce, each fixed key's shard, base bucket, tag and
/// fingerprint in the owner's index, then the client's boot nonce. Each
/// actor's first incarnation draws once at each of its sites.
fn identity(chooser: &mut Chooser) -> String {
    let [owner, client] = [OWNER, CLIENT].map(|actor| chooser.launch(actor));
    let hasher = key_pair(chooser, SITES[1], owner).expect("a registered key pair site");
    let refused = Cell::new(None);
    let (owner, routes) = owner_identity(nonce(chooser, SITES[0], owner, &refused), hasher);
    let client = client_nonce(nonce(chooser, SITES[2], client, &refused));
    let routes: Vec<String> = routes
        .iter()
        .map(|route| {
            format!(
                "{}:{}:{:04x}:{:016x}",
                route.shard().0,
                route.bucket(),
                route.tag(),
                route.fingerprint()
            )
        })
        .collect();
    format!(
        "owner {} routes {} client {}",
        hex(&owner),
        routes.join(","),
        hex(&client)
    )
}

/// The identity this process draws from `ROOT`, when it equals the pinned
/// identity and every draw was one recorded decision.
///
/// # Errors
///
/// The drawn identity or decision count, against the pinned ones.
pub(crate) fn pinned_identity() -> Result<String, String> {
    let mut chooser = Chooser::record(ROOT, &SITES);
    let drawn = identity(&mut chooser);
    if chooser.decisions() != SITES.len() as u64 {
        return Err(format!(
            "{} decisions for {} sites",
            chooser.decisions(),
            SITES.len()
        ));
    }
    if drawn != PINNED {
        return Err(format!("identity {drawn}, pinned {PINNED}"));
    }
    Ok(drawn)
}

/// The library harness's process derives the pinned identity, the same one
/// the worker's fresh processes derive.
#[test]
fn equal_roots_give_the_pinned_identity() {
    pinned_identity().unwrap();
}

/// A recorded identity replays from its tape, consuming the whole tape, and
/// another root gives another owner nonce, other routes and another client
/// nonce.
#[test]
fn an_identity_replays_from_its_tape_and_follows_its_root() {
    let mut recorder = Chooser::record(ROOT, &SITES);
    let drawn = identity(&mut recorder);
    let tape = recorder.finish().unwrap();
    let mut replayer = Chooser::replay(&SITES, tape);
    assert_eq!(identity(&mut replayer), drawn);
    replayer.finish().unwrap();
    let other = identity(&mut Chooser::record(ROOT ^ 1, &SITES));
    let (drawn, other): (Vec<&str>, Vec<&str>) =
        (drawn.split(' ').collect(), other.split(' ').collect());
    for (at, field) in [(1, "owner nonce"), (3, "routes"), (5, "client nonce")] {
        assert_eq!(drawn[at - 1], other[at - 1], "the {field} label");
        assert_ne!(drawn[at], other[at], "the {field}");
    }
}

/// An unregistered key pair site is a harness defect at the draw: no
/// decision is made and no hasher reaches a storage.
#[test]
fn an_unregistered_key_pair_site_is_a_harness_defect() {
    let mut chooser = Chooser::record(ROOT, &SITES[..1]);
    let incarnation = chooser.launch(OWNER);
    assert_eq!(
        key_pair(&mut chooser, SITES[1], incarnation).err(),
        Some(DrawRefusal {
            site: SITES[1],
            incarnation,
            error: ChoiceError::HarnessDefect(Defect::Unregistered(SITES[1])),
        })
    );
    assert_eq!(chooser.decisions(), 0);
}

/// A refused nonce draw returns `EntropyError::Refused` naming the draw's
/// site and incarnation, stores the matching `DrawRefusal`, makes no
/// decision and leaves the nonce bytes unchanged. The cases are a feed that
/// ends inside the draw (`Short`) and an unregistered site (the harness
/// defect naming it). A second refused draw keeps the first refusal stored.
#[test]
fn ib_entropy_exhaustion_a_refused_nonce_draw_returns_its_typed_refusal() {
    let short = Chooser::fed(&SITES, vec![0x5A; 15]);
    let unregistered = Chooser::record(ROOT, &SITES[1..2]);
    let cases = [
        (short, ChoiceError::Short),
        (
            unregistered,
            ChoiceError::HarnessDefect(Defect::Unregistered(SITES[2])),
        ),
    ];
    for (mut chooser, error) in cases {
        let incarnation = chooser.launch(CLIENT);
        let refused = Cell::new(None);
        let mut bytes = [0xC3; 16];
        assert_eq!(
            nonce(&mut chooser, SITES[2], incarnation, &refused)(&mut bytes),
            Err(EntropyError::Refused {
                actor: CLIENT,
                site: SITES[2].site,
                incarnation,
            }),
            "{error:?}"
        );
        let first = DrawRefusal {
            site: SITES[2],
            incarnation,
            error,
        };
        assert_eq!(refused.get(), Some(first));
        assert_eq!((bytes, chooser.decisions()), ([0xC3; 16], 0), "{error:?}");
        let owner = chooser.launch(OWNER);
        let again = nonce(&mut chooser, SITES[0], owner, &refused)(&mut bytes);
        assert!(again.is_err(), "{error:?}");
        assert_eq!(refused.get(), Some(first), "{error:?}");
    }
}
