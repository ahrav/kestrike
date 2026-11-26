//! Initialization entropy as recorded choices. Boot nonces draw as byte
//! fills in the entropy domain at the endpoints' nonce draw, and index key
//! pairs draw as one byte fill that the storage installs after
//! construction, so equal roots give equal endpoint and index identity in
//! every process and every draw replays from its tape.

use std::cell::Cell;

use crate::index::KeyHasher;
use crate::net::EntropyError;

use super::choice::{ChoiceError, Chooser, Domain, Site};

/// The site number of a boot nonce draw.
const NONCE: u16 = 1;

/// The site number of an index key pair draw.
const KEY_PAIR: u16 = 2;

/// The site where `actor` draws its boot nonce.
pub(crate) const fn nonce_site(actor: u16) -> Site {
    Site {
        domain: Domain::Entropy,
        actor,
        site: NONCE,
    }
}

/// The site where `actor` draws its index key pair.
pub(crate) const fn key_pair_site(actor: u16) -> Site {
    Site {
        domain: Domain::Entropy,
        actor,
        site: KEY_PAIR,
    }
}

/// An entropy draw the chooser refused, with the chooser's error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DrawRefusal {
    pub(crate) site: Site,
    pub(crate) incarnation: u32,
    pub(crate) error: ChoiceError,
}

/// Fills `out` from `chooser` as one byte-fill decision at `site` in
/// `incarnation`.
///
/// # Errors
///
/// A [`DrawRefusal`] naming `site`, `incarnation` and the chooser's error
/// when the chooser refuses the decision.
pub(crate) fn draw(
    chooser: &mut Chooser,
    site: Site,
    incarnation: u32,
    out: &mut [u8],
) -> Result<(), DrawRefusal> {
    chooser
        .bytes(site, incarnation, out)
        .map_err(|error| DrawRefusal {
            site,
            incarnation,
            error,
        })
}

/// A nonce supplier that fills an endpoint's boot nonce from `chooser` as
/// one byte-fill decision at `site` in `incarnation`.
///
/// A refused decision returns [`EntropyError::Refused`] naming the draw, so
/// the endpoint refuses the start or rekey. The supplier also stores the
/// refusal in `refused` when `refused` is empty, so `refused` holds the
/// first refusal across every supplier sharing it. An all-zero fill passes
/// to the endpoint, which refuses it as [`EntropyError::Zero`].
pub(crate) fn nonce<'a>(
    chooser: &'a mut Chooser,
    site: Site,
    incarnation: u32,
    refused: &'a Cell<Option<DrawRefusal>>,
) -> impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError> + 'a {
    move |bytes| {
        draw(chooser, site, incarnation, bytes).map_err(|refusal| {
            if refused.get().is_none() {
                refused.set(Some(refusal));
            }
            EntropyError::Refused {
                actor: site.actor,
                site: site.site,
                incarnation,
            }
        })
    }
}

/// A hasher keyed by a pair drawn from `chooser` as one 16-byte fill at
/// `site` in `incarnation`: `k0` from the first eight bytes and `k1` from the
/// last eight, each little-endian.
///
/// # Errors
///
/// A [`DrawRefusal`] naming `site`, `incarnation` and the chooser's error
/// when the chooser refuses the decision.
pub(crate) fn key_pair(
    chooser: &mut Chooser,
    site: Site,
    incarnation: u32,
) -> Result<KeyHasher, DrawRefusal> {
    let mut bytes = [0; 16];
    draw(chooser, site, incarnation, &mut bytes)?;
    let (k0, k1) = bytes.split_at(8);
    let word = |half: &[u8]| u64::from_le_bytes(half.try_into().expect("eight bytes"));
    Ok(KeyHasher::with_key_pair(word(k0), word(k1)))
}
