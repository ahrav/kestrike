//! The swarm family: cluster shapes a run's root selects.
//!
//! `cluster-swarm` names [`MEMBERS`] shapes drawn inside the ranges of
//! [`ENVELOPE`]. A run's root selects one member, so the root fixes the
//! owner and key counts, the object sizes, the hot key's weight, the GET
//! concurrency, the phase count and length, the link and device fault
//! rates, whether a fault phase sustains its faults until its operations'
//! outcomes were collected, which of invalidation, cancellation and
//! delayed transmit returns run, whether the sessions are versioned, the
//! idle gap, the window length and whether window cuts compact, and then
//! drives the run's choices inside that shape.
//!
//! Each member draws every fault rate as zero with probability one in
//! eight. Each other member draws its loss, duplication, reordering and
//! delay inside their ranges, and draws each of the stale replay,
//! truncation, would-block and failing call rates of its links and the
//! write and read error rates of its devices as zero with probability one
//! half, so a member runs a subset of those six faults. After every other
//! field it draws the torn-write and partial-read rates of its devices the
//! same way, so no earlier field depends on them.
//!
//! Every member keeps the cluster world's checks and probes. Its minima
//! require each of its phases to heal, which every owner's probe decides.
//!
//! Each of [`CONTROLS`] names the same members with one wrong behavior
//! planted and no minima: its root selects the member `cluster-swarm`
//! maps that root to, so the checks meet the plant in the shapes the
//! family explores. A member whose shape gives the plant no effect, such
//! as a wrong owner among one owner, ends as a control whose plant took no
//! effect.
//!
//! The members come from one fixed generator, so one build maps a root to
//! one member in every process. Every member declares the envelope's upload
//! bound, so one manifest's held counts admit every root.

use std::sync::OnceLock;

use super::{
    DAY_US, DeviceFaults, FRAGMENT_LEN, Faults, MAX_KEYS, MAX_OWNERS, Minima, NO_MINIMA, Plant,
    Shape,
};

pub(super) const NAME: &str = "cluster-swarm";

/// The shapes a root selects among.
pub(super) const MEMBERS: u64 = 4096;

/// The most fault phases a member runs, and the most generated operations
/// one of its fault phases issues.
const PHASES: u32 = 32;
const PHASE_OPS: u32 = 96;

/// The greatest loss, duplication and reordering percentage, and the most
/// turns a datagram waits.
const RATE: u64 = 30;
const DELAY: u64 = 4;

/// The greatest stale replay, truncation, would-block and failing call
/// percentage.
const CALL_RATE: u64 = 10;

/// The greatest percentage of a device's write commands, and of its read
/// commands, that each device fault kind fails.
const DEVICE_RATE: u64 = 10;

/// The object-size sets a member chooses among: one half-fragment size, the
/// lengths around one fragment, the two largest sizes, and all of them.
const SIZES: [&[u32]; 4] = [
    &[FRAGMENT_LEN / 2],
    &[FRAGMENT_LEN - 1, FRAGMENT_LEN, FRAGMENT_LEN + 1],
    &[2 * FRAGMENT_LEN, 3 * FRAGMENT_LEN - 100],
    ALL_SIZES,
];

const ALL_SIZES: &[u32] = &[
    FRAGMENT_LEN / 2,
    FRAGMENT_LEN - 1,
    FRAGMENT_LEN,
    FRAGMENT_LEN + 1,
    2 * FRAGMENT_LEN,
    3 * FRAGMENT_LEN - 100,
];

/// The idle rests a member chooses among: none, a millisecond, a second, a
/// minute and a day.
const GAPS: [u64; 6] = [0, 0, 1_000, 1_000_000, 60_000_000, DAY_US];

/// The ranges every member stays inside, as the capability listing prints
/// them. Its upload bound is the one every member declares.
pub(super) const ENVELOPE: Shape = Shape {
    name: NAME,
    owners: (1, MAX_OWNERS),
    keys: (1, MAX_KEYS),
    sizes: ALL_SIZES,
    hot: 4,
    concurrency: 2,
    phases: PHASES,
    phase_ops: PHASE_OPS,
    faults: Faults {
        loss: RATE,
        duplicate: RATE,
        reorder: RATE,
        delay: DELAY,
        stale: CALL_RATE,
        truncate: CALL_RATE,
        would_block: CALL_RATE,
        error: CALL_RATE,
        burst: 0,
        resend_loss: 0,
    },
    device: DeviceFaults {
        write_error: DEVICE_RATE,
        read_error: DEVICE_RATE,
        write_torn: DEVICE_RATE,
        read_partial: DEVICE_RATE,
    },
    sustained: true,
    delayed_returns: true,
    invalidate: true,
    versioned: true,
    cancel: true,
    plant: Plant::None,
    plant_after: 0,
    minima: NO_MINIMA,
    gap_us: DAY_US,
    window: PHASES,
    first_version: 0,
    compact: true,
    uploads: None,
};

/// Each swarm control's name, plant and the windows that close before the
/// plant takes effect. A plant that acts on a GET crossing a window cut,
/// on the next decided upload or on a bound record takes effect once one
/// window closed.
pub(super) const CONTROLS: [(&str, Plant, u32); 7] = [
    ("cluster-swarm-wrong-owner", Plant::WrongOwner, 0),
    ("cluster-swarm-stale-read", Plant::StaleRead, 0),
    ("cluster-swarm-late-stale", Plant::LateStale, 1),
    ("cluster-swarm-leak", Plant::Leak, 1),
    ("cluster-swarm-corrupt", Plant::Corrupt, 1),
    ("cluster-swarm-misread", Plant::Misread, 0),
    ("cluster-swarm-unremoved", Plant::Unremoved, 0),
];

/// The envelope of control `index` of [`CONTROLS`], as the capability
/// listing prints it.
pub(super) const fn control(index: usize) -> Shape {
    let (name, plant, plant_after) = CONTROLS[index];
    Shape {
        name,
        plant,
        plant_after,
        ..ENVELOPE
    }
}

/// One step of the SplitMix64 generator over `state`.
fn mix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Member `index` of the family.
pub(super) fn drawn(index: u64) -> Shape {
    let mut state = index;
    let mut below = |bound: u64| mix(&mut state) % bound;
    let owners = 1 + below(u64::from(MAX_OWNERS)) as u8;
    let keys = (1 + below(u64::from(MAX_KEYS)) as u8).max(owners);
    let phases = 1 + below(u64::from(PHASES)) as u32;
    let quiet = below(8) == 0;
    let mut rate = |most: u64| if quiet { 0 } else { below(most + 1) };
    let (loss, duplicate, reorder, delay) = (rate(RATE), rate(RATE), rate(RATE), rate(DELAY));
    // A rate that is zero in a quiet member and in half of the others.
    let mut some = |most: u64| match (quiet, below(2)) {
        (false, 1) => 1 + below(most),
        _ => 0,
    };
    let faults = Faults {
        loss,
        duplicate,
        reorder,
        delay,
        stale: some(CALL_RATE),
        truncate: some(CALL_RATE),
        would_block: some(CALL_RATE),
        error: some(CALL_RATE),
        burst: 0,
        resend_loss: 0,
    };
    let (write_error, read_error) = (some(DEVICE_RATE), some(DEVICE_RATE));
    let mut shape = Shape {
        name: NAME,
        owners: (owners, owners),
        keys: (keys, keys),
        sizes: SIZES[below(SIZES.len() as u64) as usize],
        hot: 1 + below(4) as u8,
        concurrency: 1 + below(2) as u8,
        phases,
        phase_ops: 1 + below(u64::from(PHASE_OPS)) as u32,
        faults,
        device: DeviceFaults {
            write_error,
            read_error,
            write_torn: 0,
            read_partial: 0,
        },
        sustained: below(2) == 1,
        delayed_returns: below(2) == 1,
        invalidate: below(2) == 1,
        versioned: below(2) == 1,
        cancel: below(2) == 1,
        plant: Plant::None,
        plant_after: 0,
        minima: Minima {
            healthy: u64::from(phases),
            ..NO_MINIMA
        },
        gap_us: GAPS[below(GAPS.len() as u64) as usize],
        window: 1 + below(u64::from(phases)) as u32,
        first_version: 0,
        compact: below(2) == 1,
        uploads: Some(ENVELOPE.upload_attempts()),
    };
    // The torn-write and partial-read rates draw after every other field,
    // so their draws leave the value of each field drawn before them as it
    // is.
    let mut later = |most: u64| match (quiet, below(2)) {
        (false, 1) => 1 + below(most),
        _ => 0,
    };
    shape.device.write_torn = later(DEVICE_RATE);
    shape.device.read_partial = later(DEVICE_RATE);
    shape
}

/// The index of the member `root` selects.
fn selected(root: u64) -> usize {
    let mut state = root;
    (mix(&mut state) % MEMBERS) as usize
}

/// The member `root` selects.
pub(super) fn member(root: u64) -> &'static Shape {
    static TABLE: OnceLock<Vec<Shape>> = OnceLock::new();
    let table = TABLE.get_or_init(|| (0..MEMBERS).map(drawn).collect());
    &table[selected(root)]
}

/// The member `root` selects with the plant of the control `name` and no
/// minima; `None` when `name` is no swarm control.
pub(super) fn planted(name: &str, root: u64) -> Option<&'static Shape> {
    static TABLE: OnceLock<Vec<Shape>> = OnceLock::new();
    let control = CONTROLS
        .iter()
        .position(|(control, _, _)| *control == name)?;
    let table = TABLE.get_or_init(|| {
        CONTROLS
            .iter()
            .flat_map(|&(name, plant, plant_after)| {
                (0..MEMBERS).map(move |index| Shape {
                    name,
                    plant,
                    plant_after,
                    minima: NO_MINIMA,
                    ..drawn(index)
                })
            })
            .collect()
    });
    Some(&table[control * MEMBERS as usize + selected(root)])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every member stays inside the envelope the capability listing
    /// prints and declares the envelope's upload bound, so one manifest's
    /// held counts admit the member any root selects. Every member and every
    /// cluster profile keeps burst and resend loss at zero.
    #[test]
    fn every_member_stays_inside_the_envelope() {
        let within = |(low, high): (u8, u8), (least, most): (u8, u8)| least <= low && high <= most;
        for index in 0..MEMBERS {
            let member = drawn(index);
            assert!(within(member.owners, ENVELOPE.owners), "member {index}");
            assert!(within(member.keys, ENVELOPE.keys), "member {index}");
            assert!(member.keys.0 >= member.owners.0, "member {index}");
            assert!((1..=ENVELOPE.phases).contains(&member.phases));
            assert!((1..=ENVELOPE.phase_ops).contains(&member.phase_ops));
            assert!((1..=member.phases).contains(&member.window));
            assert!(
                member
                    .sizes
                    .iter()
                    .all(|size| ENVELOPE.sizes.contains(size))
            );
            let faults = member.faults;
            assert!(faults.loss.max(faults.duplicate).max(faults.reorder) <= RATE);
            assert!(faults.delay <= DELAY);
            let calls = [
                faults.stale,
                faults.truncate,
                faults.would_block,
                faults.error,
            ];
            assert!(
                calls.iter().all(|&rate| rate <= CALL_RATE),
                "member {index}"
            );
            assert_eq!(
                (faults.burst, faults.resend_loss),
                (0, 0),
                "member {index}: no cluster shape draws burst or resend loss"
            );
            let device = member.device;
            let most = [
                device.write_error,
                device.read_error,
                device.write_torn,
                device.read_partial,
            ];
            assert!(
                most.iter().all(|&rate| rate <= DEVICE_RATE),
                "member {index}"
            );
            assert_eq!(member.minima.healthy, u64::from(member.phases));
            assert_eq!(member.upload_attempts(), ENVELOPE.upload_attempts());
            let own = u64::from(member.phases)
                * (u64::from(member.phase_ops) + u64::from(member.owners.1) * 3);
            assert!(own <= member.upload_attempts(), "member {index}");
        }
        for shape in &super::super::PROFILES {
            let faults = shape.faults;
            assert_eq!((faults.burst, faults.resend_loss), (0, 0), "{}", shape.name);
        }
    }

    /// A control's root selects the member `cluster-swarm` maps it to,
    /// with the control's name, plant and arming window and no minima,
    /// and a name that is no swarm control selects nothing.
    #[test]
    fn a_control_plants_in_the_member_its_root_selects() {
        assert!(planted(NAME, 1).is_none());
        for root in [1, 2, u64::MAX] {
            let live = member(root);
            for (name, plant, plant_after) in CONTROLS {
                let control = planted(name, root).unwrap();
                assert_eq!((control.name, control.plant), (name, plant));
                assert_eq!(control.plant_after, plant_after);
                assert_eq!(control.minima, NO_MINIMA);
                assert!(control.control());
                let unplanted = Shape {
                    name: NAME,
                    plant: Plant::None,
                    plant_after: 0,
                    minima: live.minima,
                    ..*control
                };
                assert_eq!(format!("{unplanted:?}"), format!("{live:?}"));
            }
        }
    }

    /// Between a tenth and a sixth of the members draw every fault rate
    /// as zero. Each of the stale replay, truncation, would-block, failing
    /// call, write error, read error, torn write and partial read rates is
    /// positive in between a third and a half of the members, and between
    /// a third and two thirds of the members sustain their fault phases.
    #[test]
    fn members_run_subsets_of_the_faults() {
        let members: Vec<Shape> = (0..MEMBERS).map(drawn).collect();
        let rates = |member: &Shape| {
            let (links, device) = (member.faults, member.device);
            [
                links.stale,
                links.truncate,
                links.would_block,
                links.error,
                device.write_error,
                device.read_error,
                device.write_torn,
                device.read_partial,
            ]
        };
        let quiet = |member: &&Shape| {
            let links = member.faults;
            rates(member) == [0; 8]
                && [links.loss, links.duplicate, links.reorder, links.delay] == [0; 4]
        };
        let silent = members.iter().filter(quiet).count() as u64;
        assert!((MEMBERS / 10..MEMBERS / 6).contains(&silent), "{silent}");
        for fault in 0..rates(&members[0]).len() {
            let on = members
                .iter()
                .filter(|member| rates(member)[fault] > 0)
                .count() as u64;
            assert!(
                (MEMBERS / 3..MEMBERS / 2).contains(&on),
                "fault {fault}: {on}"
            );
        }
        let sustained = members.iter().filter(|member| member.sustained).count() as u64;
        assert!((MEMBERS / 3..2 * MEMBERS / 3).contains(&sustained));
    }

    /// Every field of `shape` but the two drawn rates that follow the
    /// generator's earlier draws, `write_torn` and `read_partial`.
    fn earlier_fields(shape: &Shape) -> String {
        let Shape {
            name,
            owners,
            keys,
            sizes,
            hot,
            concurrency,
            phases,
            phase_ops,
            faults,
            device:
                DeviceFaults {
                    write_error,
                    read_error,
                    ..
                },
            sustained,
            delayed_returns,
            invalidate,
            versioned,
            cancel,
            plant,
            plant_after,
            minima,
            gap_us,
            window,
            first_version,
            compact,
            uploads,
        } = *shape;
        format!(
            "{name} {owners:?} {keys:?} {sizes:?} {hot} {concurrency} {phases} {phase_ops} {faults:?} {write_error} {read_error} {sustained} {delayed_returns} {invalidate} {versioned} {cancel} {plant:?} {plant_after} {minima:?} {gap_us} {window} {first_version} {compact} {uploads:?}"
        )
    }

    /// Members 0, 4, 5 and 6 hold these values for every field drawn
    /// before the torn-write and partial-read rates. Member 6 is quiet;
    /// members 4 and 5 draw both earlier device rates positive.
    #[test]
    fn members_keep_the_fields_drawn_before_the_torn_and_partial_rates() {
        const EARLIER: [(u64, &str); 4] = [
            (
                0,
                "cluster-swarm (4, 4) (5, 5) [4096] 4 2 16 43 Faults { loss: 4, duplicate: 24, reorder: 15, delay: 0, stale: 1, truncate: 7, would_block: 2, error: 8, burst: 0, resend_loss: 0 } 3 0 false true true false false None 0 Minima { published: 0, hits: 0, cross: 0, faults: 0, healthy: 16, reused: 0 } 60000000 3 0 true Some(3456)",
            ),
            (
                4,
                "cluster-swarm (3, 3) (3, 3) [16384, 24476] 3 1 32 82 Faults { loss: 7, duplicate: 28, reorder: 25, delay: 1, stale: 10, truncate: 0, would_block: 5, error: 0, burst: 0, resend_loss: 0 } 6 7 false true false true true None 0 Minima { published: 0, hits: 0, cross: 0, faults: 0, healthy: 32, reused: 0 } 1000000 27 0 true Some(3456)",
            ),
            (
                5,
                "cluster-swarm (3, 3) (3, 3) [4096, 8191, 8192, 8193, 16384, 24476] 1 2 8 12 Faults { loss: 22, duplicate: 29, reorder: 19, delay: 0, stale: 0, truncate: 2, would_block: 0, error: 8, burst: 0, resend_loss: 0 } 7 2 false true true true false None 0 Minima { published: 0, hits: 0, cross: 0, faults: 0, healthy: 8, reused: 0 } 86400000000 8 0 false Some(3456)",
            ),
            (
                6,
                "cluster-swarm (1, 1) (2, 2) [8191, 8192, 8193] 2 1 7 26 Faults { loss: 0, duplicate: 0, reorder: 0, delay: 0, stale: 0, truncate: 0, would_block: 0, error: 0, burst: 0, resend_loss: 0 } 0 0 true false true false false None 0 Minima { published: 0, hits: 0, cross: 0, faults: 0, healthy: 7, reused: 0 } 60000000 5 0 false Some(3456)",
            ),
        ];
        for (index, earlier) in EARLIER {
            assert_eq!(earlier_fields(&drawn(index)), earlier, "member {index}");
        }
        let quiet = drawn(6).device;
        assert_eq!((quiet.write_torn, quiet.read_partial), (0, 0));
    }

    /// One root selects one member on every call.
    #[test]
    fn a_root_selects_one_member() {
        for root in [1, 2, u64::MAX] {
            assert!(std::ptr::eq(member(root), member(root)));
        }
        assert!((0..64).any(|root| !std::ptr::eq(member(root), member(0))));
    }
}
