//! The workload's action vocabulary: every action kind a campaign may
//! propose, each under its own precondition, and the named profile that
//! declares which kinds a campaign covers. A world proposes and credits
//! only the kinds its profile declares ([`Profile::declares`]).

use super::choice::{Chooser, Site};

/// Declares the vocabulary from one list: the enum takes the kinds as its
/// variants from code 1 and `ALL` lists the same kinds in the same order,
/// so a kind appended to the list joins both.
macro_rules! kinds {
    ($first:ident $(, $kind:ident)* $(,)?) => {
        /// One kind of workload action. Each kind's code is its
        /// discriminant, which bundles record wherever they name a kind.
        /// The vocabulary is append-only: a new kind takes the next code
        /// after the last one, so every recorded code keeps naming its kind.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(u8)]
        pub(crate) enum ActionKind {
            $first = 1,
            $($kind,)*
        }

        impl ActionKind {
            /// Every kind, in code order.
            pub(crate) const ALL: [Self; 1 $(+ { stringify!($kind); 1 })*] =
                [Self::$first $(, Self::$kind)*];
        }
    };
}

kinds!(
    Fill,
    Receive,
    Publish,
    Acquire,
    Get,
    Read,
    Release,
    PutInvoke,
    PutPrepare,
    Supply,
    DeferSupply,
    PutCancel,
    Abandon,
    PutOutcome,
    Retry,
    Invalidate,
    Expire,
    Evict,
    Cancel,
    SessionChange,
    Rekey,
    Pressure,
    Close,
);

impl ActionKind {
    /// The kind whose code is `code`.
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code).checked_sub(1)?).copied()
    }
}

/// A named configuration chosen once per job and recorded before any
/// action: the profile's name, the action kinds it declares, and its seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Profile {
    pub(crate) name: &'static str,
    pub(crate) declared: Vec<ActionKind>,
    pub(crate) root: u64,
}

impl Profile {
    /// Whether the profile declares `kind`.
    pub(crate) fn declares(&self, kind: ActionKind) -> bool {
        self.declared.contains(&kind)
    }

    /// A chooser recording from the profile's root over `sites`.
    pub(crate) fn recorder(&self, sites: &[Site]) -> Chooser {
        Chooser::record(self.root, sites)
    }

    /// The profile's canonical record: the name's bytes, a zero, each
    /// declared kind's code once in code order, a zero, and the root
    /// little-endian.
    pub(crate) fn record(&self) -> Vec<u8> {
        let mut kinds: Vec<u8> = self.declared.iter().map(|&kind| kind as u8).collect();
        kinds.sort_unstable();
        kinds.dedup();
        let mut out = self.name.as_bytes().to_vec();
        out.push(0);
        out.extend(kinds);
        out.push(0);
        out.extend(self.root.to_le_bytes());
        out
    }

    /// The length of the profile record that starts `bytes`, as
    /// [`record`](Self::record) lays it out, or `None` when `bytes` ends
    /// inside it.
    #[cfg(test)]
    pub(crate) fn record_len(bytes: &[u8]) -> Option<usize> {
        Self::declared_codes(bytes)?;
        let name = bytes.iter().position(|&byte| byte == 0)?;
        let kinds = bytes[name + 1..].iter().position(|&byte| byte == 0)?;
        Some(name + 1 + kinds + 1 + 8)
    }

    /// The declared kinds' codes of the profile record that starts `bytes`,
    /// or `None` when `bytes` ends inside it.
    #[cfg(test)]
    pub(crate) fn declared_codes(bytes: &[u8]) -> Option<&[u8]> {
        let name = bytes.iter().position(|&byte| byte == 0)?;
        let kinds = bytes[name + 1..].iter().position(|&byte| byte == 0)?;
        let len = name + 1 + kinds + 1 + 8;
        (len <= bytes.len()).then(|| &bytes[name + 1..name + 1 + kinds])
    }
}

#[cfg(test)]
mod tests {
    use super::ActionKind;

    /// Every kind's name and code as the vocabulary first fixed them.
    /// Appending a kind leaves this table a prefix of the vocabulary;
    /// inserting or reordering one shifts a later code and fails it.
    const GOLDEN: [(&str, u8); 23] = [
        ("Fill", 1),
        ("Receive", 2),
        ("Publish", 3),
        ("Acquire", 4),
        ("Get", 5),
        ("Read", 6),
        ("Release", 7),
        ("PutInvoke", 8),
        ("PutPrepare", 9),
        ("Supply", 10),
        ("DeferSupply", 11),
        ("PutCancel", 12),
        ("Abandon", 13),
        ("PutOutcome", 14),
        ("Retry", 15),
        ("Invalidate", 16),
        ("Expire", 17),
        ("Evict", 18),
        ("Cancel", 19),
        ("SessionChange", 20),
        ("Rekey", 21),
        ("Pressure", 22),
        ("Close", 23),
    ];

    #[test]
    fn the_codes_match_their_golden_table() {
        assert!(ActionKind::ALL.len() >= GOLDEN.len());
        for (&(name, code), kind) in GOLDEN.iter().zip(ActionKind::ALL) {
            assert_eq!((format!("{kind:?}").as_str(), kind as u8), (name, code));
            assert_eq!(ActionKind::from_code(code), Some(kind));
        }
    }

    #[test]
    fn every_kind_round_trips_its_code() {
        for kind in ActionKind::ALL {
            assert_eq!(ActionKind::from_code(kind as u8), Some(kind));
        }
        assert_eq!(ActionKind::from_code(0), None);
        assert_eq!(ActionKind::from_code(ActionKind::ALL.len() as u8 + 1), None);
    }
}
