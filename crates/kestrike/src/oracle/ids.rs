//! Test-owned identities for history rows, chosen so that every expected
//! value a checker derives through an identity comes from the test's own
//! tables.
//!
//! A key is the test's name for one complete key, a label is the test's name
//! for one immutable published content of one key, and a resource identity
//! names one extent, slot, buffer, command, credit, budget charge, request
//! share, retained chunk, client source slot or accepted write's quota the
//! fixture tracks. Each is a small integer the fixture assigns.

/// One recorded operation. Rows that describe the same operation, such as a
/// lookup and the delivery its lease feeds, carry the same identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct OpId(pub(crate) u32);

/// The test's name for one complete key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct KeyId(pub(crate) u8);

/// A publication label: the test-owned identity of one immutable expected
/// content, with its metadata and body lengths, for one key.
///
/// Label equality identifies the same published content; ordinals and
/// acknowledgments determine visibility order. The type derives equality
/// and hashing only, so ranking two contents by label does not compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Label(pub(crate) u64);

/// A position on the fixture thread's one ordinal counter.
///
/// Every ordinal of a history comes from that one counter, so each row's
/// ordinals are unique and a response ordinal below an invocation ordinal
/// means the response happened first. An action recorded from a pause hook
/// takes its ordinal inside the paused bracket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Ordinal(pub(crate) u32);

/// The storage session a read or record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(pub(crate) u64);

/// One incarnation of a reusable resource: an extent's lifetime between
/// reuses, a slot's lifetime, a buffer's time off the free stack, a command
/// slot's token, a source slot's fragment tenure, or a write quota's command
/// token.
///
/// A release of such a resource names the incarnation it returns, so a stale
/// or duplicate return is distinguishable from a return of the current
/// successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Incarnation(pub(crate) u64);

/// One owner incarnation: the run of one owner between its start and its
/// stop or death. The continuation keys every resource and checkpoint by it,
/// so a fresh incarnation's resource index names another resource than a
/// dead incarnation's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Owner(pub(crate) u64);

/// An operation's wide identity, which the caller assigns once per
/// operation and never reuses; rows sharing one judge as one operation. The
/// continuation maps it to the compact [`OpId`] the shared judges read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct WideOp(pub(crate) u64);

/// One fixture scenario. A checked obligation's premises must all occur in
/// the same episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Episode(pub(crate) u64);

/// The kinds of resource the global custody and resource checks count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ResourceKind {
    Extent,
    Slot,
    Buffer,
    Command,
    Credit,
    BudgetCharge,
    RequestShare,
    RetainedChunk,
    /// A client upload's source slot holding one fragment's bytes.
    SourceSlot,
    /// The aligned units one accepted write charges to its write set, under
    /// the index and incarnation of the write's command.
    WriteQuota,
}

impl ResourceKind {
    pub(crate) const ALL: [Self; 10] = [
        Self::Extent,
        Self::Slot,
        Self::Buffer,
        Self::Command,
        Self::Credit,
        Self::BudgetCharge,
        Self::RequestShare,
        Self::RetainedChunk,
        Self::SourceSlot,
        Self::WriteQuota,
    ];

    /// Whether the fixture tracks this kind by incarnation, so a release of
    /// it must name the incarnation returned. Credits, budget charges,
    /// request shares and retained chunks are counted.
    ///
    /// A source slot's incarnation is one fragment's tenure in the slot, and
    /// a write quota's is its command's token.
    pub(crate) const fn incarnated(self) -> bool {
        matches!(
            self,
            Self::Extent
                | Self::Slot
                | Self::Buffer
                | Self::Command
                | Self::SourceSlot
                | Self::WriteQuota
        )
    }

    /// Whether a take of this kind carries a span, so the independent total
    /// sums span lengths: extent units, budget-charge bytes and write-quota
    /// units. Every other kind counts one per held resource.
    pub(crate) const fn spanned(self) -> bool {
        matches!(self, Self::Extent | Self::BudgetCharge | Self::WriteQuota)
    }

    /// Whether this kind is a remote client's buffer, outside the owner's
    /// capacity: the owner's checkpoints leave its custody to the client.
    pub(crate) const fn client_buffer(self) -> bool {
        matches!(self, Self::SourceSlot)
    }
}

/// One resource the fixture tracks, by kind and the fixture's own index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ResourceId {
    pub(crate) kind: ResourceKind,
    pub(crate) index: u32,
}

/// The key history or shared resource a row describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Subject {
    Key(KeyId),
    Resource(ResourceId),
}

/// The clock sample an action consumed.
///
/// `Unavailable` records that the action asked for a sample and the clock
/// gave none. Resource pressure is a separate action, and an action that
/// consumed no sample leaves the row's clock field empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ClockSample {
    /// Whole seconds on the fixture's deadline timeline.
    Seconds(u64),
    Unavailable,
}

/// A tenure tag `(g, a)`: the storage instance a response came from, ordered
/// lexicographically, so a later generation outranks every attachment of an
/// earlier one. `INITIAL` is active from the history's first ordinal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Tenure {
    pub(crate) g: u64,
    pub(crate) a: u64,
}

impl Tenure {
    pub(crate) const INITIAL: Self = Self { g: 0, a: 0 };
}

/// One client process instance. A restarted client is a new instance whose
/// high-water starts absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ClientId(pub(crate) u32);

/// A retained checkpoint a capture recorded and an activation may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CutId(pub(crate) u64);
