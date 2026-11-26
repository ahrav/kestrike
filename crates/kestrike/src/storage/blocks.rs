//! The sequence arena: one fixed buddy arena, laid out in the volume
//! control mapping, whose blocks hold the extent sequences of objects of
//! two or more extents.
//!
//! The arena is `R` roots of [`ROOT_BYTES`] each, sized once from the
//! validated configuration. A block of order `k` spans `32 << k` bytes at a
//! multiple of its size inside one root, from order 0 to order
//! [`BLOCK_TOP`], one whole root. Each root keeps 256 bytes of free bits,
//! one per node of its binary tree of blocks, numbered from 1 so bit 0 is
//! spare, set exactly while that node is a free block, and 128 bytes of
//! live bits, one per granule, set exactly while a live block starts
//! there. Each order keeps one doubly
//! linked list of its free blocks, linked through each free block's first
//! word, whose second word reads zero. An allocated block starts with a
//! 16-byte header: its owner's [`AllocationId`] tag, then its extent count
//! and the length of its held prefix, followed by one 8-byte locator per extent. The
//! first `held` locators are the held prefix, which an append extends and a
//! pop shortens from its end, so the prefix is always `[0, held)`.
//!
//! An allocation of `count` extents takes a block of
//! [`block_order(count)`](block_order): it probes the lists from that order
//! up, at most eleven, takes the first free block it finds, and splits it
//! down to the order, at most ten times, listing each upper half. A free
//! requires a live block to start at the handle, checks its header against
//! the owner and count, then joins the block with its buddy while the
//! buddy's free bit is set, at most ten times. Both preflight their whole
//! bound in the caller's [`WorkBudget`] and debit one visit per probe or
//! buddy check and one update per split or join; a free also debits one
//! update for its release, so every free spends at least one step of the
//! budget. Every refusal leaves the
//! arena unchanged. The pool gate serializes every access.

use super::allocation::AllocationId;
use super::block_order::{BLOCK_MIN, BLOCK_TOP, ROOT_BYTES, block_bytes, block_order};
use super::budget::{WorkBudget, WorkKind};
use super::extent::ExtentLocator;
use super::geometry::DIRECT_UNITS;
use super::geometry::EXTENT_LIMIT;

/// 32-byte granules in one root.
pub(crate) const ROOT_GRANULES: u32 = (ROOT_BYTES / BLOCK_MIN) as u32;
/// Words of one root.
pub(crate) const ROOT_WORDS: usize = ROOT_BYTES as usize / 8;
/// Free-bit words of one root: one bit per tree node, 256 bytes.
const FREE_BIT_WORDS: usize = 2 * ROOT_GRANULES as usize / 64;
/// Bit words of one root: its free bits, then one live bit per granule.
pub(crate) const BIT_WORDS: usize = FREE_BIT_WORDS + ROOT_GRANULES as usize / 64;
/// The most roots an arena holds, so every granule index fits a `u32`
/// below [`NONE`].
pub(crate) const ROOT_LIMIT: usize = (u32::MAX / ROOT_GRANULES) as usize;
/// Lists, one per order.
const ORDERS: usize = BLOCK_TOP as usize + 1;
const TOP: u32 = BLOCK_TOP as u32;
const GRANULE_WORDS: usize = 4;
/// Words of the block header before the first locator.
const LOCATORS: usize = 2;
/// The empty link.
const NONE: u32 = u32::MAX;

/// The arena's list heads and its free granule count, one record in the
/// control mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArenaLists {
    heads: [u32; ORDERS],
    free_granules: u64,
}

impl ArenaLists {
    pub(crate) const EMPTY: Self = Self {
        heads: [NONE; ORDERS],
        free_granules: 0,
    };
}

/// One block, named by the index of its first 32-byte granule in the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Block(pub(super) u32);

/// Why the arena refused; the arena is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArenaError {
    /// The extent count lies outside `2..=EXTENT_LIMIT`.
    Count { count: u32 },
    /// Fewer free bytes remain than the block takes.
    Exhausted { free_bytes: u64, block_bytes: u64 },
    /// Enough bytes are free, in blocks each smaller than the one requested.
    Fragmented { free_bytes: u64, block_bytes: u64 },
    /// The budget cannot fund the operation's bound.
    Budget,
    /// The block lies past the arena or off its order's alignment.
    Range { block: Block },
    /// No live block starts at the handle: it names a free block or lies
    /// inside a block.
    NotLive { block: Block },
    /// The header names another owner.
    Owner { expected: u64, found: u64 },
    /// The header records another extent count.
    HeaderCount { expected: u32, found: u32 },
    /// The held prefix already holds every one of the block's `count`
    /// locators.
    Full { count: u32 },
    /// The header records a held prefix past its extent count. Every arena
    /// write keeps the prefix within the count, so the header is damaged.
    Corrupt { held: u32, count: u32 },
}

/// The arena over its tables, borrowed for one gate hold.
pub(crate) struct BlockArena<'a> {
    lists: &'a mut ArenaLists,
    /// [`ROOT_WORDS`] words per root.
    words: &'a mut [u64],
    /// [`BIT_WORDS`] words per root.
    bits: &'a mut [u64],
}

impl<'a> BlockArena<'a> {
    pub(crate) fn attach(
        lists: &'a mut ArenaLists,
        words: &'a mut [u64],
        bits: &'a mut [u64],
    ) -> Self {
        debug_assert_eq!(words.len() / ROOT_WORDS, bits.len() / BIT_WORDS);
        Self { lists, words, bits }
    }

    /// Lists every root whole on zeroed tables.
    pub(crate) fn init(&mut self) {
        *self.lists = ArenaLists::EMPTY;
        for root in (0..self.bits.len() / BIT_WORDS).rev() {
            self.link(root as u32 * ROOT_GRANULES, TOP);
        }
    }

    /// Free bytes, in blocks of every order.
    pub(crate) fn free_bytes(&self) -> u64 {
        self.lists.free_granules * BLOCK_MIN
    }
}

impl BlockArena<'_> {
    /// Steps an allocation preflights: a probe per order and a split per
    /// order below the top.
    pub(crate) const ALLOCATE_STEPS: usize = 2 * ORDERS - 1;
    /// Steps a free preflights: a buddy check and a join per order below
    /// the top, and the release that lists the joined block.
    pub(crate) const FREE_STEPS: usize = 2 * (ORDERS - 1) + 1;

    /// Takes a block for `owner`'s sequence of `count` extents, its held
    /// prefix empty.
    ///
    /// # Errors
    ///
    /// `Count`, then `Budget` when `budget` cannot fund
    /// [`ALLOCATE_STEPS`](Self::ALLOCATE_STEPS), then `Exhausted` or
    /// `Fragmented`, debiting the probes, when no list from the block's
    /// order up holds a block.
    pub(crate) fn allocate(
        &mut self,
        owner: AllocationId,
        count: u32,
        budget: &mut WorkBudget,
    ) -> Result<Block, ArenaError> {
        let order = order_of(count)?;
        budget
            .preflight(Self::ALLOCATE_STEPS)
            .map_err(|_| ArenaError::Budget)?;
        let found = self.lists.heads[order as usize..]
            .iter()
            .position(|&head| head != NONE)
            .map(|above| order + above as u32);
        let probes = found.map_or(TOP + 1, |at| at + 1) - order;
        debit(budget, WorkKind::Visit, probes);
        let Some(at) = found else {
            let (free_bytes, block_bytes) = (self.free_bytes(), block_bytes(u64::from(order)));
            return Err(if free_bytes < block_bytes {
                ArenaError::Exhausted {
                    free_bytes,
                    block_bytes,
                }
            } else {
                ArenaError::Fragmented {
                    free_bytes,
                    block_bytes,
                }
            });
        };
        let block = self.lists.heads[at as usize];
        self.unlink(block, at);
        for half in (order..at).rev() {
            self.link(block + (1 << half), half);
        }
        debit(budget, WorkKind::Update, at - order);
        self.set_live(block, true);
        let word = word(block);
        self.words[word] = owner.record_tag();
        self.words[word + 1] = pack(count, 0);
        Ok(Block(block))
    }

    /// Releases `block`, which `owner` took for `count` extents, and joins
    /// it with each free buddy up the tree.
    ///
    /// # Errors
    ///
    /// The first failing check of [`held`](Self::held), then `Budget`
    /// when `budget` cannot fund [`FREE_STEPS`](Self::FREE_STEPS).
    pub(crate) fn free(
        &mut self,
        block: Block,
        owner: AllocationId,
        count: u32,
        budget: &mut WorkBudget,
    ) -> Result<(), ArenaError> {
        let (mut order, _) = self.checked(block, owner, count)?;
        budget
            .preflight(Self::FREE_STEPS)
            .map_err(|_| ArenaError::Budget)?;
        let (start, mut at) = (order, block.0);
        self.set_live(at, false);
        self.clear(at);
        while order < TOP {
            let buddy = at ^ (1 << order);
            if !self.is_free(buddy, order) {
                break;
            }
            self.unlink(buddy, order);
            self.clear(buddy);
            at &= !(1 << order);
            order += 1;
        }
        self.link(at, order);
        let joins = order - start;
        debit(budget, WorkKind::Visit, joins + u32::from(order < TOP));
        debit(budget, WorkKind::Update, joins + 1);
        Ok(())
    }

    /// The length of `block`'s held prefix, whose header is checked against the
    /// `owner` and `count` its allocation was for.
    ///
    /// # Errors
    ///
    /// In order: `Count`, `Range`, `NotLive`, `Owner`, `HeaderCount`, then
    /// `Corrupt` when the recorded prefix passes `count`.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "tests build the only sequence objects")
    )]
    pub(crate) fn held(
        &self,
        block: Block,
        owner: AllocationId,
        count: u32,
    ) -> Result<u32, ArenaError> {
        self.checked(block, owner, count).map(|(_, held)| held)
    }

    /// The held prefix of `block`, open for appends and pops. The header
    /// checks of [`held`](Self::held) run once, here, and cover every later
    /// operation on the returned prefix.
    ///
    /// # Errors
    ///
    /// The first failing check of [`held`](Self::held).
    pub(crate) fn open(
        &mut self,
        block: Block,
        owner: AllocationId,
        count: u32,
    ) -> Result<HeldPrefix<'_>, ArenaError> {
        let (_, held) = self.checked(block, owner, count)?;
        Ok(HeldPrefix {
            words: self.words,
            header: word(block.0),
            count,
            held,
        })
    }

    /// The held prefix of `block`, its locators' bits in order.
    ///
    /// # Errors
    ///
    /// The first failing check of [`held`](Self::held).
    pub(crate) fn prefix(
        &self,
        block: Block,
        owner: AllocationId,
        count: u32,
    ) -> Result<&[u64], ArenaError> {
        let (_, held) = self.checked(block, owner, count)?;
        let first = word(block.0) + LOCATORS;
        Ok(&self.words[first..first + held as usize])
    }

    /// The order and held prefix of `block` after the checks of
    /// [`held`](Self::held).
    #[inline(always)]
    fn checked(
        &self,
        block: Block,
        owner: AllocationId,
        count: u32,
    ) -> Result<(u32, u32), ArenaError> {
        let order = order_of(count)?;
        let granules = (self.bits.len() / BIT_WORDS) as u64 * u64::from(ROOT_GRANULES);
        if u64::from(block.0) >= granules || !block.0.is_multiple_of(1 << order) {
            return Err(ArenaError::Range { block });
        }
        if !self.is_live(block.0) {
            return Err(ArenaError::NotLive { block });
        }
        let word = word(block.0);
        let found = self.words[word];
        if found != owner.record_tag() {
            return Err(ArenaError::Owner {
                expected: owner.record_tag(),
                found,
            });
        }
        let (recorded, held) = unpack(self.words[word + 1]);
        if recorded != count {
            return Err(ArenaError::HeaderCount {
                expected: count,
                found: recorded,
            });
        }
        if held > count {
            return Err(ArenaError::Corrupt { held, count });
        }
        Ok((order, held))
    }
}

impl BlockArena<'_> {
    /// The free bit of the node at `order` whose block starts at granule
    /// `at`.
    #[inline(always)]
    fn bit(at: u32, order: u32) -> (usize, u64) {
        let (root, local) = (at / ROOT_GRANULES, at % ROOT_GRANULES);
        // `ROOT_GRANULES >> order` is the first node of the order's level and
        // `local >> order` lies below it, so one shift of their union is
        // their sum.
        let node = (ROOT_GRANULES | local) >> order;
        (
            root as usize * BIT_WORDS + node as usize / 64,
            1 << (node % 64),
        )
    }

    /// The live bit of granule `at`.
    #[inline(always)]
    fn live_bit(at: u32) -> (usize, u64) {
        let (root, local) = (at / ROOT_GRANULES, at % ROOT_GRANULES);
        (
            root as usize * BIT_WORDS + FREE_BIT_WORDS + local as usize / 64,
            1 << (local % 64),
        )
    }

    #[inline(always)]
    pub(super) fn is_free(&self, at: u32, order: u32) -> bool {
        let (word, mask) = Self::bit(at, order);
        self.bits[word] & mask != 0
    }

    #[inline(always)]
    pub(super) fn is_live(&self, at: u32) -> bool {
        let (word, mask) = Self::live_bit(at);
        self.bits[word] & mask != 0
    }

    #[inline(always)]
    fn set_live(&mut self, at: u32, live: bool) {
        let (word, mask) = Self::live_bit(at);
        if live {
            self.bits[word] |= mask;
        } else {
            self.bits[word] &= !mask;
        }
    }

    /// Lists a block over granule `at` at `order` without checking its
    /// buddy or its granules, as a defective join would.
    #[cfg(test)]
    pub(super) fn plant_link(&mut self, at: u32, order: u32) {
        self.link(at, order);
    }

    /// Writes `word` at word `index` of the arena, as stale bytes a block's
    /// body keeps.
    #[cfg(test)]
    pub(super) fn plant_word(&mut self, index: usize, word: u64) {
        self.words[index] = word;
    }

    /// Lists the free block at granule `at` of `order` first.
    #[inline(always)]
    fn link(&mut self, at: u32, order: u32) {
        let head = self.lists.heads[order as usize];
        self.words[word(at)] = pack(head, NONE);
        self.words[word(at) + 1] = 0;
        if head != NONE {
            self.set_links(head, |next, _| (next, at));
        }
        self.lists.heads[order as usize] = at;
        let (bit, mask) = Self::bit(at, order);
        self.bits[bit] |= mask;
        self.lists.free_granules += 1 << order;
    }

    /// Takes the free block at granule `at` of `order` off its list.
    #[inline(always)]
    fn unlink(&mut self, at: u32, order: u32) {
        let (next, prev) = unpack(self.words[word(at)]);
        if prev == NONE {
            self.lists.heads[order as usize] = next;
        } else {
            self.set_links(prev, |_, before| (next, before));
        }
        if next != NONE {
            self.set_links(next, |after, _| (after, prev));
        }
        let (bit, mask) = Self::bit(at, order);
        self.bits[bit] &= !mask;
        self.lists.free_granules -= 1 << order;
    }

    /// Rewrites the `(next, prev)` links of the free block at granule `at`.
    #[inline(always)]
    fn set_links(&mut self, at: u32, change: impl FnOnce(u32, u32) -> (u32, u32)) {
        let (next, prev) = unpack(self.words[word(at)]);
        let (next, prev) = change(next, prev);
        self.words[word(at)] = pack(next, prev);
    }

    /// Zeroes the header words of the block at granule `at`.
    #[inline(always)]
    fn clear(&mut self, at: u32) {
        self.words[word(at)..word(at) + 2].fill(0);
    }

    /// The blocks listed at `order` with each one's `(next, prev, second
    /// word)`, head first.
    #[cfg(test)]
    pub(super) fn listed(&self, order: u32) -> Vec<(u32, (u32, u32, u64))> {
        let mut blocks = Vec::new();
        let mut at = self.lists.heads[order as usize];
        while at != NONE {
            let (next, prev) = unpack(self.words[word(at)]);
            blocks.push((at, (next, prev, self.words[word(at) + 1])));
            at = next;
        }
        blocks
    }
}

/// The index of the first word of the block at granule `at`.
fn word(at: u32) -> usize {
    at as usize * GRANULE_WORDS
}

/// A checked block's held prefix of `held` locators. Each append or pop
/// writes the new length to the block's header, so the header records the
/// prefix after every operation.
pub(crate) struct HeldPrefix<'a> {
    words: &'a mut [u64],
    header: usize,
    count: u32,
    held: u32,
}

impl HeldPrefix<'_> {
    #[inline(always)]
    pub(crate) fn len(&self) -> u32 {
        self.held
    }

    /// Appends `locator`, an extent of at most one extent's units, to the
    /// held prefix and returns the prefix's new length.
    ///
    /// # Errors
    ///
    /// `Full` once the prefix holds the block's `count` locators; the
    /// block is unchanged.
    pub(crate) fn push(&mut self, locator: ExtentLocator) -> Result<u32, ArenaError> {
        debug_assert!(
            locator.len_units() <= DIRECT_UNITS,
            "an extent past one extent's units"
        );
        if self.held == self.count {
            return Err(ArenaError::Full { count: self.count });
        }
        self.words[self.header + LOCATORS + self.held as usize] = locator.bits();
        self.held += 1;
        self.words[self.header + 1] = pack(self.count, self.held);
        Ok(self.held)
    }

    /// Takes the last locator off the held prefix and returns its index
    /// with it, or `None` when the prefix is empty.
    pub(crate) fn pop(&mut self) -> Option<(u32, ExtentLocator)> {
        let last = self.held.checked_sub(1)?;
        self.held = last;
        self.words[self.header + 1] = pack(self.count, last);
        let bits = self.words[self.header + LOCATORS + last as usize];
        Some((last, ExtentLocator::from_bits(bits)))
    }
}

/// `low` in the low 32 bits of a word and `high` in the high 32.
fn pack(low: u32, high: u32) -> u64 {
    u64::from(low) | u64::from(high) << 32
}

fn unpack(word: u64) -> (u32, u32) {
    (word as u32, (word >> 32) as u32)
}

/// Debits `steps` steps of `kind` that a preflight covered.
fn debit(budget: &mut WorkBudget, kind: WorkKind, steps: u32) {
    budget
        .debit_n(kind, steps as usize)
        .expect("the preflight covered the operation's bound");
}

/// The order of the block for `count` extents.
fn order_of(count: u32) -> Result<u32, ArenaError> {
    if !(2..=EXTENT_LIMIT).contains(&u64::from(count)) {
        return Err(ArenaError::Count { count });
    }
    Ok(block_order(u64::from(count)) as u32)
}
