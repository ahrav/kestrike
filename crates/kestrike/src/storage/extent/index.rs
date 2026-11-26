//! The capped best-fit run index: the volume's maximal free runs in 256 B+ trees that share one fixed table of 128-byte nodes.
//!
//! A key packs the start in the low 40 bits and the length, saturated at `2^24 - 1`, in the high 24 bits, so integer key order is `(len.min(SATURATED), start)` order; disjoint free runs have distinct starts and therefore unique keys.
//! Tree `t` for `1 <= t < 256` holds the keys of length `t` and tree 0 the keys of length at least 256, so every key of tree `t > 0` is below every key of a higher exact tree and of tree 0.
//! Bit `t % 64` of mask word `t / 64` is set while tree `t` holds a key, and each tree caches its first leaf: the smallest key at least `(n, 0)` for `n < 256` is the first key of the lowest nonempty exact tree at or above `n`, else of tree 0, found from the mask and one leaf.
//!
//! A leaf holds up to 16 keys in ascending order and pads the rest with [`EMPTY`].
//! An inner node holds up to 10 ascending separators, padded with [`EMPTY`], in words 0 to 9 and up to 11 child links in the 32-bit halves of words 10 to 15; child `i` holds the keys at least separator `i - 1` and below separator `i`.
//! Every node other than a root holds at least 8 keys or 5 children: a removal that leaves fewer borrows from a sibling or merges with it, and an insertion into a full node splits it.
//! The node table therefore needs at most [`index_nodes`] nodes for `capacity` keys, and a tree of `m` leaves has at most `1 + log5(m / 2)` inner levels.
//! Spare nodes chain through word 0.
//! A tree's first leaf changes only when the tree gains or frees its root leaf: a split keeps the lower keys in the split node, and a merge keeps the left node.

use super::allocator::ExtentAllocator;
use super::plan::START_BITS;
pub(super) use super::plan::{SATURATED, key_run, run_key};

/// Pads a node's unused keys and separators; every key is below it, because a run of at least [`SATURATED`] units ends inside a volume of at most `2^40` units and so starts at most `2^40 - SATURATED`.
pub(super) const EMPTY: u64 = u64::MAX;
/// Marks an empty tree, an absent first leaf, the end of the spare chain and an unused child link.
pub(super) const NONE: u32 = u32::MAX;
/// Trees of the index; tree `t` holds the keys of length `t` for `0 < t < TREES` and tree 0 the longer keys.
pub(super) const TREES: usize = 256;
const MASK_WORDS: usize = TREES / 64;
const KEYS: usize = 16;
const MIN_KEYS: usize = KEYS / 2;
const SEPARATORS: usize = 10;
const CHILDREN: usize = SEPARATORS + 1;
const MIN_CHILDREN: usize = CHILDREN / 2;
/// Steps the descent path holds: a node table below `2^32` nodes holds fewer than `2^35` keys, so [`index_height`] stays at most 14.
pub(super) const MAX_HEIGHT: usize = 16;

/// One node of the run index: a leaf of keys, an inner node of separators and child links, or a spare node.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunNode([u64; KEYS]);

const _: () = assert!(size_of::<RunNode>() == 128);

impl Default for RunNode {
    fn default() -> Self {
        Self([EMPTY; KEYS])
    }
}

impl RunNode {
    fn child(&self, index: usize) -> u32 {
        (self.0[SEPARATORS + index / 2] >> (index % 2 * 32)) as u32
    }

    fn set_child(&mut self, index: usize, child: u32) {
        let shift = index % 2 * 32;
        let word = &mut self.0[SEPARATORS + index / 2];
        *word = *word & !(u64::from(u32::MAX) << shift) | u64::from(child) << shift;
    }

    /// Children of an inner node: one more than its separators.
    fn children(&self) -> usize {
        1 + self.0[..SEPARATORS]
            .iter()
            .filter(|&&sep| sep != EMPTY)
            .count()
    }

    /// Keys of a leaf.
    fn len(&self) -> usize {
        self.0.iter().filter(|&&key| key != EMPTY).count()
    }

    /// The child an inner node descends to for `key`: the count of separators at most `key`.
    #[inline(always)]
    fn route(&self, key: u64) -> usize {
        let mut index = 0;
        for &sep in &self.0[..SEPARATORS] {
            index += usize::from(sep <= key);
        }
        index
    }

    /// The count of a leaf's keys below `key`, by a branchless binary search over its 16 slots.
    #[inline(always)]
    fn rank(&self, key: u64) -> usize {
        let (mut low, mut size) = (0, KEYS + 1);
        while size > 1 {
            let half = size / 2;
            low = std::hint::select_unpredictable(self.0[low + half - 1] < key, low + half, low);
            size -= half;
        }
        low
    }

    /// Inserts `key`, absent from the leaf, which has a free slot, keeping the keys ascending.
    #[inline(always)]
    fn insert_key(&mut self, key: u64) {
        let old = self.0;
        for (index, slot) in self.0.iter_mut().enumerate() {
            let before = if index == 0 { 0 } else { old[index - 1] };
            *slot = old[index].min(key.max(before));
        }
    }

    /// Removes `key`, which the leaf holds, shifting the later keys down.
    #[inline(always)]
    fn remove_key(&mut self, key: u64) {
        let old = self.0;
        for (index, slot) in self.0.iter_mut().enumerate() {
            let after = old.get(index + 1).copied().unwrap_or(EMPTY);
            *slot = std::hint::select_unpredictable(old[index] < key, old[index], after);
        }
    }

    /// Removes a leaf's first key, shifting the others down.
    #[inline(always)]
    fn remove_first(&mut self) {
        self.0.copy_within(1.., 0);
        self.0[KEYS - 1] = EMPTY;
    }

    /// Removes child `index`, at least 1, and the separator before it from an inner node of `children` children.
    fn remove_child(&mut self, index: usize, children: usize) {
        for at in index..children - 1 {
            let next = self.child(at + 1);
            self.set_child(at, next);
        }
        self.set_child(children - 1, NONE);
        self.0.copy_within(index..children - 1, index - 1);
        self.0[children - 2] = EMPTY;
    }

    /// Inserts child `child` at `index`, at least 1, with separator `sep` before it, into an inner node of `children < CHILDREN` children.
    fn insert_child(&mut self, index: usize, sep: u64, child: u32, children: usize) {
        for at in (index..children).rev() {
            let moved = self.child(at);
            self.set_child(at + 1, moved);
        }
        self.set_child(index, child);
        self.0.copy_within(index - 1..children - 1, index);
        self.0[index - 1] = sep;
    }
}

/// The index state the allocator's root record carries.
///
/// Invariants, true after every call: tree `t` is empty exactly when `roots[t]` is [`NONE`] and its `mask` bit is clear; `heights[t]` counts its inner levels; `firsts[t]` is the leaf a descent through child 0 from `roots[t]` reaches; `count` keys are indexed, at most `capacity`; `spare` heads the chain of every node no tree holds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndexHeads {
    roots: [u32; TREES],
    firsts: [u32; TREES],
    heights: [u8; TREES],
    mask: [u64; MASK_WORDS],
    count: u64,
    pub(super) capacity: u64,
    spare: u32,
}

impl Default for IndexHeads {
    fn default() -> Self {
        Self {
            roots: [NONE; TREES],
            firsts: [NONE; TREES],
            heights: [0; TREES],
            mask: [0; MASK_WORDS],
            count: 0,
            capacity: 0,
            spare: NONE,
        }
    }
}

/// Nodes of the index table for `capacity` keys.
///
/// The trees hold at most `capacity / 8 + min(256, capacity)` leaves: a leaf other than a root holds at least 8 keys, and each nonempty tree has one root.
/// A tree of `m >= 2` leaves holds at least 16 keys and has at most `1 + (m - 2) / 4` inner nodes, because its root links at least two children and every other inner node at least five; over at most `min(256, capacity / 16)` such trees the inner nodes number at most a quarter of the leaves plus half those trees.
pub(crate) fn index_nodes(capacity: usize) -> usize {
    let leaves = capacity / MIN_KEYS + capacity.min(TREES);
    let branching = (capacity / (2 * MIN_KEYS)).min(TREES);
    leaves + leaves.div_ceil(MIN_CHILDREN - 1) + branching.div_ceil(2)
}

/// Inner levels one tree of an index of `capacity` keys reaches at most: a tree of `h >= 1` inner levels holds at least `2 * 5^(h - 1)` leaves of 8 keys.
pub(super) fn index_height(capacity: usize) -> u64 {
    let leaves = (capacity / MIN_KEYS) as u64;
    let (mut height, mut least) = (0, 2);
    while least <= leaves {
        height += 1;
        least *= MIN_CHILDREN as u64;
    }
    height
}

/// The lowest exact tree at or above `n`, `1 <= n < TREES`, that holds a key.
fn exact_at_or_above(mask: &[u64; MASK_WORDS], n: usize) -> Option<usize> {
    let first = n / 64;
    for (word, &bits) in mask.iter().enumerate().skip(first) {
        let bits = if word == first {
            bits & u64::MAX << (n % 64)
        } else {
            bits
        };
        if bits != 0 {
            return Some(word * 64 + bits.trailing_zeros() as usize);
        }
    }
    None
}

/// The tree that holds `key`.
pub(super) fn tree_of(key: u64) -> usize {
    match (key >> START_BITS) as usize {
        len if len < TREES => len,
        _ => 0,
    }
}

/// An indexed key, the tree and leaf that hold it, and whether the descent path leads to that leaf; a key read from a cached first leaf has no path and is that leaf's first key.
#[derive(Debug, Clone, Copy)]
pub(super) struct Found {
    pub(super) key: u64,
    tree: usize,
    leaf: u32,
    traced: bool,
}

/// Where a key enters: its tree, and the leaf a descent reached with the path to it, [`NONE`] for an empty tree.
#[derive(Debug, Clone, Copy)]
pub(super) struct Position {
    tree: usize,
    leaf: u32,
}

/// One step of a descent: the inner node and the child the descent took.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Step {
    node: u32,
    child: u32,
}

impl ExtentAllocator<'_> {
    /// Empties the index, sets its capacity to `capacity` keys, and chains every node of the nonempty table as spare.
    pub(super) fn index_init(&mut self, capacity: usize) {
        let last = self.nodes.len() - 1;
        for (index, node) in self.nodes.iter_mut().enumerate() {
            *node = RunNode::default();
            node.0[0] = if index < last {
                index as u64 + 1
            } else {
                u64::from(NONE)
            };
        }
        self.root.index = IndexHeads {
            capacity: capacity as u64,
            spare: 0,
            ..IndexHeads::default()
        };
    }

    pub(super) fn index_full(&self) -> bool {
        self.root.index.count == self.root.index.capacity
    }

    /// Takes the head of the spare chain, every word [`EMPTY`]; the chain holds a node whenever the key count stays within capacity, because the table holds [`index_nodes`] nodes.
    fn take_node(&mut self) -> u32 {
        let node = self.root.index.spare;
        let next = &mut self.nodes[node as usize];
        self.root.index.spare = next.0[0] as u32;
        *next = RunNode::default();
        node
    }

    /// Clears `node` and pushes it on the spare chain.
    fn give_node(&mut self, node: u32) {
        self.nodes[node as usize] = RunNode::default();
        self.nodes[node as usize].0[0] = u64::from(self.root.index.spare);
        self.root.index.spare = node;
    }

    /// The key the first leaf of the nonempty `tree` starts with, counting one visit.
    fn first_of(&mut self, tree: usize) -> Found {
        self.work += 1;
        let leaf = self.root.index.firsts[tree];
        Found {
            key: self.nodes[leaf as usize].0[0],
            tree,
            leaf,
            traced: false,
        }
    }

    /// The smallest indexed key at least `(n, 0)` for `n >= 1`, or `None`.
    ///
    /// Below 256 units the tree mask in the root record picks the tree and its first leaf, one visit, holds the key; at 256 or more a descent of tree 0 finds it, walking to the next leaf when the descent's leaf holds only smaller keys.
    /// The lookup counts at most `3h + 1` visits for a tree of `h` inner levels: the descent `h + 1` and the walk `2h`.
    #[inline(always)]
    pub(super) fn index_best_fit(&mut self, n: u64) -> Option<Found> {
        let mask = &self.root.index.mask;
        let long = mask[0] & 1 != 0;
        if n < TREES as u64 {
            let tree = match exact_at_or_above(mask, n as usize) {
                Some(tree) => tree,
                None if long => 0,
                None => return None,
            };
            return Some(self.first_of(tree));
        }
        if !long {
            return None;
        }
        self.long_fit(n)
    }

    /// [`index_best_fit`](Self::index_best_fit) for `n` of at least 256 units in tree 0, which holds a key.
    #[inline(never)]
    fn long_fit(&mut self, n: u64) -> Option<Found> {
        let key = run_key(0, n);
        let leaf = self.descend(0, key);
        let node = &self.nodes[leaf as usize];
        let rank = node.rank(key);
        if rank < KEYS && node.0[rank] != EMPTY {
            return Some(Found {
                key: node.0[rank],
                tree: 0,
                leaf,
                traced: true,
            });
        }
        self.next_leaf(0)
    }

    /// The first key of the leaf after the one the path leads to in `tree`, moving the path to it, or `None` past the tree's last leaf.
    ///
    /// The walk counts one visit per level it climbs and per node it descends to, at most `2h` for a tree of `h` inner levels.
    fn next_leaf(&mut self, tree: usize) -> Option<Found> {
        let height = usize::from(self.root.index.heights[tree]);
        for level in (0..height).rev() {
            self.work += 1;
            let Step { node, child } = self.path[level];
            let next = child as usize + 1;
            if next < self.nodes[node as usize].children() {
                self.path[level].child = next as u32;
                let mut below = self.nodes[node as usize].child(next);
                for deeper in level + 1..height {
                    self.work += 1;
                    self.path[deeper] = Step {
                        node: below,
                        child: 0,
                    };
                    below = self.nodes[below as usize].child(0);
                }
                self.work += 1;
                return Some(Found {
                    key: self.nodes[below as usize].0[0],
                    tree,
                    leaf: below,
                    traced: true,
                });
            }
        }
        None
    }

    /// Descends `tree`, which holds a key, to the leaf whose range holds `key`, recording the path and counting one visit per node on it, the leaf included.
    #[inline(always)]
    fn descend(&mut self, tree: usize, key: u64) -> u32 {
        let height = usize::from(self.root.index.heights[tree]);
        let mut node = self.root.index.roots[tree];
        for step in &mut self.path[..height] {
            let child = self.nodes[node as usize].route(key);
            *step = Step {
                node,
                child: child as u32,
            };
            node = self.nodes[node as usize].child(child);
        }
        self.work += height + 1;
        node
    }

    /// The index's smallest key, from the tree mask and one first leaf; the index holds a key.
    fn index_minimum(&mut self) -> Found {
        let tree = exact_at_or_above(&self.root.index.mask, 1).unwrap_or(0);
        self.first_of(tree)
    }

    /// Where `key` enters the index; [`index_attach`](Self::index_attach) inserts it there while the index and the descent path stay unchanged.
    /// `key` names a run inside the volume, so it lies below [`EMPTY`], as a descent requires.
    #[inline(always)]
    pub(super) fn index_position(&mut self, key: u64) -> Position {
        debug_assert!(key < EMPTY, "a descent key names a run inside the volume");
        let tree = tree_of(key);
        let leaf = if self.root.index.roots[tree] == NONE {
            NONE
        } else {
            self.descend(tree, key)
        };
        Position { tree, leaf }
    }

    /// Indexes `key`, absent from the index, at `position`; the index has room.
    ///
    /// `position` comes from the most recent [`index_position`](Self::index_position) call, with the index unchanged since, because a split reads the recorded path.
    /// The insertion counts at most `2h + 3` visits for a tree of `h` inner levels: two for the leaf split, two per inner split and one for a new root.
    #[inline(always)]
    pub(super) fn index_attach(&mut self, key: u64, position: Position) {
        let leaf = position.leaf;
        self.root.index.count += 1;
        if leaf != NONE && self.nodes[leaf as usize].0[KEYS - 1] == EMPTY {
            self.nodes[leaf as usize].insert_key(key);
        } else {
            self.attach_slow(key, position);
        }
    }

    /// [`index_attach`](Self::index_attach) into an empty tree, which takes a root leaf, or into a full leaf, which splits.
    #[inline(never)]
    fn attach_slow(&mut self, key: u64, position: Position) {
        let Position { tree, leaf } = position;
        if leaf != NONE {
            self.split_leaf(tree, leaf, key);
            return;
        }
        let node = self.take_node();
        self.nodes[node as usize].0[0] = key;
        let heads = &mut self.root.index;
        heads.mask[tree / 64] |= 1 << (tree % 64);
        (heads.roots[tree], heads.firsts[tree], heads.heights[tree]) = (node, node, 0);
    }

    /// Indexes the free run `start..start + len`, which has no entry; the index has room.
    pub(super) fn index_insert(&mut self, start: u64, len: u64) {
        let key = run_key(start, len);
        let position = self.index_position(key);
        self.index_attach(key, position);
    }

    /// Splits the full `leaf` of `tree` around `key`: the lower nine keys stay, the upper eight move to a new leaf after it, and the parent gains the new leaf.
    fn split_leaf(&mut self, tree: usize, leaf: u32, key: u64) {
        let old = self.nodes[leaf as usize].0;
        let rank = self.nodes[leaf as usize].rank(key);
        let mut all = [EMPTY; KEYS + 1];
        all[..rank].copy_from_slice(&old[..rank]);
        all[rank] = key;
        all[rank + 1..].copy_from_slice(&old[rank..]);
        let kept = KEYS / 2 + 1;
        let right = self.take_node();
        self.work += 2;
        let node = &mut self.nodes[leaf as usize].0;
        node[..kept].copy_from_slice(&all[..kept]);
        node[kept..].fill(EMPTY);
        self.nodes[right as usize].0[..KEYS + 1 - kept].copy_from_slice(&all[kept..]);
        let height = usize::from(self.root.index.heights[tree]);
        self.add_child(tree, height, all[kept], right);
    }

    /// Links `child`, whose keys are at least `sep`, after the child the path took at `level - 1`; at level 0 a new root links the old root and `child`.
    /// A full inner node splits, six children staying and six moving to a new node, and passes its middle separator up.
    fn add_child(&mut self, tree: usize, level: usize, sep: u64, child: u32) {
        if level == 0 {
            let old = self.root.index.roots[tree];
            let root = self.take_node();
            self.work += 1;
            let node = &mut self.nodes[root as usize];
            node.set_child(0, old);
            node.set_child(1, child);
            node.0[0] = sep;
            self.root.index.roots[tree] = root;
            self.root.index.heights[tree] += 1;
            return;
        }
        let Step { node, child: taken } = self.path[level - 1];
        let at = taken as usize + 1;
        let inner = &mut self.nodes[node as usize];
        let children = inner.children();
        if children < CHILDREN {
            inner.insert_child(at, sep, child, children);
            return;
        }
        let mut links = [NONE; CHILDREN + 1];
        let mut seps = [EMPTY; CHILDREN];
        for (index, link) in links.iter_mut().enumerate() {
            *link = match index {
                _ if index < at => inner.child(index),
                _ if index == at => child,
                _ => inner.child(index - 1),
            };
        }
        for (index, slot) in seps.iter_mut().enumerate() {
            *slot = match index {
                _ if index + 1 < at => inner.0[index],
                _ if index + 1 == at => sep,
                _ => inner.0[index - 1],
            };
        }
        let kept = CHILDREN.div_ceil(2);
        let right = self.take_node();
        self.work += 2;
        let (left, moved) = (&mut self.nodes[node as usize], kept..CHILDREN + 1);
        *left = RunNode::default();
        for (index, &link) in links[..kept].iter().enumerate() {
            left.set_child(index, link);
        }
        left.0[..kept - 1].copy_from_slice(&seps[..kept - 1]);
        let upper = &mut self.nodes[right as usize];
        for (index, source) in moved.enumerate() {
            upper.set_child(index, links[source]);
        }
        upper.0[..CHILDREN - kept].copy_from_slice(&seps[kept..]);
        self.add_child(tree, level - 1, seps[kept - 1], right);
    }

    /// Removes the key `found` names; the index and the descent path are unchanged since the lookup that returned `found`.
    ///
    /// A leaf left below eight keys borrows from or merges with a sibling, after recording the first-child path when `found` came from a first leaf; a tree left empty frees its root leaf and clears its mask bit.
    /// The removal counts at most `3h` visits for a tree of `h` inner levels: `h` for the path rebuild, two for the leaf refill and two per inner refill below the root.
    #[inline(always)]
    pub(super) fn index_remove(&mut self, found: Found) {
        let Found {
            key,
            tree,
            leaf,
            traced,
        } = found;
        let node = &mut self.nodes[leaf as usize];
        if traced {
            node.remove_key(key);
        } else {
            node.remove_first();
        }
        self.root.index.count -= 1;
        let root = self.root.index.heights[tree] == 0;
        let low = if root { 0 } else { MIN_KEYS - 1 };
        if self.nodes[leaf as usize].0[low] == EMPTY {
            self.remove_slow(found);
        }
    }

    /// Finishes [`index_remove`](Self::index_remove) when the removal emptied a root leaf, which frees it and empties the tree, or left another leaf with seven keys, which refills it.
    #[inline(never)]
    fn remove_slow(&mut self, found: Found) {
        let Found {
            tree, leaf, traced, ..
        } = found;
        let height = usize::from(self.root.index.heights[tree]);
        if height == 0 {
            self.give_node(leaf);
            let heads = &mut self.root.index;
            (heads.roots[tree], heads.firsts[tree]) = (NONE, NONE);
            heads.mask[tree / 64] &= !(1 << (tree % 64));
            return;
        }
        if !traced {
            let mut node = self.root.index.roots[tree];
            for step in &mut self.path[..height] {
                *step = Step { node, child: 0 };
                node = self.nodes[node as usize].child(0);
            }
            self.work += height;
        }
        self.refill_leaf(tree, leaf, height - 1);
    }

    /// Restores seven keys in `leaf`, below its parent at path level `level`, to at least eight, using the left sibling when one exists and the right otherwise.
    /// It borrows the sibling's nearest key when the sibling holds more than eight, and otherwise merges the two into the left node, which removes a child from the parent.
    fn refill_leaf(&mut self, tree: usize, leaf: u32, level: usize) {
        let Step {
            node: parent,
            child,
        } = self.path[level];
        let child = child as usize;
        self.work += 2;
        if child > 0 {
            let left = self.nodes[parent as usize].child(child - 1);
            let len = self.nodes[left as usize].len();
            let moved = self.nodes[left as usize].0[len - 1];
            if len > MIN_KEYS {
                self.nodes[left as usize].0[len - 1] = EMPTY;
                self.nodes[leaf as usize].insert_key(moved);
                self.nodes[parent as usize].0[child - 1] = moved;
                return;
            }
            let keys = self.nodes[leaf as usize].0;
            self.nodes[left as usize].0[len..len + MIN_KEYS - 1]
                .copy_from_slice(&keys[..MIN_KEYS - 1]);
            self.give_node(leaf);
            self.unlink_child(tree, level, child);
        } else {
            let right = self.nodes[parent as usize].child(1);
            let len = self.nodes[right as usize].len();
            if len > MIN_KEYS {
                let moved = self.nodes[right as usize].0[0];
                self.nodes[right as usize].remove_key(moved);
                self.nodes[leaf as usize].insert_key(moved);
                self.nodes[parent as usize].0[0] = self.nodes[right as usize].0[0];
                return;
            }
            let keys = self.nodes[right as usize].0;
            self.nodes[leaf as usize].0[MIN_KEYS - 1..MIN_KEYS - 1 + len]
                .copy_from_slice(&keys[..len]);
            self.give_node(right);
            self.unlink_child(tree, level, 1);
        }
    }

    /// Removes child `index`, at least 1, from the inner node at path level `level`; a root left with one child gives way to it, and another node left with four children borrows from or merges with a sibling.
    fn unlink_child(&mut self, tree: usize, level: usize, index: usize) {
        let node = self.path[level].node;
        let children = self.nodes[node as usize].children();
        self.nodes[node as usize].remove_child(index, children);
        if level == 0 {
            if children == 2 {
                let only = self.nodes[node as usize].child(0);
                self.give_node(node);
                self.root.index.roots[tree] = only;
                self.root.index.heights[tree] -= 1;
            }
            return;
        }
        if children - 1 < MIN_CHILDREN {
            self.refill_inner(tree, level);
        }
    }

    /// Restores four children in the inner node at path level `level` to at least five, using the left sibling when one exists and the right otherwise.
    /// It rotates the sibling's nearest child through the parent's separator when the sibling holds more than five, and otherwise merges the two into the left node around that separator.
    fn refill_inner(&mut self, tree: usize, level: usize) {
        let node = self.path[level].node;
        let Step {
            node: parent,
            child,
        } = self.path[level - 1];
        let child = child as usize;
        self.work += 2;
        let have = MIN_CHILDREN - 1;
        if child > 0 {
            let left = self.nodes[parent as usize].child(child - 1);
            let sibling = self.nodes[left as usize];
            let len = sibling.children();
            let between = self.nodes[parent as usize].0[child - 1];
            if len > MIN_CHILDREN {
                let inner = &mut self.nodes[node as usize];
                for at in (0..have).rev() {
                    let moved = inner.child(at);
                    inner.set_child(at + 1, moved);
                }
                inner.set_child(0, sibling.child(len - 1));
                inner.0.copy_within(0..have - 1, 1);
                inner.0[0] = between;
                self.nodes[parent as usize].0[child - 1] = sibling.0[len - 2];
                let left_node = &mut self.nodes[left as usize];
                left_node.set_child(len - 1, NONE);
                left_node.0[len - 2] = EMPTY;
                return;
            }
            let moved = self.nodes[node as usize];
            let target = &mut self.nodes[left as usize];
            target.0[len - 1] = between;
            target.0[len..len + have - 1].copy_from_slice(&moved.0[..have - 1]);
            for index in 0..have {
                target.set_child(len + index, moved.child(index));
            }
            self.give_node(node);
            self.unlink_child(tree, level - 1, child);
        } else {
            let right = self.nodes[parent as usize].child(1);
            let sibling = self.nodes[right as usize];
            let len = sibling.children();
            let between = self.nodes[parent as usize].0[0];
            if len > MIN_CHILDREN {
                let inner = &mut self.nodes[node as usize];
                inner.set_child(have, sibling.child(0));
                inner.0[have - 1] = between;
                self.nodes[parent as usize].0[0] = sibling.0[0];
                self.nodes[right as usize].remove_child(1, len);
                let right_node = &mut self.nodes[right as usize];
                right_node.set_child(0, sibling.child(1));
                return;
            }
            let target = &mut self.nodes[node as usize];
            target.0[have - 1] = between;
            target.0[have..have + len - 1].copy_from_slice(&sibling.0[..len - 1]);
            for index in 0..len {
                target.set_child(have + index, sibling.child(index));
            }
            self.give_node(right);
            self.unlink_child(tree, level - 1, 1);
        }
    }

    /// Removes the entry of the maximal run `start..start + len` when the index holds it; a dropped run costs the descent, `h + 1` visits for a tree of `h` inner levels, and an empty tree costs zero visits.
    pub(super) fn unindex(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let key = run_key(start, len);
        let tree = tree_of(key);
        if self.root.index.roots[tree] == NONE {
            return;
        }
        let leaf = self.descend(tree, key);
        let node = &self.nodes[leaf as usize];
        let rank = node.rank(key);
        if rank < KEYS && node.0[rank] == key {
            self.index_remove(Found {
                key,
                tree,
                leaf,
                traced: true,
            });
        }
    }

    /// Indexes the free run `start..start + len`, which has no entry; a zero length changes nothing.
    /// A full index keeps its largest keys: the smaller of the offered run and its smallest entry stays out, and `drops` counts one.
    pub(super) fn offer(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let key = run_key(start, len);
        if self.index_full() {
            self.root.drops += 1;
            let smallest = self.index_minimum();
            if key < smallest.key {
                return;
            }
            self.index_remove(smallest);
        }
        let position = self.index_position(key);
        self.index_attach(key, position);
    }

    /// Indexes the nonempty free run `start..start + len` under the drop rule of a full index; the caller supplies the `position` the most recent descent found for `run_key(start, len)`, with the index unchanged since.
    ///
    /// A full index removes its smallest entry before it inserts, which can move the position, so it descends again.
    pub(super) fn offer_at(&mut self, start: u64, len: u64, position: Position) {
        if self.index_full() {
            self.offer(start, len);
        } else {
            self.index_attach(run_key(start, len), position);
        }
    }

    /// `fill_plan` starts filling the empty index from nonempty maximal free runs in address order whose per-tree counts are `counts`; [`fill_run`](Self::fill_run) then takes each run and [`fill_end`](Self::fill_end) links the trees. Together they leave the entries and `drops` that successive [`offer`](Self::offer) calls leave: the largest keys up to the capacity.
    ///
    /// Tree 0's keys rank highest; exact trees follow in descending tree order. Within an exact tree, keys increase with start, so a partially retained tree keeps its last runs in address order, and its kept keys fill consecutive leaves taken here.
    pub(super) fn fill_plan(&mut self, counts: &[u64; TREES]) -> Filling {
        debug_assert_eq!(self.root.index.count, 0, "the index starts empty");
        let (total, capacity) = (counts.iter().sum::<u64>(), self.root.index.capacity);
        let mut filling = Filling {
            skip: *counts,
            placing: [Placing::default(); TREES],
            offered: counts[0] > capacity,
        };
        if filling.offered {
            self.root.drops += total - counts[0];
            filling.skip[0] = 0;
            return filling;
        }
        filling.skip[0] = 0;
        let mut room = capacity - counts[0];
        for tree in (1..TREES).rev() {
            let kept = counts[tree].min(room);
            (filling.skip[tree], room) = (counts[tree] - kept, room - kept);
            if kept > 0 {
                let leaves = kept.div_ceil(KEYS as u64);
                filling.placing[tree] = Placing {
                    base: self.take_run(leaves as usize),
                    leaves,
                    kept,
                    end: kept / leaves,
                    ..Placing::default()
                };
            }
        }
        self.root.drops += total - total.min(capacity);
        filling
    }

    /// Enters the next run of the fill [`fill_plan`](Self::fill_plan) began.
    #[inline(always)]
    pub(super) fn fill_run(&mut self, filling: &mut Filling, start: u64, len: u64) {
        let key = run_key(start, len);
        let tree = tree_of(key);
        match (tree, filling.skip[tree]) {
            (0, _) if filling.offered => self.offer(start, len),
            (0, _) => self.index_insert(start, len),
            (_, 0) => {
                let (leaf, slot) = filling.placing[tree].next();
                self.nodes[leaf as usize].0[slot] = key;
            }
            _ => filling.skip[tree] -= 1,
        }
    }

    /// Links the trees whose keys [`fill_run`](Self::fill_run) placed.
    pub(super) fn fill_end(&mut self, filling: &Filling) {
        for (tree, placing) in filling.placing.iter().enumerate() {
            if placing.kept > 0 {
                self.link_leaves(tree, placing);
            }
        }
    }

    /// Takes `count` nodes from the spare chain and returns the first; `index_init` links the chain in table order and a fill only takes from it, so the nodes are consecutive.
    fn take_run(&mut self, count: usize) -> u32 {
        let first = self.root.index.spare;
        for offset in 0..count as u32 {
            let node = self.take_node();
            assert_eq!(
                node,
                first + offset,
                "a filling index takes consecutive nodes"
            );
        }
        first
    }

    /// Builds the inner levels of exact tree `tree` over the `placing.leaves` consecutive leaves its keys fill, each level spreading its nodes evenly under consecutive parents, and installs the tree.
    fn link_leaves(&mut self, tree: usize, placing: &Placing) {
        let (mut first, mut count, mut height) = (placing.base, placing.leaves as u32, 0u8);
        while count > 1 {
            let parents = count.div_ceil(CHILDREN as u32);
            let up = self.take_run(parents as usize);
            for parent in 0..parents {
                let (from, to) = (
                    spread(parent, count, parents),
                    spread(parent + 1, count, parents),
                );
                let mut node = RunNode::default();
                for (index, child) in (first + from..first + to).enumerate() {
                    node.set_child(index, child);
                    if index > 0 {
                        node.0[index - 1] = self.smallest(child, height);
                    }
                }
                self.nodes[(up + parent) as usize] = node;
            }
            (first, count, height) = (up, parents, height + 1);
        }
        let heads = &mut self.root.index;
        heads.mask[tree / 64] |= 1 << (tree % 64);
        (heads.roots[tree], heads.firsts[tree], heads.heights[tree]) =
            (first, placing.base, height);
        heads.count += placing.kept;
    }

    /// The smallest key under `node`, `height` inner levels above its leaves.
    fn smallest(&self, mut node: u32, height: u8) -> u64 {
        for _ in 0..height {
            node = self.nodes[node as usize].child(0);
        }
        self.nodes[node as usize].0[0]
    }
}

/// The first of `count` children that parent `part` of `parts` takes when the children spread evenly over the parents, in `u64` because `part * count` can pass `u32::MAX`.
pub(super) fn spread(part: u32, count: u32, parts: u32) -> u32 {
    (u64::from(part) * u64::from(count) / u64::from(parts)) as u32
}

/// `Filling` holds a fill's plan: `skip[t]` counts the runs of exact tree `t` still to leave out, the first ones in address order; `placing[t]` places tree `t`'s kept keys; `offered` marks a fill whose tree 0 alone exceeds the capacity, so its long runs take ordinary offers and every exact tree's runs stay out.
pub(super) struct Filling {
    skip: [u64; TREES],
    placing: [Placing; TREES],
    offered: bool,
}

/// Where the kept keys of one exact tree land as [`fill_run`](ExtentAllocator::fill_run) places them in ascending order: `leaves` consecutive leaves from node `base`, leaf `j` taking the keys of ranks `j * kept / leaves` up to the next leaf's first rank, so every leaf of a tree of two or more leaves holds at least [`MIN_KEYS`] keys and at most [`KEYS`].
#[derive(Debug, Clone, Copy, Default)]
struct Placing {
    base: u32,
    leaves: u64,
    kept: u64,
    /// `placed` keys have landed; the current leaf `leaf` began at rank `first` and ends before rank `end`.
    placed: u64,
    leaf: u64,
    first: u64,
    end: u64,
}

impl Placing {
    /// The leaf and slot of the next key.
    fn next(&mut self) -> (u32, usize) {
        if self.placed == self.end {
            self.leaf += 1;
            (self.first, self.end) = (self.end, (self.leaf + 1) * self.kept / self.leaves);
        }
        let slot = (self.placed - self.first) as usize;
        self.placed += 1;
        (self.base + self.leaf as u32, slot)
    }
}

#[cfg(test)]
impl ExtentAllocator<'_> {
    /// The indexed keys in key order: the exact trees by length, then tree 0.
    pub(crate) fn index_keys(&self) -> Vec<u64> {
        let mut keys = Vec::new();
        for tree in (1..TREES).chain([0]) {
            let root = self.root.index.roots[tree];
            if root != NONE {
                self.collect(root, self.root.index.heights[tree], &mut keys);
            }
        }
        keys
    }

    /// The most inner levels any tree holds.
    pub(super) fn deepest(&self) -> u64 {
        u64::from(self.root.index.heights.iter().copied().max().unwrap_or(0))
    }

    fn collect(&self, node: u32, height: u8, keys: &mut Vec<u64>) {
        let at = &self.nodes[node as usize];
        if height == 0 {
            keys.extend(at.0.iter().copied().filter(|&key| key != EMPTY));
            return;
        }
        for index in 0..at.children() {
            self.collect(at.child(index), height - 1, keys);
        }
    }

    /// Asserts the index invariants: each tree's key order, separator bounds, fill, height and first leaf, the tree mask and key count, and that every node is in one tree or the spare chain.
    pub(super) fn index_check(&self) {
        let heads = &self.root.index;
        let mut seen = vec![false; self.nodes.len()];
        let mut count = 0;
        for tree in 0..TREES {
            let root = heads.roots[tree];
            assert_eq!(
                heads.mask[tree / 64] >> (tree % 64) & 1 == 1,
                root != NONE,
                "mask bit {tree}"
            );
            if root == NONE {
                assert_eq!(heads.firsts[tree], NONE, "first leaf of empty tree {tree}");
                continue;
            }
            let height = heads.heights[tree];
            assert!(
                u64::from(height) <= index_height(heads.capacity as usize),
                "height of tree {tree}"
            );
            let mut first = root;
            for _ in 0..height {
                first = self.nodes[first as usize].child(0);
            }
            assert_eq!(heads.firsts[tree], first, "first leaf of tree {tree}");
            let keys = self.check_node(tree, root, height, true, (0, EMPTY), &mut seen);
            assert!(keys > 0, "tree {tree} holds a key");
            count += keys;
        }
        assert_eq!(heads.count, count as u64, "key count");
        assert!(heads.count <= heads.capacity, "count within capacity");
        let mut spare = heads.spare;
        while spare != NONE {
            assert!(!seen[spare as usize], "spare node {spare} is free");
            seen[spare as usize] = true;
            assert!(
                self.nodes[spare as usize].0[1..]
                    .iter()
                    .all(|&word| word == EMPTY)
            );
            spare = self.nodes[spare as usize].0[0] as u32;
        }
        assert!(
            seen.iter().all(|&held| held),
            "every node is in a tree or spare"
        );
        let keys = self.index_keys();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]), "key order");
    }

    /// Checks the subtree at `node` of `tree`, `height` inner levels deep, whose keys lie in `range`, and returns its key count.
    fn check_node(
        &self,
        tree: usize,
        node: u32,
        height: u8,
        root: bool,
        range: (u64, u64),
        seen: &mut [bool],
    ) -> usize {
        assert!(!seen[node as usize], "node {node} in one place");
        seen[node as usize] = true;
        let at = &self.nodes[node as usize];
        if height == 0 {
            let len = at.len();
            assert!(
                at.0[..len].iter().all(|&key| key != EMPTY),
                "leaf keys first"
            );
            assert!(root || len >= MIN_KEYS, "leaf fill");
            for pair in at.0[..len].windows(2) {
                assert!(pair[0] < pair[1], "leaf order");
            }
            for &key in &at.0[..len] {
                assert!(
                    range.0 <= key && key < range.1,
                    "key {key:x} inside its separators"
                );
                assert_eq!(tree_of(key), tree, "key {key:x} in its tree");
            }
            return len;
        }
        let children = at.children();
        assert!(
            at.0[..children - 1].iter().all(|&sep| sep != EMPTY),
            "separators first"
        );
        assert!(
            children >= if root { 2 } else { MIN_CHILDREN },
            "inner fill"
        );
        for index in children..CHILDREN {
            assert_eq!(at.child(index), NONE, "unused child link");
        }
        assert_eq!(at.0[15] >> 32, u64::from(NONE), "unused twelfth link");
        let mut keys = 0;
        for index in 0..children {
            let low = if index == 0 { range.0 } else { at.0[index - 1] };
            let high = if index + 1 == children {
                range.1
            } else {
                at.0[index]
            };
            assert!(low < high, "separator order");
            keys += self.check_node(tree, at.child(index), height - 1, false, (low, high), seen);
        }
        keys
    }
}
