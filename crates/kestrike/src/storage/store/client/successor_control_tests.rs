//! A broken variant of [`Client::replace`] for the negative control of the manifest successor rule.

use super::{Client, Read, Store, StoreError, Tracked, WatermarkLog};

impl<S: Store, L: WatermarkLog> Client<S, L> {
    /// Writes `next` over `read` by an exact-version compare-and-swap whatever successor rule `next` breaks.
    pub(crate) fn replace_without_successor_rule<R: Tracked>(
        &mut self,
        read: &Read<R>,
        next: R,
    ) -> Result<Read<R>, StoreError> {
        let written = self.admit().and_then(|()| self.exact_one(read, next));
        self.settle_one(written)
    }
}
