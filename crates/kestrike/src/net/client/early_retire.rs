//! A broken retire for negative controls: [`Client::retire_once_known`] frees an upload's request as soon as its
//! outcome is known, without waiting for the device to return the source slots the upload still holds. The production
//! [`Client::retire`] closes an upload through `UploadCore::close`, which releases the request only once the outcome is
//! known and no source slot is still held. Record `put-then-independent-get-native-schedule` excludes exactly this
//! defect: a PUT's retire that does not wait for its late device returns.
//!
//! The GET arm is [`Client::retire`]'s `self.fetch.close(&mut self.requests, id)`. The upload arm skips
//! `UploadCore::close` and releases the request directly once `Client::put_outcome` is known.

use super::super::Datagrams;
use super::super::requests::RequestId;
use super::Client;

impl<'m, D: Datagrams<'m>> Client<'m, D> {
    /// Retires request `id` as [`Client::retire`] does, except that a decided upload's request is released while the
    /// device may still hold its source slots.
    pub(in crate::net) fn retire_once_known(&mut self, id: RequestId) -> bool {
        self.fetch.close(&mut self.requests, id)
            || (self.put_outcome(id).is_some() && self.requests.release(id))
    }
}
