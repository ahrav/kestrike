//! One table serves every operation the owner runs, and one row type retains every operation's outcomes.
//!
//! Each record and each row belongs to exactly one operation, which [`Operated`] reports to the namespace's routing. [`Requests::serve`] and its siblings return the GET state of a GET record.

use std::convert::Infallible;

use super::namespace::{Namespace, Operated, Operation};
use super::put::PutRow;
use super::requests::RequestId;
use super::serve::{GetRow, Serve};

#[expect(
    clippy::large_enum_variant,
    reason = "each table slot stores its record inline, which keeps admission allocation-free"
)]
#[cfg_attr(test, derive(Clone, Debug))]
pub enum Request<C, F = Infallible> {
    Get(Serve<C>),
    Put(F),
}

impl<C, F> Operated for Request<C, F> {
    fn operation(&self) -> Operation {
        match self {
            Self::Get(_) => Operation::Get,
            Self::Put(_) => Operation::Put,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Outcome {
    Get(GetRow),
    Put(PutRow),
}

impl Operated for Outcome {
    fn operation(&self) -> Operation {
        match self {
            Self::Get(_) => Operation::Get,
            Self::Put(_) => Operation::Put,
        }
    }
}

pub type Requests<C, F = Infallible> = Namespace<Request<C, F>, Outcome>;

impl<C, F> Requests<C, F> {
    #[inline]
    pub(super) fn serve(&self, id: RequestId) -> Option<&Serve<C>> {
        match self.table().get(id)? {
            Request::Get(serve) => Some(serve),
            Request::Put(_) => None,
        }
    }

    #[inline]
    pub(super) fn serve_mut(&mut self, id: RequestId) -> Option<&mut Serve<C>> {
        match self.record_mut(id)? {
            Request::Get(serve) => Some(serve),
            Request::Put(_) => None,
        }
    }

    #[inline]
    pub(super) fn live_serve(&mut self, slot: u32) -> Option<(RequestId, &mut Serve<C>)> {
        match self.live_mut(slot)? {
            (id, Request::Get(serve)) => Some((id, serve)),
            (_, Request::Put(_)) => None,
        }
    }

    pub(super) fn put_mut(&mut self, id: RequestId) -> Option<&mut F> {
        match self.record_mut(id)? {
            Request::Put(put) => Some(put),
            Request::Get(_) => None,
        }
    }

    pub(super) fn live_put(&mut self, slot: u32) -> Option<(RequestId, &mut F)> {
        match self.live_mut(slot)? {
            (id, Request::Put(put)) => Some((id, put)),
            (_, Request::Get(_)) => None,
        }
    }
}
