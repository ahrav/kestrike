//! Records through the store: the typed writer and reader of record files.
//! [`Store::create_record`] writes a record's canonical bytes once, and
//! [`Store::read_record`] and [`View::read_record`] return a [`Verified`]
//! record only when the file passes the read rule, so every verified
//! record came from a bounded read of canonical, checksummed bytes beneath
//! a directory the running user owns with mode 0700.

use super::codec::{Held, decode, encode};
use super::kind::Record;
use crate::store::{Creation, Dir, Error, Name, Read, Store, Unreadable, View};

pub const BOUND: u64 = 1 << 20;

/// A record that passed the read rule, with the read it came from. The
/// read gives [`Store::barrier`] the file and directory to make durable
/// before a record that depends on this one is published. A verified
/// record holds the file's descriptor, a directory descriptor and the
/// file's bytes until it is dropped, so a caller keeps verified records
/// only for the records the current step depends on.
///
/// ```
/// use campaign_supervisor::record::{Job, Verified};
/// use campaign_supervisor::store::Read;
/// fn parts(verified: &Verified<Job>) -> (&Job, &Read) {
///     (verified.record(), verified.read())
/// }
/// ```
///
/// A verified record proves the read rule for bytes read through
/// [`Store::read_record`] or [`View::read_record`]. Directory-lock ownership
/// belongs to the reader's handle.
///
/// ```compile_fail,E0277
/// use campaign_supervisor::record::{Job, Verified};
/// let verified: Verified<Job> = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail,E0614
/// // A verified record has no mutable access to its record.
/// use campaign_supervisor::record::{Job, Verified};
/// fn forge(verified: &mut Verified<Job>) -> &mut Job {
///     &mut **verified
/// }
/// ```
///
/// ```compile_fail,E0451
/// // Its fields are private, so a read and a record make no verified one.
/// use campaign_supervisor::record::{Job, Verified};
/// fn forge(record: Job, read: campaign_supervisor::store::Read) -> Verified<Job> {
///     Verified { record, read }
/// }
/// ```
///
/// ```compile_fail,E0616
/// fn forge(verified: campaign_supervisor::record::Verified<campaign_supervisor::record::Job>) {
///     let _ = verified.record;
/// }
/// ```
///
/// ```compile_fail,E0277
/// use campaign_supervisor::record::{Job, Verified};
/// let verified: Verified<Job> = Default::default();
/// ```
///
/// ```compile_fail,E0277
/// use campaign_supervisor::record::{Job, Verified};
/// fn convert(job: Job) -> Verified<Job> {
///     job.into()
/// }
/// ```
#[derive(Debug)]
pub struct Verified<R: Record> {
    record: R,
    read: Read,
}

impl<R: Record> Verified<R> {
    pub fn record(&self) -> &R {
        &self.record
    }

    pub fn read(&self) -> &Read {
        &self.read
    }

    pub(crate) fn into_record(self) -> R {
        self.record
    }
}

impl Store {
    pub fn replace_record<R: Record>(
        &self,
        dir: &Dir,
        name: &Name,
        record: &R,
    ) -> Result<(), Error> {
        self.writable(dir)?;
        let bytes = publication_bytes(record)?;
        self.replace(dir, name, &bytes)
    }

    /// Publishes `record` as the new file `name` in `dir` unless an entry
    /// has that name, as [`Store::create_once`] does. An existing entry,
    /// a held one included, keeps its bytes.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn create_record<R: Record>(
        &self,
        dir: &Dir,
        name: &Name,
        record: &R,
    ) -> Result<Creation, Error> {
        self.writable(dir)?;
        let bytes = publication_bytes(record)?;
        self.create_once(dir, name, &bytes)
    }

    pub(crate) fn create_record_if<R: Record>(
        &self,
        dir: &Dir,
        name: &Name,
        record: &R,
        commit: impl FnOnce() -> bool,
    ) -> Result<Option<Creation>, Error> {
        self.writable(dir)?;
        self.create_once_if(dir, name, &publication_bytes(record)?, commit)
    }

    /// The record file `name` in `dir` as a verified `R`; `None` when no
    /// entry has the name.
    ///
    /// # Errors
    ///
    /// The [`Held`] code of the first step of the read rule the file fails.
    ///
    /// # Panics
    ///
    /// When `dir` lies under another state directory.
    pub fn read_record<R: Record>(
        &self,
        dir: &Dir,
        name: &Name,
    ) -> Result<Option<Verified<R>>, Held> {
        verified(self.read(dir, name, R::BOUND))
    }
}

impl View {
    /// The record file `name` beneath `dir` as a verified `R`, under the
    /// read rule [`Store::read_record`] applies; `None` when no entry has
    /// the name.
    ///
    /// # Errors
    ///
    /// As [`Store::read_record`].
    ///
    /// # Panics
    ///
    /// When `dir` lies under another view.
    pub fn read_record<R: Record>(
        &self,
        dir: &Dir,
        name: &Name,
    ) -> Result<Option<Verified<R>>, Held> {
        verified(self.read(dir, name, R::BOUND))
    }
}

fn publication_bytes<R: Record>(record: &R) -> Result<Vec<u8>, Error> {
    let bytes = encode(record);
    if bytes.len() as u64 > R::BOUND {
        return Err(Error::Oversize);
    }
    if bytes.len() as u64 > crate::sys::controller_file_limit()? {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "controller record exceeds RLIMIT_FSIZE",
        )));
    }
    Ok(bytes)
}

/// The record `read` holds as a verified `R`, under the read rule.
fn verified<R: Record>(
    read: Result<Option<Read>, Unreadable>,
) -> Result<Option<Verified<R>>, Held> {
    let Some(read) = read.map_err(Held::Unreadable)? else {
        return Ok(None);
    };
    let record = decode(read.bytes())?;
    Ok(Some(Verified { record, read }))
}
