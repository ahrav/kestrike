//! A simulated namespace's reservation state with linked attachments that share a host ID, checked through the
//! Report's own-record count.
//!
//! The namespace follows the provider behavior the count must survive: attachments that share a host ID are
//! linked, so the own self Preempt-and-Abort re-registers the alias as a co-holder under the own key, and a
//! controller reset of the alias hides its record from every Report. Every row reads controller ID 65535.

use crate::failover::identity::{Exhid, Key};
use crate::storage::{ReportError, check_own_record};

#[derive(Clone, Copy)]
struct Record {
    attachment: u8,
    host: Exhid,
    key: Key,
    holder: bool,
    hidden: bool,
}

#[derive(Default)]
struct Namespace {
    records: Vec<Record>,
}

impl Namespace {
    fn register(&mut self, attachment: u8, host: Exhid, key: Key) {
        let record = Record {
            attachment,
            host,
            key,
            holder: false,
            hidden: false,
        };
        self.records.push(record);
    }

    fn acquire(&mut self, attachment: u8) {
        if self.records.iter().all(|record| !record.holder)
            && let Some(record) = self
                .records
                .iter_mut()
                .find(|record| record.attachment == attachment)
        {
            record.holder = true;
        }
    }

    /// The self Preempt-and-Abort of `attachment`: every attachment sharing its host ID is re-registered as a
    /// co-holder under the preempting key.
    fn self_preempt(&mut self, attachment: u8) {
        let own = *self
            .records
            .iter()
            .find(|record| record.attachment == attachment)
            .expect("registered");
        for record in self
            .records
            .iter_mut()
            .filter(|record| record.host == own.host)
        {
            (record.key, record.holder, record.hidden) = (own.key, true, false);
        }
    }

    fn reset(&mut self, attachment: u8) {
        for record in self
            .records
            .iter_mut()
            .filter(|record| record.attachment == attachment)
        {
            record.hidden = true;
        }
    }

    /// The extended Report's controller entries for the visible records.
    fn report(&self) -> Vec<u8> {
        let mut entries = Vec::new();
        for record in self.records.iter().filter(|record| !record.hidden) {
            let mut entry = [0; 64];
            entry[..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
            entry[2] = u8::from(record.holder);
            entry[8..16].copy_from_slice(&record.key.encode().to_le_bytes());
            entry[16..32].copy_from_slice(&record.host.bytes());
            entries.extend_from_slice(&entry);
        }
        entries
    }
}

/// The extended Report of the visible records: a type-2 header naming their count, then the controller entries.
fn report_bytes(namespace: &Namespace) -> Vec<u8> {
    let entries = namespace.report();
    let mut bytes = vec![0; 64];
    bytes[4] = 2;
    bytes[5..7].copy_from_slice(&((entries.len() / 64) as u16).to_le_bytes());
    bytes.extend_from_slice(&entries);
    bytes
}

/// Two attachments share the own host ID, and every assertion is on the own-record count of the namespace's
/// Report. With the alias registered, Report #1 refuses with a retiring refusal. After the own self preempt
/// re-registers the alias as a co-holder, the poll Report refuses the same way. A reset of the alias hides its
/// record, and the count of that Report passes. When the alias is hidden at Report #1, the self preempt builds from that parsed Report, re-registers and reveals the alias, and
/// Report #2 refuses.
#[test]
fn alias_host_id_counted() {
    use crate::failover::bounds::Bounds;
    use crate::failover::evidence::{Pair, Registrant};
    use crate::storage::{ReservationLimits, SelfPreempt, parse_extended_report};
    let (host, other) = (Exhid::new([7; 16]).unwrap(), Exhid::new([9; 16]).unwrap());
    let (own_key, alias_key) = (
        Key::decode((4 << 32) | 1).unwrap(),
        Key::decode((3 << 32) | 1).unwrap(),
    );
    let own = Pair {
        exhid: host,
        key: own_key,
    };
    let alias = ReportError::DuplicateOwnHostId { records: 2 };
    let duplicate = Err(alias);
    let mut namespace = Namespace::default();
    namespace.register(1, host, own_key);
    namespace.acquire(1);
    namespace.register(3, other, alias_key);
    assert_eq!(
        check_own_record(&namespace.report(), own),
        Ok(()),
        "a foreign registrant is not an alias"
    );
    namespace.register(2, host, alias_key);
    assert_eq!(
        check_own_record(&namespace.report(), own),
        duplicate,
        "Report #1 with the alias registered"
    );
    assert_eq!(
        alias.refusal(),
        crate::failover::evidence::NotSole::DuplicateOwnRecord
    );

    namespace.self_preempt(1);
    let holders = namespace
        .records
        .iter()
        .filter(|record| record.holder && record.key == own_key)
        .count();
    assert_eq!(
        holders, 2,
        "the preempt re-registers the alias as a co-holder under the own key"
    );
    assert_eq!(
        check_own_record(&namespace.report(), own),
        duplicate,
        "the poll Report with the co-holding alias"
    );
    namespace.reset(2);
    assert_eq!(
        check_own_record(&namespace.report(), own),
        Ok(()),
        "the reset-hidden alias is invisible"
    );

    let mut namespace = Namespace::default();
    namespace.register(1, host, own_key);
    namespace.acquire(1);
    namespace.register(2, host, alias_key);
    namespace.reset(2);
    let first = report_bytes(&namespace);
    assert_eq!(check_own_record(&first[64..], own), Ok(()), "Report #1");
    let limits = ReservationLimits::new(3, 2, 10, 20).unwrap();
    let mut entries = [Registrant {
        cntlid: 0,
        holder: false,
        pair: own,
    }; 3];
    let report = parse_extended_report(&first, limits, 0, &mut entries).unwrap();
    let bounds = Bounds::new(3, 1, 100, 10, 10, 0).unwrap();
    let preempt =
        SelfPreempt::from_report(&report, &bounds, own).expect("Report #1 shows the own holder");
    assert_eq!(preempt.pair(), own);
    namespace.self_preempt(1);
    assert_eq!(
        check_own_record(&namespace.report(), own),
        duplicate,
        "Report #2 after the preempt reveals the alias"
    );
}
