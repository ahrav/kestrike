use super::assignment::{self, Assignment, AssignmentError, Content};
use super::identity::{Generation, Incarnation};
use super::record::{Binding, LocalRecord};

pub(crate) const HOST_KEY: [u8; 32] = [0x42; 32];
pub(crate) fn sample() -> Assignment {
    Assignment {
        id: [3; 16],
        generation: Generation(8),
        issuer: "placement".into(),
        instance: "i-0123456789abcdef0".into(),
        volume: "vol-0123456789abcdef0".into(),
        az: "us-east-1a".into(),
        shard: "shard-1".into(),
        owner: "i-0123456789abcdef0".into(),
        partition: "partition-1".into(),
        color: "blue".into(),
        attachment: "attach-1".into(),
        incarnation: Incarnation::new(2).unwrap(),
        content: Content::Incarnation(9),
        delete_on_termination: Some(false),
        rollout: Generation(4),
    }
}
/// The local record a fresh path writes for [`sample`], with host ID `[9; 16]`.
pub(crate) fn record() -> LocalRecord {
    let a = sample();
    LocalRecord::fresh(
        Binding {
            instance: a.instance,
            volume: a.volume,
            attachment: a.attachment,
        },
        super::identity::Key::attachment(a.incarnation),
        || Some([9; 16]),
    )
    .unwrap()
}
/// A record with another binding, key and host ID than [`record`] at every differing field.
pub(crate) fn other_record() -> LocalRecord {
    LocalRecord::fresh(
        Binding {
            instance: "i-0fffffffffffffff0".into(),
            volume: "vol-0fffffffffffffff0".into(),
            attachment: "attach-2".into(),
        },
        super::identity::Key::decode((6 << 32) | 3).unwrap(),
        || Some([7; 16]),
    )
    .unwrap()
}
/// `a`, signed with [`HOST_KEY`] and verified.
pub(crate) fn verified(a: &Assignment) -> assignment::AuthenticatedAssignment {
    assignment::verify(&a.sign(&HOST_KEY).unwrap(), &HOST_KEY).unwrap()
}

#[test]
fn hmac_matches_rfc_4231_vectors() {
    let mut key = [0; 32];
    key[..20].fill(0x0b);
    assert_eq!(
        assignment::hmac(&key, &[b"Hi There"]),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    key.fill(0);
    key[..4].copy_from_slice(b"Jefe");
    assert_eq!(
        assignment::hmac(&key, &[b"what do ya want ", b"for nothing?"]),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}
fn hex(s: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

// Fixed offsets form an independent parser, separate from the production Reader.
fn independent(b: &[u8]) -> Assignment {
    assert_eq!(b.len(), 658);
    assert_eq!(&b[..4], &[3, 0, 0, 0]);
    let text = |i: usize| {
        let v = &b[4 + 64 * i..4 + 64 * (i + 1)];
        let end = v.iter().position(|x| *x == 0).unwrap();
        assert!(v[end..].iter().all(|x| *x == 0));
        String::from_utf8(v[..end].to_vec()).unwrap()
    };
    let number = |i: usize| u64::from_le_bytes(b[596 + 8 * i..604 + 8 * i].try_into().unwrap());
    let word = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    Assignment {
        issuer: text(0),
        instance: text(1),
        volume: text(2),
        az: text(3),
        shard: text(4),
        owner: text(5),
        partition: text(6),
        color: text(7),
        attachment: text(8),
        id: b[580..596].try_into().unwrap(),
        generation: Generation(number(0)),
        rollout: Generation(number(1)),
        content: match b[624] {
            0 => Content::Incarnation(number(2)),
            1 => {
                assert_eq!(number(2), 0);
                Content::Format
            }
            _ => panic!("content flag"),
        },
        incarnation: Incarnation::new(word(620)).unwrap(),
        delete_on_termination: match b[625] {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => panic!("deletion observation"),
        },
    }
}

#[test]
fn every_field_round_trips_through_an_independent_byte_parser() {
    for (content, deletion) in [
        (Content::Incarnation(9), Some(false)),
        (Content::Format, None),
        (Content::Incarnation(u64::MAX), Some(true)),
    ] {
        let mut a = sample();
        a.content = content;
        a.delete_on_termination = deletion;
        let bytes = a.sign(&HOST_KEY).unwrap();
        assert_eq!(independent(&bytes), a);
        assert_eq!(assignment::verify(&bytes, &HOST_KEY).unwrap().fields(), &a);
        assert_eq!(a.sign(&HOST_KEY).unwrap(), bytes);
    }
}

#[test]
fn length_version_key_and_every_modified_byte_refuse_before_fields() {
    let bytes = sample().sign(&HOST_KEY).unwrap();
    assert_eq!(
        &bytes[626..],
        &hex("cc5666311d9f3dbc2f543599ef6c0f8f93152f04040ce138f6bc4217da1d7ba1")
    );
    for len in 0..bytes.len() {
        assert_eq!(
            assignment::verify(&bytes[..len], &HOST_KEY),
            Err(AssignmentError::Length)
        );
    }
    assert_eq!(
        assignment::verify(&bytes, &[1; 32]),
        Err(AssignmentError::Tag)
    );
    for i in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[i] ^= 1;
        assert_eq!(
            assignment::verify(&changed, &HOST_KEY),
            Err(if i < 4 {
                AssignmentError::Version
            } else {
                AssignmentError::Tag
            }),
            "byte {i}"
        );
    }
    assert_eq!(
        assignment::verify(b"format=3\ninstance=legacy\n", &HOST_KEY),
        Err(AssignmentError::Length)
    );
}

#[test]
fn bounded_and_reserved_assignment_fields_refuse() {
    let mut a = sample();
    a.shard = "x".repeat(64);
    assert_eq!(a.sign(&HOST_KEY), Err(AssignmentError::Field));
    a = sample();
    a.id = [0; 16];
    assert_eq!(a.sign(&HOST_KEY), Err(AssignmentError::Field));
    a = sample();
    a.content = Content::Incarnation(0);
    assert_eq!(a.sign(&HOST_KEY), Err(AssignmentError::Field));
    let bytes = sample().sign(&HOST_KEY).unwrap();
    for (at, value) in [(620, 0), (620, u32::MAX)] {
        let mut b = bytes.clone();
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let tag = assignment::hmac(&HOST_KEY, &[b"ebs-assignment01", &b[..626]]);
        b[626..].copy_from_slice(&tag);
        assert_eq!(
            assignment::verify(&b, &HOST_KEY),
            Err(AssignmentError::Field)
        );
    }
}

#[test]
fn authenticated_noncanonical_padding_flags_counters_and_volume_refuse_fields() {
    let bytes = sample().sign(&HOST_KEY).unwrap();
    for (offset, replacement) in [
        (624, vec![2]),
        (625, vec![3]),
        (596, vec![0; 8]),
        (604, vec![0; 8]),
        (612, vec![0; 8]),
        (624, vec![1]),
        (60, vec![1]),
    ] {
        let mut b = bytes.clone();
        b[offset..offset + replacement.len()].copy_from_slice(&replacement);
        let tag = assignment::hmac(&HOST_KEY, &[b"ebs-assignment01", &b[..626]]);
        b[626..].copy_from_slice(&tag);
        assert_eq!(
            assignment::verify(&b, &HOST_KEY),
            Err(AssignmentError::Field),
            "offset {offset}"
        );
    }
    let mut a = sample();
    a.volume = a.volume.replace("vol-", "vol");
    assert_eq!(a.sign(&HOST_KEY), Err(AssignmentError::Field));
}

/// Assignments, local records and ownership bodies admit the same volume IDs: `vol-` and 1 to 17 lowercase hexadecimal digits. Each case also re-tags the assignment and recomputes the record's crc32c around the name, so a malformed ID reaches the decoder's field checks.
#[test]
fn assignments_records_and_ownership_bodies_admit_the_same_volume_ids() {
    use super::record::{RECORD_BYTES, RecordError};
    use crate::net::Kind;
    use crate::net::ownership::{OwnershipBody, Shard, Validity, Volume, VolumeState};

    const ASSIGNMENT_VOLUME: core::ops::Range<usize> = 132..196;
    const RECORD_VOLUME: core::ops::Range<usize> = 68..132;
    let signed = sample().sign(&HOST_KEY).unwrap();
    let checksummed = record().encode().unwrap();
    for (name, admitted) in [
        ("vol-0", true),
        ("vol-a", true),
        ("vol-0123456789abcdef0", true),
        ("vol-A", false),
        ("vol-0123456789ABCDEF0", false),
        ("vol-0123456789abcdef01", false),
        ("vol-", false),
        ("vol-g", false),
        ("vol0abc", false),
    ] {
        let mut a = sample();
        a.volume = name.into();
        assert_eq!(
            a.sign(&HOST_KEY).is_ok(),
            admitted,
            "signed assignment {name}"
        );
        let mut b = signed.clone();
        b[ASSIGNMENT_VOLUME].fill(0);
        b[ASSIGNMENT_VOLUME.start..][..name.len()].copy_from_slice(name.as_bytes());
        let tag = assignment::hmac(&HOST_KEY, &[b"ebs-assignment01", &b[..626]]);
        b[626..].copy_from_slice(&tag);
        assert_eq!(
            assignment::verify(&b, &HOST_KEY).map(|a| a.fields().volume.clone()),
            if admitted {
                Ok(name.to_owned())
            } else {
                Err(AssignmentError::Field)
            },
            "verified assignment {name}"
        );

        let mut binding = record().binding().clone();
        binding.volume = name.into();
        let r = LocalRecord::fresh(binding, record().pair().key, || Some([9; 16])).unwrap();
        assert_eq!(r.encode().is_ok(), admitted, "encoded record {name}");
        let mut b = checksummed;
        b[RECORD_VOLUME].fill(0);
        b[RECORD_VOLUME.start..][..name.len()].copy_from_slice(name.as_bytes());
        let crc = crate::storage::Crc32c::detect().checksum(&b[..RECORD_BYTES - 4]);
        b[RECORD_BYTES - 4..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            LocalRecord::decode(&b).map(|r| r.binding().volume.clone()),
            if admitted {
                Ok(name.to_owned())
            } else {
                Err(RecordError::Field)
            },
            "decoded record {name}"
        );

        let body = OwnershipBody {
            shard: Shard::new(1).unwrap(),
            volume: Some(Volume {
                name,
                state: VolumeState::Active,
            }),
            tenure: None,
            report_age_us: 0,
            responder: None,
            validity: Validity::new(0).unwrap(),
        };
        let mut out = vec![0; body.encoded_len()];
        assert_eq!(
            body.encode(Kind::WhoHolds, &mut out).is_ok(),
            admitted,
            "ownership body {name}"
        );
    }
}
