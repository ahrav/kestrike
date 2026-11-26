//! The record target's claim mode: the input's raw tail after its mode
//! byte, handed to `claim_header` under each chunk length of
//! [`CHUNK_LENS`] and judged against the literal parser's claim. A refusal
//! both name with the same fields is a pass, so malformed headers stay in
//! the corpus. The fuzz lanes cap a record input at 258 bytes, so a lane's
//! tail holds at most 256 header bytes.

use super::HeaderMismatch;
use super::fuzz_tests::{
    Claim, FIXED, FORMAT, apply, claimed, claimed_payload, disagree, fixed_fields, header_len,
    literal_claim,
};
use super::geometry_fuzz_tests::{CHUNK_LENS, Geometry};
use crate::sim::fuzz::Class;

/// `claim_header` on `bytes` against the literal parser's claim under
/// `chunk_len`-byte windows: the verdict both name, or the failure that
/// names their disagreement.
pub(crate) fn judge_claim(
    bytes: &[u8],
    chunk_len: u32,
) -> Result<Result<Claim, HeaderMismatch>, Class> {
    let (ours, theirs) = (claimed(bytes, chunk_len), literal_claim(bytes, chunk_len));
    if ours != theirs {
        return Err(disagree(
            &format!("claim_header under {chunk_len}-byte chunks"),
            &ours,
            &theirs,
        ));
    }
    Ok(ours)
}

/// The claim mode runs `claim_header` on `header`, the input's raw tail,
/// under each chunk length of [`CHUNK_LENS`] and judges it against the
/// literal parser's claim. A pass's run is the tail through the longest
/// header its fixed fields derive, or the whole tail when it ends sooner.
pub(crate) fn claim_mode(header: &[u8]) -> Class {
    for chunk_len in CHUNK_LENS {
        if let Err(failure) = judge_claim(header, chunk_len) {
            return failure;
        }
    }
    Class::Pass {
        run: header[..judged_len(header)].to_vec(),
    }
}

fn judged_len(header: &[u8]) -> usize {
    let payload = claimed_payload(&fixed_fields(header));
    let derived = CHUNK_LENS
        .iter()
        .map(|&chunk_len| header_len(payload, chunk_len))
        .max()
        .unwrap_or(FIXED as u64);
    usize::try_from(derived).map_or(header.len(), |derived| derived.min(header.len()))
}

/// Seeds of the claim mode: a valid header and headers, raw or resealed,
/// that reach each claim refusal, each cut to at most 256 bytes.
pub(crate) fn seeds() -> Vec<(String, Vec<u8>)> {
    let (_, valid) = Geometry::of(0b0010_0100).record(0);
    let header = |ops: &[u8], reseal: bool| {
        let bytes = apply(valid.clone(), reseal, ops, 4096).expect("ops within the bound");
        bytes[..bytes.len().min(256)].to_vec()
    };
    let claims: [(&str, &[u8], bool); 10] = [
        ("valid", &[], false),
        ("truncated", &[4, 0, 20, 0], false),
        ("derived-truncation", &[4, 0, 37, 0], false),
        ("magic", &[7, 0, 1, 0], false),
        ("version", &[0, 8, 1, 0], true),
        ("lengths", &[1, 6, 9, 1], true),
        ("extent-length", &[1, 7, 1, 0], true),
        ("chunk-parameters", &[1, 4, 1, 0], true),
        ("header-crc", &[5, 0, 4, 1], false),
        ("context-crc", &[1, 8, 1, 0], true),
    ];
    claims
        .iter()
        .map(|&(name, ops, reseal)| {
            let mut input = vec![FORMAT, 2];
            input.extend(header(ops, reseal));
            (format!("ib-record-claims-{name}-2.input"), input)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Witnesses that the claim mode reaches a valid claim and each claim
    //! refusal, with `claim_header` agreeing with the literal parser.

    use super::*;

    /// The claim mode reaches a valid claim and every claim refusal:
    /// truncation inside the fixed fields, magic, version, lengths,
    /// verified length, chunk parameters, truncation inside the derived
    /// header, header crc and context crc. `claim_header` names each rung
    /// under 4096-byte chunks and agrees with the literal parser under
    /// each chunk length of [`CHUNK_LENS`].
    #[test]
    fn ib_record_claims_reach_each_rejection_rung() {
        let wanted = [
            ("valid", None),
            ("truncated", Some("Truncated { len: 60, needed: 108 }")),
            (
                "derived-truncation",
                Some("Truncated { len: 111, needed: 116 }"),
            ),
            ("magic", Some("Magic")),
            ("version", Some("Version")),
            ("lengths", Some("Lengths")),
            ("extent-length", Some("ExtentLength")),
            ("chunk-parameters", Some("ChunkParameters")),
            ("header-crc", Some("HeaderCrc")),
            ("context-crc", Some("ContextCrc")),
        ];
        let seeds = seeds();
        for (name, rung) in wanted {
            let (_, input) = seeds
                .iter()
                .find(|(seed, _)| *seed == format!("ib-record-claims-{name}-2.input"))
                .expect("a claim seed");
            let header = &input[2..];
            assert!(matches!(claim_mode(header), Class::Pass { .. }), "{name}");
            let said = format!("{:?}", claimed(header, 4096));
            match rung {
                None => assert!(said.starts_with("Ok("), "{name}: {said}"),
                Some(rung) => assert!(said.starts_with(&format!("Err({rung}")), "{name}: {said}"),
            }
        }
    }

    /// Lengths of `u32::MAX` declare an object past the 512 MiB limit: the
    /// claim refuses them at the lengths under every chunk length, as the
    /// literal parser does.
    #[test]
    fn a_maximal_claim_refuses_at_its_lengths() {
        let (_, mut record) = Geometry::of(0).record(0);
        record.truncate(256);
        record[72..80].fill(0xff);
        for chunk_len in CHUNK_LENS {
            assert_eq!(
                claimed(&record, chunk_len),
                Err(HeaderMismatch::Lengths {
                    metadata_len: u32::MAX,
                    body_len: u32::MAX
                })
            );
        }
        assert!(matches!(claim_mode(&record), Class::Pass { .. }));
    }

    #[test]
    fn a_claim_run_ends_at_the_header_the_claim_judges() {
        let seeds = seeds();
        let (_, valid) = seeds
            .iter()
            .find(|(name, _)| name == "ib-record-claims-valid-2.input")
            .expect("the valid claim seed");
        let tail = &valid[2..];
        let header = claimed(tail, CHUNK_LENS[0]).expect("a valid claim").header;
        assert!(header < tail.len(), "the valid seed ends at its header");
        assert_eq!(
            claim_mode(tail),
            Class::Pass {
                run: tail[..header].to_vec()
            }
        );
        for (name, input) in &seeds {
            let tail = &input[2..];
            let Class::Pass { run } = claim_mode(tail) else {
                panic!("{name} did not pass");
            };
            assert!(tail.starts_with(&run), "{name}");
            for at in run.len()..tail.len() {
                let mut changed = tail.to_vec();
                changed[at] ^= 0xff;
                assert_eq!(
                    claim_mode(&changed),
                    Class::Pass { run: run.clone() },
                    "{name} at {at}"
                );
            }
            let mut changed = tail.to_vec();
            changed[run.len() - 1] ^= 0xff;
            assert!(
                matches!(claim_mode(&changed), Class::Pass { run: other } if other != run),
                "{name}"
            );
        }
    }
}
