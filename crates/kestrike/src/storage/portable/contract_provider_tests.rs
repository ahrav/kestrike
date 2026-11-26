//! The clock contract's provider identity: the codec's only provider is `SegmentV2`, identity 1, so contract bytes that name any other provider are malformed.

use super::contract::{ClockContract, Malformed};
use super::expiry::NANOS_PER_SECOND;
use super::recovery::{Withheld, recovered_deadline};
use super::recovery_tests::{E, M, PAIR, contract, reading, root};

/// The encoder writes provider identity 1 and those bytes decode to the contract; the same bytes naming provider 2, 256, 257 or 65535 refuse `Provider`, and a recovery under such a root withholds its pair with `ContractMismatch` where the encoder's own bytes recover a deadline.
#[test]
fn a_contract_naming_another_provider_refuses_by_name_and_recovers_no_pair() {
    let local = contract(0);
    let written = root(0);
    assert_eq!(written[6..8], 1u16.to_le_bytes());
    assert_eq!(ClockContract::decode(&written), Ok(local));
    let read = reading(
        E + 4 * NANOS_PER_SECOND,
        E + 4 * NANOS_PER_SECOND + 2_000_000,
    );
    assert!(recovered_deadline(PAIR, &written, &local, &read, Some(M)).is_ok());
    for provider in [2u16, 256, 257, u16::MAX] {
        let mut foreign = written;
        foreign[6..8].copy_from_slice(&provider.to_le_bytes());
        assert_eq!(
            recovered_deadline(PAIR, &foreign, &local, &read, Some(M)),
            Err(Withheld::ContractMismatch),
            "a pair written under provider {provider} recovered a deadline"
        );
        assert_eq!(
            ClockContract::decode(&foreign),
            Err(Malformed::Provider),
            "provider {provider} decoded"
        );
    }
}
