use crate::{errors::ErrorCode, state::MarketOutcome};
use anchor_lang::prelude::*;

pub(crate) fn redemption_payout(
    outcome: MarketOutcome,
    yes_shares_atoms: u64,
    no_shares_atoms: u64,
    invalid_remainder: u8,
) -> Result<(u64, u8)> {
    match outcome {
        MarketOutcome::Yes => Ok((yes_shares_atoms, invalid_remainder)),
        MarketOutcome::No => Ok((no_shares_atoms, invalid_remainder)),
        MarketOutcome::Invalid => {
            invalid_payout_with_carry(yes_shares_atoms, no_shares_atoms, invalid_remainder)
        }
        MarketOutcome::Undecided => Ok((0, invalid_remainder)),
    }
}

/// Computes `(yes + no + carry) / 2` and carries the remainder to the next
/// redemption. Since aggregate YES and NO shares are equal, the final carry is
/// zero and every collateral atom is eventually paid.
fn invalid_payout_with_carry(
    yes_shares_atoms: u64,
    no_shares_atoms: u64,
    invalid_remainder: u8,
) -> Result<(u64, u8)> {
    require!(invalid_remainder <= 1, ErrorCode::MathOverflow);
    // The two halves sum to at most u64::MAX - 1; adding the carry below is safe.
    let whole_atoms = yes_shares_atoms / 2 + no_shares_atoms / 2;
    let fractional_numerator =
        (yes_shares_atoms % 2) as u8 + (no_shares_atoms % 2) as u8 + invalid_remainder;
    let payout = whole_atoms + u64::from(fractional_numerator / 2);
    let next_remainder = fractional_numerator % 2;
    Ok((payout, next_remainder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_payout_handles_maximum_share_balances() {
        assert_eq!(
            redemption_payout(MarketOutcome::Invalid, u64::MAX, u64::MAX, 0).unwrap(),
            (u64::MAX, 0)
        );
        assert_eq!(
            redemption_payout(MarketOutcome::Invalid, u64::MAX, u64::MAX - 1, 0).unwrap(),
            (u64::MAX - 1, 1)
        );
    }

    #[test]
    fn invalid_payout_carry_conserves_odd_collateral() {
        let (first_payout, carry) = redemption_payout(MarketOutcome::Invalid, 1, 0, 0).unwrap();
        let (second_payout, carry) =
            redemption_payout(MarketOutcome::Invalid, 0, 1, carry).unwrap();

        assert_eq!(first_payout + second_payout, 1);
        assert_eq!(carry, 0);
    }
}
