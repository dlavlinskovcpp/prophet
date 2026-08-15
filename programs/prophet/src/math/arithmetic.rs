use crate::errors::ErrorCode;
use anchor_lang::prelude::*;

/// Computes `(a * b) / denominator`, rounding down. Decomposing `a` avoids
/// software-emulated u128 division on SBF for the bounded protocol ratios.
pub(crate) fn mul_div_floor(a: u64, b: u64, denominator: u64) -> Result<u64> {
    require!(denominator != 0, ErrorCode::MathOverflow);
    let quotient = a / denominator;
    let remainder = a % denominator;
    quotient
        .checked_mul(b)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_add(remainder.checked_mul(b).ok_or(ErrorCode::MathOverflow)? / denominator)
        .ok_or_else(|| ErrorCode::MathOverflow.into())
}

/// Computes `(a * b) / denominator`, rounding up.
pub(crate) fn mul_div_ceil(a: u64, b: u64, denominator: u64) -> Result<u64> {
    require!(denominator != 0, ErrorCode::MathOverflow);
    let quotient = a / denominator;
    let remainder_product = (a % denominator)
        .checked_mul(b)
        .ok_or(ErrorCode::MathOverflow)?;
    let fractional =
        remainder_product / denominator + u64::from(remainder_product % denominator != 0);
    quotient
        .checked_mul(b)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_add(fractional)
        .ok_or_else(|| ErrorCode::MathOverflow.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_results_that_do_not_fit_in_u64() {
        assert!(mul_div_floor(u64::MAX, 2, 1).is_err());
        assert!(mul_div_ceil(u64::MAX, 2, 1).is_err());
        assert!(mul_div_floor(1, 1, 0).is_err());
        assert!(mul_div_ceil(1, 1, 0).is_err());
    }

    #[test]
    fn u64_decomposition_matches_u128_reference_for_protocol_ratios() {
        for denominator in [1_u64, 10_000, 100_000_000] {
            for amount in [
                0_u64,
                1,
                denominator.saturating_sub(1),
                denominator,
                denominator.saturating_add(1),
                u64::MAX,
            ] {
                for multiplier in [0_u64, 1, denominator / 2, denominator] {
                    let numerator = u128::from(amount) * u128::from(multiplier);
                    let floor_reference = (numerator / u128::from(denominator)) as u64;
                    let ceil_reference = if numerator == 0 {
                        0
                    } else {
                        ((numerator + u128::from(denominator) - 1) / u128::from(denominator)) as u64
                    };

                    assert_eq!(
                        mul_div_floor(amount, multiplier, denominator).unwrap(),
                        floor_reference
                    );
                    assert_eq!(
                        mul_div_ceil(amount, multiplier, denominator).unwrap(),
                        ceil_reference
                    );
                }
            }
        }
    }
}
