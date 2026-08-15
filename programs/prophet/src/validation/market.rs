use crate::{
    errors::ErrorCode,
    state::{Market, MarketStatus},
};
use anchor_lang::prelude::*;

/// Shared trading-window validation. The check order intentionally matches the
/// original handlers so callers receive the same error for overlapping faults.
pub(crate) fn require_market_open_for_trading(market: &Market, now: i64) -> Result<()> {
    require!(
        market.status == MarketStatus::Open,
        ErrorCode::MarketNotOpen
    );
    require!(now >= market.open_ts, ErrorCode::MarketNotOpenYet);
    require!(now < market.lock_ts, ErrorCode::MarketLocked);
    Ok(())
}

pub(crate) fn validate_market_configuration(
    min_order_qty_atoms: u64,
    min_escrow_atoms: u64,
    max_open_orders_per_user: u16,
    max_open_orders_total: u32,
) -> Result<()> {
    require!(min_order_qty_atoms > 0, ErrorCode::InvalidMarketConfig);
    require!(min_escrow_atoms > 0, ErrorCode::InvalidMarketConfig);
    require!(max_open_orders_per_user > 0, ErrorCode::InvalidMarketConfig);
    require!(max_open_orders_total > 0, ErrorCode::InvalidMarketConfig);
    require!(
        u32::from(max_open_orders_per_user) <= max_open_orders_total,
        ErrorCode::InvalidMarketConfig
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_and_inconsistent_order_limits() {
        assert!(validate_market_configuration(0, 1, 1, 1).is_err());
        assert!(validate_market_configuration(1, 0, 1, 1).is_err());
        assert!(validate_market_configuration(1, 1, 0, 1).is_err());
        assert!(validate_market_configuration(1, 1, 1, 0).is_err());
        assert!(validate_market_configuration(1, 1, 2, 1).is_err());
        assert!(validate_market_configuration(1, 1, 1, 1).is_ok());
    }
}
