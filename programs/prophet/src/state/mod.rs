mod constants;
mod enums;
mod market;
mod notary_config;
mod order;
mod position;

pub use constants::*;
pub use enums::*;
pub use market::*;
pub use notary_config::*;
pub use order::*;
pub use position::*;

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;

    #[test]
    fn account_allocations_cover_serialized_state() {
        let market = Market {
            authority: Pubkey::default(),
            oracle_authority: Pubkey::default(),
            quote_mint: Pubkey::default(),
            quote_vault: Pubkey::default(),
            fee_recipient: Pubkey::default(),
            notary_config: Pubkey::default(),
            resolver_hash: [0; 32],
            proof_hash: [0; 32],
            public_inputs_hash: [0; 32],
            open_ts: 0,
            lock_ts: 0,
            resolve_ts: 0,
            resolved_ts: 0,
            min_order_qty_atoms: 0,
            min_escrow_atoms: 0,
            accrued_protocol_fees_atoms: 0,
            next_order_seq: 0,
            open_orders_total: 0,
            max_open_orders_total: 0,
            max_open_orders_per_user: 0,
            protocol_fee_bps: 0,
            _reserved0: [0; 6],
            quote_decimals: 0,
            status: MarketStatus::Open,
            outcome: MarketOutcome::Undecided,
            bump: 0,
            invalid_payout_remainder: 0,
        };
        let config = NotaryConfig {
            admin: Pubkey::default(),
            threshold: 0,
            notary_count: 0,
            bump: 0,
            _reserved0: [0; 5],
            version: 0,
            notary_keys: [Pubkey::default(); MAX_NOTARIES],
        };
        let order = Order {
            market: Pubkey::default(),
            owner: Pubkey::default(),
            side: OrderSide::BuyYes,
            seq: 0,
            limit_p_yes_e8: 0,
            qty_remaining_atoms: 0,
            escrow_remaining_atoms: 0,
            fee_remaining_atoms: 0,
            created_ts: 0,
            taker_cost_basis_atoms: 0,
            protocol_fee_paid_atoms: 0,
        };
        let position = Position {
            market: Pubkey::default(),
            owner: Pubkey::default(),
            yes_shares_atoms: 0,
            no_shares_atoms: 0,
            pending_refunds_atoms: 0,
            open_orders: 0,
            redeemed: false,
        };

        assert!(borsh::to_vec(&market).unwrap().len() <= Market::LEN);
        assert!(borsh::to_vec(&config).unwrap().len() <= NotaryConfig::LEN);
        assert!(borsh::to_vec(&order).unwrap().len() <= Order::LEN);
        assert!(borsh::to_vec(&position).unwrap().len() <= Position::LEN);
    }
}
