use crate::state::{Market, MarketOutcome, NotaryConfig};
use anchor_lang::prelude::*;

const RESOLUTION_DOMAIN_V2: &[u8] = b"PROPHET_RESOLVE_V2";
pub(crate) const RESOLUTION_MESSAGE_V2_LEN: usize = 235;

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolution_message_v2(
    program_id: &Pubkey,
    market_key: &Pubkey,
    market: &Market,
    config_key: &Pubkey,
    config: &NotaryConfig,
    outcome: MarketOutcome,
    proof_hash: &[u8; 32],
    public_inputs_hash: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RESOLUTION_MESSAGE_V2_LEN);
    message.extend_from_slice(RESOLUTION_DOMAIN_V2);
    message.extend_from_slice(program_id.as_ref());
    message.extend_from_slice(market_key.as_ref());
    message.extend_from_slice(config_key.as_ref());
    message.extend_from_slice(&market.resolver_hash);
    message.extend_from_slice(&market.open_ts.to_le_bytes());
    message.extend_from_slice(&market.resolve_ts.to_le_bytes());
    message.extend_from_slice(&config.version.to_le_bytes());
    message.push(outcome_byte(outcome));
    message.extend_from_slice(proof_hash);
    message.extend_from_slice(public_inputs_hash);
    message
}

fn outcome_byte(outcome: MarketOutcome) -> u8 {
    match outcome {
        MarketOutcome::Yes => 1,
        MarketOutcome::No => 2,
        MarketOutcome::Invalid => 3,
        MarketOutcome::Undecided => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{MarketStatus, MAX_NOTARIES};

    #[test]
    fn legacy_resolution_message_layout_is_byte_for_byte_stable() {
        let program = Pubkey::new_from_array([1; 32]);
        let market_key = Pubkey::new_from_array([2; 32]);
        let config_key = Pubkey::new_from_array([3; 32]);
        let market = Market {
            authority: Pubkey::default(),
            oracle_authority: Pubkey::default(),
            quote_mint: Pubkey::default(),
            quote_vault: Pubkey::default(),
            fee_recipient: Pubkey::default(),
            notary_config: config_key,
            resolver_hash: [4; 32],
            proof_hash: [0; 32],
            public_inputs_hash: [0; 32],
            open_ts: -7,
            lock_ts: 0,
            resolve_ts: 42,
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
            threshold: 1,
            notary_count: 1,
            bump: 0,
            _reserved0: [0; 5],
            version: 9,
            notary_keys: [Pubkey::default(); MAX_NOTARIES],
        };
        let actual = resolution_message_v2(
            &program,
            &market_key,
            &market,
            &config_key,
            &config,
            MarketOutcome::Invalid,
            &[5; 32],
            &[6; 32],
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(b"PROPHET_RESOLVE_V2");
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&[4; 32]);
        expected.extend_from_slice(&(-7_i64).to_le_bytes());
        expected.extend_from_slice(&42_i64.to_le_bytes());
        expected.extend_from_slice(&9_u64.to_le_bytes());
        expected.push(3);
        expected.extend_from_slice(&[5; 32]);
        expected.extend_from_slice(&[6; 32]);
        assert_eq!(actual.len(), RESOLUTION_MESSAGE_V2_LEN);
        assert_eq!(actual, expected);
    }
}
