use crate::state::{Market, MarketOutcome, NotaryConfig};
use anchor_lang::prelude::*;

const RESOLUTION_DOMAIN_V2: &[u8] = b"PROPHET_RESOLVE_V2";
pub(crate) const RESOLUTION_MESSAGE_V2_LEN: usize = 235;

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
