use crate::state::Market;

pub(crate) fn market_signer_open_ts_bytes(market: &Market) -> [u8; 8] {
    market.open_ts.to_le_bytes()
}
