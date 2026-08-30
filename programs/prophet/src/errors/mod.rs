use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Market is not open")]
    MarketNotOpen,
    #[msg("Market is not open yet (check open_ts)")]
    MarketNotOpenYet,
    #[msg("Market is locked")]
    MarketLocked,
    #[msg("Order sequence mismatch")]
    InvalidOrderSeq,
    #[msg("Order quantity too small")]
    OrderQtyTooSmall,
    #[msg("Escrow amount too small")]
    EscrowTooSmall,
    #[msg("User open orders limit reached")]
    UserOpenOrdersLimit,
    #[msg("Global open orders limit reached")]
    GlobalOpenOrdersLimit,
    #[msg("Probability must be <= 1e8")]
    InvalidProbability,
    #[msg("Orders do not cross")]
    NoCross,
    #[msg("Invalid side")]
    InvalidSide,
    #[msg("Orders must belong to same market")]
    InvalidMarket,
    #[msg("Math Overflow")]
    MathOverflow,
    #[msg("Self-match not allowed")]
    SelfMatchNotAllowed,
    #[msg("Insufficient Escrow")]
    InsufficientEscrow,
    #[msg("Zero Match Quantity")]
    ZeroMatchQty,
    #[msg("No refunds to claim")]
    NoRefunds,
    #[msg("Invalid market stage for this action")]
    InvalidStage,
    #[msg("Invalid outcome")]
    InvalidOutcome,
    #[msg("Market not resolved")]
    MarketNotResolved,
    #[msg("Market not resolvable yet (check resolve_ts)")]
    MarketNotResolvableYet,
    #[msg("Unauthorized Oracle")]
    UnauthorizedOracle,
    #[msg("Invalid Time Range")]
    InvalidTimeRange,
    #[msg("Missing Ed25519 instruction")]
    MissingEd25519Ix,
    #[msg("Invalid Ed25519 Program ID")]
    InvalidEd25519Program,
    #[msg("Invalid Ed25519 Data")]
    InvalidEd25519Data,
    #[msg("Ed25519 instruction references other instructions")]
    Ed25519IxIndexesNotSelf,
    #[msg("Signature Mismatch")]
    SignatureMismatch,
    #[msg("Message Mismatch")]
    MessageMismatch,
    #[msg("Message Size Mismatch")]
    MessageSizeMismatch,
    #[msg("Signature Verification Failed")]
    SignatureVerificationFailed,
    #[msg("Notary config is not set on this market")]
    NotaryConfigNotSet,
    #[msg("Provided notary config does not match market.notary_config")]
    NotaryConfigMismatch,
    #[msg("Notary set is invalid (empty/too large)")]
    InvalidNotarySet,
    #[msg("Notary threshold is invalid")]
    InvalidNotaryThreshold,
    #[msg("Duplicate key in notary set")]
    DuplicateNotaryKey,
    #[msg("Not enough distinct valid notary signatures")]
    NotEnoughNotarySigs,
    #[msg("Duplicate notary signature pubkey")]
    DuplicateNotarySig,
    #[msg("Notary is not allowed")]
    NotaryNotAllowed,
    #[msg("Unauthorized admin")]
    UnauthorizedAdmin,
    #[msg("Unauthorized market authority")]
    UnauthorizedMarketAuthority,
    #[msg("Market still has open orders")]
    MarketHasOpenOrders,
    #[msg("Locked market cannot be reopened after lock_ts")]
    CannotUnlockAfterLockTs,
    #[msg("Market must be locked for this action")]
    MarketNotLocked,
    #[msg("Invalid new authority")]
    InvalidNewAuthority,
    #[msg("Protocol fee bps is invalid")]
    InvalidProtocolFeeBps,
    #[msg("Market fee config is frozen after the first order")]
    FeeConfigFrozen,
    #[msg("No protocol fees available")]
    NoProtocolFees,
    #[msg("Invalid protocol fee recipient")]
    InvalidFeeRecipient,
    #[msg("Match quantity is too small to settle safely under rounding constraints")]
    MatchQtyTooSmallForRounding,
    #[msg("Market configuration contains an unsafe zero or inconsistent limit")]
    InvalidMarketConfig,
    #[msg("Notary config snapshots are immutable; create a successor snapshot")]
    NotaryConfigImmutable,
    #[msg("Notary config snapshot version is invalid")]
    InvalidNotaryConfigVersion,
    #[msg("Notary config account is not the canonical PDA for its immutable snapshot")]
    InvalidNotaryConfigSnapshot,
    #[msg("Market V2 requires an exact 2-of-2 notary topology")]
    UnsupportedNotaryTopology,
    #[msg("Resolver hash must identify a non-zero resolver definition")]
    InvalidResolverHash,
    #[msg("Settlement proof hash must be non-zero")]
    InvalidProofHash,
    #[msg("Settlement public inputs hash must be non-zero")]
    InvalidPublicInputsHash,
    #[msg("Position has already been redeemed")]
    PositionAlreadyRedeemed,
}
