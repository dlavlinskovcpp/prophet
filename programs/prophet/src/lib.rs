// programs/prophet/src/lib.rs
use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_instruction_at_checked, ID as INSTRUCTIONS_ID,
};
use anchor_lang::solana_program::ed25519_program::ID as ED25519_ID_NATIVE;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use anchor_spl::associated_token::AssociatedToken;
use crate::state::*;
use crate::errors::ErrorCode;
use crate::events::*;

pub mod state;
pub mod errors;
pub mod events;

declare_id!("913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A");

#[program]
pub mod prophet {
    use super::*;

    // -------------------------------------------------------------------------
    // 1. Initialize Market (Legacy)
    // -------------------------------------------------------------------------
    pub fn initialize_market(
        ctx: Context<InitializeMarket>,
        resolver_hash: [u8; 32],
        open_ts: i64,
        lock_ts: i64,
        resolve_ts: i64,
        min_order_qty_atoms: u64,
        min_escrow_atoms: u64,
        max_open_orders_per_user: u16,
        max_open_orders_total: u32,
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;

        require!(lock_ts >= open_ts, ErrorCode::InvalidTimeRange);
        require!(resolve_ts >= lock_ts, ErrorCode::InvalidTimeRange);

        market.authority = ctx.accounts.authority.key();
        market.oracle_authority = ctx.accounts.oracle_authority.key();
        market.quote_mint = ctx.accounts.quote_mint.key();
        market.quote_vault = ctx.accounts.quote_vault.key();
        market.quote_decimals = ctx.accounts.quote_mint.decimals;

        // Threshold oracle config not bound in legacy init
        market.notary_config = Pubkey::default();

        market.resolver_hash = resolver_hash;
        market.proof_hash = [0; 32];
        market.public_inputs_hash = [0; 32];

        market.open_ts = open_ts;
        market.lock_ts = lock_ts;
        market.resolve_ts = resolve_ts;
        market.resolved_ts = 0;

        market.min_order_qty_atoms = min_order_qty_atoms;
        market.min_escrow_atoms = min_escrow_atoms;
        market.max_open_orders_per_user = max_open_orders_per_user;
        market.max_open_orders_total = max_open_orders_total;

        market.next_order_seq = 0;
        market.open_orders_total = 0;

        market.status = MarketStatus::Open;
        market.outcome = MarketOutcome::Undecided;

        market.bump = ctx.bumps.market;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.1 Initialize Notary Config (Threshold Oracle Set)
    // -------------------------------------------------------------------------
    pub fn initialize_notary_config(
        ctx: Context<InitializeNotaryConfig>,
        threshold: u8,
        notary_keys: Vec<Pubkey>,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.notary_config;

        require!(!notary_keys.is_empty(), ErrorCode::InvalidNotarySet);
        require!(notary_keys.len() <= MAX_NOTARIES, ErrorCode::InvalidNotarySet);
        require!(threshold > 0, ErrorCode::InvalidNotaryThreshold);
        require!((threshold as usize) <= notary_keys.len(), ErrorCode::InvalidNotaryThreshold);

        // Ensure unique keys
        for i in 0..notary_keys.len() {
            for j in (i + 1)..notary_keys.len() {
                require!(notary_keys[i] != notary_keys[j], ErrorCode::DuplicateNotaryKey);
            }
        }

        cfg.admin = ctx.accounts.admin.key();
        cfg.threshold = threshold;
        cfg.notary_count = notary_keys.len() as u8;
        cfg.version = 1;
        cfg.bump = ctx.bumps.notary_config;

        // Fill fixed array
        cfg.notary_keys = [Pubkey::default(); MAX_NOTARIES];
        for (i, pk) in notary_keys.iter().enumerate() {
            cfg.notary_keys[i] = *pk;
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.2 Update Notary Config
    // -------------------------------------------------------------------------
    pub fn update_notary_config(
        ctx: Context<UpdateNotaryConfig>,
        threshold: u8,
        notary_keys: Vec<Pubkey>,
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.notary_config;

        require!(ctx.accounts.admin.key() == cfg.admin, ErrorCode::UnauthorizedAdmin);

        require!(!notary_keys.is_empty(), ErrorCode::InvalidNotarySet);
        require!(notary_keys.len() <= MAX_NOTARIES, ErrorCode::InvalidNotarySet);
        require!(threshold > 0, ErrorCode::InvalidNotaryThreshold);
        require!((threshold as usize) <= notary_keys.len(), ErrorCode::InvalidNotaryThreshold);

        for i in 0..notary_keys.len() {
            for j in (i + 1)..notary_keys.len() {
                require!(notary_keys[i] != notary_keys[j], ErrorCode::DuplicateNotaryKey);
            }
        }

        cfg.threshold = threshold;
        cfg.notary_count = notary_keys.len() as u8;
        cfg.version = cfg.version.checked_add(1).ok_or(ErrorCode::MathOverflow)?;

        cfg.notary_keys = [Pubkey::default(); MAX_NOTARIES];
        for (i, pk) in notary_keys.iter().enumerate() {
            cfg.notary_keys[i] = *pk;
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.3 Initialize Market v2 (bind NotaryConfig for threshold resolution)
    // -------------------------------------------------------------------------
    pub fn initialize_market_v2(
        ctx: Context<InitializeMarketV2>,
        resolver_hash: [u8; 32],
        open_ts: i64,
        lock_ts: i64,
        resolve_ts: i64,
        min_order_qty_atoms: u64,
        min_escrow_atoms: u64,
        max_open_orders_per_user: u16,
        max_open_orders_total: u32,
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;

        require!(lock_ts >= open_ts, ErrorCode::InvalidTimeRange);
        require!(resolve_ts >= lock_ts, ErrorCode::InvalidTimeRange);

        market.authority = ctx.accounts.authority.key();
        // legacy field retained for backward compatibility; unused in threshold flow
        market.oracle_authority = ctx.accounts.oracle_authority.key();

        market.quote_mint = ctx.accounts.quote_mint.key();
        market.quote_vault = ctx.accounts.quote_vault.key();
        market.quote_decimals = ctx.accounts.quote_mint.decimals;

        market.notary_config = ctx.accounts.notary_config.key();

        market.resolver_hash = resolver_hash;
        market.proof_hash = [0; 32];
        market.public_inputs_hash = [0; 32];

        market.open_ts = open_ts;
        market.lock_ts = lock_ts;
        market.resolve_ts = resolve_ts;
        market.resolved_ts = 0;

        market.min_order_qty_atoms = min_order_qty_atoms;
        market.min_escrow_atoms = min_escrow_atoms;
        market.max_open_orders_per_user = max_open_orders_per_user;
        market.max_open_orders_total = max_open_orders_total;

        market.next_order_seq = 0;
        market.open_orders_total = 0;

        market.status = MarketStatus::Open;
        market.outcome = MarketOutcome::Undecided;

        market.bump = ctx.bumps.market;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.4 Transfer Market Authority
    // -------------------------------------------------------------------------
    pub fn transfer_market_authority(
        ctx: Context<UpdateMarketAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        require_market_authority(market, &ctx.accounts.authority.key())?;
        require!(new_authority != Pubkey::default(), ErrorCode::InvalidNewAuthority);
        require!(new_authority != market.authority, ErrorCode::InvalidNewAuthority);

        let old_authority = market.authority;
        market.authority = new_authority;

        emit!(MarketAuthorityTransferred {
            market: market.key(),
            old_authority,
            new_authority,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.5 Lock Market
    // -------------------------------------------------------------------------
    pub fn lock_market(ctx: Context<UpdateMarketAuthority>) -> Result<()> {
        let market = &mut ctx.accounts.market;
        require_market_authority(market, &ctx.accounts.authority.key())?;
        require!(market.status != MarketStatus::Resolved, ErrorCode::InvalidStage);

        let old_status = market.status;
        if old_status != MarketStatus::Locked {
            let now = Clock::get()?.unix_timestamp;
            market.status = MarketStatus::Locked;
            emit!(MarketStatusChanged {
                market: market.key(),
                authority: ctx.accounts.authority.key(),
                old_status,
                new_status: market.status,
                effective_ts: now,
            });
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.6 Unlock Market
    // -------------------------------------------------------------------------
    pub fn unlock_market(ctx: Context<UpdateMarketAuthority>) -> Result<()> {
        let market = &mut ctx.accounts.market;
        require_market_authority(market, &ctx.accounts.authority.key())?;
        require!(market.status != MarketStatus::Resolved, ErrorCode::InvalidStage);

        let now = Clock::get()?.unix_timestamp;
        require!(now < market.lock_ts, ErrorCode::CannotUnlockAfterLockTs);

        let old_status = market.status;
        if old_status != MarketStatus::Open {
            market.status = MarketStatus::Open;
            emit!(MarketStatusChanged {
                market: market.key(),
                authority: ctx.accounts.authority.key(),
                old_status,
                new_status: market.status,
                effective_ts: now,
            });
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.7 Sync Market Status To Locked
    // -------------------------------------------------------------------------
    pub fn sync_market_status(ctx: Context<SyncMarketStatus>) -> Result<()> {
        let market = &mut ctx.accounts.market;
        if market.status != MarketStatus::Open {
            return Ok(());
        }

        let now = Clock::get()?.unix_timestamp;
        if now < market.lock_ts {
            return Ok(());
        }

        let old_status = market.status;
        market.status = MarketStatus::Locked;
        emit!(MarketStatusChanged {
            market: market.key(),
            authority: market.authority,
            old_status,
            new_status: market.status,
            effective_ts: now,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 1.8 Update Market Schedule
    // -------------------------------------------------------------------------
    pub fn update_market_schedule(
        ctx: Context<UpdateMarketAuthority>,
        new_lock_ts: i64,
        new_resolve_ts: i64,
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        require_market_authority(market, &ctx.accounts.authority.key())?;
        require!(market.status != MarketStatus::Resolved, ErrorCode::InvalidStage);

        let now = Clock::get()?.unix_timestamp;
        require!(now < market.lock_ts, ErrorCode::InvalidStage);
        require!(market.open_orders_total == 0, ErrorCode::MarketHasOpenOrders);
        require!(new_lock_ts >= market.open_ts, ErrorCode::InvalidTimeRange);
        require!(new_resolve_ts >= new_lock_ts, ErrorCode::InvalidTimeRange);

        let old_lock_ts = market.lock_ts;
        let old_resolve_ts = market.resolve_ts;
        market.lock_ts = new_lock_ts;
        market.resolve_ts = new_resolve_ts;

        emit!(MarketScheduleUpdated {
            market: market.key(),
            authority: ctx.accounts.authority.key(),
            old_lock_ts,
            new_lock_ts,
            old_resolve_ts,
            new_resolve_ts,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 2. Place Order
    // -------------------------------------------------------------------------
    pub fn place_order(
        ctx: Context<PlaceOrder>,
        order_seq: u64,
        side: OrderSide,
        limit_p_yes_e8: u32,
        qty_atoms: u64,
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        let order = &mut ctx.accounts.order;
        let position = &mut ctx.accounts.position;
        let owner = &ctx.accounts.owner;
        let now = Clock::get()?.unix_timestamp;

        require!(market.status == MarketStatus::Open, ErrorCode::MarketNotOpen);
        require!(now >= market.open_ts, ErrorCode::MarketNotOpenYet);
        require!(now < market.lock_ts, ErrorCode::MarketLocked);

        require!(order_seq == market.next_order_seq, ErrorCode::InvalidOrderSeq);
        require!(qty_atoms >= market.min_order_qty_atoms, ErrorCode::OrderQtyTooSmall);
        require!(limit_p_yes_e8 <= PROBABILITY_SCALE, ErrorCode::InvalidProbability);
        require!(position.open_orders < market.max_open_orders_per_user, ErrorCode::UserOpenOrdersLimit);
        require!(market.open_orders_total < market.max_open_orders_total, ErrorCode::GlobalOpenOrdersLimit);

        let escrow_atoms = if side == OrderSide::BuyYes {
            mul_div_ceil(qty_atoms as u128, limit_p_yes_e8 as u128, PROBABILITY_SCALE as u128)?
        } else {
            let p_no = PROBABILITY_SCALE - limit_p_yes_e8;
            mul_div_ceil(qty_atoms as u128, p_no as u128, PROBABILITY_SCALE as u128)?
        };

        require!(escrow_atoms >= market.min_escrow_atoms, ErrorCode::EscrowTooSmall);

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.owner_quote_ata.to_account_info(),
                    to: ctx.accounts.quote_vault.to_account_info(),
                    authority: owner.to_account_info(),
                },
            ),
            escrow_atoms,
        )?;

        order.market = market.key();
        order.owner = owner.key();
        order.side = side;
        order.seq = order_seq;
        order.limit_p_yes_e8 = limit_p_yes_e8;
        order.qty_remaining_atoms = qty_atoms;
        order.escrow_remaining_atoms = escrow_atoms;
        order.created_ts = now;

        if position.market == Pubkey::default() {
            position.market = market.key();
            position.owner = owner.key();
        }

        position.open_orders = position.open_orders.checked_add(1).ok_or(ErrorCode::MathOverflow)?;
        market.next_order_seq = market.next_order_seq.checked_add(1).ok_or(ErrorCode::MathOverflow)?;
        market.open_orders_total = market.open_orders_total.checked_add(1).ok_or(ErrorCode::MathOverflow)?;

        emit!(OrderPlaced {
            market: market.key(),
            order: order.key(),
            owner: owner.key(),
            side,
            seq: order_seq,
            limit_p_yes_e8,
            qty_atoms,
            escrow_atoms,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 3. Match Orders
    // -------------------------------------------------------------------------
    pub fn match_orders(
        ctx: Context<MatchOrders>,
        max_qty_atoms: u64,
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        let order_yes = &mut ctx.accounts.order_yes;
        let order_no = &mut ctx.accounts.order_no;
        let position_yes = &mut ctx.accounts.position_yes;
        let position_no = &mut ctx.accounts.position_no;

        let _ = &ctx.accounts.market_quote_vault;

        let now = Clock::get()?.unix_timestamp;

        require!(market.status == MarketStatus::Open, ErrorCode::MarketNotOpen);
        require!(now >= market.open_ts, ErrorCode::MarketNotOpenYet);
        require!(now < market.lock_ts, ErrorCode::MarketLocked);

        require!(order_yes.side == OrderSide::BuyYes, ErrorCode::InvalidSide);
        require!(order_no.side == OrderSide::BuyNo, ErrorCode::InvalidSide);
        require!(order_yes.market == market.key(), ErrorCode::InvalidMarket);
        require!(order_no.market == market.key(), ErrorCode::InvalidMarket);

        // Prevent self-matching (wash trading)
        require!(order_yes.owner != order_no.owner, ErrorCode::SelfMatchNotAllowed);

        let p_bid = order_yes.limit_p_yes_e8;
        let p_ask = order_no.limit_p_yes_e8;
        require!(p_bid >= p_ask, ErrorCode::NoCross);

        let (maker_seq, p_exec_e8) = if order_yes.seq < order_no.seq {
            (order_yes.seq, order_yes.limit_p_yes_e8)
        } else {
            (order_no.seq, order_no.limit_p_yes_e8)
        };

        let match_qty = std::cmp::min(
            max_qty_atoms,
            std::cmp::min(order_yes.qty_remaining_atoms, order_no.qty_remaining_atoms),
        );
        require!(match_qty > 0, ErrorCode::ZeroMatchQty);

        let cost_yes = mul_div_floor(match_qty as u128, p_exec_e8 as u128, PROBABILITY_SCALE as u128)?;
        let cost_no = match_qty.checked_sub(cost_yes).ok_or(ErrorCode::MathOverflow)?;

        // Update Orders (Debit with checked math)
        order_yes.qty_remaining_atoms = order_yes.qty_remaining_atoms.checked_sub(match_qty)
            .ok_or(ErrorCode::MathOverflow)?;
        order_yes.escrow_remaining_atoms = order_yes.escrow_remaining_atoms.checked_sub(cost_yes)
            .ok_or(ErrorCode::InsufficientEscrow)?;

        order_no.qty_remaining_atoms = order_no.qty_remaining_atoms.checked_sub(match_qty)
            .ok_or(ErrorCode::MathOverflow)?;
        order_no.escrow_remaining_atoms = order_no.escrow_remaining_atoms.checked_sub(cost_no)
            .ok_or(ErrorCode::InsufficientEscrow)?;

        // Refunds
        let escrow_req_yes = mul_div_ceil(
            order_yes.qty_remaining_atoms as u128,
            order_yes.limit_p_yes_e8 as u128,
            PROBABILITY_SCALE as u128
        )?;
        let refund_yes = if order_yes.escrow_remaining_atoms > escrow_req_yes {
            let diff = order_yes.escrow_remaining_atoms - escrow_req_yes;
            order_yes.escrow_remaining_atoms = escrow_req_yes;
            diff
        } else { 0 };

        let p_no_limit = PROBABILITY_SCALE - order_no.limit_p_yes_e8;
        let escrow_req_no = mul_div_ceil(
            order_no.qty_remaining_atoms as u128,
            p_no_limit as u128,
            PROBABILITY_SCALE as u128
        )?;
        let refund_no = if order_no.escrow_remaining_atoms > escrow_req_no {
            let diff = order_no.escrow_remaining_atoms - escrow_req_no;
            order_no.escrow_remaining_atoms = escrow_req_no;
            diff
        } else { 0 };

        // Update Positions
        position_yes.pending_refunds_atoms = position_yes.pending_refunds_atoms.checked_add(refund_yes)
            .ok_or(ErrorCode::MathOverflow)?;
        position_no.pending_refunds_atoms = position_no.pending_refunds_atoms.checked_add(refund_no)
            .ok_or(ErrorCode::MathOverflow)?;

        position_yes.yes_shares_atoms = position_yes.yes_shares_atoms.checked_add(match_qty)
            .ok_or(ErrorCode::MathOverflow)?;
        position_no.no_shares_atoms = position_no.no_shares_atoms.checked_add(match_qty)
            .ok_or(ErrorCode::MathOverflow)?;

        emit!(OrdersMatched {
            market: market.key(),
            order_yes: order_yes.key(),
            order_no: order_no.key(),
            maker_order_seq: maker_seq,
            p_exec_e8,
            qty_atoms: match_qty,
            cost_yes_atoms: cost_yes,
            cost_no_atoms: cost_no,
            refund_yes_atoms: refund_yes,
            refund_no_atoms: refund_no,
        });

        // Close filled orders
        if order_yes.qty_remaining_atoms == 0 {
            market.open_orders_total = market.open_orders_total.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;
            position_yes.open_orders = position_yes.open_orders.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;
            order_yes.close(ctx.accounts.owner_yes.to_account_info())?;
        }

        if order_no.qty_remaining_atoms == 0 {
            market.open_orders_total = market.open_orders_total.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;
            position_no.open_orders = position_no.open_orders.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;
            order_no.close(ctx.accounts.owner_no.to_account_info())?;
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 4. Cancel Order
    // -------------------------------------------------------------------------
    pub fn cancel_order(ctx: Context<CancelOrder>) -> Result<()> {
        let order = &mut ctx.accounts.order;
        let position = &mut ctx.accounts.position;
        let market = &mut ctx.accounts.market;

        let refund = order.escrow_remaining_atoms;
        let qty_remaining = order.qty_remaining_atoms;

        position.pending_refunds_atoms = position.pending_refunds_atoms.checked_add(refund)
            .ok_or(ErrorCode::MathOverflow)?;

        market.open_orders_total = market.open_orders_total.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;
        position.open_orders = position.open_orders.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;

        emit!(OrderCancelled {
            market: market.key(),
            order: order.key(),
            owner: ctx.accounts.owner.key(),
            qty_remaining_atoms: qty_remaining,
            refund_atoms: refund,
        });

        order.close(ctx.accounts.owner.to_account_info())?;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 5. Claim Refunds
    // -------------------------------------------------------------------------
    pub fn claim_refunds(ctx: Context<ClaimRefunds>, amount_atoms: u64) -> Result<()> {
        let position = &mut ctx.accounts.position;
        let market = &ctx.accounts.market;

        let claim_amount = std::cmp::min(amount_atoms, position.pending_refunds_atoms);
        require!(claim_amount > 0, ErrorCode::NoRefunds);

        position.pending_refunds_atoms = position.pending_refunds_atoms.checked_sub(claim_amount)
            .ok_or(ErrorCode::MathOverflow)?;

        let open_ts_bytes = market.open_ts.to_le_bytes();
        let seeds = &[
            b"market".as_ref(),
            market.resolver_hash.as_ref(),
            open_ts_bytes.as_ref(),
            &[market.bump]
        ];
        let signer = &[&seeds[..]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.quote_vault.to_account_info(),
                    to: ctx.accounts.owner_quote_ata.to_account_info(),
                    authority: market.to_account_info(),
                },
                signer,
            ),
            claim_amount,
        )?;

        emit!(RefundClaimed {
            market: market.key(),
            owner: position.owner,
            amount_atoms: claim_amount,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 6. Resolve Market (Legacy)
    // -------------------------------------------------------------------------
    pub fn resolve_market(
        ctx: Context<ResolveMarket>,
        outcome: MarketOutcome,
        proof_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        let now = Clock::get()?.unix_timestamp;

        require!(ctx.accounts.oracle_authority.key() == market.oracle_authority, ErrorCode::UnauthorizedOracle);
        require!(now >= market.resolve_ts, ErrorCode::MarketNotResolvableYet);
        require!(market.status != MarketStatus::Resolved, ErrorCode::InvalidStage);
        require!(outcome != MarketOutcome::Undecided, ErrorCode::InvalidOutcome);

        market.status = MarketStatus::Resolved;
        market.outcome = outcome;
        market.proof_hash = proof_hash;
        market.public_inputs_hash = public_inputs_hash;
        market.resolved_ts = now;

        emit!(MarketResolved {
            market: market.key(),
            outcome: outcome,
            resolved_ts: now,
            proof_hash,
            public_inputs_hash,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 6.5 Resolve Market Signed (Legacy Permissionless)
    // -------------------------------------------------------------------------
    pub fn resolve_market_signed(
        ctx: Context<ResolveMarketSigned>,
        outcome: MarketOutcome,
        proof_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
        oracle_sig: [u8; 64],
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        let now = Clock::get()?.unix_timestamp;

        require!(now >= market.resolve_ts, ErrorCode::MarketNotResolvableYet);
        require!(market.status != MarketStatus::Resolved, ErrorCode::InvalidStage);
        require!(outcome != MarketOutcome::Undecided, ErrorCode::InvalidOutcome);

        let sysvar = &ctx.accounts.instructions_sysvar;

        let sysvar_info = sysvar.to_account_info();
        let current_index = anchor_lang::solana_program::sysvar::instructions::load_current_index_checked(&sysvar_info)?;
        require!(current_index > 0, ErrorCode::MissingEd25519Ix);

        let ed25519_ix = load_instruction_at_checked((current_index - 1) as usize, &sysvar_info)?;

        require!(ed25519_ix.program_id.to_bytes() == ED25519_ID_NATIVE.to_bytes(), ErrorCode::InvalidEd25519Program);

        // Header parsing for 1 signature (16 bytes header)
        let data = &ed25519_ix.data;
        require!(data.len() > 16, ErrorCode::InvalidEd25519Data);

        require!(data[0] == 1, ErrorCode::InvalidEd25519Data); // num_sigs
        require!(data[1] == 0, ErrorCode::InvalidEd25519Data); // padding

        // Parse u16 LE offsets
        let sig_offset = u16::from_le_bytes(data[2..4].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
        let sig_ix = u16::from_le_bytes(data[4..6].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
        let pk_offset = u16::from_le_bytes(data[6..8].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
        let pk_ix = u16::from_le_bytes(data[8..10].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
        let msg_offset = u16::from_le_bytes(data[10..12].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
        let msg_size = u16::from_le_bytes(data[12..14].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
        let msg_ix = u16::from_le_bytes(data[14..16].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);

        // Enforce all instruction indices are u16::MAX (current instruction)
        require!(sig_ix == 0xFFFF, ErrorCode::Ed25519IxIndexesNotSelf);
        require!(pk_ix == 0xFFFF, ErrorCode::Ed25519IxIndexesNotSelf);
        require!(msg_ix == 0xFFFF, ErrorCode::Ed25519IxIndexesNotSelf);

        // Bounds Check
        let sig_start = sig_offset as usize;
        let sig_end = sig_start.checked_add(64).ok_or(ErrorCode::InvalidEd25519Data)?;
        let pk_start = pk_offset as usize;
        let pk_end = pk_start.checked_add(32).ok_or(ErrorCode::InvalidEd25519Data)?;
        let msg_start = msg_offset as usize;
        let msg_end = msg_start.checked_add(msg_size as usize).ok_or(ErrorCode::InvalidEd25519Data)?;

        require!(sig_end <= data.len(), ErrorCode::InvalidEd25519Data);
        require!(pk_end <= data.len(), ErrorCode::InvalidEd25519Data);
        require!(msg_end <= data.len(), ErrorCode::InvalidEd25519Data);

        // Verify Data
        let ix_sig = &data[sig_start..sig_end];
        let ix_pk = &data[pk_start..pk_end];
        let ix_msg = &data[msg_start..msg_end];

        require!(ix_pk == market.oracle_authority.as_ref(), ErrorCode::UnauthorizedOracle);
        require!(ix_sig == oracle_sig, ErrorCode::SignatureMismatch);

        // Reconstruct Expected Message (V1)
        let outcome_byte: u8 = match outcome {
            MarketOutcome::Yes => 1,
            MarketOutcome::No => 2,
            MarketOutcome::Invalid => 3,
            _ => 0,
        };

        let mut expected_msg = Vec::with_capacity(18 + 32 + 32 + 8 + 1 + 32 + 32);
        expected_msg.extend_from_slice(b"PROPHET_RESOLVE_V1");
        expected_msg.extend_from_slice(market.key().as_ref());
        expected_msg.extend_from_slice(&market.resolver_hash);
        expected_msg.extend_from_slice(&market.open_ts.to_le_bytes());
        expected_msg.push(outcome_byte);
        expected_msg.extend_from_slice(&proof_hash);
        expected_msg.extend_from_slice(&public_inputs_hash);

        require!(msg_size as usize == expected_msg.len(), ErrorCode::MessageSizeMismatch);
        require!(ix_msg == expected_msg.as_slice(), ErrorCode::MessageMismatch);

        market.status = MarketStatus::Resolved;
        market.outcome = outcome;
        market.proof_hash = proof_hash;
        market.public_inputs_hash = public_inputs_hash;
        market.resolved_ts = now;

        emit!(MarketResolved {
            market: market.key(),
            outcome: outcome,
            resolved_ts: now,
            proof_hash,
            public_inputs_hash,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 6.6 Resolve Market Threshold (Permissionless, t-of-n Notaries)
    // -------------------------------------------------------------------------
    pub fn resolve_market_threshold(
        ctx: Context<ResolveMarketThreshold>,
        outcome: MarketOutcome,
        proof_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        let cfg = &ctx.accounts.notary_config;
        let now = Clock::get()?.unix_timestamp;

        require!(now >= market.resolve_ts, ErrorCode::MarketNotResolvableYet);
        require!(market.status != MarketStatus::Resolved, ErrorCode::InvalidStage);
        require!(outcome != MarketOutcome::Undecided, ErrorCode::InvalidOutcome);

        require!(market.notary_config != Pubkey::default(), ErrorCode::NotaryConfigNotSet);
        require!(market.notary_config == cfg.key(), ErrorCode::NotaryConfigMismatch);

        require!(cfg.threshold > 0, ErrorCode::InvalidNotaryThreshold);
        require!((cfg.threshold as usize) <= (cfg.notary_count as usize), ErrorCode::InvalidNotaryThreshold);

        // Build expected canonical message (V2)
        let outcome_byte: u8 = match outcome {
            MarketOutcome::Yes => 1,
            MarketOutcome::No => 2,
            MarketOutcome::Invalid => 3,
            _ => 0,
        };

        let mut expected_msg = Vec::with_capacity(18 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 1 + 32 + 32);
        expected_msg.extend_from_slice(b"PROPHET_RESOLVE_V2");
        expected_msg.extend_from_slice(crate::ID.as_ref());
        expected_msg.extend_from_slice(market.key().as_ref());
        expected_msg.extend_from_slice(cfg.key().as_ref());
        expected_msg.extend_from_slice(&market.resolver_hash);
        expected_msg.extend_from_slice(&market.open_ts.to_le_bytes());
        expected_msg.extend_from_slice(&market.resolve_ts.to_le_bytes());
        expected_msg.extend_from_slice(&cfg.version.to_le_bytes());
        expected_msg.push(outcome_byte);
        expected_msg.extend_from_slice(&proof_hash);
        expected_msg.extend_from_slice(&public_inputs_hash);

        // Scan a bounded window of prior instructions for Ed25519 verify ixs.
        let sysvar_info = ctx.accounts.instructions_sysvar.to_account_info();
        let current_index =
            anchor_lang::solana_program::sysvar::instructions::load_current_index_checked(&sysvar_info)?;

        require!(current_index > 0, ErrorCode::MissingEd25519Ix);

        // Count distinct valid notary signatures
        let mut seen: Vec<Pubkey> = Vec::with_capacity(cfg.threshold as usize);
        let mut valid_count: u8 = 0;

        // Scan backwards to prefer latest ixs and keep compute bounded
        let max_scan: u16 = MAX_ED25519_SCAN as u16;
        let mut scanned: u16 = 0;
        let mut i: i32 = (current_index as i32) - 1;
        while i >= 0 && scanned < max_scan && valid_count < cfg.threshold {
            let ix = load_instruction_at_checked(i as usize, &sysvar_info)?;
            scanned = scanned.saturating_add(1);

            if ix.program_id.to_bytes() != ED25519_ID_NATIVE.to_bytes() {
                i -= 1;
                continue;
            }

            // Parse the ed25519 ix (support only 1 signature per ix for MVP)
            let data = &ix.data;
            if data.len() < 16 {
                i -= 1;
                continue;
            }
            if data[0] != 1 || data[1] != 0 {
                i -= 1;
                continue;
            }

            let sig_offset = u16::from_le_bytes(data[2..4].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
            let sig_ix = u16::from_le_bytes(data[4..6].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
            let pk_offset = u16::from_le_bytes(data[6..8].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
            let pk_ix = u16::from_le_bytes(data[8..10].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
            let msg_offset = u16::from_le_bytes(data[10..12].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
            let msg_size = u16::from_le_bytes(data[12..14].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);
            let msg_ix = u16::from_le_bytes(data[14..16].try_into().map_err(|_| ErrorCode::InvalidEd25519Data)?);

            // Require self-contained message/sig/pubkey within the ed25519 instruction.
            require!(sig_ix == 0xFFFF, ErrorCode::Ed25519IxIndexesNotSelf);
            require!(pk_ix == 0xFFFF, ErrorCode::Ed25519IxIndexesNotSelf);
            require!(msg_ix == 0xFFFF, ErrorCode::Ed25519IxIndexesNotSelf);

            let sig_start = sig_offset as usize;
            let sig_end = sig_start.checked_add(64).ok_or(ErrorCode::InvalidEd25519Data)?;
            let pk_start = pk_offset as usize;
            let pk_end = pk_start.checked_add(32).ok_or(ErrorCode::InvalidEd25519Data)?;
            let msg_start = msg_offset as usize;
            let msg_end = msg_start.checked_add(msg_size as usize).ok_or(ErrorCode::InvalidEd25519Data)?;

            if sig_end > data.len() || pk_end > data.len() || msg_end > data.len() {
                i -= 1;
                continue;
            }

            let pk_bytes: [u8; 32] = data[pk_start..pk_end]
                .try_into()
                .map_err(|_| ErrorCode::InvalidEd25519Data)?;
            let pk = Pubkey::new_from_array(pk_bytes);

            // Must be in notary set
            if !cfg.contains_notary(&pk) {
                i -= 1;
                continue;
            }

            // Must be distinct
            if seen.iter().any(|x| x == &pk) {
                return Err(ErrorCode::DuplicateNotarySig.into());
            }

            let msg = &data[msg_start..msg_end];
            if msg != expected_msg.as_slice() {
                i -= 1;
                continue;
            }

            // If the ed25519 program ix exists, the signature was already verified by the runtime.
            // We do not need to re-verify on-chain.
            seen.push(pk);
            valid_count = valid_count.saturating_add(1);

            i -= 1;
        }

        require!(valid_count >= cfg.threshold, ErrorCode::NotEnoughNotarySigs);

        market.status = MarketStatus::Resolved;
        market.outcome = outcome;
        market.proof_hash = proof_hash;
        market.public_inputs_hash = public_inputs_hash;
        market.resolved_ts = now;

        emit!(MarketResolved {
            market: market.key(),
            outcome,
            resolved_ts: now,
            proof_hash,
            public_inputs_hash,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 7. Redeem
    // -------------------------------------------------------------------------
    pub fn redeem(ctx: Context<Redeem>) -> Result<()> {
        let market = &ctx.accounts.market;
        let position = &mut ctx.accounts.position;

        require!(market.status == MarketStatus::Resolved, ErrorCode::MarketNotResolved);

        // Capture values BEFORE zeroing for event emission
        let yes = position.yes_shares_atoms;
        let no = position.no_shares_atoms;

        let payout = match market.outcome {
            MarketOutcome::Yes => yes,
            MarketOutcome::No => no,
            MarketOutcome::Invalid => {
                yes.checked_add(no).ok_or(ErrorCode::MathOverflow)?
                   .checked_div(2).ok_or(ErrorCode::MathOverflow)?
            },
            _ => 0,
        };

        position.yes_shares_atoms = 0;
        position.no_shares_atoms = 0;
        position.redeemed = true;

        if payout > 0 {
            let open_ts_bytes = market.open_ts.to_le_bytes();
            let seeds = &[
                b"market".as_ref(),
                market.resolver_hash.as_ref(),
                open_ts_bytes.as_ref(),
                &[market.bump]
            ];
            let signer = &[&seeds[..]];

            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.quote_vault.to_account_info(),
                        to: ctx.accounts.owner_quote_ata.to_account_info(),
                        authority: market.to_account_info(),
                    },
                    signer,
                ),
                payout,
            )?;
        }

        // Emitting captured non-zero values
        emit!(Redeemed {
            market: market.key(),
            owner: position.owner,
            outcome: market.outcome,
            payout_atoms: payout,
            yes_burned_atoms: yes,
            no_burned_atoms: no,
        });

        Ok(())
    }

    // -------------------------------------------------------------------------
    // 8. Emergency Resolve Invalid (Authority)
    // -------------------------------------------------------------------------
    pub fn emergency_resolve_invalid(
        ctx: Context<UpdateMarketAuthority>,
        proof_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
    ) -> Result<()> {
        let market = &mut ctx.accounts.market;
        require_market_authority(market, &ctx.accounts.authority.key())?;
        require!(market.status == MarketStatus::Locked, ErrorCode::MarketNotLocked);

        let now = Clock::get()?.unix_timestamp;
        market.status = MarketStatus::Resolved;
        market.outcome = MarketOutcome::Invalid;
        market.proof_hash = proof_hash;
        market.public_inputs_hash = public_inputs_hash;
        market.resolved_ts = now;

        emit!(MarketResolved {
            market: market.key(),
            outcome: MarketOutcome::Invalid,
            resolved_ts: now,
            proof_hash,
            public_inputs_hash,
        });

        Ok(())
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn mul_div_floor(a: u128, b: u128, den: u128) -> Result<u64> {
    let res = (a.checked_mul(b).ok_or(ErrorCode::MathOverflow)?)
        .checked_div(den).ok_or(ErrorCode::MathOverflow)?;
    Ok(res as u64)
}

fn mul_div_ceil(a: u128, b: u128, den: u128) -> Result<u64> {
    if den == 0 { return Err(ErrorCode::MathOverflow.into()); }
    let num = a.checked_mul(b).ok_or(ErrorCode::MathOverflow)?;
    if num == 0 { return Ok(0); }
    let den_minus_one = den.checked_sub(1).ok_or(ErrorCode::MathOverflow)?;
    let num_plus = num.checked_add(den_minus_one).ok_or(ErrorCode::MathOverflow)?;
    let res = num_plus.checked_div(den).ok_or(ErrorCode::MathOverflow)?;
    Ok(res as u64)
}

fn require_market_authority(market: &Market, authority: &Pubkey) -> Result<()> {
    require!(market.authority == *authority, ErrorCode::UnauthorizedMarketAuthority);
    Ok(())
}

// -------------------------------------------------------------------------
// Contexts
// -------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(resolver_hash: [u8; 32], open_ts: i64)]
pub struct InitializeMarket<'info> {
    #[account(
        init,
        seeds = [b"market", resolver_hash.as_ref(), &open_ts.to_le_bytes()],
        bump,
        payer = authority,
        space = 8 + Market::LEN
    )]
    pub market: Box<Account<'info, Market>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Trusted oracle authority (legacy)
    pub oracle_authority: AccountInfo<'info>,
    pub quote_mint: Box<Account<'info, token::Mint>>,

    #[account(
        init,
        payer = authority,
        associated_token::mint = quote_mint,
        associated_token::authority = market
    )]
    pub quote_vault: Box<Account<'info, TokenAccount>>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct InitializeNotaryConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + NotaryConfig::LEN,
        seeds = [b"notary_config", admin.key().as_ref()],
        bump
    )]
    pub notary_config: Box<Account<'info, NotaryConfig>>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateNotaryConfig<'info> {
    #[account(
        mut,
        seeds = [b"notary_config", admin.key().as_ref()],
        bump = notary_config.bump,
        has_one = admin
    )]
    pub notary_config: Box<Account<'info, NotaryConfig>>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(resolver_hash: [u8; 32], open_ts: i64)]
pub struct InitializeMarketV2<'info> {
    #[account(
        init,
        seeds = [b"market", resolver_hash.as_ref(), &open_ts.to_le_bytes()],
        bump,
        payer = authority,
        space = 8 + Market::LEN
    )]
    pub market: Box<Account<'info, Market>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Legacy field; unused for threshold resolution.
    pub oracle_authority: AccountInfo<'info>,
    pub quote_mint: Box<Account<'info, token::Mint>>,

    #[account(
        init,
        payer = authority,
        associated_token::mint = quote_mint,
        associated_token::authority = market
    )]
    pub quote_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [b"notary_config", notary_config.admin.as_ref()],
        bump = notary_config.bump
    )]
    pub notary_config: Box<Account<'info, NotaryConfig>>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct UpdateMarketAuthority<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SyncMarketStatus<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
}

#[derive(Accounts)]
#[instruction(order_seq: u64)]
pub struct PlaceOrder<'info> {
    #[account(mut)]
    pub market: Box<Account<'info, Market>>,
    #[account(
        init,
        payer = owner,
        space = 8 + Order::LEN,
        seeds = [b"order", market.key().as_ref(), owner.key().as_ref(), &order_seq.to_le_bytes()],
        bump
    )]
    pub order: Box<Account<'info, Order>>,
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + Position::LEN,
        seeds = [b"position", market.key().as_ref(), owner.key().as_ref()],
        bump
    )]
    pub position: Box<Account<'info, Position>>,
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        constraint = owner_quote_ata.mint == market.quote_mint,
        constraint = owner_quote_ata.owner == owner.key()
    )]
    pub owner_quote_ata: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        constraint = quote_vault.key() == market.quote_vault,
        constraint = quote_vault.mint == market.quote_mint,
        constraint = quote_vault.owner == market.key()
    )]
    pub quote_vault: Box<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MatchOrders<'info> {
    #[account(mut)]
    pub market: Box<Account<'info, Market>>,
    #[account(mut)]
    pub order_yes: Box<Account<'info, Order>>,
    #[account(mut)]
    pub order_no: Box<Account<'info, Order>>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), order_yes.owner.as_ref()], bump)]
    pub position_yes: Box<Account<'info, Position>>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), order_no.owner.as_ref()], bump)]
    pub position_no: Box<Account<'info, Position>>,
    /// CHECK: Address checked via constraint
    #[account(mut, address = order_yes.owner)]
    pub owner_yes: AccountInfo<'info>,
    /// CHECK: Address checked via constraint
    #[account(mut, address = order_no.owner)]
    pub owner_no: AccountInfo<'info>,
    #[account(
        mut,
        constraint = market_quote_vault.key() == market.quote_vault,
        constraint = market_quote_vault.mint == market.quote_mint,
        constraint = market_quote_vault.owner == market.key()
    )]
    pub market_quote_vault: Box<Account<'info, TokenAccount>>,
}

#[derive(Accounts)]
pub struct CancelOrder<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    #[account(mut, has_one = owner, has_one = market)]
    pub order: Account<'info, Order>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), owner.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRefunds<'info> {
    #[account(mut, seeds = [b"market", market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes()], bump = market.bump)]
    pub market: Account<'info, Market>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), owner.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        constraint = quote_vault.key() == market.quote_vault,
        constraint = quote_vault.mint == market.quote_mint,
        constraint = quote_vault.owner == market.key()
    )]
    pub quote_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = owner_quote_ata.mint == market.quote_mint,
        constraint = owner_quote_ata.owner == owner.key()
    )]
    pub owner_quote_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ResolveMarket<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    pub oracle_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ResolveMarketSigned<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    /// CHECK: Checked via address constraint
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ResolveMarketThreshold<'info> {
    #[account(mut)]
    pub market: Account<'info, Market>,
    pub notary_config: Account<'info, NotaryConfig>,
    /// CHECK: Checked via address constraint
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Redeem<'info> {
    #[account(mut, seeds = [b"market", market.resolver_hash.as_ref(), &market.open_ts.to_le_bytes()], bump = market.bump)]
    pub market: Account<'info, Market>,
    #[account(mut, seeds = [b"position", market.key().as_ref(), owner.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        constraint = quote_vault.key() == market.quote_vault,
        constraint = quote_vault.mint == market.quote_mint,
        constraint = quote_vault.owner == market.key()
    )]
    pub quote_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = owner_quote_ata.mint == market.quote_mint,
        constraint = owner_quote_ata.owner == owner.key()
    )]
    pub owner_quote_ata: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}
