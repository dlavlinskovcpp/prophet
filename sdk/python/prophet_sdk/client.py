import hashlib
import json
import os
import struct
from typing import Dict, List, Optional, Sequence, Tuple

from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import MemcmpOpts
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from .accounts import decode_claim, decode_market, decode_order, decode_position, extract_account_bytes
from .ata import ensure_ata
from .ed25519 import build_ed25519_ix
from .pdas import (
    derive_associated_token_account,
    derive_claim_pda,
    derive_market_pda,
    derive_notary_config_pda,
    derive_order_pda,
    derive_position_pda,
)
from .tx import submit_and_confirm
from .types import (
    ClaimAccount,
    ClaimOutcome,
    MarketAccount,
    MarketOutcome,
    OrderAccount,
    OrderSide,
    PositionAccount,
)

SYSTEM_PROGRAM_ID = Pubkey.from_string("11111111111111111111111111111111")
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
SYSVAR_INSTRUCTIONS_ID = Pubkey.from_string("Sysvar1nstructions1111111111111111111111111")

ORDER_DISCRIMINATOR = hashlib.sha256(b"account:Order").digest()[:8]

DOMAIN_V1 = b"PROPHET_RESOLVE_V1"
DOMAIN_V2 = b"PROPHET_RESOLVE_V2"
DOMAIN_CLAIM_V1 = b"PROPHET_CLAIM_RESOLVE_V1"
DOMAIN_CLAIM_V2 = b"PROPHET_CLAIM_RESOLVE_V2"


class ProphetClient:
    def __init__(self, rpc_url: str = None, payer_keypair_path: str = None, program_id: str = None):
        self.rpc_url = rpc_url or os.getenv("RPC_URL", "http://localhost:8899")
        self.client = Client(self.rpc_url)
        self.program_id = Pubkey.from_string(
            program_id or os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")
        )
        self.payer = self._load_keypair(payer_keypair_path or os.getenv("PAYER_KEYPAIR_PATH", "./id.json"))

    def _load_keypair(self, path_or_str: str) -> Keypair:
        val = (path_or_str or "").strip()
        if not val:
            raise ValueError("Empty keypair path/string")

        if os.path.exists(val):
            with open(val, "r") as f:
                val = f.read().strip()

        kp = None
        if val.startswith("[") and val.endswith("]"):
            try:
                raw = json.loads(val)
                if len(raw) == 64:
                    kp = Keypair.from_bytes(bytes(raw))
            except Exception:
                kp = None
        elif "," in val:
            try:
                raw = [int(x) for x in val.split(",")]
                if len(raw) == 64:
                    kp = Keypair.from_bytes(bytes(raw))
            except Exception:
                kp = None

        if kp is None:
            try:
                kp = Keypair.from_base58_string(val)
            except Exception:
                kp = None

        if kp is None:
            raise ValueError(f"Failed to load Keypair from input: {path_or_str[:20]}...")

        return kp

    def _get_discriminator(self, name: str) -> bytes:
        return hashlib.sha256(f"global:{name}".encode()).digest()[:8]

    def _outcome_index(self, outcome: MarketOutcome) -> int:
        return int(outcome)

    def _claim_outcome_index(self, outcome: ClaimOutcome) -> int:
        return int(outcome)

    def _build_resolve_message_v1(
        self,
        market: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        outcome: MarketOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> bytes:
        return (
            DOMAIN_V1
            + bytes(market)
            + resolver_hash
            + struct.pack("<q", open_ts)
            + struct.pack("B", self._outcome_index(outcome))
            + proof_hash
            + public_inputs_hash
        )

    def _build_resolve_message_v2(
        self,
        market: Pubkey,
        notary_config: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        resolve_ts: int,
        outcome: MarketOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> bytes:
        return (
            DOMAIN_V2
            + bytes(self.program_id)
            + bytes(market)
            + bytes(notary_config)
            + resolver_hash
            + struct.pack("<q", open_ts)
            + struct.pack("<q", resolve_ts)
            + struct.pack("B", self._outcome_index(outcome))
            + proof_hash
            + public_inputs_hash
        )

    def _build_claim_resolve_message_v1(
        self,
        claim: Pubkey,
        resolver_hash: bytes,
        issuer: Pubkey,
        claim_id: int,
        resolve_ts: int,
        outcome: ClaimOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> bytes:
        return (
            DOMAIN_CLAIM_V1
            + bytes(self.program_id)
            + bytes(claim)
            + resolver_hash
            + bytes(issuer)
            + struct.pack("<Q", claim_id)
            + struct.pack("<q", resolve_ts)
            + struct.pack("B", self._claim_outcome_index(outcome))
            + proof_hash
            + public_inputs_hash
        )

    def _build_claim_resolve_message_v2(
        self,
        claim: Pubkey,
        notary_config: Pubkey,
        resolver_hash: bytes,
        issuer: Pubkey,
        claim_id: int,
        resolve_ts: int,
        outcome: ClaimOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> bytes:
        return (
            DOMAIN_CLAIM_V2
            + bytes(self.program_id)
            + bytes(claim)
            + bytes(notary_config)
            + resolver_hash
            + bytes(issuer)
            + struct.pack("<Q", claim_id)
            + struct.pack("<q", resolve_ts)
            + struct.pack("B", self._claim_outcome_index(outcome))
            + proof_hash
            + public_inputs_hash
        )

    # -------------------------------------------------------------------------
    # Fetch Helpers
    # -------------------------------------------------------------------------

    def fetch_market(self, pubkey: Pubkey) -> Optional[MarketAccount]:
        resp = self.client.get_account_info(pubkey, commitment=Confirmed)
        if not resp.value:
            return None
        return decode_market(extract_account_bytes(resp.value.data))

    def fetch_order(self, pubkey: Pubkey) -> Optional[OrderAccount]:
        resp = self.client.get_account_info(pubkey, commitment=Confirmed)
        if not resp.value:
            return None
        return decode_order(extract_account_bytes(resp.value.data))

    def fetch_position(self, pubkey: Pubkey) -> Optional[PositionAccount]:
        resp = self.client.get_account_info(pubkey, commitment=Confirmed)
        if not resp.value:
            return None
        return decode_position(extract_account_bytes(resp.value.data))

    def fetch_claim(self, pubkey: Pubkey) -> Optional[ClaimAccount]:
        resp = self.client.get_account_info(pubkey, commitment=Confirmed)
        if not resp.value:
            return None
        return decode_claim(extract_account_bytes(resp.value.data))

    def get_next_order_seq(self, market: Pubkey) -> int:
        m = self.fetch_market(market)
        if m is None:
            raise ValueError(f"Market {market} not found")
        return int(m.next_order_seq)

    def fetch_orders_for_market(self, market: Pubkey) -> List[Tuple[Pubkey, OrderAccount]]:
        filters = [MemcmpOpts(offset=8, bytes=str(market))]

        resp = self.client.get_program_accounts(
            self.program_id,
            commitment=Confirmed,
            encoding="base64",
            filters=filters,
        )

        results = []
        if not resp.value:
            return results

        for item in resp.value:
            try:
                if hasattr(item, "account"):
                    acc_data_obj = item.account.data
                    pk_str = str(item.pubkey)
                else:
                    acc_data_obj = item["account"]["data"]
                    pk_str = item["pubkey"]

                raw_bytes = extract_account_bytes(acc_data_obj)

                if raw_bytes[:8] != ORDER_DISCRIMINATOR:
                    continue

                order_acc = decode_order(raw_bytes)
                if order_acc.market != market:
                    continue

                if order_acc.qty_remaining_atoms > 0:
                    pubkey = Pubkey.from_string(pk_str)
                    results.append((pubkey, order_acc))
            except Exception:
                continue

        return results

    def fetch_orders_bulk(self, order_pubkeys: List[Pubkey]):
        if not order_pubkeys:
            return {}
        batch_size = 100
        results: Dict[Pubkey, Optional[OrderAccount]] = {}
        for i in range(0, len(order_pubkeys), batch_size):
            batch = order_pubkeys[i : i + batch_size]
            resp = self.client.get_multiple_accounts(batch, commitment=Confirmed)
            if not resp.value:
                continue
            for pubkey, account_info in zip(batch, resp.value):
                if account_info is None:
                    results[pubkey] = None
                    continue
                try:
                    raw_bytes = extract_account_bytes(account_info.data)
                    if len(raw_bytes) < 8 or raw_bytes[:8] != ORDER_DISCRIMINATOR:
                        results[pubkey] = None
                        continue
                    order = decode_order(raw_bytes)
                    results[pubkey] = order if order.qty_remaining_atoms > 0 else None
                except Exception:
                    results[pubkey] = None
        return results

    # -------------------------------------------------------------------------
    # Notary + Market Initialization
    # -------------------------------------------------------------------------

    def initialize_notary_config(self, threshold: int, notary_keys: Sequence[Pubkey]) -> Tuple[Pubkey, str]:
        cfg_pda, _ = derive_notary_config_pda(self.payer.pubkey(), self.program_id)

        data = self._get_discriminator("initialize_notary_config")
        data += struct.pack("<B", threshold)
        data += struct.pack("<I", len(notary_keys))
        for pk in notary_keys:
            data += bytes(pk)

        keys = [
            AccountMeta(cfg_pda, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(SYSTEM_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        sig = submit_and_confirm(self.client, [ix], self.payer)
        return cfg_pda, sig

    def update_notary_config(self, threshold: int, notary_keys: Sequence[Pubkey]) -> str:
        cfg_pda, _ = derive_notary_config_pda(self.payer.pubkey(), self.program_id)

        data = self._get_discriminator("update_notary_config")
        data += struct.pack("<B", threshold)
        data += struct.pack("<I", len(notary_keys))
        for pk in notary_keys:
            data += bytes(pk)

        keys = [
            AccountMeta(cfg_pda, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
        ]

        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    def initialize_market(
        self,
        resolver_hash: bytes,
        open_ts: int,
        lock_ts: int,
        resolve_ts: int,
        oracle_authority: Pubkey = None,
        min_order_qty_atoms: int = 1,
        min_escrow_atoms: int = 1,
        max_open_orders_per_user: int = 32,
        max_open_orders_total: int = 4096,
        quote_mint: Pubkey = None,
    ) -> str:
        if len(resolver_hash) != 32:
            raise ValueError("Resolver hash must be 32 bytes")

        market_pda, _ = derive_market_pda(resolver_hash, open_ts, self.program_id)
        quote_vault = derive_associated_token_account(market_pda, quote_mint)

        oracle_auth = oracle_authority or self.payer.pubkey()

        data = self._get_discriminator("initialize_market")
        data += resolver_hash
        data += struct.pack(
            "<qqqQQHI",
            open_ts,
            lock_ts,
            resolve_ts,
            min_order_qty_atoms,
            min_escrow_atoms,
            max_open_orders_per_user,
            max_open_orders_total,
        )

        keys = [
            AccountMeta(market_pda, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(oracle_auth, False, False),
            AccountMeta(quote_mint, False, False),
            AccountMeta(quote_vault, False, True),
            AccountMeta(SYSTEM_PROGRAM_ID, False, False),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
            AccountMeta(ASSOCIATED_TOKEN_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    def initialize_market_v2(
        self,
        resolver_hash: bytes,
        open_ts: int,
        lock_ts: int,
        resolve_ts: int,
        notary_config: Pubkey,
        oracle_authority: Pubkey = None,
        min_order_qty_atoms: int = 1,
        min_escrow_atoms: int = 1,
        max_open_orders_per_user: int = 32,
        max_open_orders_total: int = 4096,
        quote_mint: Pubkey = None,
    ) -> str:
        if len(resolver_hash) != 32:
            raise ValueError("Resolver hash must be 32 bytes")

        market_pda, _ = derive_market_pda(resolver_hash, open_ts, self.program_id)
        quote_vault = derive_associated_token_account(market_pda, quote_mint)

        oracle_auth = oracle_authority or self.payer.pubkey()

        data = self._get_discriminator("initialize_market_v2")
        data += resolver_hash
        data += struct.pack(
            "<qqqQQHI",
            open_ts,
            lock_ts,
            resolve_ts,
            min_order_qty_atoms,
            min_escrow_atoms,
            max_open_orders_per_user,
            max_open_orders_total,
        )

        keys = [
            AccountMeta(market_pda, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(oracle_auth, False, False),
            AccountMeta(quote_mint, False, False),
            AccountMeta(quote_vault, False, True),
            AccountMeta(notary_config, False, False),
            AccountMeta(SYSTEM_PROGRAM_ID, False, False),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
            AccountMeta(ASSOCIATED_TOKEN_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    # -------------------------------------------------------------------------
    # Claim Flow (Bonded Claims MVP)
    # -------------------------------------------------------------------------

    def create_claim(
        self,
        claim_id: int,
        resolver_hash: bytes,
        resolve_ts: int,
        bond_atoms: int,
        pass_recipient: Pubkey,
        fail_recipient: Pubkey,
        quote_mint: Pubkey,
        oracle_authority: Optional[Pubkey] = None,
        notary_config: Optional[Pubkey] = None,
        issuer_quote_ata: Optional[Pubkey] = None,
    ) -> Tuple[Pubkey, str]:
        if len(resolver_hash) != 32:
            raise ValueError("resolver_hash must be 32 bytes")

        claim_pda, _ = derive_claim_pda(self.payer.pubkey(), claim_id, self.program_id)
        quote_vault = derive_associated_token_account(claim_pda, quote_mint)
        issuer_ata = issuer_quote_ata or ensure_ata(
            self.client, self.payer, self.payer.pubkey(), quote_mint
        )

        oracle = oracle_authority or self.payer.pubkey()
        cfg = notary_config or Pubkey.default()

        data = self._get_discriminator("create_claim")
        data += struct.pack("<Q", claim_id)
        data += resolver_hash
        data += struct.pack("<q", resolve_ts)
        data += struct.pack("<Q", bond_atoms)
        data += bytes(pass_recipient)
        data += bytes(fail_recipient)
        data += bytes(oracle)
        data += bytes(cfg)

        keys = [
            AccountMeta(claim_pda, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(quote_mint, False, False),
            AccountMeta(issuer_ata, False, True),
            AccountMeta(quote_vault, False, True),
            AccountMeta(SYSTEM_PROGRAM_ID, False, False),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
            AccountMeta(ASSOCIATED_TOKEN_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        sig = submit_and_confirm(self.client, [ix], self.payer)
        return claim_pda, sig

    def redeem_claim(
        self,
        claim: Pubkey,
        recipient_keypair: Optional[Keypair] = None,
        recipient_quote_ata: Optional[Pubkey] = None,
    ) -> str:
        recipient = recipient_keypair or self.payer
        claim_acc = self.fetch_claim(claim)
        if claim_acc is None:
            raise ValueError(f"Claim {claim} not found")

        ata = recipient_quote_ata or ensure_ata(
            self.client, self.payer, recipient.pubkey(), claim_acc.quote_mint
        )

        data = self._get_discriminator("redeem_claim")
        keys = [
            AccountMeta(claim, False, True),
            AccountMeta(recipient.pubkey(), True, True),
            AccountMeta(claim_acc.quote_vault, False, True),
            AccountMeta(ata, False, True),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
        ]
        ix = Instruction(self.program_id, data, keys)

        extra_signers = [recipient] if recipient.pubkey() != self.payer.pubkey() else None
        return submit_and_confirm(self.client, [ix], self.payer, signers=extra_signers)

    # -------------------------------------------------------------------------
    # Trading Flow
    # -------------------------------------------------------------------------

    def place_order(
        self,
        market: Pubkey,
        order_seq: int,
        side: OrderSide,
        limit_p_yes_e8: int,
        qty_atoms: int,
        quote_mint: Pubkey,
    ) -> str:
        owner_ata = ensure_ata(self.client, self.payer, self.payer.pubkey(), quote_mint)

        order_pda, _ = derive_order_pda(market, self.payer.pubkey(), order_seq, self.program_id)
        position_pda, _ = derive_position_pda(market, self.payer.pubkey(), self.program_id)
        quote_vault = derive_associated_token_account(market, quote_mint)

        data = self._get_discriminator("place_order")
        data += struct.pack("<Q", order_seq)
        data += struct.pack("B", int(side))
        data += struct.pack("<IQ", limit_p_yes_e8, qty_atoms)

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(order_pda, False, True),
            AccountMeta(position_pda, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(owner_ata, False, True),
            AccountMeta(quote_vault, False, True),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
            AccountMeta(SYSTEM_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    def place_order_auto_seq(
        self,
        market: Pubkey,
        side: OrderSide,
        limit_p_yes_e8: int,
        qty_atoms: int,
        quote_mint: Pubkey,
    ) -> str:
        seq = self.get_next_order_seq(market)
        try:
            return self.place_order(market, seq, side, limit_p_yes_e8, qty_atoms, quote_mint)
        except Exception as e:
            msg = str(e).lower()
            if "invalidorderseq" in msg or "order sequence mismatch" in msg:
                seq2 = self.get_next_order_seq(market)
                return self.place_order(market, seq2, side, limit_p_yes_e8, qty_atoms, quote_mint)
            raise

    def place_order_auto_seq_with_seq(
        self,
        market: Pubkey,
        side: OrderSide,
        limit_p_yes_e8: int,
        qty_atoms: int,
        quote_mint: Pubkey,
    ) -> Tuple[int, str]:
        seq = self.get_next_order_seq(market)
        try:
            sig = self.place_order(market, seq, side, limit_p_yes_e8, qty_atoms, quote_mint)
            return seq, sig
        except Exception as e:
            msg = str(e).lower()
            if "invalidorderseq" in msg or "order sequence mismatch" in msg:
                seq2 = self.get_next_order_seq(market)
                sig2 = self.place_order(market, seq2, side, limit_p_yes_e8, qty_atoms, quote_mint)
                return seq2, sig2
            raise e

    def match_orders(
        self,
        market: Pubkey,
        order_yes: Pubkey,
        order_no: Pubkey,
        owner_yes: Pubkey,
        owner_no: Pubkey,
        quote_mint: Pubkey,
        max_qty_atoms: int,
        compute_unit_limit: Optional[int] = None,
        compute_unit_price_micro_lamports: Optional[int] = None,
    ) -> str:
        pos_yes, _ = derive_position_pda(market, owner_yes, self.program_id)
        pos_no, _ = derive_position_pda(market, owner_no, self.program_id)
        quote_vault = derive_associated_token_account(market, quote_mint)

        data = self._get_discriminator("match_orders")
        data += struct.pack("<Q", max_qty_atoms)

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(order_yes, False, True),
            AccountMeta(order_no, False, True),
            AccountMeta(pos_yes, False, True),
            AccountMeta(pos_no, False, True),
            AccountMeta(owner_yes, False, True),
            AccountMeta(owner_no, False, True),
            AccountMeta(quote_vault, False, True),
        ]

        ix = Instruction(self.program_id, data, keys)

        return submit_and_confirm(
            self.client,
            [ix],
            self.payer,
            compute_unit_limit=compute_unit_limit,
            compute_unit_price_micro_lamports=compute_unit_price_micro_lamports,
        )

    def cancel_order(self, market: Pubkey, order: Pubkey, position: Pubkey) -> str:
        data = self._get_discriminator("cancel_order")
        keys = [
            AccountMeta(market, False, True),
            AccountMeta(order, False, True),
            AccountMeta(position, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
        ]
        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    def cancel_order_by_seq(self, market: Pubkey, seq: int) -> str:
        order_pda, _ = derive_order_pda(market, self.payer.pubkey(), seq, self.program_id)
        pos_pda, _ = derive_position_pda(market, self.payer.pubkey(), self.program_id)
        return self.cancel_order(market, order_pda, pos_pda)

    def claim_refunds(
        self,
        market: Pubkey,
        position: Pubkey,
        quote_vault: Pubkey,
        amount_atoms: int,
        owner_quote_ata: Optional[Pubkey] = None,
        quote_mint: Optional[Pubkey] = None,
    ) -> str:
        if not owner_quote_ata:
            if not quote_mint:
                raise ValueError("Must provide quote_mint to auto-derive ATA")
            owner_quote_ata = ensure_ata(self.client, self.payer, self.payer.pubkey(), quote_mint)

        data = self._get_discriminator("claim_refunds")
        data += struct.pack("<Q", amount_atoms)

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(position, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(quote_vault, False, True),
            AccountMeta(owner_quote_ata, False, True),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    def redeem(
        self,
        market: Pubkey,
        position: Pubkey,
        quote_vault: Pubkey,
        owner_quote_ata: Optional[Pubkey] = None,
        quote_mint: Optional[Pubkey] = None,
    ) -> str:
        if not owner_quote_ata:
            if not quote_mint:
                raise ValueError("Must provide quote_mint to auto-derive ATA")
            owner_quote_ata = ensure_ata(self.client, self.payer, self.payer.pubkey(), quote_mint)

        data = self._get_discriminator("redeem")

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(position, False, True),
            AccountMeta(self.payer.pubkey(), True, True),
            AccountMeta(quote_vault, False, True),
            AccountMeta(owner_quote_ata, False, True),
            AccountMeta(TOKEN_PROGRAM_ID, False, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        return submit_and_confirm(self.client, [ix], self.payer)

    # -------------------------------------------------------------------------
    # Resolution Flow
    # -------------------------------------------------------------------------

    def resolve_market(
        self,
        market: Pubkey,
        outcome: MarketOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
        oracle_keypair: Optional[Keypair] = None,
    ) -> str:
        if len(proof_hash) != 32 or len(public_inputs_hash) != 32:
            raise ValueError("proof_hash and public_inputs_hash must be 32 bytes each")

        oracle = oracle_keypair or self.payer

        data = self._get_discriminator("resolve_market")
        data += struct.pack("B", self._outcome_index(outcome))
        data += proof_hash
        data += public_inputs_hash

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(oracle.pubkey(), True, False),
        ]

        ix = Instruction(self.program_id, data, keys)
        extra_signers = [oracle] if oracle.pubkey() != self.payer.pubkey() else None
        return submit_and_confirm(self.client, [ix], self.payer, signers=extra_signers)

    def resolve_market_signed(
        self,
        market: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        oracle_keypair: Keypair,
        outcome: MarketOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
        relayer_keypair: Optional[Keypair] = None,
    ) -> str:
        if len(resolver_hash) != 32:
            raise ValueError("resolver_hash must be 32 bytes")
        if len(proof_hash) != 32 or len(public_inputs_hash) != 32:
            raise ValueError("proof_hash and public_inputs_hash must be 32 bytes each")

        msg = self._build_resolve_message_v1(
            market=market,
            resolver_hash=resolver_hash,
            open_ts=open_ts,
            outcome=outcome,
            proof_hash=proof_hash,
            public_inputs_hash=public_inputs_hash,
        )
        sig_bytes = bytes(oracle_keypair.sign_message(msg))
        ed_ix = build_ed25519_ix(msg, sig_bytes, bytes(oracle_keypair.pubkey()))

        data = self._get_discriminator("resolve_market_signed")
        data += struct.pack("B", self._outcome_index(outcome))
        data += proof_hash
        data += public_inputs_hash
        data += sig_bytes

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(SYSVAR_INSTRUCTIONS_ID, False, False),
        ]

        resolve_ix = Instruction(self.program_id, data, keys)

        payer = relayer_keypair or self.payer
        return submit_and_confirm(self.client, [ed_ix, resolve_ix], payer, signers=None)

    def resolve_market_threshold(
        self,
        market: Pubkey,
        notary_config: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        resolve_ts: int,
        outcome: MarketOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
        notary_keypairs: Sequence[Keypair],
        relayer_keypair: Optional[Keypair] = None,
    ) -> str:
        if len(resolver_hash) != 32:
            raise ValueError("resolver_hash must be 32 bytes")
        if len(proof_hash) != 32 or len(public_inputs_hash) != 32:
            raise ValueError("proof_hash and public_inputs_hash must be 32 bytes each")
        if not notary_keypairs:
            raise ValueError("at least one notary keypair is required")

        msg = self._build_resolve_message_v2(
            market=market,
            notary_config=notary_config,
            resolver_hash=resolver_hash,
            open_ts=open_ts,
            resolve_ts=resolve_ts,
            outcome=outcome,
            proof_hash=proof_hash,
            public_inputs_hash=public_inputs_hash,
        )

        ed_ixs: List[Instruction] = []
        for kp in notary_keypairs:
            sig_bytes = bytes(kp.sign_message(msg))
            ed_ixs.append(build_ed25519_ix(msg, sig_bytes, bytes(kp.pubkey())))

        data = self._get_discriminator("resolve_market_threshold")
        data += struct.pack("B", self._outcome_index(outcome))
        data += proof_hash
        data += public_inputs_hash

        keys = [
            AccountMeta(market, False, True),
            AccountMeta(notary_config, False, False),
            AccountMeta(SYSVAR_INSTRUCTIONS_ID, False, False),
        ]

        resolve_ix = Instruction(self.program_id, data, keys)

        payer = relayer_keypair or self.payer
        return submit_and_confirm(self.client, [*ed_ixs, resolve_ix], payer, signers=None)

    def resolve_claim_signed(
        self,
        claim: Pubkey,
        outcome: ClaimOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
        oracle_keypair: Keypair,
        relayer_keypair: Optional[Keypair] = None,
    ) -> str:
        if len(proof_hash) != 32 or len(public_inputs_hash) != 32:
            raise ValueError("proof_hash and public_inputs_hash must be 32 bytes each")

        claim_acc = self.fetch_claim(claim)
        if claim_acc is None:
            raise ValueError(f"Claim {claim} not found")
        if oracle_keypair.pubkey() != claim_acc.oracle_authority:
            raise ValueError("oracle_keypair does not match claim.oracle_authority")

        msg = self._build_claim_resolve_message_v1(
            claim=claim,
            resolver_hash=claim_acc.resolver_hash,
            issuer=claim_acc.issuer,
            claim_id=claim_acc.claim_id,
            resolve_ts=claim_acc.resolve_ts,
            outcome=outcome,
            proof_hash=proof_hash,
            public_inputs_hash=public_inputs_hash,
        )

        sig_bytes = bytes(oracle_keypair.sign_message(msg))
        ed_ix = build_ed25519_ix(msg, sig_bytes, bytes(oracle_keypair.pubkey()))

        data = self._get_discriminator("resolve_claim_signed")
        data += struct.pack("B", self._claim_outcome_index(outcome))
        data += proof_hash
        data += public_inputs_hash
        data += sig_bytes

        keys = [
            AccountMeta(claim, False, True),
            AccountMeta(SYSVAR_INSTRUCTIONS_ID, False, False),
        ]
        resolve_ix = Instruction(self.program_id, data, keys)

        payer = relayer_keypair or self.payer
        return submit_and_confirm(self.client, [ed_ix, resolve_ix], payer, signers=None)

    def resolve_claim_threshold(
        self,
        claim: Pubkey,
        notary_config: Pubkey,
        outcome: ClaimOutcome,
        proof_hash: bytes,
        public_inputs_hash: bytes,
        notary_keypairs: Sequence[Keypair],
        relayer_keypair: Optional[Keypair] = None,
    ) -> str:
        if len(proof_hash) != 32 or len(public_inputs_hash) != 32:
            raise ValueError("proof_hash and public_inputs_hash must be 32 bytes each")
        if not notary_keypairs:
            raise ValueError("at least one notary keypair is required")

        claim_acc = self.fetch_claim(claim)
        if claim_acc is None:
            raise ValueError(f"Claim {claim} not found")
        if notary_config == Pubkey.default():
            raise ValueError("notary_config must not be default pubkey")
        if claim_acc.notary_config != Pubkey.default() and claim_acc.notary_config != notary_config:
            raise ValueError("provided notary_config does not match claim.notary_config")

        msg = self._build_claim_resolve_message_v2(
            claim=claim,
            notary_config=notary_config,
            resolver_hash=claim_acc.resolver_hash,
            issuer=claim_acc.issuer,
            claim_id=claim_acc.claim_id,
            resolve_ts=claim_acc.resolve_ts,
            outcome=outcome,
            proof_hash=proof_hash,
            public_inputs_hash=public_inputs_hash,
        )

        ed_ixs: List[Instruction] = []
        for kp in notary_keypairs:
            sig_bytes = bytes(kp.sign_message(msg))
            ed_ixs.append(build_ed25519_ix(msg, sig_bytes, bytes(kp.pubkey())))

        data = self._get_discriminator("resolve_claim_threshold")
        data += struct.pack("B", self._claim_outcome_index(outcome))
        data += proof_hash
        data += public_inputs_hash

        keys = [
            AccountMeta(claim, False, True),
            AccountMeta(notary_config, False, False),
            AccountMeta(SYSVAR_INSTRUCTIONS_ID, False, False),
        ]
        resolve_ix = Instruction(self.program_id, data, keys)

        payer = relayer_keypair or self.payer
        return submit_and_confirm(self.client, [*ed_ixs, resolve_ix], payer, signers=None)
