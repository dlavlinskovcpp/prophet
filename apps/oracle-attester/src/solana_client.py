# apps/oracle-attester/src/solana_client.py
import base64
import hashlib
import struct
from typing import Optional, List

from construct import Bytes, Int8ul, Int16ul, Int32ul, Int64sl, Struct as CStruct
from borsh_construct import CStruct as BStruct, U8, U16, U32, U64, I64
from solders.instruction import Instruction, AccountMeta
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.sysvar import INSTRUCTIONS as SYSVAR_INSTRUCTIONS_ID
from solders.hash import Hash
from solders.message import MessageV0
from solders.transaction import VersionedTransaction

from solana.rpc.api import Client
from solana.rpc.types import TxOpts
from solana.rpc.commitment import Confirmed

from .config import settings


# Borsh layout for Market account data (excluding discriminator)
MarketLayout = BStruct(
    "authority" / Bytes(32),
    "oracle_authority" / Bytes(32),
    "quote_mint" / Bytes(32),
    "quote_vault" / Bytes(32),
    "notary_config" / Bytes(32),
    "resolver_hash" / Bytes(32),
    "proof_hash" / Bytes(32),
    "public_inputs_hash" / Bytes(32),
    "open_ts" / I64,
    "lock_ts" / I64,
    "resolve_ts" / I64,
    "resolved_ts" / I64,
    "min_order_qty_atoms" / U64,
    "min_escrow_atoms" / U64,
    "next_order_seq" / U64,
    "open_orders_total" / U32,
    "max_open_orders_total" / U32,
    "max_open_orders_per_user" / U16,
    "quote_decimals" / U8,
    "status" / U8,
    "outcome" / U8,
    "bump" / U8,
)


class SolanaClient:
    def __init__(self):
        self.client = Client(settings.RPC_URL)
        self.program_id = Pubkey.from_string(settings.PROPHET_PROGRAM_ID)

        self.oracle_kp = self.load_keypair(settings.ORACLE_KEYPAIR_PATH)
        self.relayer_kp = self.load_keypair(settings.RELAYER_KEYPAIR_PATH) if settings.RELAYER_KEYPAIR_PATH else None

    def load_keypair(self, path: str) -> Keypair:
        with open(path, "r") as f:
            return Keypair.from_bytes(bytes(__import__("json").load(f)))

    def extract_account_bytes(self, account_data) -> bytes:
        if isinstance(account_data, (list, tuple)):
            b64 = account_data[0]
            return base64.b64decode(b64)
        if isinstance(account_data, str):
            return base64.b64decode(account_data)
        raise ValueError("Unknown account data format")

    def get_discriminator(self, namespace: str, name: str) -> bytes:
        preimage = f"{namespace}:{name}".encode("utf-8")
        return hashlib.sha256(preimage).digest()[:8]

    def get_chain_time(self) -> int:
        slot = self.client.get_slot().value
        bt = self.client.get_block_time(slot).value
        if bt is None:
            raise RuntimeError("No block time available")
        return int(bt)

    def get_market_state_full(self, market: Pubkey) -> Optional[dict]:
        resp = self.client.get_account_info(market, commitment=Confirmed)
        if not resp.value:
            return None
        raw_bytes = self.extract_account_bytes(resp.value.data)
        if len(raw_bytes) < 8:
            raise ValueError("Market account data too short")

        parsed = MarketLayout.parse(raw_bytes[8:])

        return {
            "oracle_authority": Pubkey.from_bytes(parsed.oracle_authority),
            "notary_config": Pubkey.from_bytes(parsed.notary_config),
            "resolver_hash": bytes(parsed.resolver_hash),
            "open_ts": parsed.open_ts,
            "lock_ts": parsed.lock_ts,
            "resolve_ts": parsed.resolve_ts,
            "resolved_ts": parsed.resolved_ts,
            "status": parsed.status,
            "proof_hash": bytes(parsed.proof_hash),
            "public_inputs_hash": bytes(parsed.public_inputs_hash)
        }

    def get_notary_config(self, cfg_pubkey: Pubkey) -> Optional[dict]:
        resp = self.client.get_account_info(cfg_pubkey, commitment=Confirmed)
        if not resp.value:
            return None
        raw_bytes = self.extract_account_bytes(resp.value.data)
        if len(raw_bytes) < 8:
            raise ValueError("NotaryConfig account data too short")
        data = raw_bytes[8:]

        # Layout (borsh):
        # admin: [0..32)
        # threshold: [32]
        # notary_count: [33]
        # bump: [34]
        # reserved0: [35..40)
        # version: u64 [40..48)
        # notary_keys: MAX_NOTARIES * 32 starting at 48
        if len(data) < 48:
            raise ValueError("NotaryConfig account data too short (header)")

        admin = Pubkey.from_bytes(data[0:32])
        threshold = data[32]
        notary_count = data[33]
        bump = data[34]
        version = struct.unpack_from("<Q", data, 40)[0]

        keys = []
        offset = 48
        for i in range(int(notary_count)):
            start = offset + i * 32
            end = start + 32
            if end > len(data):
                break
            keys.append(Pubkey.from_bytes(data[start:end]))

        return {
            "admin": admin,
            "threshold": threshold,
            "notary_count": notary_count,
            "bump": bump,
            "version": version,
            "notary_keys": keys,
        }

    def sha256_digest(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def build_ed25519_ix(self, msg: bytes, sig: bytes, pk: bytes) -> Instruction:
        # Manual ed25519 program ix:
        # header (16) + pubkey(32) + signature(64) + message(len)
        pk_offset = 16
        sig_offset = 48
        msg_offset = 112
        msg_size = len(msg)

        header = struct.pack(
            "<BBHHHHHH",
            1,      # num_sigs
            0,      # padding
            sig_offset, 0xFFFF,
            pk_offset,  0xFFFF,
            msg_offset, msg_size
        ) + struct.pack("<H", 0xFFFF)

        data = header + pk + sig + msg

        return Instruction(
            program_id=Pubkey.from_string("Ed25519SigVerify111111111111111111111111111"),
            accounts=[],
            data=data
        )

    def build_resolve_threshold_ix(
        self,
        market: Pubkey,
        notary_config: Pubkey,
        outcome_idx: int,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> Instruction:
        discriminator = self.get_discriminator("global", "resolve_market_threshold")

        data = discriminator
        data += struct.pack("B", outcome_idx)
        data += proof_hash
        data += public_inputs_hash

        accounts = [
            AccountMeta(pubkey=market, is_signer=False, is_writable=True),
            AccountMeta(pubkey=notary_config, is_signer=False, is_writable=False),
            AccountMeta(pubkey=SYSVAR_INSTRUCTIONS_ID, is_signer=False, is_writable=False),
        ]

        return Instruction(program_id=self.program_id, accounts=accounts, data=data)

    def submit_and_confirm(self, ixs: List[Instruction], payer: Keypair) -> str:
        latest = self.client.get_latest_blockhash().value
        blockhash = Hash.from_string(latest.blockhash)

        msg = MessageV0.try_compile(
            payer=payer.pubkey(),
            instructions=ixs,
            address_lookup_table_accounts=[],
            recent_blockhash=blockhash
        )

        tx = VersionedTransaction(msg, [payer])

        resp = self.client.send_raw_transaction(
            bytes(tx),
            opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed)
        )
        sig = resp.value

        self.client.confirm_transaction(sig, commitment=Confirmed)

        return str(sig)
