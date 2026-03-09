import time
import logging
from typing import List, Optional
from solana.rpc.api import Client
from solana.rpc.types import TxOpts
from solana.rpc.commitment import Confirmed
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
from solders.message import MessageV0
from solders.instruction import Instruction
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price

logger = logging.getLogger(__name__)


def _status_is_confirmed(conf) -> bool:
    if isinstance(conf, str):
        return conf in ["confirmed", "finalized"]
    return str(conf) in ["confirmed", "finalized"]

def submit_and_confirm(
    client: Client,
    instructions: List[Instruction],
    payer: Keypair,
    signers: List[Keypair] = None,
    timeout_s: int = 30,
    compute_unit_limit: Optional[int] = None,
    compute_unit_price_micro_lamports: Optional[int] = None,
    skip_preflight: bool = False,
) -> str:
    # 1. Prepend Compute Budget Instructions if requested
    final_ixs = []
    
    if compute_unit_limit is not None:
        final_ixs.append(set_compute_unit_limit(compute_unit_limit))
        
    if compute_unit_price_micro_lamports is not None:
        final_ixs.append(set_compute_unit_price(compute_unit_price_micro_lamports))
        
    final_ixs.extend(instructions)

    # 2. Deduplicate signers by pubkey bytes (not object hashability/identity)
    all_signers: List[Keypair] = []
    seen_signers = set()
    for s in [payer] + (signers or []):
        signer_key = bytes(s.pubkey())
        if signer_key in seen_signers:
            continue
        seen_signers.add(signer_key)
        all_signers.append(s)
    
    last_err = None
    for attempt in range(4):
        try:
            blockhash_resp = client.get_latest_blockhash(commitment=Confirmed)
            blockhash = blockhash_resp.value.blockhash
            
            msg = MessageV0.try_compile(
                payer=payer.pubkey(),
                instructions=final_ixs,
                address_lookup_table_accounts=[],
                recent_blockhash=blockhash
            )
            
            tx = VersionedTransaction(msg, all_signers)
            
            send_resp = client.send_raw_transaction(
                bytes(tx),
                opts=TxOpts(
                    skip_preflight=skip_preflight,
                    preflight_commitment=Confirmed,
                ),
            )
            sig = send_resp.value

            logger.info(f"Tx sent: {sig}. Confirming transaction...")

            try:
                client.confirm_transaction(sig, commitment=Confirmed)
                return str(sig)
            except Exception as confirm_err:
                logger.warning(f"RPC confirm_transaction failed for sig {sig}: {confirm_err}")

            start = time.time()
            saw_success_status = False
            while time.time() - start < timeout_s:
                time.sleep(1)
                statuses = client.get_signature_statuses([sig], search_transaction_history=True)
                if statuses.value and statuses.value[0]:
                    status = statuses.value[0]
                    if status.err:
                        raise RuntimeError(f"Transaction failed on-chain: {status.err}")

                    saw_success_status = True
                    if _status_is_confirmed(status.confirmation_status):
                        return str(sig)

            if saw_success_status:
                logger.warning(f"Confirmation timed out for sig {sig}, but the transaction reached the validator")
                return str(sig)

            logger.warning(f"Timeout waiting for sig {sig}")

        except Exception as e:
            logger.warning(f"Attempt {attempt+1} failed: {e}")
            last_err = e
            time.sleep(1)
    
    raise RuntimeError(f"Failed to submit tx after retries: {last_err}")
