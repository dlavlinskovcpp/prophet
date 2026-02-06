import struct
from solders.instruction import Instruction
from solders.pubkey import Pubkey

ED25519_PROGRAM_ID = Pubkey.from_string("Ed25519SigVerify111111111111111111111111111")

def build_ed25519_ix(
    message: bytes, 
    signature: bytes, 
    pubkey_bytes: bytes
) -> Instruction:
    pk_offset = 16
    sig_offset = 16 + 32 # 48
    msg_offset = 16 + 32 + 64 # 112
    msg_len = len(message)
    
    header = struct.pack("<BBHHHHHHH", 
        1, 0, 
        sig_offset, 0xFFFF, 
        pk_offset, 0xFFFF, 
        msg_offset, msg_len, 0xFFFF
    )
    
    data = header + pubkey_bytes + signature + message
    
    # solders Instruction(program_id, data, accounts)
    return Instruction(
        ED25519_PROGRAM_ID,
        data,
        [] 
    )