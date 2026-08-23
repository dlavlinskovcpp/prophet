import hashlib, struct
import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from prophet_sdk.pdas import derive_market_pda, derive_notary_config_snapshot_pda
from prophet_sdk.settlement_message import build_resolution_message_v2
from src.signer_authorization import *
from src.verifier_attestation import VerifierAttestationSigner, settlement_authorization_job_id

H=lambda n:f"{n:02x}"*32
PROGRAM=str(Pubkey.from_bytes(bytes([9])*32)); CREATOR=str(Pubkey.from_bytes(bytes([8])*32)); ADMIN=str(Pubkey.from_bytes(bytes([7])*32)); GEN=H(6)
class Rpc:
 def __init__(self, accounts, genesis=GEN, time=20):
  self.accounts,self.g,self.time,self.block_time_calls=accounts,genesis,time,0
  self.finalized_slot_value=1; self.probe_context_slot=1; self.snapshot_context_slot=1
  self.probe_accounts=accounts; self.snapshot_accounts=accounts; self.account_read_calls=0; self.block_time_slots=[]
 def genesis_hash(self): return self.g
 def finalized_slot(self): return self.finalized_slot_value
 def block_time(self, slot): self.block_time_calls+=1; self.block_time_slots.append(slot); return self.time
 def finalized_account(self,p,*,min_context_slot):
  self.account_read_calls+=1; return FinalizedAccountRead(self.probe_accounts.get(p),self.probe_context_slot)
 def finalized_accounts(self,ps,*,min_context_slot):
  self.account_read_calls+=1; return FinalizedAccountsRead({p:self.snapshot_accounts.get(p) for p in ps},self.snapshot_context_slot)
def notary(a,b):
 p,bump=derive_notary_config_snapshot_pda(Pubkey.from_string(ADMIN),1,Pubkey.from_string(PROGRAM)); d=bytes(Pubkey.from_string(ADMIN))+bytes((2,2,bump))+bytes(5)+struct.pack('<Q',1)+bytes(Pubkey.from_string(a))+bytes(Pubkey.from_string(b))+bytes(30*32)
 return str(p),hashlib.sha256(b'account:NotaryConfig').digest()[:8]+d
def market(cfg,open_ts=10,lock_ts=10,resolve_ts=20):
 rh=bytes.fromhex(H(1)); p,bump=derive_market_pda(Pubkey.from_string(CREATOR),rh,open_ts,0,Pubkey.from_string(PROGRAM)); keys=[bytes(32)]*5+[bytes(Pubkey.from_string(cfg))]; d=b''.join(keys)+rh+bytes(64)+struct.pack('<qqqq',open_ts,lock_ts,resolve_ts,0)+bytes(32)+bytes(8)+bytes(4)+bytes(6)+bytes((0,0,0,bump,0))+bytes(Pubkey.from_string(CREATOR))+struct.pack('<Q',0)
 return str(p),hashlib.sha256(b'account:Market').digest()[:8]+d+bytes(1)
def fixture(open_ts=10,lock_ts=10,resolve_ts=20):
 na,nb=Keypair.from_seed(bytes(range(32))),Keypair.from_seed(bytes(range(32,64))); va,vb=Keypair.from_seed(bytes(range(64,96))),Keypair.from_seed(bytes(range(96,128))); cfg,cfgd=notary(str(na.pubkey()),str(nb.pubkey())); m,md=market(cfg,open_ts,lock_ts,resolve_ts)
 binding={"cluster_genesis_hash":GEN,"program_id":PROGRAM,"market":m,"resolver_definition_hash":H(1),"evidence_hash":H(2),"proof_hash":H(3),"public_inputs_hash":H(4)}; job=settlement_authorization_job_id(binding)
 def att(k,id,d):
  s=VerifierAttestationSigner(id,'1.0.0',d,k); payload={"attestation_schema":"prophet.verifier-attestation.v1","attestation_version":"1","verifier_id":id,"verifier_version":"1.0.0","verifier_implementation_digest":d,"job_id":job,**binding,"outcome":"YES","acquired_at_ms":"10","valid_until_ms":"30"}; return s.sign(payload,now_ms=20).as_transport(),VerifierPin(str(k.pubkey()),id,'1.0.0',d)
 aa,pa=att(va,'a',H(5)); ab,pb=att(vb,'b',H(6)); request={"schema":AUTHORIZATION_SCHEMA,"version":"1",**{k:binding[k] for k in ('cluster_genesis_hash','program_id','market')},"verifier_a_attestation":aa,"verifier_b_attestation":ab}; config=SignerAuthorizationConfig('A',str(na.pubkey()),str(nb.pubkey()),pa,pb,GEN,PROGRAM); rpc=Rpc({m:Account(PROGRAM,md),cfg:Account(PROGRAM,cfgd)})
 return request,config,rpc,m,cfg
def test_authorizes_a_and_b_with_identical_frozen_message():
 r,c,rpc,m,cfg=fixture(); a=authorize(request=r,config=c,rpc=rpc,now_ms=20); b=authorize(request=r,config=SignerAuthorizationConfig('B',c.counterpart_notary_public_key,c.own_notary_public_key,c.verifier_a,c.verifier_b,GEN,PROGRAM),rpc=rpc,now_ms=20)
 assert a.market==m and a.notary_config==cfg and len(a.canonical_message_bytes)==235 and a.canonical_message_bytes==b.canonical_message_bytes
 assert a.canonical_message_bytes==build_resolution_message_v2(program_id=PROGRAM,market=m,notary_config=cfg,resolver_hash=bytes.fromhex(H(1)),open_ts=10,resolve_ts=20,notary_config_version=1,outcome='YES',proof_hash=bytes.fromhex(H(3)),public_inputs_hash=bytes.fromhex(H(4)))
@pytest.mark.parametrize('mutate',[lambda r,c,x:r.update(cluster_genesis_hash=H(9)),lambda r,c,x:r['verifier_a_attestation'].update(signature_hex='00'*64),lambda r,c,x:r['verifier_b_attestation']['payload'].update(outcome='NO'),lambda r,c,x:setattr(x,'g',H(9)),lambda r,c,x:x.accounts.pop(r['market']),lambda r,c,x:x.accounts.__setitem__(r['market'],Account('11111111111111111111111111111111',x.accounts[r['market']].data)),lambda r,c,x:setattr(x,'time',19)])
def test_rejects_untrusted_or_invalid_authorization_inputs(mutate):
 r,c,rpc,*_=fixture(); mutate(r,c,rpc)
 with pytest.raises(SignerAuthorizationError): authorize(request=r,config=c,rpc=rpc,now_ms=20)


def _reject(request, config, rpc):
 with pytest.raises(SignerAuthorizationError):
  authorize(request=request,config=config,rpc=rpc,now_ms=20)


def _replace_data(rpc, address, offset, value):
 data=bytearray(rpc.accounts[address].data)
 data[offset:offset+len(value)]=value
 rpc.accounts[address]=Account(rpc.accounts[address].owner,bytes(data))


@pytest.mark.parametrize("mutation", [
 lambda r,c,rpc,m,n: rpc.accounts.pop(n),
 lambda r,c,rpc,m,n: rpc.accounts.__setitem__(n,Account("11111111111111111111111111111111",rpc.accounts[n].data)),
 lambda r,c,rpc,m,n: _replace_data(rpc,n,0,b"bad-not!"),
 lambda r,c,rpc,m,n: rpc.accounts.__setitem__(n,Account(PROGRAM,rpc.accounts[n].data[:-1])),
 lambda r,c,rpc,m,n: rpc.accounts.__setitem__(n,Account(PROGRAM,rpc.accounts[n].data+b"x")),
 lambda r,c,rpc,m,n: _replace_data(rpc,n,41,b"\x21"),
 lambda r,c,rpc,m,n: _replace_data(rpc,n,42,b"\x00"),
 lambda r,c,rpc,m,n: _replace_data(rpc,n,48,struct.pack("<Q",2)),
], ids=["missing","wrong_owner","wrong_discriminator","truncated","trailing","invalid_count","wrong_bump","wrong_version"])
def test_rejects_malformed_or_noncanonical_notary_snapshot(mutation):
 r,c,rpc,m,n=fixture(); mutation(r,c,rpc,m,n); _reject(r,c,rpc)


@pytest.mark.parametrize("threshold,count,keys", [
 (1,2,"expected"), (2,1,"expected"), (2,3,"expected"),
 (2,2,"own_missing"), (2,2,"counterpart_missing"),
 (2,2,"duplicate_a"), (2,2,"duplicate_b"), (2,2,"unexpected"),
], ids=["threshold_one","count_one","count_three","own_missing","counterpart_missing","a_a","b_b","unexpected"])
def test_rejects_non_2_of_2_notary_membership(threshold,count,keys):
 r,c,rpc,m,n=fixture(); data=bytearray(rpc.accounts[n].data); data[40]=threshold; data[41]=count
 other=str(Keypair.from_seed(bytes([1])*32).pubkey())
 pair={
  "expected":(c.own_notary_public_key,c.counterpart_notary_public_key),
  "own_missing":(other,c.counterpart_notary_public_key),
  "counterpart_missing":(c.own_notary_public_key,other),
  "duplicate_a":(c.own_notary_public_key,c.own_notary_public_key),
  "duplicate_b":(c.counterpart_notary_public_key,c.counterpart_notary_public_key),
  "unexpected":(c.own_notary_public_key,other),
 }[keys]
 data[56:88]=bytes(Pubkey.from_string(pair[0])); data[88:120]=bytes(Pubkey.from_string(pair[1]))
 if count==3: data[120:152]=bytes(Pubkey.from_string(other))
 rpc.accounts[n]=Account(PROGRAM,bytes(data)); _reject(r,c,rpc)


def test_notary_member_order_is_irrelevant_for_2_of_2_snapshot():
 r,c,rpc,m,n=fixture(); data=bytearray(rpc.accounts[n].data)
 data[56:88]=bytes(Pubkey.from_string(c.counterpart_notary_public_key)); data[88:120]=bytes(Pubkey.from_string(c.own_notary_public_key))
 rpc.accounts[n]=Account(PROGRAM,bytes(data))
 assert authorize(request=r,config=c,rpc=rpc,now_ms=20).market == m


@pytest.mark.parametrize("mutation", [
 lambda r,c,rpc,m,n: rpc.accounts.pop(m),
 lambda r,c,rpc,m,n: rpc.accounts.__setitem__(m,Account("11111111111111111111111111111111",rpc.accounts[m].data)),
 lambda r,c,rpc,m,n: _replace_data(rpc,m,0,b"bad-mark"),
 lambda r,c,rpc,m,n: rpc.accounts.__setitem__(m,Account(PROGRAM,rpc.accounts[m].data[:-1])),
 lambda r,c,rpc,m,n: rpc.accounts.__setitem__(m,Account(PROGRAM,rpc.accounts[m].data+b"x")),
], ids=["missing","wrong_owner","wrong_discriminator","truncated","trailing"])
def test_rejects_malformed_market_account(mutation):
 r,c,rpc,m,n=fixture(); mutation(r,c,rpc,m,n); _reject(r,c,rpc)


@pytest.mark.parametrize("offset,value", [
 (375,bytes(Pubkey.from_string(str(Keypair.from_seed(bytes([2])*32).pubkey())))),
 (407,struct.pack("<Q",1)),
 (200,b"\xff"),
 (296,struct.pack("<q",9)),
 (371,b"\x02"),
 (372,b"\x01"),
 (373,b"\x00"),
 (224,b"\x01"),
 (256,b"\x01"),
], ids=["creator","nonce","resolver_hash","open_schedule","resolved_status","outcome","bump","proof","inputs"])
def test_rejects_market_security_field_mutations(offset,value):
 r,c,rpc,m,n=fixture(); _replace_data(rpc,m,8+offset,value); _reject(r,c,rpc)


@pytest.mark.parametrize("status,outcome,resolved_ts,proof,inputs", [
 (2,1,20,b"\0"*32,b"\0"*32), (2,2,20,b"\0"*32,b"\0"*32),
 (2,3,20,b"\0"*32,b"\0"*32), (2,0,0,b"\0"*32,b"\0"*32),
 (0,0,0,b"\1"+b"\0"*31,b"\0"*32), (0,0,0,b"\0"*32,b"\1"+b"\0"*31),
], ids=["resolved_yes","resolved_no","resolved_invalid","resolved_undecided","proof_only","inputs_only"])
def test_rejects_resolved_or_partially_resolved_market(status,outcome,resolved_ts,proof,inputs):
 r,c,rpc,m,n=fixture(); _replace_data(rpc,m,8+371,bytes((status,outcome))); _replace_data(rpc,m,8+312,struct.pack("<q",resolved_ts)); _replace_data(rpc,m,8+224,proof); _replace_data(rpc,m,8+256,inputs); _reject(r,c,rpc)


@pytest.mark.parametrize("invalid_status", [3, 255])
def test_rejects_unknown_market_status_values(invalid_status):
 r,c,rpc,m,n=fixture(); _replace_data(rpc,m,8+371,bytes((invalid_status,))); _reject(r,c,rpc)


@pytest.mark.parametrize("invalid_outcome", [4, 255])
def test_rejects_unknown_market_outcome_values(invalid_outcome):
 r,c,rpc,m,n=fixture(); _replace_data(rpc,m,8+372,bytes((invalid_outcome,))); _reject(r,c,rpc)


def test_authorizes_legitimate_current_pre_activity_resolve_timestamp():
 r,c,rpc,m,n=fixture(); _replace_data(rpc,m,8+304,struct.pack("<q",21)); rpc.time=21
 result=authorize(request=r,config=c,rpc=rpc,now_ms=20)
 assert len(result.canonical_message_bytes)==235


def test_rejects_notary_snapshot_data_substituted_at_market_pinned_address():
 r,c,rpc,m,n=fixture(); other_admin=str(Keypair.from_seed(bytes([3])*32).pubkey()); other,bump=derive_notary_config_snapshot_pda(Pubkey.from_string(other_admin),1,Pubkey.from_string(PROGRAM))
 data=bytearray(rpc.accounts[n].data); data[8:40]=bytes(Pubkey.from_string(other_admin)); data[42]=bump
 rpc.accounts[n]=Account(PROGRAM,bytes(data))
 _reject(r,c,rpc)


@pytest.mark.parametrize("time", [None,True,False,-1,0,19,1.0,"1",b"1"])
def test_rejects_malformed_or_too_early_finalized_time(time):
 r,c,rpc,*_=fixture(); rpc.time=time; _reject(r,c,rpc)


def test_rejects_boolean_block_time_for_valid_low_resolve_timestamp_market():
 r,c,rpc,*_=fixture(open_ts=0,lock_ts=0,resolve_ts=0); rpc.time=True; _reject(r,c,rpc)


def test_rejects_unavailable_finalized_slot():
 r,c,rpc,*_=fixture()
 rpc.finalized_slot=lambda: None
 _reject(r,c,rpc)
 assert rpc.block_time_calls == 0
 assert rpc.account_read_calls == 0


@pytest.mark.parametrize("slot", [-1, True, "1"])
def test_rejects_malformed_finalized_slot(slot):
 r,c,rpc,*_=fixture(); rpc.finalized_slot=lambda: slot
 _reject(r,c,rpc)
 assert rpc.block_time_calls == 0
 assert rpc.account_read_calls == 0


@pytest.mark.parametrize("time", [20,21])
def test_authorizes_at_or_after_finalized_resolve_timestamp(time):
 r,c,rpc,*_=fixture(); rpc.time=time
 assert authorize(request=r,config=c,rpc=rpc,now_ms=20).canonical_message_bytes


@pytest.mark.parametrize("field,value", [
 ("probe_context_slot",None), ("probe_context_slot",True), ("probe_context_slot","2"),
 ("probe_context_slot",0), ("snapshot_context_slot",None),
 ("snapshot_context_slot",True), ("snapshot_context_slot","2"), ("snapshot_context_slot",0),
], ids=["probe_missing","probe_bool","probe_string","probe_below_floor","snapshot_missing","snapshot_bool","snapshot_string","snapshot_below_floor"])
def test_rejects_missing_malformed_or_stale_finalized_account_context(field,value):
 r,c,rpc,*_=fixture(); rpc.finalized_slot_value=1; setattr(rpc,field,value); _reject(r,c,rpc)
 assert rpc.block_time_calls == 0


def test_rejects_context_free_authorization_read():
 r,c,rpc,m,*_=fixture(); rpc.finalized_account=lambda p,*,min_context_slot: rpc.accounts[p]
 _reject(r,c,rpc)
 assert rpc.block_time_calls == 0


def test_rejects_shared_snapshot_context_below_probe_context():
 r,c,rpc,*_=fixture(); rpc.finalized_slot_value=1; rpc.probe_context_slot=2; rpc.snapshot_context_slot=1
 _reject(r,c,rpc)
 assert rpc.block_time_calls == 0


@pytest.mark.parametrize("missing", ["market", "notary"])
def test_rejects_missing_account_from_authoritative_shared_snapshot(missing):
 r,c,rpc,m,n=fixture(); rpc.snapshot_accounts=dict(rpc.accounts); rpc.snapshot_accounts.pop(m if missing == "market" else n)
 _reject(r,c,rpc)
 assert rpc.block_time_calls == 0


def test_rejects_market_notary_change_between_probe_and_authoritative_snapshot():
 r,c,rpc,m,n=fixture(); other_admin=str(Keypair.from_seed(bytes([4])*32).pubkey()); other,bump=derive_notary_config_snapshot_pda(Pubkey.from_string(other_admin),1,Pubkey.from_string(PROGRAM))
 data=bytearray(rpc.accounts[n].data); data[8:40]=bytes(Pubkey.from_string(other_admin)); data[42]=bump
 alternate_market=bytearray(rpc.accounts[m].data); alternate_market[8+160:8+192]=bytes(other)
 rpc.snapshot_accounts=dict(rpc.accounts); rpc.snapshot_accounts[m]=Account(PROGRAM,bytes(alternate_market))
 _reject(r,c,rpc)
 assert rpc.block_time_calls == 0


def test_binds_block_time_to_authoritative_shared_snapshot_slot():
 r,c,rpc,*_=fixture(); rpc.finalized_slot_value=5; rpc.probe_context_slot=6; rpc.snapshot_context_slot=7
 assert authorize(request=r,config=c,rpc=rpc,now_ms=20).canonical_message_bytes
 assert rpc.block_time_slots == [7]
