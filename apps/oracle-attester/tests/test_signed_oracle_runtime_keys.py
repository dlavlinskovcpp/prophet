import pytest
from src.signed_oracle_runtime_keys import TrustedOracleKey,TrustedOracleKeyRegistry,LegacyKeyBinding,RegistryBackedOracleKeyring
from src.resolver_v2_pipeline import PipelineRejected

def key(epoch="old",start="0",end="100",pub="11111111111111111111111111111111"):
 return TrustedOracleKey("oracle",("resolver-a",),pub,epoch,start,end,("2.0.0",))
def test_boundaries_and_history():
 r=TrustedOracleKeyRegistry([key()]); assert r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms="0").key_epoch=="old"
 with pytest.raises(PipelineRejected): r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms="100")
def test_scope_version_duplicate_and_fingerprint():
 r=TrustedOracleKeyRegistry([key()]); assert r.fingerprint()==TrustedOracleKeyRegistry([key()]).fingerprint()
 with pytest.raises(PipelineRejected): r.resolve(oracle_identity="oracle",resolver_id="resolver-b",message_version="2.0.0",source_timestamp_ms="1")
 with pytest.raises(PipelineRejected): TrustedOracleKeyRegistry([key(),key()])

def test_activation_and_retirement_boundaries_are_inclusive_exclusive():
 r=TrustedOracleKeyRegistry([key(start="10",end="20")])
 for at in ("9","20","21"):
  with pytest.raises(PipelineRejected): r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms=at)
 for at in ("10","11","19"):
  assert r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms=at).key_epoch=="old"

def test_overlap_is_explicitly_rejected_at_all_boundaries():
 old=key("old","0","20"); new=TrustedOracleKey("oracle",("resolver-a",),"SysvarC1ock11111111111111111111111111111111","new","10","30",("2.0.0",))
 r=TrustedOracleKeyRegistry([old,new],overlap_ms=10)
 for at in ("9","10","11","19"):
  if at=="9": assert r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms=at).key_epoch=="old"
  else:
   with pytest.raises(PipelineRejected): r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms=at)
 assert r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms="20").key_epoch=="new"

def test_historical_lookup_uses_message_timestamp_only():
 old=key("old","0","10"); new=TrustedOracleKey("oracle",("resolver-a",),"SysvarC1ock11111111111111111111111111111111","new","10",None,("2.0.0",))
 r=TrustedOracleKeyRegistry([old,new])
 assert r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms="9").key_epoch=="old"
 assert r.resolve(oracle_identity="oracle",resolver_id="resolver-a",message_version="2.0.0",source_timestamp_ms="10").key_epoch=="new"

def test_legacy_keyring_bridge_delegates_scope_and_epoch():
 r=TrustedOracleKeyRegistry([key("e","10","20")]); bridge=RegistryBackedOracleKeyring(r,[LegacyKeyBinding("legacy","3","oracle")],resolver_id="resolver-a",message_version="2.0.0")
 assert bridge.resolve("legacy","10","3").public_key=="11111111111111111111111111111111"
 for args in (("missing","10","3"),("legacy","9","3"),("legacy","10","4")):
  with pytest.raises(PipelineRejected): bridge.resolve(*args)
