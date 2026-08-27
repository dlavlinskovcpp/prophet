from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import pytest
from pathlib import Path
import runpy
from src.operational_evidence import BASELINE_GIT_SHA, OperationalEvidenceError, _MANUAL_PERMIT_DOMAIN, _jcs, _preimage, parse_manual_review_permit, parse_r3c_trust_policy

NOW=datetime(2026,8,25,12,tzinfo=timezone.utc)

# Independently derived from the frozen MR-D1 permit contract. Expected
# constants are intentionally literal and are not generated from production
# helpers at test runtime.
FROZEN_DETERMINISTIC_PERMIT = {
 'schema':'PROPHET_MANUAL_REVIEW_PERMIT_V1', 'version':1,
 'permit_id':'manual-review-a-journal-001', 'environment':'public-devnet',
 'git_sha':'af50c01f562b6cb1a0851fa0f59c45d820d595f8',
 'evidence_set_id':'evidence-set-001', 'signer_role':'A',
 'evidence_category':'journal_storage', 'artifact_id':'artifact-a-journal-001',
 'raw_artifact_sha256':'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'redacted_artifact_sha256':'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 'valid_from':'2026-08-25T12:00:00Z', 'valid_until':'2026-08-26T12:00:00Z',
}
EXPECTED_PERMIT_JCS = b'{"artifact_id":"artifact-a-journal-001","environment":"public-devnet","evidence_category":"journal_storage","evidence_set_id":"evidence-set-001","git_sha":"af50c01f562b6cb1a0851fa0f59c45d820d595f8","permit_id":"manual-review-a-journal-001","raw_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","redacted_artifact_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","schema":"PROPHET_MANUAL_REVIEW_PERMIT_V1","signer_role":"A","valid_from":"2026-08-25T12:00:00Z","valid_until":"2026-08-26T12:00:00Z","version":1}'
EXPECTED_JCS_LENGTH_LE = b"\x39\x02\x00\x00"
EXPECTED_PERMIT_PREIMAGE = b'PROPHET_MANUAL_REVIEW_PERMIT_V1\x009\x02\x00\x00{"artifact_id":"artifact-a-journal-001","environment":"public-devnet","evidence_category":"journal_storage","evidence_set_id":"evidence-set-001","git_sha":"af50c01f562b6cb1a0851fa0f59c45d820d595f8","permit_id":"manual-review-a-journal-001","raw_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","redacted_artifact_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","schema":"PROPHET_MANUAL_REVIEW_PERMIT_V1","signer_role":"A","valid_from":"2026-08-25T12:00:00Z","valid_until":"2026-08-26T12:00:00Z","version":1}'
EXPECTED_PROVENANCE_REF = 'bb9845b7099ba1620ce6ca09c2a3853c4c475f1b8776eb5cd1b84a205e7dd7ee'


def test_manual_review_permit_literal_rfc8785_jcs():
 assert _jcs(FROZEN_DETERMINISTIC_PERMIT, 'manual_review_permit') == EXPECTED_PERMIT_JCS
 assert len(EXPECTED_PERMIT_JCS) == 569


def test_manual_review_permit_literal_length_prefix_le():
 actual_jcs, actual_preimage = _preimage(_MANUAL_PERMIT_DOMAIN, FROZEN_DETERMINISTIC_PERMIT, 'manual_review_permit')
 assert actual_jcs == EXPECTED_PERMIT_JCS
 assert actual_preimage[32:36] == EXPECTED_JCS_LENGTH_LE
 assert int.from_bytes(EXPECTED_JCS_LENGTH_LE, 'little') == 569


def test_manual_review_permit_literal_preimage():
 _, actual_preimage = _preimage(_MANUAL_PERMIT_DOMAIN, FROZEN_DETERMINISTIC_PERMIT, 'manual_review_permit')
 assert actual_preimage == EXPECTED_PERMIT_PREIMAGE
 assert len(actual_preimage) == 605
 assert actual_preimage.startswith(b'PROPHET_MANUAL_REVIEW_PERMIT_V1\0')


def test_manual_review_permit_literal_provenance_ref():
 actual = parse_manual_review_permit(FROZEN_DETERMINISTIC_PERMIT).provenance_ref
 assert actual == EXPECTED_PROVENANCE_REF
 assert len(actual) == 64
 assert actual == actual.lower() and set(actual) <= set('0123456789abcdef')

def stamp(x): return x.strftime('%Y-%m-%dT%H:%M:%SZ')
def permit(role='A', category='journal_storage'):
 return {'schema':'PROPHET_MANUAL_REVIEW_PERMIT_V1','version':1,'permit_id':f'p-{role}-{category}','environment':'public-devnet','git_sha':BASELINE_GIT_SHA,'evidence_set_id':'evidence-001','signer_role':role,'evidence_category':category,'artifact_id':f'artifact-{role}-{category}','raw_artifact_sha256':'a'*64,'redacted_artifact_sha256':'b'*64,'valid_from':stamp(NOW),'valid_until':stamp(NOW+timedelta(hours=72))}
@pytest.mark.parametrize('role,category',[('A','journal_storage'),('B','journal_storage'),('A','audit_domain'),('B','audit_domain')])
def test_permit_positive(role,category):
 p=parse_manual_review_permit(permit(role,category)); assert (p.signer_role,p.evidence_category)==(role,category) and len(p.provenance_ref)==64 and p.provenance_ref==p.provenance_ref.lower()
@pytest.mark.parametrize('field,value',[('schema','bad'),('version',True),('version','1'),('signer_role','a'),('signer_role',None),('evidence_category','host_vm'),('evidence_category',None),('raw_artifact_sha256','A'*64),('redacted_artifact_sha256','0x'+'a'*64),('permit_id',''),('valid_from','bad')])
def test_permit_rejects_strict_invalid_values(field,value):
 v=permit();v[field]=value
 with pytest.raises(OperationalEvidenceError): parse_manual_review_permit(v)
def test_permit_time_boundaries_and_exact_shape():
 v=permit();parse_manual_review_permit(v)
 for start,end in [(NOW,NOW),(NOW+timedelta(seconds=1),NOW),(NOW,NOW+timedelta(hours=72,seconds=1))]:
  x=permit();x['valid_from']=stamp(start);x['valid_until']=stamp(end)
  with pytest.raises(OperationalEvidenceError): parse_manual_review_permit(x)
 for change in (lambda x:x.pop('permit_id'),lambda x:x.__setitem__('extra',1)):
  x=permit();change(x)
  with pytest.raises(OperationalEvidenceError):parse_manual_review_permit(x)
def test_mutations_change_reference():
 base=parse_manual_review_permit(permit()).provenance_ref
 for field,value in [('signer_role','B'),('evidence_category','audit_domain'),('artifact_id','other'),('raw_artifact_sha256','c'*64),('valid_until',stamp(NOW+timedelta(hours=71)))]:
  x=permit();x[field]=value;assert parse_manual_review_permit(x).provenance_ref!=base

@pytest.mark.parametrize('field,value',[('signer_role',x) for x in ['b',' A','A ','unknown',0,True,None]]+[( 'evidence_category',x) for x in ['host_vm','JOURNAL_STORAGE',' journal_storage',0,True,None]]+[(f,x) for f in ['permit_id','environment','git_sha','evidence_set_id','artifact_id'] for x in ['',None]]+[(f,x) for f in ['raw_artifact_sha256','redacted_artifact_sha256'] for x in ['A'*64,'a'*63,'g'*64,'0x'+'a'*64,' a'*32,'',None]]+[( 'valid_from',x) for x in ['2026-08-25T12:00:00','2026-08-25T12:00:00+00:00',' 2026-08-25T12:00:00Z','2026-08-25T12:00:00Z ',None,0,'2026-08-25T12:00:00z']])
def test_complete_strict_rejection_matrix(field,value):
 x=permit();x[field]=value
 with pytest.raises(OperationalEvidenceError): parse_manual_review_permit(x)

def test_policy_permit_integration_fail_closed():
 ns=runpy.run_path(str(Path(__file__).with_name('test_operational_evidence_r3c_i1.py'))); p=ns['policy']()
 assert parse_r3c_trust_policy(p).manual_review_permits==()
 a=permit();b=permit('B','audit_domain');p['manual_review_permits']=[a,b];assert len(parse_r3c_trust_policy(p).manual_review_permits)==2
 for mutate in (lambda x:x[1].__setitem__('evidence_category','host_vm'),lambda x:x[1].__setitem__('permit_id',x[0]['permit_id']),lambda x:x[1].update({'permit_id':'other'})):
  q=copy.deepcopy(p);mutate(q['manual_review_permits'])
  if q['manual_review_permits'][1]['permit_id']=='other': q['manual_review_permits'][1].update({k:q['manual_review_permits'][0][k] for k in ('signer_role','evidence_category','artifact_id','raw_artifact_sha256','redacted_artifact_sha256')})
  with pytest.raises(OperationalEvidenceError):parse_r3c_trust_policy(q)
