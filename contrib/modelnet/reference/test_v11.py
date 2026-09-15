"""Executed local reference tests. These do not run BTX or verify PQ signatures."""
import copy, hashlib, json, unittest
from collections import Counter
from pathlib import Path
import reference_v11 as r

ROOT=Path(__file__).resolve().parents[1]
VECTORS=json.loads((ROOT/'evidence/v1.1-vectors.json').read_text())

class URI(unittest.TestCase):
    def setUp(self):self.d=bytes(range(48));self.u=r.encode_resource(0,self.d)
    def test_all_types(self):
        for k in r.KINDS:
            x=r.decode_resource(r.encode_resource(k,self.d));self.assertEqual((x.kind,x.digest),(k,self.d))
    def test_lengths(self):self.assertEqual((len(self.u),len(self.u[6:]),len('btx1'+self.u[6:])),(91,85,89))
    def test_scheme_aliases(self):
        for u in [self.u,self.u.upper(),self.u[6:],'btx:'+self.u[6:],self.u+'/']:
            self.assertEqual(r.decode_resource(u).uri,self.u)
    def test_mutations(self):
        t=self.u[6:]
        for i in range(len(t)):
            for c in r.ALPHABET:
                if c==t[i]:continue
                with self.assertRaises(ValueError):r.decode_resource('btx://'+t[:i]+c+t[i+1:])
    def test_mixed_case(self):
        t=self.u[6:];j=next(i for i,c in enumerate(t) if c.isalpha())
        with self.assertRaises(ValueError):r.decode_resource(t[:j]+t[j].upper()+t[j+1:])
    def test_bad_forms(self):
        for u in [self.u+'?pay=1',self.u+'#run',self.u+':80',self.u+'/m',self.u+'//','btx://a@'+self.u[6:],' '+self.u,'btx://m/'+self.u[6:],'btx://'+self.u[6:]+'.',self.u.replace('btx','ｂｔｘ'),'btx1'+self.u[6:]]:
            with self.subTest(u=u),self.assertRaises(ValueError):r.decode_resource(u)
    def test_unknown_headers(self):
        for v,k in [(2,0),(1,31)]:
            with self.assertRaises(ValueError):r.decode_resource(r.raw_token(v,k,self.d))
    def test_nonzero_pad_rechecksummed(self):
        vals=[1,0]+r.convertbits(self.d,8,5,True);vals[-1]|=1
        chk=r.polymod(r.hrp_expand('btx')+vals+[0]*6)^r.BECH32M
        t=''.join(r.ALPHABET[x] for x in vals+[(chk>>(5*(5-i)))&31 for i in range(6)])
        with self.assertRaises(ValueError):r.decode_resource(t)
    def test_legacy_checksum_rejected(self):
        vals=[1,0]+r.convertbits(self.d,8,5,True)
        chk=r.polymod(r.hrp_expand('btx')+vals+[0]*6)^1
        t=''.join(r.ALPHABET[x] for x in vals+[(chk>>(5*(5-i)))&31 for i in range(6)])
        with self.assertRaises(ValueError):r.decode_resource(t)
    def test_bad_digest_sizes(self):
        for n in (0,20,32,47,49,64):
            with self.assertRaises(ValueError):r.encode_resource(0,b'\x00'*n)
    def test_bridge_path_and_split(self):
        self.assertTrue(r.bridge_path(self.u).endswith('/'+self.u[6:]))
        h=r.split_bridge_host(self.u).split('.')
        self.assertEqual([len(x) for x in h[:2]],[42,43]);self.assertEqual(''.join(h[:2]),self.u[6:])
    def test_bridge_origin_injection(self):
        for origin in ('http://example.org','https://example.org/path','https://user@example.org','https://example.org?x=1'):
            with self.assertRaises(ValueError):r.bridge_path(self.u,origin)
    def test_vector_stability(self):
        for v in VECTORS['resource_vectors']:
            self.assertEqual(r.encode_resource(v['kind'],bytes.fromhex(v['digest'])),v['uri'])

class RecordCodec(unittest.TestCase):
    def sample(self,k):return copy.deepcopy(next(v['body'] for v in VECTORS['record_vectors'] if v['kind']==k))
    def test_roundtrips_and_vectors(self):
        for v in VECTORS['record_vectors']:
            k=v['kind'];b=r.encode_record(k,v['body'])
            self.assertEqual(b.hex(),v['encoded_hex']);self.assertEqual(r.decode_record(k,b),v['body'])
            self.assertEqual(r.record_id(k,v['body']).hex(),v['object_id'])
            self.assertEqual(r.signing_message(k,v['body']).hex(),v['signing_message'])
    def test_trailing_and_truncated(self):
        for v in VECTORS['record_vectors']:
            b=bytes.fromhex(v['encoded_hex'])
            for wrong in (b+b'\0',b[:-1]):
                with self.assertRaises(ValueError):r.decode_record(v['kind'],wrong)
    def test_signer_role_and_version(self):
        for field in ('signer_role','ext_version'):
            v=self.sample(19);v[field]=0
            with self.assertRaises(ValueError):r.encode_record(19,v)
    def test_extra_field(self):
        v=self.sample(23);v['payment_atoms']=0
        with self.assertRaises(ValueError):r.encode_record(23,v)
    def test_changed_record_changes_id(self):
        v=self.sample(19);a=r.record_id(19,v);v['title']='changed'
        self.assertNotEqual(a,r.record_id(19,v))
    def test_utf8_byte_cap(self):
        v=self.sample(16);v['display_name']='界'*40
        with self.assertRaises(ValueError):r.encode_record(16,v)
    def test_collection_duplicate_and_order(self):
        v=self.sample(19);v['entries']*=2
        with self.assertRaises(ValueError):r.encode_record(19,v)
        v=self.sample(19);v['entries']=[dict(model_id='ff'*48,priority=1,retention_days=1),v['entries'][0]]
        with self.assertRaises(ValueError):r.encode_record(19,v)
    def test_delegation_bound(self):
        for field,val in [('expires_at',1700000000+8*r.DAY),('scopes',64),('all_models',False)]:
            v=self.sample(17);v[field]=val
            with self.assertRaises(ValueError):r.encode_record(17,v)
    def test_alias_tombstone(self):
        v=self.sample(20);v.update(active=False,target_kind=255,target_id='00'*48)
        self.assertEqual(r.decode_record(20,r.encode_record(20,v)),v)
    def test_alias_invalid(self):
        for field,val in [('slug','../pay'),('target_kind',7)]:
            v=self.sample(20);v[field]=val
            with self.assertRaises(ValueError):r.encode_record(20,v)
    def test_free_grant_expiry_and_range(self):
        for field,val in [('expires_at',1700000601),('piece_count',0),('maximum_bytes',0)]:
            v=self.sample(23);v[field]=val
            with self.assertRaises(ValueError):r.encode_record(23,v)
    def test_receipt_signer(self):
        v=self.sample(24);v['signer_id']='ff'*48
        with self.assertRaises(ValueError):r.encode_record(24,v)
    def test_nonminimal_and_overflow(self):
        with self.assertRaises(ValueError):r.Reader(b'\xfd\x01\x00').size(1000)
        with self.assertRaises(ValueError):r.compact_size(1<<64)
        with self.assertRaises(ValueError):r.encode_value('u64',-1)
        with self.assertRaises(ValueError):r.encode_value('u8',True)
    def test_revocation_persists(self):
        v=self.sample(18);self.assertEqual(r.decode_record(18,r.encode_record(18,v))['expires_at'],0)
        v['expires_at']=1700000400
        with self.assertRaises(ValueError):r.encode_record(18,v)
    def test_policy_action_target(self):
        for action,kind in [(1,8),(2,3)]:
            v=self.sample(21);v['recommendations'][0].update(action=action,target_kind=kind)
            with self.assertRaises(ValueError):r.encode_record(21,v)
    def test_no_signature_simulation(self):
        # This package has no sign/verify implementation masquerading as PQ evidence.
        self.assertFalse(hasattr(r,'sign_record'));self.assertFalse(hasattr(r,'verify_mldsa'))

class Planner(unittest.TestCase):
    def test_free_only_never_spends(self):
        for eta in (None,5,50000):
            got=r.choose_plan('FREE_ONLY',free_eta_s=eta,paid=r.PaidPlan(1,1,1),budget_atoms=100000,approved=True)
            self.assertIn(got,('FREE','WAIT_FREE'))
    def test_fast_free_wins(self):self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=2,paid=r.PaidPlan(1,1,20),budget_atoms=100), 'FREE')
    def test_approval_required(self):self.assertEqual(r.choose_plan('FREE_FIRST_APPROVAL',free_eta_s=None,paid=r.PaidPlan(1,1,20),budget_atoms=100),'APPROVAL_REQUIRED')
    def test_budget_all_in_fees(self):self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=None,paid=r.PaidPlan(90,11,20),budget_atoms=100),'WAIT_FREE')
    def test_scarce_range_budget(self):self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=None,paid=r.PaidPlan(90,10,20),budget_atoms=100),'PAID')
    def test_deadline_includes_settlement(self):self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=1000,paid=r.PaidPlan(1,1,200),budget_atoms=100,deadline_s=100),'FREE')
    def test_value_of_time(self):self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=1000,paid=r.PaidPlan(10,10,50),budget_atoms=100,value_per_second_atoms=1),'PAID')
    def test_risky_or_unavailable_paid(self):
        for p in [r.PaidPlan(1,1,1,safe=False),r.PaidPlan(1,1,1,deliverable=False),r.PaidPlan(1,1,1,requires_release=True)]:
            self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=None,paid=p,budget_atoms=100),'WAIT_FREE')
    def test_exposure(self):self.assertEqual(r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=None,paid=r.PaidPlan(1,1,1),budget_atoms=100,exposure_ok=False),'WAIT_FREE')
    def test_negative_estimates(self):
        for free,paid,deadline in [(-1,1,None),(None,-1,None),(1,1,-1)]:
            with self.assertRaises(ValueError):r.choose_plan('FREE_FIRST_BUDGET',free_eta_s=free,paid=r.PaidPlan(1,1,paid),deadline_s=deadline,budget_atoms=100)
    def test_explicit_paid_approval(self):self.assertEqual(r.choose_plan('EXPLICIT_PAID',free_eta_s=1,paid=r.PaidPlan(1,1,100),budget_atoms=100,approved=True),'PAID')

class Reciprocity(unittest.TestCase):
    def receive(self,l,**kwargs):
        p=dict(peer='alice',artifact='m',file=0,piece=0,nbytes=64*r.MIB,when=0,verified=True,needed=True,paid=False,observed_sources=3);p.update(kwargs)
        return l.received(**p)
    def test_verified_only(self):
        l=r.ReciprocityLedger();self.assertFalse(self.receive(l,verified=False));self.assertEqual(l.effective('alice',0),0)
    def test_free_needed_only(self):
        for kw in ({'paid':True},{'needed':False}):
            l=r.ReciprocityLedger();self.assertFalse(self.receive(l,**kw))
    def test_cross_peer_duplicate(self):
        l=r.ReciprocityLedger();self.assertTrue(self.receive(l));self.assertFalse(self.receive(l,peer='bob'));self.assertEqual(l.effective('bob',0),0)
    def test_bounded_rarity(self):
        l=r.ReciprocityLedger();self.receive(l,observed_sources=1);self.assertEqual(l.effective('alice',0),128*r.MIB)
    def test_decay(self):
        l=r.ReciprocityLedger();self.receive(l);self.assertEqual(l.effective('alice',7*r.DAY),32*r.MIB);self.assertEqual(l.effective('alice',28*r.DAY),0)
    def test_weight_cap(self):
        l=r.ReciprocityLedger();self.receive(l,nbytes=100<<30);self.assertEqual(l.weight('alice',0),4);self.assertEqual(l.weight('new',0),1)
    def test_lane_share(self):
        q=r.lane_sequence(dict(bootstrap=100,reciprocal=100,preservation=100),100)
        self.assertEqual(Counter(q),dict(bootstrap=20,reciprocal=60,preservation=20))
    def test_idle_borrowing(self):self.assertEqual(r.lane_sequence(dict(bootstrap=50),50),['bootstrap']*50)
    def test_no_fake_traffic(self):self.assertEqual(r.lane_sequence({},100),[])

class ACL(unittest.TestCase):
    def call(self,**kw):
        x=dict(crypto_ok=True,hard_limit_ok=True);x.update(kw);return r.acl_decision(**x)
    def test_crypto_unconditional(self):self.assertEqual(self.call(crypto_ok=False,exact_allow=True),'REJECT_CRYPTO')
    def test_hard_caps(self):self.assertEqual(self.call(hard_limit_ok=False,exact_allow=True),'RETRY_RESOURCE')
    def test_local_deny(self):self.assertEqual(self.call(local_deny=True,exact_allow=True),'DENY_LOCAL')
    def test_quarantine(self):self.assertEqual(self.call(quarantined=True,exact_allow=True),'QUARANTINE')
    def test_explicit_scoped_override(self):self.assertEqual(self.call(exact_allow=True,subscribed_deny=True),'ALLOW')
    def test_subscribed_deny(self):self.assertEqual(self.call(subscribed_deny=True),'DENY_SUBSCRIBED')
    def test_allow_not_spend(self):self.assertEqual(self.call(exact_allow=True,needs_spend=True),'REQUIRE_SPEND_APPROVAL')
    def test_default_free(self):self.assertEqual(self.call(),'ALLOW')

if __name__=='__main__':unittest.main(verbosity=2)
