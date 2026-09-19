import unittest, sys, json, hashlib
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'reference'))
from crl_reference import *

class CanonicalTests(unittest.TestCase):
    def test_key_order(self):self.assertEqual(canonical_json({'z':1,'a':2}),b'{"a":2,"z":1}')
    def test_roundtrip_unicode(self):
        v={'a':'Japanese 日本語','b':[True,None,3]};self.assertEqual(parse_canonical(canonical_json(v)),v)
    def test_duplicate(self):
        with self.assertRaisesRegex(ContractError,'DUPLICATE'):parse_canonical(b'{"a":1,"a":2}')
    def test_float(self):
        with self.assertRaises(ContractError):parse_canonical(b'{"a":1.1}')
    def test_exponent(self):
        with self.assertRaises(ContractError):parse_canonical(b'{"a":1e2}')
    def test_negative_zero(self):
        with self.assertRaises(ContractError):parse_canonical(b'{"a":-0}')
    def test_trailing(self):
        with self.assertRaises(ContractError):parse_canonical(b'{}[]')
    def test_whitespace(self):
        with self.assertRaises(ContractError):parse_canonical(b'{ "a": 1 }')
    def test_json_integer_range(self):
        with self.assertRaises(ContractError):canonical_json({'a':1<<54})
    def test_key_ascii(self):
        with self.assertRaises(ContractError):canonical_json({'日':1})
    def test_surrogate(self):
        with self.assertRaises(ContractError):canonical_json({'a':'\ud800'})
    def test_domain(self):self.assertNotEqual(body_id('ProviderRoleManifestV1_2',{}),body_id('RightsStatementV1_2',{}))
    def test_unknown_type(self):
        with self.assertRaises(ContractError):body_id('GenericTrustMeV1_2',{})
    def test_uint_valid(self):self.assertEqual(uint('18446744073709551615'),(1<<64)-1)
    def test_uint_leading_zero(self):
        with self.assertRaises(ContractError):uint('01')
    def test_uint_overflow(self):
        with self.assertRaises(ContractError):uint(str(1<<64))
    def test_uint_negative(self):
        with self.assertRaises(ContractError):uint('-1')

class RoleTests(unittest.TestCase):
    def test_generic_roles(self):validate_role_operations(['DISCOVERY','PORTFOLIO_ANALYTICS'],{'read':'READ'},{'read':'READ'})
    def test_unregistered(self):
        with self.assertRaises(ContractError):validate_role_operations(['DISCOVERY'],{'missing':'READ'},{})
    def test_effect(self):
        with self.assertRaises(ContractError):validate_role_operations(['DISCOVERY'],{'read':'EXECUTE_APPROVED'},{'read':'READ'})
    def test_brand_role(self):
        with self.assertRaises(ContractError):validate_role_operations(['SPECIAL_COMPANY'],{}, {})
    def test_role_duplicates(self):
        with self.assertRaises(ContractError):validate_role_operations(['DISCOVERY','DISCOVERY'],{}, {})
    def b(self,**kw):
        args=dict(role='DISCOVERY',offered_roles={'DISCOVERY'},requested_effect='READ',permitted_effects={'READ'},owner_effects={'READ'},active=True,expires=20,now=10,network_matches=True);args.update(kw);check_binding(**args)
    def test_binding_good(self):self.b()
    def test_binding_expired(self):
        with self.assertRaises(ContractError):self.b(now=20)
    def test_binding_revoke(self):
        with self.assertRaises(ContractError):self.b(active=False)
    def test_binding_network(self):
        with self.assertRaises(ContractError):self.b(network_matches=False)
    def test_binding_scope(self):
        with self.assertRaises(ContractError):self.b(requested_effect='EXECUTE_APPROVED')

class TemporalTests(unittest.TestCase):
    def setUp(self):self.a=Observation('entity-a','p','source-a','g',1,10,10,100,'a')
    def select(self,rs,**kw):
        args=dict(entity='entity-a',as_of=30,cutoff=30,authoritative_sources={'p':'source-a'});args.update(kw);return select_asof(rs,**args)
    def test_exact_replay(self):self.assertEqual(len(self.select([self.a,self.a])),1)
    def test_conflict(self):
        with self.assertRaises(ContractError):self.select([self.a,replace(self.a,digest='b')])
    def test_effective_future(self):self.assertEqual(self.select([self.a,replace(self.a,sequence=2,effective=40,digest='b',quantity=200)])[0].quantity,100)
    def test_late_record(self):self.assertEqual(self.select([self.a,replace(self.a,sequence=2,recorded=40,digest='b',quantity=200)])[0].quantity,100)
    def test_later_cutoff(self):self.assertEqual(self.select([self.a,replace(self.a,sequence=2,recorded=40,digest='b',quantity=200)],cutoff=50)[0].quantity,200)
    def test_closed(self):self.assertEqual(self.select([self.a,replace(self.a,sequence=2,status='CLOSED',digest='b')]),[])
    def test_source_precedence(self):self.assertEqual(len(self.select([self.a,replace(self.a,source='other',digest='b')])),1)
    def test_entity_isolation(self):self.assertEqual(self.select([replace(self.a,entity='entity-b')]),[])
    def test_generation_break(self):
        with self.assertRaises(ContractError):self.select([self.a,replace(self.a,generation='h',digest='b')])
    def test_disputed(self):
        with self.assertRaises(ContractError):self.select([replace(self.a,status='DISPUTED')])

class MetricTests(unittest.TestCase):
    def setUp(self):self.p=MetricPosition('p','NATIVE_RESERVE',True,'DIRECT','USD',2,10000,managed=True,custodied=True)
    def m(self,ps,kind='AUM',**kw):return metric(ps,kind=kind,currency='USD',exponent=2,**kw)
    def test_aum(self):self.assertEqual(self.m([self.p])['value'],10000)
    def test_no_mandate(self):self.assertEqual(self.m([replace(self.p,managed=False)])['value'],0)
    def test_auc(self):self.assertEqual(self.m([replace(self.p,managed=False)],'AUC')['value'],10000)
    def test_aua(self):self.assertEqual(self.m([replace(self.p,administered=True)],'AUA')['value'],10000)
    def test_duplicate_same(self):self.assertEqual(self.m([self.p,self.p])['value'],10000)
    def test_duplicate_conflict(self):
        with self.assertRaises(ContractError):self.m([self.p,replace(self.p,value_minor=20000)])
    def test_lookthrough_excluded(self):self.assertEqual(self.m([self.p,replace(self.p,key='child',view='LOOKTHROUGH')])['value'],10000)
    def test_nonfinancial_excluded(self):self.assertEqual(self.m([replace(self.p,financial=False)])['eligible'],0)
    def test_missing_not_zero(self):self.assertIsNone(self.m([replace(self.p,value_minor=None)])['value'])
    def test_true_zero(self):self.assertEqual(self.m([replace(self.p,value_minor=0)])['status'],'COMPLETE')
    def test_partial(self):self.assertEqual(self.m([self.p,replace(self.p,key='q',value_minor=None)])['status'],'PARTIAL')
    def test_stale(self):self.assertEqual(self.m([replace(self.p,current=False)])['status'],'UNAVAILABLE')
    def test_empty_complete(self):self.assertEqual(self.m([])['value'],0)
    def test_empty_incomplete(self):self.assertIsNone(self.m([],coverage_complete=False)['value'])
    def test_currency(self):
        with self.assertRaises(ContractError):self.m([replace(self.p,currency='JPY')])
    def test_count_not_nav(self):
        p=replace(self.p,asset_kind='CAPABILITY_RESOURCE',financial=False,view='OPERATIONAL')
        self.assertEqual(self.m([p,p],'CAPABILITY_COUNT')['count'],1)
    def test_scenario_excluded(self):self.assertEqual(self.m([replace(self.p,purpose='REPLACEMENT_SCENARIO')])['eligible'],0)
    def test_cost_basis(self):self.assertEqual(self.m([replace(self.p,purpose='COST_BASIS',financial=False)],'ACTUAL_COST')['value'],10000)
    def test_fx(self):self.assertEqual(convert_minor(10000,2,'150',0),15000)
    def test_half_even(self):self.assertEqual(convert_minor(1,0,'0.005',2),0)
    def test_rate_nonfinite(self):
        with self.assertRaises(ContractError):convert_minor(100,2,'NaN',2)
    def test_new_firm_assets(self):self.assertEqual(growth_bridge(external_in=2,external_out=0,internal_in=3,internal_out=0,performance=0),{'new_firm_assets':2,'product_change':5})

class GraphTests(unittest.TestCase):
    def test_replace_parent(self):self.assertEqual(expand_exposure('fund',{'fund':[('asset',Decimal(1))]}),{'asset':Decimal(1)})
    def test_residual(self):self.assertEqual(expand_exposure('fund',{'fund':[('asset',Decimal('.8'))]})['unresolved:fund'],Decimal('.2'))
    def test_cycle(self):
        with self.assertRaises(ContractError):expand_exposure('a',{'a':[('b',Decimal(1))],'b':[('a',Decimal(1))]})
    def test_weight_overflow(self):
        with self.assertRaises(ContractError):expand_exposure('a',{'a':[('b',Decimal('1.2'))]})
    def test_nan_weight(self):
        with self.assertRaises(ContractError):expand_exposure('a',{'a':[('b',Decimal('NaN'))]})
    def test_zero_weight(self):self.assertEqual(expand_exposure('a',{'a':[('b',Decimal(0))]})['unresolved:a'],1)
    def test_depth(self):
        with self.assertRaises(ContractError):expand_exposure('0',{str(i):[(str(i+1),Decimal(1))] for i in range(20)})

class ImportTests(unittest.TestCase):
    def setUp(self):self.s=ImportStore();self.b=b'{"sample":true}\n';self.h=hashlib.sha384(self.b).hexdigest()
    def test_good(self):
        self.s.stage('a','c',self.b,self.h);v=self.s.validate('a','i',['c'],'map');self.assertEqual(self.s.commit('a','i',v),v)
    def test_bad_hash(self):
        with self.assertRaises(ContractError):self.s.stage('a','c',self.b,'0'*96)
    def test_wrong_tenant(self):
        self.s.stage('a','c',self.b,self.h)
        with self.assertRaises(ContractError):self.s.validate('b','i',['c'],'map')
    def test_unvalidated(self):
        with self.assertRaises(ContractError):self.s.commit('a','i','x')
    def test_duplicate_chunk(self):
        self.s.stage('a','c',self.b,self.h)
        with self.assertRaises(ContractError):self.s.validate('a','i',['c','c'],'map')
    def test_commit_repeat(self):
        self.s.stage('a','c',self.b,self.h);v=self.s.validate('a','i',['c'],'map');self.s.commit('a','i',v);self.s.commit('a','i',v);self.assertEqual(len(self.s.published),1)
    def test_mapping_change(self):
        self.s.stage('a','c',self.b,self.h);self.s.validate('a','i',['c'],'map')
        with self.assertRaises(ContractError):self.s.validate('a','i',['c'],'other')
    def test_empty_chunk(self):
        with self.assertRaises(ContractError):self.s.stage('a','c',b'',hashlib.sha384(b'').hexdigest())

class DraftTests(unittest.TestCase):
    def setUp(self):self.i=json.loads((R/'examples/valid/PortfolioInstructionV1_2.json').read_text())
    def test_draft(self):self.assertFalse(translate_to_draft(expected_entity='entity-a',instruction=self.i,now=1,permitted=True)['financial_authorized'])
    def test_wrong_entity(self):
        with self.assertRaises(ContractError):translate_to_draft(expected_entity='b',instruction=self.i,now=1,permitted=True)
    def test_expired(self):
        with self.assertRaises(ContractError):translate_to_draft(expected_entity='entity-a',instruction=self.i,now=10**20,permitted=True)
    def test_no_permission(self):
        with self.assertRaises(ContractError):translate_to_draft(expected_entity='entity-a',instruction=self.i,now=1,permitted=False)
    def test_execution_rejected(self):
        self.i['requested_action']='EXECUTE_NOW'
        with self.assertRaises(ContractError):translate_to_draft(expected_entity='entity-a',instruction=self.i,now=1,permitted=True)
    def test_idempotency(self):
        s=IdempotencyStore();self.assertEqual(s.record('p','t','e','op','hash','first'),s.record('p','t','e','op','hash','second'))
    def test_idempotency_conflict(self):
        s=IdempotencyStore();s.record('p','t','e','op','hash','first')
        with self.assertRaises(ContractError):s.record('p','t','e','op','other','second')
    def test_provider_separate(self):
        s=IdempotencyStore();s.record('p','t','e','op','hash','first');s.record('q','t','e','op','hash','second');self.assertEqual(len(s.rows),2)

if __name__=='__main__':unittest.main()
