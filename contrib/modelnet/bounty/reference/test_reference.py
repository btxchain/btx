import unittest,concurrent.futures,json,copy
from pathlib import Path
from bounty_reference import *
class ReferenceTests(unittest.TestCase):
    def body(self):return {'envelope_version':1,'record_type':'BountyTerms','network_id':'00'*32,'signer_id':'11'*48,'public_key_hex':'22'*1312,'delegation_id':None,'payload':{'title':'研究モデル','amount_atoms':'500','tags':['coding'],'tombstone':False}}
    def test_dictionary_order(self):self.assertEqual(canonical({'a':1,'b':2}),canonical({'b':2,'a':1}))
    def test_array_order_bound(self):self.assertNotEqual(canonical([1,2]),canonical([2,1]))
    def test_no_floats(self):
        with self.assertRaises(ContractError):canonical(1.2)
    def test_no_negative_integer(self):
        with self.assertRaises(ContractError):canonical(-1)
    def test_no_bad_unicode(self):
        with self.assertRaises(ContractError):canonical('\ud800')
    def test_no_long_string(self):
        with self.assertRaises(ContractError):canonical('x'*8193)
    def test_no_unknown_envelope_field(self):
        b=self.body();b['signed_ok']=True
        with self.assertRaises(ContractError):digest(b)
    def test_network_binding(self):
        b=self.body();c=copy.deepcopy(b);c['network_id']='01'*32;self.assertNotEqual(digest(b),digest(c))
    def test_mutated_tags_change_digest(self):
        b=self.body();c=copy.deepcopy(b);c['payload']['tags']=['medical'];self.assertNotEqual(digest(b),digest(c))
    def test_mutated_publisher_changes_digest(self):
        b=self.body();c=copy.deepcopy(b);c['signer_id']='33'*48;self.assertNotEqual(digest(b),digest(c))
    def test_tombstone_changes_digest(self):
        b=self.body();c=copy.deepcopy(b);c['payload']['tombstone']=True;self.assertNotEqual(digest(b),digest(c))
    def test_duplicate_json_keys(self):
        with self.assertRaises(ContractError):strict_json('{"a":1,"a":2}')
    def test_nan_rejected(self):
        with self.assertRaises(ContractError):strict_json('{"a":NaN}')
    def test_canonical_atoms(self):self.assertEqual(atoms('100'),100)
    def test_noncanonical_atoms(self):
        for x in ['01','-1','1.0',' 1','+1',1]:
            with self.subTest(x=x),self.assertRaises(ContractError):atoms(x)
    def test_money_range(self):
        with self.assertRaises(ContractError):atoms(str(MAX_MONEY+1))
    def test_pledge_not_funded(self):
        v=funding_view('500','450','200');self.assertEqual(v['remaining_atoms'],'300');self.assertEqual(v['funded_bps'],4000)
    def test_unknown_funding(self):self.assertIsNone(funding_view('500','450',None)['remaining_atoms'])
    def test_percentage_example(self):self.assertEqual(funding_view('500','0','371')['funded_bps'],7420)
    def test_eligibility_boundary(self):self.assertTrue(eligible('5','500',100));self.assertFalse(eligible('4','500',100))
    def test_large_eligibility_exact(self):self.assertTrue(eligible(str(MAX_MONEY//100),str(MAX_MONEY),100))
    def test_timeline(self):validate_timeline(100,200,250,270,300,350,6,20)
    def test_timelock_not_timestamp(self):
        with self.assertRaises(ContractError):validate_timeline(100,200,250,270,300,500000000,6,20)
    def test_insufficient_margin(self):
        with self.assertRaises(ContractError):validate_timeline(100,200,250,270,300,310,6,20)
    def test_council_max_eight(self):
        self.assertTrue(council_shape(list('abcdefg'),5))
        with self.assertRaises(ContractError):council_shape(list('abcdefghi'),7)
    def test_duplicate_council(self):
        with self.assertRaises(ContractError):council_shape(['a','a'],2)
    def test_refund_preserved(self):
        o=RefundLineage('lot','mine',500,100);self.assertEqual(stage(o,'mine',500,100),o)
    def test_no_refund_substitution(self):
        with self.assertRaises(ContractError):stage(RefundLineage('lot','mine',500,100),'other',500,100)
    def test_no_refund_extension(self):
        with self.assertRaises(ContractError):stage(RefundLineage('lot','mine',500,100),'mine',501,100)
    def test_secret_survives_reorg(self):
        s=ObservationState(100);s.observe_secret();s.reorg_funding();self.assertTrue(s.secret_known);self.assertEqual(s.confirmed_funding,0)
    def test_idempotent_budget(self):
        b=MandateBudget(20,10);b.reserve('a',5);b.reserve('a',5);self.assertEqual(b.used,5)
    def test_idempotency_conflict(self):
        b=MandateBudget(20,10);b.reserve('a',5)
        with self.assertRaises(ContractError):b.reserve('a',6)
    def test_budget_concurrency(self):
        b=MandateBudget(20,5)
        def run(i):
            try:return b.reserve(str(i),5)
            except ContractError:return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as e:results=list(e.map(run,range(100)))
        self.assertEqual(sum(results),20);self.assertEqual(b.used,20)
    def test_revocation(self):
        b=MandateBudget(20,5);b.reserve('old',5);b.revoke();self.assertEqual(b.reserve('old',5),5)
        with self.assertRaises(ContractError):b.reserve('new',5)
    def test_dedupe_outpoints(self):self.assertEqual(dedupe_principal([('a:0',10),('a:0',10),('b:1',20)]),30)
    def test_outpoint_conflict(self):
        with self.assertRaises(ContractError):dedupe_principal([('a:0',10),('a:0',20)])
    def test_fee_conservation(self):
        for reserves in [[1,1,1],[10,20,30],[0,10,20],[0,0]]:
            for fee in range(sum(reserves)+1):
                charges,refunds=allocate_fee_reserve(reserves,fee)
                self.assertEqual(sum(charges),fee);self.assertEqual(sum(refunds)+fee,sum(reserves));self.assertTrue(all(x>=0 for x in refunds))
    def test_golden_vectors(self):
        path=Path(__file__).parent/'golden-vectors.json'
        for v in json.loads(path.read_text())['vectors']:
            self.assertEqual(digest(v['body']),v['sha384']);self.assertEqual(preimage(v['body']).hex(),v['preimage_hex'])
if __name__=='__main__':unittest.main()
