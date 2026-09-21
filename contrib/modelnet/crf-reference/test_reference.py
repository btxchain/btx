#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Offline Cognitive Reserve v1.1 reference tests. Not an exchange ledger."""
import unittest, tempfile, json, sys, concurrent.futures
from pathlib import Path
from decimal import Decimal

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from reference.reserve import *  # noqa: E402,F403


def _crf_root() -> Path:
    for p in [HERE, *HERE.parents]:
        cand = p / 'src' / 'modelnet' / 'crf'
        if (cand / 'schemas' / 'CognitiveReserve.schema.json').is_file():
            return cand
        if (p / 'schemas' / 'CognitiveReserve.schema.json').is_file():
            return p
    return HERE


R = _crf_root()
try:
    import jsonschema
except ImportError:
    jsonschema = None
try:
    import yaml
except ImportError:
    yaml = None


class ArithmeticTests(unittest.TestCase):
    def test_capacity(self):
        self.assertEqual(capacity(1000, 400, 250), 250)

    def test_floor(self):
        self.assertEqual(capacity(300, 400, 250), 0)

    def test_authority(self):
        self.assertEqual(capacity(1000, 0, 0), 0)

    def test_mandate_binds_before_cash(self):
        self.assertEqual(capacity(1000, 0, 10), 10)

    def test_exact_large(self):
        self.assertEqual(capacity(MAX_ATOMS, 1, MAX_ATOMS), MAX_ATOMS - 1)

    def test_negative(self):
        with self.assertRaises(ContractError):
            capacity(-1, 0, 1)

    def test_bool(self):
        with self.assertRaises(ContractError):
            atoms(True)

    def test_uint(self):
        self.assertEqual(uint_string('100'), 100)

    def test_leading_zero(self):
        with self.assertRaises(ContractError):
            uint_string('010')

    def test_stale(self):
        with self.assertRaises(ContractError) as cm:
            reporting_floor_atoms('10', '3', 2, 0, 11, 10)
        self.assertEqual(str(cm.exception), 'PRICE_STALE')

    def test_price_round(self):
        self.assertEqual(reporting_floor_atoms('10', '3', 2, 10, 11, 10), 334)

    def test_haircut(self):
        self.assertEqual(reporting_floor_atoms('10', '2', 2, 10, 11, 10, 5000), 1000)

    def test_price_zero(self):
        with self.assertRaises(ContractError):
            reporting_floor_atoms('10', '0', 2, 10, 11, 10)

    def test_nonfinite(self):
        with self.assertRaises(ContractError):
            decimal('NaN')

    def test_tco(self):
        d = tco('20000000', '0.01', 3, '50000', '65000')
        self.assertEqual(d['external'], Decimal('600000'))
        self.assertEqual(d['local'], Decimal('245000'))
        self.assertEqual(d['difference'], Decimal('355000'))

    def test_break_even(self):
        self.assertAlmostEqual(float(tco('1', '0.01', 3, '50000', '65000')['break_even_annual_tasks']), 8166666.666666667)

    def test_quality(self):
        with self.assertRaises(ContractError) as cm:
            tco('1', '1', 3, '1', '1', quality_equivalent=False)
        self.assertEqual(str(cm.exception), 'QUALITY_UNPROVEN')

    def test_unknown(self):
        with self.assertRaises(ContractError) as cm:
            tco('1', '1', 3, '1', '1', inputs_known=False)
        self.assertEqual(str(cm.exception), 'INPUT_UNKNOWN')

    def test_zero_service(self):
        self.assertIsNone(tco('1', '0', 3, '1', '1')['break_even_annual_tasks'])

    def test_horizon(self):
        with self.assertRaises(ContractError):
            tco('1', '1', 0, '1', '1')

    def test_horizon_high(self):
        with self.assertRaises(ContractError) as cm:
            tco('1', '1', 11, '1', '1')
        self.assertEqual(str(cm.exception), 'INVALID_HORIZON')

    def test_horizon_bool(self):
        with self.assertRaises(ContractError):
            tco('1', '1', True, '1', '1')

    def test_utilization(self):
        a = tco('1000000', '0.01', 3, '50000', '65000')
        b = tco('20000000', '0.01', 3, '50000', '65000')
        self.assertNotEqual(a['external'], b['external'])
        self.assertEqual(a['local'], b['local'])

    def test_no_float(self):
        with self.assertRaises(ContractError):
            decimal(.1)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name + '/ledger.db'
        self.l = AtomicLedger(self.path)
        self.l.account('a', 1000, 400, 250)

    def tearDown(self):
        self.tmp.cleanup()

    def hold(self):
        return self.l.reserve('a', 'op1', 'digest1', 100)

    def test_hold(self):
        self.hold()
        self.assertEqual(self.l.snapshot('a')['available'], 900)

    def test_hold_once(self):
        self.hold()
        self.assertEqual(self.l.snapshot('a')['capacity'], 150)

    def test_hold_not_double_subtracted(self):
        self.l.account('cash', 1000, 0, 10000)
        self.l.reserve('cash', 'op', 'd', 100)
        s = self.l.snapshot('cash')
        self.assertEqual(s['held'], 100)
        self.assertEqual(s['available'], 900)
        self.assertEqual(s['capacity'], 900)

    def test_duplicate(self):
        self.hold()
        self.hold()
        self.assertEqual(self.l.snapshot('a')['held'], 100)

    def test_conflict(self):
        self.hold()
        with self.assertRaises(ContractError) as cm:
            self.l.reserve('a', 'op1', 'digest2', 100)
        self.assertEqual(str(cm.exception), 'IDEMPOTENCY_CONFLICT')

    def test_conflicting_amount(self):
        self.hold()
        with self.assertRaises(ContractError):
            self.l.reserve('a', 'op1', 'digest1', 101)

    def test_ceiling(self):
        with self.assertRaises(ContractError) as cm:
            self.l.reserve('a', 'op2', 'd', 251)
        self.assertEqual(str(cm.exception), 'CAPACITY_EXCEEDED')

    def test_exact_ceiling(self):
        self.l.reserve('a', 'op2', 'd', 250)
        self.assertEqual(self.l.snapshot('a')['capacity'], 0)

    def test_unknown_hold(self):
        self.hold()
        self.l.transition('a', 'op1', 'UNKNOWN')
        self.assertEqual(self.l.snapshot('a')['held'], 100)

    def test_unknown_cancel(self):
        self.hold()
        self.l.transition('a', 'op1', 'UNKNOWN')
        with self.assertRaises(ContractError):
            self.l.transition('a', 'op1', 'CANCELED')

    def test_signed_cancel(self):
        self.hold()
        self.l.transition('a', 'op1', 'SIGNED')
        with self.assertRaises(ContractError):
            self.l.transition('a', 'op1', 'CANCELED')

    def test_signed_settles(self):
        self.hold()
        self.l.transition('a', 'op1', 'SIGNED')
        self.l.transition('a', 'op1', 'SETTLED')
        self.assertEqual(self.l.snapshot('a')['spent'], 100)
        self.assertEqual(self.l.snapshot('a')['held'], 0)

    def test_unknown_then_settle(self):
        self.hold()
        self.l.transition('a', 'op1', 'UNKNOWN')
        self.l.transition('a', 'op1', 'SETTLED')
        self.assertEqual(self.l.snapshot('a')['spent'], 100)

    def test_cancel(self):
        self.hold()
        self.l.transition('a', 'op1', 'CANCELED')
        self.assertEqual(self.l.snapshot('a')['available'], 1000)

    def test_settle(self):
        self.hold()
        self.l.transition('a', 'op1', 'SETTLED')
        self.assertEqual(self.l.snapshot('a')['spent'], 100)

    def test_refund_not_recycle(self):
        self.hold()
        self.l.transition('a', 'op1', 'SETTLED')
        self.l.transition('a', 'op1', 'REFUNDED')
        s = self.l.snapshot('a')
        self.assertEqual(s['available'], 1000)
        self.assertEqual(s['capacity'], 150)

    def test_transition_idempotent(self):
        self.hold()
        self.l.transition('a', 'op1', 'SETTLED')
        self.l.transition('a', 'op1', 'SETTLED')
        self.assertEqual(self.l.snapshot('a')['spent'], 100)

    def test_restart(self):
        self.hold()
        self.assertEqual(AtomicLedger(self.path).snapshot('a')['held'], 100)

    def test_entity(self):
        with self.assertRaises(ContractError):
            self.l.reserve('b', 'op1', 'd', 1)

    def test_same_id_other_entity(self):
        self.l.account('b', 1000, 0, 1000)
        self.hold()
        self.l.reserve('b', 'op1', 'd', 200)
        self.assertEqual(self.l.snapshot('a')['held'], 100)

    def test_concurrent(self):
        def f(i):
            try:
                self.l.reserve('a', 'op' + str(i), 'd' + str(i), 10)
                return True
            except ContractError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            r = list(ex.map(f, range(100)))
        self.assertEqual(sum(r), 25)
        self.assertEqual(self.l.snapshot('a')['capacity'], 0)

    def test_zero(self):
        with self.assertRaises(ContractError) as cm:
            self.l.reserve('a', 'op', 'd', 0)
        self.assertEqual(str(cm.exception), 'ZERO_RESERVATION')

    def test_refund_once(self):
        self.hold()
        self.l.transition('a', 'op1', 'SETTLED')
        self.l.transition('a', 'op1', 'REFUNDED')
        self.l.transition('a', 'op1', 'REFUNDED')
        self.assertEqual(self.l.snapshot('a')['available'], 1000)

    def test_missing_operation(self):
        with self.assertRaises(ContractError) as cm:
            self.l.transition('a', 'nope', 'SETTLED')
        self.assertEqual(str(cm.exception), 'OPERATION_NOT_FOUND')

    def test_unsafe_refund_from_held(self):
        self.hold()
        with self.assertRaises(ContractError) as cm:
            self.l.transition('a', 'op1', 'REFUNDED')
        self.assertEqual(str(cm.exception), 'UNSAFE_TRANSITION')


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.kw = dict(entity='a', plan='p', policy_generation='1', rule='r',
                       eligible_people={'alice', 'bob', 'carol'}, quorum=2, initiator='carol', now=100)

    def d(self, p='alice', decision='APPROVE', seq=1, **changes):
        d = dict(entity='a', plan='p', policy_generation='1', rule='r', person=p, decision=decision,
                 sequence=seq, expires_at=200)
        d.update(changes)
        return d

    def test_two(self):
        self.assertTrue(approved([self.d(), self.d('bob')], **self.kw))

    def test_same_person(self):
        self.assertFalse(approved([self.d(), self.d(seq=2)], **self.kw))

    def test_distinct_person_quorum(self):
        two_sessions = [self.d(seq=1), self.d(seq=2)]
        self.assertFalse(approved(two_sessions, **self.kw))
        self.assertTrue(approved(two_sessions + [self.d('bob')], **self.kw))

    def test_self(self):
        self.assertFalse(approved([self.d(), self.d('carol')], **self.kw))

    def test_initiator_counted_when_included(self):
        kw = dict(self.kw)
        kw['exclude_initiator'] = False
        self.assertTrue(approved([self.d(), self.d('carol')], **kw))

    def test_changed_plan(self):
        self.assertFalse(approved([self.d(), self.d('bob', plan='new')], **self.kw))

    def test_changed_policy(self):
        self.assertFalse(approved([self.d(), self.d('bob', policy_generation='2')], **self.kw))

    def test_expiry(self):
        self.assertFalse(approved([self.d(), self.d('bob', expires_at=99)], **self.kw))

    def test_withdraw(self):
        self.assertFalse(approved([self.d(), self.d('bob'), self.d('bob', 'WITHDRAW', 2)], **self.kw))

    def test_veto(self):
        self.kw['quorum'] = 1
        self.assertFalse(approved([self.d(), self.d('bob', 'REJECT')], **self.kw))

    def test_wrong_entity(self):
        self.assertFalse(approved([self.d(), self.d('bob', entity='b')], **self.kw))

    def test_ineligible(self):
        self.assertFalse(approved([self.d(), self.d('dave')], **self.kw))

    def test_invalid_quorum(self):
        with self.assertRaises(ContractError) as cm:
            approved([], **{**self.kw, 'quorum': 0})
        self.assertEqual(str(cm.exception), 'INVALID_QUORUM')

    def test_equivocation(self):
        with self.assertRaises(ContractError) as cm:
            approved([self.d(), self.d(decision='REJECT')], **self.kw)
        self.assertEqual(str(cm.exception), 'DECISION_EQUIVOCATION')


class ContractTests(unittest.TestCase):
    def test_offline_disclaimer(self):
        import reference.reserve as m
        self.assertIn('Not an exchange ledger', m.__doc__)

    def test_schemas(self):
        if jsonschema is None:
            self.skipTest('jsonschema not installed')
        schema = R / 'schemas' / 'CognitiveReserve.schema.json'
        if not schema.is_file():
            self.skipTest('CognitiveReserve schema not mounted')
        jsonschema.Draft202012Validator.check_schema(json.loads(schema.read_text()))

    def test_positive_vectors(self):
        if jsonschema is None:
            self.skipTest('jsonschema not installed')
        schema_path = R / 'schemas' / 'CognitiveReserve.schema.json'
        valid = R / 'examples' / 'valid'
        if not schema_path.is_file() or not valid.exists():
            self.skipTest('CRF examples not mounted')
        s = json.loads(schema_path.read_text())
        files = list(valid.glob('*.json'))
        self.assertGreaterEqual(len(files), 18)
        for p in files:
            x = json.loads(p.read_text())
            jsonschema.validate(x, s)
            self.assertEqual(x['body_id'], body_id(x['object_type'], x['body']))

    def test_negative_vectors(self):
        if jsonschema is None:
            self.skipTest('jsonschema not installed')
        schema_path = R / 'schemas' / 'CognitiveReserve.schema.json'
        invalid = R / 'examples' / 'invalid'
        if not schema_path.is_file() or not invalid.exists():
            self.skipTest('CRF invalid examples not mounted')
        s = json.loads(schema_path.read_text())
        files = list(invalid.glob('*.json'))
        self.assertGreaterEqual(len(files), 1)
        for p in files:
            with self.assertRaises(jsonschema.ValidationError, msg=p.name):
                jsonschema.validate(json.loads(p.read_text()), s)

    def test_domain(self):
        self.assertNotEqual(body_id('PortfolioV1_1', {}), body_id('ReserveSnapshotV1_1', {}))

    def test_unknown_type(self):
        with self.assertRaises(ContractError):
            body_id('evil', {})

    def test_duplicate_json(self):
        with self.assertRaises(ContractError):
            parse_canonical(b'{"a":1,"a":2}')

    def test_noncanonical(self):
        with self.assertRaises(ContractError):
            parse_canonical(b'{ "a":1}')

    def test_negativezero(self):
        with self.assertRaises(ContractError):
            parse_canonical(b'{"a":-0}')

    def test_float(self):
        with self.assertRaises(ContractError):
            parse_canonical(b'{"a":1e2}')

    def test_roundtrip(self):
        self.assertEqual(parse_canonical(canonical_bytes({'b': '\u65e5\u672c', 'a': 2})), {'b': '\u65e5\u672c', 'a': 2})

    def test_dag(self):
        self.assertEqual(validate_dag([{'leg_id': 'b', 'depends_on': ['a']}, {'leg_id': 'a', 'depends_on': []}]), ['a', 'b'])

    def test_cycle(self):
        with self.assertRaises(ContractError) as cm:
            validate_dag([{'leg_id': 'a', 'depends_on': ['a']}])
        self.assertEqual(str(cm.exception), 'GRAPH_CYCLE')

    def test_two_node_cycle(self):
        with self.assertRaises(ContractError) as cm:
            validate_dag([{'leg_id': 'A', 'depends_on': ['B']}, {'leg_id': 'B', 'depends_on': ['A']}])
        self.assertEqual(str(cm.exception), 'GRAPH_CYCLE')

    def test_missing(self):
        with self.assertRaises(ContractError) as cm:
            validate_dag([{'leg_id': 'a', 'depends_on': ['b']}])
        self.assertEqual(str(cm.exception), 'MISSING_DEPENDENCY')

    def test_duplicate_leg(self):
        with self.assertRaises(ContractError):
            validate_dag([{'leg_id': 'a'}, {'leg_id': 'a'}])

    def test_graph_limit(self):
        with self.assertRaises(ContractError) as cm:
            validate_dag([{'leg_id': str(i)} for i in range(33)])
        self.assertEqual(str(cm.exception), 'GRAPH_LIMIT')

    def test_empty_graph(self):
        with self.assertRaises(ContractError) as cm:
            validate_dag([])
        self.assertEqual(str(cm.exception), 'GRAPH_LIMIT')

    def test_graph_depth(self):
        legs = [{'leg_id': str(i), 'depends_on': [str(i + 1)] if i < 16 else []} for i in range(17)]
        with self.assertRaises(ContractError) as cm:
            validate_dag(legs)
        self.assertEqual(str(cm.exception), 'GRAPH_DEPTH')

    def test_graph_depth_ok(self):
        legs = [{'leg_id': str(i), 'depends_on': [str(i + 1)] if i < 15 else []} for i in range(16)]
        self.assertEqual(len(validate_dag(legs)), 16)

    def test_base_preserved(self):
        if yaml is None:
            self.skipTest('PyYAML not installed')
        bp = R / 'compatibility' / 'hcp1' / 'schemas' / 'openapi.yaml'
        if not bp.exists():
            self.skipTest('Base artifact not mounted; coordinator must run original package checks')
        old = yaml.safe_load(bp.read_text())
        new = yaml.safe_load((R / 'schemas' / 'openapi-v1.1.yaml').read_text())
        for path, item in old['paths'].items():
            for method, v in item.items():
                self.assertEqual(new['paths'][path][method], v)

    def test_50_operations(self):
        ops = R / 'schemas' / 'operations-v1.1.json'
        if not ops.is_file():
            self.skipTest('operations catalogue not mounted')
        self.assertEqual(len(json.loads(ops.read_text())['operations']), 50)

    def test_no_signature_claim(self):
        valid = R / 'examples' / 'valid'
        if not valid.exists():
            self.skipTest('CRF examples not mounted')
        for p in valid.glob('*.json'):
            self.assertEqual(set(json.loads(p.read_text())['signature']), {'0'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
