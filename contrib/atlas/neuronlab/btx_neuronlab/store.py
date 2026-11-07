"""Private artifact store, local trust, revocation and immutable operation journal.

The store never calls a wallet and never adopts on download. It is not a swarm
consensus database. Signature validity, operator trust and activation are separate.
"""
from __future__ import annotations
import hashlib
import os
import sqlite3
import time
from pathlib import Path
from .codec import require, keys, text, digest_text, canonical, loads, identity, read_file, atomic_write, LabError
from .capsule import Capsule, MAX_CAPSULE
from .schema import compatibility
from .crypto import MLDSA44

def model_key_for(binding):
    return identity('BTX/NeuronLab/ModelBinding/1', {k:v for k,v in binding.items() if k != 'btx_model_id'})

class Store:
    def __init__(self, root: Path, crypto: MLDSA44 | None = None):
        root = Path(root).absolute()
        require(not root.is_symlink(), 'STORE', 'Symlink store refused')
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == 'posix':
            os.chmod(root, 0o700)
        self.root, self.crypto = root, crypto or MLDSA44()
        (root/'capsules').mkdir(exist_ok=True, mode=0o700)
        (root/'evidence').mkdir(exist_ok=True, mode=0o700)
        for name in ['catalog.sqlite', 'catalog.sqlite-wal', 'catalog.sqlite-shm']:
            require(not (root/name).is_symlink(), 'SYMLINK', 'Symlink database refused')
        self.db = sqlite3.connect(root/'catalog.sqlite', timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS capsules(id TEXT PRIMARY KEY, publisher TEXT NOT NULL, bytes_hash TEXT NOT NULL, title TEXT NOT NULL, imported_ms INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS trust(publisher TEXT PRIMARY KEY, domain_label TEXT NOT NULL, revoked INTEGER NOT NULL, sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS activations(model_key TEXT PRIMARY KEY, profile_id TEXT NOT NULL, binding_json TEXT NOT NULL, generation INTEGER NOT NULL, previous_id TEXT, enabled INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL, entry_json TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, semantic_hash TEXT NOT NULL, result_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS models(id TEXT PRIMARY KEY, path TEXT NOT NULL, binding_json TEXT NOT NULL, recipe_json TEXT NOT NULL);
        ''')
        if os.name == 'posix': os.chmod(root/'catalog.sqlite', 0o600)

    def close(self): self.db.close()

    def _event(self, kind, body):
        row = self.db.execute('SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        seq, previous = (row['seq'] + 1, row['hash']) if row else (1, '0'*96)
        entry = {'seq': seq, 'time_ms': int(time.time()*1000), 'kind': kind, 'body': body, 'previous_hash': previous}
        digest = identity('BTX/NeuronLab/LocalEvent/1', entry)
        self.db.execute('INSERT INTO events VALUES(?,?,?,?)', (seq, previous, canonical(entry).decode(), digest))
        return digest

    def mutate(self, op_id, semantic, function):
        text(op_id, 96, 'operation ID')
        h = identity('BTX/NeuronLab/Operation/1', semantic)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            old = self.db.execute('SELECT * FROM operations WHERE id=?', (op_id,)).fetchone()
            if old:
                require(old['semantic_hash'] == h, 'IDEMPOTENCY_CONFLICT', 'Operation ID reused with different content')
                result = loads(old['result_json'])
            else:
                result = function()
                self.db.execute('INSERT INTO operations VALUES(?,?,?)', (op_id, h, canonical(result).decode()))
            self.db.execute('COMMIT')
            return result
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def import_capsule(self, raw, op_id):
        cap = Capsule(raw, self.crypto)
        path = self.root/'capsules'/f'{cap.id}.safetensors'
        def act():
            old = self.db.execute('SELECT * FROM capsules WHERE id=?', (cap.id,)).fetchone()
            # ML-DSA signatures may differ for the same signed profile. Retain the
            # first valid representation; content identity is manifest identity.
            if not old:
                atomic_write(path, cap.raw)
                self.db.execute('INSERT INTO capsules VALUES(?,?,?,?,?)', (cap.id, cap.publisher, cap.bytes_hash, cap.profile['title'], int(time.time()*1000)))
                self._event('CAPSULE_IMPORTED_NO_ACTIVATION', {'profile': cap.id, 'publisher': cap.publisher})
            else:
                require(old['publisher'] == cap.publisher, 'PUBLISHER_CONFLICT', 'Existing profile attributed to another publisher')
            return {'id': cap.id, 'signature_valid': True, 'activation': 'NOT_AUTHORIZED', 'trust': self.trust_status(cap.publisher)}
        return self.mutate(op_id, {'kind': 'import', 'id': cap.id, 'publisher': cap.publisher}, act)

    def get(self, profile_id):
        digest_text(profile_id)
        row = self.db.execute('SELECT * FROM capsules WHERE id=?', (profile_id,)).fetchone()
        require(row is not None, 'NOT_FOUND', 'Unknown intervention profile')
        cap = Capsule(read_file(self.root/'capsules'/f'{profile_id}.safetensors', MAX_CAPSULE), self.crypto)
        require(cap.id == profile_id and cap.publisher == row['publisher'] and cap.bytes_hash == row['bytes_hash'], 'STORE_TAMPER', 'Stored capsule changed')
        return cap

    def list(self, limit=100, after=''):
        require(type(limit) is int and 1 <= limit <= 100, 'LIMIT', 'Invalid page size')
        require(after == '' or len(after) == 96, 'CURSOR', 'Invalid cursor')
        rows = self.db.execute('SELECT * FROM capsules WHERE id>? ORDER BY id LIMIT ?', (after, limit+1)).fetchall()
        items = []
        for r in rows[:limit]:
            item = dict(r)
            item['trust'] = self.trust_status(r['publisher'])
            items.append(item)
        return {'items': items, 'next_cursor': rows[limit-1]['id'] if len(rows)>limit else None, 'complete': len(rows)<=limit}

    def trust_status(self, publisher):
        r = self.db.execute('SELECT * FROM trust WHERE publisher=?', (publisher,)).fetchone()
        return 'UNTRUSTED' if r is None else 'REVOKED' if r['revoked'] else 'LOCALLY_TRUSTED_PUBLISHER'

    def set_trust(self, publisher, domain_label, revoked, op_id):
        digest_text(publisher); text(domain_label, 128)
        require(type(revoked) is bool, 'TRUST', 'Revocation must be boolean')
        def act():
            old = self.db.execute('SELECT sequence FROM trust WHERE publisher=?', (publisher,)).fetchone()
            seq = old['sequence'] + 1 if old else 1
            self.db.execute('INSERT INTO trust VALUES(?,?,?,?) ON CONFLICT(publisher) DO UPDATE SET domain_label=excluded.domain_label,revoked=excluded.revoked,sequence=excluded.sequence', (publisher, domain_label, int(revoked), seq))
            if revoked:
                self.db.execute('UPDATE activations SET enabled=0,generation=generation+1 WHERE profile_id IN (SELECT id FROM capsules WHERE publisher=?)', (publisher,))
            self._event('PUBLISHER_REVOKED' if revoked else 'PUBLISHER_TRUSTED', {'publisher': publisher, 'sequence': seq, 'domain_label': domain_label})
            return {'publisher': publisher, 'status': self.trust_status(publisher), 'sequence': seq, 'domain_independence': 'OPERATOR_ASSERTED_NOT_PROVED'}
        return self.mutate(op_id, {'kind': 'trust', 'publisher': publisher, 'domain_label': domain_label, 'revoked': revoked}, act)

    def activate(self, profile_id, actual_binding, op_id, expected_generation=0):
        cap = self.get(profile_id)
        model_key = model_key_for(actual_binding)
        def act():
            require(self.trust_status(cap.publisher) == 'LOCALLY_TRUSTED_PUBLISHER', 'TRUST_REQUIRED', 'Trust/verify this publisher before local application')
            match = compatibility(cap.profile, actual_binding)
            require(match['compatible'], 'INCOMPATIBLE', 'Exact model/runtime representation mismatch: '+','.join(match['mismatches']))
            old = self.db.execute('SELECT * FROM activations WHERE model_key=?', (model_key,)).fetchone()
            generation = old['generation'] if old else 0
            require(generation == expected_generation, 'STALE_GENERATION', 'Activation changed since review')
            prev = old['profile_id'] if old else None
            self.db.execute('INSERT INTO activations VALUES(?,?,?,?,?,1) ON CONFLICT(model_key) DO UPDATE SET profile_id=excluded.profile_id,binding_json=excluded.binding_json,generation=excluded.generation,previous_id=excluded.previous_id,enabled=1',
                            (model_key, profile_id, canonical(actual_binding).decode(), generation+1, prev))
            self._event('LOCAL_EXPERIMENT_ENABLED', {'model_key': model_key, 'profile': profile_id, 'generation': generation+1})
            return {'model_key': model_key, 'profile_id': profile_id, 'generation': generation+1, 'scope': 'LOCAL_EXPERIMENT_NOT_SWARM_RELEASE'}
        return self.mutate(op_id, {'kind': 'activate', 'id': profile_id, 'binding': actual_binding, 'expected_generation': expected_generation}, act)

    def deactivate(self, model_key, op_id):
        digest_text(model_key)
        def act():
            self.db.execute('UPDATE activations SET enabled=0,generation=generation+1 WHERE model_key=?', (model_key,))
            self._event('LOCAL_EXPERIMENT_DISABLED', {'model_key': model_key})
            return {'model_key': model_key, 'enabled': False}
        return self.mutate(op_id, {'kind': 'deactivate', 'model_key': model_key}, act)

    def active(self, binding):
        model_key = model_key_for(binding)
        r = self.db.execute('SELECT * FROM activations WHERE model_key=? AND enabled=1', (model_key,)).fetchone()
        if not r: return None
        cap = self.get(r['profile_id'])
        require(self.trust_status(cap.publisher) == 'LOCALLY_TRUSTED_PUBLISHER', 'REVOKED', 'Active publisher no longer trusted')
        require(compatibility(cap.profile, binding)['compatible'], 'INCOMPATIBLE', 'Active profile no longer compatible')
        return cap, r['generation']

    def check_fence(self, profile_id, binding, generation):
        current = self.active(binding)
        require(current is not None and current[0].id == profile_id and current[1] == generation,
                'REVOKED_OR_CHANGED', 'Local intervention was revoked or changed; discard in-flight output')

    def events(self, after=0, limit=100):
        require(type(after) is int and after >= 0 and type(limit) is int and 1 <= limit <= 1000, 'LIMIT', 'Invalid event page')
        rows = self.db.execute('SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?', (after, limit+1)).fetchall()
        return {'items': [loads(r['entry_json']) | {'event_hash': r['hash']} for r in rows[:limit]],
                'next_cursor': rows[limit-1]['seq'] if len(rows)>limit else None,
                'scope': 'LOCAL_APPLICATION_JOURNAL_NOT_CHAIN_CONSENSUS'}

    def verify_journal(self):
        previous, seq = '0'*96, 0
        for r in self.db.execute('SELECT * FROM events ORDER BY seq'):
            e = loads(r['entry_json'])
            require(r['seq'] == seq+1 and e['previous_hash'] == previous and r['previous_hash'] == previous and identity('BTX/NeuronLab/LocalEvent/1', e) == r['hash'], 'JOURNAL_TAMPER', 'Journal chain invalid')
            seq, previous = r['seq'], r['hash']
        return {'entries': seq, 'head': previous, 'assurance': 'LOCAL_HASH_CHAIN_NOT_EXTERNAL_ATTESTATION'}
