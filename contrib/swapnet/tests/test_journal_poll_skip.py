"""Poll timestamps alone must not rewrite an unchanged stage."""
import json
from copy import deepcopy
import pytest
from swapnet.errors import SwapError
from swapnet.journal import Journal

SID = 'ab' * 32

def session(stage='committed'):
    return {
        'stage': stage,
        'principal': 'alice',
        'peer': 'bob',
        'agreement_id': 'cd' * 32,
        'secret_exposed': True,
        'updated_at': 100,
        'last_error': None,
        'refs': {'a': {'txid': '11' * 32, 'vout': 0}},
        'observations': {
            'a': {'present': True, 'canonical': True, 'confirmations': 3, 'observed_at': 100},
            'b': {'present': False, 'observed_at': 100},
        },
    }

def writes(store):
    count = 0
    for (raw,) in store.db.execute('SELECT body FROM audit'):
        event = json.loads(raw)
        if event.get('type') == 'swap_v2_saved' and event.get('id') == SID:
            count += 1
    return count

@pytest.mark.parametrize('stage', ['proposed', 'committed', 'complete', 'refunded'])
def test_unchanged_stage_skips_poll_timestamps(store, stage):
    journal = Journal(store)
    rev = journal.save(SID, session(stage), -1)
    assert writes(store) == 1
    poll = session(stage)
    poll['updated_at'] = 700
    poll['observations']['a']['observed_at'] = 700
    poll['observations']['b']['observed_at'] = 700
    assert journal.save(SID, poll, rev) == rev
    assert journal.load(SID) == (rev, session(stage))
    assert writes(store) == 1

def test_stage_error_observation_and_ref_still_write(store):
    journal = Journal(store)
    rev = journal.save(SID, session(), -1)
    current = session()

    staged = deepcopy(current)
    staged['stage'] = 'refund_broadcast'
    staged['updated_at'] = 200
    rev = journal.save(SID, staged, rev)
    assert rev == 1
    current = staged

    erred = deepcopy(current)
    erred['last_error'] = {'code': 'RPC', 'message': 'Observation unavailable'}
    erred['updated_at'] = 300
    rev = journal.save(SID, erred, rev)
    assert rev == 2
    current = erred

    observed = deepcopy(current)
    observed['observations']['a']['confirmations'] = 4
    observed['observations']['a']['observed_at'] = 400
    observed['updated_at'] = 400
    rev = journal.save(SID, observed, rev)
    assert rev == 3
    current = observed

    refd = deepcopy(current)
    refd['refs']['b'] = {'txid': '22' * 32, 'vout': 1}
    refd['updated_at'] = 500
    rev = journal.save(SID, refd, rev)
    assert rev == 4
    assert writes(store) == 5
    assert journal.load(SID) == (rev, refd)

    secret = deepcopy(refd)
    secret['secret_exposed'] = False
    with pytest.raises(SwapError, match='SECRET_ROLLBACK'):
        journal.save(SID, secret, rev)
    owner = deepcopy(refd)
    owner['principal'] = 'mallory'
    with pytest.raises(SwapError, match='SESSION_BINDING'):
        journal.save(SID, owner, rev)
    agreement = deepcopy(refd)
    agreement['agreement_id'] = 'ee' * 32
    with pytest.raises(SwapError, match='AGREEMENT_CHANGED'):
        journal.save(SID, agreement, rev)
    assert journal.load(SID) == (rev, refd)
    assert writes(store) == 5
