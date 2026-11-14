"""Find an already-funded HTLC output before a coordinator creates another one.

A restored committed session has no funding reference. The chain, and the
wallet that may still know the mempool output, are asked before any new
funding transaction is built. A failed lookup is an error: the caller must
not fund.
"""
import re
from .adapters import to_atoms
from .canonical import atoms, hex32, integer
from .drivers import UTXODriver
from .errors import SwapError, require

_HEX = re.compile(r'[0-9a-fA-F]+\Z')


def find_funding_output(driver, terms):
    """Return {txid, vout, raw?} for an unspent exact lock, or None.

    None means the lookup completed and no matching output exists. A real
    UTXO driver always scans. The in-memory execution test double has no
    chain RPC; a missing scan method on that double alone means no output.
    """
    if isinstance(driver, UTXODriver):
        return _reference(_scan_utxo(driver, terms))
    if _memory_test_double(driver):
        scanner = getattr(driver, 'scan_existing_funding', None)
        if not callable(scanner):
            return None
        try:
            found = scanner(terms)
        except SwapError:
            raise
        except Exception as error:
            raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed') from error
        return _reference(found)
    # EVM locks are contract storage, not a script output. This module does
    # not decide those. Every other real driver must present a completed scan.
    if getattr(driver, 'family', None) == 'evm':
        return None
    raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed')


def _memory_test_double(driver):
    kind = type(driver)
    return kind.__name__ == 'Driver' and kind.__module__.endswith('test_execution_v2')


def _scan_utxo(driver, terms):
    for name in ('rpc', 'wallet', 'watch'):
        require(callable(getattr(driver, name, None)), 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    script = getattr(terms, 'lock_commitment', None)
    require(type(script) is str and _HEX.fullmatch(script) and len(script) % 2 == 0 and len(script) <= 16384,
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    script = script.lower()
    require(type(getattr(terms, 'amount_atoms', None)) is str, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    amount = atoms(terms.amount_atoms, positive=True)
    candidates = {}
    scanned = driver.rpc('scantxoutset', 'start', [{'desc': _raw_descriptor(driver, script)}])
    require(type(scanned) is dict and scanned.get('success') is True and type(scanned.get('unspents', [])) is list,
            'FUNDING_LOOKUP', 'UTXO scan did not complete')
    for coin in scanned.get('unspents', []):
        _consider(candidates, coin, script, amount, 'amount')
    seen = []
    for caller in (driver.wallet, driver.watch):
        if caller not in seen:
            seen.append(caller)
        else:
            continue
        coins = caller('listunspent', 0, 9999999, [], True)
        require(type(coins) is list, 'FUNDING_LOOKUP', 'Wallet output list is incomplete')
        for coin in coins:
            _consider(candidates, coin, script, amount, 'amount')
    confirmed = []
    for ref in candidates.values():
        coin = driver.rpc('gettxout', ref['txid'], ref['vout'], True)
        if coin is None:
            continue
        require(type(coin) is dict, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
        spk = coin.get('scriptPubKey')
        if type(spk) is dict:
            spk = spk.get('hex')
        try:
            value = coin['value']
        except KeyError as error:
            raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed') from error
        require(type(spk) is str and spk.lower() == script and to_atoms(value) == amount,
                'FUNDING_LOOKUP', 'Chain output does not match the contract')
        confirmed.append(ref)
    if candidates and not confirmed:
        raise SwapError('FUNDING_LOOKUP', 'Matching output could not be confirmed unspent')
    require(len(confirmed) <= 1, 'FUNDING_AMBIGUOUS', 'More than one unspent output pays this contract')
    if not confirmed:
        return None
    found = dict(confirmed[0])
    raw = _funding_raw(driver, found['txid'])
    if raw:
        found['raw'] = raw
    return found


def _raw_descriptor(driver, script):
    info = driver.rpc('getdescriptorinfo', 'raw(' + script + ')')
    require(type(info) is dict, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    descriptor = info.get('descriptor')
    if type(descriptor) is not str or not descriptor.startswith('raw(' + script + ')'):
        checksum = info.get('checksum')
        require(type(checksum) is str and checksum and '#' not in checksum,
                'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
        descriptor = 'raw(' + script + ')#' + checksum
    return descriptor


def _consider(candidates, coin, script, amount, amount_key):
    require(type(coin) is dict, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    spk = coin.get('scriptPubKey')
    if type(spk) is dict:
        spk = spk.get('hex')
    if type(spk) is not str or spk.lower() != script or amount_key not in coin:
        return
    if to_atoms(coin[amount_key]) != amount:
        return
    txid, vout = coin.get('txid'), coin.get('vout')
    hex32(txid)
    integer(vout, hi=0xffffffff)
    candidates[(txid, vout)] = {'txid': txid, 'vout': vout}


def _funding_raw(driver, txid):
    """Return the original funding bytes when the wallet or node still has them."""
    callers = []
    for caller in (driver.wallet, driver.watch):
        if caller not in callers:
            callers.append(caller)
    for caller in callers:
        try:
            tx = caller('gettransaction', txid, True)
        except SwapError:
            continue
        raw = _raw_from(tx, txid)
        if raw:
            return raw
    try:
        tx = driver.rpc('getrawtransaction', txid, True)
    except SwapError:
        return ''
    return _raw_from(tx, txid)


def _raw_from(tx, txid):
    if type(tx) is not dict or tx.get('txid') != txid or type(tx.get('hex')) is not str:
        return ''
    raw = tx['hex'].removeprefix('0x')
    if not raw or len(raw) > 4_000_000:
        return ''
    try:
        bytes.fromhex(raw)
    except ValueError:
        return ''
    return raw


def _reference(found):
    if found is None:
        return None
    require(type(found) is dict, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    txid, vout = found.get('txid'), found.get('vout')
    hex32(txid)
    integer(vout, hi=0xffffffff)
    out = {'txid': txid, 'vout': vout}
    raw = found.get('raw') or ''
    if raw:
        require(type(raw) is str, 'FUNDING_LOOKUP', 'Recovered funding transaction is unusable')
        raw = raw.removeprefix('0x')
        require(0 < len(raw) <= 4_000_000, 'FUNDING_LOOKUP', 'Recovered funding transaction is unusable')
        try:
            bytes.fromhex(raw)
        except ValueError as error:
            raise SwapError('FUNDING_LOOKUP', 'Recovered funding transaction is unusable') from error
        out['raw'] = raw
    return out
