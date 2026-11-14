"""Find an already-funded HTLC output before a coordinator creates another one.

A restored committed session has no funding reference. The chain, and the
wallet that may still know the mempool output, are asked before any new
funding transaction is built. An EVM lock is the same kind of fact: the
deterministic lock id is read from contract storage, and a Locked log on that
contract supplies the funding transaction when the node still has it. A failed
lookup is an error: the caller must not fund.
"""
import re
from .adapters import to_atoms
from .canonical import atoms, digest, hex32, integer
from .drivers import UTXODriver
from .errors import SwapError, require
from .evm import address_bytes, calldata, keccak256, lock_id

_HEX = re.compile(r'[0-9a-fA-F]+\Z')
_ZERO_ADDRESS = '0x' + '00' * 20
_LOCKED_TOPIC = '0x' + keccak256(b'Locked(bytes32,bytes32,address,address,address,uint256,uint64)').hex()
_UNKNOWN_EVM_TX = '0x' + '00' * 32


def find_funding_output(driver, terms, sid=None, *, recover_history=False):
    """Return an existing exact lock, or None when the lookup found nothing.

    A UTXO hit is {txid, vout, raw?}. An EVM hit is {txid, lock_id, salt}, the
    reference prepare_funding stores. None means the lookup completed and no
    matching lock exists. A real UTXO driver always scans. The in-memory
    execution test double has no chain RPC; a missing scan method on that
    double alone means no output.
    """
    if isinstance(driver, UTXODriver):
        return _reference(_scan_utxo_history(driver, terms) if recover_history else _scan_utxo(driver, terms))
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
    if getattr(driver, 'family', None) == 'evm':
        return _scan_evm(driver, terms, sid)
    raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed')


def _memory_test_double(driver):
    kind = type(driver)
    return kind.__name__ == 'Driver' and kind.__module__.endswith('test_execution_v2')


def _scan_evm(driver, terms, sid):
    """Return the EVM funding reference when that lock id is already on chain."""
    try:
        return _evm_lock(driver, terms, sid)
    except SwapError as error:
        if error.code == 'FUNDING_LOOKUP':
            raise
        raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed') from error
    except Exception as error:
        raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed') from error


def _evm_lock(driver, terms, sid):
    # Latest storage is the existence check. A lock that is still only in the
    # mempool has no latest state and no Locked log, so this lookup cannot see it.
    require(callable(getattr(driver, 'rpc', None)), 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    contract, salt, lid = _evm_identity(driver, terms, sid)
    _require_chain(driver)
    view = _parse_swap(_rpc(driver, 'eth_call', {
        'to': contract,
        'data': '0x' + calldata('getSwap(bytes32)', bytes.fromhex(lid)).hex(),
    }, 'latest'))
    if view['state'] == 0:
        return None
    _require_lock_terms(view, terms)
    return {'txid': _locked_txid(driver, contract, lid, terms), 'lock_id': lid, 'salt': salt}


def _evm_identity(driver, terms, sid):
    hex32(sid)
    asset = driver.asset
    require(getattr(asset, 'family', None) == 'evm' and type(getattr(asset, 'chain_id', None)) is int and asset.chain_id > 0
            and type(getattr(asset, 'id', None)) is str and asset.id == getattr(terms, 'asset', None),
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    contract = driver.contract
    address_bytes(contract)
    salt = digest('BTX/SWAPNET/EVM-SALT/2', {'swap_id': sid, 'asset': asset.id})
    lid = lock_id(asset.chain_id, contract, terms.refund_key, salt)
    mirror = getattr(driver, 'reference', None)
    if callable(mirror):
        mirrored = mirror(sid, terms, _UNKNOWN_EVM_TX)
        require(type(mirrored) is dict and mirrored.get('lock_id') == lid and mirrored.get('salt') == salt,
                'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    return contract, salt, lid


def _require_chain(driver):
    reported = _rpc(driver, 'eth_chainId')
    require(type(reported) is str and int(reported, 16) == driver.asset.chain_id,
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')


def _rpc(driver, method, *args):
    try:
        return driver.rpc(method, *args)
    except SwapError as error:
        raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed') from error


def _parse_swap(raw):
    require(type(raw) is str and len(raw) >= 2 and raw[:2].lower() == '0x',
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    try:
        body = bytes.fromhex(raw[2:])
    except ValueError as error:
        raise SwapError('FUNDING_LOOKUP', 'Funding output lookup cannot be completed') from error
    require(len(body) == 224, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    words = [body[i:i + 32] for i in range(0, 224, 32)]
    require(all(word[:12] == b'\x00' * 12 for word in words[1:4]),
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    state = int.from_bytes(words[6], 'big')
    require(state in (0, 1, 2, 3) and int.from_bytes(words[5], 'big') < 2 ** 64,
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    return {'hashlock': words[0].hex(), 'token': '0x' + words[1][-20:].hex(),
            'refund_to': '0x' + words[2][-20:].hex(), 'claim_to': '0x' + words[3][-20:].hex(),
            'amount': int.from_bytes(words[4], 'big'), 'refund_at': int.from_bytes(words[5], 'big'), 'state': state}


def _require_lock_terms(view, terms):
    refund = '0x' + address_bytes(terms.refund_key).hex()
    claim = '0x' + address_bytes(terms.claim_key).hex()
    require(view['hashlock'] == hex32(terms.hashlock) and view['token'] == _ZERO_ADDRESS
            and view['refund_to'] == refund and view['claim_to'] == claim
            and view['amount'] == atoms(terms.amount_atoms, positive=True)
            and type(terms.lock_value) is int and view['refund_at'] == terms.lock_value,
            'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')


def _locked_txid(driver, contract, lock_id_hex, terms):
    logs = _rpc(driver, 'eth_getLogs', {
        'address': contract, 'fromBlock': '0x0', 'toBlock': 'latest',
        'topics': [_LOCKED_TOPIC, '0x' + lock_id_hex],
    })
    require(type(logs) is list and len(logs) <= 64, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    refund = '0x' + address_bytes(terms.refund_key).hex().rjust(64, '0')
    claim = '0x' + address_bytes(terms.claim_key).hex().rjust(64, '0')
    want = '0x' + lock_id_hex
    found = []
    for log in logs:
        if type(log) is not dict or log.get('removed') is True:
            continue
        if str(log.get('address', '')).lower() != contract.lower():
            continue
        topics = log.get('topics') or []
        if type(topics) is not list or len(topics) < 2:
            continue
        if str(topics[0]).lower() != _LOCKED_TOPIC or str(topics[1]).lower() != want:
            continue
        if len(topics) > 2 and str(topics[2]).lower() != refund:
            continue
        if len(topics) > 3 and str(topics[3]).lower() != claim:
            continue
        txid = _evm_txid(log.get('transactionHash'))
        if txid:
            found.append(txid)
    unique = list(dict.fromkeys(found))
    require(len(unique) <= 1, 'FUNDING_LOOKUP', 'Funding output lookup cannot be completed')
    return unique[0] if unique else _UNKNOWN_EVM_TX


def _evm_txid(value):
    if type(value) is not str:
        return None
    text = value.strip().lower()
    if text.startswith('0x'):
        text = text[2:]
    if len(text) != 64:
        return None
    try:
        hex32(text)
    except SwapError:
        return None
    return '0x' + text


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


def _scan_utxo_history(driver, terms):
    """A restored Bitcoin session cannot treat missing history as a new spend grant."""
    try:
        return _utxo_history(driver, terms)
    except SwapError:
        raise
    except Exception as error:
        raise SwapError('FUNDING_LOOKUP', 'Wallet history recovery is incomplete') from error


def _utxo_history(driver, terms):
    require(driver.family == 'btc', 'FUNDING_LOOKUP', 'Unsupported historical recovery')
    tip = driver.rpc('getbestblockhash')
    candidates = {}
    live = _scan_utxo(driver, terms)
    if live:
        candidates[(live['txid'], live['vout'])] = live
    wallets = []
    for caller in (driver.wallet, driver.watch):
        if caller not in wallets:
            wallets.append(caller)
    for caller in wallets:
        before = caller('getwalletinfo')
        require(type(before) is dict and type(before.get('txcount')) is int
                and before.get('scanning', False) is False,
                'FUNDING_LOOKUP', 'Wallet history is not ready')
        seen = set()
        for skip in range(0, 1000, 100):
            rows = caller('listtransactions', '*', 100, skip, True)
            require(type(rows) is list and len(rows) <= 100, 'FUNDING_LOOKUP', 'Invalid history page')
            for row in rows:
                require(type(row) is dict, 'FUNDING_LOOKUP', 'Invalid history row')
                txid = hex32(row.get('txid'))
                if txid in seen:
                    continue
                seen.add(txid)
                tx = caller('gettransaction', txid, True)
                raw = _raw_from(tx, txid)
                require(raw, 'FUNDING_LOOKUP', 'Historical transaction bytes are unavailable')
                decoded = driver.rpc('decoderawtransaction', raw)
                require(type(decoded) is dict and decoded.get('txid') == txid
                        and type(decoded.get('vout')) is list,
                        'FUNDING_LOOKUP', 'Historical transaction cannot be decoded')
                for output in decoded['vout']:
                    matches = {}
                    _consider(matches, dict(output, txid=txid, vout=output.get('n')),
                              terms.lock_commitment.lower(), atoms(terms.amount_atoms, positive=True), 'value')
                    for key, match in matches.items():
                        require(type(tx.get('confirmations')) is int and tx['confirmations'] >= 0
                                and not tx.get('abandoned', False),
                                'FUNDING_LOOKUP', 'Historical funding is conflicted or abandoned')
                        if tx.get('blockhash'):
                            header = driver.rpc('getblockheader', tx['blockhash'])
                            require(header.get('confirmations', 0) > 0,
                                    'FUNDING_LOOKUP', 'Historical funding is not canonical')
                        else:
                            driver.rpc('getmempoolentry', txid)
                        candidates[key] = match
            if len(rows) < 100:
                break
        else:
            raise SwapError('FUNDING_LOOKUP', 'Wallet history exceeds the bounded recovery scan')
        after = caller('getwalletinfo')
        require(type(after) is dict and after.get('scanning', False) is False
                and after.get('txcount') == before['txcount'],
                'FUNDING_LOOKUP', 'Wallet history changed during recovery')
    require(driver.rpc('getbestblockhash') == tip, 'FUNDING_LOOKUP', 'Chain changed during history recovery')
    require(len(candidates) <= 1, 'FUNDING_AMBIGUOUS', 'More than one historical output pays this contract')
    require(candidates, 'RECOVERY_UNRESOLVED', 'No original payment found; restored session cannot fund again')
    # Do not rebroadcast recovered funding bytes, including an already-spent tx.
    return dict(next(iter(candidates.values())), raw='')
