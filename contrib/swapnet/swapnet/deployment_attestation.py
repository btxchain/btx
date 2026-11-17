"""Creation-provenance checks for NEW EVM obligations only.

The expected hashes are owner-selected from the reproducible release manifest;
never obtain them from a counterparty. Existing HTLC recovery calls do not invoke
this preflight. A failed RPC or missing finality never becomes a successful check.
"""
from __future__ import annotations
from .canonical import exact_fields,hex32
from .errors import require,SwapError
from .evm import keccak256,address_bytes


def _hex(value):
    require(type(value) is str and value.startswith('0x') and len(value)%2==0,
            'DEPLOYMENT_ENCODING','Invalid hexadecimal chain response')
    try:return bytes.fromhex(value[2:])
    except ValueError as e:raise SwapError('DEPLOYMENT_ENCODING','Malformed hexadecimal chain response') from e


def verify_deployment(rpc,contract,manifest):
    require(type(manifest) is dict,'DEPLOYMENT_REQUIRED','Install an owner-verified deployment manifest before new EVM trades')
    kind=manifest.get('kind')
    require(kind in {'create','create2'},'DEPLOYMENT_KIND','Unsupported deployment profile')
    fields={'kind','transaction_id','creation_hash'}
    if kind=='create2':fields|={'factory','factory_runtime_hash','salt'}
    exact_fields(manifest,fields)
    txid='0x'+hex32(manifest['transaction_id'].removeprefix('0x'))
    expected=hex32(manifest['creation_hash']);address_bytes(contract)
    tx=rpc('eth_getTransactionByHash',txid);receipt=rpc('eth_getTransactionReceipt',txid)
    require(type(tx) is dict and type(receipt) is dict,'DEPLOYMENT_UNAVAILABLE','Deployment transaction is unavailable')
    require(str(tx.get('hash','')).lower()==txid.lower() and str(receipt.get('transactionHash','')).lower()==txid.lower(),
            'DEPLOYMENT_BINDING','Deployment transaction hash mismatch')
    require(int(receipt.get('status','0x0'),16)==1,'DEPLOYMENT_FAILED','Deployment transaction did not succeed')
    block=rpc('eth_getBlockByNumber',receipt['blockNumber'],False)
    final=rpc('eth_getBlockByNumber','finalized',False)
    require(block and block.get('hash')==receipt.get('blockHash') and tx.get('blockHash')==receipt.get('blockHash'),
            'DEPLOYMENT_REORG','Deployment receipt is not on the canonical chain')
    require(final and int(final['number'],16)>=int(receipt['blockNumber'],16),
            'DEPLOYMENT_NOT_FINAL','Deployment has not reached configured finality')
    data=_hex(tx.get('input','0x'))
    if kind=='create':
        require(tx.get('to') is None and str(receipt.get('contractAddress','')).lower()==contract.lower(),
                'DEPLOYMENT_BINDING','Not the direct deployment of this contract')
        init=data
    else:
        factory=manifest['factory'];address_bytes(factory);salt=bytes.fromhex(hex32(manifest['salt']))
        require(str(tx.get('to','')).lower()==factory.lower() and len(data)>32 and data[:32]==salt,
                'DEPLOYMENT_BINDING','CREATE2 factory call differs from the selected profile')
        code=_hex(rpc('eth_getCode',factory,receipt['blockNumber']))
        require(code and keccak256(code).hex()==hex32(manifest['factory_runtime_hash']),
                'DEPLOYMENT_FACTORY','Factory runtime differs from owner-selected code hash')
        init=data[32:]
        predicted='0x'+keccak256(b'\xff'+address_bytes(factory)+salt+keccak256(init))[-20:].hex()
        require(predicted.lower()==contract.lower(),'DEPLOYMENT_BINDING','CREATE2 address does not match exact init code')
    require(init and keccak256(init).hex()==expected,'DEPLOYMENT_CREATION','Creation bytecode differs from release manifest')
    # Re-read after assembling the observations to reject a mixed-reorg view.
    require(rpc('eth_getBlockByNumber',receipt['blockNumber'],False)['hash']==receipt['blockHash'],
            'DEPLOYMENT_REORG','Deployment changed during verification')
    return {'verified':True,'transaction_id':txid,'block_hash':receipt['blockHash'],
            'creation_hash':expected,'source':'independently configured local EVM client'}
