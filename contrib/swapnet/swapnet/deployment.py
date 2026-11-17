"""Verify a native-ETH HTLC deployment from an owner-selected local chain client.

A runtime hash alone does not attest initial storage. Only the exact pinned init
code, via direct creation or the exact deterministic proxy profile, is accepted.
No public-chain deployment or successful receipt is asserted by these constants.
"""
from .market_controls import require
from .evm import keccak256

INIT_HASH='401e81e4ab795f39e48b76bda608771e10078e23cfc1d807983b05ee3da97cde'
RUNTIME_HASH='a06e30bad714ff02db5a2401a898bd7194d1c475b61bdab312ae194b1509e45d'
SALT='6c32ecc2f6028d26d3ac1321496eb9cff36cf20907d51a348ebc8113aa45139c'
PROXY='0x4e59b44847b379578588920ca78fbf26c0b4956c'
CONTRACT='0x944c528f2e206a93ceb32b4723cd25daa8f303ef'
# Arachnid/deterministic-deployment-proxy's 69-byte CREATE2 proxy runtime.
PROXY_RUNTIME='7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3'

def _hex(value,maximum=65536):
 require(type(value) is str and value.startswith('0x') and len(value)%2==0 and len(value)<=2+2*maximum,
         'DEPLOYMENT_PROOF','Invalid bounded hexadecimal RPC value')
 try:return bytes.fromhex(value[2:])
 except ValueError as e:raise ValueError('Invalid deployment hexadecimal') from e

def verify_deployment(rpc,contract,runtime_hash,transaction_id):
 require(type(transaction_id) is str and len(_hex(transaction_id,32))==32,'DEPLOYMENT_PROOF','A creation transaction ID is required')
 require(type(contract) is str and len(_hex(contract,20))==20,'DEPLOYMENT_PROOF','Invalid contract address')
 require(runtime_hash==RUNTIME_HASH,'DEPLOYMENT_ARTIFACT','This profile qualifies only the pinned HTLC artifact')
 tx=rpc('eth_getTransactionByHash',transaction_id)
 receipt=rpc('eth_getTransactionReceipt',transaction_id)
 require(isinstance(tx,dict) and isinstance(receipt,dict) and tx.get('hash','').lower()==transaction_id.lower() and
         receipt.get('transactionHash','').lower()==transaction_id.lower(),
         'DEPLOYMENT_UNAVAILABLE','Creation transaction and receipt are unavailable')
 require(int(receipt.get('status','0x0'),16)==1,'DEPLOYMENT_REVERTED','Deployment transaction did not succeed')
 block_number=receipt.get('blockNumber');block_hash=receipt.get('blockHash')
 block=rpc('eth_getBlockByNumber',block_number,False);finalized=rpc('eth_getBlockByNumber','finalized',False)
 require(block and finalized and block.get('hash')==block_hash and int(finalized['number'],16)>=int(block_number,16),
         'DEPLOYMENT_NOT_FINAL','Creation must be canonical and finalized')
 data=_hex(tx.get('input',''),16384)
 if tx.get('to') is None:
  require(str(receipt.get('contractAddress','')).lower()==contract.lower(),'DEPLOYMENT_ADDRESS','Creation receipt targets another address')
  init=data;profile='direct-create-pinned-init'
 else:
  require(str(tx['to']).lower()==PROXY and contract.lower()==CONTRACT and len(data)>32 and data[:32].hex()==SALT,
          'DEPLOYMENT_FACTORY','Unsupported factory or salt')
  require(_hex(rpc('eth_getCode',PROXY,block_number)).hex()==PROXY_RUNTIME,
          'DEPLOYMENT_FACTORY','Factory runtime is not the pinned permissionless proxy')
  init=data[32:]
  derived='0x'+keccak256(b'\xff'+bytes.fromhex(PROXY[2:])+bytes.fromhex(SALT)+keccak256(init))[-20:].hex()
  require(derived==contract.lower(),'DEPLOYMENT_ADDRESS','CREATE2 derivation mismatch');profile='create2-pinned-init'
 require(keccak256(init).hex()==INIT_HASH,'DEPLOYMENT_INIT','Unrecognized creation code; runtime equality is insufficient')
 require(keccak256(_hex(rpc('eth_getCode',contract,block_number))).hex()==runtime_hash,
         'DEPLOYMENT_RUNTIME','Unexpected runtime at deployment block')
 require(rpc('eth_getBlockByNumber',block_number,False).get('hash')==block_hash,
         'DEPLOYMENT_REORG','Chain changed during deployment verification')
 return {'profile':profile,'creation_transaction':transaction_id,'creation_block_hash':block_hash,
         'init_code_hash':INIT_HASH,'runtime_hash':runtime_hash,'contract':contract.lower(),
         'verified_by':'configured_local_chain_client','public_mainnet_qualification':False}
