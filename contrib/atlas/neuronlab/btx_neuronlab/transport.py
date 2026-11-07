"""Reuse BTX's existing verified byte distribution, not a new swarm controller.

A capsule is a SafeTensors *data artifact*, not an executable model. The native
host calls these plans using its own local RPC credentials; none enter Python.
These are plans until the native node has returned actual observations.
"""
from __future__ import annotations
from pathlib import Path
from .codec import require, keys, text, digest_text, read_file
from .capsule import Capsule, MAX_CAPSULE


def publish_plan(store, profile_id):
    cap=store.get(profile_id)
    require(cap.profile['privacy']=='public','PRIVATE_EXPORT','Only explicitly public profiles may enter public byte distribution')
    require(store.trust_status(cap.publisher)=='LOCALLY_TRUSTED_PUBLISHER','TRUST_REQUIRED','Publisher must be locally trusted')
    return {'schema':'btx.neuronlab.transport-plan/1','profile_id':cap.id,'capsule_sha384':cap.bytes_hash,
        'artifact_kind':'INTERVENTION_PROFILE_NOT_MODEL_CHECKPOINT',
        'method':'hostmodel','params':[str(store.root/'capsules'/f'{cap.id}.safetensors'),{'pin':True,'publish':False}],
        'index_publication':False,'automatic_activation':False,'automatic_spend_atoms':'0',
        'discovery':'explicit BTX resource URI; no global intervention directory is claimed'}


def acquire_plan(uri):
    text(uri,4096)
    require(uri.startswith('btx://') and '?' not in uri and '#' not in uri and not any(c.isspace()for c in uri), 'URI','Expected canonical model resource URI without query or fragment')
    return {'method':'getmodel','params':[uri,{'mode':'FREE_ONLY'}], 'automatic_activation':False,
            'next':'Wait for genuine completion, exportmodelpath, then verify capsule and original profile identity'}


def import_checkout(store, checkout:Path, expected_profile_id, op_id):
    digest_text(expected_profile_id)
    root=Path(checkout)
    require(root.is_dir() and not root.is_symlink(),'CHECKOUT','A verified native checkout directory is required')
    candidates=[]
    for p in root.iterdir():
        require(not p.is_symlink(),'SYMLINK','Checkout symlink refused')
        if p.is_file() and p.suffix=='.safetensors':candidates.append(p)
        else:
            require(p.name in {'manifest.json','model.btx','README.md','config.json'},'CHECKOUT','Unexpected checkout content')
    require(len(candidates)==1,'CHECKOUT','Exactly one capsule payload is required')
    raw=read_file(candidates[0],MAX_CAPSULE)
    cap=Capsule(raw,store.crypto)
    require(cap.id==expected_profile_id,'PROFILE_ID','Retrieved signed profile does not match the expected profile ID')
    return store.import_capsule(raw,op_id)


class ChunkReceiver:
    """Bounded in-order payload receiver for admitted native channels or offline transfer.

    This is a byte-transport component, not a network authentication implementation.
    Authentication must be supplied by the existing admitted BTX transport.
    """
    def __init__(self,total_bytes,expected_sha384):
        require(type(total_bytes)is int and 0<total_bytes<=MAX_CAPSULE,'SIZE','Invalid total payload size')
        digest_text(expected_sha384)
        self.total,self.expected,self.data=total_bytes,expected_sha384,bytearray()
    def add(self,offset,chunk):
        require(type(offset)is int and offset==len(self.data),'CHUNK_ORDER','Out-of-order or repeated chunk')
        require(type(chunk)is bytes and 0<len(chunk)<=65536 and len(self.data)+len(chunk)<=self.total,'CHUNK_SIZE','Invalid chunk length')
        self.data.extend(chunk)
    def finish(self,store,expected_profile_id,op_id):
        from .codec import sha384
        require(len(self.data)==self.total,'INCOMPLETE','Capsule download is incomplete')
        require(sha384(self.data)==self.expected,'BYTES_HASH','Transfer checksum failed')
        cap=Capsule(bytes(self.data),store.crypto)
        require(cap.id==expected_profile_id,'PROFILE_ID','Wrong signed profile identity')
        return store.import_capsule(bytes(self.data),op_id)
