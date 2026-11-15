"""Portable, signed, data-only SafeTensors capsules.

Metadata carries a canonical profile and detached ML-DSA signature. Tensor bytes
are signed through their exact little-endian f32 hashes. No pickle, model code,
URLs, loader hooks, import instructions or executable plugins are permitted.
"""
from __future__ import annotations
import copy
import struct
import numpy as np
from .codec import require, keys, loads, canonical, identity, sha384, LabError
from .schema import validate_profile
from .crypto import MLDSA44

MAX_CAPSULE = 16_777_216
MAX_HEADER = 1_048_576
MAX_TENSORS = 128


def tensor_records(tensors):
    result, arrays = {}, {}
    require(type(tensors) is dict and len(tensors) <= MAX_TENSORS, 'TENSORS', 'Invalid tensor map')
    for name, value in tensors.items():
        require(type(name) is str and name != '__metadata__', 'TENSOR_NAME', 'Invalid tensor name')
        a = np.asarray(value, dtype='<f4', order='C')
        require(1 <= a.ndim <= 2 and 0 < a.size <= 2_097_152 and np.isfinite(a).all(), 'TENSOR', 'Invalid, nonfinite or oversized tensor')
        a = np.ascontiguousarray(a, dtype='<f4')
        result[name] = {'dtype': 'F32', 'shape': list(a.shape), 'sha384': sha384(a.tobytes(order='C'))}
        arrays[name] = a
    return result, arrays


def encode(profile, tensors, signer: MLDSA44, key_file):
    profile = copy.deepcopy(profile)
    records, arrays = tensor_records(tensors or {'btx_capsule_marker': [1.0]})
    profile['tensors'] = records
    validate_profile(profile)
    signed = signer.sign(profile, key_file)
    metadata = {'btx.artifact.kind': 'INTERVENTION_PROFILE', 'btx.neuronlab.profile': canonical(profile).decode(),
                'btx.neuronlab.signature': canonical(signed).decode(), 'btx.neuronlab.schema': '1'}
    header = {'__metadata__': metadata}
    offset, payload = 0, []
    for name in sorted(arrays):
        raw = arrays[name].tobytes(order='C')
        header[name] = {'dtype': 'F32', 'shape': list(arrays[name].shape), 'data_offsets': [offset, offset + len(raw)]}
        payload.append(raw)
        offset += len(raw)
    raw_header = canonical(header)
    raw_header += b' ' * ((-len(raw_header)) % 8)
    result = struct.pack('<Q', len(raw_header)) + raw_header + b''.join(payload)
    require(len(result) <= MAX_CAPSULE, 'SIZE', 'Capsule exceeds 16 MiB')
    return result


class Capsule:
    def __init__(self, raw: bytes, verifier: MLDSA44):
        require(type(raw) is bytes and 8 < len(raw) <= MAX_CAPSULE, 'SIZE', 'Invalid capsule length')
        length, = struct.unpack('<Q', raw[:8])
        require(2 <= length <= MAX_HEADER and 8 + length <= len(raw), 'HEADER', 'Invalid SafeTensors header size')
        header = loads(raw[8:8+length], limit=MAX_HEADER)
        require(type(header) is dict and '__metadata__' in header and len(header) <= MAX_TENSORS + 1, 'HEADER', 'Invalid capsule header')
        meta = header['__metadata__']
        keys(meta, {'btx.artifact.kind', 'btx.neuronlab.profile', 'btx.neuronlab.signature', 'btx.neuronlab.schema'})
        require(meta['btx.artifact.kind'] == 'INTERVENTION_PROFILE' and meta['btx.neuronlab.schema'] == '1', 'KIND', 'Not an intervention capsule')
        self.profile = validate_profile(loads(meta['btx.neuronlab.profile']))
        self.signature = loads(meta['btx.neuronlab.signature'])
        require(canonical(self.profile).decode() == meta['btx.neuronlab.profile'], 'CANONICAL', 'Profile must use canonical encoding')
        require(set(header) - {'__metadata__'} == set(self.profile['tensors']), 'TENSORS', 'Tensor set differs from signed manifest')
        offset, self.tensors = 0, {}
        for name in sorted(self.profile['tensors']):
            entry = header[name]
            keys(entry, {'dtype', 'shape', 'data_offsets'})
            rec = self.profile['tensors'][name]
            require(entry['dtype'] == 'F32' and entry['shape'] == rec['shape'], 'TENSOR', 'Tensor schema mismatch')
            size = 4
            for n in rec['shape']: size *= n
            require(entry['data_offsets'] == [offset, offset + size], 'OFFSETS', 'Noncontiguous, overlapping or reordered tensor offsets')
            start = 8 + length + offset
            require(start + size <= len(raw), 'TRUNCATED', 'Tensor payload truncated')
            payload = raw[start:start+size]
            require(sha384(payload) == rec['sha384'], 'TENSOR_HASH', 'Tensor bytes do not match signed digest')
            a = np.frombuffer(payload, dtype='<f4').reshape(rec['shape'])
            require(np.isfinite(a).all(), 'NONFINITE', 'Nonfinite control tensor')
            self.tensors[name] = a
            offset += size
        require(8 + length + offset == len(raw), 'TRAILING_BYTES', 'Trailing bytes refused')
        for o in self.profile['operations']:
            if o['tensor'] is not None:
                norm = float(np.linalg.norm(self.tensors[o['tensor']].astype(np.float64)))
                require(abs(norm - 1) <= 1e-4, 'DIRECTION_NORM', 'Directions must be unit vectors; dose is separate')
        self.publisher = verifier.verify(self.profile, self.signature)
        self.id = identity('BTX/NeuronLab/Profile/1', self.profile)
        self.raw = raw
        self.bytes_hash = sha384(raw)

    def summary(self):
        return {'id': self.id, 'title': self.profile['title'], 'publisher': self.publisher,
                'bytes_hash': self.bytes_hash, 'bytes': len(self.raw), 'binding': self.profile['binding'],
                'privacy': self.profile['privacy'], 'signature_valid': True,
                'behavioral_safety': 'NOT_ESTABLISHED_BY_SIGNATURE', 'operations': len(self.profile['operations'])}
