"""Local inspection, paired generation and calibrated directions."""
from __future__ import annotations
import copy
import hashlib
import time
from pathlib import Path
import numpy as np
import torch
from .codec import require, identity, sha384, canonical, LabError
from .operators import InterventionSession, Capture, cache_fingerprint
from .models import load_local


def encode_prompt(prompt, tokenizer, vocab_size=32):
    require(type(prompt) is str and 0 < len(prompt.encode()) <= 65536, 'PROMPT', 'Prompt must be 1..65536 UTF-8 bytes')
    if tokenizer is None:
        # Explicit token-ID input for the synthetic scientific model; never
        # presented as human-language understanding.
        try: ids = [int(t) for t in prompt.split()]
        except ValueError as e: raise LabError('TINY_PROMPT', 'Tiny model accepts space-separated integer token IDs') from e
        require(ids and all(0 <= x < vocab_size for x in ids), 'TOKEN', 'Token outside tiny vocabulary')
    else:
        ids = tokenizer.encode(prompt, add_special_tokens=True)
    require(0 < len(ids) <= 2048, 'TOKEN_BUDGET', 'At most 2048 prompt tokens')
    return ids


def generate(model, tokenizer, adapter, binding, prompt, *, profile=None, tensors=None, max_new_tokens=32,
             seed=0, capture=None, fence=None, cancel=None, device='cpu'):
    require(type(max_new_tokens) is int and 1 <= max_new_tokens <= 256, 'TOKEN_BUDGET', 'Output tokens outside 1..256')
    require(type(seed) is int and 0 <= seed < 2**31, 'SEED', 'Invalid seed')
    ids = encode_prompt(prompt, tokenizer, model.config_dict['vocab_size'] if hasattr(model,'config_dict') else 32)
    require(not hasattr(model, 'config_dict') or len(ids)+max_new_tokens <= 512, 'CONTEXT', 'Tiny context budget exceeded')
    start = time.perf_counter_ns()
    outputs = []
    profile_id = identity('BTX/NeuronLab/Profile/1', profile) if profile else None
    namespace = cache_fingerprint(binding, profile_id, f'torch/{torch.__version__}', str(next(model.parameters()).dtype),
                                  sha384(bytes(str(ids), 'ascii')), 'request-private/phase-aware/v1')
    # Greedy decoding makes the comparison reproducible on the SAME backend.
    # No assertion of bitwise cross-device equivalence is made.
    with InterventionSession(model, adapter, binding, profile, tensors, capture, fence) as session:
        with torch.inference_mode():
            tokens = torch.tensor([ids], dtype=torch.long, device=device)
            past = None
            for step in range(max_new_tokens):
                if cancel is not None: require(not cancel.is_set(), 'CANCELLED', 'Generation cancelled')
                if fence: fence()
                if past is None:
                    data, offset = tokens, 0
                else:
                    data, offset = tokens[:, -1:], tokens.shape[1]-1
                session.before_forward(len(ids), offset)
                result = model(input_ids=data, use_cache=True, past_key_values=past,
                               attention_mask=torch.ones_like(tokens))
                logits = result.logits[:, -1, :].float()
                require(torch.isfinite(logits).all().item(), 'NONFINITE_LOGITS', 'Invalid output logits')
                nxt = int(logits.argmax(-1).item())
                past = getattr(result, 'past_key_values', None)
                outputs.append(nxt)
                tokens = torch.cat([tokens, torch.tensor([[nxt]], device=device)], -1)
                if tokenizer is not None and nxt == tokenizer.eos_token_id: break
            if fence: fence()  # final result-release revocation fence
    text = ' '.join(map(str, outputs)) if tokenizer is None else tokenizer.decode(outputs, skip_special_tokens=True)
    return {'generated': True, 'text': text, 'token_ids': outputs, 'profile_id': profile_id, 'cache_namespace': namespace,
            'elapsed_us': (time.perf_counter_ns()-start)//1000, 'sampling': 'greedy', 'seed_recorded_not_used_by_greedy': seed,
            'capture': capture.result() if capture else None,
            'scope': 'SYNTHETIC_TINY_MODEL' if tokenizer is None else 'LOCAL_MODEL',
            'weight_mutation': False, 'remote_inference': False}


def compare(root, capsule, prompt, *, max_new_tokens=16, selected_layer=0, selected_units=None,
            fence=None, device='cpu'):
    model, tokenizer, adapter, binding = load_local(Path(root), capsule.profile['binding'], device=device)
    from .schema import compatibility
    require(compatibility(capsule.profile, binding)['compatible'], 'INCOMPATIBLE', 'Selected model changed')
    variants = [('baseline', None), ('positive', capsule.profile)]
    negative = copy.deepcopy(capsule.profile)
    for op in negative['operations']:
        # Clamp has no meaningful "negative clamp". Keep it unchanged and label
        # the exact transform. Mixed operators must be inspected by the user.
        if op['kind'] != 'neuron_clamp': op['coefficient_ppm'] *= -1
    variants.append(('sign-reversed', negative))
    result = []
    for name, profile in variants:
        capture = Capture([selected_layer], selected_units or [0,1,2], max_records=1024)
        response = generate(model, tokenizer, adapter, binding, prompt, profile=profile,
                            tensors=capsule.tensors, max_new_tokens=max_new_tokens, capture=capture, fence=fence, device=device)
        result.append({'arm': name, **response})
    return {'schema': 'btx.neuronlab.comparison/1', 'binding': binding, 'profile_id': capsule.id,
            'arms': result, 'warning': 'Exploratory examples, not an evaluation or semantic proof. Reversed scale means x(-s), not x(1-s). Clamp is unchanged.'}


def extract_direction(positive, reference, *, neutral=None, variance_ppm=500000):
    """Contrastive mean, optional neutral-PCA removal, then unit normalization.

    reference may be a grand mean built from a declared concept panel. Supplying
    a contrast corpus instead is a different estimator and must be recorded.
    """
    a,b = np.asarray(positive, dtype=np.float64), np.asarray(reference, dtype=np.float64)
    require(a.ndim == b.ndim == 2 and a.shape[1] == b.shape[1] and 2 <= a.shape[0] <= 4096 and 2 <= b.shape[0] <= 4096 and a.shape[1] <= 8192,
            'DIRECTION_DATA', 'Bounded aligned capture matrices required')
    require(np.isfinite(a).all() and np.isfinite(b).all(), 'NONFINITE', 'Invalid captures')
    vector = a.mean(0) - b.mean(0)
    removed = 0
    if neutral is not None:
        n = np.asarray(neutral, dtype=np.float64)
        require(n.ndim == 2 and n.shape[1] == a.shape[1] and 2 <= n.shape[0] <= 4096 and np.isfinite(n).all(), 'NEUTRAL', 'Invalid neutral capture')
        require(type(variance_ppm) is int and 1 <= variance_ppm <= 999999, 'PCA', 'Invalid neutral variance threshold')
        centered = n - n.mean(0)
        _, singular, vh = np.linalg.svd(centered, full_matrices=False)
        energy = singular**2
        if energy.sum() > 0:
            removed = int(np.searchsorted(np.cumsum(energy)/energy.sum(), variance_ppm/1e6)) + 1
            q = vh[:removed]
            vector -= (q @ vector) @ q
    norm = float(np.linalg.norm(vector))
    require(norm > 1e-10, 'DEGENERATE_DIRECTION', 'Direction has negligible norm after controls')
    direction = np.asarray(vector/norm, dtype='<f4')
    return direction, {'method':'mean-difference/neutral-PCA/v1', 'positive_samples':a.shape[0],
        'reference_samples':b.shape[0], 'neutral_components_removed':removed,
        'positive_capture_hash':sha384(b'BTX/NeuronLab/MatrixF64/1\0'+canonical(list(a.shape))+a.astype('<f8').tobytes()),
        'reference_capture_hash':sha384(b'BTX/NeuronLab/MatrixF64/1\0'+canonical(list(b.shape))+b.astype('<f8').tobytes()),
        'neutral_capture_hash':sha384(b'BTX/NeuronLab/MatrixF64/1\0'+canonical(list(n.shape))+n.astype('<f8').tobytes()) if neutral is not None else None,
        'direction_f32_hash':sha384(b'BTX/NeuronLab/DirectionF32/1\0'+direction.tobytes()),
        'pre_normalization_norm_millionths':round(norm*1e6),
        'claim':'DATASET_CONTRAST_DIRECTION_NOT_AN_EMOTION_OR_CONCEPT_GUARANTEE'}


def down_projection_lens(adapter, layer, unit, unembedding, topk=12):
    """Static weight projection only, explicitly not a causal circuit proof."""
    require(1 <= topk <= 64, 'LENS', 'Invalid top-k')
    col = adapter.down_columns(layer, [unit])[:,0]
    w = unembedding.detach().float()
    require(w.ndim == 2 and w.shape[1] == col.shape[0], 'LENS', 'Unembedding width mismatch')
    scores = w @ col
    k = min(topk, scores.numel())
    up = torch.topk(scores, k); down = torch.topk(-scores, k)
    return {'up': [{'token':int(i), 'projection_millionths':round(float(v)*1e6)} for i,v in zip(up.indices,up.values)],
            'down': [{'token':int(i), 'projection_millionths':round(-float(v)*1e6)} for i,v in zip(down.indices,down.values)],
            'kind':'STATIC_WEIGHT_PROJECTION_NOT_CAUSAL_EFFECT'}
