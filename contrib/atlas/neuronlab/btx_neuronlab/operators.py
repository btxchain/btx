"""Request-local tensor interventions. Pure numeric recipes never contain code."""
from __future__ import annotations
from dataclasses import dataclass
import threading
import weakref
import torch
from .codec import require, identity, LabError
from .schema import validate_profile, compatibility

_LOCKS = weakref.WeakKeyDictionary()
_LOCK_GUARD = threading.Lock()

def model_lock(model):
    with _LOCK_GUARD:
        if model not in _LOCKS: _LOCKS[model] = threading.Lock()
        return _LOCKS[model]


def site_for(kind):
    if kind.startswith('neuron_'): return 'mlp_post_activation'
    if kind == 'head_scale': return 'attention_pre_output'
    return 'residual_post'


def cache_fingerprint(binding, profile_id, runtime, precision, tokenization_hash, phase_policy):
    return identity('BTX/NeuronLab/CacheNamespace/1', {
        'binding': binding, 'profile_id': profile_id, 'runtime': runtime,
        'precision': precision, 'tokenization_hash': tokenization_hash, 'phase_policy': phase_policy})


def token_mask(op, positions, prompt_length):
    mask = positions >= op['token_start']
    if op['token_end'] >= 0: mask = mask & (positions < op['token_end'])
    if op['phase'] == 'prefill': mask = mask & (positions < prompt_length)
    elif op['phase'] == 'decode': mask = mask & (positions >= prompt_length)
    return mask


def apply_site(tensor, operations, tensors, positions, prompt_length, heads, *, maximum_delta_ratio=8.0):
    """[batch, tokens, width]; fp32 edits, original dtype restored.

    Operators execute in listed order. Every norm-normalized residual addition at
    this site uses the original pre-intervention site's norm (not a moving norm).
    No in-place write touches shared model activations or weight storage.
    """
    require(tensor.ndim == 3 and tensor.shape[1] == len(positions), 'ACTIVATION_SHAPE', 'Expected [batch, tokens, width]')
    require(torch.isfinite(tensor).all().item(), 'NONFINITE', 'Nonfinite input activation')
    if not operations: return tensor
    original = tensor.float()
    current = original.clone()
    base_norm = original.norm(dim=-1, keepdim=True)
    for op in operations:
        mask = token_mask(op, positions, prompt_length).to(device=tensor.device)[None, :, None]
        if not mask.any().item(): continue
        kind, coefficient = op['kind'], op['coefficient_ppm'] / 1_000_000
        changed = current.clone()
        if kind == 'neuron_scale':
            changed[..., op['indices']] = current[..., op['indices']] * coefficient
        elif kind == 'neuron_add':
            if op['normalization'] == 'residual_median_downcol':
                c = op['calibration']
                dose = torch.tensor([coefficient * c['residual_median_millionths'] / n for n in c['down_column_norms_millionths']], device=current.device, dtype=torch.float32)
            else: dose = coefficient
            changed[..., op['indices']] = current[..., op['indices']] + dose
        elif kind == 'neuron_clamp':
            lo, hi = [v/1_000_000 for v in op['bounds_ppm']]
            changed[..., op['indices']] = current[..., op['indices']].clamp(lo, hi)
        elif kind == 'head_scale':
            require(current.shape[-1] % heads == 0, 'HEAD_SHAPE', 'Head output width is not divisible')
            v = changed.reshape(*current.shape[:-1], heads, current.shape[-1]//heads)
            v[..., op['indices'], :] *= coefficient
        elif kind in {'residual_add', 'residual_project_out'}:
            vector = tensors[op['tensor']].to(current.device, dtype=torch.float32)
            if kind == 'residual_add':
                scale = base_norm if op['normalization'] == 'token_l2' else 1.0
                changed = current + coefficient * scale * vector
            else:
                changed = current - coefficient * (current * vector).sum(-1, keepdim=True) * vector
        elif kind == 'sae_feature_add':
            # Rectified affine SAE; residual-error-preserving feature edit.
            s = op['sae']
            enc, dec, bias = (tensors[s[k]].to(current.device, dtype=torch.float32) for k in ('encoder', 'decoder', 'bias'))
            f = s['feature']
            z = torch.relu(torch.matmul(current, enc[f]) + bias[f])
            edited = torch.clamp(z + coefficient, min=0)
            changed = current + (edited-z)[..., None] * dec[:, f]
        else:
            raise LabError('OPERATOR', 'Unknown operator reached executor')
        current = torch.where(mask, changed, current)
    require(torch.isfinite(current).all().item(), 'NONFINITE', 'Intervention produced nonfinite activations')
    # A hard operator-owned guard, not a claim of behavioral safety.
    ratio = (current-original).norm(dim=-1) / original.norm(dim=-1).clamp_min(1e-6)
    require(ratio.max().item() <= maximum_delta_ratio, 'DELTA_BUDGET', 'Intervention exceeded local activation-delta budget')
    restored = current.to(tensor.dtype)
    require(torch.isfinite(restored).all().item(), 'DTYPE_OVERFLOW', 'Intervention overflowed runtime precision')
    return restored


@dataclass
class PositionContext:
    prompt_length: int = 0
    offset: int = 0
    budget_tokens: int = 4096


class Capture:
    """Bounded selected-unit captures. Pre/post values are explicitly distinguished."""
    def __init__(self, selected_layers=None, units=None, max_records=4096):
        self.layers = set(selected_layers or [0])
        self.units = list(units or [0])
        require(len(self.layers) <= 8 and len(self.units) <= 64 and 0 < max_records <= 8192, 'CAPTURE_BUDGET', 'Capture selection exceeds budget')
        require(all(type(x) is int and 0 <= x <= 131071 for x in self.units), 'CAPTURE_INDEX', 'Invalid selected unit')
        self.max_records, self.records, self.omitted = max_records, [], 0

    def observe(self, layer, site, stage, value, positions):
        if layer not in self.layers: return
        units = [x for x in self.units if x < value.shape[-1]]
        if not units: return
        remaining = self.max_records-len(self.records)
        n = min(len(positions), max(0, remaining//len(units)))
        self.omitted += (len(positions)-n)*len(units)
        # Only selected coordinates cross from GPU to CPU.
        values = value[0, :n, units].detach().float().cpu()
        for j in range(n):
            for k, unit in enumerate(units):
                number = float(values[j, k])
                self.records.append({'layer': layer, 'site': site, 'stage': stage,
                    'token': int(positions[j]), 'unit': unit, 'value_millionths': round(number*1_000_000)})

    def result(self):
        return {'schema': 'btx.neuronlab.capture/1', 'records': self.records, 'omitted_records': self.omitted,
                'complete': self.omitted == 0, 'semantics': 'MEASURED_COORDINATES_NOT_SEMANTIC_LABELS'}


class InterventionSession:
    """One model, one active request, one exact profile. Cleanup is unconditional."""
    def __init__(self, model, adapter, binding, profile=None, tensors=None, capture=None, fence=None, max_delta_ratio=8.0):
        self.model, self.adapter, self.binding = model, adapter, binding
        self.profile, self.capture, self.fence = profile, capture, fence
        self.context = PositionContext()
        self.max_delta_ratio = max_delta_ratio
        self.handles, self.tensor_map = [], {}
        self.lock = model_lock(model)
        self.entered = False
        if profile:
            validate_profile(profile)
            require(compatibility(profile, binding)['compatible'], 'INCOMPATIBLE', 'Profile/model binding mismatch')
            self.tensor_map = {k: torch.tensor(v.copy(), dtype=torch.float32) for k, v in (tensors or {}).items()}
            require(set(self.tensor_map) == set(profile['tensors']), 'TENSORS', 'Runtime tensor set mismatch')
        self.by_site = {}
        for op in profile['operations'] if profile else []:
            self.by_site.setdefault((op['layer'], site_for(op['kind'])), []).append(op)

    def before_forward(self, prompt_length, offset):
        require(self.entered, 'SESSION', 'Session is not active')
        self.context.prompt_length, self.context.offset = prompt_length, offset
        if self.fence: self.fence()

    def _edit(self, layer, site, x):
        require(x.ndim == 3 and x.shape[0] == 1 and x.shape[1] <= self.context.budget_tokens, 'BATCH_SCOPE', 'This reference adapter admits one bounded request')
        positions = torch.arange(self.context.offset, self.context.offset+x.shape[1], device=x.device)
        if self.capture: self.capture.observe(layer, site, 'pre', x, positions)
        ops = self.by_site.get((layer, site), [])
        out = apply_site(x, ops, self.tensor_map, positions, self.context.prompt_length,
                         self.binding['heads'], maximum_delta_ratio=self.max_delta_ratio) if ops else x
        if self.capture: self.capture.observe(layer, site, 'post', out, positions)
        return out

    def __enter__(self):
        require(self.lock.acquire(blocking=False), 'MODEL_BUSY', 'Another intervention session owns this model')
        try:
            require(not self.model.training, 'TRAIN_MODE', 'Inference interventions require eval mode; training dropout is not an inference switch')
            if self.fence: self.fence()
            targets = set(self.by_site)
            if self.capture:
                targets |= {(l, site) for l in self.capture.layers for site in ('mlp_post_activation', 'residual_post')}
            for layer, site in sorted(targets):
                module, position = self.adapter.hook_target(layer, site)
                if position == 'pre':
                    def pre(mod, args, l=layer, s=site):
                        return (self._edit(l, s, args[0]), *args[1:])
                    self.handles.append(module.register_forward_pre_hook(pre))
                else:
                    def post(mod, args, out, l=layer, s=site):
                        if isinstance(out, tuple): return (self._edit(l, s, out[0]), *out[1:])
                        return self._edit(l, s, out)
                    self.handles.append(module.register_forward_hook(post))
            self.entered = True
            return self
        except BaseException:
            for h in self.handles: h.remove()
            self.handles.clear()
            self.lock.release()
            raise

    def __exit__(self, *args):
        for h in self.handles: h.remove()
        self.handles.clear()
        self.tensor_map.clear()
        self.entered = False
        self.lock.release()
