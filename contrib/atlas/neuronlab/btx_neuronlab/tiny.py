"""Small real causal transformer for reproducible local experiments, NOT an LLM benchmark."""
from __future__ import annotations
import math
from types import SimpleNamespace
from pathlib import Path
import torch
from torch import nn
import torch.nn.functional as F
from .codec import canonical, atomic_write, require

class MLP(nn.Module):
    def __init__(self, width, intermediate, activation, dropout):
        super().__init__()
        self.up_proj = nn.Linear(width, intermediate, bias=False)
        self.gate_proj = nn.Linear(width, intermediate, bias=False) if activation == 'silu' else None
        self.down_proj = nn.Linear(intermediate, width, bias=False)
        self.activation = activation
        self.dropout = nn.Dropout(dropout)
    def forward(self, x):
        if self.gate_proj is not None: h = F.silu(self.gate_proj(x)) * self.up_proj(x)
        else: h = F.gelu(self.up_proj(x))
        return self.dropout(self.down_proj(h))

class Attention(nn.Module):
    def __init__(self, width, heads, dropout):
        super().__init__()
        self.qkv = nn.Linear(width, 3*width, bias=False)
        self.out_proj = nn.Linear(width, width, bias=False)
        self.heads, self.dropout = heads, dropout
    def forward(self, x):
        b,t,d = x.shape
        q,k,v = self.qkv(x).reshape(b,t,3,self.heads,d//self.heads).unbind(2)
        h = F.scaled_dot_product_attention(q.transpose(1,2), k.transpose(1,2), v.transpose(1,2),
            is_causal=True, dropout_p=self.dropout if self.training else 0.0)
        return self.out_proj(h.transpose(1,2).contiguous().reshape(b,t,d))

class Block(nn.Module):
    def __init__(self, width, intermediate, heads, activation, dropout):
        super().__init__()
        self.ln1, self.ln2 = nn.LayerNorm(width), nn.LayerNorm(width)
        self.attention = Attention(width, heads, dropout)
        self.mlp = MLP(width, intermediate, activation, dropout)
        self.drop = nn.Dropout(dropout)
    def forward(self, x):
        x = x + self.drop(self.attention(self.ln1(x)))
        return x + self.mlp(self.ln2(x))

class TinyLM(nn.Module):
    def __init__(self, width=24, intermediate=64, layers=2, heads=4, vocab=32, activation='gelu', dropout=0.0):
        super().__init__()
        self.embedding = nn.Embedding(vocab, width)
        self.positions = nn.Embedding(512, width)
        self.drop = nn.Dropout(dropout)
        self.blocks = nn.ModuleList([Block(width, intermediate, heads, activation, dropout) for _ in range(layers)])
        self.norm = nn.LayerNorm(width)
        self.lm_head = nn.Linear(width, vocab, bias=False)
        self.config_dict = {'architectures':['BTXTinyLM'], 'model_type':'btx_tiny', 'hidden_size':width,
            'intermediate_size':intermediate, 'num_hidden_layers':layers, 'num_attention_heads':heads,
            'vocab_size':vocab, 'hidden_act':activation, 'dropout_ppm':round(dropout*1_000_000), 'torch_dtype':'float32'}
    @classmethod
    def from_config(cls,c):
        return cls(width=c['hidden_size'], intermediate=c['intermediate_size'], layers=c['num_hidden_layers'],
            heads=c['num_attention_heads'], vocab=c['vocab_size'], activation=c['hidden_act'], dropout=c['dropout_ppm']/1e6)
    def forward(self, input_ids, **kwargs):
        b,t = input_ids.shape
        require(t <= 512, 'CONTEXT', 'Tiny experiment context is at most 512 tokens')
        x = self.drop(self.embedding(input_ids) + self.positions(torch.arange(t, device=input_ids.device))[None])
        for block in self.blocks: x = block(x)
        return SimpleNamespace(logits=self.lm_head(self.norm(x)), past_key_values=None)
    def save(self, root: Path):
        from safetensors.torch import save
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(root/'config.json', canonical(self.config_dict))
        atomic_write(root/'model.safetensors', save({k:v.detach().contiguous().cpu() for k,v in self.state_dict().items()}))
