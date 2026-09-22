#!/usr/bin/env python3
"""Local generate adapter for btx-modeld (BTX_MODEL_GENERATE).

Reads one JSON object from stdin:
  {"prompt":"...","max_new_tokens":32}

Writes one JSON line to stdout. Never downloads, never trust_remote_code,
never a network server, never spends.

SafeTensors: transformers + local_files_only. GGUF: BTX_LLAMA_CLI.
Missing deps → ok=false NOT_RUN (not a fake generate).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def fail(msg: str, code: int = 2) -> None:
    print(json.dumps({"ok": False, "error": msg, "generated": False}), flush=True)
    raise SystemExit(code)


def read_request(max_new_default: int) -> tuple[str, int]:
    raw = sys.stdin.readline()
    prompt = ""
    max_new = max_new_default
    if raw.strip():
        try:
            req = json.loads(raw)
        except json.JSONDecodeError as e:
            fail(f"stdin json: {e}")
        if not isinstance(req, dict):
            fail("stdin must be a JSON object")
        if "prompt" in req and req["prompt"] is not None:
            prompt = str(req["prompt"])
        if "max_new_tokens" in req and req["max_new_tokens"] is not None:
            max_new = int(req["max_new_tokens"])
    max_new = max(1, min(max_new, 512))
    if len(prompt) > 64 * 1024:
        fail("prompt too large")
    return prompt, max_new


def find_gguf(root: Path) -> Path | None:
    hits = list(root.rglob("*.gguf"))
    return hits[0] if hits else None


def find_safetensors(root: Path) -> bool:
    return any(root.rglob("*.safetensors"))


def generate_gguf(gguf: Path, prompt: str, max_new: int) -> None:
    cli = os.environ.get("BTX_LLAMA_CLI", "")
    if not cli or not os.path.isfile(cli) or not os.access(cli, os.X_OK):
        fail("GGUF checkout but BTX_LLAMA_CLI is not an executable; NOT_RUN")
    cmd = [
        cli,
        "-m",
        str(gguf),
        "-p",
        prompt,
        "-n",
        str(max_new),
        "-ngl",
        os.environ.get("BTX_LLAMA_NGL", "99"),
        "--no-display-prompt",
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("BTX_GENERATE_TIMEOUT_S", "600")),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        fail(f"llama-cli: {e}")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "llama-cli failed").strip().split("\n")[-1]
        fail(err[:500])
    text = (proc.stdout or "").strip()
    print(
        json.dumps(
            {
                "ok": True,
                "generated": True,
                "text": text,
                "backend": "llama.cpp",
                "format": "gguf",
                "remote_inference": False,
            }
        ),
        flush=True,
    )


def generate_safetensors(root: Path, prompt: str, max_new: int) -> None:
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as e:
        fail(f"transformers/torch not installed ({e}); set BTX_MODEL_GENERATE after installing; NOT_RUN")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    try:
        tok = AutoTokenizer.from_pretrained(
            str(root), local_files_only=True, trust_remote_code=False
        )
        model = AutoModelForCausalLM.from_pretrained(
            str(root),
            local_files_only=True,
            trust_remote_code=False,
            torch_dtype=torch.bfloat16 if device == "cuda" else torch.float32,
            device_map="auto" if device == "cuda" else None,
        )
        if device == "cpu":
            model = model.to(device)
        if tok.pad_token_id is None:
            tok.pad_token = tok.eos_token
        inputs = tok(prompt, return_tensors="pt")
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        with torch.no_grad():
            out = model.generate(
                **inputs,
                max_new_tokens=max_new,
                do_sample=False,
                pad_token_id=tok.pad_token_id,
            )
        text = tok.decode(out[0, inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
    except Exception as e:  # noqa: BLE001 — adapter fail-closes to JSON
        fail(f"transformers generate: {type(e).__name__}: {e}")
    print(
        json.dumps(
            {
                "ok": True,
                "generated": True,
                "text": text,
                "backend": "transformers",
                "format": "safetensors",
                "device": device,
                "remote_inference": False,
            }
        ),
        flush=True,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="BTX local generate adapter")
    ap.add_argument("--dir", required=True, help="materialized checkout")
    ap.add_argument("--max-new-tokens", type=int, default=32)
    args = ap.parse_args()
    root = Path(args.dir)
    if not root.exists():
        fail("checkout missing")
    prompt, max_new = read_request(args.max_new_tokens)
    if not prompt:
        fail("empty prompt")
    gguf = find_gguf(root)
    if gguf is not None:
        generate_gguf(gguf, prompt, max_new)
        return
    if find_safetensors(root):
        generate_safetensors(root, prompt, max_new)
        return
    fail("no GGUF or SafeTensors weights in checkout")


if __name__ == "__main__":
    main()
