#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Export trained tensors and consume the same bytes in btx-native-qualify.

The native consumer performs a verified CPU dense layer from resident checkpoint
bytes. This is neither a complete native decoder nor vendor-engine qualification.
The export is called in the training process; it never deserializes external .pt
files. Two independently pinned ML-DSA source receipts are required to consume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct

try:
    from .evidence import EvidenceError, HEX64, atomic_json, canonical, run_command, sha256_file, strict_json
except ImportError:
    from evidence import EvidenceError, HEX64, atomic_json, canonical, run_command, sha256_file, strict_json

MAX_CHECKPOINT = 256 * 1024 * 1024


def sha384_file(path: Path) -> str:
    # sha256_file also rejects symlinks, nonregular files and files over the cap.
    sha256_file(path, MAX_CHECKPOINT)
    hasher = hashlib.sha384()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def f32(value: float) -> float:
    try:
        result = struct.unpack("<f", struct.pack("<f", value))[0]
    except (OverflowError, struct.error) as exc:
        raise EvidenceError("tensor witness exceeds finite F32") from exc
    if not math.isfinite(result):
        raise EvidenceError("nonfinite tensor witness")
    return result


def linear_witness(weights: bytes, shape: list[int], bias: bytes = b"") -> dict:
    if len(shape) != 2 or any(type(n) is not int or not 1 <= n <= 65536 for n in shape):
        raise EvidenceError("dense witness requires a bounded two-dimensional F32 tensor")
    rows, columns = shape
    if len(weights) != rows * columns * 4 or len(weights) > MAX_CHECKPOINT:
        raise EvidenceError("dense tensor byte extent differs from shape")
    if bias and len(bias) != rows * 4:
        raise EvidenceError("dense bias shape differs")
    inputs = [f32(((i % 7) - 3) / 8) for i in range(columns)]
    output = []
    # Match native LinearF32: F32 input and weights, sequential F64 sum, final
    # F32 cast. No PyTorch matmul algorithm/TF32 reduction is substituted.
    for row in range(rows):
        value = struct.unpack_from("<f", bias, row * 4)[0] if bias else 0.0
        for column in range(columns):
            weight = struct.unpack_from("<f", weights, (row * columns + column) * 4)[0]
            if not math.isfinite(weight):
                raise EvidenceError("nonfinite trained tensor")
            value += weight * inputs[column]
        output.append(f32(value))
    return {"input": inputs, "expected_output": output}


def write_safetensors(path: Path, tensors: dict[str, dict]) -> dict:
    """Write a small, canonical F32 SafeTensors file with exact disjoint extents."""
    if not tensors or len(tensors) > 10000 or Path(path).exists() or Path(path).is_symlink():
        raise EvidenceError("export requires a new checkpoint and bounded tensor set")
    header, payload, offset = {}, [], 0
    for name, tensor in sorted(tensors.items()):
        if not isinstance(name, str) or not name or name == "__metadata__":
            raise EvidenceError("invalid tensor name")
        shape, data = tensor.get("shape"), tensor.get("data")
        if not isinstance(shape, list) or not shape or any(type(n) is not int or n < 1 for n in shape):
            raise EvidenceError("invalid F32 tensor shape")
        if not isinstance(data, bytes) or math.prod(shape) * 4 != len(data):
            raise EvidenceError("tensor bytes differ from shape")
        if offset + len(data) > MAX_CHECKPOINT:
            raise EvidenceError("checkpoint exceeds export bound")
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + len(data)]}
        offset += len(data)
        payload.append(data)
    raw = canonical(header)
    raw += b" " * ((8 - len(raw) % 8) % 8)
    if len(raw) > 8 * 1024 * 1024 or offset + len(raw) + 8 > MAX_CHECKPOINT:
        raise EvidenceError("checkpoint header exceeds export bound")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("xb") as target:
        target.write(struct.pack("<Q", len(raw)))
        target.write(raw)
        for data in payload:
            target.write(data)
    return {"path": Path(path).name, "sha256": sha256_file(path), "sha384": sha384_file(path),
            "bytes": Path(path).stat().st_size, "tensor_count": len(header)}


def export_trained_model(model, torch, destination: Path, training: dict) -> dict:
    """Export actual final in-memory weights, called only after replay succeeded."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise EvidenceError("trained export directory already exists")
    tensors = {}
    for name, tensor in model.state_dict().items():
        if not tensor.is_floating_point():
            raise EvidenceError("reference decoder export supports only floating tensors")
        value = tensor.detach().to(device="cpu", dtype=torch.float32).contiguous()
        data = value.numpy().astype("<f4", copy=False).tobytes()
        tensors[name] = {"shape": list(value.shape), "data": data}
    weights = next((name for name in ("head.weight", "lm_head.weight") if name in tensors), None)
    if weights is None:
        weights = next((name for name, tensor in tensors.items()
                        if name.endswith(".weight") and len(tensor["shape"]) == 2), None)
    if weights is None:
        raise EvidenceError("trained decoder has no native-compatible dense tensor")
    bias = weights.removesuffix("weight") + "bias"
    if bias not in tensors:
        bias = ""
    witness = linear_witness(tensors[weights]["data"], tensors[weights]["shape"],
                             tensors[bias]["data"] if bias else b"")
    witness.update({"weights": weights, "bias": bias})
    destination.mkdir(parents=True, mode=0o700)
    checkpoint = write_safetensors(destination / "trained.safetensors", tensors)
    identity = {"checkpoint_sha384": checkpoint["sha384"], "training": training,
                "architecture": type(model).__name__}
    manifest = {"schema": "BTX-TRAINED-NATIVE-EXPORT/1", "checkpoint": checkpoint,
                "artifact_id": hashlib.sha384(canonical(identity)).hexdigest(),
                "training": training, "linear": witness,
                "qualification_scope": "TRAINED_WEIGHTS_AND_CPU_DENSE_LAYER_ONLY",
                "complete_native_decoder": False, "release_qualified": False}
    manifest_path = destination / "export.json"
    atomic_json(manifest_path, manifest)
    return {"manifest_path": str(manifest_path.resolve()), "manifest_sha256": sha256_file(manifest_path),
            "checkpoint_sha256": checkpoint["sha256"], "checkpoint_sha384": checkpoint["sha384"],
            "artifact_id": manifest["artifact_id"], "native_consumption": "NOT_RUN"}


def prepare_native_request(export_path: Path, export_pin: str, sources_path: Path,
                           sources_pin: str, nonce: str) -> tuple[dict, dict]:
    if not HEX64.fullmatch(nonce) or sha256_file(export_path) != export_pin or sha256_file(sources_path) != sources_pin:
        raise EvidenceError("export/source manifest pin or challenge differs")
    exported = strict_json(Path(export_path).read_bytes())
    sources = strict_json(Path(sources_path).read_bytes())
    if exported.get("schema") != "BTX-TRAINED-NATIVE-EXPORT/1" or sources.get("schema") != "BTX-CHECKPOINT-SOURCES/1":
        raise EvidenceError("invalid checkpoint source/export schema")
    checkpoint = exported["checkpoint"]
    if not re.fullmatch(r"[0-9a-f]{96}", exported.get("artifact_id", "")):
        raise EvidenceError("invalid exported artifact identity")
    if type(checkpoint.get("bytes")) is not int or not 1 <= checkpoint["bytes"] <= MAX_CHECKPOINT:
        raise EvidenceError("invalid exported checkpoint extent")
    rows, keys = [], set()
    for source in sources.get("sources", []):
        path, receipt_path = Path(source["path"]), Path(source["receipt_path"])
        if not path.is_absolute() or not receipt_path.is_absolute():
            raise EvidenceError("source paths must be absolute")
        pin = source["expected_source_public_key"]
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{2624}", pin) or pin in keys:
            raise EvidenceError("independently pinned distinct ML-DSA-44 source keys required")
        keys.add(pin)
        if sha256_file(path, MAX_CHECKPOINT) != checkpoint["sha256"] or sha384_file(path) != checkpoint["sha384"]:
            raise EvidenceError("source bytes do not equal the actually trained checkpoint")
        if sha256_file(receipt_path) != source["receipt_sha256"]:
            raise EvidenceError("signed source receipt pin differs")
        raw = strict_json(receipt_path.read_bytes())
        receipt = raw.get("receipt", raw)
        expected = {"artifact_id": exported["artifact_id"], "checkpoint_sha384": checkpoint["sha384"],
                    "bytes": checkpoint["bytes"], "request_nonce": nonce, "source_public_key": pin}
        if any(type(receipt.get(key)) is not type(value) or receipt.get(key) != value for key, value in expected.items()):
            raise EvidenceError("source receipt is not bound to this trained export and challenge")
        rows.append({"path": str(path), "receipt": receipt, "expected_source_public_key": pin,
                     "expected_request_nonce": nonce})
    if not 2 <= len(rows) <= 16:
        raise EvidenceError("native acquisition requires two to sixteen independent source identities")
    return {"max_checkpoint_bytes": MAX_CHECKPOINT, "sources": rows, "linear": exported["linear"]}, exported


def consume(export_path: Path, export_pin: str, sources_path: Path, sources_pin: str,
            native_binary: Path, native_pin: str, nonce: str, work: Path) -> dict:
    request, exported = prepare_native_request(export_path, export_pin, sources_path, sources_pin, nonce)
    if sha256_file(native_binary) != native_pin:
        raise EvidenceError("native qualification executable pin differs")
    if work.exists() or work.is_symlink():
        raise EvidenceError("native bridge requires a fresh work directory")
    work.mkdir(parents=True, mode=0o700)
    request_path = work / "native-load.json"
    atomic_json(request_path, request)
    command = run_command([str(native_binary.resolve()), "load", str(request_path.resolve())], work, 120)
    if command["returncode"] or command["failure"]:
        raise EvidenceError("native trained-tensor consumer failed: " + command["stderr"][-500:])
    observed = strict_json(command["stdout"])
    if observed.get("success") is not True or observed.get("module_passed") is not True:
        raise EvidenceError("native tensor consumer did not pass its verified load")
    if observed.get("checkpoint_sha384") != exported["checkpoint"]["sha384"] or observed.get("bytes_consumed") != exported["checkpoint"]["bytes"]:
        raise EvidenceError("native consumer measured a different checkpoint")
    if type(observed.get("verified_source_identities")) is not int or observed["verified_source_identities"] < 2:
        raise EvidenceError("native consumer did not verify independent source identities")
    # Bind the final receipt to the same bytes before/after execution.
    prepare_native_request(export_path, export_pin, sources_path, sources_pin, nonce)
    if sha256_file(native_binary) != native_pin:
        raise EvidenceError("native consumer changed while executing")
    result = {"schema": "BTX-TRAINED-NATIVE-CONSUMPTION/1", "nonce": nonce,
              "export_sha256": export_pin, "sources_sha256": sources_pin, "native_binary_sha256": native_pin,
              "native_request_sha256": sha256_file(request_path), "command": command, "observed": observed,
              "training": exported["training"], "qualification_scope": "TRAINED_WEIGHTS_AND_CPU_DENSE_LAYER_ONLY",
              "complete_native_decoder": False, "native_vendor_engine": "NOT_EXERCISED", "release_qualified": False}
    atomic_json(work / "consumption.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("export", "sources", "native-bin", "work-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("export-sha256", "sources-sha256", "native-bin-sha256", "nonce"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = consume(args.export, args.export_sha256, args.sources, args.sources_sha256,
                         args.native_bin, args.native_bin_sha256, args.nonce, args.work_dir)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc), "release_qualified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
