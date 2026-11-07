#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Native model RPC workload using explicitly pinned owner-supplied model bytes.

Imported by native_node.py only when --model-run and its independent SHA-256 are
given. Performs host/export/load/generate/unload through the real default helper.
It never fetches a model, installs packages, grants remote inference, or spends.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

try:
    from .evidence import EvidenceError, HEX64, sha256_file, strict_json
    from .offline_image import safe_name
except ImportError:
    from evidence import EvidenceError, HEX64, sha256_file, strict_json
    from offline_image import safe_name

MAX_MODEL_BYTES = 64 * 1024 ** 3


def verify_model_files(root: Path, rows: list[dict]) -> list[dict]:
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or not root.is_absolute():
        raise EvidenceError("model root must be an absolute regular directory")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20000:
        raise EvidenceError("model must enumerate bounded exact input bytes")
    names, total, verified = set(), 0, []
    for row in rows:
        name = safe_name(row.get("path", ""))
        if name.casefold() in names:
            raise EvidenceError("duplicate model filename")
        names.add(name.casefold())
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise EvidenceError("model file escapes owner-pinned root")
        if not HEX64.fullmatch(str(row.get("sha256", ""))) or sha256_file(path, MAX_MODEL_BYTES) != row["sha256"]:
            raise EvidenceError("model bytes differ from owner pin: " + name)
        size = path.stat().st_size
        if type(row.get("bytes")) is not int or row["bytes"] != size:
            raise EvidenceError("model extent differs from owner pin")
        total += size
        if total > MAX_MODEL_BYTES:
            raise EvidenceError("native model exceeds bounded local input size")
        verified.append({"path": name, "sha256": row["sha256"], "bytes": size})
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EvidenceError("model tree contains a symbolic link")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix().casefold())
    if actual != names:
        raise EvidenceError("model tree contains unpinned or missing files")
    if not any(row["path"].endswith((".safetensors", ".gguf")) for row in rows):
        raise EvidenceError("native generation requires actual SafeTensors or GGUF weights")
    return verified


def pinned_executable(row: dict) -> Path:
    path = Path(row.get("path", ""))
    if not path.is_absolute() or sha256_file(path) != row.get("sha256"):
        raise EvidenceError("runtime executable differs from owner pin")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise EvidenceError("runtime executable is not executable")
    return path


def prepare_model_run(path: Path, expected_sha256: str, work: Path) -> tuple[dict, dict]:
    if not HEX64.fullmatch(expected_sha256) or sha256_file(path) != expected_sha256:
        raise EvidenceError("native model workload differs from owner pin")
    config = strict_json(Path(path).read_bytes())
    if config.get("schema") != "BTX-NATIVE-MODEL-RUN/1":
        raise EvidenceError("invalid native model workload schema")
    verify_model_files(Path(config["model_root"]), config["files"])
    request = config.get("generate", {})
    if not isinstance(request.get("prompt"), str) or not 1 <= len(request["prompt"]) <= 65536:
        raise EvidenceError("native model workload requires a bounded explicit prompt")
    if type(request.get("max_new_tokens")) is not int or not 1 <= request["max_new_tokens"] <= 512:
        raise EvidenceError("native model workload requires a bounded token count")
    if not HEX64.fullmatch(str(request.get("expected_text_sha256", ""))):
        raise EvidenceError("generation needs an independently approved expected text digest")
    if request.get("expected_device") not in {"cpu", "cuda"} or not request.get("expected_backend") or not request.get("expected_architecture"):
        raise EvidenceError("expected model architecture, actual adapter backend and device are required")
    adapter = config["adapter"]
    adapter_path = Path(adapter["path"])
    if not adapter_path.is_absolute() or sha256_file(adapter_path) != adapter["sha256"]:
        raise EvidenceError("local generation adapter pin differs")
    env = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1"}
    if adapter.get("kind") == "python":
        interpreter = pinned_executable(adapter["python"])
        if os.name == "nt" or any(c.isspace() for c in str(interpreter)):
            raise EvidenceError("the native helper's exec adapter requires a POSIX Python path without whitespace")
        # Pin the interpreter too; env python3 could select a different venv.
        wrapper = work / "owner-generate-adapter"
        wrapper.write_text("#!" + str(interpreter) + "\nimport runpy\nrunpy.run_path(" + repr(str(adapter_path)) + ", run_name='__main__')\n")
        wrapper.chmod(0o700)
        env["BTX_MODEL_GENERATE"] = str(wrapper.resolve())
        config["executed_adapter_sha256"] = sha256_file(wrapper)
    elif adapter.get("kind") == "executable":
        env["BTX_MODEL_GENERATE"] = str(pinned_executable(adapter))
        config["executed_adapter_sha256"] = adapter["sha256"]
    else:
        raise EvidenceError("explicit python or executable adapter kind required")
    if config.get("cuda_loader") is not None:
        env["BTX_MODEL_CUDA_LOADER"] = str(pinned_executable(config["cuda_loader"]))
    if config.get("llama_cli") is not None:
        env["BTX_LLAMA_CLI"] = str(pinned_executable(config["llama_cli"]))
    if config.get("require_cuda_resident") is True and "BTX_MODEL_CUDA_LOADER" not in env:
        raise EvidenceError("resident CUDA acceptance requires a pinned actual CUDA loader")
    config["owner_manifest_sha256"] = expected_sha256
    config["owner_manifest_path"] = str(Path(path).resolve())
    return config, env


def exercise_model(rpc, config: dict) -> dict:
    original = verify_model_files(Path(config["model_root"]), config["files"])
    imported = rpc("hostmodel", config["model_root"], {"pin": True, "publish": False})
    uri = imported.get("uri")
    if not isinstance(uri, str) or not uri.startswith("btx:"):
        raise EvidenceError("native hostmodel did not return a model URI")
    exported = rpc("exportmodelpath", uri)
    if exported.get("materialized") is not True or not exported.get("usable_runtime_root"):
        raise EvidenceError("native helper did not materialize verified model pieces")
    checkout = Path(exported["usable_runtime_root"])
    verify_model_files(checkout, original)
    exported_paths = {row.get("path") for row in exported.get("files", [])}
    if exported_paths != {row["path"] for row in original}:
        raise EvidenceError("native artifact inventory differs from the approved checkpoint")
    loaded, generated, unloaded = None, None, None
    try:
        loaded = rpc("loadmodel", uri)
        if config.get("require_cuda_resident") is True:
            if not all(loaded.get(key) is True for key in ("device_loaded", "weights_resident", "runtime_started", "smoke_passed")):
                raise EvidenceError("real CUDA tensor residency/smoke was not observed")
            if type(loaded.get("bytes_on_device")) is not int or loaded["bytes_on_device"] <= 0:
                raise EvidenceError("CUDA loader measured no resident tensor bytes")
        request = config["generate"]
        generated = rpc("generatemodel", uri, {"prompt": request["prompt"], "max_new_tokens": request["max_new_tokens"]})
        if not all(generated.get(key) is True for key in ("compatible", "generated", "local_generate")):
            raise EvidenceError("native helper did not run local model generation")
        if any(generated.get(key) is not False for key in ("remote_inference", "network_server")):
            raise EvidenceError("native local generation crossed its authorized scope")
        adapter = generated.get("adapter", {})
        if generated.get("architecture") != request["expected_architecture"] or generated.get("backend") != request["expected_backend"]:
            raise EvidenceError("actual native decoder architecture/backend differs")
        if adapter.get("device") != request["expected_device"]:
            raise EvidenceError("actual generator device differs; CPU fallback cannot qualify CUDA")
        text = generated.get("text")
        if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != request["expected_text_sha256"]:
            raise EvidenceError("actual generated output differs from the independently approved result")
        for record in (imported, exported, loaded, generated):
            if record.get("automatic_spend_atoms") not in (0, "0"):
                raise EvidenceError("model RPC automatic spend invariant failed")
    finally:
        unloaded = rpc("unloadmodel", uri)
    if unloaded.get("unloaded") is not True or unloaded.get("weights_resident") is not False:
        raise EvidenceError("native helper did not release the owned runtime")
    verify_model_files(Path(config["model_root"]), original)
    verify_model_files(checkout, original)
    for name in ("adapter", "cuda_loader", "llama_cli"):
        if config.get(name) is not None and sha256_file(Path(config[name]["path"])) != config[name]["sha256"]:
            raise EvidenceError("executed native adapter changed during the workload")
    if config["adapter"].get("kind") == "python":
        pinned_executable(config["adapter"]["python"])
    if sha256_file(Path(config["owner_manifest_path"])) != config["owner_manifest_sha256"]:
        raise EvidenceError("owner workload changed during native execution")
    return {"schema": "BTX-NATIVE-MODEL-RESULT/1", "owner_manifest_sha256": config["owner_manifest_sha256"],
            "executed_adapter_sha256": config["executed_adapter_sha256"], "verified_model_files": original,
            "hostmodel": imported, "exportmodelpath": exported, "loadmodel": loaded,
            "generatemodel": generated, "unloadmodel": unloaded,
            "vendor_engine_qualification": "ONLY_THE_RECORDED_ADAPTER_AND_DEVICE", "release_qualified": False}
