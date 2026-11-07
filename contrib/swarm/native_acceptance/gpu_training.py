#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Bounded, real multirank decoder training and exact state-replay workload.

Launch through torchrun on each enrolled machine. CUDA/NCCL is the default.
CPU/Gloo requires --allow-cpu and is labelled CPU_ONLY. This exercises actual
PyTorch distributed execution, not an installed BTX vendor-engine adapter.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys


def tensor_tree_digest(value, torch) -> str:
    hasher = hashlib.sha256()

    def walk(item):
        if isinstance(item, torch.Tensor):
            tensor = item.detach().cpu().contiguous()
            hasher.update(json.dumps(["tensor", str(tensor.dtype), list(tensor.shape)]).encode())
            hasher.update(tensor.reshape(-1).view(torch.uint8).numpy().tobytes())
        elif isinstance(item, dict):
            hasher.update(b"{")
            for key in sorted(item, key=lambda k: (type(k).__name__, str(k))):
                walk(key)
                walk(item[key])
            hasher.update(b"}")
        elif isinstance(item, (tuple, list)):
            hasher.update(b"[")
            for child in item:
                walk(child)
            hasher.update(b"]")
        else:
            hasher.update(json.dumps([type(item).__name__, item], sort_keys=True, allow_nan=False).encode())
    walk(value)
    return hasher.hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--steps", type=int, default=6)
    parser.add_argument("--seed", type=int, default=245)
    parser.add_argument("--allow-cpu", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    if not 4 <= args.steps <= 100 or not 10 <= args.timeout <= 900:
        parser.error("bounded workload requires 4..100 steps and 10..900 second timeout")
    if len(args.nonce) != 64 or any(c not in "0123456789abcdef" for c in args.nonce):
        parser.error("nonce must be 256-bit lowercase hexadecimal")
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    import torch
    import torch.distributed as dist
    from torch.nn.parallel import DistributedDataParallel
    from torch.nn import functional as functional
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from btxmesh.runtime import Decoder, DecoderConfig
    try:
        from .evidence import machine_probe, sha256_file
    except ImportError:
        from evidence import machine_probe, sha256_file

    rank, world, local_rank = (int(os.environ.get(k, default)) for k, default in
                               (("RANK", "0"), ("WORLD_SIZE", "1"), ("LOCAL_RANK", "0")))
    if world < 2:
        raise RuntimeError("distributed acceptance requires at least two ranks")
    cuda = torch.cuda.is_available() and not args.allow_cpu
    if not cuda and not args.allow_cpu:
        raise RuntimeError("CUDA is absent; no CPU substitution is allowed for GPU evidence")
    backend = "nccl" if cuda else "gloo"
    if cuda:
        if local_rank >= torch.cuda.device_count():
            raise RuntimeError("each local rank requires its own visible GPU")
        torch.cuda.set_device(local_rank)
    device = torch.device(f"cuda:{local_rank}" if cuda else "cpu")
    torch.set_num_threads(1)
    torch.manual_seed(args.seed)
    if cuda:
        torch.cuda.manual_seed_all(args.seed)
    torch.use_deterministic_algorithms(True)
    if cuda:
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
    dist.init_process_group(backend=backend, timeout=datetime.timedelta(seconds=args.timeout))
    try:
        model = Decoder(DecoderConfig(vocab=64, width=32, layers=2, heads=4, context=32)).to(device)
        distributed = DistributedDataParallel(model, device_ids=[local_rank] if cuda else None)
        optimizer = torch.optim.AdamW(distributed.parameters(), lr=0.005)
        root = Path(__file__).resolve().parents[3]
        probe = machine_probe(root, args.nonce)
        machine = probe["machine_id_sha256"]
        gpu_uuid = None
        if cuda:
            properties = torch.cuda.get_device_properties(local_rank)
            gpu_uuid = str(getattr(properties, "uuid", "")) or None
            if gpu_uuid is None:
                visible = os.environ.get("CUDA_VISIBLE_DEVICES", "").split(",")
                physical_index = int(visible[local_rank]) if visible and visible[0].isdigit() else local_rank
                if physical_index < len(probe["gpus"]):
                    gpu_uuid = probe["gpus"][physical_index]["uuid"]
            if not gpu_uuid:
                raise RuntimeError("cannot identify the physical GPU selected by this rank")
        identities = [None] * world
        dist.all_gather_object(identities, {"rank": rank, "machine_id_sha256": machine, "gpu_uuid": gpu_uuid})
        if cuda and len({row["gpu_uuid"] for row in identities}) != world:
            raise RuntimeError("ranks reuse a GPU; multiple processes are not multiple GPU contributors")

        def state(step):
            return {"model": model.state_dict(), "optimizer": optimizer.state_dict(),
                    "cpu_rng": torch.get_rng_state(),
                    "device_rng": torch.cuda.get_rng_state(device) if cuda else torch.get_rng_state(),
                    "step": step, "next_batch": step, "world_size": world, "seed": args.seed}

        def one_step(step):
            generator = torch.Generator(device="cpu").manual_seed(args.seed + step * world + rank)
            tokens = torch.randint(0, 64, (4, 16), generator=generator).to(device)
            targets = torch.roll(tokens, shifts=-1, dims=1)
            optimizer.zero_grad(set_to_none=True)
            logits, _ = distributed(tokens)
            loss = functional.cross_entropy(logits.reshape(-1, 64), targets.reshape(-1))
            if not torch.isfinite(loss):
                raise RuntimeError("nonfinite training loss")
            loss.backward()
            optimizer.step()
            dist.barrier()
            return float(loss.detach().cpu())

        initial = tensor_tree_digest(model.state_dict(), torch)
        midpoint = args.steps // 2
        losses = []
        for step in range(midpoint):
            losses.append(one_step(step))
        args.output_dir.mkdir(parents=True, exist_ok=True)
        checkpoint = args.output_dir / f"rank-{rank}-{args.nonce}.pt"
        if checkpoint.exists():
            raise RuntimeError("checkpoint path already exists; refusing stale evidence overwrite")
        torch.save(state(midpoint), checkpoint)
        checkpoint_sha = sha256_file(checkpoint)
        for step in range(midpoint, args.steps):
            losses.append(one_step(step))
        final_state = tensor_tree_digest(state(args.steps), torch)
        final_parameters = tensor_tree_digest(model.state_dict(), torch)
        # Only this workload's freshly written checkpoint is read; weights_only
        # prevents an externally substituted pickle from importing executable code.
        restored = torch.load(checkpoint, map_location=device, weights_only=True)
        if sha256_file(checkpoint) != checkpoint_sha or restored["world_size"] != world:
            raise RuntimeError("checkpoint identity or rank topology changed")
        model.load_state_dict(restored["model"], strict=True)
        optimizer.load_state_dict(restored["optimizer"])
        torch.set_rng_state(restored["cpu_rng"].cpu())
        if cuda:
            torch.cuda.set_rng_state(restored["device_rng"].cpu(), device)
        for step in range(restored["next_batch"], args.steps):
            one_step(step)
        replay_state = tensor_tree_digest(state(args.steps), torch)
        if initial == final_parameters or final_state != replay_state:
            raise RuntimeError("parameters did not update or full-state replay diverged")
        parameter_hashes = [None] * world
        dist.all_gather_object(parameter_hashes, final_parameters)
        if len(set(parameter_hashes)) != 1:
            raise RuntimeError("distributed ranks disagree on trained parameters")
        row = {"rank": rank, "machine_id_sha256": machine, "gpu_uuid": gpu_uuid,
               "checkpoint_sha256": checkpoint_sha, "initial_parameters_sha256": initial,
               "final_parameters_sha256": final_parameters, "final_full_state_sha256": final_state,
               "replayed_full_state_sha256": replay_state, "losses": losses,
               "training_steps": args.steps, "device": str(device), "torch_version": torch.__version__}
        rows = [None] * world
        dist.all_gather_object(rows, row)
        if local_rank == 0:
            try:
                from .checkpoint_bridge import export_trained_model
            except ImportError:
                from checkpoint_bridge import export_trained_model
            exported = export_trained_model(
                model, torch, args.output_dir / f"native-export-rank-{rank}-{args.nonce}",
                {"nonce": args.nonce, "backend": backend, "world_size": world,
                 "machine_ids": sorted({r["machine_id_sha256"] for r in rows}),
                 "gpu_uuids": sorted({r["gpu_uuid"] for r in rows if r["gpu_uuid"]}),
                 "final_parameters_sha256": final_parameters, "replayed_full_state_sha256": replay_state,
                 "steps": args.steps, "native_btx_engine_integration": "NOT_EXERCISED"})
            print(json.dumps({"schema": "BTX-DISTRIBUTED-WORKLOAD/1", "nonce": args.nonce,
                              "backend": backend, "classification": "GPU_WORKLOAD_NATIVE" if cuda else "CPU_ONLY",
                              "world_size": world, "machine_ids": sorted({r["machine_id_sha256"] for r in rows}),
                              "gpu_uuids": sorted({r["gpu_uuid"] for r in rows if r["gpu_uuid"]}),
                              "checkpoint_closure": ["model", "optimizer", "cpu_rng", "device_rng", "step", "next_batch", "world_size", "seed"],
                              "ranks": rows, "native_checkpoint_export": exported,
                              "native_btx_engine_integration": "NOT_EXERCISED",
                              "automatic_spend_atoms": "0", "release_qualified": False}, sort_keys=True))
    finally:
        dist.destroy_process_group()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
