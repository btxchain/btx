# Capability evidence (0.34.9)

**Status:** 0.34.9-dev. `CLIENT_VERSION_IS_RELEASE=false`. This is the **run**
question: *can this verified artifact execute here?* It is not a vendor name,
not a Hugging Face `pipeline_tag`, not a vendor marketing tier, and not a
reason to collapse identity into a registry.

The **what** question lives in [registry-independence.md](registry-independence.md)
(`btx://` / `VerifiedManifest`). **Who** is native BTX publisher signatures plus
optional OMS/Sigstore/Cosign/OCI evidence. **Where** is `origins[]`. **How**
distribution is funded is the monetary plane (free / private / BTX incentives /
bounties / paid hosting). Fetch does not require a wallet. Wallets, ExactReplay,
and consensus stay.

## The run question

Local capability evidence answers, for *this* host against a *verified*
artifact:

- container format (SafeTensors, GGUF, …)
- architecture family
- accelerator compatibility **observed locally** (CUDA / ROCm / Metal / CPU)
- which runtime adapters are present and usable here
- minimum on-disk storage the artifact needs before it can be loaded

It is a statement about a machine and an artifact. It is not an admission
decision, not a payment, and not a claim about global availability.

`automatic_spend_atoms` stays `0`, and a ready receipt is wallet-free: the
readiness record carries `funded_wallet=false` and `remote_endpoint=false`. A
node can verify, store, and report capability without holding secrets or a
balance, and without spending.

Import StatusJson emits a structured `capability` object at
`readiness_target=VERIFIED_FILES` (`inference=false`) without probing a GPU.
That is a local statement about the import plane, not a vendor name and not a
network-wide accelerator requirement. ProbeAcceleratedAdapters remains the
later host-observation path described below.

## Vendor naming is not evidence

A Hugging Face `pipeline_tag`, a ModelScope task label, a catalog SKU, or an
NVIDIA marketing tier is **not** a BTX capability record. Those labels may be
copied into an evidence slot, but they never become the artifact identity and
never override locally observed facts. Naming describes intent; capability
evidence describes what was probed on this host.

## Accelerator neutrality

BTX does not prefer one accelerator vendor, and there is no network-wide
"required GPU". `CanonicalBackend` folds `cpu`, `cuda`, `rocm` / `hip`, and
`metal` / `mlx` into a small neutral set; `DefaultBackend` only suggests a
default (for example, a CPU-only runtime stays CPU). `ProbeAcceleratedAdapters`
reports CUDA, ROCm, and Metal **as this host's observations**.

A backend label must not be laundered into another. `RocmMetalDirectDistinction`
fails closed: a CUDA/GDS path that is absent returns `NOT_RUN` (never a
ROCm/Metal relabel), and ROCm/HIP or Metal resolve to the eligible `HOST_BUFFER`
fallback rather than borrowing the CUDA fast path. The neutral fallback is a
host buffer, so a node with **no** accelerator at all still participates in
resolution: it can verify, store, and serve pieces. A node that *can* run CUDA
still reports that as local evidence, not as a requirement imposed on peers.

## Storage is not RAM and not VRAM

The storage figure is a **disk / file** requirement for the verified bytes.
It is **not** a RAM claim and **not** a VRAM claim. BTX does not conflate the
two, and capacity is reported by tier (`PlacementTier`): `LOCAL_FILE` and
`PAGE_CACHE` are storage-side; `HOST_PAGEABLE`, `HOST_PINNED`, `DEVICE`, and
`CXL_NUMA` are memory/residency-side; `PEER_HOST` / `PEER_DEVICE` mean the
bytes live elsewhere. Transport is likewise typed (`TransportAssurance`):
`NATIVE_PQ1` is the strict-PQ path, and `HOST_BUFFER` is the neutral fallback
rather than a silent downgrade.

Do not turn a quoted model size into a free-space promise, and do not turn
free disk into free VRAM. A host may be able to **store** an artifact it cannot
**reside**; that is a `RUNTIME_LOADED` / `RUNTIME_READY` distinction, not a
failure of fetch.

## BTX does not run inference

BTX is not the inference engine. The monetary plane (wallets, bounties,
ExactReplay, consensus) remains and is the **HOW / funding** layer, not an
admission ticket: it does not gate fetch, verification, or a local run. The
engine is whatever local runtime the operator supplies; BTX acquires verified
bytes and reports local capability, and leaves execution to the host.
