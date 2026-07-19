// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// matmul-v4-report — one-command MatMul v4.1 hardware measurement tool.
//
// This is the report the activation gates consume: run it on ANY machine
// (CPU-only, or a host with a compiled-in CUDA / Metal / HIP backend) and it
// emits a single JSON file plus a human summary that feed three §K activation
// gates directly:
//
//   B1  (bit-exact determinism)  — runs the resolved backend's BATCHED path
//        (matmul_v4::accel::ComputeDigestsBatchedDispatched) over a nonce
//        window and asserts every digest+payload is BYTE-IDENTICAL to the CPU
//        reference (matmul_v4::ComputeDigest). A FAIL is a hard consensus-split
//        signal — the backend must NOT be activated.
//   B2b (ASERT throughput calibration) — reports sustained MARGINAL nonce/s
//        (the per-nonce unit difficulty prices, since U*A is template-amortized
//        under invariant I1'); with a supplied v3 baseline it prints a ready
//        nMatMulV4AsertRescaleNum/Den candidate.
//   B2g (datacenter-vs-consumer go/no-go) — instruments the §K.2a-WT stage
//        boundaries (S0/S1b/S2/S3/S4) on the STACKED window shapes, reports the
//        tensor-stage wall-time share and an implied INT8 tensor-utilization
//        estimate vs a supplied device peak.
//
// This tool is NOT a nanobench: it is a standalone executable with explicit
// timers and a machine-readable JSON output so results from many machines can
// be diffed and aggregated. The per-stage instrumentation is the CPU-reference
// methodology of src/bench/matmul_v4_stage_bench.cpp, lifted to a stacked
// window; a GPU backend mirrors the SAME S-boundaries on-device and the
// operator captures the device's own per-stage timers (see notes in output).
//
// ---------------------------------------------------------------------------
// --profile bmx4c --mt24 : the M-t24 accumulator-exactness measurement (v4.2).
//
// doc/btx-matmul-v4.2-bmx4c-spec.md §5/§9 and doc/btx-matmul-v4-bmx4-asic-fpga-
// deepdive.md pin M-t24 as THE gating measurement for whether commodity block-
// scaled FP4/MX silicon may run the BMX4-C NATIVE path: the native path needs
// a PROVEN exact accumulator of t=24 mantissa/integer bits (consensus
// Params::nMatMulBMX4CMinProvenAccumulatorBits, BMX4C_NATIVE_PATH_PROVEN_T);
// datasheet claims are never trusted (Hopper's "FP32-accumulate" FP8 path
// retained only ~t=14 in practice). A device proven only t~=14 MUST fail
// closed to the 1-GEMM INT8 fallback (§5.2's ladder) -- silently mining the
// native path on such a device would round high-magnitude partial sums and
// split the chain.
//
// `--profile bmx4c` runs the ENC-BMX4C reference (matmul::v4::bmx4,
// src/matmul/matmul_v4_bmx4.{h,cpp}, COMMITTED and UNCHANGED by this tool)
// instead of the v4.1 ENC-S8 profile: a BMX4-C bit-exactness gate (the B1
// analogue: run-to-run determinism + limb-tensor-combine == direct-mod-q-
// combine byte-equality over a nonce window), BMX4-C per-stage stacked-window
// timing (the §K.2a-WT/§K.2b analogue), and the M-t24 boundary-vector suite
// (`--mt24`, forced on under this profile): the §5.3 C-1' t-discrimination and
// boundary-pin vectors (odd-step crossings of 2^14, exact pins at 2^22/2^23/
// 2^24) run through the SAME accumulation primitives (ExactDot,
// ComputeCombineModQ, ComputeCombineLimbTensor[BMX4C]) a device's native
// block-scaled kernel must reproduce byte-for-byte. On CPU these primitives
// are true int64/int32 C++ arithmetic, so M-t24 PASSes trivially and
// `proven_accumulator_bits` reports the pinned t=24 threshold -- this is the
// harness self-test (deliberately runnable/verifiable with no GPU). NO device-
// side BMX4-C block-scaled kernel is wired into this repository yet (only the
// v4.1 ENC-S8 s8x s8->s32 IMMA/MFMA/TensorOps kernels are); until one lands,
// running this tool with `--backend cuda|metal|hip --profile bmx4c --mt24` on
// real block-scaled silicon (B200 / RTX 5090-class per §9) still exercises
// the CPU reference and reports `native_path_eligible=false` with an explicit
// reason -- it does NOT fabricate an on-device pass. Wiring a real vendor
// FP4/MX kernel behind this same vector table is the natural follow-up
// (tracked in the spec, out of scope for this tool per its own charter of
// touching only the measurement/tooling layer).
//
// ---------------------------------------------------------------------------
// --profile bmx4c-lt : ENC-DR-LT (Rank-1 MatExpand + deep-m + Q*) measurement.
//
// doc/btx-matmul-v4.4-lt-normative-spec.md. Instruments the MatExpand+Q*
// stage boundaries (I1' amortized template MatExpand-A + U/V/P; per-nonce
// MatExpand-B; Bhat*V; combine; digest; optional Q* seal sample). Emits
// schema_version 3 JSON. Does NOT invent on-silicon rates: a non-CPU backend
// reports device_native_kernel_wired only when ComputeDigestsBMX4CLTDispatched
// actually accepted a device window (ProbeStats *_batch_ok). Aggregate with
// contrib/matmul-v4/lt-gate.py (fail-closed if JSON fields are missing).

#include <matmul/accel_v4.h>
#include <matmul/backend_capabilities_v4.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_batch.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/pow_v4.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/translation.h>

#include <univalue.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

using Clock = std::chrono::steady_clock;
namespace mv4 = matmul::v4;

double Secs(Clock::time_point a, Clock::time_point b)
{
    return std::chrono::duration<double>(b - a).count();
}

std::string HostName()
{
#if defined(__unix__) || defined(__APPLE__)
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) == 0 && buf[0] != '\0') {
        return std::string{buf};
    }
#endif
    if (const char* h = std::getenv("HOSTNAME")) {
        if (h[0] != '\0') return std::string{h};
    }
    return "unknown-host";
}

std::string HostCpuArch()
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__arm__)
    return "arm";
#else
    return "unknown";
#endif
}

// A fixed synthetic template header (same constants as the stage bench so
// results are comparable across machines); matmul_dim = n, nonce set per index.
CBlockHeader ReportHeader(uint32_t n)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.hashPrevBlock = uint256::FromHex("1111111111111111111111111111111111111111111111111111111111111111").value();
    header.hashMerkleRoot = uint256::FromHex("2222222222222222222222222222222222222222222222222222222222222222").value();
    header.nTime = 1'770'000'090U;
    header.nBits = 0x207fffff;
    header.nNonce64 = 7;
    header.nNonce = 7;
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000000000").value();
    header.seed_b = uint256::FromHex("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150").value();
    return header;
}

std::vector<CBlockHeader> WindowHeaders(uint32_t n, uint32_t window, uint64_t base_nonce)
{
    std::vector<CBlockHeader> headers(window, ReportHeader(n));
    for (uint32_t i = 0; i < window; ++i) {
        headers[i].nNonce64 = base_nonce + i;
        headers[i].nNonce = static_cast<uint32_t>(headers[i].nNonce64);
    }
    return headers;
}

// Per-stage wall-time over a STACKED nonce window, mirroring
// matmul_v4_stage_bench::RunStagedNonce but across `window` nonces so S2/S3
// run on the batched (stacked) shapes the §K.2b profile exists to enforce.
struct StageResult {
    uint32_t n{0};
    uint32_t m{0};
    uint32_t window{0};
    double s0_template{0};   // amortized per template (EXCLUDED from marginal)
    double s1b_expand{0};    // summed across window
    double s2_gemm{0};       // summed across window
    double s3_limb{0};       // stacked limb-tensor combine (one big GEMM)
    double s3_alu{0};        // integer-ALU direct alternative (summed)
    double s4_digest{0};     // summed across window
    bool stage_bit_exact{false};
    std::vector<uint256> digests;
    std::vector<std::vector<unsigned char>> payloads;
    bool valid{false};
};

StageResult MeasureStages(uint32_t n, uint32_t window, uint32_t rounds, uint64_t base_nonce)
{
    StageResult r;
    r.n = n;
    r.window = window;
    uint32_t m = 0;
    if (!mv4::ValidateDims(n, mv4::kTileB, m) || !mv4::CheckCombineLimbBound(n) || window == 0) {
        return r;
    }
    r.m = m;
    const uint32_t q_cols = window * m;
    const std::vector<CBlockHeader> headers = WindowHeaders(n, window, base_nonce);

    // S0: template-scoped work (A,U,V expand + P = U*A), paid ONCE per template
    // under invariant I1'; reported separately, excluded from the marginal.
    auto c0 = Clock::now();
    const uint256 seed_a = mv4::DeriveOperandSeed(headers[0], mv4::Operand::A);
    const auto [seed_u, seed_v] = mv4::DeriveProjectorSeeds(headers[0]);
    const std::vector<int8_t> A = mv4::ExpandOperand(seed_a, n);
    const std::vector<int8_t> U = mv4::ExpandProjector(seed_u, m, n);
    const std::vector<int8_t> V = mv4::ExpandProjector(seed_v, n, m);
    const std::vector<int32_t> P = mv4::ComputeProjectedLeft(U, A, n, m);
    auto c1 = Clock::now();
    r.s0_template = Secs(c0, c1);

    // Build the stacked right factor Qstack = [B_1*V | ... | B_Q*V] (n x q_cols).
    // S1b (expand B, per nonce) and S2 (Q_i = B_i*V, per nonce) are summed; on
    // device these stack as one [B_1; ...; B_Q]*V GEMM with expansions overlapped.
    std::vector<uint256> sigmas(window);
    std::vector<int32_t> Qstack(static_cast<size_t>(n) * q_cols);
    for (uint32_t i = 0; i < window; ++i) {
        auto ca = Clock::now();
        sigmas[i] = mv4::DeriveSigma(headers[i]);
        const uint256 seed_b = mv4::DeriveOperandSeed(headers[i], mv4::Operand::B);
        const std::vector<int8_t> B = mv4::ExpandOperand(seed_b, n);
        auto cb = Clock::now();
        r.s1b_expand += Secs(ca, cb);
        const std::vector<int32_t> Qi = mv4::ComputeProjectedRight(B, V, n, m);
        auto cc = Clock::now();
        r.s2_gemm += Secs(cb, cc);
        for (uint32_t k = 0; k < n; ++k) {
            int32_t* dst = &Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(i) * m];
            const int32_t* src = &Qi[static_cast<size_t>(k) * m];
            std::copy(src, src + m, dst);
        }
    }

    // S3 (limb-tensor path): the ONE LARGE DENSE GEMM P * Qstack (m x n by
    // n x q_cols), the §K.2b combine the profile exists to make dense.
    auto cd = Clock::now();
    const std::vector<mv4::Fq> Chat_wide = mv4::ComputeCombineLimbTensorStacked(P, Qstack, n, m, q_cols);
    auto ce = Clock::now();
    r.s3_limb = Secs(cd, ce);

    // S3' (integer-ALU direct alternative): per-nonce ComputeCombineModQ over
    // the sliced Q_i. Miners take min(S3, S3') per device.
    std::vector<mv4::Fq> Chat_alu_all;
    {
        auto cf = Clock::now();
        for (uint32_t i = 0; i < window; ++i) {
            std::vector<int32_t> Qi(static_cast<size_t>(n) * m);
            for (uint32_t k = 0; k < n; ++k) {
                const int32_t* src = &Qstack[static_cast<size_t>(k) * q_cols + static_cast<size_t>(i) * m];
                std::copy(src, src + m, &Qi[static_cast<size_t>(k) * m]);
            }
            const std::vector<mv4::Fq> Chat = mv4::ComputeCombineModQ(P, Qi, n, m);
            Chat_alu_all.insert(Chat_alu_all.end(), Chat.begin(), Chat.end());
        }
        auto cg = Clock::now();
        r.s3_alu = Secs(cf, cg);
    }

    // S4 (serialize + digest, per nonce): slice the m x m block from Chat_wide.
    r.digests.resize(window);
    r.payloads.resize(window);
    bool alu_matches_limb = true;
    auto ch = Clock::now();
    for (uint32_t i = 0; i < window; ++i) {
        std::vector<mv4::Fq> Chat(static_cast<size_t>(m) * m);
        for (uint32_t a = 0; a < m; ++a) {
            const mv4::Fq* src = &Chat_wide[static_cast<size_t>(a) * q_cols + static_cast<size_t>(i) * m];
            std::copy(src, src + m, &Chat[static_cast<size_t>(a) * m]);
        }
        r.payloads[i] = mv4::SerializeSketch(Chat);
        r.digests[i] = mv4::ComputeSketchDigest(sigmas[i], r.payloads[i]);
    }
    auto ci = Clock::now();
    r.s4_digest = Secs(ch, ci);

    // Stage bit-exactness: each stacked-window nonce vs the single-nonce
    // consensus reference AND the limb path vs the ALU-direct path.
    bool all_ok = true;
    for (uint32_t i = 0; i < window; ++i) {
        uint256 ref_digest;
        std::vector<unsigned char> ref_payload;
        const bool ok = matmul_v4::ComputeDigest(headers[i], n, rounds, ref_digest, ref_payload);
        // Compare this nonce's limb-path C-block against the ALU-direct block.
        for (uint32_t a = 0; a < m && alu_matches_limb; ++a) {
            const mv4::Fq* limb_src = &Chat_wide[static_cast<size_t>(a) * q_cols + static_cast<size_t>(i) * m];
            const mv4::Fq* alu_src = &Chat_alu_all[(static_cast<size_t>(i) * m + a) * m];
            if (!std::equal(limb_src, limb_src + m, alu_src)) alu_matches_limb = false;
        }
        if (!ok || r.digests[i] != ref_digest || r.payloads[i] != ref_payload) {
            all_ok = false;
        }
    }
    r.stage_bit_exact = all_ok && alu_matches_limb;
    r.valid = true;
    return r;
}

// Raw device batched entry point for a resolved GPU backend (nullptr for CPU).
// Used to measure device mining throughput WITHOUT the per-nonce host verify
// that ComputeDigestsBatchedDispatched adds (the miner only verifies a winner).
matmul_v4::accel::BatchAccelFn RawBatchFnFor(matmul_v4::accel::Kind kind)
{
    using K = matmul_v4::accel::Kind;
    switch (kind) {
    case K::CUDA:  return &matmul_v4::cuda::ComputeDigestsBatchedAccel;
    case K::METAL: return &matmul_v4::metal::ComputeDigestsBatchedAccel;
    case K::HIP:   return &matmul_v4::hip::ComputeDigestsBatchedAccel;
    case K::CPU:   return nullptr;
    }
    return nullptr;
}

matmul_v4::backend::Kind ToEligKind(matmul_v4::accel::Kind k)
{
    using A = matmul_v4::accel::Kind;
    using B = matmul_v4::backend::Kind;
    switch (k) {
    case A::CPU:   return B::CPU;
    case A::CUDA:  return B::CUDA;
    case A::METAL: return B::METAL;
    case A::HIP:   return B::HIP;
    }
    return B::CPU;
}

struct Args {
    uint32_t n{4096};
    uint32_t window{32};   // §K.2b asks for Q >= 32
    uint32_t rounds{matmul_v4::kFreivaldsRounds};
    bool quick{false};     // also run a n=256 / n=512 lane
    double device_peak_int8_tops{0}; // advertised INT8 TOPS (0 = unknown)
    double v3_hashrate{0};           // v3 sustained hashes/s on this box (0 = unset)
    std::string out_path;            // JSON output (default derived from hostname)
    std::string backend_override;    // sets BTX_MATMUL_V4_BACKEND if non-empty
    std::string profile{"v41"};      // "v41" | "bmx4c" | "bmx4c-lt"
    bool mt24{false};                 // run the M-t24 boundary-vector suite (forced on for bmx4c)
    bool window_explicit{false};      // true if --window / env set the window
};

void PrintUsage(std::ostream& os)
{
    os << "Usage: matmul-v4-report [options]\n"
       << "  --backend <cpu|cuda|metal|hip>   force backend (sets BTX_MATMUL_V4_BACKEND)\n"
       << "  --profile <v41|bmx4c|bmx4c-lt>   encoding profile: v4.1 ENC-S8, v4.2 ENC-BMX4C, or\n"
       << "                                   v4.4-LT ENC-DR-LT (MatExpand + deep-m + Q*)\n"
       << "  --mt24                           run the M-t24 accumulator-exactness boundary-vector suite\n"
       << "                                   (§5.3/C-1'; always on under --profile bmx4c)\n"
       << "  --n <dim>                        matrix dimension (default 4096; env BTX_MATMUL_V4_REPORT_N)\n"
       << "  --window <Q>                     nonce window (default 32; 64 under bmx4c-lt unless set;\n"
       << "                                   env BTX_MATMUL_V4_REPORT_WINDOW)\n"
       << "  --rounds <R>                     Freivalds rounds for the verify gate (default 3)\n"
       << "  --quick                          also run a fast n=256 and n=512 lane (v4.1 profile only)\n"
       << "  --device-peak-int8-tops <TOPS>   advertised INT8 TOPS, for the tensor-utilization estimate\n"
       << "  --v3-hashrate <H/s>              v3 sustained hashes/s on this host, for the ASERT rescale suggestion\n"
       << "  --out <path>                     JSON output path (default matmul-v4-report-<hostname>.json)\n"
       << "  -h, --help                       this help\n";
}

bool ParseArgs(int argc, char* argv[], Args& args, std::string& err)
{
    auto need = [&](int& i) -> const char* {
        if (i + 1 >= argc) { err = std::string("missing value for ") + argv[i]; return nullptr; }
        return argv[++i];
    };
    for (int i = 1; i < argc; ++i) {
        const std::string a{argv[i]};
        if (a == "-h" || a == "--help") { PrintUsage(std::cout); std::exit(0); }
        else if (a == "--backend") { const char* v = need(i); if (!v) return false; args.backend_override = v; }
        else if (a == "--profile") {
            const char* v = need(i); if (!v) return false;
            args.profile = v;
            if (args.profile != "v41" && args.profile != "bmx4c" && args.profile != "bmx4c-lt") {
                err = "unknown --profile (want v41, bmx4c, or bmx4c-lt): " + args.profile;
                return false;
            }
        }
        else if (a == "--mt24") { args.mt24 = true; }
        else if (a == "--n") { const char* v = need(i); if (!v) return false; args.n = static_cast<uint32_t>(std::strtoul(v, nullptr, 10)); }
        else if (a == "--window") {
            const char* v = need(i); if (!v) return false;
            args.window = static_cast<uint32_t>(std::strtoul(v, nullptr, 10));
            args.window_explicit = true;
        }
        else if (a == "--rounds") { const char* v = need(i); if (!v) return false; args.rounds = static_cast<uint32_t>(std::strtoul(v, nullptr, 10)); }
        else if (a == "--quick") { args.quick = true; }
        else if (a == "--device-peak-int8-tops") { const char* v = need(i); if (!v) return false; args.device_peak_int8_tops = std::strtod(v, nullptr); }
        else if (a == "--v3-hashrate") { const char* v = need(i); if (!v) return false; args.v3_hashrate = std::strtod(v, nullptr); }
        else if (a == "--out") { const char* v = need(i); if (!v) return false; args.out_path = v; }
        else { err = "unknown argument: " + a; return false; }
    }
    // Environment overrides (only when the flag was left at default).
    if (const char* e = std::getenv("BTX_MATMUL_V4_REPORT_N")) args.n = static_cast<uint32_t>(std::strtoul(e, nullptr, 10));
    if (const char* e = std::getenv("BTX_MATMUL_V4_REPORT_WINDOW")) {
        args.window = static_cast<uint32_t>(std::strtoul(e, nullptr, 10));
        args.window_explicit = true;
    }
    if (args.window == 0) args.window = 1;
    if (args.rounds == 0) args.rounds = 1;
    // The M-t24 boundary-vector suite is the reason to run --profile bmx4c at
    // all; force it on so an operator cannot forget the flag and mistake a
    // profile-only run for a real M-t24 verdict. Symmetrically, `--mt24`
    // alone (profile left at its default) selects the bmx4c profile, since
    // M-t24 is meaningless under the v4.1 ENC-S8 profile. Never auto-select
    // bmx4c-lt from --mt24 (M-t24 is a BMX4C gate, not an LT gate).
    if (args.profile == "bmx4c") args.mt24 = true;
    else if (args.mt24 && args.profile != "bmx4c-lt") args.profile = "bmx4c";
    // Rank-1 LT production windows are consensus Q* ∈ {64,128}; default the
    // measurement window to 64 when the operator did not override it.
    if (args.profile == "bmx4c-lt" && !args.window_explicit) {
        args.window = matmul::v4::lt::kConsensusQStarDefault;
    }
    return true;
}

// Sustained MARGINAL nonce/s for the resolved backend. For a GPU backend, time
// the raw batched entry point (no per-nonce verify — that is the miner's
// throughput). For CPU, use the batched miner (template-amortized), which is
// the honest marginal per-nonce CPU unit. Returns 0 if unmeasurable.
double MeasureBackendNoncePerSec(matmul_v4::accel::Kind kind, uint32_t n, uint32_t window,
                                 uint32_t rounds, bool& used_device, std::string& note)
{
    used_device = false;
    const std::vector<CBlockHeader> headers = WindowHeaders(n, window, 100000);

    if (kind != matmul_v4::accel::Kind::CPU) {
        const matmul_v4::accel::BatchAccelFn fn = RawBatchFnFor(kind);
        std::vector<uint256> digs;
        std::vector<std::vector<unsigned char>> pays;
        // Warmup + capability probe.
        bool ok = false;
        try { ok = fn && fn(headers, n, rounds, digs, pays); } catch (...) { ok = false; }
        if (ok && digs.size() == window) {
            used_device = true;
            uint32_t windows = 0;
            auto t0 = Clock::now();
            while (Secs(t0, Clock::now()) < 1.0 && windows < 64) {
                try { fn(headers, n, rounds, digs, pays); } catch (...) { break; }
                ++windows;
            }
            const double elapsed = Secs(t0, Clock::now());
            note = "device raw batched throughput (no per-nonce host verify)";
            if (elapsed > 0 && windows > 0) return (static_cast<double>(windows) * window) / elapsed;
        }
        note = "device backend not runnable on this host; reporting CPU marginal";
    }

    // CPU marginal via the batched miner (template-amortized), summed windows to ~0.5s.
    const mv4::BatchedSketchMiner miner{ReportHeader(n), n};
    if (!miner.Valid()) return 0;
    std::vector<mv4::BatchNonceResult> out;
    if (!miner.Mine(uint64_t{200000}, window, out)) return 0; // warmup
    uint32_t windows = 0;
    uint64_t nonce = 300000;
    auto t0 = Clock::now();
    while (Secs(t0, Clock::now()) < 0.5 && windows < 1024) {
        if (!miner.Mine(nonce, window, out)) break;
        nonce += window;
        ++windows;
    }
    const double elapsed = Secs(t0, Clock::now());
    if (kind == matmul_v4::accel::Kind::CPU) note = "CPU batched miner marginal per-nonce throughput";
    if (elapsed > 0 && windows > 0) return (static_cast<double>(windows) * window) / elapsed;
    return 0;
}

UniValue StageJson(const StageResult& r, double device_peak_tops, double backend_nps,
                   double& tensor_share_pct_out, double& tensor_util_pct_out)
{
    UniValue o(UniValue::VOBJ);
    const double comb = std::min(r.s3_limb, r.s3_alu);
    const bool limb_chosen = r.s3_limb < r.s3_alu;
    const double marginal = r.s1b_expand + r.s2_gemm + comb + r.s4_digest; // S0 amortized out
    const double marginal_ns_per_nonce = r.window ? (marginal * 1e9 / r.window) : 0;
    // Tensor-stage share: S2 (B*V) + S3b (the limb GEMMs) when the limb path is
    // chosen; on the ALU-direct path only S2 is a tensor stage (§K.2a-WT gate).
    const double tensor_time = r.s2_gemm + (limb_chosen ? comb : 0.0);
    tensor_share_pct_out = marginal > 0 ? 100.0 * tensor_time / marginal : 0;

    // Implied INT8 tensor utilization vs a supplied device peak. Marginal
    // tensor MACs/nonce = n^2*m (B*V) + 16*m^2*n (the 16 limb-pair GEMMs) ~
    // 1.25*n^3 at b=4; 1 MAC = 2 INT8 ops.
    const double marginal_tensor_macs = static_cast<double>(r.n) * r.n * r.m + 16.0 * r.m * r.m * r.n;
    const double marginal_tensor_ops = 2.0 * marginal_tensor_macs;
    tensor_util_pct_out = -1; // unknown sentinel
    if (device_peak_tops > 0 && backend_nps > 0) {
        tensor_util_pct_out = 100.0 * marginal_tensor_ops * backend_nps / (device_peak_tops * 1e12);
    }

    o.pushKV("n", static_cast<uint64_t>(r.n));
    o.pushKV("b", static_cast<uint64_t>(mv4::kTileB));
    o.pushKV("m", static_cast<uint64_t>(r.m));
    o.pushKV("window", static_cast<uint64_t>(r.window));
    o.pushKV("bit_exact", r.stage_bit_exact);
    o.pushKV("s0_template_ms", r.s0_template * 1e3);
    o.pushKV("s1b_expand_ms", r.s1b_expand * 1e3);
    o.pushKV("s2_gemm_ms", r.s2_gemm * 1e3);
    o.pushKV("s3_limb_combine_ms", r.s3_limb * 1e3);
    o.pushKV("s3_alu_direct_ms", r.s3_alu * 1e3);
    o.pushKV("s3_chosen", limb_chosen ? "limb-tensor" : "alu-direct");
    o.pushKV("s4_digest_ms", r.s4_digest * 1e3);
    o.pushKV("marginal_per_nonce_ms", r.window ? (marginal * 1e3 / r.window) : 0);
    o.pushKV("marginal_ns", marginal_ns_per_nonce);
    o.pushKV("cpu_reference_nonce_per_s", marginal > 0 ? (r.window / marginal) : 0);
    o.pushKV("marginal_tensor_macs_per_nonce", marginal_tensor_macs);
    o.pushKV("tensor_share_pct", tensor_share_pct_out);
    if (tensor_util_pct_out >= 0) {
        o.pushKV("tensor_util_pct", tensor_util_pct_out);
    } else {
        o.pushKV("tensor_util_pct", "unknown");
    }
    return o;
}

std::string ReducedRatio(double num, double den)
{
    if (num <= 0 || den <= 0) return "n/a";
    // Scale to integers with ~6 significant digits then reduce.
    const int64_t N = static_cast<int64_t>(num + 0.5);
    const int64_t D = static_cast<int64_t>(den + 0.5);
    if (N <= 0 || D <= 0) return "n/a";
    const int64_t g = std::gcd(N, D);
    return std::to_string(N / g) + "/" + std::to_string(D / g);
}

// ---------------------------------------------------------------------------
// M-t24 accumulator-exactness boundary-vector suite (spec §5.3, companion
// doc/btx-matmul-v4-accumulator-eligibility.md's C-1 -> C-1' generalization).
// ---------------------------------------------------------------------------

namespace bx = matmul::v4::bmx4;

// The proven-exact-accumulator-bits threshold the BMX4-C native path requires
// (consensus Params::nMatMulBMX4CMinProvenAccumulatorBits /
// Consensus::BMX4C_NATIVE_PATH_PROVEN_T, src/consensus/params.h). Mirrored as
// a local constant so this tool does not need to pull in consensus/params.h.
constexpr uint32_t kMt24RequiredProvenBits = 24;

// One C-1' boundary/t-discrimination vector (spec §5.3 items 1-2): an
// analytic `expected` value crossing, or pinned exactly at, a claimed
// accumulator threshold; `actual` is produced by the SAME accumulation
// primitive (ExactDot / ComputeCombineModQ / ComputeCombineLimbTensor[BMX4C])
// a device's native block-scaled kernel must reproduce byte-for-byte.
// `regime_pow2` is the 2^t threshold this vector exercises (14/19/22/23/24);
// -1 marks a structural precondition (E8M0 scale-exactness) rather than an
// accumulator-magnitude rung.
struct BoundaryVector {
    std::string name;
    int64_t expected{0};
    int64_t actual{0};
    bool pass{false};
    int32_t regime_pow2{-1};
};

std::vector<BoundaryVector> RunMt24BoundaryVectors()
{
    std::vector<BoundaryVector> out;

    // V0 (precondition, §5.3 item 3): E8M0 dequant mu*2^e is a pure
    // power-of-two shift for every (mu, e) in M11 x {0..S}; the top magnitude
    // 6*2^3 must land EXACTLY at E_max = 48, no rounding, no overflow.
    {
        bool ok = true;
        int64_t peak = 0;
        for (int8_t mu : bx::kAlphabetM11) {
            for (uint8_t e = 0; e <= bx::kScaleS; ++e) {
                const int64_t deq = static_cast<int64_t>(mu) * (int64_t{1} << e);
                if (deq < -bx::kEmax || deq > bx::kEmax) ok = false;
                peak = std::max(peak, deq < 0 ? -deq : deq);
            }
        }
        out.push_back({"e8m0_scale_exactness_precondition", bx::kEmax, peak,
                       ok && peak == bx::kEmax, -1});
    }

    // V1 (t-discrimination): odd-step accumulation crossing 2^14. mu=3 (M11,
    // e=0) rails, per-MAC 9, N=1824 -> 16,416 > 2^14 = 16,384; a device exact
    // only to 2^14 (FP32-class ULP >= 2 there) MUST round on this dot product.
    {
        const uint32_t N = 1824;
        const std::vector<int8_t> a(N, 3), b(N, 3);
        const int64_t expected = int64_t{9} * N;
        const int64_t actual = matmul::int8_field::ExactDot(a.data(), b.data(), N);
        out.push_back({"t14_odd_step_base_product", expected, actual,
                       actual == expected && expected > (int64_t{1} << 14), 14});
    }

    // V2 (t-discrimination, real GEMM shape): E_max=48 rails at n=256 push
    // EVERY base-product entry to exactly 2304*n (well past 2^19), then
    // cross-checks the three consensus-equivalent sketch paths byte-for-byte.
    {
        const uint32_t n = 256;
        const uint32_t m = n / mv4::kTileB;
        const std::vector<int8_t> Ahat(static_cast<size_t>(n) * n, static_cast<int8_t>(bx::kEmax));
        const std::vector<int8_t> Bhat(static_cast<size_t>(n) * n, static_cast<int8_t>(bx::kEmax));
        const auto C = mv4::ComputeExactProduct(Ahat, Bhat, n);
        const int64_t expected = static_cast<int64_t>(bx::kBaseProductPerMac) * n;
        size_t mismatches = 0;
        for (int32_t x : C) mismatches += (x != expected) ? 1 : 0;

        const uint256 su = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000e1").value();
        const uint256 sv = uint256::FromHex("00000000000000000000000000000000000000000000000000000000000000e2").value();
        const auto U = bx::ExpandProjectorBMX4C(su, m, n);
        const auto V = bx::ExpandProjectorBMX4C(sv, n, m);
        const auto full = mv4::ComputeSketch(U, C, V, n, m);
        const auto P = mv4::ComputeProjectedLeft(U, Ahat, n, m);
        const auto Q = mv4::ComputeProjectedRight(Bhat, V, n, m);
        const auto direct = mv4::ComputeCombineModQ(P, Q, n, m);
        const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
        const bool pass = mismatches == 0 && direct == full && limb == full;
        out.push_back({"t19_high_magnitude_real_gemm", expected, C.empty() ? 0 : C[0], pass, 19});
    }

    // V3/V4 (boundary-pin): the BMX4-C limb-pair GEMM accumulator peak
    // 1024*n hits EXACTLY 2^22 at n=4096 and 2^23 at n=8192 (all-32 rails).
    for (const uint32_t n : {4096u, 8192u}) {
        const uint32_t m = 8;
        const std::vector<int32_t> P(static_cast<size_t>(m) * n, 32), Q(static_cast<size_t>(n) * m, 32);
        const auto direct = mv4::ComputeCombineModQ(P, Q, n, m);
        const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
        const int64_t expected = int64_t{1024} * n; // 2^22 at n=4096, 2^23 at n=8192
        size_t mismatches = 0;
        for (mv4::Fq v : direct) mismatches += (v != static_cast<uint64_t>(expected)) ? 1 : 0;
        const int32_t pin = (n == 4096u) ? 22 : 23;
        out.push_back({"t" + std::to_string(pin) + "_limb_pair_boundary_n" + std::to_string(n),
                       expected, direct.empty() ? 0 : static_cast<int64_t>(direct[0]),
                       mismatches == 0 && limb == direct, pin});
    }

    // V5 (boundary-pin, "any miner-local base-2^7 limb variant", spec §5.3
    // item 2): the v4.1 base-2^7 limb combine (matmul::v4::
    // ComputeCombineLimbTensor, digits in [-64,63]) hits EXACTLY n*64^2 = 2^24
    // at n=4096 with all-64 rails -- the FP32-boundary-exact case the BMX4-C
    // spec names explicitly as a cross-check pin.
    {
        const uint32_t n = 4096, m = 4;
        const std::vector<int32_t> P(static_cast<size_t>(m) * n, 64), Q(static_cast<size_t>(n) * m, 64);
        const auto direct = mv4::ComputeCombineModQ(P, Q, n, m);
        const auto limb = mv4::ComputeCombineLimbTensor(P, Q, n, m);
        const int64_t expected = int64_t{4096} * 64 * 64; // 2^24
        size_t mismatches = 0;
        for (mv4::Fq v : direct) mismatches += (v != static_cast<uint64_t>(expected)) ? 1 : 0;
        out.push_back({"t24_boundary_pin_base2e7_limb_n4096", expected,
                       direct.empty() ? 0 : static_cast<int64_t>(direct[0]),
                       mismatches == 0 && limb == direct, 24});
    }

    return out;
}

struct Mt24Summary {
    bool precondition_pass{true};
    bool all_pass{false};
    uint32_t proven_accumulator_bits{0};
};

// A device is "proven" up to the highest 2^t rung it passed WITHOUT any
// lower rung failing first: a pass at a high magnitude certifies nothing if a
// lower magnitude already diverged (the §5.1 associativity argument requires
// EVERY intermediate accumulated value to be exact, not just the largest).
Mt24Summary SummarizeMt24(const std::vector<BoundaryVector>& vecs)
{
    Mt24Summary s;
    std::vector<const BoundaryVector*> ladder;
    for (const auto& v : vecs) {
        if (v.regime_pow2 < 0) { if (!v.pass) s.precondition_pass = false; continue; }
        ladder.push_back(&v);
    }
    std::sort(ladder.begin(), ladder.end(),
             [](const BoundaryVector* a, const BoundaryVector* b) { return a->regime_pow2 < b->regime_pow2; });
    uint32_t proven = 0;
    for (const auto* v : ladder) {
        if (!v->pass) break;
        proven = static_cast<uint32_t>(v->regime_pow2);
    }
    s.proven_accumulator_bits = proven;
    s.all_pass = s.precondition_pass && proven >= kMt24RequiredProvenBits;
    return s;
}

// Full M-t24 report: the boundary vectors, the derived proven-bits summary,
// and the native-path-eligibility decision for the RESOLVED backend. No
// device-side BMX4-C kernel is wired into this repository yet (only the v4.1
// ENC-S8 s8xs8->s32 kernels have cuda/metal/hip entry points), so for any
// non-CPU backend this honestly reports native_path_eligible=false with the
// reason, rather than fabricating an on-device verdict from a CPU-only run.
struct Mt24Report {
    std::vector<BoundaryVector> vectors;
    Mt24Summary summary;
    bool device_native_kernel_wired{false};
    bool native_path_eligible{false};
    std::string native_path_reason;
};

Mt24Report RunMt24(matmul_v4::accel::Kind backend)
{
    Mt24Report r;
    r.vectors = RunMt24BoundaryVectors();
    r.summary = SummarizeMt24(r.vectors);
    r.device_native_kernel_wired = (backend == matmul_v4::accel::Kind::CPU);
    if (backend == matmul_v4::accel::Kind::CPU) {
        r.native_path_eligible = r.summary.all_pass;
        r.native_path_reason = r.summary.all_pass
            ? "CPU is a true int64/int32 accumulator by construction; all C-1' boundary vectors are "
              "bit-exact up to and including the proven t=24 threshold."
            : "CPU boundary-vector self-test FAILED -- this indicates a bug in the harness or the "
              "BMX4-C reference implementation, not a hardware accumulator limitation.";
    } else {
        r.native_path_eligible = false;
        r.native_path_reason =
            "no on-device BMX4-C block-scaled tensor kernel is wired into this build for backend '" +
            matmul_v4::accel::ToString(backend) + "' (only the v4.1 ENC-S8 s8xs8->s32 IMMA/MFMA/"
            "TensorOps kernels exist). This run exercised the CPU-reference boundary vectors only "
            "(mt24_pass reflects that self-test); it does NOT constitute an on-silicon M-t24 "
            "measurement for this device. Wiring the vendor FP4/MX block-scaled GEMM behind this same "
            "vector table is the required follow-up (spec §9 item 1) before this backend can report a "
            "real verdict.";
    }
    return r;
}

// ---------------------------------------------------------------------------
// BMX4-C per-stage marginal wall-time on a nonce window (§K.2a-WT/§K.2b
// analogue for the ENC-BMX4C profile). Per-nonce combine (not a single
// stacked GEMM like matmul_v4_batch's v4.1 path, since matmul_v4_bmx4.* has no
// stacked-combine entry point) -- still gives an honest per-stage wall-time
// split and tensor-stage share on this host.
// ---------------------------------------------------------------------------

struct StageResultBMX4C {
    uint32_t n{0};
    uint32_t m{0};
    uint32_t window{0};
    double s0_template{0};
    double s1b_expand{0};
    double s2_gemm{0};
    double s3_limb{0};
    double s3_alu{0};
    double s4_digest{0};
    bool stage_bit_exact{false};
    bool valid{false};
};

StageResultBMX4C MeasureStagesBMX4C(uint32_t n, uint32_t window, uint64_t base_nonce)
{
    StageResultBMX4C r;
    r.n = n;
    r.window = window;
    uint32_t m = 0;
    if (!bx::ValidateDimsBMX4C(n, mv4::kTileB, m) || window == 0) {
        return r;
    }
    r.m = m;
    const std::vector<CBlockHeader> headers = WindowHeaders(n, window, base_nonce);

    auto c0 = Clock::now();
    const uint256 seed_a = bx::DeriveOperandSeedBMX4C(headers[0], mv4::Operand::A);
    const auto [seed_u, seed_v] = bx::DeriveProjectorSeedsBMX4C(headers[0]);
    const std::vector<int8_t> Ahat = bx::ExpandOperandA(seed_a, n);
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);
    const std::vector<int32_t> P = mv4::ComputeProjectedLeft(U, Ahat, n, m);
    auto c1 = Clock::now();
    r.s0_template = Secs(c0, c1);

    bool all_ok = true;
    for (uint32_t i = 0; i < window; ++i) {
        auto ca = Clock::now();
        const uint256 sigma = mv4::DeriveSigma(headers[i]);
        const uint256 seed_b = bx::DeriveOperandSeedBMX4C(headers[i], mv4::Operand::B);
        const std::vector<int8_t> Bhat = bx::ExpandOperandB(seed_b, n);
        auto cb = Clock::now();
        r.s1b_expand += Secs(ca, cb);

        const std::vector<int32_t> Q = mv4::ComputeProjectedRight(Bhat, V, n, m);
        auto cc = Clock::now();
        r.s2_gemm += Secs(cb, cc);

        const auto direct = mv4::ComputeCombineModQ(P, Q, n, m);
        auto cd = Clock::now();
        r.s3_alu += Secs(cc, cd);
        const auto limb = bx::ComputeCombineLimbTensorBMX4C(P, Q, n, m);
        auto ce = Clock::now();
        r.s3_limb += Secs(cd, ce);

        const auto payload = mv4::SerializeSketch(direct);
        const uint256 digest = mv4::ComputeSketchDigest(sigma, payload);
        auto cf = Clock::now();
        r.s4_digest += Secs(ce, cf);

        if (limb != direct) all_ok = false;
        uint256 ref_digest;
        std::vector<unsigned char> ref_payload;
        if (!bx::ComputeDigestBMX4C(headers[i], n, ref_digest, ref_payload) ||
            ref_digest != digest || ref_payload != payload) {
            all_ok = false;
        }
    }
    r.stage_bit_exact = all_ok;
    r.valid = true;
    return r;
}

UniValue StageJsonBMX4C(const StageResultBMX4C& r, double device_peak_tops, double backend_nps,
                        double& tensor_share_pct_out, double& tensor_util_pct_out)
{
    UniValue o(UniValue::VOBJ);
    const double comb = std::min(r.s3_limb, r.s3_alu);
    const bool limb_chosen = r.s3_limb < r.s3_alu;
    const double marginal = r.s1b_expand + r.s2_gemm + comb + r.s4_digest;
    const double tensor_time = r.s2_gemm + (limb_chosen ? comb : 0.0);
    tensor_share_pct_out = marginal > 0 ? 100.0 * tensor_time / marginal : 0;

    // Marginal tensor MACs/nonce: n^2*m (Bhat*V) + 16*m^2*n (16 limb-pair
    // GEMMs), the same shape as the v4.1 estimate (StageJson).
    const double marginal_tensor_macs = static_cast<double>(r.n) * r.n * r.m + 16.0 * r.m * r.m * r.n;
    const double marginal_tensor_ops = 2.0 * marginal_tensor_macs;
    tensor_util_pct_out = -1;
    if (device_peak_tops > 0 && backend_nps > 0) {
        tensor_util_pct_out = 100.0 * marginal_tensor_ops * backend_nps / (device_peak_tops * 1e12);
    }

    o.pushKV("n", static_cast<uint64_t>(r.n));
    o.pushKV("b", static_cast<uint64_t>(mv4::kTileB));
    o.pushKV("m", static_cast<uint64_t>(r.m));
    o.pushKV("window", static_cast<uint64_t>(r.window));
    o.pushKV("bit_exact", r.stage_bit_exact);
    o.pushKV("s0_template_ms", r.s0_template * 1e3);
    o.pushKV("s1b_expand_ms", r.s1b_expand * 1e3);
    o.pushKV("s2_gemm_ms", r.s2_gemm * 1e3);
    o.pushKV("s3_limb_combine_ms", r.s3_limb * 1e3);
    o.pushKV("s3_alu_direct_ms", r.s3_alu * 1e3);
    o.pushKV("s3_chosen", limb_chosen ? "limb-tensor" : "alu-direct");
    o.pushKV("s4_digest_ms", r.s4_digest * 1e3);
    o.pushKV("marginal_per_nonce_ms", r.window ? (marginal * 1e3 / r.window) : 0);
    o.pushKV("cpu_reference_nonce_per_s", marginal > 0 ? (r.window / marginal) : 0);
    o.pushKV("marginal_tensor_macs_per_nonce", marginal_tensor_macs);
    o.pushKV("tensor_share_pct", tensor_share_pct_out);
    if (tensor_util_pct_out >= 0) {
        o.pushKV("tensor_util_pct", tensor_util_pct_out);
    } else {
        o.pushKV("tensor_util_pct", "unknown");
    }
    return o;
}

// ---------------------------------------------------------------------------
// --profile bmx4c entry point: BMX4-C bit-exactness gate (B1 analogue) +
// per-stage stacked-window timing (B2g analogue) + the M-t24 boundary-vector
// verdict, combined into one GO/NO-GO keyed to §K.2b AND M-t24.
// ---------------------------------------------------------------------------

int RunBmx4cProfile(const Args& args, const std::string& host, matmul_v4::accel::Kind backend,
                    const std::string& backend_name, const matmul_v4::backend::Eligibility& elig)
{
    uint32_t m_check = 0;
    if (!bx::ValidateDimsBMX4C(args.n, mv4::kTileB, m_check)) {
        std::cerr << "error: invalid dimension n=" << args.n
                  << " for --profile bmx4c (need n%32==0, b|n, and 288*n<=2^23-1)\n";
        return 2;
    }

    // ---- BMX4-C bit-exactness gate (B1 analogue) ---------------------------
    const std::vector<CBlockHeader> headers = WindowHeaders(args.n, args.window, 42);
    bool bmx4c_bit_exact = true;
    for (uint32_t i = 0; i < args.window; ++i) {
        uint256 d1, d2;
        std::vector<unsigned char> p1, p2;
        const bool ok1 = bx::ComputeDigestBMX4C(headers[i], args.n, d1, p1);
        const bool ok2 = bx::ComputeDigestBMX4C(headers[i], args.n, d2, p2); // run-to-run determinism
        if (!ok1 || !ok2 || d1 != d2 || p1 != p2) { bmx4c_bit_exact = false; continue; }
        CBlockHeader vh = headers[i];
        vh.matmul_digest = d1;
        uint256 vout;
        if (!bx::VerifySketchBMX4C(vh, args.n, args.rounds, p1, vout) || vout != d1) {
            bmx4c_bit_exact = false;
        }
    }

    std::cout << "\n[B1-analogue] BMX4-C bit-exact determinism gate\n";
    std::cout << "  ComputeDigestBMX4C determinism + VerifySketchBMX4C round-trip over "
              << args.window << " nonces: " << (bmx4c_bit_exact ? "PASS" : "FAIL") << "\n";
    if (!bmx4c_bit_exact) {
        std::cout << "  *** FAIL is a HARD consensus-split signal for the ENC-BMX4C profile ***\n";
    }
    std::cout << "  NOTE: no on-device BMX4-C dispatch exists in this build yet (only v4.1 ENC-S8 has\n"
                 "  cuda/metal/hip kernels); this gate certifies the CPU reference only.\n";

    // ---- BMX4-C per-stage marginal wall-time -------------------------------
    std::cout << "\n[B2g-analogue] BMX4-C per-stage marginal wall-time (n=" << args.n
              << ", window Q=" << args.window << ")\n";
    const StageResultBMX4C stage = MeasureStagesBMX4C(args.n, args.window, 42);
    double tensor_share_pct = 0, tensor_util_pct = -1;
    UniValue stage_json(UniValue::VOBJ);
    if (stage.valid) {
        const double comb = std::min(stage.s3_limb, stage.s3_alu);
        const bool limb_chosen = stage.s3_limb < stage.s3_alu;
        const double marginal = stage.s1b_expand + stage.s2_gemm + comb + stage.s4_digest;
        auto pct = [&](double x) { return marginal > 0 ? 100.0 * x / marginal : 0.0; };
        std::printf("  S0  template Ahat,U,V + P=U*Ahat (amortized): %9.3f ms\n", stage.s0_template * 1e3);
        std::printf("  S1b per-nonce expand Bhat   (SHA/int)  : %9.3f ms  %5.1f%%\n",
                    stage.s1b_expand * 1e3 / args.window, pct(stage.s1b_expand));
        std::printf("  S2  per-nonce GEMM Q=Bhat*V (tensor)   : %9.3f ms  %5.1f%%\n",
                    stage.s2_gemm * 1e3 / args.window, pct(stage.s2_gemm));
        std::printf("  S3  combine P*Q chosen=%-13s: %9.3f ms  %5.1f%%\n",
                    limb_chosen ? "limb-tensor" : "alu-direct", comb * 1e3 / args.window, pct(comb));
        std::printf("      (limb-tensor %.3f ms vs ALU-direct %.3f ms, whole window)\n",
                    stage.s3_limb * 1e3, stage.s3_alu * 1e3);
        std::printf("  S4  serialize + digest      (SHA/int)  : %9.3f ms  %5.1f%%\n",
                    stage.s4_digest * 1e3 / args.window, pct(stage.s4_digest));
        std::printf("  per-nonce MARGINAL total (S0 amortized): %9.3f ms   stage-bit-exact=%s\n",
                    marginal * 1e3 / args.window, stage.stage_bit_exact ? "YES" : "NO -- STAGE DIVERGED, TIMES VOID");
        stage_json = StageJsonBMX4C(stage, args.device_peak_int8_tops, 0.0, tensor_share_pct, tensor_util_pct);
    } else {
        std::cout << "  (stage measurement unavailable for this dimension)\n";
    }
    std::cout << "  tensor-stage share (§K.2a-WT majority gate): ";
    if (stage.valid) std::printf("%.1f%%\n", tensor_share_pct); else std::cout << "n/a\n";

    // ---- M-t24 boundary-vector suite ---------------------------------------
    std::cout << "\n[M-t24] accumulator-exactness boundary-vector suite (spec §5.3/C-1')\n";
    const Mt24Report mt24 = RunMt24(backend);
    for (const auto& v : mt24.vectors) {
        std::string rung = v.regime_pow2 >= 0 ? (" (2^" + std::to_string(v.regime_pow2) + " rung)") : " (precondition)";
        std::printf("  %-42s expected=%-12lld actual=%-12lld %s%s\n",
                    v.name.c_str(), static_cast<long long>(v.expected), static_cast<long long>(v.actual),
                    v.pass ? "PASS" : "FAIL", rung.c_str());
    }
    std::cout << "  proven exact-accumulator bits : " << mt24.summary.proven_accumulator_bits
              << (mt24.summary.proven_accumulator_bits >= kMt24RequiredProvenBits
                      ? "  (>= t=24: NATIVE PATH threshold met)"
                      : "  (< t=24: native path FAILS CLOSED to the INT8 fallback)")
              << "\n";
    std::cout << "  M-t24 verdict                 : " << (mt24.summary.all_pass ? "PASS" : "FAIL") << "\n";
    std::cout << "  device native kernel wired    : " << (mt24.device_native_kernel_wired ? "yes" : "no") << "\n";
    std::cout << "  native path eligible           : " << (mt24.native_path_eligible ? "YES" : "NO") << "\n";
    std::cout << "  reason                         : " << mt24.native_path_reason << "\n";

    // ---- combined GO / NO-GO (§K.2b tensor majority AND M-t24) -------------
    std::string verdict;
    if (!bmx4c_bit_exact) {
        verdict = "NO-GO: BMX4-C bit-exact determinism FAILED (consensus split)";
    } else if (!stage.valid || !stage.stage_bit_exact) {
        verdict = "NO-GO: BMX4-C stage outputs diverged (measurement void)";
    } else if (!mt24.summary.all_pass) {
        verdict = "NO-GO(native path): M-t24 FAILED -- proven only " +
                  std::to_string(mt24.summary.proven_accumulator_bits) +
                  " exact-accumulator bits (< t=24); BMX4-C NATIVE path is INELIGIBLE, MUST fall back "
                  "to the 1-GEMM INT8 path (spec §5.2 fallback ladder)";
    } else if (tensor_share_pct <= 50.0) {
        verdict = "NO-GO(this machine's stage profile): tensor-stage share is NOT a strict majority ("
                  + std::to_string(static_cast<int>(tensor_share_pct + 0.5)) + "%, §K.2b)";
    } else if (!mt24.native_path_eligible) {
        verdict = "GO-CANDIDATE(harness-only): bit-exact + M-t24 boundary vectors PASS on the CPU "
                  "reference and tensor-stage share is a majority, but no on-device BMX4-C kernel is "
                  "wired for backend '" + backend_name + "' in this build -- native_path_eligible is "
                  "UNVERIFIED on real silicon (see reason above)";
    } else {
        verdict = "GO: BMX4-C bit-exact PASS, M-t24 PASS (proven t=" +
                  std::to_string(mt24.summary.proven_accumulator_bits) +
                  "), tensor-stage share is a majority (" +
                  std::to_string(static_cast<int>(tensor_share_pct + 0.5)) +
                  "%) -- native path ELIGIBLE on this device";
    }
    std::cout << "\n[GO/NO-GO §K.2b + M-t24] " << verdict << "\n";

    // ---- H8: device-execution certification gate ---------------------------
    // The BMX4-C profile is a DEVICE-certification profile: a green PASS
    // (exit 0) may be emitted ONLY when a real on-silicon BMX4-C native tensor
    // path actually executed and was certified. `native_path_eligible` is true
    // for the CPU backend (the CPU is a true int64 accumulator) and for a real
    // device only once an on-device BMX4-C block-scaled kernel is wired AND
    // proves M-t24 on that silicon; no such kernel exists in this build, so a
    // CPU-only run -- or any run on this GPU-less host -- must NOT certify.
    // Failing closed here is always safe: the failure mode we eliminate is a
    // CPU/emulation run masquerading as a certified native tensor measurement.
    const bool ran_on_device = (backend != matmul_v4::accel::Kind::CPU);
    const bool device_certified = ran_on_device && mt24.native_path_eligible;
    const bool harness_self_test_ok =
        bmx4c_bit_exact && stage.stage_bit_exact && mt24.summary.all_pass;
    if (device_certified) {
        // Honest device marker: verify-backend.sh (bmx4c mode) requires this in
        // the report output, not merely exit 0. Emitted ONLY on a real,
        // certified on-device native tensor path -- never on a CPU-only run.
        std::cout << "DEVICE_BMX4C_MT24_PASS:" << backend_name << ":" << elig.reason << "\n";
    } else {
        std::cout << "\n[CERTIFICATION] NOT-CERTIFIED: no on-device BMX4-C native tensor path "
                     "executed on this host (resolved backend=" << backend_name
                  << "). The CPU harness self-test "
                  << (harness_self_test_ok ? "PASSED" : "FAILED")
                  << ", but a DEVICE profile certifies only on ACTUAL device execution; "
                     "exiting non-zero (a CPU-only run of a device profile is NOT a PASS).\n";
    }

    // ---- machine-readable JSON ----------------------------------------------
    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "matmul-v4-report");
    root.pushKV("schema_version", 2);
    root.pushKV("host", host);
    root.pushKV("host_cpu_arch", HostCpuArch());
    root.pushKV("backend", backend_name);
    UniValue elig_obj(UniValue::VOBJ);
    elig_obj.pushKV("compiled", elig.compiled);
    elig_obj.pushKV("available", elig.available);
    elig_obj.pushKV("admissible", elig.admissible);
    elig_obj.pushKV("reason", elig.reason);
    root.pushKV("device", std::move(elig_obj));
    root.pushKV("n", static_cast<uint64_t>(args.n));
    root.pushKV("b", static_cast<uint64_t>(mv4::kTileB));
    root.pushKV("window", static_cast<uint64_t>(args.window));
    root.pushKV("rounds", static_cast<uint64_t>(args.rounds));

    // -- additive top-level fields (task contract: profile / mt24_pass /
    // proven_accumulator_bits / native_path_eligible) -----------------------
    root.pushKV("profile", "bmx4c");
    root.pushKV("mt24_pass", mt24.summary.all_pass);
    root.pushKV("proven_accumulator_bits", static_cast<uint64_t>(mt24.summary.proven_accumulator_bits));
    root.pushKV("native_path_eligible", mt24.native_path_eligible);
    // H8: did an ACTUAL device tensor path execute and certify? (Gates exit 0.)
    root.pushKV("device_execution_certified", device_certified);
    root.pushKV("harness_self_test_pass", harness_self_test_ok);

    root.pushKV("bit_exact", bmx4c_bit_exact);
    root.pushKV("stages", stage_json);
    root.pushKV("tensor_share_pct", stage.valid ? tensor_share_pct : 0);
    if (tensor_util_pct >= 0) root.pushKV("tensor_util_pct", tensor_util_pct);
    else root.pushKV("tensor_util_pct", "unknown");
    root.pushKV("device_peak_int8_tops", args.device_peak_int8_tops);

    UniValue mt24_obj(UniValue::VOBJ);
    mt24_obj.pushKV("device_native_kernel_wired", mt24.device_native_kernel_wired);
    mt24_obj.pushKV("native_path_reason", mt24.native_path_reason);
    mt24_obj.pushKV("required_proven_bits", static_cast<uint64_t>(kMt24RequiredProvenBits));
    UniValue vec_arr(UniValue::VARR);
    for (const auto& v : mt24.vectors) {
        UniValue vo(UniValue::VOBJ);
        vo.pushKV("name", v.name);
        vo.pushKV("expected", v.expected);
        vo.pushKV("actual", v.actual);
        vo.pushKV("pass", v.pass);
        vo.pushKV("regime_pow2", v.regime_pow2);
        vec_arr.push_back(vo);
    }
    mt24_obj.pushKV("vectors", vec_arr);
    root.pushKV("mt24", mt24_obj);

    root.pushKV("verdict", verdict);
    root.pushKV("gates", [] {
        UniValue g(UniValue::VOBJ);
        g.pushKV("B1_analogue", "bit_exact (BMX4-C determinism + verifier round-trip)");
        g.pushKV("B2g_analogue", "tensor_share_pct (§K.2a-WT/§K.2b tensor-stage majority)");
        g.pushKV("Mt24", "mt24_pass + proven_accumulator_bits + native_path_eligible (spec §5.3/C-1')");
        return g;
    }());

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    ofs.close();
    std::cout << "\nJSON report written: " << args.out_path << "\n";
    std::cout << "M-t24 decides native-path eligibility; ENC-BMX4C MUST NOT activate without M-t24 "
                 "PASS on >= 2 independent vendors' frontier parts (spec §7.5/§9).\n";

    // H8: exit 0 (green PASS = CERTIFIED) requires an ACTUAL certified on-device
    // native tensor path. The harness self-test passing on the CPU reference is
    // necessary but NOT sufficient -- a CPU-only run of this device profile is a
    // NOT-CERTIFIED result, so it returns non-zero.
    return device_certified ? 0 : 1;
}

// ---------------------------------------------------------------------------
// --profile bmx4c-lt : ENC-DR-LT MatExpand+Q* stage measurement (schema v3).
// ---------------------------------------------------------------------------

namespace lt = matmul::v4::lt;

struct StageResultLT {
    uint32_t n{0};
    uint32_t m{0};
    uint32_t window{0};
    double s0_template{0};       // MatExpand-A + U,V + P=U*A (I1' amortized)
    double s1_matexpand_b{0};    // per-nonce MatExpand-B (tensor GEMMs + Extract)
    double s2_bhat_v{0};         // Bhat*V
    double s3_combine{0};        // P*Q mod-q (normative LT path)
    double s4_digest{0};
    double s5_qstar_seal{0};     // Merkle + SealWindowCommit over the window
    bool stage_bit_exact{false};
    bool valid{false};
};

StageResultLT MeasureStagesLT(uint32_t n, uint32_t window, uint64_t base_nonce)
{
    StageResultLT r;
    r.n = n;
    r.window = window;
    uint32_t m = 0;
    if (!lt::ValidateDimsBMX4CLT(n, m) || window == 0) {
        return r;
    }
    r.m = m;
    const std::vector<CBlockHeader> headers = WindowHeaders(n, window, base_nonce);

    // S0: template-scoped MatExpand-A + projectors + P (invariant I1').
    auto c0 = Clock::now();
    const auto [seed_u, seed_v] = lt::DeriveProjectorSeedsBMX4CLT(headers[0]);
    const std::vector<int8_t> Ahat = lt::ExpandOperandAMatExpand(headers[0], n);
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);
    const std::vector<int32_t> P = mv4::ComputeProjectedLeft(U, Ahat, n, m);
    auto c1 = Clock::now();
    r.s0_template = Secs(c0, c1);

    bool all_ok = true;
    std::vector<uint256> digests;
    digests.reserve(window);
    for (uint32_t i = 0; i < window; ++i) {
        auto ca = Clock::now();
        const uint256 sigma = mv4::DeriveSigma(headers[i]);
        const std::vector<int8_t> Bhat = lt::ExpandOperandBMatExpand(headers[i], n);
        auto cb = Clock::now();
        r.s1_matexpand_b += Secs(ca, cb);

        const std::vector<int32_t> Q = mv4::ComputeProjectedRight(Bhat, V, n, m);
        auto cc = Clock::now();
        r.s2_bhat_v += Secs(cb, cc);

        const auto Chat = mv4::ComputeCombineModQ(P, Q, n, m);
        auto cd = Clock::now();
        r.s3_combine += Secs(cc, cd);

        const auto payload = mv4::SerializeSketch(Chat);
        const uint256 digest = mv4::ComputeSketchDigest(sigma, payload);
        auto ce = Clock::now();
        r.s4_digest += Secs(cd, ce);
        digests.push_back(digest);

        uint256 ref_digest;
        std::vector<unsigned char> ref_payload;
        if (!lt::ComputeDigestBMX4CLT(headers[i], n, ref_digest, ref_payload) ||
            ref_digest != digest || ref_payload != payload) {
            all_ok = false;
        }
    }

    // S5: Q* seal sample over the measured window (Phase-B cost signal;
    // Phase-A lottery remains per-nonce). Uses CommitWindowSlotLeaf +
    // SealWindowCommit with the measured window size even if it is not a
    // consensus Q* — operators should pass --window 64|128 for production
    // Rank-1 shapes.
    auto cs0 = Clock::now();
    const uint256 sigma_anchor = mv4::DeriveSigma(headers[0]);
    std::vector<uint256> leaves;
    leaves.reserve(digests.size());
    for (size_t i = 0; i < digests.size(); ++i) {
        const uint256 slot_id = lt::DeriveWindowSlotId(sigma_anchor, static_cast<uint32_t>(i));
        leaves.push_back(lt::CommitWindowSlotLeaf(slot_id, digests[i]));
    }
    const uint256 merkle = lt::ComputeWindowMerkleRoot(leaves);
    const uint256 seal = lt::SealWindowCommit(sigma_anchor, merkle, window);
    auto cs1 = Clock::now();
    r.s5_qstar_seal = Secs(cs0, cs1);
    if (seal.IsNull() && window > 0) {
        all_ok = false;
    }

    r.stage_bit_exact = all_ok;
    r.valid = true;
    return r;
}

UniValue StageJsonLT(const StageResultLT& r, double device_peak_tops, double backend_nps,
                     double& tensor_share_pct_out, double& tensor_util_pct_out)
{
    UniValue o(UniValue::VOBJ);
    // Marginal = MatExpand-B + Bhat*V + combine + digest (S0 amortized; S5 is
    // a window-level seal sample reported separately, not in per-nonce share).
    const double marginal = r.s1_matexpand_b + r.s2_bhat_v + r.s3_combine + r.s4_digest;
    // Tensor stages under LT: MatExpand-B (dense G*W / Y*H) + Bhat*V.
    const double tensor_time = r.s1_matexpand_b + r.s2_bhat_v;
    tensor_share_pct_out = marginal > 0 ? 100.0 * tensor_time / marginal : 0;

    const double w = static_cast<double>(lt::kMatExpandPanelW);
    const double marginal_tensor_macs =
        2.0 * static_cast<double>(r.n) * r.n * w + // MatExpand G*W + Y*H
        static_cast<double>(r.n) * r.n * r.m;      // Bhat*V
    const double marginal_tensor_ops = 2.0 * marginal_tensor_macs;
    tensor_util_pct_out = -1;
    if (device_peak_tops > 0 && backend_nps > 0) {
        tensor_util_pct_out = 100.0 * marginal_tensor_ops * backend_nps / (device_peak_tops * 1e12);
    }

    o.pushKV("n", static_cast<uint64_t>(r.n));
    o.pushKV("b", static_cast<uint64_t>(lt::kTileBLT));
    o.pushKV("m", static_cast<uint64_t>(r.m));
    o.pushKV("window", static_cast<uint64_t>(r.window));
    o.pushKV("bit_exact", r.stage_bit_exact);
    o.pushKV("i1_prime_amortized", true);
    o.pushKV("s0_template_ms", r.s0_template * 1e3);
    o.pushKV("s1_matexpand_b_ms", r.s1_matexpand_b * 1e3);
    o.pushKV("s2_bhat_v_ms", r.s2_bhat_v * 1e3);
    o.pushKV("s3_combine_ms", r.s3_combine * 1e3);
    o.pushKV("s4_digest_ms", r.s4_digest * 1e3);
    o.pushKV("s5_qstar_seal_ms", r.s5_qstar_seal * 1e3);
    o.pushKV("marginal_per_nonce_ms", r.window ? (marginal * 1e3 / r.window) : 0);
    o.pushKV("cpu_reference_nonce_per_s", marginal > 0 ? (r.window / marginal) : 0);
    o.pushKV("marginal_tensor_macs_per_nonce", marginal_tensor_macs);
    o.pushKV("tensor_share_pct", tensor_share_pct_out);
    if (tensor_util_pct_out >= 0) {
        o.pushKV("tensor_util_pct", tensor_util_pct_out);
    } else {
        o.pushKV("tensor_util_pct", "unknown");
    }
    return o;
}

int RunBmx4cLtProfile(const Args& args, const std::string& host, matmul_v4::accel::Kind backend,
                      const std::string& backend_name, const matmul_v4::backend::Eligibility& elig)
{
    uint32_t m_check = 0;
    if (!lt::ValidateDimsBMX4CLT(args.n, m_check)) {
        std::cerr << "error: invalid dimension n=" << args.n
                  << " for --profile bmx4c-lt (need n%32==0, b=2 | n, ENC-BMX4C dim gates)\n";
        return 2;
    }
    if (!lt::IsValidConsensusQStar(args.window)) {
        std::cout << "NOTE: --window=" << args.window
                  << " is not a consensus Q* ({64,128}); stage timings are still valid but "
                     "Rank-1 production campaigns should use --window 64 or 128.\n";
    }

    // ---- LT bit-exactness gate (B1 analogue) -------------------------------
    const std::vector<CBlockHeader> headers = WindowHeaders(args.n, args.window, 42);
    bool lt_bit_exact = true;
    for (uint32_t i = 0; i < args.window; ++i) {
        uint256 d1, d2;
        std::vector<unsigned char> p1, p2;
        const bool ok1 = lt::ComputeDigestBMX4CLT(headers[i], args.n, d1, p1);
        const bool ok2 = lt::ComputeDigestBMX4CLT(headers[i], args.n, d2, p2);
        if (!ok1 || !ok2 || d1 != d2 || p1 != p2) { lt_bit_exact = false; continue; }
        CBlockHeader vh = headers[i];
        vh.matmul_digest = d1;
        uint256 vout;
        if (!lt::VerifySketchBMX4CLT(vh, args.n, args.rounds, p1, vout) || vout != d1) {
            lt_bit_exact = false;
        }
    }

    std::cout << "\n[B1-analogue] ENC-DR-LT bit-exact determinism gate\n";
    std::cout << "  ComputeDigestBMX4CLT determinism + VerifySketchBMX4CLT round-trip over "
              << args.window << " nonces: " << (lt_bit_exact ? "PASS" : "FAIL") << "\n";
    if (!lt_bit_exact) {
        std::cout << "  *** FAIL is a HARD consensus-split signal for the ENC-DR-LT profile ***\n";
    }

    // ---- Device dispatch probe (honest: only *_batch_ok counts as wired) ---
    matmul_v4::accel::ResetStats();
    std::vector<uint256> disp_digests;
    std::vector<std::vector<unsigned char>> disp_payloads;
    // All-ones win_target forces host verify of the whole window when a device
    // path returns (see accel_v4.h contract).
    uint256 win_all_ones;
    std::memset(win_all_ones.begin(), 0xff, win_all_ones.size());
    const bool disp_ok = matmul_v4::accel::ComputeDigestsBMX4CLTDispatched(
        headers, args.n, args.rounds, win_all_ones, disp_digests, disp_payloads);
    const auto stats = matmul_v4::accel::ProbeStats();
    bool device_native_kernel_wired = false;
    std::string native_path_reason;
    if (backend == matmul_v4::accel::Kind::CPU) {
        device_native_kernel_wired = true;
        native_path_reason =
            "CPU reference path; certifies the harness only — never counts as frontier silicon.";
    } else if (backend == matmul_v4::accel::Kind::CUDA) {
        device_native_kernel_wired = stats.cuda_batch_ok > 0;
        native_path_reason = device_native_kernel_wired
            ? "ComputeDigestsBMX4CLTDispatched accepted a CUDA LT window (cuda_batch_ok>0)."
            : "no CUDA LT device window accepted (cuda_batch_ok==0; CPU fallback or unavailable). "
              "This run does NOT invent an on-silicon rate.";
    } else if (backend == matmul_v4::accel::Kind::METAL) {
        device_native_kernel_wired = stats.metal_batch_ok > 0;
        native_path_reason = device_native_kernel_wired
            ? "ComputeDigestsBMX4CLTDispatched accepted a Metal LT window (metal_batch_ok>0)."
            : "no Metal LT device window accepted (metal_batch_ok==0; CPU fallback or unavailable). "
              "This run does NOT invent an on-silicon rate.";
    } else if (backend == matmul_v4::accel::Kind::HIP) {
        device_native_kernel_wired = stats.hip_batch_ok > 0;
        native_path_reason = device_native_kernel_wired
            ? "ComputeDigestsBMX4CLTDispatched accepted a HIP LT window (hip_batch_ok>0)."
            : "no HIP LT device window accepted (hip_batch_ok==0; CPU fallback or unavailable). "
              "This run does NOT invent an on-silicon rate.";
    }
    if (disp_ok && lt_bit_exact && disp_digests.size() == args.window) {
        for (uint32_t i = 0; i < args.window; ++i) {
            uint256 ref;
            std::vector<unsigned char> ref_p;
            if (!lt::ComputeDigestBMX4CLT(headers[i], args.n, ref, ref_p) ||
                ref != disp_digests[i] || ref_p != disp_payloads[i]) {
                lt_bit_exact = false;
                break;
            }
        }
    } else if (!disp_ok) {
        // Dispatch failure is a harness problem only when the CPU reference also fails;
        // device fallback still returns CPU digests, so !disp_ok means empty/invalid.
        lt_bit_exact = false;
    }

    // ---- MatExpand+Q* per-stage marginal wall-time -------------------------
    std::cout << "\n[B2g-analogue] ENC-DR-LT MatExpand+Q* stage boundaries (n=" << args.n
              << ", window Q=" << args.window << ", b=" << lt::kTileBLT << ")\n";
    const StageResultLT stage = MeasureStagesLT(args.n, args.window, 42);
    double tensor_share_pct = 0, tensor_util_pct = -1;
    UniValue stage_json(UniValue::VOBJ);
    double cpu_nps = 0;
    if (stage.valid) {
        const double marginal =
            stage.s1_matexpand_b + stage.s2_bhat_v + stage.s3_combine + stage.s4_digest;
        auto pct = [&](double x) { return marginal > 0 ? 100.0 * x / marginal : 0.0; };
        std::printf("  S0  template MatExpand-A + U,V + P (I1' amortized): %9.3f ms\n",
                    stage.s0_template * 1e3);
        std::printf("  S1  per-nonce MatExpand-B     (tensor) : %9.3f ms  %5.1f%%\n",
                    stage.s1_matexpand_b * 1e3 / args.window, pct(stage.s1_matexpand_b));
        std::printf("  S2  per-nonce GEMM Bhat*V     (tensor) : %9.3f ms  %5.1f%%\n",
                    stage.s2_bhat_v * 1e3 / args.window, pct(stage.s2_bhat_v));
        std::printf("  S3  combine P*Q               (int)    : %9.3f ms  %5.1f%%\n",
                    stage.s3_combine * 1e3 / args.window, pct(stage.s3_combine));
        std::printf("  S4  serialize + digest        (SHA/int): %9.3f ms  %5.1f%%\n",
                    stage.s4_digest * 1e3 / args.window, pct(stage.s4_digest));
        std::printf("  S5  Q* Merkle+SealWindowCommit (window): %9.3f ms\n",
                    stage.s5_qstar_seal * 1e3);
        std::printf("  per-nonce MARGINAL total (S0 amortized): %9.3f ms   stage-bit-exact=%s\n",
                    marginal * 1e3 / args.window, stage.stage_bit_exact ? "YES" : "NO -- STAGE DIVERGED, TIMES VOID");
        stage_json = StageJsonLT(stage, args.device_peak_int8_tops, 0.0, tensor_share_pct, tensor_util_pct);
        cpu_nps = marginal > 0 ? (args.window / marginal) : 0;
    } else {
        std::cout << "  (stage measurement unavailable for this dimension)\n";
    }
    std::cout << "  tensor-stage share (MatExpand-B + Bhat*V majority gate): ";
    if (stage.valid) std::printf("%.1f%%\n", tensor_share_pct); else std::cout << "n/a\n";

    std::cout << "\n[device] LT native MatExpand GEMM path\n";
    std::cout << "  device native kernel wired    : " << (device_native_kernel_wired ? "yes" : "no") << "\n";
    std::cout << "  reason                         : " << native_path_reason << "\n";

    const bool native_path_eligible =
        lt_bit_exact && stage.valid && stage.stage_bit_exact && device_native_kernel_wired &&
        tensor_share_pct > 50.0 && backend != matmul_v4::accel::Kind::CPU;

    std::string verdict;
    if (!lt_bit_exact) {
        verdict = "NO-GO: ENC-DR-LT bit-exact determinism FAILED (consensus split)";
    } else if (!stage.valid || !stage.stage_bit_exact) {
        verdict = "NO-GO: ENC-DR-LT stage outputs diverged (measurement void)";
    } else if (tensor_share_pct <= 50.0) {
        verdict = "NO-GO(this machine's stage profile): MatExpand+Bhat*V tensor share is NOT a "
                  "strict majority (" + std::to_string(static_cast<int>(tensor_share_pct + 0.5)) + "%)";
    } else if (backend == matmul_v4::accel::Kind::CPU) {
        verdict = "GO-CANDIDATE(harness-only): bit-exact + tensor-majority on the CPU reference; "
                  "CPU never counts as frontier silicon for Rank-1 GO/NO-GO";
    } else if (!device_native_kernel_wired) {
        verdict = "GO-CANDIDATE(harness-only): bit-exact + tensor-majority on CPU timings, but no "
                  "on-device LT MatExpand GEMM window was accepted for backend '" + backend_name +
                  "' — native_path_eligible is UNVERIFIED (no invented silicon numbers)";
    } else {
        verdict = "GO-CANDIDATE(device path exercised): bit-exact PASS, tensor-stage majority (" +
                  std::to_string(static_cast<int>(tensor_share_pct + 0.5)) +
                  "%), device LT window accepted — aggregate with lt-gate.py across B200/5090 "
                  "(this tool does not close Rank-1 GO/NO-GO)";
    }
    std::cout << "\n[GO/NO-GO candidate §LT stages] " << verdict << "\n";

    const bool ran_on_device = (backend != matmul_v4::accel::Kind::CPU);
    const bool device_certified = ran_on_device && native_path_eligible;
    const bool harness_self_test_ok = lt_bit_exact && stage.valid && stage.stage_bit_exact;
    if (device_certified) {
        std::cout << "DEVICE_BMX4CLT_PASS:" << backend_name << ":" << elig.reason << "\n";
    } else {
        std::cout << "\n[CERTIFICATION] NOT-CERTIFIED as Rank-1 frontier silicon on this host "
                     "(resolved backend=" << backend_name << "). Harness self-test "
                  << (harness_self_test_ok ? "PASSED" : "FAILED")
                  << "; exiting non-zero unless a real device LT window was accepted with "
                     "tensor majority. JSON is still written for lt-gate.py aggregation.\n";
    }

    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "matmul-v4-report");
    root.pushKV("schema_version", 3);
    root.pushKV("host", host);
    root.pushKV("host_cpu_arch", HostCpuArch());
    root.pushKV("backend", backend_name);
    UniValue elig_obj(UniValue::VOBJ);
    elig_obj.pushKV("compiled", elig.compiled);
    elig_obj.pushKV("available", elig.available);
    elig_obj.pushKV("admissible", elig.admissible);
    elig_obj.pushKV("reason", elig.reason);
    root.pushKV("device", std::move(elig_obj));
    root.pushKV("n", static_cast<uint64_t>(args.n));
    root.pushKV("b", static_cast<uint64_t>(lt::kTileBLT));
    root.pushKV("window", static_cast<uint64_t>(args.window));
    root.pushKV("rounds", static_cast<uint64_t>(args.rounds));
    root.pushKV("profile", "bmx4c-lt");
    root.pushKV("native_path_eligible", native_path_eligible);
    root.pushKV("device_execution_certified", device_certified);
    root.pushKV("harness_self_test_pass", harness_self_test_ok);
    root.pushKV("bit_exact", lt_bit_exact);
    root.pushKV("stages", stage_json);
    root.pushKV("tensor_share_pct", stage.valid ? tensor_share_pct : UniValue(UniValue::VNULL));
    if (tensor_util_pct >= 0) root.pushKV("tensor_util_pct", tensor_util_pct);
    else root.pushKV("tensor_util_pct", "unknown");
    root.pushKV("device_peak_int8_tops", args.device_peak_int8_tops);
    // Throughput: stage clocks in this tool are CPU-instrumented even when a
    // device MatExpand GEMM window was accepted. Never promote CPU timers to a
    // device nonce/s field — lt-gate.py fails closed on G2/G3 when
    // device_nonce_per_s is missing (no invented silicon numbers).
    root.pushKV("device_nonce_per_s", UniValue(UniValue::VNULL));
    root.pushKV("backend_nonce_per_s", UniValue(UniValue::VNULL));
    if (stage.valid) {
        root.pushKV("cpu_reference_nonce_per_s", cpu_nps);
    } else {
        root.pushKV("cpu_reference_nonce_per_s", UniValue(UniValue::VNULL));
    }
    root.pushKV("throughput_note",
                "cpu_reference_nonce_per_s is host-CPU stage timing only. device_nonce_per_s is "
                "null until on-device MatExpand+Q* stage timers land; lt-gate MUST NOT invent rates.");

    UniValue lt_obj(UniValue::VOBJ);
    lt_obj.pushKV("device_native_kernel_wired", device_native_kernel_wired);
    lt_obj.pushKV("native_path_reason", native_path_reason);
    lt_obj.pushKV("tile_b", static_cast<uint64_t>(lt::kTileBLT));
    lt_obj.pushKV("matexpand_panel_w", static_cast<uint64_t>(lt::kMatExpandPanelW));
    lt_obj.pushKV("qstar_window", static_cast<uint64_t>(args.window));
    lt_obj.pushKV("qstar_is_consensus", lt::IsValidConsensusQStar(args.window));
    lt_obj.pushKV("cuda_batch_ok", static_cast<uint64_t>(stats.cuda_batch_ok));
    lt_obj.pushKV("metal_batch_ok", static_cast<uint64_t>(stats.metal_batch_ok));
    lt_obj.pushKV("hip_batch_ok", static_cast<uint64_t>(stats.hip_batch_ok));
    root.pushKV("lt", lt_obj);
    root.pushKV("verdict", verdict);
    root.pushKV("gates", [] {
        UniValue g(UniValue::VOBJ);
        g.pushKV("B1_analogue", "bit_exact (ENC-DR-LT determinism + verifier round-trip)");
        g.pushKV("B2g_analogue", "tensor_share_pct (MatExpand-B + Bhat*V majority)");
        g.pushKV("Qstar", "s5_qstar_seal_ms + qstar_is_consensus");
        g.pushKV("Device", "lt.device_native_kernel_wired (ProbeStats batch_ok; no invented rates)");
        return g;
    }());

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    ofs.close();
    std::cout << "\nJSON report written: " << args.out_path << "\n";
    std::cout << "Aggregate Rank-1 measurements with:\n"
                 "  contrib/matmul-v4/lt-gate.py <dir-of-json> --manifest parts.tsv\n"
                 "This tool does not raise nMatMulDRLTHeight and does not close GO/NO-GO.\n";

    return device_certified ? 0 : 1;
}

} // namespace

int main(int argc, char* argv[])
{
    Args args;
    std::string err;
    if (!ParseArgs(argc, argv, args, err)) {
        std::cerr << "error: " << err << "\n";
        PrintUsage(std::cerr);
        return 2;
    }
    if (!args.backend_override.empty()) {
#if defined(_WIN32)
        _putenv_s("BTX_MATMUL_V4_BACKEND", args.backend_override.c_str());
#else
        setenv("BTX_MATMUL_V4_BACKEND", args.backend_override.c_str(), 1);
#endif
    }

    const std::string host = HostName();
    if (args.out_path.empty()) {
        args.out_path = "matmul-v4-report-" + host + ".json";
    }

    // ---- resolve backend + device identity -------------------------------
    const matmul_v4::accel::Kind backend = matmul_v4::accel::ResolveBackend();
    const std::string backend_name = matmul_v4::accel::ToString(backend);
    const auto elig = matmul_v4::backend::EligibilityFor(ToEligKind(backend));

    std::cout << "== MatMul v"
              << (args.profile == "bmx4c-lt" ? "4.4 (ENC-DR-LT)"
                                            : (args.profile == "bmx4c" ? "4.2 (ENC-BMX4C)" : "4.1"))
              << " hardware report (" << host << ") ==\n";
    std::cout << "profile          : " << args.profile << "\n";
    std::cout << "resolved backend : " << backend_name
              << "  [compiled=" << (elig.compiled ? "yes" : "no")
              << " available=" << (elig.available ? "yes" : "no")
              << " admissible=" << (elig.admissible ? "yes" : "no") << "]\n";
    std::cout << "device identity  : " << elig.reason << "\n";
    std::cout << "host cpu arch    : " << HostCpuArch() << "\n";
    if (args.profile == "bmx4c-lt") {
        std::cout << "dims             : n=" << args.n << " b=" << matmul::v4::lt::kTileBLT
                  << " window(Q)=" << args.window << " rounds=" << args.rounds << "\n";
        return RunBmx4cLtProfile(args, host, backend, backend_name, elig);
    }
    std::cout << "dims             : n=" << args.n << " b=" << mv4::kTileB
              << " window(Q)=" << args.window << " rounds=" << args.rounds << "\n";

    if (args.profile == "bmx4c") {
        return RunBmx4cProfile(args, host, backend, backend_name, elig);
    }

    uint32_t m_check = 0;
    if (!mv4::ValidateDims(args.n, mv4::kTileB, m_check) || !mv4::CheckCombineLimbBound(args.n)) {
        std::cerr << "error: invalid dimension n=" << args.n
                  << " (need b|n, accumulation bound, and n<=8589)\n";
        return 2;
    }

    // ---- B1 bit-exactness via the resolved backend's BATCHED dispatch ----
    // ComputeDigestsBatchedDispatched runs the device path (on a GPU host) and
    // re-verifies every result against the CPU reference; here we ALSO compare
    // its output byte-for-byte to per-nonce ComputeDigest so a silent device
    // fallback still surfaces if the device output ever diverged.
    const std::vector<CBlockHeader> b1_headers = WindowHeaders(args.n, args.window, 42);
    std::vector<uint256> ref_digests(args.window);
    std::vector<std::vector<unsigned char>> ref_payloads(args.window);
    bool ref_ok = true;
    for (uint32_t i = 0; i < args.window; ++i) {
        if (!matmul_v4::ComputeDigest(b1_headers[i], args.n, args.rounds, ref_digests[i], ref_payloads[i])) {
            ref_ok = false;
        }
    }
    matmul_v4::accel::ResetStats();
    std::vector<uint256> disp_digests;
    std::vector<std::vector<unsigned char>> disp_payloads;
    const bool disp_ok = matmul_v4::accel::ComputeDigestsBatchedDispatched(
        b1_headers, args.n, args.rounds, disp_digests, disp_payloads);
    bool bit_exact = ref_ok && disp_ok &&
                     disp_digests.size() == args.window && disp_payloads.size() == args.window;
    if (bit_exact) {
        for (uint32_t i = 0; i < args.window; ++i) {
            if (disp_digests[i] != ref_digests[i] || disp_payloads[i] != ref_payloads[i]) {
                bit_exact = false;
                break;
            }
        }
    }
    const auto stats = matmul_v4::accel::ProbeStats();

    std::cout << "\n[B1] bit-exact determinism gate\n";
    std::cout << "  resolved-backend batched digests vs CPU reference over "
              << args.window << " nonces: " << (bit_exact ? "PASS" : "FAIL") << "\n";
    if (!bit_exact) {
        std::cout << "  *** FAIL is a HARD consensus-split signal — do NOT activate this backend ***\n";
    }
    if (backend != matmul_v4::accel::Kind::CPU) {
        std::cout << "  device windows accepted(ok)/mismatch/fallback: "
                  << (stats.cuda_batch_ok + stats.metal_batch_ok + stats.hip_batch_ok) << "/"
                  << (stats.cuda_batch_mismatch + stats.metal_batch_mismatch + stats.hip_batch_mismatch) << "/"
                  << (stats.cuda_batch_fallback + stats.metal_batch_fallback + stats.hip_batch_fallback) << "\n";
    }

    // ---- B2g per-stage wall-time on stacked window shapes -----------------
    std::cout << "\n[B2g] per-stage marginal wall-time (n=" << args.n << ", stacked window Q=" << args.window << ")\n";
    const StageResult stage = MeasureStages(args.n, args.window, args.rounds, 42);
    double tensor_share_pct = 0, tensor_util_pct = -1;
    UniValue stage_json(UniValue::VOBJ);
    if (stage.valid) {
        const double comb = std::min(stage.s3_limb, stage.s3_alu);
        const bool limb_chosen = stage.s3_limb < stage.s3_alu;
        const double marginal = stage.s1b_expand + stage.s2_gemm + comb + stage.s4_digest;
        auto pct = [&](double x) { return marginal > 0 ? 100.0 * x / marginal : 0.0; };
        std::printf("  S0  template A,U,V + P=U*A (amortized) : %9.3f ms\n", stage.s0_template * 1e3);
        std::printf("  S1b per-nonce expand B      (SHA/int)  : %9.3f ms  %5.1f%%\n", stage.s1b_expand * 1e3 / args.window, pct(stage.s1b_expand));
        std::printf("  S2  per-nonce GEMM Q=B*V    (tensor)   : %9.3f ms  %5.1f%%\n", stage.s2_gemm * 1e3 / args.window, pct(stage.s2_gemm));
        std::printf("  S3  combine P*Qstack chosen=%-11s: %9.3f ms  %5.1f%%\n", limb_chosen ? "limb-tensor" : "alu-direct", comb * 1e3 / args.window, pct(comb));
        std::printf("      (limb-tensor %.3f ms vs ALU-direct %.3f ms, whole window)\n", stage.s3_limb * 1e3, stage.s3_alu * 1e3);
        std::printf("  S4  serialize + digest      (SHA/int)  : %9.3f ms  %5.1f%%\n", stage.s4_digest * 1e3 / args.window, pct(stage.s4_digest));
        std::printf("  per-nonce MARGINAL total (S0 amortized): %9.3f ms   stage-bit-exact=%s\n",
                    marginal * 1e3 / args.window, stage.stage_bit_exact ? "YES" : "NO -- STAGE DIVERGED, TIMES VOID");
    } else {
        std::cout << "  (stage measurement unavailable for this dimension)\n";
    }

    // ---- B2b sustained throughput -----------------------------------------
    bool used_device = false;
    std::string tp_note;
    const double backend_nps = MeasureBackendNoncePerSec(backend, args.n, args.window, args.rounds, used_device, tp_note);
    if (stage.valid) {
        stage_json = StageJson(stage, args.device_peak_int8_tops, backend_nps, tensor_share_pct, tensor_util_pct);
    }

    std::cout << "\n[B2b] sustained throughput (ASERT calibration input)\n";
    std::cout << "  backend marginal nonce/s : " << backend_nps
              << "  (" << tp_note << ")\n";
    std::cout << "  tensor-stage share (§K.2a-WT majority gate): ";
    if (stage.valid) std::printf("%.1f%%\n", tensor_share_pct); else std::cout << "n/a\n";
    std::cout << "  implied INT8 tensor utilization vs peak    : ";
    if (tensor_util_pct >= 0) std::printf("%.1f%% (peak %.0f TOPS)\n", tensor_util_pct, args.device_peak_int8_tops);
    else std::cout << "unknown (pass --device-peak-int8-tops to estimate)\n";

    std::string asert_suggestion = "n/a (pass --v3-hashrate)";
    if (args.v3_hashrate > 0 && backend_nps > 0) {
        // target scales by v3/v4 throughput: next_target = parent_target*Num/Den,
        // Num/Den = v3_hashes_per_s : v4_nonce_per_s (pow.cpp §I.4).
        asert_suggestion = ReducedRatio(args.v3_hashrate, backend_nps);
        std::cout << "  v3 baseline " << args.v3_hashrate << " H/s -> suggested nMatMulV4AsertRescaleNum/Den = "
                  << asert_suggestion << "  (=" << (args.v3_hashrate / backend_nps) << ")\n";
    }

    // ---- quick lane (optional) --------------------------------------------
    UniValue quick_arr(UniValue::VARR);
    if (args.quick) {
        std::cout << "\n[quick lane] fast n=256 / n=512 stage + bit-exact\n";
        for (uint32_t qn : {256u, 512u}) {
            const StageResult qr = MeasureStages(qn, std::min<uint32_t>(args.window, 16), args.rounds, 7);
            double qts = 0, qtu = -1;
            double qnps = 0; bool qdev = false; std::string qnote;
            qnps = MeasureBackendNoncePerSec(backend, qn, std::min<uint32_t>(args.window, 16), args.rounds, qdev, qnote);
            UniValue qj = StageJson(qr, args.device_peak_int8_tops, qnps, qts, qtu);
            qj.pushKV("backend_nonce_per_s", qnps);
            quick_arr.push_back(qj);
            std::printf("  n=%u  bit-exact=%s  marginal=%.3f ms  tensor-share=%.1f%%  nonce/s=%.1f\n",
                        qn, qr.stage_bit_exact ? "PASS" : "FAIL",
                        qr.window ? (qr.s1b_expand + qr.s2_gemm + std::min(qr.s3_limb, qr.s3_alu) + qr.s4_digest) * 1e3 / qr.window : 0,
                        qts, qnps);
        }
    }

    // ---- GO / NO-GO line (§K.2b) ------------------------------------------
    std::string verdict;
    if (!bit_exact) {
        verdict = "NO-GO: bit-exact determinism FAILED (consensus split)";
    } else if (!stage.valid || !stage.stage_bit_exact) {
        verdict = "NO-GO: stage outputs diverged (measurement void)";
    } else if (tensor_share_pct <= 50.0) {
        verdict = "NO-GO(this machine's stage profile): tensor-stage share is NOT a strict majority ("
                  + std::to_string(static_cast<int>(tensor_share_pct + 0.5)) + "%)";
    } else {
        verdict = "GO-CANDIDATE: bit-exact PASS and tensor-stage share is a strict majority ("
                  + std::to_string(static_cast<int>(tensor_share_pct + 0.5))
                  + "%); ordering is UNDECIDABLE on one machine — aggregate across "
                    "datacenter+consumer machines to decide the datacenter-favoring ordering (§K.2b(c))";
    }
    std::cout << "\n[GO/NO-GO §K.2b] " << verdict << "\n";

    // ---- H8: device-execution certification gate --------------------------
    // The v4.1 (ENC-S8) profile is a DEVICE-certification profile. A green PASS
    // (exit 0) may be emitted ONLY when a real device backend actually executed
    // its accelerated path AND its output was accepted bit-exact against the CPU
    // reference: backend != CPU, at least one device window ACCEPTED (not fallen
    // back), and the bit-exact gate green. A CPU-only run (backend resolves to
    // CPU on this GPU-less host) certifies NOTHING about device silicon, so it
    // must exit non-zero -- never a green PASS. Failing closed is always safe.
    const uint64_t device_windows_ok =
        stats.cuda_batch_ok + stats.metal_batch_ok + stats.hip_batch_ok;
    const bool ran_on_device = (backend != matmul_v4::accel::Kind::CPU);
    const bool device_certified = ran_on_device && bit_exact && device_windows_ok > 0;
    if (device_certified) {
        // Honest device marker (parallel to the bmx4c profile / verify-backend.sh).
        std::cout << "DEVICE_V41_BITEXACT_PASS:" << backend_name << ":" << elig.reason << "\n";
    } else {
        std::cout << "\n[CERTIFICATION] NOT-CERTIFIED: no accepted on-device tensor path executed "
                     "on this host (resolved backend=" << backend_name
                  << ", device windows accepted=" << device_windows_ok
                  << "). The bit-exact self-test " << (bit_exact ? "PASSED" : "FAILED")
                  << " on the CPU reference, but a DEVICE profile certifies only on ACTUAL device "
                     "execution; exiting non-zero (a CPU-only run of a device profile is NOT a PASS).\n";
    }

    // ---- machine-readable JSON --------------------------------------------
    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "matmul-v4-report");
    root.pushKV("schema_version", 1);
    root.pushKV("host", host);
    root.pushKV("host_cpu_arch", HostCpuArch());
    root.pushKV("backend", backend_name);
    root.pushKV("backend_used_device", used_device);
    // H8: did an ACTUAL device tensor path execute and get accepted? (Gates exit 0.)
    root.pushKV("device_execution_certified", device_certified);
    UniValue elig_obj(UniValue::VOBJ);
    elig_obj.pushKV("compiled", elig.compiled);
    elig_obj.pushKV("available", elig.available);
    elig_obj.pushKV("admissible", elig.admissible);
    elig_obj.pushKV("reason", elig.reason);
    root.pushKV("device", std::move(elig_obj));
    root.pushKV("n", static_cast<uint64_t>(args.n));
    root.pushKV("b", static_cast<uint64_t>(mv4::kTileB));
    root.pushKV("window", static_cast<uint64_t>(args.window));
    root.pushKV("rounds", static_cast<uint64_t>(args.rounds));
    // Additive schema fields (task contract for --profile bmx4c --mt24); the
    // v4.1 profile does not run M-t24, so these are neutral placeholders that
    // any consumer keyed on `profile == "bmx4c"` should ignore.
    root.pushKV("profile", args.profile);
    root.pushKV("mt24_pass", NullUniValue);
    root.pushKV("proven_accumulator_bits", static_cast<uint64_t>(0));
    root.pushKV("native_path_eligible", NullUniValue);
    root.pushKV("bit_exact", bit_exact);
    root.pushKV("stages", stage_json);
    root.pushKV("backend_nonce_per_s", backend_nps);
    root.pushKV("backend_throughput_note", tp_note);
    root.pushKV("tensor_share_pct", stage.valid ? tensor_share_pct : 0);
    if (tensor_util_pct >= 0) root.pushKV("tensor_util_pct", tensor_util_pct);
    else root.pushKV("tensor_util_pct", "unknown");
    root.pushKV("device_peak_int8_tops", args.device_peak_int8_tops);
    root.pushKV("v3_hashrate", args.v3_hashrate);
    root.pushKV("asert_rescale_num_den_suggestion", asert_suggestion);
    if (args.quick) root.pushKV("quick_lane", quick_arr);
    root.pushKV("verdict", verdict);
    root.pushKV("gates", [] {
        UniValue g(UniValue::VOBJ);
        g.pushKV("B1", "bit_exact");
        g.pushKV("B2b", "backend_nonce_per_s + asert_rescale_num_den_suggestion");
        g.pushKV("B2g", "tensor_share_pct + tensor_util_pct + ordering(aggregate across machines)");
        return g;
    }());

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    ofs.close();
    std::cout << "\nJSON report written: " << args.out_path << "\n";
    std::cout << "Aggregate the JSON from datacenter + consumer + Apple machines to settle the B2g ordering.\n";

    // H8: exit 0 (green PASS = CERTIFIED) requires an ACTUAL accepted on-device
    // tensor path. bit_exact alone is a CPU-reference self-test; a CPU-only run
    // of this device profile is NOT-CERTIFIED and returns non-zero.
    return device_certified ? 0 : 1;
}
