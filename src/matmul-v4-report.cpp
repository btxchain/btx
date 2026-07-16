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

#include <matmul/accel_v4.h>
#include <matmul/backend_capabilities_v4.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_batch.h>
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
};

void PrintUsage(std::ostream& os)
{
    os << "Usage: matmul-v4-report [options]\n"
       << "  --backend <cpu|cuda|metal|hip>   force backend (sets BTX_MATMUL_V4_BACKEND)\n"
       << "  --n <dim>                        matrix dimension (default 4096; env BTX_MATMUL_V4_REPORT_N)\n"
       << "  --window <Q>                     nonce window (default 32; env BTX_MATMUL_V4_REPORT_WINDOW)\n"
       << "  --rounds <R>                     Freivalds rounds for the verify gate (default 3)\n"
       << "  --quick                          also run a fast n=256 and n=512 lane\n"
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
        else if (a == "--n") { const char* v = need(i); if (!v) return false; args.n = static_cast<uint32_t>(std::strtoul(v, nullptr, 10)); }
        else if (a == "--window") { const char* v = need(i); if (!v) return false; args.window = static_cast<uint32_t>(std::strtoul(v, nullptr, 10)); }
        else if (a == "--rounds") { const char* v = need(i); if (!v) return false; args.rounds = static_cast<uint32_t>(std::strtoul(v, nullptr, 10)); }
        else if (a == "--quick") { args.quick = true; }
        else if (a == "--device-peak-int8-tops") { const char* v = need(i); if (!v) return false; args.device_peak_int8_tops = std::strtod(v, nullptr); }
        else if (a == "--v3-hashrate") { const char* v = need(i); if (!v) return false; args.v3_hashrate = std::strtod(v, nullptr); }
        else if (a == "--out") { const char* v = need(i); if (!v) return false; args.out_path = v; }
        else { err = "unknown argument: " + a; return false; }
    }
    // Environment overrides (only when the flag was left at default).
    if (const char* e = std::getenv("BTX_MATMUL_V4_REPORT_N")) args.n = static_cast<uint32_t>(std::strtoul(e, nullptr, 10));
    if (const char* e = std::getenv("BTX_MATMUL_V4_REPORT_WINDOW")) args.window = static_cast<uint32_t>(std::strtoul(e, nullptr, 10));
    if (args.window == 0) args.window = 1;
    if (args.rounds == 0) args.rounds = 1;
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

    std::cout << "== MatMul v4.1 hardware report (" << host << ") ==\n";
    std::cout << "resolved backend : " << backend_name
              << "  [compiled=" << (elig.compiled ? "yes" : "no")
              << " available=" << (elig.available ? "yes" : "no")
              << " admissible=" << (elig.admissible ? "yes" : "no") << "]\n";
    std::cout << "device identity  : " << elig.reason << "\n";
    std::cout << "host cpu arch    : " << HostCpuArch() << "\n";
    std::cout << "dims             : n=" << args.n << " b=" << mv4::kTileB
              << " window(Q)=" << args.window << " rounds=" << args.rounds << "\n";

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

    // ---- machine-readable JSON --------------------------------------------
    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "matmul-v4-report");
    root.pushKV("schema_version", 1);
    root.pushKV("host", host);
    root.pushKV("host_cpu_arch", HostCpuArch());
    root.pushKV("backend", backend_name);
    root.pushKV("backend_used_device", used_device);
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

    return bit_exact ? 0 : 1;
}
