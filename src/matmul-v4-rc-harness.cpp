// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// matmul-v4-rc-harness — real CPU measurement path for ENC_RC (Resident Curriculum).
//
// Runs RecomputeResidentCurriculumReference / MineRCEpisode on toy (default) or
// refused consensus dims, emits machine-readable JSON for contrib/matmul-v4/rc-gate.py.
// Never raises nMatMulRCHeight. stub:false — timings and digests are from real runs.
//
// Usage:
//   matmul-v4-rc-harness --toy --episodes 3 --backend cpu --out rc-report.json
//   matmul-v4-rc-harness --help

#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_scale_axes.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_coupled_netcost.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <matmul/matmul_v4_rc_transcript.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/translation.h>

#include <univalue.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#include <unistd.h>
#endif

// Standalone util: no GUI translation table.
const TranslateFn G_TRANSLATION_FUN{nullptr};

// Match matmul-v4-report: some SHA helpers expect this process-local label.
std::string g_sha256_implementation{"uninitialized"};

namespace rc = matmul::v4::rc;

namespace {

struct Args {
    bool toy{true};
    bool medium{false};
    bool production{false};
    bool base_production{false};
    bool help{false};
    bool coupled{false};
    bool coupled_medium{false};
    bool coupled_production{false};      // V2 production (alias of --coupled-production-v2)
    bool coupled_production_v2{false};   // explicit V2 production label
    bool coupled_v3_ci{false};           // MediumV3 CI shape
    bool mode_sweep{false};
    bool mem_cap_sweep{false};
    bool prove_winner_gkr{false};
    uint32_t rounds{0};   // 0 ⇒ keep params.rounds
    uint32_t episodes{3}; // default for toy
    uint32_t output_row_tile{256};
    uint64_t mem_cap{0};  // 0 = unlimited
    std::string backend{"cpu"};
    std::string out_path{"rc-report.json"};
    std::string source_revision; // optional tip provenance
};

void PrintUsage(std::ostream& os)
{
    os << "Usage: matmul-v4-rc-harness [options]\n"
       << "  --toy / --no-toy           tiny dims (default: --toy; CI-safe)\n"
       << "  --medium                   medium dims (wgrad >2^24); implies not toy\n"
       << "  --production               historical PR95 Profile-2 datacenter episode; off-CI\n"
       << "  --base-production          MatMul v4.7 Epoch-A Profile-1 episode; off-CI\n"
       << "  --coupled                  Stage C coupled-puzzle timing (toy dims)\n"
       << "  --coupled-medium           Stage C coupled-puzzle timing (medium dims)\n"
       << "  --coupled-production       Stage C V2 production HBM dims (off-CI; alias of --coupled-production-v2)\n"
       << "  --coupled-production-v2    Stage C V2 production dims (MakeProductionRCCoupParams)\n"
       << "  --coupled-v3-ci            Stage C V3 CI dims (MakeMediumV3RCCoupParams)\n"
       << "  --mem-cap-sweep            production coupled under 512MiB/2GiB/8GiB caps\n"
       << "  --mode-sweep               also time Resident/Checkpointed/Streamed\n"
       << "  --prove-winner-gkr         Stage E winner-only: mine + reseal + ProveWinner* + verify\n"
       << "                             (refuses --coupled-production* / --production)\n"
       << "  --rounds N                 override episode rounds (default: params)\n"
       << "  --episodes N               ExtractMX self-qual episode count (default: 3)\n"
       << "  --row-tile N               device FFN output-row tile (default: 256)\n"
       << "  --backend NAME             cpu|cuda|hip|metal|auto (default: cpu).\n"
       << "                             Non-CPU requires a self-qualified RC device lane;\n"
       << "                             any missing/declined contraction fails the run.\n"
       << "                             Toy/medium digests are resealed against CPU once.\n"
       << "  --mem-cap BYTES            soft RSS/peak budget; auto-Streamed if over (0=off)\n"
       << "  --source-revision TIP      same-tip provenance for rc-gate\n"
       << "  --out PATH                 JSON output (default: rc-report.json)\n"
       << "  -h, --help                 this help\n";
}

size_t PeakRssKiB()
{
#if defined(__linux__)
    struct rusage ru {};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return static_cast<size_t>(ru.ru_maxrss); // KiB on Linux
    }
#elif defined(__APPLE__)
    struct rusage ru {};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return static_cast<size_t>(ru.ru_maxrss / 1024); // bytes → KiB
    }
#endif
    return 0;
}

double CoeffVar(const std::vector<double>& xs)
{
    if (xs.size() < 2) return 0.0;
    double sum = 0.0;
    for (double x : xs) sum += x;
    const double mean = sum / static_cast<double>(xs.size());
    if (!(mean > 0.0)) return 0.0;
    double acc = 0.0;
    for (double x : xs) {
        const double d = x - mean;
        acc += d * d;
    }
    const double var = acc / static_cast<double>(xs.size() - 1);
    return std::sqrt(var) / mean;
}

double NearestRankPercentile(std::vector<double> xs, double percentile)
{
    if (xs.empty() || !(percentile > 0.0) || percentile > 1.0) return 0.0;
    std::sort(xs.begin(), xs.end());
    const size_t rank = static_cast<size_t>(
        std::ceil(percentile * static_cast<double>(xs.size())));
    return xs[std::max<size_t>(1, rank) - 1];
}

bool ParseUint32(const char* v, uint32_t& out)
{
    if (!v || !*v) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long x = std::strtoull(v, &end, 10);
    if (errno || end == v || *end || x == 0 || x > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = static_cast<uint32_t>(x);
    return true;
}

bool ParseUint64AllowZero(const char* v, uint64_t& out)
{
    if (!v || !*v) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long x = std::strtoull(v, &end, 10);
    if (errno || end == v || *end || x > std::numeric_limits<uint64_t>::max()) {
        return false;
    }
    out = static_cast<uint64_t>(x);
    return true;
}

bool ParseArgs(int argc, char** argv, Args& args, std::string& err)
{
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                err = std::string("missing value for ") + name;
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") {
            args.help = true;
        } else if (a == "--toy") {
            args.toy = true;
            args.medium = false;
        } else if (a == "--no-toy") {
            args.toy = false;
        } else if (a == "--medium") {
            args.medium = true;
            args.toy = false;
            args.production = false;
            args.base_production = false;
        } else if (a == "--production") {
            args.production = true;
            args.base_production = false;
            args.toy = false;
            args.medium = false;
        } else if (a == "--base-production") {
            args.production = true;
            args.base_production = true;
            args.toy = false;
            args.medium = false;
        } else if (a == "--coupled") {
            args.coupled = true;
        } else if (a == "--coupled-medium") {
            args.coupled = true;
            args.coupled_medium = true;
            args.coupled_production = false;
            args.coupled_production_v2 = false;
            args.coupled_v3_ci = false;
        } else if (a == "--coupled-production" || a == "--coupled-production-v2") {
            args.coupled = true;
            args.coupled_production = true;
            args.coupled_production_v2 = true;
            args.coupled_medium = false;
            args.coupled_v3_ci = false;
        } else if (a == "--coupled-v3-ci") {
            args.coupled = true;
            args.coupled_v3_ci = true;
            args.coupled_production = false;
            args.coupled_production_v2 = false;
            args.coupled_medium = false;
        } else if (a == "--mem-cap-sweep") {
            args.mem_cap_sweep = true;
            args.coupled = true;
            args.coupled_production = true;
            args.coupled_production_v2 = true;
        } else if (a == "--mode-sweep") {
            args.mode_sweep = true;
        } else if (a == "--prove-winner-gkr") {
            args.prove_winner_gkr = true;
        } else if (a == "--rounds") {
            const char* v = need("--rounds");
            if (!v || !ParseUint32(v, args.rounds)) {
                err = "invalid --rounds";
                return false;
            }
        } else if (a == "--episodes") {
            const char* v = need("--episodes");
            if (!v || !ParseUint32(v, args.episodes)) {
                err = "invalid --episodes";
                return false;
            }
        } else if (a == "--row-tile") {
            const char* v = need("--row-tile");
            if (!v || !ParseUint32(v, args.output_row_tile)) {
                err = "invalid --row-tile";
                return false;
            }
        } else if (a == "--backend") {
            const char* v = need("--backend");
            if (!v) return false;
            args.backend = v;
        } else if (a == "--mem-cap") {
            const char* v = need("--mem-cap");
            if (!v || !ParseUint64AllowZero(v, args.mem_cap)) {
                err = "invalid --mem-cap";
                return false;
            }
        } else if (a == "--source-revision") {
            const char* v = need("--source-revision");
            if (!v) return false;
            args.source_revision = v;
        } else if (a == "--out") {
            const char* v = need("--out");
            if (!v) return false;
            args.out_path = v;
        } else {
            err = "unknown argument: " + a;
            return false;
        }
    }
    return true;
}

std::string HostName()
{
#if defined(__unix__) || defined(__APPLE__)
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) {
        buf[sizeof(buf) - 1] = '\0';
        return buf;
    }
#endif
    return "unknown";
}

size_t CurrentRssKiB()
{
#if defined(__linux__)
    std::ifstream in("/proc/self/status");
    std::string key;
    while (in >> key) {
        if (key == "VmRSS:") {
            size_t kib = 0;
            in >> kib;
            return kib;
        }
        std::string rest;
        std::getline(in, rest);
    }
#endif
#if defined(__unix__) || defined(__APPLE__)
    struct rusage ru {};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
#if defined(__APPLE__)
        return static_cast<size_t>(ru.ru_maxrss / 1024);
#else
        return static_cast<size_t>(ru.ru_maxrss); // KiB on Linux
#endif
    }
#endif
    return 0;
}

CBlockHeader MakeHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

UniValue CoupParamsJson(const rc::RCCoupParams& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("barriers", static_cast<uint64_t>(p.barriers));
    o.pushKV("lobes", static_cast<uint64_t>(p.lobes));
    o.pushKV("lobe_width", static_cast<uint64_t>(p.lobe_width));
    o.pushKV("bank_pages", static_cast<uint64_t>(p.bank_pages));
    o.pushKV("rows_per_lobe", static_cast<uint64_t>(p.rows_per_lobe));
    o.pushKV("pages_per_barrier_lobe", static_cast<uint64_t>(p.pages_per_barrier_lobe));
    o.pushKV("state_bytes", static_cast<uint64_t>(p.StateBytes()));
    return o;
}

/** Resolve coupled harness shape (F8 labels). */
rc::RCCoupParams SelectCoupledHarnessParams(const Args& args)
{
    if (args.coupled_v3_ci) return rc::MakeMediumV3RCCoupParams();
    if (args.coupled_production || args.coupled_production_v2) {
        return rc::MakeProductionRCCoupParams();
    }
    if (args.coupled_medium) return rc::MakeMediumRCCoupParams();
    return rc::MakeToyRCCoupParams();
}

const char* CoupledShapeLabel(const Args& args)
{
    if (args.coupled_v3_ci) return "v3-ci";
    if (args.coupled_production || args.coupled_production_v2) return "production-v2";
    if (args.coupled_medium) return "medium";
    return "toy";
}

const char* CoupModeName(rc::RCCoupExecMode m)
{
    switch (m) {
    case rc::RCCoupExecMode::SequentialLobes: return "SequentialLobes";
    case rc::RCCoupExecMode::Checkpointed: return "Checkpointed";
    case rc::RCCoupExecMode::Streamed: return "Streamed";
    case rc::RCCoupExecMode::Resident: return "Resident";
    }
    return "unknown";
}


/** Drive dispatch from --backend; hard-error if env conflicts (no silent mislabel). */
bool ApplyBackendDispatch(const std::string& backend, std::string& err)
{
    const char* env = std::getenv("BTX_MATMUL_V4_BACKEND");
    const std::string env_s = (env != nullptr) ? std::string(env) : std::string{};
    auto conflict = [&](const std::string& want) {
        if (!env_s.empty() && env_s != want && env_s != "auto") {
            err = "conflict: --backend " + backend + " vs BTX_MATMUL_V4_BACKEND=" + env_s +
                  " (set them equal, or unset the env)";
            return true;
        }
        return false;
    };
    if (backend == "cpu") {
        if (conflict("cpu")) return false;
        setenv("BTX_MATMUL_V4_BACKEND", "cpu", 1);
        return true;
    }
    if (backend == "auto") {
        // Leave env untouched; ResolveBackend picks default/cert registry.
        return true;
    }
    if (backend == "cuda" || backend == "hip" || backend == "metal" || backend == "ascend") {
        if (conflict(backend)) return false;
        setenv("BTX_MATMUL_V4_BACKEND", backend.c_str(), 1);
        return true;
    }
    err = "unknown --backend " + backend + " (want cpu|cuda|hip|metal|ascend|auto)";
    return false;
}

int RunCoupledHarness(const Args& args)
{
    std::string be_err;
    if (!ApplyBackendDispatch(args.backend, be_err)) {
        std::cerr << "error: " << be_err << "\n";
        return 2;
    }

    const rc::RCCoupParams params = SelectCoupledHarnessParams(args);
    if (!rc::ValidateRCCoupParams(params)) {
        std::cerr << "error: invalid coupled params\n";
        return 2;
    }

    const uint64_t streamed_peak = rc::EstimateRCCoupStreamedPeakBytes(params);
    const uint64_t resident_peak = rc::EstimateRCCoupResidentPeakBytes(params);
    // Soft mem-cap: TILE to Streamed when resident estimate exceeds cap (never OOM-reject).
    const bool force_streamed =
        args.mem_cap != 0 && resident_peak > args.mem_cap;
    if (force_streamed && streamed_peak > args.mem_cap) {
        std::cerr << "error: streamed peak " << streamed_peak << " still exceeds --mem-cap "
                  << args.mem_cap << "\n";
        return 1;
    }

    // Mining ExactGemm: MakeResolvedExactGemmBackendForRC → CUDA/HIP/Metal
    // LaunchGemmS8S8 after RC self-qual; empty → CPU fail-closed.
    matmul::v4::lt::ExactGemmBackend gemm{};
    std::string backend_resolved = "cpu";
    if (args.backend != "cpu") {
        gemm = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
        if (gemm.gemm_s8s8 != nullptr) {
            backend_resolved = args.backend;
        } else {
            backend_resolved = "cpu-fallback";
        }
    }
    const auto device_probe = rc::ProbeRCCoupledDevice();

    const std::string host = HostName();
    const std::string device_id = backend_resolved + "-ref:" + host;
    const auto header = MakeHeader(42);
    const size_t rss_before = CurrentRssKiB();

    std::vector<rc::RCCoupExecMode> modes;
    // Resident (48 GiB device-resident, the datacenter-advantage path) is DEFAULT-ON:
    // production runs BOTH Streamed and Resident so the resident-vs-streamed ratio is
    // always measured, never hidden behind an opt-in. The only escape hatch is a
    // kill switch (BTX_RC_COUP_FORCE_STREAMED=1) for a card that physically cannot
    // hold the resident set; --mem-cap also forces streamed when the estimate exceeds
    // the cap (physical constraint, not a feature gate).
    const bool force_streamed_env =
        std::getenv("BTX_RC_COUP_FORCE_STREAMED") != nullptr;
    const bool production_v2 = args.coupled_production || args.coupled_production_v2;
    if (force_streamed || force_streamed_env) {
        modes.push_back(rc::RCCoupExecMode::Streamed);
    } else if (production_v2) {
        // Default: measure the resident path against streamed on every production run.
        modes = {rc::RCCoupExecMode::Streamed, rc::RCCoupExecMode::Resident};
    } else {
        modes = {rc::RCCoupExecMode::SequentialLobes, rc::RCCoupExecMode::Checkpointed,
                 rc::RCCoupExecMode::Streamed, rc::RCCoupExecMode::Resident};
    }

    UniValue mode_walls(UniValue::VARR);
    uint256 digest_ref;
    bool digests_match = true;
    bool mine_matches = true;
    rc::RCCoupTiming timed_mine{};
    rc::RCCoupTiming timed_ref{};

    for (size_t i = 0; i < modes.size(); ++i) {
        rc::RCCoupOptions opt;
        opt.mode = modes[i];
        // F9: CPU-oracle phases are correctness_reference only — never GPU throughput.
        rc::RCCoupTiming t_ref{};
        const uint256 d =
            rc::RecomputeCoupledPuzzleReference(header, /*height=*/0, params, opt, {}, &t_ref);
        // F9: wall_s / total_s / nonce_per_s / phase_wall_s time MineCoupledPuzzle.
        rc::RCCoupTiming t_mine{};
        const uint256 d_mine =
            rc::MineCoupledPuzzle(header, /*height=*/0, params, gemm, opt, &t_mine);
        if (d != d_mine) mine_matches = false;
        if (i == 0) {
            digest_ref = d;
            timed_mine = t_mine;
            timed_ref = t_ref;
        } else if (d != digest_ref) {
            digests_match = false;
        }
        UniValue ref_walls(UniValue::VOBJ);
        ref_walls.pushKV("bank", t_ref.bank_s);
        ref_walls.pushKV("barriers", t_ref.barriers_s);
        ref_walls.pushKV("total", t_ref.total_s);
        ref_walls.pushKV("label", "correctness_reference");
        ref_walls.pushKV("provenance", "cpu_exactgemm_oracle");

        UniValue mw(UniValue::VOBJ);
        mw.pushKV("mode", CoupModeName(modes[i]));
        mw.pushKV("digest", d.GetHex());
        mw.pushKV("mine_matches_cpu", d == d_mine);
        mw.pushKV("bank_s", t_mine.bank_s);
        mw.pushKV("barriers_s", t_mine.barriers_s);
        mw.pushKV("wall_s", t_mine.total_s);
        mw.pushKV("total_s", t_mine.total_s);
        mw.pushKV("nonce_per_s", t_mine.total_s > 0.0 ? (1.0 / t_mine.total_s) : 0.0);
        mw.pushKV("phase_wall_s", t_mine.total_s);
        mw.pushKV("reference_wall_s", ref_walls);
        mw.pushKV("peak_rss_kib", static_cast<uint64_t>(std::max(rss_before, CurrentRssKiB())));
        mode_walls.push_back(mw);
    }

    const size_t rss_after = CurrentRssKiB();
    const size_t peak_rss = std::max({rss_before, rss_after, PeakRssKiB()});

    // Streamed vs Resident ratio (expect ≥1 when paging costs).
    double wall_stream = 0.0, wall_resident = 0.0;
    for (size_t i = 0; i < mode_walls.size(); ++i) {
        const UniValue& mw = mode_walls[i];
        const std::string m = mw["mode"].get_str();
        if (m == "Streamed") wall_stream = mw["wall_s"].get_real();
        if (m == "Resident") wall_resident = mw["wall_s"].get_real();
    }

    const char* shape = CoupledShapeLabel(args);
    std::cout << "== MatMul ENC_RC coupled harness (Stage C) ==\n";
    std::cout << "  device_id:  " << device_id << "\n";
    std::cout << "  backend:    " << args.backend << " → " << backend_resolved << "\n";

    // LOUD native-path status: never let a deactivated FP4/native tensor path hide
    // behind quiet INT8 numbers. Surface exactly what the runtime selected and, when
    // a native path is BUILT but not qualified, why it fell back — so "deactivated"
    // is impossible to miss in the fleet JSON and console. This does NOT gate mining;
    // it only reports the state the byte-exact self-qual already decided.
    const matmul::v4::rc::RCOzakiMxfp4Status mxfp4 =
        matmul::v4::rc::ProbeRcOzakiMxfp4Status();
    const bool native_requested = (args.backend != "cpu");
    const bool native_declined =
        native_requested && (mxfp4.attempted || mxfp4.sm120a_kernel_linked) && !mxfp4.qualified;
    std::cout << "  native_fp4: linked_sm120a=" << (mxfp4.sm120a_kernel_linked ? 1 : 0)
              << " attempted=" << (mxfp4.attempted ? 1 : 0)
              << " qualified=" << (mxfp4.qualified ? 1 : 0)
              << " selected=" << (mxfp4.backend.empty() ? "none" : mxfp4.backend)
              << " arch=" << (mxfp4.arch_key.empty() ? "?" : mxfp4.arch_key) << "\n";
    if (native_declined) {
        std::cerr << "!! NATIVE MXFP4 PATH DEACTIVATED — mining the INT8 fallback, NOT the "
                     "native tensor path.\n"
                     "!! reason: "
                  << (mxfp4.deficit_reason.empty() ? "unspecified" : mxfp4.deficit_reason)
                  << "\n!! This is a build/silicon gap to FIX (default-on native was refused "
                     "by the byte-exact self-qual), not a supported steady state.\n";
    } else if (native_requested && !mxfp4.qualified && !mxfp4.sm120a_kernel_linked &&
               !mxfp4.attempted) {
        std::cerr << "!! NATIVE MXFP4 NOT BUILT INTO THIS BINARY — no sm_120a/sm_100 object "
                     "linked; mining INT8. Rebuild with the native CUDA path to exercise FP4.\n";
    }
    std::cout << "  shape:      " << shape << "\n";
    std::cout << "  peak_est:   streamed=" << streamed_peak << " resident=" << resident_peak
              << (force_streamed ? " (auto-Streamed by --mem-cap)" : "") << "\n";
    std::cout << "  barriers:   " << params.barriers << " lobes=" << params.lobes
              << " width=" << params.lobe_width << " pages=" << params.bank_pages
              << " rows_per_lobe=" << params.rows_per_lobe
              << " pages_per_barrier_lobe=" << params.pages_per_barrier_lobe << "\n";
    std::cout << "  digest:     " << digest_ref.GetHex() << "\n";
    std::cout << "  modes_ok:   " << (digests_match ? "true" : "false") << "\n";
    std::cout << "  mine_ok:    " << (mine_matches ? "true" : "false") << "\n";
    std::cout << "  device_probe: resolved=" << (device_probe.backend_resolved ? 1 : 0)
              << " provider=" << device_probe.provider << " detail=" << device_probe.detail
              << "\n";
    std::cout << "  phase_wall: bank=" << timed_mine.bank_s << "s barriers="
              << timed_mine.barriers_s << "s total=" << timed_mine.total_s << "s (mine)\n";
    std::cout << "  reference_wall: bank=" << timed_ref.bank_s << "s barriers="
              << timed_ref.barriers_s << "s total=" << timed_ref.total_s
              << "s (correctness_reference)\n";
    std::cout << "  rss_kib:    before=" << rss_before << " after=" << rss_after
              << " peak=" << peak_rss << "\n";
    if (wall_resident > 0.0) {
        std::cout << "  stream/res: " << (wall_stream / wall_resident) << "\n";
    }

    UniValue walls(UniValue::VOBJ);
    walls.pushKV("bank", timed_mine.bank_s);
    walls.pushKV("barriers", timed_mine.barriers_s);
    walls.pushKV("total", timed_mine.total_s);
    walls.pushKV("provenance", "chrono_steady_clock_mine_coupled_puzzle");
    walls.pushKV("evidence_kind",
                 args.coupled_v3_ci           ? "v3_ci_chrono_measured"
                 : production_v2             ? "production_chrono_measured"
                 : args.coupled_medium       ? "chrono_measured"
                                               : "toy_chrono_measured");

    UniValue ref_walls_root(UniValue::VOBJ);
    ref_walls_root.pushKV("bank", timed_ref.bank_s);
    ref_walls_root.pushKV("barriers", timed_ref.barriers_s);
    ref_walls_root.pushKV("total", timed_ref.total_s);
    ref_walls_root.pushKV("label", "correctness_reference");
    ref_walls_root.pushKV("provenance", "cpu_exactgemm_oracle");

    UniValue rss(UniValue::VOBJ);
    rss.pushKV("before_kib", static_cast<uint64_t>(rss_before));
    rss.pushKV("after_kib", static_cast<uint64_t>(rss_after));
    rss.pushKV("peak_kib", static_cast<uint64_t>(peak_rss));

    // Native FP4 status in the fleet JSON: a deactivated native path is now a
    // first-class, machine-readable field (native_declined=true + reason), not an
    // absence to be inferred from INT8-looking numbers.
    UniValue mxfp4_j(UniValue::VOBJ);
    mxfp4_j.pushKV("sm120a_kernel_linked", mxfp4.sm120a_kernel_linked);
    mxfp4_j.pushKV("attempted", mxfp4.attempted);
    mxfp4_j.pushKV("qualified", mxfp4.qualified);
    mxfp4_j.pushKV("exact_panels_qualified", mxfp4.exact_panels_qualified);
    mxfp4_j.pushKV("selected_backend", mxfp4.backend);
    mxfp4_j.pushKV("arch_key", mxfp4.arch_key);
    mxfp4_j.pushKV("deficit_reason", mxfp4.deficit_reason);
    mxfp4_j.pushKV("native_declined", native_declined);

    UniValue probe_j(UniValue::VOBJ);
    probe_j.pushKV("backend_resolved", device_probe.backend_resolved);
    probe_j.pushKV("device_gemm_returned", device_probe.device_gemm_returned);
    probe_j.pushKV("matched_cpu_exactgemm", device_probe.matched_cpu_exactgemm);
    probe_j.pushKV("provider", device_probe.provider);
    probe_j.pushKV("detail", device_probe.detail);

    // SIMULATED interconnect model — NOT Stage-I gate 4 evidence.
    const auto net = rc::SimulateCoupledExchangeNetCost(
        rc::RCCoupNetCostParams{/*fabric_us=*/5.0, /*pcie_us=*/80.0,
                                /*barriers=*/params.barriers});
    UniValue netj(UniValue::VOBJ);
    netj.pushKV("simulated", true);
    netj.pushKV("stage_i_gate4_evidence", false);
    netj.pushKV("label", net.label);
    netj.pushKV("fabric_us_per_barrier", 5.0);
    netj.pushKV("pcie_us_per_barrier", 80.0);
    netj.pushKV("barriers", static_cast<uint64_t>(params.barriers));
    netj.pushKV("fabric_exchange_us", net.fabric_exchange_us);
    netj.pushKV("pcie_exchange_us", net.pcie_exchange_us);
    netj.pushKV("exchange_slowdown_factor", net.exchange_slowdown_factor);
    netj.pushKV("stage_i_gate4_threshold", rc::kStageIGate4NvlinkVsPcieMin);
    netj.pushKV("stage_i_gate4_pass", false);

    UniValue qual(UniValue::VOBJ);
    qual.pushKV("status", (digests_match && mine_matches) ? "pass" : "fail");
    qual.pushKV("episodes", static_cast<uint64_t>(std::max<uint32_t>(1, args.episodes)));
    qual.pushKV("digests_stable", digests_match);
    qual.pushKV("mine_matches_cpu", mine_matches);

    UniValue caps(UniValue::VOBJ);
    caps.pushKV("512MiB", "skip");
    caps.pushKV("2GiB", "skip");
    caps.pushKV("8GiB", "skip");

    UniValue residency(UniValue::VARR);
    {
        UniValue pt(UniValue::VOBJ);
        pt.pushKV("working_set_bytes", static_cast<uint64_t>(params.StateBytes()));
        pt.pushKV("wall_s", timed_mine.total_s);
        pt.pushKV("dims", shape);
        residency.push_back(pt);
    }

    UniValue k_curve(UniValue::VOBJ);
    k_curve.pushKV("mode", "toy_synthetic_structure");
    k_curve.pushKV("digests_match", digests_match);
    k_curve.pushKV("note", "Coupled campaign placeholder k_curve for rc-gate schema");

    UniValue vf(UniValue::VOBJ);
    vf.pushKV("measured", false);
    vf.pushKV("binding", true);
    vf.pushKV("evidence_kind", "unmeasured");

    UniValue run_variance(UniValue::VOBJ);
    run_variance.pushKV("episode_cv", 0.0);
    run_variance.pushKV("n_runs", 1);
    run_variance.pushKV("note", "Cross-process variance filled by rc-stage-g-campaign.py");

    UniValue coupled(UniValue::VOBJ);
    coupled.pushKV("shape", shape);
    coupled.pushKV("streamed_peak_bytes_est", streamed_peak);
    coupled.pushKV("resident_peak_bytes_est", resident_peak);
    coupled.pushKV("mem_cap_bytes", args.mem_cap);
    coupled.pushKV("auto_streamed", force_streamed || force_streamed_env);
    coupled.pushKV("stream_vs_resident_wall_ratio",
                   wall_resident > 0.0 ? (wall_stream / wall_resident) : 0.0);
    coupled.pushKV("modes", mode_walls);
    coupled.pushKV("digests_match", digests_match);
    coupled.pushKV("modes_available", "Sequential,Checkpointed,Streamed,Resident");
    if (wall_resident > 0.0) {
        coupled.pushKV("streamed_over_resident", wall_stream / wall_resident);
    }
    coupled.pushKV("interconnect_sim", netj);

    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "rc-episode-harness");
    root.pushKV("schema_version", 2);
    root.pushKV("stub", false);
    root.pushKV("device_id", device_id);
    root.pushKV("backend", backend_resolved);
    root.pushKV("backend_requested", args.backend);
    root.pushKV("exact_gemm_inject", gemm.gemm_s8s8 != nullptr);
    root.pushKV("profile", "coupled");
    root.pushKV("toy", !args.coupled_medium && !production_v2 && !args.coupled_v3_ci);
    root.pushKV("medium", args.coupled_medium);
    root.pushKV("production_dims", production_v2);
    root.pushKV("coupled_production_v2", production_v2);
    root.pushKV("coupled_v3_ci", args.coupled_v3_ci);
    root.pushKV("streamed_peak_bytes_est", streamed_peak);
    root.pushKV("resident_peak_bytes_est", resident_peak);
    root.pushKV("mem_cap_bytes", args.mem_cap);
    root.pushKV("evidence_kind",
                args.coupled_v3_ci     ? "v3_ci_chrono_measured"
                : production_v2       ? "production_chrono_measured"
                : args.coupled_medium ? "chrono_measured"
                                      : "toy_chrono_measured");
    root.pushKV("wall_clock_provenance", "chrono_steady_clock_mine_coupled_puzzle");
    root.pushKV("device_resident", false);
    root.pushKV("native_path_eligible", mxfp4.qualified);
    root.pushKV("params", CoupParamsJson(params));
    root.pushKV("digest", digest_ref.GetHex());
    root.pushKV("modes_digest_match", digests_match);
    root.pushKV("mine_matches_cpu", mine_matches);
    root.pushKV("mode_walls", mode_walls);
    root.pushKV("coupled", coupled);
    root.pushKV("extractmx_self_qual", qual);
    root.pushKV("phase_wall_s", walls);
    root.pushKV("reference_wall_s", ref_walls_root);
    root.pushKV("peak_rss_kib", static_cast<uint64_t>(peak_rss));
    root.pushKV("rss_kib", rss);
    root.pushKV("run_variance", run_variance);
    root.pushKV("residency_sweep", residency);
    root.pushKV("k_curve", k_curve);
    root.pushKV("allocation_cap_verdicts", caps);
    root.pushKV("verifier_floor", vf);
    root.pushKV("device_probe", probe_j);
    root.pushKV("native_mxfp4", mxfp4_j);
    root.pushKV("interconnect_sim", netj);
    root.pushKV("gpu_campaign_present", false);
    root.pushKV("nvlink_campaign_present", false);
    root.pushKV("gpu_status", "SILICON-GATED");
    root.pushKV("consensus_note",
                "nMatMulRCCoupledHeight remains INT32_MAX on public nets; coupled "
                "profile (ENC_RC_COUPLED) is INERT unless regtest sets a finite height. "
                "Mining inject uses MakeResolvedExactGemmBackendForRC when active. "
                "SIMULATED interconnect is NOT Stage-I gate 4 evidence. "
                "phase_wall_s times MineCoupledPuzzle; reference_wall_s is "
                "correctness_reference (CPU ExactGemm oracle) — not GPU throughput. "
                "This harness never raises height.");
    std::string tip = args.source_revision;
    if (tip.empty()) {
        if (const char* env = std::getenv("BTX_SOURCE_REVISION")) tip = env;
    }
    if (!tip.empty()) {
        root.pushKV("source_revision", tip);
        root.pushKV("git_tip", tip);
    }

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    ofs.close();

    std::cout << "  sim_factor: " << net.exchange_slowdown_factor
              << " (SIMULATED / NOT Stage-I gate 4 evidence)\n";
    std::cout << "  wrote:      " << args.out_path << "\n";
    std::cout << "  consensus:  nMatMulRCHeight=INT32_MAX (NO-GO activation)\n";
    const bool ok = digests_match && mine_matches;
    std::cout << (ok ? "RESULT: coupled modes PASS\n" : "RESULT: coupled modes FAIL\n");
    return ok ? 0 : 1;
}

/** Conservative working-set byte estimate for int8 tensors held simultaneously. */
uint64_t EstimateWorkingSetBytes(const rc::RCEpisodeParams& p)
{
    const uint64_t dh = p.d_head;
    const uint64_t nq = p.n_q;
    const uint64_t nctx = p.n_ctx;
    const uint64_t dm = p.d_model;
    const uint64_t bs = p.b_seq;
    const uint64_t L = p.L_lyr;
    // Phase 1 peak: Q + K + V + Z
    const uint64_t p1 = nq * dh + 2 * nctx * dh + nq * dh;
    // Phase 2 peak (StoreAll): all W + all X + all G + all D
    const uint64_t W = L * dm * dm;
    const uint64_t X = (L + 1) * bs * dm;
    const uint64_t G = (L + 1) * bs * dm;
    const uint64_t D = L * dm * dm;
    const uint64_t p2 = W + X + G + D;
    return p1 > p2 ? p1 : p2;
}

UniValue ParamsJson(const rc::RCEpisodeParams& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("rounds", static_cast<uint64_t>(p.rounds));
    o.pushKV("d_head", static_cast<uint64_t>(p.d_head));
    o.pushKV("n_q", static_cast<uint64_t>(p.n_q));
    o.pushKV("n_ctx", static_cast<uint64_t>(p.n_ctx));
    o.pushKV("L_lyr", static_cast<uint64_t>(p.L_lyr));
    o.pushKV("d_model", static_cast<uint64_t>(p.d_model));
    o.pushKV("b_seq", static_cast<uint64_t>(p.b_seq));
    o.pushKV("T_leaf", static_cast<uint64_t>(p.T_leaf));
    return o;
}

int RunProveWinnerGkrHarness(const Args& args)
{
    // F8: production dims + GKR proof evidence is refused (clear message).
    if (args.production || args.coupled_production || args.coupled_production_v2) {
        std::cerr
            << "error: --prove-winner-gkr cannot be combined with production dims "
               "(--production / --coupled-production / --coupled-production-v2). "
               "Use --coupled / --coupled-medium / --coupled-v3-ci for GKR evidence; "
               "production shapes stay ExactReplay-only.\n";
        return 2;
    }

    // Easy target so a winner appears quickly; losers still skip Prove*.
    arith_uint256 easy;
    easy.SetCompact(0x207fffff); // matches harness header nBits (regtest-easy)

    CBlockHeader header = MakeHeader(0);
    rc::WinnerGkrSolveReport rep;
    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "rc-prove-winner-gkr");
    root.pushKV("stub", false);
    root.pushKV("e5_direction", "DECIDED");
    root.pushKV("e5_path", "winner_only_gkr_sumcheck");
    root.pushKV("soundness", "computational_not_eps0");
    root.pushKV("consensus_note", "nMatMulRCHeight remains INT32_MAX");

    if (args.coupled) {
        const rc::RCCoupParams params = args.coupled_v3_ci ? rc::MakeMediumV3RCCoupParams()
                                      : args.coupled_medium  ? rc::MakeMediumRCCoupParams()
                                                             : rc::MakeToyRCCoupParams();
        if (!rc::ValidateRCCoupParams(params)) {
            std::cerr << "error: invalid coupled params for --prove-winner-gkr\n";
            return 2;
        }
        rep = rc::SolveCoupledProveWinner(header, /*height=*/0, params, easy,
                                          /*max_tries=*/64, /*do_prove=*/true);
        root.pushKV("mode", "coupled");
        root.pushKV("shape", CoupledShapeLabel(args));
    } else {
        const rc::RCEpisodeParams params =
            args.medium ? rc::MakeMediumRCEpisodeParams() : rc::MakeToyRCEpisodeParams();
        rep = rc::SolveRCEpisodeProveWinner(header, params, /*height=*/0, easy,
                                            /*max_tries=*/64, /*do_prove=*/true);
        root.pushKV("mode", "episode");
        root.pushKV("toy", args.toy);
        root.pushKV("medium", args.medium);
    }

    root.pushKV("ok", rep.ok);
    root.pushKV("proved", rep.proved);
    root.pushKV("digest", rep.digest.GetHex());
    root.pushKV("nonce", static_cast<uint64_t>(rep.nonce));
    root.pushKV("nonces_tried", static_cast<uint64_t>(rep.nonces_tried));
    root.pushKV("mine_s", rep.mine_s);
    root.pushKV("reseal_s", rep.reseal_s);
    root.pushKV("prove_s", rep.prove_s);
    root.pushKV("verify_s", rep.verify_s);
    root.pushKV("proof_bytes", static_cast<uint64_t>(rep.proof_bytes));
    root.pushKV("note", rep.note);

    std::cout << "== MatMul ENC_RC winner-only GKR (== Stage E DECIDED) ==\n";
    std::cout << "  ok:          " << (rep.ok ? "true" : "false") << "\n";
    std::cout << "  nonces:      " << rep.nonces_tried << " (losers: zero Prove*)\n";
    std::cout << "  mine_s:      " << rep.mine_s << "\n";
    std::cout << "  reseal_s:    " << rep.reseal_s << "\n";
    std::cout << "  prove_s:     " << rep.prove_s << "\n";
    std::cout << "  verify_s:    " << rep.verify_s << "\n";
    std::cout << "  proof_bytes: " << rep.proof_bytes << "\n";
    std::cout << "  note:        " << rep.note << "\n";

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    std::cout << "  wrote:       " << args.out_path << "\n";
    return rep.ok ? 0 : 1;
}

} // namespace

int main(int argc, char* argv[])
{
    // Standalone tools do not construct kernel::Context — select SHA-256 impl.
    g_sha256_implementation = SHA256AutoDetect();

    Args args;
    std::string err;
    if (!ParseArgs(argc, argv, args, err)) {
        std::cerr << "error: " << err << "\n";
        PrintUsage(std::cerr);
        return 2;
    }
    if (args.help) {
        PrintUsage(std::cout);
        return 0;
    }

    if (args.prove_winner_gkr) {
        return RunProveWinnerGkrHarness(args);
    }

    if (args.mem_cap_sweep) {
        // Production coupled under fixed soft caps via Streamed (A4).
        const uint64_t caps[] = {512ull << 20, 2ull << 30, 8ull << 30};
        int rc_all = 0;
        for (uint64_t cap : caps) {
            Args one = args;
            one.mem_cap_sweep = false;
            one.coupled = true;
            one.coupled_production = true;
            one.mem_cap = cap;
            one.out_path = args.out_path + ".cap" + std::to_string(cap);
            std::cout << "== mem-cap-sweep cap=" << cap << " out=" << one.out_path << "==\n";
            const int rc = RunCoupledHarness(one);
            if (rc != 0) rc_all = rc;
        }
        return rc_all;
    }

    if (args.coupled) {
        return RunCoupledHarness(args);
    }

    std::string be_err;
    if (!ApplyBackendDispatch(args.backend, be_err)) {
        std::cerr << "error: " << be_err << "\n";
        return 2;
    }

    if (!args.toy && !args.medium && !args.production) {
        std::cerr << "error: need --toy, --medium, or --production\n";
        return 2;
    }

    rc::RCEpisodeParams params = args.production
                                   ? (args.base_production
                                          ? rc::MakeProductionRCEpisodeParams()
                                          : rc::MakeDatacenterRCEpisodeParams())
                               : args.medium     ? rc::MakeMediumRCEpisodeParams()
                                                 : rc::MakeToyRCEpisodeParams();
    if (args.rounds > 0) params.rounds = args.rounds;
    if (!rc::ValidateRCEpisodeParams(params)) {
        std::cerr << "error: invalid RC episode params\n";
        return 2;
    }
    const bool production_shape =
        args.production && args.rounds == 0;

    // Resolve the RC-only lane with provider/reason provenance. Unlike normal
    // consensus verification, this measurement harness is strict: a requested
    // device that is absent or fails self-qualification is an error, never a
    // silently timed CPU fallback.
    matmul::v4::lt::ExactGemmBackend gemm{};
    rc::RCSelfQualStatus selfqual{};
    std::string backend_resolved = "cpu";
    std::string backend_reason = "cpu_reference";
    if (args.backend == "cpu") {
        selfqual = rc::ProbeRCSelfQual(gemm);
        selfqual.exact_gemm_backend_ok = true; // empty backend is the CPU oracle path
        selfqual.mining_accelerator_ok = false;
        selfqual.deficit_reason.clear();
    } else if (args.backend == "cuda" || args.backend == "hip" || args.backend == "metal" ||
               args.backend == "ascend" || args.backend == "auto") {
        const auto resolved = matmul_v4::accel::ResolveExactGemmBackendForRC();
        gemm = resolved.backend;
        backend_resolved = resolved.provider;
        backend_reason = resolved.reason;
        if (gemm.gemm_s8s8 != nullptr && resolved.self_qualified) {
            // ForRC already ProbeRCSelfQual'd successfully; avoid a second medium probe.
            // Report the real Ozaki native latch (A5/F12) — never hardcode false.
            selfqual.cpu_oracle_ok = true;
            selfqual.exact_gemm_backend_ok = true;
            selfqual.mining_accelerator_ok = true;
            selfqual.native_mxfp4_qualified = rc::IsRcOzakiMxfp4Qualified();
            selfqual.native_fp8_qualified = false;
            selfqual.deficit_reason.clear();
        } else {
            std::cerr << "error: requested " << args.backend
                      << " ExactReplay backend did not self-qualify: "
                      << (backend_reason.empty() ? "unspecified" : backend_reason)
                      << "\n";
            return 1;
        }
    } else {
        std::cerr << "error: unknown --backend " << args.backend
                  << " (want cpu|cuda|hip|metal|ascend|auto)\n";
        return 2;
    }

    const uint64_t footprint = EstimateWorkingSetBytes(params);
    const uint64_t streamed_ep = rc::EstimateRCStreamedPeakBytes(params);
    bool episode_streamed_tiling = false;
    if (args.mem_cap != 0 && footprint > args.mem_cap) {
        if (streamed_ep > args.mem_cap) {
            std::cerr << "error: working-set " << footprint << " and streamed peak " << streamed_ep
                      << " both exceed --mem-cap " << args.mem_cap << "\n";
            return 1;
        }
        episode_streamed_tiling = true;
        std::cout << "note: resident footprint " << footprint << " > mem-cap " << args.mem_cap
                  << "; proceeding under streamed peak estimate " << streamed_ep << "\n";
    }
    (void)episode_streamed_tiling;

    const std::string host = HostName();
    const std::string device_id = backend_resolved + ":" + host;
    const auto metal_arch = matmul_v4::metal::ProbeLtMetalArch();

    std::cout << "== MatMul ENC_RC harness (real episodes) ==\n";
    std::cout << "  device_id:  " << device_id << "\n";
    std::cout << "  backend:    " << args.backend << " → " << backend_resolved << "\n";
    std::cout << "  resolution: " << backend_reason << "\n";
    if (metal_arch.available) {
        std::cout << "  metal_hw:   " << metal_arch.device_name
                  << " identity=" << metal_arch.name_class_string
                  << " metal4_mpp_compile="
                  << (metal_arch.metal4_tensor_ops_compile_ok ? 1 : 0) << "\n";
    }

    // LOUD native-path status (same contract as the coupled harness): a deactivated
    // FP4/native tensor path must never hide behind quiet INT8 numbers in the fleet
    // report. Reports, never gates — the byte-exact self-qual already decided.
    const matmul::v4::rc::RCOzakiMxfp4Status mxfp4 =
        matmul::v4::rc::ProbeRcOzakiMxfp4Status();
    const bool native_requested = (args.backend != "cpu");
    const bool metal_exact_lane =
        backend_resolved.rfind("metal_", 0) == 0;
    const bool native_declined =
        native_requested && !metal_exact_lane &&
        (mxfp4.attempted || mxfp4.sm120a_kernel_linked) && !mxfp4.qualified;
    std::cout << "  native_fp4: linked_sm120a=" << (mxfp4.sm120a_kernel_linked ? 1 : 0)
              << " attempted=" << (mxfp4.attempted ? 1 : 0)
              << " qualified=" << (mxfp4.qualified ? 1 : 0)
              << " selected=" << (mxfp4.backend.empty() ? "none" : mxfp4.backend)
              << " arch=" << (mxfp4.arch_key.empty() ? "?" : mxfp4.arch_key) << "\n";
    if (metal_exact_lane) {
        const bool mpp_tensorops =
            backend_resolved.find("mpp_tensorops") != std::string::npos;
        std::cout << "  metal_lane: "
                  << (mpp_tensorops ? "exact Metal 4 MPP INT8 TensorOps"
                                    : "exact MSL integer ALU")
                  << "; every consensus GEMM must execute on Metal. "
                     "M5-class silicon and OCP MXFP4 are not claimed.\n";
    } else if (native_declined) {
        std::cerr << "!! NATIVE MXFP4 PATH DEACTIVATED — mining the INT8 fallback, NOT the "
                     "native tensor path.\n!! reason: "
                  << (mxfp4.deficit_reason.empty() ? "unspecified" : mxfp4.deficit_reason)
                  << "\n!! Build/silicon gap to FIX (default-on native refused by the byte-exact "
                     "self-qual), not a supported steady state.\n";
    } else if (native_requested && !metal_exact_lane &&
               !mxfp4.qualified && !mxfp4.sm120a_kernel_linked &&
               !mxfp4.attempted) {
        std::cerr << "!! NATIVE MXFP4 NOT BUILT INTO THIS BINARY — no sm_120a/sm_100 object "
                     "linked; mining INT8. Rebuild with the native CUDA path to exercise FP4.\n";
    }
    std::cout << "  dims:       toy=" << (args.toy ? "true" : "false")
              << " medium=" << (args.medium ? "true" : "false")
              << " production=" << (args.production ? "true" : "false")
              << " episode_profile="
              << (args.production ? (args.base_production ? 1 : 2) : 0)
              << " consensus_shape="
              << (production_shape ? "true" : "false")
              << "\n";
    std::cout << "  episodes:   " << args.episodes << "\n";
    std::cout << "  rounds:     " << params.rounds << "\n";
    std::cout << "  row_tile:   " << args.output_row_tile << "\n";
    std::cout << "  footprint≈  " << footprint << " bytes\n";
    std::cout << "  selfqual:   mining_accel=" << (selfqual.mining_accelerator_ok ? 1 : 0)
              << " exact_gemm=" << (selfqual.exact_gemm_backend_ok ? 1 : 0)
              << " native_mxfp4=" << (selfqual.native_mxfp4_qualified ? 1 : 0)
              << " native_fp8=" << (selfqual.native_fp8_qualified ? 1 : 0) << "\n";
    if (!selfqual.deficit_reason.empty()) {
        std::cout << "  deficit:    " << selfqual.deficit_reason << "\n";
    }

    // --- G1: ExtractMX / episode digest self-qual (CPU reseal identity) ---
    rc::RCEpisodeTiming timed{};
    bool digests_stable = true;
    const bool device_run = args.backend != "cpu";
    bool all_fully_accelerated = device_run;
    bool all_full_metal_pipeline = metal_exact_lane;
    rc::RCExactReplayAccelerationStats acceleration_totals{};
    acceleration_totals.backend = backend_resolved;
    acceleration_totals.device_backend_present = gemm.gemm_s8s8 != nullptr;
    acceleration_totals.require_device = device_run;
    double sum_p1 = 0, sum_p2 = 0, sum_p3 = 0, sum_tot = 0;
    std::vector<double> episode_walls;
    episode_walls.reserve(args.episodes);
    UniValue episode_digests(UniValue::VARR);
    const size_t rss_before = PeakRssKiB();

    for (uint32_t e = 0; e < args.episodes; ++e) {
        auto header = MakeHeader(1000 + e);
        // Production evidence must use a header that can enter the actual
        // consensus predicate. Leaving this field at CBlockHeader's zero
        // default produces a representative workload but a digest that can
        // never satisfy CheckMatMulProofOfWork_RC's dimension bind.
        if (args.production) {
            header.matmul_dim = 4096;
        }
        rc::RCEpisodeTiming t{};
        rc::RCExactReplayAccelerationStats run_stats{};
        rc::RCExactReplayAcceleration acceleration{
            .gemm = gemm,
            .backend = backend_resolved,
            .require_device = device_run,
            .output_row_tile = args.output_row_tile,
            .stats = &run_stats,
        };
        const uint256 digest = rc::RecomputeResidentCurriculumAccelerated(
            header, params, /*height=*/0, {}, nullptr, &t, acceleration);
        episode_digests.push_back(digest.GetHex());
        if (digest.IsNull()) {
            digests_stable = false;
        }

        // A production CPU reseal is intentionally not hidden in a nominal
        // device timing. The resolver has already run byte-parity toy+medium
        // self-qualification; additionally compare every toy episode and the
        // first medium episode against the empty-backend CPU oracle.
        if (!args.production && (args.toy || e == 0)) {
            const uint256 cpu = rc::RecomputeResidentCurriculumReference(
                header, params, 0, {}, nullptr, nullptr, {});
            if (cpu.IsNull() || cpu != digest) digests_stable = false;
        }

        all_fully_accelerated =
            all_fully_accelerated && run_stats.fully_accelerated;
        if (metal_exact_lane) {
            all_full_metal_pipeline =
                all_full_metal_pipeline &&
                run_stats.full_metal_pipeline;
        }
        acceleration_totals.device_calls += run_stats.device_calls;
        acceleration_totals.device_macs += run_stats.device_macs;
        acceleration_totals.phase1_device_calls += run_stats.phase1_device_calls;
        acceleration_totals.phase1_device_macs += run_stats.phase1_device_macs;
        acceleration_totals.phase2_device_calls += run_stats.phase2_device_calls;
        acceleration_totals.phase2_device_macs += run_stats.phase2_device_macs;
        acceleration_totals.device_fused_ffn_calls +=
            run_stats.device_fused_ffn_calls;
        acceleration_totals.device_fused_ffn_chain_calls +=
            run_stats.device_fused_ffn_chain_calls;
        acceleration_totals.device_fused_phase1_calls +=
            run_stats.device_fused_phase1_calls;
        acceleration_totals.device_extract_elements +=
            run_stats.device_extract_elements;
        acceleration_totals.device_xof_calls +=
            run_stats.device_xof_calls;
        acceleration_totals.device_xof_elements +=
            run_stats.device_xof_elements;
        acceleration_totals.device_xof_s +=
            run_stats.device_xof_s;
        acceleration_totals.resident_ffn_chain_s +=
            run_stats.resident_ffn_chain_s;
        acceleration_totals.device_merkle_rounds +=
            run_stats.device_merkle_rounds;
        acceleration_totals.operand_xof_on_device =
            acceleration_totals.operand_xof_on_device ||
            run_stats.operand_xof_on_device;
        acceleration_totals.merkle_on_device =
            acceleration_totals.merkle_on_device ||
            run_stats.merkle_on_device;
        acceleration_totals.resident_ffn_chain_on_device =
            acceleration_totals.resident_ffn_chain_on_device ||
            run_stats.resident_ffn_chain_on_device;
        acceleration_totals.phase2_extract_on_device =
            acceleration_totals.phase2_extract_on_device ||
            run_stats.phase2_extract_on_device;
        acceleration_totals.phase1_extract_on_device =
            acceleration_totals.phase1_extract_on_device ||
            run_stats.phase1_extract_on_device;
        acceleration_totals.cpu_calls += run_stats.cpu_calls;
        acceleration_totals.cpu_macs += run_stats.cpu_macs;
        acceleration_totals.cpu_fallbacks += run_stats.cpu_fallbacks;
        if (acceleration_totals.first_failure.empty() &&
            !run_stats.first_failure.empty()) {
            acceleration_totals.first_failure = run_stats.first_failure;
        }

        sum_p1 += t.phase1_s;
        sum_p2 += t.phase2_s;
        sum_p3 += t.phase3_s;
        sum_tot += t.total_s;
        episode_walls.push_back(t.total_s);
    }
    acceleration_totals.fully_accelerated = all_fully_accelerated;
    acceleration_totals.full_metal_pipeline =
        all_full_metal_pipeline;

    // Mean phase walls across episodes (real chrono measurements).
    const double inv_ep = args.episodes > 0 ? 1.0 / static_cast<double>(args.episodes) : 0.0;
    timed.phase1_s = sum_p1 * inv_ep;
    timed.phase2_s = sum_p2 * inv_ep;
    timed.phase3_s = sum_p3 * inv_ep;
    timed.total_s = sum_tot * inv_ep;
    const double episode_cv = CoeffVar(episode_walls);
    const size_t peak_rss_kib = std::max(PeakRssKiB(), rss_before);

    // --- G3: k-curve proxy — StoreAll vs StoreOnlyX0 wall ratio (toy) ---
    auto k_header = MakeHeader(42);
    if (args.production) {
        k_header.matmul_dim = 4096;
    }
    rc::RCEpisodeOptions opt_all;
    opt_all.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreAll;
    rc::RCEpisodeOptions opt_x0;
    opt_x0.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;

    rc::RCEpisodeTiming t_all{}, t_x0{};
    uint256 d_all;
    uint256 d_x0;
    const bool k_curve_measured = !args.production;
    if (k_curve_measured) {
        const rc::RCExactReplayAcceleration k_acceleration{
            .gemm = gemm,
            .backend = backend_resolved,
            .require_device = device_run,
            .output_row_tile = args.output_row_tile,
            .stats = nullptr,
        };
        d_all = rc::RecomputeResidentCurriculumAccelerated(
            k_header, params, 0, opt_all, nullptr, &t_all, k_acceleration);
        d_x0 = rc::RecomputeResidentCurriculumAccelerated(
            k_header, params, 0, opt_x0, nullptr, &t_x0, k_acceleration);
        if (d_all.IsNull() || d_all != d_x0) {
            digests_stable = false; // checkpoint must be digest-invariant
        }
    }

    // Optional Resident / Checkpointed / Streamed mode sweep (RCExecMode).
    UniValue mode_sweep(UniValue::VOBJ);
    if (args.mode_sweep) {
        const auto modes = std::vector<std::pair<const char*, rc::RCExecMode>>{
            {"Resident", rc::RCExecMode::Resident},
            {"Checkpointed", rc::RCExecMode::Checkpointed},
            {"Streamed", rc::RCExecMode::Streamed},
        };
        UniValue rows(UniValue::VARR);
        uint256 dig0;
        bool first = true;
        bool modes_match = true;
        double wall_res = 0.0, wall_stream = 0.0;
        for (const auto& [name, mode] : modes) {
            const auto opt = rc::OptionsForExecMode(mode);
            rc::RCEpisodeTiming tm{};
            const size_t rss0 = PeakRssKiB();
            const rc::RCExactReplayAcceleration mode_acceleration{
                .gemm = gemm,
                .backend = backend_resolved,
                .require_device = device_run,
                .output_row_tile = args.output_row_tile,
                .stats = nullptr,
            };
            const uint256 d = rc::RecomputeResidentCurriculumAccelerated(
                k_header, params, 0, opt, nullptr, &tm, mode_acceleration);
            const size_t rss1 = PeakRssKiB();
            if (first) {
                dig0 = d;
                first = false;
            } else if (d != dig0) {
                modes_match = false;
                digests_stable = false;
            }
            if (std::string(name) == "Resident") wall_res = tm.total_s;
            if (std::string(name) == "Streamed") wall_stream = tm.total_s;
            UniValue row(UniValue::VOBJ);
            row.pushKV("mode", name);
            row.pushKV("wall_s", tm.total_s);
            row.pushKV("phase1_s", tm.phase1_s);
            row.pushKV("phase2_s", tm.phase2_s);
            row.pushKV("phase3_s", tm.phase3_s);
            row.pushKV("peak_rss_kib", static_cast<uint64_t>(std::max(rss0, rss1)));
            row.pushKV("digest", d.GetHex());
            rows.push_back(row);
        }
        mode_sweep.pushKV("digests_match", modes_match);
        mode_sweep.pushKV("modes", rows);
        // Forced Streamed vs Resident ratio (paging cost ≥ 1.0 expected).
        if (wall_res > 0.0) {
            mode_sweep.pushKV("streamed_over_resident", wall_stream / wall_res);
        }
    }

    const bool g1_pass =
        digests_stable && args.episodes > 0 &&
        (!device_run || all_fully_accelerated) &&
        (!metal_exact_lane || all_full_metal_pipeline);
    std::cout << "  ExtractMX:  " << (g1_pass ? "pass" : "fail")
              << " digests_stable=" << (digests_stable ? "true" : "false") << "\n";
    std::cout << "  phase_wall: p1=" << timed.phase1_s << "s p2=" << timed.phase2_s
              << "s p3=" << timed.phase3_s << "s total=" << timed.total_s << "s\n";
    std::cout << "  episode_cv: " << episode_cv << " peak_rss_kib=" << peak_rss_kib << "\n";
    std::cout << "  device_exec: provider=" << backend_resolved
              << " fully_accelerated=" << (all_fully_accelerated ? "true" : "false")
              << " full_metal_pipeline="
              << (all_full_metal_pipeline ? "true" : "false")
              << " device_calls=" << acceleration_totals.device_calls
              << " device_macs=" << acceleration_totals.device_macs
              << " cpu_calls=" << acceleration_totals.cpu_calls
              << " cpu_fallbacks=" << acceleration_totals.cpu_fallbacks << "\n";
    if (!acceleration_totals.first_failure.empty()) {
        std::cout << "  accel_fail: " << acceleration_totals.first_failure << "\n";
    }

    const double wall_all = k_curve_measured ? t_all.total_s : 0.0;
    const double wall_x0 = k_curve_measured ? t_x0.total_s : 0.0;
    // k ≈ recompute inflation of StoreOnlyX0 relative to StoreAll (real timing ratio).
    const double k_est = wall_all > 0 ? (wall_x0 / wall_all) : 0.0;

    UniValue k_curve(UniValue::VOBJ);
    k_curve.pushKV("measured", k_curve_measured);
    k_curve.pushKV("mode", k_curve_measured ? "synthetic_structure" : "skipped");
    k_curve.pushKV("note",
                   k_curve_measured
                       ? "k estimated as wall(StoreOnlyX0)/wall(StoreAll); "
                         "not a consensus-dim k(M) curve."
                       : "Skipped at production dimensions to avoid two extra full "
                         "episodes outside the requested measurement.");
    k_curve.pushKV("store_all_wall_s", wall_all);
    k_curve.pushKV("store_only_x0_wall_s", wall_x0);
    k_curve.pushKV("k_estimate", k_est);
    k_curve.pushKV("digests_match", k_curve_measured && d_all == d_x0);
    UniValue k_points(UniValue::VARR);
    {
        UniValue pt(UniValue::VOBJ);
        pt.pushKV("checkpoint", "StoreAll");
        pt.pushKV("wall_s", wall_all);
        pt.pushKV("recompute_ratio", k_curve_measured ? 1.0 : 0.0);
        k_points.push_back(pt);
    }
    {
        UniValue pt(UniValue::VOBJ);
        pt.pushKV("checkpoint", "StoreOnlyX0");
        pt.pushKV("wall_s", wall_x0);
        pt.pushKV("recompute_ratio", k_est);
        k_points.push_back(pt);
    }
    k_curve.pushKV("points", k_points);

    // --- G2: residency sweep (toy — one working-set point + measured wall) ---
    UniValue residency(UniValue::VARR);
    {
        UniValue pt(UniValue::VOBJ);
        pt.pushKV("working_set_bytes", footprint);
        pt.pushKV("wall_s", timed.total_s);
        pt.pushKV("dims", production_shape ? "production"
                                            : args.production ? "production-override"
                                            : args.medium ? "medium" : "toy");
        pt.pushKV("note", "Single working-set point; not a 64→256 MB cliff sweep.");
        residency.push_back(pt);
    }

    // --- Allocation caps: skip when toy footprint << named cap; never fake consensus ---
    auto cap_verdict = [&](uint64_t named_cap) -> std::string {
        // A normal run without --mem-cap did not test any named cap. Likewise,
        // a different requested cap is not evidence for this one.
        if (args.mem_cap != named_cap) return "skip";
        // Reaching this point means the episode completed under the requested
        // resident or streamed plan; over-cap plans returned before execution.
        return "pass";
    };
    const std::string cap512 = cap_verdict(512ull * 1024 * 1024);
    const std::string cap2g = cap_verdict(2ull * 1024 * 1024 * 1024);
    const std::string cap8g = cap_verdict(8ull * 1024 * 1024 * 1024);
    UniValue caps(UniValue::VOBJ);
    caps.pushKV("512MiB", cap512);
    caps.pushKV("2GiB", cap2g);
    caps.pushKV("8GiB", cap8g);
    caps.pushKV("note",
                "Only an explicitly requested --mem-cap receives pass/fail evidence; "
                "ordinary runs and other named caps remain skip.");

    UniValue walls(UniValue::VOBJ);
    walls.pushKV("phase1", timed.phase1_s);
    walls.pushKV("phase2", timed.phase2_s);
    walls.pushKV("phase3", timed.phase3_s);
    walls.pushKV("total", timed.total_s);

    UniValue qual(UniValue::VOBJ);
    qual.pushKV("status", g1_pass ? "pass" : "fail");
    qual.pushKV("episodes", static_cast<uint64_t>(args.episodes));
    qual.pushKV("digests_stable", digests_stable);
    qual.pushKV("exact_gemm_backend_ok", selfqual.exact_gemm_backend_ok);
    qual.pushKV("mining_accelerator_ok", selfqual.mining_accelerator_ok);
    qual.pushKV("native_mxfp4_qualified", selfqual.native_mxfp4_qualified);
    qual.pushKV("native_fp8_qualified", selfqual.native_fp8_qualified);
    qual.pushKV("deficit_reason", selfqual.deficit_reason);
    qual.pushKV("boundary_vector_notes",
                args.production
                    ? "Production dimensions: strict device coverage forbids CPU GEMM "
                      "fallback; resolver toy+medium byte-parity self-qual is binding."
                : args.medium
                    ? "Medium dimensions: first accelerated digest resealed vs CPU; "
                      "strict telemetry covers every contraction."
                    : "Toy self-qual: every accelerated digest equals the CPU reference; "
                      "strict telemetry covers every contraction.");

    UniValue exact_replay_acceleration(UniValue::VOBJ);
    exact_replay_acceleration.pushKV("provider", backend_resolved);
    exact_replay_acceleration.pushKV("resolution_reason", backend_reason);
    exact_replay_acceleration.pushKV("device_backend_present",
                                     acceleration_totals.device_backend_present);
    exact_replay_acceleration.pushKV("require_device", acceleration_totals.require_device);
    exact_replay_acceleration.pushKV("fully_accelerated",
                                     acceleration_totals.fully_accelerated);
    exact_replay_acceleration.pushKV(
        "full_metal_pipeline",
        acceleration_totals.full_metal_pipeline);
    exact_replay_acceleration.pushKV("all_consensus_macs_on_device",
                                     acceleration_totals.fully_accelerated);
    exact_replay_acceleration.pushKV("output_row_tile",
                                     static_cast<uint64_t>(args.output_row_tile));
    exact_replay_acceleration.pushKV("expected_macs",
                                     rc::TotalRCEpisodeMacs(params) * args.episodes);
    exact_replay_acceleration.pushKV("device_calls", acceleration_totals.device_calls);
    exact_replay_acceleration.pushKV("device_macs", acceleration_totals.device_macs);
    exact_replay_acceleration.pushKV("phase1_device_calls",
                                     acceleration_totals.phase1_device_calls);
    exact_replay_acceleration.pushKV("phase1_device_macs",
                                     acceleration_totals.phase1_device_macs);
    exact_replay_acceleration.pushKV("phase2_device_calls",
                                     acceleration_totals.phase2_device_calls);
    exact_replay_acceleration.pushKV("phase2_device_macs",
                                     acceleration_totals.phase2_device_macs);
    exact_replay_acceleration.pushKV("device_fused_ffn_calls",
                                     acceleration_totals.device_fused_ffn_calls);
    exact_replay_acceleration.pushKV(
        "device_fused_ffn_chain_calls",
        acceleration_totals.device_fused_ffn_chain_calls);
    exact_replay_acceleration.pushKV("device_fused_phase1_calls",
                                     acceleration_totals.device_fused_phase1_calls);
    exact_replay_acceleration.pushKV("device_extract_elements",
                                     acceleration_totals.device_extract_elements);
    exact_replay_acceleration.pushKV(
        "device_xof_calls",
        acceleration_totals.device_xof_calls);
    exact_replay_acceleration.pushKV(
        "device_xof_elements",
        acceleration_totals.device_xof_elements);
    exact_replay_acceleration.pushKV(
        "device_xof_s",
        acceleration_totals.device_xof_s);
    exact_replay_acceleration.pushKV(
        "resident_ffn_chain_s",
        acceleration_totals.resident_ffn_chain_s);
    exact_replay_acceleration.pushKV(
        "device_merkle_rounds",
        acceleration_totals.device_merkle_rounds);
    exact_replay_acceleration.pushKV(
        "operand_xof_on_device",
        acceleration_totals.operand_xof_on_device);
    exact_replay_acceleration.pushKV(
        "merkle_on_device",
        acceleration_totals.merkle_on_device);
    exact_replay_acceleration.pushKV(
        "resident_ffn_chain_on_device",
        acceleration_totals.resident_ffn_chain_on_device);
    exact_replay_acceleration.pushKV("phase2_extract_on_device",
                                     acceleration_totals.phase2_extract_on_device);
    exact_replay_acceleration.pushKV("phase1_extract_on_device",
                                     acceleration_totals.phase1_extract_on_device);
    exact_replay_acceleration.pushKV("cpu_calls", acceleration_totals.cpu_calls);
    exact_replay_acceleration.pushKV("cpu_macs", acceleration_totals.cpu_macs);
    exact_replay_acceleration.pushKV("cpu_fallbacks", acceleration_totals.cpu_fallbacks);
    exact_replay_acceleration.pushKV("first_failure", acceleration_totals.first_failure);
    exact_replay_acceleration.pushKV(
        "device_resident",
        acceleration_totals.resident_ffn_chain_on_device);
    exact_replay_acceleration.pushKV(
        "device_residency_note",
        acceleration_totals.full_metal_pipeline
            ? "Self-qualified Metal operand XOF, exact contractions, ExtractMX, "
              "resident FFN chain, streaming Merkle leaves, and Merkle subtree "
              "folding produced the consensus digest."
            : "Every consensus matrix contraction is device-enforced; deterministic "
              "XOF, ExtractMX, Merkle hashing, and operand staging remain on the host.");

    // Honest evidence labels for rc-gate.py (schema v2). Toy chrono walls are
    // real measurements but NEVER production-dim GO evidence. Verifier-floor
    // stays unmeasured here — MAC/heuristic projections are NOT EVIDENCE.
    UniValue walls_out = walls;
    walls_out.pushKV("provenance", "chrono_steady_clock");
    walls_out.pushKV("evidence_kind", args.toy ? "toy_chrono_measured" : "chrono_measured");

    UniValue verifier_floor(UniValue::VOBJ);
    const bool production_verifier_measured =
        production_shape && g1_pass;
    verifier_floor.pushKV("measured", production_verifier_measured);
    verifier_floor.pushKV("binding", true);
    verifier_floor.pushKV("evidence_kind",
                          production_verifier_measured
                              ? "production_exact_replay_chrono_measured"
                              : "unmeasured");
    if (production_verifier_measured) {
        verifier_floor.pushKV("wall_s", timed.total_s);
        verifier_floor.pushKV(
            "note",
            "Measured end-to-end production ExactReplay wall-clock with strict "
            "full-Metal pipeline coverage; claim comparison is constant-time.");
    } else {
        verifier_floor.pushKV(
            "note",
            "Verifier-floor is binding and must be measured at production dimensions. "
            "MAC-count projections are not evidence and cannot activate consensus.");
    }

    UniValue run_variance(UniValue::VOBJ);
    run_variance.pushKV("episode_cv", episode_cv);
    run_variance.pushKV("n_runs", static_cast<uint64_t>(args.episodes));
    UniValue wall_samples(UniValue::VARR);
    for (const double wall : episode_walls) {
        wall_samples.push_back(wall);
    }
    run_variance.pushKV("episode_wall_samples_s", wall_samples);
    if (!episode_walls.empty()) {
        const auto [minimum, maximum]{
            std::minmax_element(
                episode_walls.begin(), episode_walls.end())};
        run_variance.pushKV("sample_min_s", *minimum);
        run_variance.pushKV("sample_max_s", *maximum);
    }
    run_variance.pushKV(
        "nearest_rank_p50_s",
        NearestRankPercentile(episode_walls, 0.50));
    run_variance.pushKV(
        "nearest_rank_p95_s",
        NearestRankPercentile(episode_walls, 0.95));
    run_variance.pushKV(
        "nearest_rank_p99_s",
        NearestRankPercentile(episode_walls, 0.99));
    run_variance.pushKV(
        "empirical_p99_claimable",
        episode_walls.size() >= 100);

    // Treat the measured walls as one saturated verifier's service times.
    // This is the exact single-device queue model used by MatMulVerifyWorker:
    // one device submitter, FIFO within equal priority, no overlapping Metal
    // episodes. It records both an adversarial zero-gap pair and the intended
    // 90-second arrival cadence without inserting idle time into the loaded
    // measurement process.
    constexpr double kBlockIntervalS{90.0};
    double max_immediate_pair_s{0.0};
    for (size_t i = 1; i < episode_walls.size(); ++i) {
        max_immediate_pair_s = std::max(
            max_immediate_pair_s,
            episode_walls[i - 1] + episode_walls[i]);
    }
    double queued_work_s{0.0};
    double max_queue_wait_s{0.0};
    double max_arrival_to_verdict_s{0.0};
    for (const double service_s : episode_walls) {
        max_queue_wait_s = std::max(max_queue_wait_s, queued_work_s);
        max_arrival_to_verdict_s =
            std::max(max_arrival_to_verdict_s, queued_work_s + service_s);
        queued_work_s =
            std::max(0.0, queued_work_s + service_s - kBlockIntervalS);
    }
    UniValue back_to_back(UniValue::VOBJ);
    back_to_back.pushKV("block_interval_s", kBlockIntervalS);
    back_to_back.pushKV(
        "max_immediate_two_block_drain_s",
        max_immediate_pair_s);
    back_to_back.pushKV(
        "max_queue_wait_at_interval_s",
        max_queue_wait_s);
    back_to_back.pushKV(
        "max_arrival_to_verdict_at_interval_s",
        max_arrival_to_verdict_s);
    back_to_back.pushKV(
        "ending_queued_work_s",
        queued_work_s);
    back_to_back.pushKV(
        "no_expanding_queue",
        queued_work_s == 0.0 && max_queue_wait_s == 0.0);
    run_variance.pushKV("back_to_back", back_to_back);
    run_variance.pushKV("note",
                        "Continuous in-process samples with no cooldown. Percentiles use "
                        "the nearest-rank estimator; p99 is claimable only at n>=100. "
                        "Back-to-back queue metrics use the measured single-Metal-device "
                        "service times at a 90-second block cadence.");

    std::string tip = args.source_revision;
    if (tip.empty()) {
        if (const char* env = std::getenv("BTX_SOURCE_REVISION")) tip = env;
    }

    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "rc-episode-harness");
    root.pushKV("schema_version", 2);
    root.pushKV("stub", false);
    root.pushKV("device_id", device_id);
    root.pushKV("backend", backend_resolved);
    root.pushKV("backend_requested", args.backend);
    root.pushKV("backend_resolution_reason", backend_reason);
    root.pushKV("profile", args.coupled ? "coupled" : "episode");
    root.pushKV("mem_cap_bytes", args.mem_cap);
    root.pushKV("toy", args.toy);
    root.pushKV("medium", args.medium);
    root.pushKV("production_dims", production_shape);
    root.pushKV("rounds_override", static_cast<uint64_t>(args.rounds));
    root.pushKV(
        "episode_profile",
        static_cast<uint64_t>(
            args.production ? (args.base_production ? 1 : 2) : 0));
    root.pushKV(
        "header_matmul_dim",
        static_cast<uint64_t>(args.production ? 4096 : 0));
    root.pushKV("evidence_kind", args.toy ? "toy_chrono_measured"
                               : production_shape ? "production_chrono_measured"
                                                  : "chrono_measured");
    root.pushKV("wall_clock_provenance", "chrono_steady_clock");
    root.pushKV(
        "device_resident",
        acceleration_totals.resident_ffn_chain_on_device);
    root.pushKV("all_consensus_macs_on_device",
                acceleration_totals.fully_accelerated);
    root.pushKV("native_path_eligible",
                selfqual.native_mxfp4_qualified || selfqual.native_fp8_qualified);
    if (metal_arch.available) {
        UniValue hardware(UniValue::VOBJ);
        hardware.pushKV("metal_device_name", metal_arch.device_name);
        hardware.pushKV("apple_silicon_identity", metal_arch.name_class_string);
        hardware.pushKV("metal4_mpp_compile_ok",
                        metal_arch.metal4_tensor_ops_compile_ok);
        root.pushKV("hardware", hardware);
    }
    {
        // Machine-readable native-FP4 status: a deactivated path is a first-class
        // field (native_declined + reason), not an absence inferred from INT8 numbers.
        UniValue mxfp4_j(UniValue::VOBJ);
        mxfp4_j.pushKV("sm120a_kernel_linked", mxfp4.sm120a_kernel_linked);
        mxfp4_j.pushKV("attempted", mxfp4.attempted);
        mxfp4_j.pushKV("qualified", mxfp4.qualified);
        mxfp4_j.pushKV("exact_panels_qualified", mxfp4.exact_panels_qualified);
        mxfp4_j.pushKV("selected_backend", mxfp4.backend);
        mxfp4_j.pushKV("arch_key", mxfp4.arch_key);
        mxfp4_j.pushKV("deficit_reason", mxfp4.deficit_reason);
        mxfp4_j.pushKV("native_declined", native_declined);
        root.pushKV("native_mxfp4", mxfp4_j);
    }
    if (!tip.empty()) {
        root.pushKV("source_revision", tip);
        root.pushKV("git_tip", tip);
    }
    root.pushKV("peak_rss_kib", static_cast<uint64_t>(peak_rss_kib));
    root.pushKV("run_variance", run_variance);
    root.pushKV("params", ParamsJson(params));
    root.pushKV("working_set_bytes_est", footprint);
    root.pushKV("episode_digests", episode_digests);
    root.pushKV("extractmx_self_qual", qual);
    root.pushKV("exact_replay_acceleration", exact_replay_acceleration);
    root.pushKV("phase_wall_s", walls_out);
    root.pushKV("k_curve", k_curve);
    root.pushKV("residency_sweep", residency);
    root.pushKV("allocation_cap_verdicts", caps);
    root.pushKV("verifier_floor", verifier_floor);
    if (args.mode_sweep) root.pushKV("exec_mode_sweep", mode_sweep);
    root.pushKV("gpu_campaign_present",
                device_run && acceleration_totals.fully_accelerated);
    root.pushKV("nvlink_campaign_present", false);
    root.pushKV("consensus_note",
                "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
                "This harness never recommends raising consensus height. "
                "Projections/MAC estimates are NOT EVIDENCE for rc-gate GO. "
                "Cross-host Metal and datacenter campaigns remain Stage G blockers.");

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    ofs.close();

    if (k_curve_measured) {
        std::cout << "  k_est:      " << k_est << " (StoreOnlyX0/StoreAll)\n";
    } else {
        std::cout << "  k_est:      skipped at production dimensions\n";
    }
    std::cout << "  caps:       512MiB=" << cap512 << " 2GiB=" << cap2g
              << " 8GiB=" << cap8g << "\n";
    std::cout << "  wrote:      " << args.out_path << "\n";
    std::cout << "  consensus:  nMatMulRCHeight=INT32_MAX (NO-GO activation)\n";
    std::cout << (g1_pass ? "RESULT: ExtractMX self-qual PASS\n"
                          : "RESULT: ExtractMX self-qual FAIL\n");

    return g1_pass ? 0 : 1;
}
