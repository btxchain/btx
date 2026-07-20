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
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_scale_axes.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_coupled_netcost.h>
#include <matmul/matmul_v4_rc_gkr.h>
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
    bool help{false};
    bool coupled{false};
    bool coupled_medium{false};
    bool coupled_production{false};
    bool mode_sweep{false};
    bool mem_cap_sweep{false};
    bool prove_winner_gkr{false};
    uint32_t rounds{0};   // 0 ⇒ keep params.rounds
    uint32_t episodes{3}; // default for toy
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
       << "  --production               frozen episode dims (n_ctx=786432 …); off-CI\n"
       << "  --coupled                  Stage C coupled-puzzle timing (toy dims)\n"
       << "  --coupled-medium           Stage C coupled-puzzle timing (medium dims)\n"
       << "  --coupled-production       Stage C provisional HBM coupled dims (off-CI)\n"
       << "  --mem-cap-sweep            production coupled under 512MiB/2GiB/8GiB caps\n"
       << "  --mode-sweep               also time Resident/Checkpointed/Streamed\n"
       << "  --prove-winner-gkr         Stage E winner-only: mine + reseal + ProveWinner* + verify\n"
       << "  --rounds N                 override episode rounds (default: params)\n"
       << "  --episodes N               ExtractMX self-qual episode count (default: 3)\n"
       << "  --backend NAME             cpu|cuda|hip|metal|auto (default: cpu).\n"
       << "                             Non-CPU uses MakeResolvedExactGemmBackendForRC\n"
       << "                             (LT resolve + RC self-qual fail-closed → CPU).\n"
       << "                             Digests are always resealed vs empty-backend CPU.\n"
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
        } else if (a == "--production") {
            args.production = true;
            args.toy = false;
            args.medium = false;
        } else if (a == "--coupled") {
            args.coupled = true;
        } else if (a == "--coupled-medium") {
            args.coupled = true;
            args.coupled_medium = true;
            args.coupled_production = false;
        } else if (a == "--coupled-production") {
            args.coupled = true;
            args.coupled_production = true;
            args.coupled_medium = false;
        } else if (a == "--mem-cap-sweep") {
            args.mem_cap_sweep = true;
            args.coupled = true;
            args.coupled_production = true;
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
    o.pushKV("state_bytes", static_cast<uint64_t>(p.StateBytes()));
    return o;
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

    const rc::RCCoupParams params = args.coupled_production ? rc::MakeProductionRCCoupParams()
                                  : args.coupled_medium     ? rc::MakeMediumRCCoupParams()
                                                            : rc::MakeToyRCCoupParams();
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
    const bool allow_resident =
        std::getenv("BTX_RC_COUP_ALLOW_RESIDENT") != nullptr;
    if (force_streamed || (args.coupled_production && !allow_resident)) {
        // Production defaults to Streamed-only (48 GiB Resident is opt-in via env).
        modes.push_back(rc::RCCoupExecMode::Streamed);
    } else if (args.coupled_production && allow_resident) {
        modes = {rc::RCCoupExecMode::Streamed, rc::RCCoupExecMode::Resident};
    } else {
        modes = {rc::RCCoupExecMode::SequentialLobes, rc::RCCoupExecMode::Checkpointed,
                 rc::RCCoupExecMode::Streamed, rc::RCCoupExecMode::Resident};
    }

    UniValue mode_walls(UniValue::VARR);
    uint256 digest_ref;
    bool digests_match = true;
    bool mine_matches = true;
    rc::RCCoupTiming timed{};

    for (size_t i = 0; i < modes.size(); ++i) {
        rc::RCCoupOptions opt;
        opt.mode = modes[i];
        rc::RCCoupTiming t{};
        const uint256 d =
            rc::RecomputeCoupledPuzzleReference(header, /*height=*/0, params, opt, {}, &t);
        const uint256 d_mine =
            rc::MineCoupledPuzzle(header, /*height=*/0, params, gemm, opt);
        if (d != d_mine) mine_matches = false;
        if (i == 0) {
            digest_ref = d;
            timed = t;
        } else if (d != digest_ref) {
            digests_match = false;
        }
        UniValue mw(UniValue::VOBJ);
        mw.pushKV("mode", CoupModeName(modes[i]));
        mw.pushKV("digest", d.GetHex());
        mw.pushKV("mine_matches_cpu", d == d_mine);
        mw.pushKV("bank_s", t.bank_s);
        mw.pushKV("barriers_s", t.barriers_s);
        mw.pushKV("wall_s", t.total_s);
        mw.pushKV("total_s", t.total_s);
        mw.pushKV("nonce_per_s", t.total_s > 0.0 ? (1.0 / t.total_s) : 0.0);
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

    std::cout << "== MatMul ENC_RC coupled harness (Stage C) ==\n";
    std::cout << "  device_id:  " << device_id << "\n";
    std::cout << "  backend:    " << args.backend << " → " << backend_resolved << "\n";
    const char* shape = args.coupled_production ? "production"
                         : args.coupled_medium     ? "medium"
                                                   : "toy";
    std::cout << "  shape:      " << shape << "\n";
    std::cout << "  peak_est:   streamed=" << streamed_peak << " resident=" << resident_peak
              << (force_streamed ? " (auto-Streamed by --mem-cap)" : "") << "\n";
    std::cout << "  barriers:   " << params.barriers << " lobes=" << params.lobes
              << " width=" << params.lobe_width << " pages=" << params.bank_pages << "\n";
    std::cout << "  digest:     " << digest_ref.GetHex() << "\n";
    std::cout << "  modes_ok:   " << (digests_match ? "true" : "false") << "\n";
    std::cout << "  mine_ok:    " << (mine_matches ? "true" : "false") << "\n";
    std::cout << "  device_probe: resolved=" << (device_probe.backend_resolved ? 1 : 0)
              << " provider=" << device_probe.provider << " detail=" << device_probe.detail
              << "\n";
    std::cout << "  phase_wall: bank=" << timed.bank_s << "s barriers=" << timed.barriers_s
              << "s total=" << timed.total_s << "s\n";
    std::cout << "  rss_kib:    before=" << rss_before << " after=" << rss_after
              << " peak=" << peak_rss << "\n";
    if (wall_resident > 0.0) {
        std::cout << "  stream/res: " << (wall_stream / wall_resident) << "\n";
    }

    UniValue walls(UniValue::VOBJ);
    walls.pushKV("bank", timed.bank_s);
    walls.pushKV("barriers", timed.barriers_s);
    walls.pushKV("total", timed.total_s);
    walls.pushKV("provenance", "chrono_steady_clock");
    walls.pushKV("evidence_kind",
                 args.coupled_medium ? "chrono_measured" : "toy_chrono_measured");

    UniValue rss(UniValue::VOBJ);
    rss.pushKV("before_kib", static_cast<uint64_t>(rss_before));
    rss.pushKV("after_kib", static_cast<uint64_t>(rss_after));
    rss.pushKV("peak_kib", static_cast<uint64_t>(peak_rss));

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
        pt.pushKV("wall_s", timed.total_s);
        pt.pushKV("dims", args.coupled_medium ? "medium" : "toy");
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
    coupled.pushKV("auto_streamed", force_streamed || (args.coupled_production && !allow_resident));
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
    root.pushKV("toy", !args.coupled_medium && !args.coupled_production);
    root.pushKV("medium", args.coupled_medium);
    root.pushKV("production_dims", args.coupled_production);
    root.pushKV("streamed_peak_bytes_est", streamed_peak);
    root.pushKV("resident_peak_bytes_est", resident_peak);
    root.pushKV("mem_cap_bytes", args.mem_cap);
    root.pushKV("evidence_kind",
                args.coupled_production ? "production_chrono_measured"
                : args.coupled_medium     ? "chrono_measured"
                                          : "toy_chrono_measured");
    root.pushKV("wall_clock_provenance", "chrono_steady_clock");
    root.pushKV("device_resident", false);
    root.pushKV("native_path_eligible", false);
    root.pushKV("params", CoupParamsJson(params));
    root.pushKV("digest", digest_ref.GetHex());
    root.pushKV("modes_digest_match", digests_match);
    root.pushKV("mine_matches_cpu", mine_matches);
    root.pushKV("mode_walls", mode_walls);
    root.pushKV("coupled", coupled);
    root.pushKV("extractmx_self_qual", qual);
    root.pushKV("phase_wall_s", walls);
    root.pushKV("peak_rss_kib", static_cast<uint64_t>(peak_rss));
    root.pushKV("rss_kib", rss);
    root.pushKV("run_variance", run_variance);
    root.pushKV("residency_sweep", residency);
    root.pushKV("k_curve", k_curve);
    root.pushKV("allocation_cap_verdicts", caps);
    root.pushKV("verifier_floor", vf);
    root.pushKV("device_probe", probe_j);
    root.pushKV("interconnect_sim", netj);
    root.pushKV("gpu_campaign_present", false);
    root.pushKV("nvlink_campaign_present", false);
    root.pushKV("gpu_status", "SILICON-GATED");
    root.pushKV("consensus_note",
                "nMatMulRCCoupledHeight remains INT32_MAX on public nets; coupled "
                "profile (ENC_RC_COUPLED) is INERT unless regtest sets a finite height. "
                "Mining inject uses MakeResolvedExactGemmBackendForRC when active. "
                "SIMULATED interconnect is NOT Stage-I gate 4 evidence. "
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
        const rc::RCCoupParams params =
            args.coupled_medium ? rc::MakeMediumRCCoupParams() : rc::MakeToyRCCoupParams();
        rep = rc::SolveCoupledProveWinner(header, /*height=*/0, params, easy,
                                          /*max_tries=*/64, /*do_prove=*/true);
        root.pushKV("mode", "coupled");
        root.pushKV("shape", args.coupled_medium ? "medium" : "toy");
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

    rc::RCEpisodeParams params = args.production ? rc::MakeProductionRCEpisodeParams()
                               : args.medium     ? rc::MakeMediumRCEpisodeParams()
                                                 : rc::MakeToyRCEpisodeParams();
    if (args.rounds > 0) params.rounds = args.rounds;
    if (!rc::ValidateRCEpisodeParams(params)) {
        std::cerr << "error: invalid RC episode params\n";
        return 2;
    }

    // RC-only ExactGemm inject: MakeResolvedExactGemmBackendForRC applies
    // ProbeRCSelfQual fail-closed (empty = CPU ExactGemmS8S8). The LT resolver
    // (MakeResolvedExactGemmBackend) intentionally skips this gate.
    matmul::v4::lt::ExactGemmBackend gemm{};
    rc::RCSelfQualStatus selfqual{};
    std::string backend_resolved = "cpu";
    if (args.backend == "cpu") {
        selfqual = rc::ProbeRCSelfQual(gemm);
        selfqual.exact_gemm_backend_ok = true; // empty backend is the CPU oracle path
        selfqual.mining_accelerator_ok = false;
        selfqual.deficit_reason.clear();
    } else if (args.backend == "cuda" || args.backend == "hip" || args.backend == "metal" ||
               args.backend == "ascend" || args.backend == "auto") {
        gemm = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
        if (gemm.gemm_s8s8 != nullptr) {
            // ForRC already ProbeRCSelfQual'd successfully; avoid a second medium probe.
            selfqual.cpu_oracle_ok = true;
            selfqual.exact_gemm_backend_ok = true;
            selfqual.mining_accelerator_ok = true;
            selfqual.native_mxfp4_qualified = false;
            selfqual.native_fp8_qualified = false;
            backend_resolved = args.backend;
        } else {
            // RC gate cleared (or no device): probe ungated LT candidate for deficit.
            const auto candidate = matmul_v4::accel::MakeResolvedExactGemmBackend();
            selfqual = rc::ProbeRCSelfQual(candidate);
            backend_resolved = "cpu-fallback";
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
    const std::string device_id = backend_resolved + "-ref:" + host;

    std::cout << "== MatMul ENC_RC harness (real episodes) ==\n";
    std::cout << "  device_id:  " << device_id << "\n";
    std::cout << "  backend:    " << args.backend << " → " << backend_resolved << "\n";
    std::cout << "  dims:       toy=" << (args.toy ? "true" : "false")
              << " medium=" << (args.medium ? "true" : "false")
              << " production=" << (args.production ? "true" : "false") << "\n";
    std::cout << "  episodes:   " << args.episodes << "\n";
    std::cout << "  rounds:     " << params.rounds << "\n";
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
    double sum_p1 = 0, sum_p2 = 0, sum_p3 = 0, sum_tot = 0;
    std::vector<double> episode_walls;
    episode_walls.reserve(args.episodes);
    const size_t rss_before = PeakRssKiB();

    for (uint32_t e = 0; e < args.episodes; ++e) {
        const auto header = MakeHeader(1000 + e);
        rc::RCEpisodeTiming t{};
        const uint256 d_ref =
            rc::RecomputeResidentCurriculumReference(header, params, /*height=*/0, {}, nullptr, &t,
                                                     /*gemm=*/{});
        const uint256 d_mine = rc::MineRCEpisode(header, params, /*height=*/0, nullptr, gemm);
        if (d_ref.IsNull() || d_ref != d_mine) {
            digests_stable = false;
        }
        const uint256 d_again =
            rc::RecomputeResidentCurriculumReference(header, params, 0, {}, nullptr, nullptr, {});
        if (d_again != d_ref) digests_stable = false;

        sum_p1 += t.phase1_s;
        sum_p2 += t.phase2_s;
        sum_p3 += t.phase3_s;
        sum_tot += t.total_s;
        episode_walls.push_back(t.total_s);
    }

    // Mean phase walls across episodes (real chrono measurements).
    const double inv_ep = args.episodes > 0 ? 1.0 / static_cast<double>(args.episodes) : 0.0;
    timed.phase1_s = sum_p1 * inv_ep;
    timed.phase2_s = sum_p2 * inv_ep;
    timed.phase3_s = sum_p3 * inv_ep;
    timed.total_s = sum_tot * inv_ep;
    const double episode_cv = CoeffVar(episode_walls);
    const size_t peak_rss_kib = std::max(PeakRssKiB(), rss_before);

    // --- G3: k-curve proxy — StoreAll vs StoreOnlyX0 wall ratio (toy) ---
    const auto k_header = MakeHeader(42);
    rc::RCEpisodeOptions opt_all;
    opt_all.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreAll;
    rc::RCEpisodeOptions opt_x0;
    opt_x0.checkpoint = rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0;

    rc::RCEpisodeTiming t_all{}, t_x0{};
    const uint256 d_all =
        rc::RecomputeResidentCurriculumReference(k_header, params, 0, opt_all, nullptr, &t_all);
    const uint256 d_x0 =
        rc::RecomputeResidentCurriculumReference(k_header, params, 0, opt_x0, nullptr, &t_x0);
    if (d_all.IsNull() || d_all != d_x0) {
        digests_stable = false; // checkpoint must be digest-invariant
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
            const uint256 d =
                rc::RecomputeResidentCurriculumReference(k_header, params, 0, opt, nullptr, &tm);
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

    const bool g1_pass = digests_stable && args.episodes > 0;
    std::cout << "  ExtractMX:  " << (g1_pass ? "pass" : "fail")
              << " digests_stable=" << (digests_stable ? "true" : "false") << "\n";
    std::cout << "  phase_wall: p1=" << timed.phase1_s << "s p2=" << timed.phase2_s
              << "s p3=" << timed.phase3_s << "s total=" << timed.total_s << "s\n";
    std::cout << "  episode_cv: " << episode_cv << " peak_rss_kib=" << peak_rss_kib << "\n";

    const double wall_all = t_all.total_s > 0 ? t_all.total_s : timed.total_s;
    const double wall_x0 = t_x0.total_s > 0 ? t_x0.total_s : wall_all;
    // k ≈ recompute inflation of StoreOnlyX0 relative to StoreAll (real timing ratio).
    const double k_est = wall_all > 0 ? (wall_x0 / wall_all) : 0.0;

    UniValue k_curve(UniValue::VOBJ);
    k_curve.pushKV("mode", "toy_synthetic_structure");
    k_curve.pushKV("note",
                   "Toy dims: k estimated as wall(StoreOnlyX0)/wall(StoreAll); "
                   "not a consensus-dim k(M) curve.");
    k_curve.pushKV("store_all_wall_s", wall_all);
    k_curve.pushKV("store_only_x0_wall_s", wall_x0);
    k_curve.pushKV("k_estimate", k_est);
    k_curve.pushKV("digests_match", d_all == d_x0);
    UniValue k_points(UniValue::VARR);
    {
        UniValue pt(UniValue::VOBJ);
        pt.pushKV("checkpoint", "StoreAll");
        pt.pushKV("wall_s", wall_all);
        pt.pushKV("recompute_ratio", 1.0);
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
        pt.pushKV("dims", args.medium ? "medium" : "toy");
        pt.pushKV("note", "Single working-set point; not a 64→256 MB cliff sweep.");
        residency.push_back(pt);
    }

    // --- Allocation caps: skip when toy footprint << named cap; never fake consensus ---
    auto cap_verdict = [&](uint64_t named_cap) -> std::string {
        if (footprint < named_cap) return "skip"; // toy cannot stress this cap
        // Episode completed under mem_cap==0 or mem_cap large enough.
        if (args.mem_cap == 0 || args.mem_cap >= footprint) return "pass";
        return "fail";
    };
    const std::string cap512 = cap_verdict(512ull * 1024 * 1024);
    const std::string cap2g = cap_verdict(2ull * 1024 * 1024 * 1024);
    const std::string cap8g = cap_verdict(8ull * 1024 * 1024 * 1024);
    UniValue caps(UniValue::VOBJ);
    caps.pushKV("512MiB", cap512);
    caps.pushKV("2GiB", cap2g);
    caps.pushKV("8GiB", cap8g);
    caps.pushKV("note",
                "Toy footprint << named caps ⇒ skip (not pass). Consensus-dim "
                "cap verdicts require running consensus dims.");

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
                args.medium
                    ? "Medium dims: MineRCEpisode(backend) resealed vs CPU reference; "
                      "wgrad contraction exceeds 2^24 (int64 oracle)."
                    : "Toy self-qual: MineRCEpisode(backend) == CPU reference per episode; "
                      "re-run digest stability. Use --medium for >2^24 wgrad.");

    // Honest evidence labels for rc-gate.py (schema v2). Toy chrono walls are
    // real measurements but NEVER production-dim GO evidence. Verifier-floor
    // stays unmeasured here — MAC/heuristic projections are NOT EVIDENCE.
    UniValue walls_out = walls;
    walls_out.pushKV("provenance", "chrono_steady_clock");
    walls_out.pushKV("evidence_kind", args.toy ? "toy_chrono_measured" : "chrono_measured");

    UniValue verifier_floor(UniValue::VOBJ);
    verifier_floor.pushKV("measured", false);
    verifier_floor.pushKV("binding", true);
    verifier_floor.pushKV("evidence_kind", "unmeasured");
    verifier_floor.pushKV("note",
                          "Verifier-floor is the binding constraint (doc §R.7.6) and "
                          "MUST be measured full-episode + full-verify wall-clock at "
                          "production dims. MAC-count / replay_s_heuristic projections "
                          "are NOT EVIDENCE and must never raise nMatMulRCHeight.");

    UniValue run_variance(UniValue::VOBJ);
    run_variance.pushKV("episode_cv", episode_cv);
    run_variance.pushKV("n_runs", static_cast<uint64_t>(args.episodes));
    run_variance.pushKV("note",
                        "Coefficient of variation across episode walls in this process. "
                        "Campaign harness aggregates cross-process variance separately.");

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
    root.pushKV("profile", args.coupled ? "coupled" : "episode");
    root.pushKV("mem_cap_bytes", args.mem_cap);
    root.pushKV("toy", args.toy);
    root.pushKV("medium", args.medium);
    root.pushKV("production_dims", args.production);
    root.pushKV("evidence_kind", args.toy ? "toy_chrono_measured"
                               : args.production ? "production_chrono_measured"
                                                 : "chrono_measured");
    root.pushKV("wall_clock_provenance", "chrono_steady_clock");
    root.pushKV("device_resident", false);
    root.pushKV("native_path_eligible",
                selfqual.native_mxfp4_qualified || selfqual.native_fp8_qualified);
    if (!tip.empty()) {
        root.pushKV("source_revision", tip);
        root.pushKV("git_tip", tip);
    }
    root.pushKV("peak_rss_kib", static_cast<uint64_t>(peak_rss_kib));
    root.pushKV("run_variance", run_variance);
    root.pushKV("params", ParamsJson(params));
    root.pushKV("working_set_bytes_est", footprint);
    root.pushKV("extractmx_self_qual", qual);
    root.pushKV("phase_wall_s", walls_out);
    root.pushKV("k_curve", k_curve);
    root.pushKV("residency_sweep", residency);
    root.pushKV("allocation_cap_verdicts", caps);
    root.pushKV("verifier_floor", verifier_floor);
    if (args.mode_sweep) root.pushKV("exec_mode_sweep", mode_sweep);
    root.pushKV("gpu_campaign_present", false);
    root.pushKV("nvlink_campaign_present", false);
    root.pushKV("consensus_note",
                "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
                "This harness never recommends raising consensus height. "
                "Projections/MAC estimates are NOT EVIDENCE for rc-gate GO. "
                "Missing GPU/NVLink campaigns are Stage G blockers.");

    std::ofstream ofs(args.out_path, std::ios::trunc);
    if (!ofs) {
        std::cerr << "error: cannot write JSON to " << args.out_path << "\n";
        return 1;
    }
    ofs << root.write(2) << "\n";
    ofs.close();

    std::cout << "  k_est:      " << k_est << " (StoreOnlyX0/StoreAll)\n";
    std::cout << "  caps:       512MiB=" << cap512 << " 2GiB=" << cap2g
              << " 8GiB=" << cap8g << "\n";
    std::cout << "  wrote:      " << args.out_path << "\n";
    std::cout << "  consensus:  nMatMulRCHeight=INT32_MAX (NO-GO activation)\n";
    std::cout << (g1_pass ? "RESULT: ExtractMX self-qual PASS\n"
                          : "RESULT: ExtractMX self-qual FAIL\n");

    return g1_pass ? 0 : 1;
}
