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

#include <crypto/sha256.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/translation.h>

#include <univalue.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

// Standalone util: no GUI translation table.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace rc = matmul::v4::rc;

namespace {

struct Args {
    bool toy{true};
    bool medium{false};
    bool help{false};
    uint32_t rounds{0};   // 0 ⇒ keep params.rounds
    uint32_t episodes{3}; // default for toy
    uint64_t mem_cap{0};  // 0 = unlimited
    std::string backend{"cpu"};
    std::string out_path{"rc-report.json"};
};

void PrintUsage(std::ostream& os)
{
    os << "Usage: matmul-v4-rc-harness [options]\n"
       << "  --toy / --no-toy           tiny dims (default: --toy; CI-safe)\n"
       << "  --medium                   medium dims (wgrad >2^24); implies not toy\n"
       << "  --rounds N                 override episode rounds (default: params)\n"
       << "  --episodes N               ExtractMX self-qual episode count (default: 3)\n"
       << "  --backend NAME             cpu|cuda|hip|metal|auto (default: cpu).\n"
       << "                             Non-CPU uses MakeResolvedExactGemmBackend +\n"
       << "                             ProbeRCSelfQual (fail-closed → CPU). Digests\n"
       << "                             are always resealed vs empty-backend CPU.\n"
       << "  --mem-cap BYTES            allocator budget check (0 = unlimited)\n"
       << "  --out PATH                 JSON output (default: rc-report.json)\n"
       << "  -h, --help                 this help\n";
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

} // namespace

int main(int argc, char* argv[])
{
    // Standalone tools do not construct kernel::Context — select SHA-256 impl.
    const std::string sha256_impl = SHA256AutoDetect();
    (void)sha256_impl;

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

    if (!args.toy && !args.medium) {
        std::cerr << "error: --no-toy without --medium refuses consensus dims "
                     "(n_ctx=786432) in this harness; use --toy or --medium.\n";
        return 2;
    }

    rc::RCEpisodeParams params =
        args.medium ? rc::MakeMediumRCEpisodeParams() : rc::MakeToyRCEpisodeParams();
    if (args.rounds > 0) params.rounds = args.rounds;
    if (!rc::ValidateRCEpisodeParams(params)) {
        std::cerr << "error: invalid RC episode params\n";
        return 2;
    }

    // Resolve ExactGemm for non-CPU backends (CUDA/HIP/Metal/Ascend via accel).
    // ProbeRCSelfQual fail-closes to empty backend (= CPU ExactGemmS8S8).
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
        gemm = matmul_v4::accel::MakeResolvedExactGemmBackend();
        selfqual = rc::ProbeRCSelfQual(gemm);
        if (!selfqual.mining_accelerator_ok) {
            gemm = {};
            backend_resolved = "cpu-fallback";
        } else {
            backend_resolved = args.backend;
        }
    } else {
        std::cerr << "error: unknown --backend " << args.backend
                  << " (want cpu|cuda|hip|metal|ascend|auto)\n";
        return 2;
    }

    const uint64_t footprint = EstimateWorkingSetBytes(params);
    if (args.mem_cap != 0 && footprint > args.mem_cap) {
        std::cerr << "error: estimated working-set " << footprint
                  << " bytes exceeds --mem-cap " << args.mem_cap << "\n";
        return 1;
    }

    const std::string host = HostName();
    const std::string device_id = backend_resolved + "-ref:" + host;

    std::cout << "== MatMul ENC_RC harness (real episodes) ==\n";
    std::cout << "  device_id:  " << device_id << "\n";
    std::cout << "  backend:    " << args.backend << " → " << backend_resolved << "\n";
    std::cout << "  toy/medium: toy=" << (args.toy ? "true" : "false")
              << " medium=" << (args.medium ? "true" : "false") << "\n";
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
    }

    // Mean phase walls across episodes (real chrono measurements).
    const double inv_ep = args.episodes > 0 ? 1.0 / static_cast<double>(args.episodes) : 0.0;
    timed.phase1_s = sum_p1 * inv_ep;
    timed.phase2_s = sum_p2 * inv_ep;
    timed.phase3_s = sum_p3 * inv_ep;
    timed.total_s = sum_tot * inv_ep;

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

    const bool g1_pass = digests_stable && args.episodes > 0;
    std::cout << "  ExtractMX:  " << (g1_pass ? "pass" : "fail")
              << " digests_stable=" << (digests_stable ? "true" : "false") << "\n";
    std::cout << "  phase_wall: p1=" << timed.phase1_s << "s p2=" << timed.phase2_s
              << "s p3=" << timed.phase3_s << "s total=" << timed.total_s << "s\n";

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
        pt.pushKV("dims", "toy");
        pt.pushKV("note", "Single toy working-set point; not a 64→256 MB cliff sweep.");
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

    UniValue root(UniValue::VOBJ);
    root.pushKV("tool", "rc-episode-harness");
    root.pushKV("schema_version", 1);
    root.pushKV("stub", false);
    root.pushKV("device_id", device_id);
    root.pushKV("backend", backend_resolved);
    root.pushKV("backend_requested", args.backend);
    root.pushKV("profile", "episode");
    root.pushKV("mem_cap_bytes", args.mem_cap);
    root.pushKV("toy", args.toy);
    root.pushKV("medium", args.medium);
    root.pushKV("params", ParamsJson(params));
    root.pushKV("working_set_bytes_est", footprint);
    root.pushKV("extractmx_self_qual", qual);
    root.pushKV("phase_wall_s", walls);
    root.pushKV("k_curve", k_curve);
    root.pushKV("residency_sweep", residency);
    root.pushKV("allocation_cap_verdicts", caps);
    root.pushKV("consensus_note",
                "nMatMulRCHeight remains INT32_MAX; ENC_RC activation is NO-GO. "
                "This harness never recommends raising consensus height.");

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
