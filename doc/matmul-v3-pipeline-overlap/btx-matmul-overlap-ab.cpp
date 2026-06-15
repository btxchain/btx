// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// btx-matmul-overlap-ab: byte-exact A/B harness for the v3 nonce-seeded solver
// pipeline overlap. It solves the SAME fixed job over the SAME nonce range twice,
// once with the serial path (BTX_MATMUL_PIPELINE_ASYNC=0) and once with the
// overlap path (BTX_MATMUL_PIPELINE_ASYNC=1), collecting the full sequence of
// found (nonce64, digest) pairs each pass, and asserts the two sequences are
// IDENTICAL. Any divergence => a scheduling race (buffer reused before the GPU
// finished) and the tool exits non-zero. This is the consensus-solver gate: the
// overlap must produce the same blocks as the serial path.
//
// To produce a rich, comparable sequence in a short run, relax --nbits so the
// digest gate admits several candidates; the per-nonce v3 seed path is still
// fully exercised because --parent-mtp-seed-height / --parent-mtp / --nonce-seed
// -height / --product-digest-height are set to the real values.

#include <arith_uint256.h>
#include <chainparams.h>
#include <common/args.h>
#include <matmul/accelerated_solver.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/translation.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

struct Options {
    uint32_t n{256};
    uint32_t b{16};
    uint32_t r{8};
    uint32_t nbits{0x207fffffU}; // easy regtest-style target by default (rich finds)
    uint32_t epsilon_bits{0};
    int32_t block_height{130'500};
    uint64_t max_tries{4096};
    std::optional<int32_t> nonce_seed_height_override;
    std::optional<int32_t> parent_mtp_seed_height_override;
    std::optional<int64_t> parent_mtp_override;
    std::optional<int32_t> product_digest_height_override;
    std::optional<std::string> backend_override;
    std::optional<std::string> gpu_inputs_override;
    std::optional<std::string> batch_size_override;
    std::optional<std::string> prefetch_depth_override;
    std::optional<std::string> prepare_workers_override;
};

uint256 ParseUint256(std::string_view hex) {
    const auto parsed = uint256::FromHex(hex);
    if (!parsed.has_value()) throw std::runtime_error("invalid uint256 literal");
    return *parsed;
}

[[noreturn]] void Die(const std::string& msg) {
    std::cerr << "error: " << msg << std::endl;
    std::exit(2);
}

bool ParseU32(std::string_view v, uint32_t& out) {
    try { out = static_cast<uint32_t>(std::stoul(std::string{v}, nullptr, 0)); return true; }
    catch (...) { return false; }
}
bool ParseU64(std::string_view v, uint64_t& out) {
    try { out = static_cast<uint64_t>(std::stoull(std::string{v}, nullptr, 0)); return true; }
    catch (...) { return false; }
}
bool ParseI32(std::string_view v, int32_t& out) {
    try { out = static_cast<int32_t>(std::stol(std::string{v}, nullptr, 0)); return true; }
    catch (...) { return false; }
}
bool ParseI64(std::string_view v, int64_t& out) {
    try { out = static_cast<int64_t>(std::stoll(std::string{v}, nullptr, 0)); return true; }
    catch (...) { return false; }
}

void PrintUsage(std::ostream& os) {
    os << "btx-matmul-overlap-ab byte-exact A/B (serial vs overlap)\n"
       << "  --n --b --r --nbits --epsilon-bits --tries\n"
       << "  --block-height --nonce-seed-height --parent-mtp-seed-height --parent-mtp\n"
       << "  --product-digest-height --backend --gpu-inputs --batch-size\n"
       << "  --prefetch-depth --prepare-workers\n";
}

bool ParseArgs(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        std::string a{argv[i]};
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) Die(std::string("missing value for ") + name);
            return std::string{argv[++i]};
        };
        if (a == "--help" || a == "-h") { PrintUsage(std::cout); std::exit(0); }
        else if (a == "--n") { if (!ParseU32(next("--n"), o.n)) Die("bad --n"); }
        else if (a == "--b") { if (!ParseU32(next("--b"), o.b)) Die("bad --b"); }
        else if (a == "--r") { if (!ParseU32(next("--r"), o.r)) Die("bad --r"); }
        else if (a == "--nbits") { if (!ParseU32(next("--nbits"), o.nbits)) Die("bad --nbits"); }
        else if (a == "--epsilon-bits") { if (!ParseU32(next("--epsilon-bits"), o.epsilon_bits)) Die("bad --epsilon-bits"); }
        else if (a == "--tries") { if (!ParseU64(next("--tries"), o.max_tries)) Die("bad --tries"); }
        else if (a == "--block-height") { if (!ParseI32(next("--block-height"), o.block_height)) Die("bad --block-height"); }
        else if (a == "--nonce-seed-height") { int32_t v; if (!ParseI32(next("--nonce-seed-height"), v)) Die("bad --nonce-seed-height"); o.nonce_seed_height_override = v; }
        else if (a == "--parent-mtp-seed-height") { int32_t v; if (!ParseI32(next("--parent-mtp-seed-height"), v)) Die("bad --parent-mtp-seed-height"); o.parent_mtp_seed_height_override = v; }
        else if (a == "--parent-mtp") { int64_t v; if (!ParseI64(next("--parent-mtp"), v)) Die("bad --parent-mtp"); o.parent_mtp_override = v; }
        else if (a == "--product-digest-height") { int32_t v; if (!ParseI32(next("--product-digest-height"), v)) Die("bad --product-digest-height"); o.product_digest_height_override = v; }
        else if (a == "--backend") { o.backend_override = next("--backend"); }
        else if (a == "--gpu-inputs") { o.gpu_inputs_override = next("--gpu-inputs"); }
        else if (a == "--batch-size") { o.batch_size_override = next("--batch-size"); }
        else if (a == "--prefetch-depth") { o.prefetch_depth_override = next("--prefetch-depth"); }
        else if (a == "--prepare-workers") { o.prepare_workers_override = next("--prepare-workers"); }
        else { Die("unknown argument: " + a); }
    }
    return true;
}

// Same fixed header the solve-bench uses (deterministic seeds).
CBlockHeader BuildCandidateHeader(uint32_t n, uint32_t nbits, uint64_t nonce64) {
    CBlockHeader c{};
    c.nVersion = 1;
    c.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000011");
    c.hashMerkleRoot = ParseUint256("0000000000000000000000000000000000000000000000000000000000000022");
    c.nTime = 1'773'277'390U;
    c.nBits = nbits;
    c.nNonce64 = nonce64;
    c.nNonce = static_cast<uint32_t>(nonce64);
    c.matmul_dim = static_cast<uint16_t>(n);
    c.seed_a = ParseUint256("6410ee507c58dca3d22f950385d38fdd5fba9dd2e424b2657a2410e92d23dc63");
    c.seed_b = ParseUint256("7f165f0361461f69e2442a31fec8c26d2d95928cae37cb1673cd14fbba25f03c");
    c.matmul_digest.SetNull();
    return c;
}

struct Found { uint64_t nonce64; std::string digest; };

// Collect EVERY find across the [start, start+max_tries) nonce budget by
// repeatedly calling SolveMatMul, each time resuming past the previous find.
// This produces the full deterministic sequence the overlap must reproduce.
std::vector<Found> CollectFinds(const Options& o, const Consensus::Params& consensus) {
    std::vector<Found> finds;
    uint64_t start = 1U;
    uint64_t budget = o.max_tries;
    int safety = 0;
    while (budget > 0) {
        if (++safety > 100000) break; // hard guard
        CBlockHeader cand = BuildCandidateHeader(o.n, o.nbits, start);
        uint64_t tries = budget;
        const bool solved = SolveMatMul(
            cand, consensus, tries, o.block_height,
            /*abort=*/nullptr, /*freivalds=*/nullptr, /*share_override=*/nullptr,
            o.parent_mtp_override);
        const uint64_t consumed = (budget > tries) ? (budget - tries) : budget;
        if (solved) {
            finds.push_back(Found{cand.nNonce64, cand.matmul_digest.GetHex()});
            // Resume strictly AFTER the found nonce. SolveMatMul leaves
            // cand.nNonce64 at the winning nonce.
            const uint64_t resume = cand.nNonce64 + 1;
            if (resume <= start) break; // overflow / no progress
            // Budget shrinks by the nonces consumed up to and including the find.
            if (consumed >= budget) break;
            budget -= consumed;
            start = resume;
        } else {
            break; // exhausted budget without a (further) find
        }
    }
    return finds;
}

void SetEnv(const char* k, const char* v) {
#if defined(_WIN32)
    _putenv_s(k, v);
#else
    setenv(k, v, 1);
#endif
}

} // namespace

int main(int argc, char* argv[]) {
    Options o;
    ParseArgs(argc, argv, o);

    if (o.backend_override) SetEnv("BTX_MATMUL_BACKEND", o.backend_override->c_str());
    if (o.gpu_inputs_override) SetEnv("BTX_MATMUL_GPU_INPUTS", o.gpu_inputs_override->c_str());
    if (o.batch_size_override) SetEnv("BTX_MATMUL_SOLVE_BATCH_SIZE", o.batch_size_override->c_str());
    if (o.prefetch_depth_override) SetEnv("BTX_MATMUL_PREPARE_PREFETCH_DEPTH", o.prefetch_depth_override->c_str());
    if (o.prepare_workers_override) SetEnv("BTX_MATMUL_PREPARE_WORKERS", o.prepare_workers_override->c_str());

    ArgsManager args;
    auto consensus = CreateChainParams(args, ChainType::REGTEST)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulDimension = o.n;
    consensus.nMatMulTranscriptBlockSize = o.b;
    consensus.nMatMulNoiseRank = o.r;
    consensus.nMatMulPreHashEpsilonBits = o.epsilon_bits;
    if (o.nonce_seed_height_override) consensus.nMatMulNonceSeedHeight = *o.nonce_seed_height_override;
    if (o.parent_mtp_seed_height_override) consensus.nMatMulParentMtpSeedHeight = *o.parent_mtp_seed_height_override;
    if (o.product_digest_height_override) consensus.nMatMulProductDigestHeight = *o.product_digest_height_override;
    consensus.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    std::cout << "[ab] job: n=" << o.n << " b=" << o.b << " r=" << o.r
              << " nbits=0x" << std::hex << o.nbits << std::dec
              << " epsilon_bits=" << o.epsilon_bits
              << " height=" << o.block_height
              << " parent_mtp=" << (o.parent_mtp_override ? std::to_string(*o.parent_mtp_override) : std::string("none"))
              << " parent_mtp_seed_height=" << (o.parent_mtp_seed_height_override ? std::to_string(*o.parent_mtp_seed_height_override) : std::string("none"))
              << " nonce_seed_height=" << (o.nonce_seed_height_override ? std::to_string(*o.nonce_seed_height_override) : std::string("none"))
              << " product_digest_height=" << (o.product_digest_height_override ? std::to_string(*o.product_digest_height_override) : std::string("none"))
              << " tries=" << o.max_tries << "\n";
    std::cout << "[ab] parent_mtp_seed_active@height="
              << (consensus.IsMatMulParentMtpSeedActive(o.block_height) ? "YES(v3)" : "no")
              << " product_digest_active=" << (consensus.IsMatMulProductDigestActive(o.block_height) ? "yes" : "no")
              << "\n";

    // PASS A: serial (overlap forced OFF).
    SetEnv("BTX_MATMUL_PIPELINE_ASYNC", "0");
    std::cout << "[ab] PASS A: serial (BTX_MATMUL_PIPELINE_ASYNC=0)\n";
    const auto serial = CollectFinds(o, consensus);

    // PASS B: overlap (forced ON).
    SetEnv("BTX_MATMUL_PIPELINE_ASYNC", "1");
    std::cout << "[ab] PASS B: overlap (BTX_MATMUL_PIPELINE_ASYNC=1)\n";
    const auto overlap = CollectFinds(o, consensus);

    auto dump = [](const char* tag, const std::vector<Found>& f) {
        std::cout << "[ab] " << tag << " found " << f.size() << " nonce(s):\n";
        for (const auto& x : f) {
            std::cout << "      nonce64=" << x.nonce64 << " digest=" << x.digest << "\n";
        }
    };
    dump("serial ", serial);
    dump("overlap", overlap);

    bool identical = serial.size() == overlap.size();
    if (identical) {
        for (size_t i = 0; i < serial.size(); ++i) {
            if (serial[i].nonce64 != overlap[i].nonce64 || serial[i].digest != overlap[i].digest) {
                identical = false;
                std::cout << "[ab] DIVERGENCE at index " << i << ":\n"
                          << "      serial  nonce64=" << serial[i].nonce64 << " digest=" << serial[i].digest << "\n"
                          << "      overlap nonce64=" << overlap[i].nonce64 << " digest=" << overlap[i].digest << "\n";
                break;
            }
        }
    }

    if (serial.empty()) {
        std::cout << "[ab] WARNING: serial pass found ZERO nonces - relax --nbits so the digest "
                     "gate admits candidates, otherwise the comparison is vacuous.\n";
    }

    if (identical && !serial.empty()) {
        std::cout << "[ab] RESULT: BYTE-EXACT IDENTICAL (" << serial.size()
                  << " found nonces + digests match between serial and overlap)\n";
        return 0;
    }
    if (identical && serial.empty()) {
        std::cout << "[ab] RESULT: VACUOUS (0 == 0) - re-run with an easier target\n";
        return 3;
    }
    std::cout << "[ab] RESULT: DIVERGED - overlap is NOT byte-exact, do not deploy\n";
    return 1;
}
