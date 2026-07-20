// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_verify_bakeoff.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <sys/resource.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>

namespace matmul::v4::rc {
namespace {

uint256 Sha256dBytes(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    uint256 out;
    std::memcpy(out.data(), d2, 32);
    return out;
}

uint256 DeriveTagged(const uint256& seed, const char* tag)
{
    std::vector<unsigned char> buf;
    const size_t tag_len = std::strlen(tag);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tag),
               reinterpret_cast<const unsigned char*>(tag) + tag_len);
    buf.insert(buf.end(), seed.begin(), seed.end());
    return Sha256dBytes(buf.data(), buf.size());
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
    struct rusage ru {};
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
#if defined(__APPLE__)
        return static_cast<size_t>(ru.ru_maxrss / 1024);
#else
        return static_cast<size_t>(ru.ru_maxrss); // KiB on Linux
#endif
    }
    return 0;
}

class ScopedWall {
public:
    void Start() { m_t0 = std::chrono::steady_clock::now(); }
    double StopS() const
    {
        const auto t1 = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(t1 - m_t0).count();
    }

private:
    std::chrono::steady_clock::time_point m_t0{};
};

uint256 FsChallenge(const uint256& transcript, uint32_t round)
{
    unsigned char buf[32 + 4];
    std::memcpy(buf, transcript.data(), 32);
    WriteLE32(buf + 32, round);
    return Sha256dBytes(buf, sizeof(buf));
}

/** Educational "sumcheck" fold: reduce segs with FS random linear combo. */
int64_t FoldSegEval(const std::vector<std::vector<int64_t>>& segs, size_t elem,
                    const std::vector<uint256>& challenges)
{
    // Start with per-segment values at a fixed matrix element.
    std::vector<int64_t> vals;
    vals.reserve(segs.size());
    for (const auto& s : segs) {
        vals.push_back(s[elem]);
    }
    uint32_t round = 0;
    while (vals.size() > 1) {
        if (vals.size() % 2 == 1) vals.push_back(0);
        std::vector<int64_t> nxt;
        nxt.reserve(vals.size() / 2);
        const uint256& ch = challenges[std::min<size_t>(round, challenges.size() - 1)];
        // Use low 32 bits as a tiny multiplier in [1, 16] — educational only.
        const uint32_t r = (ReadLE32(ch.data()) % 15u) + 1u;
        for (size_t i = 0; i < vals.size(); i += 2) {
            nxt.push_back(vals[i] + static_cast<int64_t>(r) * vals[i + 1]);
        }
        vals = std::move(nxt);
        ++round;
    }
    return vals.empty() ? 0 : vals[0];
}

size_t ProofBytesB(const ToyGkrProof& p)
{
    return p.claimed_sum.size() * 8 + p.claimed_extract.size() +
           p.fs_challenges.size() * 32 + p.round_evals.size() * 8 + 32;
}

} // namespace

BakeoffAResult BakeoffA_ExactReplay(const CBlockHeader& header, const RCEpisodeParams& params,
                                    int32_t height)
{
    // E1: this IS the sole ε=0 consensus shape (wrapped for measurement only).
    BakeoffAResult out;
    const size_t rss0 = CurrentRssKiB();
    ScopedWall wall;
    wall.Start();
    out.digest = RecomputeResidentCurriculumReference(header, params, height);
    out.timing.wall_s = wall.StopS();
    out.timing.verify_s = out.timing.wall_s; // verify == full replay
    out.timing.rss_kib = std::max(CurrentRssKiB(), rss0);
    out.timing.proof_bytes = 0; // no proof — recompute is the check
    out.timing.ok = !out.digest.IsNull();
    out.timing.note = "E3-A exact RecomputeResidentCurriculumReference (ε=0 baseline)";
    return out;
}

BakeoffBResult BakeoffB_ToyGkrSumcheck(const uint256& seed, const DistSynthShape& shape)
{
    BakeoffBResult out;
    ScopedWall wall;
    wall.Start();

    std::vector<int8_t> A, B;
    ExpandSynthOperands(seed, shape, A, B);
    auto parts = SimulateDevices(A, B, shape, /*n_devices=*/1);
    const auto sum = SumSegmentPartials(parts.segs);
    const uint256 seed_extract = DeriveTagged(seed, "BTX_RC_DIST_EXTRACT_V1");
    auto extracted = ExtractOnce(seed_extract, sum, shape.m, shape.n);

    // Transcript commit over segment LE bytes (toy).
    std::vector<unsigned char> tbuf;
    static constexpr char kTag[] = "BTX_RC_TOY_GKR_V1";
    tbuf.insert(tbuf.end(), reinterpret_cast<const unsigned char*>(kTag),
                reinterpret_cast<const unsigned char*>(kTag) + sizeof(kTag) - 1);
    for (const auto& seg : parts.segs) {
        for (int64_t v : seg) {
            unsigned char b[8];
            WriteLE64(b, static_cast<uint64_t>(v));
            tbuf.insert(tbuf.end(), b, b + 8);
        }
    }
    out.proof.transcript_commit = Sha256dBytes(tbuf.data(), tbuf.size());

    // Fiat–Shamir challenges (SHA256) — NOT production Poseidon/FRI.
    const uint32_t n_rounds = 4;
    out.proof.fs_challenges.reserve(n_rounds);
    uint256 cur = out.proof.transcript_commit;
    for (uint32_t r = 0; r < n_rounds; ++r) {
        cur = FsChallenge(cur, r);
        out.proof.fs_challenges.push_back(cur);
    }

    // Educational evaluations at a few matrix elements.
    for (size_t elem : {size_t{0}, size_t{17}, size_t{31 * 32 + 7}}) {
        if (elem < sum.size()) {
            out.proof.round_evals.push_back(
                FoldSegEval(parts.segs, elem, out.proof.fs_challenges));
        }
    }

    out.proof.claimed_sum = sum;
    out.proof.claimed_extract = extracted;

    // Table-lookup check for Extract: recompute ExtractMX and MixBits path.
    const auto recomputed = ExtractOnce(seed_extract, sum, shape.m, shape.n);
    out.proof.extract_in_table = (recomputed == extracted);

    out.prove.wall_s = wall.StopS();
    out.prove.proof_bytes = ProofBytesB(out.proof);
    out.prove.rss_kib = CurrentRssKiB();
    out.prove.ok = out.proof.extract_in_table;
    out.prove.note = "E3-B toy GKR/sumcheck-shaped prove (SHA256 FS; NOT production crypto)";

    // Verify: re-fold evals + re-Extract.
    ScopedWall vwall;
    vwall.Start();
    bool ok = out.proof.extract_in_table;
    const auto vsum = SumSegmentPartials(parts.segs);
    ok = ok && (vsum == out.proof.claimed_sum);
    const auto vext = ExtractOnce(seed_extract, vsum, shape.m, shape.n);
    ok = ok && (vext == out.proof.claimed_extract);
    for (size_t i = 0; i < out.proof.round_evals.size(); ++i) {
        static const size_t elems[] = {0, 17, 31 * 32 + 7};
        if (elems[i] >= vsum.size()) continue;
        const int64_t ev = FoldSegEval(parts.segs, elems[i], out.proof.fs_challenges);
        ok = ok && (ev == out.proof.round_evals[i]);
    }
    out.verify.verify_s = vwall.StopS();
    out.verify.wall_s = out.verify.verify_s;
    out.verify.proof_bytes = out.prove.proof_bytes;
    out.verify.rss_kib = CurrentRssKiB();
    out.verify.ok = ok;
    out.verify.note = "E3-B verify: sumcheck evals + Extract table match";
    return out;
}

StarkAirFriSketch BakeoffC_StarkStub()
{
    StarkAirFriSketch s;
    s.implemented = false;
    s.reason =
        "STARK/AIR+FRI not fully implemented: would require a finite-field AIR for "
        "int64 GEMM + non-affine ExtractMX (lookup/permutation args), FRI commitment "
        "scheme, and soundness analysis under SHA256 Fiat–Shamir. Out of scope for "
        "Stage E toy bake-off; interface reserved for a future research spike. "
        "Even a complete STARK would change ε=0 to computational soundness (E6) and "
        "is NOT a drop-in for CheckMatMulProofOfWork_RC without a consensus fork.";
    s.estimated_proof_bytes_toy = 0;
    return s;
}

BakeoffDResult BakeoffD_FraudProofSketch(const uint256& seed, const DistSynthShape& shape,
                                         uint32_t challenged_segment, bool inject_fault)
{
    BakeoffDResult out;
    ScopedWall wall;
    wall.Start();

    std::vector<int8_t> A, B;
    ExpandSynthOperands(seed, shape, A, B);
    auto parts = SimulateDevices(A, B, shape, /*n_devices=*/1);
    const uint32_t n_segs = static_cast<uint32_t>(parts.segs.size());
    assert(n_segs > 0);
    const uint32_t sid = challenged_segment % n_segs;

    out.sketch.challenged_segment = sid;
    out.sketch.recomputed_partial = parts.segs[sid];
    out.sketch.claimed_partial = parts.segs[sid];
    if (inject_fault && !out.sketch.claimed_partial.empty()) {
        out.sketch.claimed_partial[0] += 1; // corrupt one limb
    }
    out.sketch.mismatch = (out.sketch.claimed_partial != out.sketch.recomputed_partial);

    const auto honest = RunSyntheticDistributed(seed, shape, 1, DistReduceOrder::TreeLeftToRight);
    out.sketch.honest_digest = honest.digest;
    out.sketch.claimed_digest = honest.digest;
    if (inject_fault) {
        // Claimed digest would differ if miner committed the bad partial.
        auto bad_segs = parts.segs;
        bad_segs[sid] = out.sketch.claimed_partial;
        const auto bad_sum = SumSegmentPartials(bad_segs);
        const uint256 seed_extract = DeriveTagged(seed, "BTX_RC_DIST_EXTRACT_V1");
        auto bad_ext = ExtractOnce(seed_extract, bad_sum, shape.m, shape.n);
        out.sketch.claimed_digest = DigestSyntheticDistributed(shape, bad_segs, bad_ext);
    }

    out.sketch.fork_requirements =
        "Fraud-proof completion requires a SEPARATE consensus fork from today's "
        "digest-only full-recompute path: (1) challenge window (timeout → invalidate "
        "or force full recompute); (2) data-availability for segment bodies / Merkle "
        "openings; (3) bonds / slash for unanswered or failed challenges; "
        "(4) in-block round_roots (see P2.1 §2). DO NOT bolt this sketch onto "
        "CheckMatMulProofOfWork_RC without that fork. Sampling with q=8 remains a "
        "DoS prefilter only (E2), never sole validity.";

    // Spot-check prefilter: open one leaf of the synthetic transcript via FS.
    // For the toy we just check segment recompute matches when no fault.
    out.spot_check_prefilter_ok = !out.sketch.mismatch;

    out.timing.wall_s = wall.StopS();
    out.timing.verify_s = out.timing.wall_s;
    out.timing.rss_kib = CurrentRssKiB();
    out.timing.proof_bytes =
        out.sketch.claimed_partial.size() * 8 + out.sketch.recomputed_partial.size() * 8 + 64;
    out.timing.ok = inject_fault ? out.sketch.mismatch : !out.sketch.mismatch;
    out.timing.note = inject_fault ? "E3-D fraud sketch caught injected fault"
                                   : "E3-D honest challenged-segment recompute";
    return out;
}

std::string RunBakeoffReport(const CBlockHeader& header, const RCEpisodeParams& toy_params,
                             const uint256& synth_seed)
{
    std::ostringstream os;
    os << "{\n";
    os << "  \"stage\": \"E\",\n";
    os << "  \"toy_only\": true,\n";
    os << "  \"e1\": \"full_exact_streamed_replay_sole_eps0_consensus\",\n";
    os << "  \"e2\": \"merkle_q8_dos_prefilter_only_never_o1_verify\",\n";

    const auto a = BakeoffA_ExactReplay(header, toy_params, 0);
    os << "  \"A_exact_replay\": {\n";
    os << "    \"wall_s\": " << a.timing.wall_s << ",\n";
    os << "    \"rss_kib\": " << a.timing.rss_kib << ",\n";
    os << "    \"proof_bytes\": " << a.timing.proof_bytes << ",\n";
    os << "    \"ok\": " << (a.timing.ok ? "true" : "false") << ",\n";
    os << "    \"digest\": \"" << a.digest.GetHex() << "\"\n";
    os << "  },\n";

    DistSynthShape shape{32, 32, 128, 32};
    const auto b = BakeoffB_ToyGkrSumcheck(synth_seed, shape);
    os << "  \"B_toy_gkr\": {\n";
    os << "    \"prove_wall_s\": " << b.prove.wall_s << ",\n";
    os << "    \"verify_s\": " << b.verify.verify_s << ",\n";
    os << "    \"proof_bytes\": " << b.prove.proof_bytes << ",\n";
    os << "    \"rss_kib\": " << b.prove.rss_kib << ",\n";
    os << "    \"extract_in_table\": " << (b.proof.extract_in_table ? "true" : "false") << ",\n";
    os << "    \"ok\": " << (b.verify.ok ? "true" : "false") << "\n";
    os << "  },\n";

    const auto c = BakeoffC_StarkStub();
    os << "  \"C_stark_stub\": {\n";
    os << "    \"implemented\": " << (c.implemented ? "true" : "false") << ",\n";
    os << "    \"reason_code\": \"air_fri_out_of_scope_toy_stage_e\"\n";
    os << "  },\n";

    const auto d_ok = BakeoffD_FraudProofSketch(synth_seed, shape, 1, /*inject_fault=*/false);
    const auto d_bad = BakeoffD_FraudProofSketch(synth_seed, shape, 1, /*inject_fault=*/true);
    os << "  \"D_fraud_sketch\": {\n";
    os << "    \"honest_ok\": " << (d_ok.timing.ok ? "true" : "false") << ",\n";
    os << "    \"fault_detected\": " << (d_bad.sketch.mismatch ? "true" : "false") << ",\n";
    os << "    \"wall_s\": " << d_ok.timing.wall_s << ",\n";
    os << "    \"proof_bytes\": " << d_ok.timing.proof_bytes << ",\n";
    os << "    \"spot_check_prefilter_ok\": "
       << (d_ok.spot_check_prefilter_ok ? "true" : "false") << ",\n";
    os << "    \"fork_required\": true\n";
    os << "  },\n";

    os << RunWinnerGkrBakeoffSection(synth_seed, shape);
    os << ",\n";
    os << "  \"e5_direction\": \"DECIDED\",\n";
    os << "  \"e5_path\": \"winner_only_gkr_sumcheck\",\n";
    os << "  \"e5_decision\": \"" << kRCGkrE5Decision << "\",\n";
    os << "  \"e6\": \"gkr_computational_soundness__fraud_proofs_deferred__eps0_replay_until_stage_i\",\n";
    os << "  \"production_extrapolation\": \"NOT_EVIDENCE\"\n";
    os << "}\n";
    return os.str();
}

} // namespace matmul::v4::rc
