// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_gemm_sumcheck_binding.h>

#include <matmul/matmul_v4_rc_air_quotient.h>

#include <hash.h>

#include <cstring>

namespace matmul::v4::rc {

namespace {

namespace gf = gkr_field;
namespace ah = alg_hash;
namespace aq = air_quotient;

using gf::Fp;
using gf::Fp3;

// --- Fp3 helpers ----------------------------------------------------------

[[nodiscard]] Fp3 F3(uint64_t x) { return gf::FromU64_3(x); }

[[nodiscard]] bool Eq3(const Fp3& a, const Fp3& b)
{
    return gf::Canonical(a.c0) == gf::Canonical(b.c0) &&
           gf::Canonical(a.c1) == gf::Canonical(b.c1) &&
           gf::Canonical(a.c2) == gf::Canonical(b.c2);
}

// Evaluate the degree-2 polynomial through (0,g0),(1,g1),(2,g2) at r
// (Lagrange-from-3-points).  L0=(r-1)(r-2)/2, L1=-r(r-2), L2=r(r-1)/2.
[[nodiscard]] Fp3 Lagrange3(const Fp3& g0, const Fp3& g1, const Fp3& g2,
                            const Fp3& r)
{
    const Fp3 inv2 = gf::Inv(F3(2));
    const Fp3 rm1 = gf::Sub(r, F3(1));
    const Fp3 rm2 = gf::Sub(r, F3(2));
    const Fp3 l0 = gf::Mul(gf::Mul(rm1, rm2), inv2);
    const Fp3 l1 = gf::Sub(F3(0), gf::Mul(r, rm2)); // -(r)(r-2)
    const Fp3 l2 = gf::Mul(gf::Mul(r, rm1), inv2);
    return gf::Add(gf::Add(gf::Mul(g0, l0), gf::Mul(g1, l1)), gf::Mul(g2, l2));
}

// --- alg-hash fold helpers -----------------------------------------------

[[nodiscard]] uint256 DigestToUint256(const ah::Digest& d)
{
    uint256 out;
    unsigned char* p = out.begin();
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        const uint64_t lane = static_cast<uint64_t>(gf::Canonical(d[i]));
        std::memcpy(p + i * 8, &lane, 8);
    }
    return out;
}

// Per-round leaf: binds layer, round index, the degree-2 message and r_k.
[[nodiscard]] ah::Digest RoundLeaf(uint32_t layer_ordinal, uint32_t k,
                                   const RCStage3GemmSumcheckRound& rd)
{
    std::vector<Fp3> row;
    row.push_back(F3(layer_ordinal));
    row.push_back(F3(k));
    row.push_back(rd.g0);
    row.push_back(rd.g1);
    row.push_back(rd.g2);
    row.push_back(rd.r);
    return ah::LeafHashRow(row, k);
}

// FS pre-leaf: binds layer, round index and the degree-2 message ONLY (no r_k),
// so it can be absorbed to DERIVE r_k without circularity.
[[nodiscard]] ah::Digest FsPreLeaf(uint32_t layer_ordinal, uint32_t k,
                                   const Fp3& g0, const Fp3& g1, const Fp3& g2)
{
    std::vector<Fp3> row;
    row.push_back(F3(layer_ordinal));
    row.push_back(F3(k));
    row.push_back(g0);
    row.push_back(g1);
    row.push_back(g2);
    return ah::LeafHashRow(row, k);
}

// Running alg-hash sponge FS transcript.  Domain-separated in a capacity lane;
// one Poseidon2 permutation absorbs each round's pre-leaf digest and squeezes
// r_k = (state[0],state[1],state[2]).
class SumcheckFsSponge
{
public:
    explicit SumcheckFsSponge(uint32_t layer_ordinal)
    {
        const auto& c = ah::GetAlgHashConstants();
        m_state.fill(0);
        // Capacity lanes carry the leaf domain plus a sumcheck-FS tag and the
        // layer ordinal, giving cross-domain and per-layer separation.
        m_state[ah::kAlgHashRate + 0] = c.leaf_domain;
        m_state[ah::kAlgHashRate + 1] =
            gf::FromU64(0x53554d43'4845434bULL); // "SUMCHECK"
        m_state[ah::kAlgHashRate + 2] = gf::FromU64(layer_ordinal);
    }

    [[nodiscard]] Fp3 AbsorbAndSqueeze(const ah::Digest& pre_leaf)
    {
        for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
            m_state[i] = gf::Add(m_state[i], pre_leaf[i]);
        }
        ah::Permute(m_state);
        return Fp3{gf::Canonical(m_state[0]), gf::Canonical(m_state[1]),
                   gf::Canonical(m_state[2])};
    }

private:
    ah::State m_state{};
};

// --- In-AIR discharge of families (i)-(iii) ------------------------------
//
// Columns (Fp3): 0=claim, 1=g0, 2=g1, 3=g2, 4=r.  Row 0 pins claim_0; rows
// 1..kappa carry the messages and challenges; claim_j = g_j(r_j).  N=kappa+1
// (caller supplies a power-of-two round count).
enum { kColClaim = 0, kColG0 = 1, kColG1 = 2, kColG2 = 3, kColR = 4, kNCols = 5 };

[[nodiscard]] Fp3 Lagrange3Cols(const std::vector<Fp3>& c)
{
    return Lagrange3(c[kColG0], c[kColG1], c[kColG2], c[kColR]);
}

[[nodiscard]] bool BuildAndProveSumcheckAir(
    const RCStage3GemmSumcheckLayerTranscript& t, const Fp3& terminal,
    const uint256& seed, bool& proved, bool& verified, std::string* why)
{
    const uint32_t kappa = static_cast<uint32_t>(t.rounds.size());
    const uint32_t n_rows = kappa + 1;
    if ((n_rows & (n_rows - 1)) != 0 || n_rows < 2) {
        if (why != nullptr) *why = "sumcheck_air:rows_not_pow2";
        return false;
    }

    const Fp3 claim0 = t.initial_claim;

    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = n_rows;
    cs.n_columns = kNCols;

    // (ii) initial claim: claim[0] == claim_0.
    cs.constraints.push_back(
        {"initial_claim", aq::AirKind::kFirstRow, 1,
         [claim0](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
             return gf::Sub(cur[kColClaim], claim0);
         }});
    // (i) chaining: next.g0 + next.g1 - cur.claim == 0 (rows 0..N-2).
    cs.constraints.push_back(
        {"chaining", aq::AirKind::kTransition, 1,
         [](const std::vector<Fp3>& cur, const std::vector<Fp3>& next) {
             return gf::Sub(gf::Add(next[kColG0], next[kColG1]), cur[kColClaim]);
         }});
    // (i) claim update: next.claim - g_next(r_next) == 0 (rows 0..N-2).
    cs.constraints.push_back(
        {"claim_update", aq::AirKind::kTransition, 3,
         [](const std::vector<Fp3>& cur, const std::vector<Fp3>& next) {
             (void)cur;
             return gf::Sub(next[kColClaim], Lagrange3Cols(next));
         }});
    // (iii) terminal: claim[N-1] - a_eval*b_eval == 0.
    cs.constraints.push_back(
        {"terminal", aq::AirKind::kLastRow, 1,
         [terminal](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
             return gf::Sub(cur[kColClaim], terminal);
         }});

    // Witness columns.
    std::vector<std::vector<Fp3>> cols(kNCols, std::vector<Fp3>(n_rows));
    // Row 0: initial claim; dummy self-consistent message (never a transition
    // "next", so its message is unconstrained; keep it inert).
    cols[kColClaim][0] = claim0;
    cols[kColG0][0] = claim0;
    cols[kColG1][0] = F3(0);
    cols[kColG2][0] = F3(0);
    cols[kColR][0] = F3(0);
    Fp3 claim = claim0;
    for (uint32_t k = 1; k <= kappa; ++k) {
        const auto& rd = t.rounds[k - 1];
        cols[kColG0][k] = rd.g0;
        cols[kColG1][k] = rd.g1;
        cols[kColG2][k] = rd.g2;
        cols[kColR][k] = rd.r;
        claim = Lagrange3(rd.g0, rd.g1, rd.g2, rd.r);
        cols[kColClaim][k] = claim;
    }

    const auto pr = aq::AirQuotientProve<Fp3>(cs, cols, seed);
    proved = pr.ok && pr.division_exact;
    if (!proved) {
        verified = false;
        if (why != nullptr) *why = "sumcheck_air:division_not_exact";
        return true; // built ok; proof rejected (expected under tamper)
    }
    std::string vwhy;
    verified = aq::AirQuotientVerify<Fp3>(cs, pr.proof, seed, &vwhy);
    if (!verified && why != nullptr) *why = "sumcheck_air:verify:" + vwhy;
    return true;
}

[[nodiscard]] uint256 SumcheckAirSeed(uint32_t layer_ordinal,
                                      const uint256& sumcheck_root)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_GEMM_SUMCHECK_AIR_V1";
    hash << kRCStage3GemmSumcheckBindingVersion;
    hash << layer_ordinal;
    hash << sumcheck_root;
    return hash.GetHash();
}

} // namespace

uint256 ComputeRCStage3GemmSumcheckRoot(
    const RCStage3GemmSumcheckLayerTranscript& transcript)
{
    if (transcript.rounds.empty()) return uint256{};
    ah::Digest acc = RoundLeaf(transcript.layer_ordinal, 1, transcript.rounds[0]);
    for (uint32_t k = 2; k <= transcript.rounds.size(); ++k) {
        const ah::Digest leaf =
            RoundLeaf(transcript.layer_ordinal, k, transcript.rounds[k - 1]);
        acc = ah::Compress(acc, leaf);
    }
    return DigestToUint256(acc);
}

RCStage3GemmSumcheckLayerTranscript
BuildRCStage3HonestGemmSumcheckLayerTranscript(uint32_t layer_ordinal,
                                               uint32_t k_log2, uint64_t seed)
{
    RCStage3GemmSumcheckLayerTranscript t;
    t.layer_ordinal = layer_ordinal;

    auto derive = [&](uint64_t salt) -> Fp3 {
        HashWriter h;
        h << "BTX_RC_SUMCHECK_HONEST_V1";
        h << layer_ordinal << k_log2 << seed << salt;
        const uint256 d = h.GetHash();
        uint64_t a, b, c;
        std::memcpy(&a, d.begin() + 0, 8);
        std::memcpy(&b, d.begin() + 8, 8);
        std::memcpy(&c, d.begin() + 16, 8);
        return Fp3{gf::FromU64(a), gf::FromU64(b), gf::FromU64(c)};
    };

    t.initial_claim = derive(0xA11);
    Fp3 claim = t.initial_claim;

    SumcheckFsSponge fs(layer_ordinal);
    for (uint32_t k = 1; k <= k_log2; ++k) {
        RCStage3GemmSumcheckRound rd;
        rd.g0 = derive(0x100 + 2 * k);
        rd.g2 = derive(0x100 + 2 * k + 1);
        // Chaining: g0 + g1 = claim_{k-1}  =>  g1 = claim - g0.
        rd.g1 = gf::Sub(claim, rd.g0);
        // FS challenge from the pre-leaf digest (no r yet).
        const ah::Digest pre = FsPreLeaf(layer_ordinal, k, rd.g0, rd.g1, rd.g2);
        rd.r = fs.AbsorbAndSqueeze(pre);
        claim = Lagrange3(rd.g0, rd.g1, rd.g2, rd.r);
        t.rounds.push_back(rd);
    }
    // Terminal: a_eval*b_eval = claim_kappa.  Choose a_eval=1, b_eval=claim.
    t.a_eval = Fp3::One();
    t.b_eval = claim;
    return t;
}

bool VerifyRCStage3GemmSumcheckAlgBinding(
    const RCStage3GemmSumcheckLayerTranscript& transcript,
    const gf::Fp3& y_claim, const uint256& committed_sumcheck_commitment,
    RCStage3GemmSumcheckAlgBindingResult& out, std::string* why)
{
    out = RCStage3GemmSumcheckAlgBindingResult{};
    out.k_log2 = static_cast<uint32_t>(transcript.rounds.size());
    out.a_eval = transcript.a_eval;
    out.b_eval = transcript.b_eval;

    if (transcript.rounds.empty() ||
        transcript.rounds.size() > kRCStage3GemmSumcheckMaxRounds) {
        out.note = "bad_round_count";
        if (why != nullptr) *why = "gemm_sumcheck:bad_round_count";
        return false;
    }

    // (ii) initial claim pinned to the endpoint-7 MLE(Y) value.
    out.initial_claim_ok = Eq3(transcript.initial_claim, y_claim);

    // (i) chaining + claim recurrence over every round (native).
    out.chaining_ok = true;
    Fp3 claim = transcript.initial_claim;
    for (uint32_t k = 1; k <= transcript.rounds.size(); ++k) {
        const auto& rd = transcript.rounds[k - 1];
        if (!Eq3(gf::Add(rd.g0, rd.g1), claim)) {
            out.chaining_ok = false;
            break;
        }
        claim = Lagrange3(rd.g0, rd.g1, rd.g2, rd.r);
    }
    const Fp3 claim_last = claim;

    // (iii) terminal: claim_kappa == a_eval * b_eval.
    out.terminal_ok = out.chaining_ok &&
                      Eq3(claim_last, gf::Mul(transcript.a_eval, transcript.b_eval));

    // (iv) challenge honesty: r_k == alg-hash sponge FS(prefix).
    out.challenge_fs_ok = true;
    {
        SumcheckFsSponge fs(transcript.layer_ordinal);
        for (uint32_t k = 1; k <= transcript.rounds.size(); ++k) {
            const auto& rd = transcript.rounds[k - 1];
            const ah::Digest pre =
                FsPreLeaf(transcript.layer_ordinal, k, rd.g0, rd.g1, rd.g2);
            const Fp3 r_expected = fs.AbsorbAndSqueeze(pre);
            if (!Eq3(r_expected, rd.r)) {
                out.challenge_fs_ok = false;
                break;
            }
        }
    }

    // Alg fold + obligation pin.
    out.sumcheck_root = ComputeRCStage3GemmSumcheckRoot(transcript);
    out.fold_root_pinned = (out.sumcheck_root == committed_sumcheck_commitment);

    // In-AIR discharge of (i)-(iii).
    const Fp3 terminal = gf::Mul(transcript.a_eval, transcript.b_eval);
    const uint256 seed =
        SumcheckAirSeed(transcript.layer_ordinal, out.sumcheck_root);
    std::string air_why;
    (void)BuildAndProveSumcheckAir(transcript, terminal, seed, out.air_proved,
                                   out.air_verified, &air_why);

    out.binding_complete = out.initial_claim_ok && out.chaining_ok &&
                           out.terminal_ok && out.challenge_fs_ok &&
                           out.air_proved && out.air_verified &&
                           out.fold_root_pinned;
    if (out.binding_complete) {
        out.note = "binding_complete";
    } else if (!out.initial_claim_ok) {
        out.note = "initial_claim_mismatch";
    } else if (!out.chaining_ok) {
        out.note = "chaining_violation";
    } else if (!out.terminal_ok) {
        out.note = "terminal_violation";
    } else if (!out.challenge_fs_ok) {
        out.note = "fs_challenge_inconsistent";
    } else if (!out.fold_root_pinned) {
        out.note = "sumcheck_root_unpinned";
    } else {
        out.note = "air_rejected:" + air_why;
    }
    if (why != nullptr) *why = "gemm_sumcheck:" + out.note;
    return out.binding_complete;
}

RCStage3GemmSumcheckSemanticPin RCStage3GemmSumcheckWireSemanticPin(
    const RCStage3GemmSumcheckAlgBindingResult& result)
{
    RCStage3GemmSumcheckSemanticPin pin;
    pin.semantic_relation_complete = result.binding_complete;
    pin.sumcheck_root = result.sumcheck_root;
    pin.note = result.note;
    return pin;
}

} // namespace matmul::v4::rc
