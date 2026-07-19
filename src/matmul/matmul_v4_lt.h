// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_LT_H
#define BTX_MATMUL_MATMUL_V4_LT_H

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <string_view>
#include <utility>
#include <vector>

// ENC-DR-LT / MatMul v4.4-LT — Rank-1 package (MatExpand + deep-m + Q*).
// Normative: doc/btx-matmul-v4.4-lt-normative-spec.md
// Activation: Consensus::Params::nMatMulDRLTHeight (default INT32_MAX).

namespace matmul::v4::lt {

using int8_field::Fq;

inline constexpr uint32_t kTileBLT = 2;
inline constexpr uint32_t kMatExpandPanelW = 128;
inline constexpr int32_t kMatExpandEmax = 48;
inline constexpr uint32_t kConsensusQStarDefault = 64;
inline constexpr uint32_t kConsensusQStarMax = 128;

[[nodiscard]] inline bool IsValidConsensusQStar(uint32_t q_star)
{
    return q_star == kConsensusQStarDefault || q_star == kConsensusQStarMax;
}

[[nodiscard]] int32_t FoldInt32ToEmax48(int32_t y);

/** Position-salted SplitMix64 avalanche (MatExpand C-15 non-collapse).
 *  Pure integer; identical on every backend. */
[[nodiscard]] uint64_t MixMatExpandEntry(int32_t raw, uint32_t i, uint32_t j, uint64_t salt);

/** Nonlinear map raw → dequantized int8 in [-48,48]: M11 rejection sample
 *  from Mix stream + E8M0-style scale e∈{0..3}, value = mu<<e.
 *  NOT an affine function of `raw` — blocks Freivalds reassociation shortcuts. */
[[nodiscard]] int8_t ExtractDequantMatExpand(int32_t raw, uint32_t i, uint32_t j, uint64_t salt);

[[nodiscard]] std::vector<int32_t> ExactGemmS8S8(const std::vector<int8_t>& L,
                                                 const std::vector<int8_t>& R,
                                                 uint32_t rows, uint32_t inner, uint32_t cols);
[[nodiscard]] std::vector<int32_t> ExactGemmS32S8(const std::vector<int32_t>& L,
                                                  const std::vector<int8_t>& R,
                                                  uint32_t rows, uint32_t inner, uint32_t cols);

/** Injectable exact-GEMM backend for MatExpand operand GEMMs (G*W and (G*W)*H).
 *  Null function pointers ⇒ CPU ExactGemm*. Non-null backends MUST be
 *  bit-identical to ExactGemm* (self-test before advertising availability).
 *  Consensus ComputeDigestBMX4CLT defaults to CPU; miners inject a backend
 *  into ExpandOperand* / WindowSketchMinerLT for throughput. */
struct ExactGemmBackend {
    using S8S8Fn = bool (*)(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                            uint32_t rows, uint32_t inner, uint32_t cols,
                            std::vector<int32_t>& out);
    using S32S8Fn = bool (*)(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                             uint32_t rows, uint32_t inner, uint32_t cols,
                             std::vector<int32_t>& out);
    S8S8Fn gemm_s8s8{nullptr};
    S32S8Fn gemm_s32s8{nullptr};

    [[nodiscard]] bool HasDeviceGemms() const
    {
        return gemm_s8s8 != nullptr && gemm_s32s8 != nullptr;
    }
};

[[nodiscard]] std::vector<int8_t> ExpandOperandAMatExpand(const CBlockHeader& header, uint32_t n);
[[nodiscard]] std::vector<int8_t> ExpandOperandAMatExpand(const CBlockHeader& header, uint32_t n,
                                                          const ExactGemmBackend& backend);
[[nodiscard]] std::vector<int8_t> ExpandOperandBMatExpand(const CBlockHeader& header, uint32_t n);
[[nodiscard]] std::vector<int8_t> ExpandOperandBMatExpand(const CBlockHeader& header, uint32_t n,
                                                          const ExactGemmBackend& backend);

[[nodiscard]] std::pair<uint256, uint256> DeriveProjectorSeedsBMX4CLT(const CBlockHeader& header);

[[nodiscard]] bool ValidateDimsBMX4CLT(uint32_t n, uint32_t& m_out);
[[nodiscard]] bool ComputeDigestBMX4CLT(const CBlockHeader& header, uint32_t n,
                                        uint256& digest_out,
                                        std::vector<unsigned char>& payload_out);
[[nodiscard]] bool ComputeDigestBMX4CLT(const CBlockHeader& header, uint32_t n,
                                        const ExactGemmBackend& backend,
                                        uint256& digest_out,
                                        std::vector<unsigned char>& payload_out);
[[nodiscard]] bool VerifySketchBMX4CLT(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                       const std::vector<unsigned char>& payload,
                                       uint256& digest_out);

struct WindowSlot {
    uint64_t nonce{0};
    uint256 digest;
};

[[nodiscard]] uint256 ComputeWindowMerkleRoot(Span<const uint256> digests);
[[nodiscard]] uint256 SealWindowCommit(const uint256& sigma_anchor,
                                       const uint256& merkle_root, uint32_t Qstar);
/** TEST/DIAGNOSTIC ONLY — does NOT prove Q* window membership.
 *
 *  Reconstructs digests from caller-supplied slot nonces without re-deriving
 *  expected nonces from sigma_anchor, without SlotSeedFn / parent MTP, and
 *  without checking seal order or uniqueness. Unused in production validation.
 *  Prefer VerifySealWindowFreivalds / SealWindowProofMatchesCommitment. */
[[nodiscard]] bool VerifyWindowSlotFreivalds(const CBlockHeader& tmpl, uint32_t n,
                                             const std::vector<WindowSlot>& slots, uint32_t r);

// ---------------------------------------------------------------------------
// Q* Phase B — SEAL-AS-PoW (doc/btx-matmul-v4.4-lt-normative-spec.md "Q* window";
// doc/btx-matmul-v4.4-lt-adversarial-analysis.md "Phase B"). Implemented and
// unit-tested, but INERT on every public network (gated behind
// Consensus::Params::IsMatMulLTSealAsPoWActive, which requires the still-
// INT32_MAX nMatMulDRLTHeight). In seal mode the header's lottery object is not
// the per-nonce ENC-DR-LT digest but the WINDOW SEAL binding a full Q* window of
// sibling-nonce digests:
//
//   matmul_digest := SealWindowCommit(sigma_anchor, Merkle(slot digests), Q*)
//
// where sigma_anchor = DeriveSigma(anchor), slot j has nonce
// DeriveWindowSlotNonce(sigma_anchor, j) with the consensus V3 (parent-MTP-
// bound) seed_a/seed_b pinned onto it (SlotSeedFn — threads LT-Q2), and each
// slot digest is the Phase-A ENC-DR-LT digest ComputeDigestBMX4CLT(slot header)
// = H(sigma_slot || Chat_slot).
// ---------------------------------------------------------------------------

/** Deterministic per-anchor window-slot nonce for slot `slot_index`
 *  (SHA256("BTX_QSTAR_SLOT_V44LT" ‖ sigma_anchor ‖ slot_index LE32), low 64
 *  bits LE). Pseudo-random per anchor so distinct anchors' windows are disjoint
 *  nonce sets: a miner cannot amortize one nonce's digest across many anchors'
 *  windows, so evaluating the seal genuinely costs Q* fresh digests (the
 *  fat-window enforcement, adversarial LT-Q1). */
[[nodiscard]] uint64_t DeriveWindowSlotNonce(const uint256& sigma_anchor, uint32_t slot_index);

/** Callback that pins the consensus-correct seed_a/seed_b onto a window-slot
 *  header whose nNonce64/nNonce are already set to the slot nonce. The caller
 *  binds the params/height/parent-MTP and typically wraps
 *  SetDeterministicMatMulSeeds, so every sibling slot re-derives its V3 seeds
 *  under the SAME parent-MTP rule as any block at this height (threads the
 *  parent MTP into the whole window — adversarial LT-Q2). Returns false if the
 *  seeds cannot be derived (e.g. parent MTP unavailable), which fails the seal
 *  closed. */
using SlotSeedFn = std::function<bool(CBlockHeader&)>;

/** CONSENSUS DEFINITION of the seal-as-PoW lottery object (ε = 0). Derives the
 *  Q* window from `anchor` (sigma_anchor = DeriveSigma(anchor)), computes each
 *  slot's ENC-DR-LT digest via ComputeDigestBMX4CLT after `slot_seed_fn` pins
 *  its V3 seeds, builds the Merkle root, and returns the seal in `seal_out`.
 *  `Qstar` MUST be a valid consensus Q* ({64,128}). On success `slots_out` (if
 *  non-null) receives the per-slot (nonce, digest) leaves in window order, and
 *  `slot_payloads_out` (if non-null) receives each slot's serialized sketch
 *  bytes (for the Freivalds seal-auth path / harnesses). Returns false if any
 *  slot fails (bad dims, slot_seed_fn failure). */
[[nodiscard]] bool ComputeSealDigestBMX4CLT(
    const CBlockHeader& anchor, uint32_t n, uint32_t Qstar,
    const SlotSeedFn& slot_seed_fn, uint256& seal_out,
    std::vector<WindowSlot>* slots_out = nullptr,
    std::vector<std::vector<unsigned char>>* slot_payloads_out = nullptr);

/** SEAL-AUTH FAST PATH (accept-side; per-slot Freivalds, ε ≤ 2^-180). Given the
 *  window proof `slot_payloads` (exactly Q* per-slot serialized sketches), re-
 *  derives each slot header (nonce + `slot_seed_fn` seeds), Freivalds-checks
 *  that slot's sketch against its re-MatExpanded operands with `rounds` rounds,
 *  recomputes the slot digest H(sigma_slot ‖ bytes), rebuilds the Merkle root
 *  and returns the resulting seal in `seal_out`. The slot sketches stay
 *  Freivalds-checkable and the seal binds the Merkle of the slot DIGESTS — this
 *  path never requires H(sigma ‖ Chat) == matmul_digest (that Phase-A identity
 *  does not hold in seal mode). The caller compares `seal_out` to the header's
 *  matmul_digest and the target. Returns false on any slot Freivalds failure,
 *  size/dim error, or slot_seed_fn failure. */
[[nodiscard]] bool VerifySealWindowFreivalds(
    const CBlockHeader& anchor, uint32_t n, uint32_t Qstar, uint32_t rounds,
    const SlotSeedFn& slot_seed_fn,
    const std::vector<std::vector<unsigned char>>& slot_payloads, uint256& seal_out);

/** One-pass seal-mode authentication of a relayed/cached window proof (the seal
 *  analogue of matmul_v4::PayloadMatchesCommitment). Recomputes each slot digest
 *  H(sigma_slot ‖ bytes) from `slot_payloads`, rebuilds the Merkle root + seal,
 *  and returns true iff it equals `anchor.matmul_digest`. Runs NO Freivalds and
 *  NO target check — it only answers "is this window proof the one the seal
 *  commits to?" (the MUTATED-vs-CONSENSUS classifier), so a caller must still
 *  run VerifySealWindowFreivalds (or the ε = 0 recompute) before accepting. */
[[nodiscard]] bool SealWindowProofMatchesCommitment(
    const CBlockHeader& anchor, uint32_t n, uint32_t Qstar,
    const SlotSeedFn& slot_seed_fn,
    const std::vector<std::vector<unsigned char>>& slot_payloads);

[[nodiscard]] matmul::v4::bmx4::ExactAccelPlan PlanLTAccel(std::string_view device_class);

struct DigestOnlyResultLT {
    uint64_t nonce{0};
    uint256 digest;
    bool target_match{false};
    matmul::v4::bmx4::DigestOnlyBackendStatus backend_status{
        matmul::v4::bmx4::DigestOnlyBackendStatus::Ok};
};

class WindowSketchMinerLT
{
public:
    explicit WindowSketchMinerLT(const CBlockHeader& header, uint32_t n,
                                 ExactGemmBackend backend = {});

    [[nodiscard]] bool Valid() const { return m_valid; }
    [[nodiscard]] uint32_t SketchDim() const { return m_m; }
    [[nodiscard]] const uint256& TemplateHash() const { return m_template_hash; }
    [[nodiscard]] bool UsingDeviceGemms() const { return m_backend.HasDeviceGemms(); }

    [[nodiscard]] bool MineWindow(const std::vector<CBlockHeader>& headers,
                                  const uint256& target,
                                  std::vector<DigestOnlyResultLT>& out) const;

[[nodiscard]] bool MineSlot(const CBlockHeader& header,
                                uint256& digest_out,
                                std::vector<unsigned char>* payload_out = nullptr) const;

    [[nodiscard]] bool Mine(const std::vector<uint64_t>& nonces, const uint256& target,
                            std::vector<DigestOnlyResultLT>& out,
                            std::vector<std::vector<unsigned char>>* payloads_out = nullptr) const;

private:
    CBlockHeader m_template;
    uint256 m_template_hash;
    uint32_t m_n{0};
    uint32_t m_m{0};
    bool m_valid{false};
    ExactGemmBackend m_backend{};
    std::vector<int8_t> m_A;
    std::vector<int8_t> m_U;
    std::vector<int8_t> m_V;
    std::vector<int32_t> m_P;
};

} // namespace matmul::v4::lt

#endif // BTX_MATMUL_MATMUL_V4_LT_H
