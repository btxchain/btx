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
/** MatExpand panel width. Raised 128→1024 to rebalance MatExpand GEMM (Θ(n²·w))
 *  vs Extract (MX-block PRF, Θ(n²/32) ChaCha tiles) for the datacenter thesis. */
inline constexpr uint32_t kMatExpandPanelW = 1024;
inline constexpr int32_t kMatExpandEmax = 48;
/** MX Extract E8M0 block length along columns (matches bmx4::kBlockLen). */
inline constexpr uint32_t kMatExpandMxBlockLen = 32;
/** Consensus Q* window sizes: {128,256,512}. Default 256 (Phase B fat window). */
inline constexpr uint32_t kConsensusQStarDefault = 256;
inline constexpr uint32_t kConsensusQStarMax = 512;

[[nodiscard]] inline bool IsValidConsensusQStar(uint32_t q_star)
{
    return q_star == 128 || q_star == 256 || q_star == 512;
}

[[nodiscard]] int32_t FoldInt32ToEmax48(int32_t y);

/** Legacy per-cell ChaCha lane tags (non-normative ChaChaCell Extract only).
 *  Related-nonce identity: MantPRF(raw) = ScalePRF(raw⊕Δ) with
 *  Δ = kMatExpandPrfLaneMant ⊕ kMatExpandPrfLaneScale (= 0x1e020211). */
inline constexpr uint32_t kMatExpandPrfLaneMant = 0x4D414E54u;  // 'MANT'
inline constexpr uint32_t kMatExpandPrfLaneScale = 0x53434C45u; // 'SCLE'
inline constexpr uint32_t kMatExpandPrfLaneXorDelta =
    kMatExpandPrfLaneMant ^ kMatExpandPrfLaneScale; // 0x1e020211
/** MX-block ChaCha nonce_first tag: bj ⊕ kMatExpandPrfLaneMxBlock. */
inline constexpr uint32_t kMatExpandPrfLaneMxBlock = 0x4D58424Cu; // 'MXBL'

/** Domain-separated PRF key for normative MX-block MatExpand Extract.
 *  key = SHA256("BTX_MATEXPAND_MXPRF_V44LT" ‖ seed_W). */
[[nodiscard]] uint256 DeriveMatExpandPrfKey(const uint256& seed_w);

/** Legacy ChaChaCell PRF key: SHA256("BTX_MATEXPAND_PRF_V44LT" ‖ seed_W).
 *  Only for ExtractDequantMatExpandChaChaCell / related-nonce differentials. */
[[nodiscard]] uint256 DeriveMatExpandPrfKeyChaChaCell(const uint256& seed_w);

/** E8M0 scale e∈{0..3} for row i, column-block bj = j/32.
 *  e = SHA256("BTX_MATEXPAND_MXSCALE_V44LT" ‖ prf_key ‖ i ‖ bj)_0 & 3. */
[[nodiscard]] uint8_t DeriveMatExpandMxScale(const uint256& prf_key, uint32_t i, uint32_t bj);

/** Fill 32 M11 mantissas for tile (i, bj) from raw32[0..31] (B32 row segment).
 *  One ChaCha20 stream per tile; each accepted nibble is XOR-mixed with the
 *  corresponding cell's raw so Extract depends on B32 (non-XOF). */
void ExtractMatExpandMxTileMantissas(const uint256& prf_key, uint32_t i, uint32_t bj,
                                     const int32_t raw32[kMatExpandMxBlockLen],
                                     int8_t mu_out[kMatExpandMxBlockLen]);

/** First 8 bytes (LE64) of legacy per-cell ChaCha keystream (ChaChaCell twin).
 *  Not used by consensus digests. */
[[nodiscard]] uint64_t MatExpandPrfLaneLE64(const uint256& prf_key, int32_t raw, uint32_t i,
                                            uint32_t j, uint32_t remix, uint32_t lane);

/** Position-salted SplitMix64 avalanche — LEGACY / differential tests only. */
[[nodiscard]] uint64_t MixMatExpandEntry(int32_t raw, uint32_t i, uint32_t j, uint64_t salt);

/** Legacy SplitMix+M11 Extract — differential tests only (non-normative). */
[[nodiscard]] int8_t ExtractDequantMatExpandSplitMix(int32_t raw, uint32_t i, uint32_t j,
                                                     uint64_t salt);

/** Legacy per-cell ChaCha20 Extract — differential / related-nonce tests only.
 *  NOT used by normative ENC_BMX4C_LT MatExpand after Lever-B MX Extract. */
[[nodiscard]] int8_t ExtractDequantMatExpandChaChaCell(int32_t raw, uint32_t i, uint32_t j,
                                                       const uint256& prf_key);

/** Normative MatExpand Extract (ENC_BMX4C_LT, Lever-B MX): E8M0 block scale +
 *  tile ChaCha M11 mantissas. Single-cell convenience builds a synthetic tile
 *  with all 32 raws equal to `raw` (tests/differentials). Consensus MatExpand
 *  uses ExtractMatExpandMxTileMantissas over real B32 tiles.
 *  `prf_key` MUST be DeriveMatExpandPrfKey(seed_W). Output ∈ [-48,48].
 *  C-15 external review still required before any public height raise. */
[[nodiscard]] int8_t ExtractDequantMatExpand(int32_t raw, uint32_t i, uint32_t j,
                                             const uint256& prf_key);

/** Consensus-faithful single-cell Extract from a full B32 matrix (reads the
 *  real 32-col tile containing (i,j)). Prefer this over the synthetic-tile
 *  convenience API when comparing to MatExpandCore / ExpandOperand*. */
[[nodiscard]] int8_t ExtractDequantMatExpandAt(const int32_t* B32, uint32_t n, uint32_t i,
                                               uint32_t j, const uint256& prf_key);
/** Host-callable replica of the CUDA/HIP DeviceExtractDequant ChaCha path.
 *  Must stay bit-identical to ExtractDequantMatExpand and to the device
 *  kernels — runnable parity tests pin this so a kernel edit cannot silently
 *  drift from the CPU goldens. Same full-width (i,j) packing as DeviceMatExpandPrfLE64. */
[[nodiscard]] int8_t ExtractDequantMatExpandAccelReplica(int32_t raw, uint32_t i, uint32_t j,
                                                         const uint256& prf_key);

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

/** Expand Bhat plus MX mantissas / E8M0 scales for scale-partitioned B̂·V.
 *  `mu_out` is n×n M11; `scales_out` is n×(n/32) with e(i, j/32). */
[[nodiscard]] std::vector<int8_t> ExpandOperandBMatExpandMx(
    const CBlockHeader& header, uint32_t n, const ExactGemmBackend& backend,
    std::vector<int8_t>& mu_out, std::vector<uint8_t>& scales_out);

/** Q = (μ · 2^e) · V with e shared on 32-col blocks per row (Lever-B MX layout).
 *  Bit-identical to ComputeProjectedRight(Bhat, V) when Bhat[i,j]=μ[i,j]<<e[i,j/32]. */
[[nodiscard]] std::vector<int32_t> ComputeProjectedRightMxBlockScaleLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m);

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
    uint256 slot_id;   // DeriveWindowSlotId(sigma_anchor, j) — full 256-bit identity
    uint64_t nonce{0}; // == ReadLE64(slot_id) — header grinding field only
    uint256 digest;    // Phase-A ENC-DR-LT digest H(sigma_slot ‖ Chat_slot)
};

[[nodiscard]] uint256 ComputeWindowMerkleRoot(Span<const uint256> digests);
[[nodiscard]] uint256 SealWindowCommit(const uint256& sigma_anchor,
                                       const uint256& merkle_root, uint32_t Qstar);
/** Consensus Merkle leaf for slot j (exact preimage):
 *  SHA256("BTX_QSTAR_LEAF_V44LT" ‖ slot_id ‖ digest). */
[[nodiscard]] uint256 CommitWindowSlotLeaf(const uint256& slot_id, const uint256& digest);
/** After SlotSeedFn pins V3 seeds, fold the full 256-bit slot_id into seed_a /
 *  seed_b (exact preimage):
 *    seed_a := SHA256("BTX_QSTAR_SLOTSEED_A_V44LT" ‖ seed_a ‖ slot_id)
 *    seed_b := SHA256("BTX_QSTAR_SLOTSEED_B_V44LT" ‖ seed_b ‖ slot_id)
 *  Mandatory on every seal path so high bits of slot_id bind into operand B /
 *  sigma even when nNonce64 only carries the low 64 bits. */
void BindWindowSlotIdIntoSeeds(CBlockHeader& header, const uint256& slot_id);
/** TEST/DIAGNOSTIC ONLY — does NOT prove Q* window membership.
 *
 *  Reconstructs digests from caller-supplied slot nonces without re-deriving
 *  expected slot ids from sigma_anchor, without SlotSeedFn / parent MTP /
 *  BindWindowSlotIdIntoSeeds, and without checking seal order or uniqueness.
 *  Unused in production validation. Prefer VerifySealWindowFreivalds /
 *  SealWindowProofMatchesCommitment. */
[[nodiscard]] bool VerifyWindowSlotFreivalds(const CBlockHeader& tmpl, uint32_t n,
                                             const std::vector<WindowSlot>& slots, uint32_t r);

// ---------------------------------------------------------------------------
// Q* Phase B — SEAL-AS-PoW (doc/btx-matmul-v4.4-lt-normative-spec.md "Q* window";
// doc/btx-matmul-v4.4-lt-adversarial-analysis.md "Phase B"). Implemented and
// unit-tested, but INERT on every public network (gated behind
// Consensus::Params::IsMatMulLTSealAsPoWActive, which requires the still-
// INT32_MAX nMatMulDRLTHeight). In seal mode the header's lottery object is not
// the per-nonce ENC-DR-LT digest but the WINDOW SEAL binding a full Q* window of
// sibling slot digests:
//
//   slot_id_j  := DeriveWindowSlotId(sigma_anchor, j)          // 256-bit
//   nNonce64_j := ReadLE64(slot_id_j)                         // grinding field
//   seeds_j    := BindWindowSlotIdIntoSeeds(V3(...), slot_id_j)
//   digest_j   := ComputeDigestBMX4CLT(slot_j)                // H(σ‖Chat)
//   leaf_j     := CommitWindowSlotLeaf(slot_id_j, digest_j)
//   matmul_digest := SealWindowCommit(sigma_anchor, Merkle(leaves), Q*)
//
// Q* is an aggregate work commitment over the leaf digests — it does NOT prove
// classical GEMM, tensor-core use, or simultaneous slot execution. Slot-id
// binding (id → seeds + leaf) IS consensus.
// ---------------------------------------------------------------------------

/** Full 256-bit per-anchor window-slot identifier:
 *  SHA256("BTX_QSTAR_SLOT_V44LT" ‖ sigma_anchor ‖ slot_index LE32). */
[[nodiscard]] uint256 DeriveWindowSlotId(const uint256& sigma_anchor, uint32_t slot_index);

/** Header grinding field for slot `slot_index`: low 64 bits LE of
 *  DeriveWindowSlotId(sigma_anchor, slot_index). Distinct anchors still yield
 *  disjoint low-64 sets with overwhelming probability; consensus uniqueness is
 *  enforced on the full slot_id, not this truncation. */
[[nodiscard]] uint64_t DeriveWindowSlotNonce(const uint256& sigma_anchor, uint32_t slot_index);

/** Callback that pins the consensus-correct V3 seed_a/seed_b onto a window-slot
 *  header whose nNonce64/nNonce are already set to the slot nonce (low 64 of
 *  slot_id). The caller binds the params/height/parent-MTP and typically wraps
 *  SetDeterministicMatMulSeeds, so every sibling slot re-derives its V3 seeds
 *  under the SAME parent-MTP rule as any block at this height (threads the
 *  parent MTP into the whole window — adversarial LT-Q2). After this callback
 *  returns, ComputeSealDigestBMX4CLT always applies BindWindowSlotIdIntoSeeds.
 *  Returns false if the seeds cannot be derived (e.g. parent MTP unavailable),
 *  which fails the seal closed. */
using SlotSeedFn = std::function<bool(CBlockHeader&)>;

/** CONSENSUS DEFINITION of the seal-as-PoW lottery object (ε = 0). Derives the
 *  Q* window from `anchor` (sigma_anchor = DeriveSigma(anchor)), computes each
 *  slot's ENC-DR-LT digest via ComputeDigestBMX4CLT after `slot_seed_fn` pins
 *  its V3 seeds and BindWindowSlotIdIntoSeeds folds in the full slot_id, builds
 *  the Merkle root over CommitWindowSlotLeaf(slot_id, digest) leaves, and
 *  returns the seal in `seal_out`. `Qstar` MUST be a valid consensus Q*
 *  ({128,256,512}). Rejects duplicate slot_ids deterministically. On success
 *  `slots_out` (if non-null) receives the per-slot (slot_id, nonce, digest)
 *  records in window order, and `slot_payloads_out` (if non-null) receives each
 *  slot's serialized sketch bytes (for the Freivalds seal-auth path /
 *  harnesses). Returns false if any slot fails (bad dims, slot_seed_fn failure,
 *  duplicate slot_id). Optional `backend` injects device ExactGemm for MatExpand
 *  GEMMs on the prepared WindowSketchMinerLT (miners pass
 *  MakeResolvedExactGemmBackend()); default {} keeps CPU ExactGemm*. */
[[nodiscard]] bool ComputeSealDigestBMX4CLT(
    const CBlockHeader& anchor, uint32_t n, uint32_t Qstar,
    const SlotSeedFn& slot_seed_fn, uint256& seal_out,
    std::vector<WindowSlot>* slots_out = nullptr,
    std::vector<std::vector<unsigned char>>* slot_payloads_out = nullptr,
    ExactGemmBackend backend = {});

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
