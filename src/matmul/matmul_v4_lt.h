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
[[nodiscard]] bool VerifyWindowSlotFreivalds(const CBlockHeader& tmpl, uint32_t n,
                                             const std::vector<WindowSlot>& slots, uint32_t r);

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
