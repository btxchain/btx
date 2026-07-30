// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_CODEC_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_CODEC_H

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_composition.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CBlock;
class CBlockHeader;

namespace matmul::v4::rc::bounded_semantic_codec {

/** "BSC1": direct complete typed-child inventory, not a receipt. */
inline constexpr uint32_t kEnvelopeMagicV1 = 0x31435342U;
inline constexpr uint16_t kEnvelopeVersionV1 = 1;

/**
 * The direct codec is diagnostic and a correctness bridge. It is deliberately
 * bounded above the consensus payload cap so an honest proof can be measured
 * and rejected with an exact size rather than truncated. Production carriage
 * remains capped by kRCStage3MaxProofBytes.
 */
inline constexpr size_t kDirectCodecMaxBytesV1 =
    64ULL * 1024ULL * 1024ULL;

struct SizeReportV1 {
    size_t statement_bytes{0};
    size_t episode_bytes{0};
    size_t coupled_bytes{0};
    size_t envelope_bytes{0};
    bool direct_codec_fit{false};
    bool consensus_payload_fit{false};

    [[nodiscard]] std::string ToString() const;
};

struct EnvelopeV1 {
    RCStage3SuccinctProof statement;
    RCStage3BoundedSemanticComposition composition;
};

/**
 * Serialize every typed episode and coupled proof object and every proof-owned
 * opening in declaration order. There are no completion/readiness booleans in
 * the envelope header and no commitment-only substitute for child proofs.
 *
 * The codec uses fixed-width little-endian scalars, bounded u32 vector lengths,
 * canonical field elements, strict trailing-byte rejection, and byte-for-byte
 * re-encoding after decode.
 */
[[nodiscard]] bool SerializeEnvelopeV1(
    const EnvelopeV1& envelope,
    std::vector<unsigned char>& out,
    SizeReportV1* size = nullptr,
    std::string* why = nullptr);

[[nodiscard]] std::optional<EnvelopeV1>
DeserializeEnvelopeV1(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

/**
 * Fresh verifier-side execution after strict decoding. This invokes the
 * complete 52-endpoint/81-edge bounded semantic verifier on the reconstructed
 * typed inventory. It performs no native episode/coupled workload replay.
 */
[[nodiscard]] bool VerifyEnvelopeV1(
    const std::vector<unsigned char>& bytes,
    const CBlockHeader& header,
    const RCEpisodeParams& episode_params,
    const RCStage3CoupledShape& coupled_shape,
    EnvelopeV1* decoded = nullptr,
    std::string* why = nullptr);

/**
 * Mechanism-only block attachment. It succeeds only when the complete direct
 * envelope fits the Stage-3 consensus payload cap. Authority/activation is not
 * changed and no consensus path calls this function.
 */
[[nodiscard]] bool AttachEnvelopeV1(
    CBlock& block,
    const EnvelopeV1& envelope,
    SizeReportV1* size = nullptr,
    std::string* why = nullptr);

[[nodiscard]] std::optional<std::vector<unsigned char>>
UnpackEnvelopeWordsV1(
    const std::vector<uint32_t>& words,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyAttachedEnvelopeV1(
    const CBlock& block,
    const RCEpisodeParams& episode_params,
    const RCStage3CoupledShape& coupled_shape,
    EnvelopeV1* decoded = nullptr,
    std::string* why = nullptr);

inline constexpr bool kDirectTypedInventoryCodecExecutableV1 = true;
inline constexpr bool kDirectTypedInventoryConsensusAuthorityV1 = false;

static_assert(kDirectTypedInventoryCodecExecutableV1);
static_assert(!kDirectTypedInventoryConsensusAuthorityV1);

} // namespace matmul::v4::rc::bounded_semantic_codec

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_CODEC_H
