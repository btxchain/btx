// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSENSUS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSENSUS_H

#include <matmul/matmul_v4_rc_stage3.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CBlock;
class CBlockHeader;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

/** Result of inspecting the durable Stage-3 attachment. Missing, malformed,
 * and statement-binding failures are body mutations: matrix_c_data is not part
 * of CBlockHeader::GetHash(), so another body with the same header may contain
 * the valid proof. AUTHORITY_UNAVAILABLE is fail-closed, not a mutation. */
enum class RCStage3AttachmentStatus : uint8_t {
    NotRequired = 0,
    Missing = 1,
    Malformed = 2,
    BindingMismatch = 3,
    AuthorityUnavailable = 4,
    ReadyForMathematicalVerification = 5,
    MathematicalVerificationFailed = 6,
    Valid = 7,
};

struct RCStage3ProofCacheKey {
    uint256 block_hash{};
    /** Explicit verifying-key namespace; payload digest alone is insufficient
     * context for a reusable mathematical-verification verdict. */
    uint256 program_registry_alg_root{};
    uint256 proof_payload_digest{};

    friend bool operator==(const RCStage3ProofCacheKey&,
                           const RCStage3ProofCacheKey&) = default;
    friend bool operator<(const RCStage3ProofCacheKey& a,
                          const RCStage3ProofCacheKey& b)
    {
        if (a.block_hash != b.block_hash) return a.block_hash < b.block_hash;
        if (a.program_registry_alg_root != b.program_registry_alg_root) {
            return a.program_registry_alg_root <
                   b.program_registry_alg_root;
        }
        return a.proof_payload_digest < b.proof_payload_digest;
    }
};

/** Stage-3 statement required by consensus at height, or nullopt outside the
 * RC family. Coupled activation is additive and therefore requires Composed,
 * never a coupled-only proof. */
[[nodiscard]] std::optional<RCStage3StatementKind>
RequiredRCStage3Statement(const Consensus::Params& params, int32_t height);

/** Consensus-stable public bindings. The header projection zeroes
 * matmul_digest to avoid a proof/final-digest fixed-point while retaining all
 * template, nonce, seed, dimension, and nBits fields. The parameter commitment
 * includes every resolved episode/coupled shape and every digest-affecting
 * coupled option. */
[[nodiscard]] uint256 RCStage3HeaderCommitment(const CBlockHeader& header);
[[nodiscard]] uint256 RCStage3ParamsCommitment(const Consensus::Params& params,
                                               int32_t height,
                                               RCStage3StatementKind statement);
[[nodiscard]] uint256 RCStage3ProofPayloadDigest(const std::vector<uint32_t>& words);
[[nodiscard]] RCStage3ProofCacheKey
RCStage3ProofKey(const CBlock& block);

/** Validate the proof's public inputs against immutable consensus context.
 * This does not verify relation sections. `target` is the canonical integer
 * returned by DeriveTarget(header.nBits, params.powLimit). */
[[nodiscard]] bool ValidateRCStage3ConsensusBinding(
    const RCStage3SuccinctProof& proof,
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why = nullptr);

/** Producer attachment seam. Accepts only an already-formed proof whose public
 * inputs bind this exact block/height/params/target, then packs it canonically
 * into matrix_c_data. Failure is atomic and leaves the block unchanged. This
 * helper does not generate or mathematically verify relation proofs. */
[[nodiscard]] bool AttachRCStage3ConsensusProof(
    CBlock& block,
    const RCStage3SuccinctProof& proof,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why = nullptr);

/** Canonically parse matrix_c_data from a full CBlock and bind it to consensus
 * context. The authority-ready gate is checked last: malformed attachments can
 * still be identified precisely while the mathematical verifier remains off. */
[[nodiscard]] RCStage3AttachmentStatus InspectRCStage3ConsensusAttachment(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    RCStage3SuccinctProof* proof_out = nullptr,
    RCStage3ProofCacheKey* cache_key_out = nullptr,
    std::string* why = nullptr);

/** Full consensus attachment entry point. It is compile-time fail-closed while
 * kRCStage3SuccinctAuthorityReady is false. Once enabled, it consults only the
 * proof-aware positive cache and otherwise calls the complete mathematical
 * verifier; failed relation proofs remain body mutations. */
[[nodiscard]] RCStage3AttachmentStatus VerifyRCStage3ConsensusAttachment(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    std::string* why = nullptr);

[[nodiscard]] bool RCStage3AttachmentIsMutation(RCStage3AttachmentStatus status);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_CONSENSUS_H
