// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_CONSENSUS_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_CONSENSUS_BINDING_H

#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>

#include <string>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc::normalized_consensus_binding {

namespace nav3 = normalized_authority;

/**
 * Rebuild the direct normalized public statement from immutable consensus
 * context plus the two digest claims that the recursive parent must prove.
 *
 * The digest claims are not trusted: the recomputed composed digest must equal
 * the finalized block header's matmul_digest and satisfy the canonical target.
 */
[[nodiscard]] bool RebuildComposedPublicStatementV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    const uint256& episode_digest,
    const uint256& coupled_digest,
    nav3::ComposedPublicStatementV3& out,
    std::string* why = nullptr);

/**
 * Bind a decoded direct NAV3 receipt to the block and frozen chain parameters.
 *
 * This is the missing deserialize-to-consensus statement bridge.  It does not
 * rebuild or verify the parent AIR; success means only that a subsequent
 * canonical parent builder may safely use the receipt's statement and role
 * pins.  No serialized readiness value is consumed.
 */
[[nodiscard]] bool ValidateDirectReceiptConsensusBindingV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    const nav3::NormalizedAuthorityReceiptV3& receipt,
    nav3::RebuiltVerifierInputsV3& public_inputs_out,
    std::string* why = nullptr);

/**
 * Execute the durable block boundary: strict BNV3 unpack, strict NAV3 decode,
 * then the complete direct public-statement binding above.
 */
[[nodiscard]] bool DecodeAndBindAttachedDirectReceiptV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    nav3::NormalizedAuthorityReceiptV3& receipt_out,
    nav3::RebuiltVerifierInputsV3& public_inputs_out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_consensus_binding

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_CONSENSUS_BINDING_H
