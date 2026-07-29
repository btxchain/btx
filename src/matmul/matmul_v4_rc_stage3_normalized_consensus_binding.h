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
 * The only NAV3 fields that the direct block-binding layer may export.
 *
 * Parent shape, role pins, fixed-trace columns/root, verifier-program roots
 * and the parent-CS commitment are deliberately absent.  They are proof
 * claims and must be reconstructed by the frozen-registry parent builder
 * before native verification; copying them out of the receipt under a
 * "rebuilt inputs" type would create a dangerous trust seam.
 */
struct DirectReceiptConsensusStatementV3 {
    nav3::OuterBindingKindV3 outer_binding_kind{
        nav3::OuterBindingKindV3::DirectBlockReceipt};
    nav3::ComposedPublicStatementV3 public_statement{};
    uint256 expected_program_registry_root{};

    bool operator==(
        const DirectReceiptConsensusStatementV3&) const = default;
};

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
 * This is the deserialize-to-consensus statement bridge.  It does not rebuild
 * or verify the parent AIR; success exports only the block-derived public
 * statement and consensus-selected registry root.  A subsequent canonical
 * parent builder must independently reconstruct role pins, fixed trace,
 * schedule and parent CS.  No receipt-owned parent field or serialized
 * readiness value is exported.
 */
[[nodiscard]] bool ValidateDirectReceiptConsensusBindingV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    const nav3::NormalizedAuthorityReceiptV3& receipt,
    DirectReceiptConsensusStatementV3& statement_out,
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
    DirectReceiptConsensusStatementV3& statement_out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_consensus_binding

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_CONSENSUS_BINDING_H
