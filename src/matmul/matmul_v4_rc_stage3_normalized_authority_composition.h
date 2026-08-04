// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_AUTHORITY_COMPOSITION_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_AUTHORITY_COMPOSITION_H

#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>

#include <string>

namespace matmul::v4::rc::normalized_authority {

/**
 * Commitment to the outer composed statement which the normalized parent
 * must verify.
 *
 * The preimage contains the complete public context and the exact ordered
 * commitments and section-byte digests for the fourteen semantic roles.
 * It deliberately excludes both the CompositionLink section and
 * `transcript_commitment`: including either would make the receipt, which is
 * carried in that section, self-referential.  The existing Stage-3 transcript
 * commitment subsequently binds the completed CompositionLink bytes/root.
 */
[[nodiscard]] uint256 ComputeOuterStatementRootV3(
    const RCStage3SuccinctProof& proof);

struct BoundCompositionLinkV3 {
    NormalizedAuthorityReceiptV3 receipt{};
    uint256 outer_statement_root{};
};

/**
 * Executable outer-envelope consumer for NormalizedAuthorityReceiptV3.
 *
 * It verifies the ordinary composed-digest/transcript link, decodes the
 * canonical receipt from the CompositionLink section, binds its receipt root
 * to the corresponding outer commitment, binds its registry to the
 * consensus/public registry pin, and binds every one of its fourteen role
 * statements to the matching outer role commitment.
 *
 * Successful return is NOT proof authority.  Consensus must next
 * independently rebuild RebuiltVerifierInputsV3 and the exact parent
 * AirConstraintSystem from the pinned production registry, call
 * ValidateAndDecodeVerifierInputsV3, and execute
 * AirQuotientVerifyRowsSplitRapSafeFixedV3.  This API has no callback or
 * serialized acceptance value which could bypass those steps.
 */
[[nodiscard]] bool DecodeAndBindCompositionLinkV3(
    const RCStage3SuccinctProof& proof,
    BoundCompositionLinkV3& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_authority

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_AUTHORITY_COMPOSITION_H
