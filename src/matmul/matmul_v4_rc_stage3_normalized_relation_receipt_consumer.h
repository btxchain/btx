// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_RELATION_RECEIPT_CONSUMER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_RELATION_RECEIPT_CONSUMER_H

#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::normalized_relation_receipt_consumer {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace nav3 = normalized_authority;

inline constexpr uint16_t kNormalizedRelationReceiptConsumerVersionV1 = 1;

/**
 * Generic output contract of the canonical same-parent relation builder.
 *
 * The V13/V14/ABI parent and the eventual complete episode+coupled parent
 * deliberately meet the production provider through this tuple rather than
 * through either construction's concrete C++ type.  Every object here is
 * consumed:
 *
 *  - `cs` and `columns` are proved by SAFE FixedTrace V3;
 *  - `r0_base_column_indices` and `r0_session` are the proof-owned R0 group,
 *    not a host acceptance bit;
 *  - `verifier_inputs` contains the independently rebuildable public roots,
 *    role/endpoint inventory and program commitment.  Its shape and fixed
 *    trace fields must already equal the values derived from the actual CS.
 *
 * A product whose proof cannot be verified immediately is rejected and can
 * never become receipt bytes.
 */
struct CanonicalRelationParentProductV1 {
    uint16_t version{kNormalizedRelationReceiptConsumerVersionV1};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    nav3::RebuiltVerifierInputsV3 verifier_inputs;
};

struct ReceiptBuildV1 {
    nav3::NormalizedAuthorityReceiptV3 receipt;
    aq::AirQuotientSplitRapRowsProof decoded_parent_proof;
    aq::AirQuotientFixedTracePinV3 fixed_trace;
    std::vector<unsigned char> receipt_bytes;
    uint64_t violations{UINT64_MAX};
    bool exact_parent_shape_derived{false};
    bool actual_r0_session_consumed{false};
    bool actual_parent_cs_proved{false};
    bool canonical_parent_proof_codec{false};
    bool verifier_inputs_rebuilt_and_equal{false};
    bool unmodified_parent_verifier_accepted{false};
    /**
     * This conversion consumes the complete relation-parent proof natively.
     * It does not claim the still-separate self-similar verifier-as-AIR fixed
     * point; that remains the next recursive aggregation obligation.
     */
    bool normalized_recursive_child_verifier_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/** Derive the exact NAV3 shape from the constraint system, without proving. */
[[nodiscard]] bool DeriveParentShapeV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    nav3::ParentShapeV3& out,
    std::string* why = nullptr);

/**
 * Prove the supplied canonical relation parent, populate every derived NAV3
 * field, serialize it canonically, decode it again, and execute the unmodified
 * SAFE FixedTrace V3 verifier before returning any bytes.
 */
[[nodiscard]] bool BuildReceiptV1(
    const CanonicalRelationParentProductV1& product,
    ReceiptBuildV1& out,
    const aq::AirProveOptions& options = {},
    std::string* why = nullptr);

/**
 * Consensus-side half of the seam.  The caller supplies independently rebuilt
 * verifier inputs and the exact canonical parent CS; nothing is inferred from
 * receipt booleans or notes.
 */
[[nodiscard]] bool VerifyReceiptV1(
    const aq::AirConstraintSystem<gf::Fp3>& rebuilt_parent_cs,
    const nav3::RebuiltVerifierInputsV3& rebuilt_inputs,
    const std::vector<unsigned char>& receipt_bytes,
    aq::AirQuotientSplitRapRowsProof* decoded_parent_proof = nullptr,
    std::string* why = nullptr);

inline constexpr bool kCanonicalRelationReceiptExecutableV1 = true;
inline constexpr bool kNormalizedRecursiveChildVerifierConsumedV1 = false;
inline constexpr bool kCanonicalRelationReceiptAuthorityReadyV1 = false;

static_assert(kCanonicalRelationReceiptExecutableV1);
static_assert(!kNormalizedRecursiveChildVerifierConsumedV1);
static_assert(!kCanonicalRelationReceiptAuthorityReadyV1);

} // namespace matmul::v4::rc::normalized_relation_receipt_consumer

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_RELATION_RECEIPT_CONSUMER_H
