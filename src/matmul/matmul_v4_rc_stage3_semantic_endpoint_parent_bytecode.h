// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_PARENT_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_PARENT_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::
    stage3_semantic_endpoint_parent_bytecode {

namespace cb = constraint_bytecode;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kChallengeWidthV1 = 4;
inline constexpr uint32_t kCanonicalConstraintCountV1 = 48;

enum ChallengeOrdinalV1 : uint32_t {
    kGamma0 = 0,
    kAlpha0 = 1,
    kGamma1 = 2,
    kAlpha1 = 3,
};

/**
 * Canonical source of truth for the semantic-endpoint parent glue.
 *
 * The table is statement-independent.  Manifest-derived gamma/alpha values
 * enter only through the verifier-owned Challenge column class; receipt
 * terminal coordinates enter through verifier-owned preprocessed columns.
 */
[[nodiscard]] bool BuildCanonicalProgramTableV1(
    const fp::SemanticEndpointReceiptTerminalLayoutV1& layout,
    cb::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Exact-table validator used at registry/normalized-parent boundaries.
 * Syntactically valid but semantically changed opcodes or operands reject.
 */
[[nodiscard]] bool IsCanonicalProgramTableV1(
    const fp::SemanticEndpointReceiptTerminalLayoutV1& layout,
    const cb::ProgramTable& candidate,
    std::string* why = nullptr);

/**
 * Native mathematical reference for differential tests.  This is not an AIR
 * callback and is never appended to a proof constraint system.
 */
[[nodiscard]] bool EvaluateNativeConstraintV1(
    const fp::SemanticEndpointReceiptTerminalLayoutV1& layout,
    uint32_t constraint_ordinal,
    const std::vector<gf::Fp3>& current,
    const std::vector<gf::Fp3>& next,
    const std::vector<gf::Fp3>& challenge,
    gf::Fp3& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::
  // stage3_semantic_endpoint_parent_bytecode

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SEMANTIC_ENDPOINT_PARENT_BYTECODE_H
