// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFY_H

#include <arith_uint256.h>
#include <matmul/matmul_v4_rc_stage3.h>

#include <cstdint>
#include <string>

class CBlockHeader;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc {

/**
 * Complete mathematical Stage-3 verifier entry point used by the durable
 * consensus attachment. Acceptance is the conjunction of:
 *
 *  - immutable consensus/public-input binding;
 *  - every episode relation for Episode/Composed statements;
 *  - every coupled relation for Composed statements;
 *  - the deterministic transcript/final-digest composition link.
 *
 * No sampled carrier, exact replay, native witness reconstruction, or
 * environment-selected fallback is reachable from this function.
 */
[[nodiscard]] bool VerifyRCStage3MathematicalProof(
    const RCStage3SuccinctProof& proof,
    const CBlockHeader& header,
    const Consensus::Params& params,
    int32_t height,
    const arith_uint256& target,
    std::string* why = nullptr);

/**
 * Global build-readiness gate. Statement-specific verification still checks
 * only the relations required by that statement, but public activation must
 * wait for the complete composed authority.
 */
/** True once episode RelationsReady and coupled engines Ready are measured;
 * RecursiveAggregation / SuccinctAuthority remain separate fail-closed gates. */
inline constexpr bool kRCStage3MathematicalVerifierReady = true;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_VERIFY_H
