// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_GATED_CTL_ALIAS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_GATED_CTL_ALIAS_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::gated_ctl_alias {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;

namespace col {
enum : uint32_t {
    NAMESPACE = 0,
    STAGE,
    ADDRESS,
    MULTIPLICITY,
    INVERSE1,
    INVERSE2,
    TERM1,
    TERM2,
    RUNNING1,
    RUNNING2,
    NUM_COLUMNS,
};
} // namespace col

/**
 * Verifier-owned sparse bus description.
 *
 * `selector_column` is a column of the relation itself.  The composed AIR
 * constrains it to {0,1}; multiplicity is constrained in the same trace to
 * sign*selector.  VALUE is not copied into a free CTL witness column: every
 * denominator reads `source_column` directly.
 */
struct SpecV1 {
    uint16_t version{kVersionV1};
    uint32_t namespace_id{0};
    uint32_t stage{0};
    int8_t sign{0};
    uint32_t source_column{0};
    uint32_t selector_column{0};
    std::vector<uint32_t> addresses;
    RCStage3CtlChallenges challenges;
    RCStage3CtlTerminal expected_terminal;
};

struct LayoutV1 {
    uint16_t version{kVersionV1};
    uint32_t relation_columns{0};
    uint32_t ctl_base{0};
    uint32_t total_columns{0};
    uint32_t source_column{0};
    uint32_t selector_column{0};
    std::vector<uint32_t> base_column_indices;
};

struct WitnessV1 {
    uint16_t version{kVersionV1};
    std::vector<std::vector<gf::Fp3>> columns;
    RCStage3CtlTerminal terminal;
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildConstraintSystemV1(
    const aq::AirConstraintSystem<gf::Fp3>& relation,
    const SpecV1& spec,
    aq::AirConstraintSystem<gf::Fp3>& out,
    LayoutV1& layout,
    std::string* why = nullptr);

[[nodiscard]] WitnessV1 BuildWitnessV1(
    const std::vector<std::vector<gf::Fp3>>& relation_columns,
    const SpecV1& spec,
    const LayoutV1& layout);

/**
 * Build the exact R0 witness before lookup challenges exist.  Dependent
 * columns are canonical zero and are excluded by layout.base_column_indices.
 */
[[nodiscard]] bool BuildPrechallengeColumnsV1(
    const std::vector<std::vector<gf::Fp3>>& relation_columns,
    const SpecV1& spec,
    const LayoutV1& layout,
    std::vector<std::vector<gf::Fp3>>& out,
    std::string* why = nullptr);

/**
 * Reconstruct the prechallenge trace root from authenticated column roots.
 * The value and selector roots are relation-owned; tuple/multiplicity roots
 * are verifier-recomputable preprocessed roots.
 */
[[nodiscard]] uint256 ComputeTraceCommitmentV1(
    const aq::AirConstraintSystem<gf::Fp3>& combined,
    const LayoutV1& layout,
    const std::vector<uint256>& ordered_base_roots);

} // namespace matmul::v4::rc::gated_ctl_alias

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_GATED_CTL_ALIAS_H
