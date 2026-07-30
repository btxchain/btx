// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_TWO_CHILD_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_TWO_CHILD_PARENT_H

#include <matmul/matmul_v4_rc_stage3_v13_complete_child_parent.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_two_child_parent {

namespace aq = air_quotient;
namespace complete = stage3_v13_complete_child_parent;
namespace composer = stage3_air_parent_composer;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kArityV1 = 2;

/**
 * Ordered pair of complete child statements under one parent transcript.
 *
 * Each child's dependent relation seed is derived from the parent seed,
 * its slot and both ordered child statement commitments.  A proof therefore
 * cannot be replayed after swapping, omitting or duplicating a sibling.
 */
struct PublicStatementV1 {
    uint16_t version{kVersionV1};
    std::array<complete::PublicStatementV1, kArityV1>
        children{};
    uint256 parent_public_seed{};
};

[[nodiscard]] uint256 CommitChildStatementV1(
    const complete::PublicStatementV1& statement);

/**
 * Stable child-work identity.  It excludes the caller-provided child-local
 * seed, so changing only that seed cannot disguise a duplicated sibling.
 */
[[nodiscard]] uint256 CommitChildIdentityV1(
    const complete::PublicStatementV1& statement);

[[nodiscard]] uint256 CommitStatementV1(
    const PublicStatementV1& statement);

[[nodiscard]] uint256 DeriveChildFinalizationSeedV1(
    const PublicStatementV1& statement,
    uint32_t child_ordinal);

struct DeterministicParentV1 {
    uint16_t version{kVersionV1};
    PublicStatementV1 statement{};
    std::array<uint256, kArityV1>
        child_statement_roots{};
    std::array<uint256, kArityV1>
        child_identity_roots{};
    uint256 statement_root{};
    std::array<uint256, kArityV1>
        child_finalization_seeds{};
    std::array<
        complete::PublicDeterministicComponentV1,
        kArityV1> children{};
    std::array<composer::ChildAttachmentV1, kArityV1>
        child_attachments{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    uint32_t parent_acceptance_column{UINT32_MAX};
    bool ordered_siblings_bound{false};
    bool duplicate_sibling_rejected{false};
    bool both_children_pre_r0{false};
    bool arity_two_acceptance_constrained{false};
    bool proof_values_excluded{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildDeterministicConstraintSystemV1(
    const PublicStatementV1& statement,
    DeterministicParentV1& out,
    std::string* why = nullptr);

struct VerifierConstraintSystemV1 {
    uint16_t version{kVersionV1};
    DeterministicParentV1 deterministic{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<uint32_t> r0_base_column_indices;
    std::array<complete::ComponentFinalizationV1, kArityV1>
        child_finalizations{};
    uint256 r0_row_root{};
    bool single_shared_r0{false};
    bool both_children_finalized{false};
    bool proof_values_excluded{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildConstraintSystemV1(
    const PublicStatementV1& statement,
    const uint256& r0_row_root,
    VerifierConstraintSystemV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyProofV1(
    const PublicStatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why = nullptr);

/**
 * Prover-side counterpart used once two complete deterministic child
 * witnesses are available.  Both are appended before one parent R0 session;
 * only then are their two domain-separated dependent relations materialized.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    PublicStatementV1 statement{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::array<composer::ChildAttachmentV1, kArityV1>
        child_attachments{};
    std::array<complete::ComponentFinalizationV1, kArityV1>
        child_finalizations{};
    aq::AirQuotientTwoEpochBaseRowSession r0_session{};
    std::vector<uint32_t> r0_base_column_indices;
    uint32_t parent_acceptance_column{UINT32_MAX};
    uint64_t violations{UINT64_MAX};
    bool verifier_constraint_system_rebuilt{false};
    bool single_shared_r0{false};
    bool arity_two_acceptance_constrained{false};
    bool proof_ready{false};
    bool recursively_consumed{false};
    bool authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildProductV1(
    const PublicStatementV1& statement,
    const std::array<complete::DeterministicComponentV1, kArityV1>&
        children,
    ProductV1& out,
    std::string* why = nullptr);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(kExecutableV1);
static_assert(!kRecursiveConsumptionV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_two_child_parent

#endif
