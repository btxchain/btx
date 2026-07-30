// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FAMILY_FOLD_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FAMILY_FOLD_H

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_eval.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_family_fold {

/**
 * This module proves one precise, deliberately linear statement.
 *
 * Let T[s,r] be a two-dimensional coefficient table whose AlgHash row root is
 * a public input.  After that source root is fixed, Fiat--Shamir samples beta
 * and the prover commits
 *
 *     F[r] = sum_s eq(beta,s) T[s,r].
 *
 * Only after the F commitment is fixed does Fiat--Shamir sample rho.  A
 * Construction-I evaluation argument then proves
 *
 *     T~(rho || beta) = F~(rho || 0...0)
 *
 * against a single Q192 ordered Main/Auxiliary/Quotient multi-row FRI.
 *
 * The ordering is the security property: beta never depends on F or the
 * evaluation witnesses, and rho never depends on the evaluation witnesses.
 * This rules out a post-beta source self-commitment and a post-rho folded
 * polynomial.
 *
 * IMPORTANT: this is NOT a proof that nonlinear AIR constraints survive a
 * linear trace fold.  Production family aggregation must apply it to
 * per-shard composition/quotient residuals, or combine it with a constraint
 * VM sumcheck.  The explicit false readiness constants below prevent this
 * primitive from being promoted as the complete semantic backend.
 */
inline constexpr uint16_t kAuthenticatedLinearFamilyFoldVersion = 1;
inline constexpr uint32_t kAuthenticatedLinearFamilyFoldMagic =
    0x31464c41U; // 'ALF1'
inline constexpr uint16_t kAuthenticatedLinearFamilyFoldMaxFamilies = 28;
inline constexpr uint16_t kAuthenticatedLinearFamilyFoldMaxRoles = 14;
inline constexpr size_t kAuthenticatedLinearFamilyFoldMaxProofBytes =
    kRCFri3AlgMultiRowMaxProofBytesHard + 128;
inline constexpr bool kAuthenticatedLinearFamilyFoldExecutable = true;
inline constexpr bool kAuthenticatedLinearFamilyFoldCodecExecutable = true;
inline constexpr bool kAuthenticatedLinearFamilyFoldPreservesNonlinearAir = false;
inline constexpr bool kAuthenticatedFamilyResidualZeroFoldExecutable = true;
inline constexpr bool kAuthenticatedFamilyResidualOracleBoundToConstraintVm = false;
inline constexpr bool kAuthenticatedFamilyQuotientIdentityExecutable = false;
inline constexpr bool kAuthenticatedFamilyBackendProductionSelectable = false;

struct AuthenticatedLinearFamilyFoldMetadataV1 {
    uint16_t version{kAuthenticatedLinearFamilyFoldVersion};
    uint16_t family_index{0};
    uint16_t role_index{0};
    uint32_t committed_shards{0};
    uint32_t rows_per_shard{0};
    /** Consensus-owned canonical constraint-program/registry AlgHash root. */
    uint256 program_registry_alg_root{};
    /** Binds episode/coupled public inputs and the family schedule. */
    uint256 family_statement_binding{};
};

struct AuthenticatedLinearFamilyFoldPublicInputsV1 {
    AuthenticatedLinearFamilyFoldMetadataV1 metadata{};
    /** Root of the MainTrace group containing flattened T[s,r]. */
    Fri3AlgDigest source_root{};
};

struct AuthenticatedLinearFamilyFoldProofV1 {
    uint16_t version{kAuthenticatedLinearFamilyFoldVersion};
    /** Common claimed value T~(rho||beta) = F~(rho||0...). */
    Fp3 evaluation{};
    RCGkrEvalArgumentProof3 evaluation_argument{};
    Fri3AlgMultiRowBatchProof batch{};
};

struct AuthenticatedLinearFamilyFoldProveResultV1 {
    AuthenticatedLinearFamilyFoldPublicInputsV1 public_inputs{};
    AuthenticatedLinearFamilyFoldProofV1 proof{};
    bool ok{false};
    std::string note;
};

/**
 * Compute the honest beta fold. Both dimensions must be powers of two and at
 * least two. `beta.size()` must equal log2(shards.size()).
 */
[[nodiscard]] bool ComputeAuthenticatedLinearFamilyFoldV1(
    const std::vector<std::vector<Fp3>>& shards,
    const std::vector<Fp3>& beta,
    std::vector<Fp3>& folded,
    std::string* why = nullptr);

/**
 * Commit the source, derive beta, compute the honest fold, and prove it.
 * The two public roots in `metadata` must be non-null.
 */
[[nodiscard]] AuthenticatedLinearFamilyFoldProveResultV1
ProveAuthenticatedLinearFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& shards);

/**
 * Adversarial/prover-core entry point. It commits the caller-supplied folded
 * vector without first checking it against the source. A false candidate can
 * be committed and FRI-proved, but VerifyAuthenticatedLinearFamilyFoldV1 must
 * reject it at the rho-bound evaluation argument. This is intentional and
 * permits an executable adaptive-forgery regression.
 */
[[nodiscard]] AuthenticatedLinearFamilyFoldProveResultV1
ProveAuthenticatedLinearFamilyFoldCandidateV1(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& shards,
    const std::vector<Fp3>& folded_candidate);

[[nodiscard]] bool VerifyAuthenticatedLinearFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const AuthenticatedLinearFamilyFoldProofV1& proof,
    std::string* why = nullptr);

/**
 * Family batching for an already-constructed residual oracle. The prover
 * commits residual shards R[s,r], beta-folds them with the linear protocol,
 * and the verifier additionally requires R~(rho||beta)=0. A fixed nonzero
 * residual table passes only with the usual multilinear identity error over
 * beta and rho.
 *
 * This proves "the committed residual oracle is zero"; it does not by itself
 * prove that R was computed by the canonical constraint bytecode. The latter
 * source-root equality is the explicit constraint-VM integration gate.
 */
[[nodiscard]] AuthenticatedLinearFamilyFoldProveResultV1
ProveAuthenticatedZeroResidualFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldMetadataV1& metadata,
    const std::vector<std::vector<Fp3>>& residual_shards);

[[nodiscard]] bool VerifyAuthenticatedZeroResidualFamilyFoldV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const AuthenticatedLinearFamilyFoldProofV1& proof,
    std::string* why = nullptr);

/** Canonical proof-section codec. Public inputs stay in the enclosing
 * consensus statement and are deliberately not duplicated here. */
[[nodiscard]] size_t SerializeAuthenticatedLinearFamilyFoldProofV1(
    const AuthenticatedLinearFamilyFoldProofV1& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<AuthenticatedLinearFamilyFoldProofV1>
DeserializeAuthenticatedLinearFamilyFoldProofV1(
    const std::vector<unsigned char>& bytes);

/** Transcript audit hooks. They expose no prover secret and let tests pin the
 * exact epoch separation: beta uses only the statement and source root; rho
 * additionally uses the folded root. */
[[nodiscard]] bool DeriveAuthenticatedLinearFamilyBetaV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    std::vector<Fp3>& beta,
    std::string* why = nullptr);
[[nodiscard]] bool DeriveAuthenticatedLinearFamilyRhoV1(
    const AuthenticatedLinearFamilyFoldPublicInputsV1& public_inputs,
    const Fri3AlgDigest& folded_root,
    const std::vector<Fp3>& beta,
    std::vector<Fp3>& rho,
    std::string* why = nullptr);

struct NonlinearTraceFoldCounterexampleV1 {
    Fp3 beta{};
    Fp3 fold_then_square{};
    Fp3 square_then_fold{};
    bool unequal{false};
};

/** C(x)=x^2, T0=1, T1=2, beta=2: C(fold(T))=9 while
 * fold(C(T))=7. This is a permanent guard against treating this linear
 * primitive as a nonlinear relation proof. */
[[nodiscard]] NonlinearTraceFoldCounterexampleV1
BuildNonlinearTraceFoldCounterexampleV1();

} // namespace matmul::v4::rc::stage3_family_fold

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_FAMILY_FOLD_H
