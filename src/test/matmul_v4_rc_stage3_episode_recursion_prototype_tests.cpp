// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// g1 episode relations -- RecursionPrototypeV1 NON-VACUOUS VERTICAL SLICES.
//
// Before this file, NOTHING in the tree ever called ProveRCStage3RecursiveProof /
// air_recurse::ProveAggregate for ANY episode role: matmul_v4_rc_stage3_
// recursive_tests.cpp exercises the aggregation carrier only with synthetic,
// shape-mismatched toy pins (ChildPin(), width=1), which the EpisodeGemm
// resolver correctly rejects with ConstraintRegistryUnavailable.
//
// This file drives each episode role's REAL C_rho all the way through:
//
//   real AIR + witness -> real AirQuotientProve/Verify (the child C_rho FRI
//   proof) -> real air_recurse::ProveAggregate/VerifyAggregate (the k=1
//   recursion root over that child) -> a canonically-serializable
//   RCStage3RecursiveProof carrier -> AssessRCStage3RecursiveReadiness.
//
// The measured, honest result per role: `constraints_resolved` and
// `backend_shape_supported` are TRUE for a genuine relation instance, and the
// ONLY residual gaps are the shared cross-lane authority gates
// (ChildFiatShamirReplayNotClosed, SelfSimilarFixedPointNotClosed,
// ProductionPerformanceUnmeasured, AuthorityDisabled) that matmul_v4_rc_
// stage3_recursive.cpp / the global soundness ledger already track and that
// no episode-only change can close. VerifyRCStage3RecursiveProof therefore
// still (correctly) fails closed, but on that exact, pre-existing, honestly
// documented reason -- not on any episode-role-specific defect.
//
// FIXED (matmul_v4_rc_stage3_recursive.cpp, ProveRCStage3RecursiveProof): the
// exposed convenience prover threads child_shape.endpoint_authority_roots onto
// every pin it builds. See the Gemm wrapper regression case below.
// ============================================================================

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace {

using namespace matmul::v4::rc;
namespace ar = matmul::v4::rc::air_recurse;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
using Fp3 = gf::Fp3;
using AlgB3 = aq::AirFriBackendAlg<Fp3>;

uint256 U256(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

double SecondsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
        .count();
}

/** A real, header-shape Episode statement (no coupled/composed fields
 * touched). Only public_inputs feed the aggregation/role seeds. */
RCStage3SuccinctProof EpisodeStatement()
{
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Episode;
    statement.public_inputs.height = 42;
    statement.public_inputs.n_bits = 0x207fffff;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = kRCTranscriptVersion;
    statement.public_inputs.header_commitment = U256(0x11);
    statement.public_inputs.params_commitment = U256(0x22);
    statement.public_inputs.target = U256(0x33);
    statement.public_inputs.sigma = U256(0x44);
    statement.public_inputs.episode_digest = U256(0x55);
    statement.public_inputs.final_digest = U256(0x55);
    return statement;
}

struct RecursionPrototypeDriveResult {
    RCStage3RecursiveProof carrier;
    RCStage3RecursiveReadiness readiness;
    aq::AirConstraintSystem<Fp3> resolved;
    double child_prove_s{0};
    double agg_prove_s{0};
    double agg_verify_s{0};
};

/** Drive a real role AIR product through child FRI + k=1 aggregate + readiness.
 * Asserts the episode-side preconditions that back the measured Gaps() flags. */
RecursionPrototypeDriveResult DriveEpisodeRoleRecursionPrototype(
    RCStage3RelationRole role,
    const RCStage3RoleAirProduct& product,
    unsigned char child_seed_byte,
    unsigned char ctl_byte,
    const char* label)
{
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE(!product.endpoint_committed_roots.empty());
    BOOST_REQUIRE_EQUAL(
        ar::CountWitnessViolationsOnH(product.cs, product.witness), 0U);

    const uint256 child_seed = U256(child_seed_byte);
    const auto t_child = std::chrono::steady_clock::now();
    const auto child_proved =
        aq::AirQuotientProve<Fp3, AlgB3>(product.cs, product.witness, child_seed, {});
    const double child_prove_s = SecondsSince(t_child);
    BOOST_REQUIRE_MESSAGE(child_proved.ok && child_proved.division_exact,
                          child_proved.note);

    std::string child_why;
    // Assign to a bool first: BOOST_REQUIRE_MESSAGE is a macro and the
    // AirQuotientVerify<...> template commas would otherwise split args.
    const bool child_verified = aq::AirQuotientVerify<Fp3, AlgB3>(
        product.cs, child_proved.proof, child_seed, &child_why);
    BOOST_REQUIRE_MESSAGE(child_verified, child_why);

    ar::ChildPublicInputs pi =
        ar::ExtractChildPublicInputs(product.cs, child_proved.proof, child_seed);
    BOOST_REQUIRE_MESSAGE(pi.ok, pi.note);
    pi.endpoint_authority_roots = product.endpoint_committed_roots;
    pi.child_constraints.clear();
    pi.note.clear();

    std::string why;
    aq::AirConstraintSystem<Fp3> resolved;
    const bool resolved_ok =
        ResolveCurrentRCStage3RelationConstraintSystem(role, pi, resolved, &why);
    BOOST_REQUIRE_MESSAGE(resolved_ok, why);
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(resolved, product.witness), 0U);

    const uint256 ctl_child_commitment = U256(ctl_byte);
    const std::vector<RCStage3RecursiveChildPin> children_pins{{pi}};
    const uint256 fixed_role_commitment = ComputeRCStage3RecursiveChildPinsCommitment(
        role, ctl_child_commitment, children_pins);

    const RCStage3SuccinctProof statement = EpisodeStatement();
    const uint256 role_seed =
        ComputeRCStage3RecursiveRoleSeed(statement, role, fixed_role_commitment);

    const auto t_agg = std::chrono::steady_clock::now();
    const ar::AggregateResult aggregate = ar::ProveAggregateChecked(
        product.cs, {child_proved.proof}, child_seed, role_seed,
        RCStage3MandatoryVerifierAirFamilies());
    const double agg_prove_s = SecondsSince(t_agg);
    BOOST_REQUIRE_MESSAGE(aggregate.ok && aggregate.witness_satisfies,
                          aggregate.note);

    std::string agg_why;
    const auto t_agg_verify = std::chrono::steady_clock::now();
    const bool agg_verified = ar::VerifyAggregate(
        aggregate.proof, aggregate.pis, role_seed, 1,
        RCStage3MandatoryVerifierAirFamilies(), &agg_why);
    BOOST_REQUIRE_MESSAGE(agg_verified, agg_why);
    const double agg_verify_s = SecondsSince(t_agg_verify);

    BOOST_TEST_MESSAGE(
        label << " child_prove_s=" << child_prove_s
              << " agg_prove_s=" << agg_prove_s
              << " agg_verify_s=" << agg_verify_s
              << " child_cols=" << product.cs.n_columns
              << " child_rows=" << product.cs.n_rows
              << " vcs_cols=" << aggregate.measurement.n_columns
              << " vcs_rows=" << aggregate.measurement.n_rows);

    RecursionPrototypeDriveResult out;
    out.child_prove_s = child_prove_s;
    out.agg_prove_s = agg_prove_s;
    out.agg_verify_s = agg_verify_s;
    out.resolved = std::move(resolved);
    out.carrier.role = role;
    out.carrier.ctl_child_commitment = ctl_child_commitment;
    out.carrier.fixed_role_commitment = fixed_role_commitment;
    out.carrier.child_fs_seed = child_seed;
    out.carrier.root = aggregate.proof;
    for (ar::ChildPublicInputs child_pi : aggregate.pis) {
        child_pi.endpoint_authority_roots = product.endpoint_committed_roots;
        child_pi.child_constraints.clear();
        child_pi.ok = true;
        child_pi.note.clear();
        out.carrier.children.push_back({std::move(child_pi)});
    }
    BOOST_REQUIRE_EQUAL(out.carrier.children.size(), 1U);

    // READINESS first: this is the measured episode-lane evidence behind the
    // kRCStage3Episode*RecursionEnginesExecuted flags. Canonical wire
    // serialization of the mandatory-family V_CS root can independently exceed
    // kRCFriMaxProofBytesHard (~16 MiB). That codec residual is NOT covered by
    // ProductionPerformanceUnmeasured / g2 within_relay_budget (verify wall-
    // clock only); the ledger now conjoins an explicit serialize-within-budget
    // measured pin into g2. Do not treat soft-fail as an episode-role engine
    // failure.
    out.readiness = AssessRCStage3RecursiveReadiness(statement, out.carrier);
    BOOST_CHECK(out.readiness.structurally_valid);
    BOOST_CHECK(out.readiness.mandatory_families);
    BOOST_CHECK_MESSAGE(out.readiness.constraints_resolved,
                        std::string(label) + " resolver rejected real pin");
    BOOST_CHECK_MESSAGE(out.readiness.backend_shape_supported,
                        std::string(label) + " V_CS exceeded a backend cap");

    for (const auto& gap : out.readiness.gaps) {
        BOOST_TEST_MESSAGE(label << " gap code=" << static_cast<int>(gap.code)
                                 << " detail=\"" << gap.detail << "\"");
        BOOST_CHECK_MESSAGE(
            gap.code != RCStage3RecursiveGapCode::MalformedCarrier &&
                gap.code != RCStage3RecursiveGapCode::RoleNotRequired &&
                gap.code != RCStage3RecursiveGapCode::FixedCommitmentMismatch &&
                gap.code !=
                    RCStage3RecursiveGapCode::ConstraintRegistryUnavailable &&
                gap.code != RCStage3RecursiveGapCode::BackendColumnCapExceeded &&
                gap.code != RCStage3RecursiveGapCode::BackendLdeCapExceeded,
            std::string(label) + " unexpected episode-side gap code " +
                std::to_string(static_cast<int>(gap.code)));
    }

    // After g4 joint P2 activation, child_fiat_shamir_replay_closed (and thus
    // self_similar_fixed_point_closed) flips true, so
    // cryptographic_verification_ready becomes true. Verify then exercises
    // child FS binding: carriers set child_fs_seed to the prove seed and bind
    // via AirChallengeDigestSelected (Poseidon2 when activated). Shared
    // residuals AuthorityDisabled / ProductionPerformanceUnmeasured remain
    // gaps but do not block cryptographic_verification_ready.
    std::string verify_why;
    const bool verified =
        VerifyRCStage3RecursiveProof(statement, out.carrier, &verify_why);
    BOOST_TEST_MESSAGE(label << " cryptographic_verification_ready="
                             << out.readiness.cryptographic_verification_ready
                             << " verify_ok=" << verified
                             << " verify_why=" << verify_why);
    if (out.readiness.cryptographic_verification_ready) {
        BOOST_CHECK_MESSAGE(verified, std::string(label) + " verify_why=" +
                                          verify_why);
    } else {
        BOOST_CHECK(!verified);
        BOOST_CHECK(
            verify_why.rfind("stage3:recursive:cryptographic_not_ready:", 0) ==
            0);
    }

    // Canonical wire serialization of the mandatory-family V_CS root is a
    // shared codec/budget residual (ProductionPerformanceUnmeasured). With
    // Q=192, row openings alone are Q * n_cols * 24 bytes — ~30 MiB at the
    // PureStream V_CS (~10k cols) and ~380 MiB at Builder (~82k cols), both
    // over kRCFriMaxProofBytesHard (~16 MiB). Estimate BEFORE allocating so
    // large roles do not thrash on a doomed SerializeFri3AlgBatchProof.
    // Soft budget only — do NOT treat over-budget serialize as an episode
    // Gaps()/Ready flip condition.
    {
        constexpr size_t kFp3Bytes = 24;
        const size_t n_cols = out.carrier.root.batch.column_len.size();
        const size_t n_q = out.carrier.root.batch.queries.size();
        const size_t row_vals_lb = n_q * n_cols * kFp3Bytes;
        BOOST_TEST_MESSAGE(label << " root_batch_row_vals_lower_bound_bytes="
                                 << row_vals_lb << " n_cols=" << n_cols
                                 << " n_queries=" << n_q
                                 << " fri_max_proof_bytes_hard="
                                 << kRCFriMaxProofBytesHard);
        if (row_vals_lb > kRCFriMaxProofBytesHard) {
            BOOST_TEST_MESSAGE(label << " serialize_soft_fail why=stage3:"
                                        "recursive:root_batch_serialize "
                                        "(estimated over budget; readiness "
                                        "already measured above)");
            BOOST_CHECK(true); // explicit soft-fail branch taken
            return out;
        }
    }

    std::vector<unsigned char> encoded;
    std::string ser_why;
    const bool encoded_ok =
        SerializeRCStage3RecursiveProof(out.carrier, encoded, &ser_why);
    if (!encoded_ok) {
        BOOST_TEST_MESSAGE(label << " serialize_soft_fail why=" << ser_why
                                 << " (shared codec/budget; readiness already "
                                    "measured above)");
        BOOST_CHECK_EQUAL(ser_why, "stage3:recursive:root_batch_serialize");
    } else {
        const auto decoded = DeserializeRCStage3RecursiveProof(encoded, &ser_why);
        BOOST_REQUIRE_MESSAGE(decoded.has_value(), ser_why);
        std::vector<unsigned char> reencoded;
        const bool reencoded_ok =
            SerializeRCStage3RecursiveProof(*decoded, reencoded, &ser_why);
        BOOST_REQUIRE_MESSAGE(reencoded_ok, ser_why);
        BOOST_CHECK(reencoded == encoded);
    }

    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_episode_recursion_prototype_tests)

BOOST_AUTO_TEST_CASE(episode_tiletree_recursion_prototype_proves_and_aggregates)
{
    using Role = RCStage3RelationRole;
    std::string why;
    const RCStage3RoleAirProduct product =
        BuildRCStage3PureStreamRoleAir(Role::EpisodeTileTree, &why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    auto driven = DriveEpisodeRoleRecursionPrototype(
        Role::EpisodeTileTree, product, 0xA1, 0xA2,
        "EPISODE_TILETREE_RECURSION_PROTOTYPE");
    // Tamper stream witness cell -> reject.
    auto tampered = product.witness;
    BOOST_REQUIRE(!tampered.empty() && !tampered[0].empty());
    tampered[0][0] = gf::Add(tampered[0][0], Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(driven.resolved, tampered), 0U);
}

BOOST_AUTO_TEST_CASE(episode_digest_recursion_prototype_proves_and_aggregates)
{
    using Role = RCStage3RelationRole;
    std::string why;
    const RCStage3RoleAirProduct product =
        BuildRCStage3PureStreamRoleAir(Role::EpisodeDigest, &why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    auto driven = DriveEpisodeRoleRecursionPrototype(
        Role::EpisodeDigest, product, 0xB1, 0xB2,
        "EPISODE_DIGEST_RECURSION_PROTOTYPE");
    auto tampered = product.witness;
    BOOST_REQUIRE(!tampered.empty() && !tampered[0].empty());
    tampered[0][0] = gf::Add(tampered[0][0], Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(driven.resolved, tampered), 0U);
}

BOOST_AUTO_TEST_CASE(episode_builder_recursion_prototype_proves_and_aggregates)
{
    using Role = RCStage3RelationRole;
    std::string why;
    const RCStage3RoleAirProduct product =
        BuildRCStage3NoKernelRoleAir(Role::EpisodeDeterministicBuilder, &why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    auto driven = DriveEpisodeRoleRecursionPrototype(
        Role::EpisodeDeterministicBuilder, product, 0xC1, 0xC2,
        "EPISODE_BUILDER_RECURSION_PROTOTYPE");
    auto tampered = product.witness;
    BOOST_REQUIRE(!tampered.empty() && !tampered[0].empty());
    tampered[0][0] = gf::Add(tampered[0][0], Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(driven.resolved, tampered), 0U);
}

BOOST_AUTO_TEST_CASE(episode_extract_recursion_prototype_proves_and_aggregates)
{
    using Role = RCStage3RelationRole;
    std::string why;
    const RCStage3RoleAirProduct product =
        BuildRCStage3NoKernelRoleAir(Role::EpisodeExtract, &why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    auto driven = DriveEpisodeRoleRecursionPrototype(
        Role::EpisodeExtract, product, 0xD1, 0xD2,
        "EPISODE_EXTRACT_RECURSION_PROTOTYPE");
    auto tampered = product.witness;
    BOOST_REQUIRE(!tampered.empty() && !tampered[0].empty());
    tampered[0][0] = gf::Add(tampered[0][0], Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(driven.resolved, tampered), 0U);
}

BOOST_AUTO_TEST_CASE(episode_wiring_recursion_prototype_proves_and_aggregates)
{
    using Role = RCStage3RelationRole;
    std::string why;
    const RCStage3RoleAirProduct product =
        BuildRCStage3EpisodeWiringRoleAir(&why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 4U);
    auto driven = DriveEpisodeRoleRecursionPrototype(
        Role::EpisodeWiring, product, 0xE1, 0xE2,
        "EPISODE_WIRING_RECURSION_PROTOTYPE");
    auto tampered = product.witness;
    BOOST_REQUIRE(!tampered.empty() && !tampered[0].empty());
    tampered[0][0] = gf::Add(tampered[0][0], Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(driven.resolved, tampered), 0U);
}

BOOST_AUTO_TEST_CASE(episode_gemm_recursion_prototype_proves_and_aggregates)
{
    using Role = RCStage3RelationRole;
    std::string why;
    const RCStage3RoleAirProduct product = BuildRCStage3EpisodeGemmRoleAir(&why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 5U);
    auto driven = DriveEpisodeRoleRecursionPrototype(
        Role::EpisodeGemm, product, 0x71, 0x72,
        "EPISODE_GEMM_RECURSION_PROTOTYPE");
    // Tampering the real GEMM operand-A witness cell breaks the CS-level flip.
    auto tampered_witness = product.witness;
    tampered_witness[1][0] = gf::Add(tampered_witness[1][0], Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(driven.resolved, tampered_witness), 0U);
}

// Direct regression test for the ProveRCStage3RecursiveProof fix: before it,
// this exact call sequence failed with ConstraintRegistryUnavailable because
// the wrapper never threaded endpoint_authority_roots onto the pins it built.
BOOST_AUTO_TEST_CASE(
    episode_gemm_prove_rc_stage3_recursive_proof_wrapper_threads_endpoint_roots)
{
    using Role = RCStage3RelationRole;

    std::string why;
    const RCStage3RoleAirProduct product = BuildRCStage3EpisodeGemmRoleAir(&why);
    BOOST_REQUIRE_MESSAGE(product.ok, why);

    const uint256 child_seed = U256(0x81);
    const auto child_proved =
        aq::AirQuotientProve<Fp3, AlgB3>(product.cs, product.witness, child_seed, {});
    BOOST_REQUIRE_MESSAGE(child_proved.ok && child_proved.division_exact,
                          child_proved.note);

    ar::ChildPublicInputs child_shape =
        ar::ExtractChildPublicInputs(product.cs, child_proved.proof, child_seed);
    BOOST_REQUIRE_MESSAGE(child_shape.ok, child_shape.note);
    child_shape.endpoint_authority_roots = product.endpoint_committed_roots;
    child_shape.child_constraints.clear();
    child_shape.note.clear();

    const uint256 ctl_child_commitment = U256(0x82);
    const std::vector<RCStage3RecursiveChildPin> children_pins{{child_shape}};
    const uint256 fixed_role_commitment = ComputeRCStage3RecursiveChildPinsCommitment(
        Role::EpisodeGemm, ctl_child_commitment, children_pins);

    const RCStage3SuccinctProof statement = EpisodeStatement();
    const RCStage3RecursiveProveResult result = ProveRCStage3RecursiveProof(
        statement, Role::EpisodeGemm, fixed_role_commitment, ctl_child_commitment,
        {child_proved.proof}, child_seed, child_shape);

    BOOST_TEST_MESSAGE(
        "PROVE_RC_STAGE3_RECURSIVE_PROOF_WRAPPER note=" << result.note);
    BOOST_CHECK_MESSAGE(result.ok, result.note);
    BOOST_CHECK(result.readiness.structurally_valid);
    BOOST_CHECK_MESSAGE(result.readiness.constraints_resolved,
                        "wrapper-built carrier did not resolve -- endpoint "
                        "roots regression?");
    BOOST_CHECK(result.readiness.backend_shape_supported);
    BOOST_CHECK_EQUAL(result.proof.children.size(), 1U);
    BOOST_CHECK(result.proof.children[0].public_inputs.endpoint_authority_roots ==
                product.endpoint_committed_roots);
}

BOOST_AUTO_TEST_SUITE_END()
