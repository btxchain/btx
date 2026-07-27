// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <algorithm>
#include <chrono>
#include <vector>

namespace {

using namespace matmul::v4::rc;
using Fp3 = gkr_field::Fp3;

uint256 U256(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

Fri3AlgDigest Digest(gkr_field::Fp value)
{
    return {value, value + 1, value + 2, value + 3};
}

air_recurse::ChildPublicInputs ChildPin(uint32_t width = 1,
                                        uint32_t n_coeffs = 2)
{
    air_recurse::ChildPublicInputs pi;
    pi.child_n_rows = 2;
    pi.child_w = width;
    pi.child_quotient_len = 2;
    pi.child_n_coeffs = n_coeffs;
    pi.child_n_lde = n_coeffs * kRCFriBlowup;
    auto log2 = [](uint32_t value) {
        uint32_t out = 0;
        while (value > 1) {
            value >>= 1;
            ++out;
        }
        return out;
    };
    pi.merkle_depth = log2(pi.child_n_lde);
    pi.n_folds = log2(n_coeffs);
    pi.row_commit_root = Digest(1);
    pi.rt_root = Digest(5);
    pi.fold_roots.assign(pi.n_folds, Digest(9));
    pi.fri_lambda = Fp3{1, 2, 3};
    pi.z1 = Fp3{4, 5, 6};
    pi.z2 = Fp3{7, 8, 9};
    pi.w1 = Fp3{10, 11, 12};
    pi.w2 = Fp3{13, 14, 15};
    pi.final_value = Fp3{16, 17, 18};
    pi.air_lambda = Fp3{19, 20, 21};
    pi.fold_challenges.assign(pi.n_folds, Fp3{22, 23, 24});
    pi.column_len.assign(width + 1, 2);
    pi.evals_z1.assign(width + 1, Fp3{25, 26, 27});
    pi.evals_z2.assign(width + 1, Fp3{28, 29, 30});
    pi.query_index.resize(kRCFri3AlgNumQueries);
    for (uint32_t i = 0; i < kRCFri3AlgNumQueries; ++i) {
        pi.query_index[i] = i % pi.child_n_lde;
    }
    pi.ok = true;
    return pi;
}

RCStage3SuccinctProof Statement(RCStage3RelationRole role,
                                const uint256& commitment)
{
    RCStage3SuccinctProof statement;
    statement.statement = RCStage3StatementKind::Episode;
    statement.public_inputs.height = 1;
    statement.public_inputs.n_bits = 1;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.header_commitment = U256(1);
    statement.public_inputs.params_commitment = U256(2);
    statement.public_inputs.target = U256(3);
    statement.public_inputs.sigma = U256(4);
    statement.public_inputs.episode_digest = U256(5);
    statement.public_inputs.final_digest = U256(5);
    statement.public_inputs.transcript_commitment = U256(6);
    for (RCStage3RelationRole required :
         RequiredRCStage3RelationRoles(statement.statement)) {
        statement.commitments.push_back(
            {required, required == role ? commitment : U256(
                 static_cast<unsigned char>(static_cast<uint16_t>(required)))});
        statement.sections.push_back({required, {1}});
    }
    return statement;
}

RCStage3CtlChildPin CtlPin(RCStage3RelationRole role)
{
    RCStage3CtlChildPin pin;
    pin.role = role;
    pin.bus_id = 7;
    pin.event_count = 2;
    pin.send_count = 1;
    pin.receive_count = 1;
    pin.schedule_commitment = U256(41);
    pin.trace_commitment = U256(42);
    pin.auxiliary_commitment = U256(43);
    pin.challenge_commitment = U256(44);
    return pin;
}

RCStage3RecursiveProof Carrier()
{
    RCStage3RecursiveProof proof;
    proof.role = RCStage3RelationRole::EpisodeGemm;
    proof.children.push_back({ChildPin()});
    proof.ctl_child_commitment =
        CommitRCStage3CtlChildPin(CtlPin(proof.role));
    proof.fixed_role_commitment =
        ComputeRCStage3RecursiveChildPinsCommitment(
            proof.role, proof.ctl_child_commitment, proof.children);

    auto& batch = proof.root.batch;
    // PR-89 g4 ACTIVATION: the codec validates against the LIVE lane
    // version, so this synthetic carrier must move with it.
    batch.version = kRCFri3AlgActiveBatchProofVersion;
    batch.blowup = kRCFriBlowup;
    batch.n_coeffs = 2;
    batch.row_commit.root = Digest(31);
    batch.row_commit.n_leaves = 32;
    batch.column_len = {2, 2};
    batch.lambda = Fp3{1, 1, 1};
    batch.z1 = Fp3{2, 2, 2};
    batch.z2 = Fp3{3, 3, 3};
    batch.evals_z1 = {Fp3{4, 4, 4}, Fp3{5, 5, 5}};
    batch.evals_z2 = {Fp3{6, 6, 6}, Fp3{7, 7, 7}};
    batch.w1 = Fp3{8, 8, 8};
    batch.w2 = Fp3{9, 9, 9};
    batch.fold_layers = {{Digest(40), 32}, {Digest(44), 16}};
    batch.final_value = Fp3{10, 10, 10};
    batch.fold_challenges = {Fp3{11, 11, 11}};
    batch.queries.resize(kRCFri3AlgNumQueries);
    for (uint32_t i = 0; i < kRCFri3AlgNumQueries; ++i) {
        auto& query = batch.queries[i];
        query.index = i % 32;
        query.row.values = {Fp3{12, 12, 12}, Fp3{13, 13, 13}};
        query.row.siblings.assign(5, Digest(50));
        Fri3AlgFoldStep step;
        step.even_index = i % 16;
        step.odd_index = step.even_index + 16;
        step.even = Fp3{14, 14, 14};
        step.odd = Fp3{15, 15, 15};
        step.even_siblings.assign(5, Digest(60));
        step.odd_siblings.assign(5, Digest(70));
        query.steps.push_back(std::move(step));
    }
    proof.root.trace_commit = Fri3AlgDigestToUint256(Digest(80));
    proof.root.next_openings.resize(kRCFri3AlgNumQueries);
    for (uint32_t i = 0; i < kRCFri3AlgNumQueries; ++i) {
        air_quotient::AirAlgRowPath next;
        next.index = (i + 1) % 32;
        next.values = {Fp3{16, 16, 16}, Fp3{17, 17, 17}};
        next.siblings.assign(5, Digest(90));
        air_quotient::AirAlgRowPath trace;
        trace.index = i % 32;
        trace.siblings.assign(5, Digest(100));
        proof.root.next_openings[i] = {std::move(next), std::move(trace)};
    }
    return proof;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_recursive_tests)

BOOST_AUTO_TEST_CASE(canonical_recursive_codec_roundtrip)
{
    const RCStage3RecursiveProof proof = Carrier();
    std::vector<unsigned char> bytes;
    std::string why;
    BOOST_REQUIRE_MESSAGE(SerializeRCStage3RecursiveProof(proof, bytes, &why), why);
    const auto decoded = DeserializeRCStage3RecursiveProof(bytes, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(decoded->children == proof.children);
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(decoded->role),
                      static_cast<uint16_t>(proof.role));
    BOOST_CHECK(decoded->fixed_role_commitment == proof.fixed_role_commitment);
    BOOST_CHECK(decoded->ctl_child_commitment ==
                proof.ctl_child_commitment);

    std::vector<unsigned char> roundtrip;
    BOOST_REQUIRE(SerializeRCStage3RecursiveProof(*decoded, roundtrip, &why));
    BOOST_CHECK(roundtrip == bytes);
}

BOOST_AUTO_TEST_CASE(recursive_codec_requires_real_fri_terminal_layer)
{
    RCStage3RecursiveProof missing_terminal = Carrier();
    missing_terminal.root.batch.fold_layers.pop_back();
    std::vector<unsigned char> bytes;
    std::string why;
    BOOST_CHECK(
        !SerializeRCStage3RecursiveProof(missing_terminal, bytes, &why));
    BOOST_CHECK(
        why.find("root_batch_vectors") != std::string::npos);

    RCStage3RecursiveProof wrong_terminal = Carrier();
    wrong_terminal.root.batch.fold_layers.back().n_leaves = 8;
    BOOST_CHECK(
        !SerializeRCStage3RecursiveProof(wrong_terminal, bytes, &why));
    BOOST_CHECK(
        why.find("root_fold_layer_shape") != std::string::npos ||
        why.find("root_terminal_layer_shape") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(codec_rejects_mutations_and_allocation_claims)
{
    std::vector<unsigned char> bytes;
    std::string why;
    BOOST_REQUIRE(SerializeRCStage3RecursiveProof(Carrier(), bytes, &why));

    auto mutation = bytes;
    mutation[0] ^= 1;
    BOOST_CHECK(!DeserializeRCStage3RecursiveProof(mutation, &why).has_value());

    mutation = bytes;
    mutation[10] = 1; // reserved u16
    BOOST_CHECK(!DeserializeRCStage3RecursiveProof(mutation, &why).has_value());

    mutation = bytes;
    mutation.pop_back();
    BOOST_CHECK(!DeserializeRCStage3RecursiveProof(mutation, &why).has_value());

    mutation = bytes;
    mutation.push_back(0);
    BOOST_CHECK(!DeserializeRCStage3RecursiveProof(mutation, &why).has_value());

    mutation = bytes;
    // child count is at byte 76; UINT32_MAX must fail before allocation.
    std::fill(mutation.begin() + 76, mutation.begin() + 80, 0xff);
    BOOST_CHECK(!DeserializeRCStage3RecursiveProof(mutation, &why).has_value());
}

BOOST_AUTO_TEST_CASE(seed_binds_public_inputs_and_role_pins_without_proof_cycle)
{
    const RCStage3RecursiveProof carrier = Carrier();
    RCStage3SuccinctProof statement =
        Statement(carrier.role, carrier.fixed_role_commitment);
    const uint256 seed = ComputeRCStage3RecursiveRoleSeed(
        statement, carrier.role, carrier.fixed_role_commitment);

    auto changed_public = statement;
    changed_public.public_inputs.height++;
    BOOST_CHECK(seed != ComputeRCStage3RecursiveRoleSeed(
                            changed_public, carrier.role,
                            carrier.fixed_role_commitment));

    auto changed_other_root = statement;
    changed_other_root.commitments.front().root = U256(201);
    BOOST_CHECK(seed == ComputeRCStage3RecursiveRoleSeed(
                            changed_other_root, carrier.role,
                            carrier.fixed_role_commitment));

    const uint256 changed_role_pins = U256(202);
    BOOST_CHECK(seed != ComputeRCStage3RecursiveRoleSeed(
                            statement, carrier.role, changed_role_pins));

    auto changed_root_bytes = carrier;
    changed_root_bytes.root.batch.pow_grind_nonce++;
    BOOST_CHECK(seed == ComputeRCStage3RecursiveRoleSeed(
                            statement, changed_root_bytes.role,
                            changed_root_bytes.fixed_role_commitment));
}

BOOST_AUTO_TEST_CASE(readiness_is_exact_and_authority_stays_fail_closed)
{
    const RCStage3RecursiveProof carrier = Carrier();
    const RCStage3SuccinctProof statement =
        Statement(carrier.role, carrier.fixed_role_commitment);
    const RCStage3RecursiveReadiness report =
        AssessRCStage3RecursiveReadiness(statement, carrier);
    BOOST_CHECK(report.structurally_valid);
    BOOST_CHECK(report.mandatory_families);
    BOOST_CHECK(!report.constraints_resolved);
    BOOST_CHECK(!report.cryptographic_verification_ready);
    BOOST_CHECK(!report.production_ready);
    BOOST_CHECK_EQUAL(report.soundness_bits,
                      static_cast<uint32_t>(Fri3AlgSoundnessBoundBits()));

    auto has = [&](RCStage3RecursiveGapCode code) {
        return std::any_of(report.gaps.begin(), report.gaps.end(),
                           [&](const RCStage3RecursiveGap& gap) {
                               return gap.code == code;
                           });
    };
    BOOST_CHECK(has(RCStage3RecursiveGapCode::ConstraintRegistryUnavailable));
    BOOST_CHECK_EQUAL(
        has(RCStage3RecursiveGapCode::SoundnessTargetNotMet),
        report.soundness_bits < kRCStage3RecursiveTargetSoundnessBits);
    BOOST_CHECK(has(RCStage3RecursiveGapCode::ChildFiatShamirReplayNotClosed));
    BOOST_CHECK(has(RCStage3RecursiveGapCode::SelfSimilarFixedPointNotClosed));
    BOOST_CHECK(has(RCStage3RecursiveGapCode::ProductionPerformanceUnmeasured));
    BOOST_CHECK(has(RCStage3RecursiveGapCode::AuthorityDisabled));

    std::string why;
    BOOST_CHECK(!VerifyRCStage3RecursiveProof(statement, carrier, &why));
    BOOST_CHECK(
        why.rfind(
            "stage3:recursive:cryptographic_not_ready:", 0) == 0);
}

BOOST_AUTO_TEST_CASE(commitment_and_role_mutations_reject_before_aggregate)
{
    RCStage3RecursiveProof carrier = Carrier();
    RCStage3SuccinctProof statement =
        Statement(carrier.role, carrier.fixed_role_commitment);

    carrier.fixed_role_commitment = U256(43);
    const auto mismatch =
        AssessRCStage3RecursiveReadiness(statement, carrier);
    BOOST_CHECK(std::any_of(
        mismatch.gaps.begin(), mismatch.gaps.end(),
        [](const RCStage3RecursiveGap& gap) {
            return gap.code ==
                   RCStage3RecursiveGapCode::FixedCommitmentMismatch;
        }));

    carrier = Carrier();
    carrier.role = RCStage3RelationRole::CoupledBank;
    const auto wrong_role =
        AssessRCStage3RecursiveReadiness(statement, carrier);
    BOOST_CHECK(std::any_of(
        wrong_role.gaps.begin(), wrong_role.gaps.end(),
        [](const RCStage3RecursiveGap& gap) {
            return gap.code == RCStage3RecursiveGapCode::RoleNotRequired;
        }));
}

BOOST_AUTO_TEST_CASE(recursive_role_proof_binds_exact_ctl_public_pin)
{
    const RCStage3RecursiveProof carrier = Carrier();
    const RCStage3CtlChildPin ctl = CtlPin(carrier.role);
    std::string why;
    BOOST_REQUIRE(
        ValidateRCStage3RecursiveCtlBinding(carrier, ctl, &why));

    auto terminal = ctl;
    terminal.terminal.alpha2_sum = Fp3::One();
    BOOST_CHECK(
        !ValidateRCStage3RecursiveCtlBinding(carrier, terminal, &why));
    BOOST_CHECK(why.find("ctl_binding:commitment") != std::string::npos);

    auto role = ctl;
    role.role = RCStage3RelationRole::EpisodeExtract;
    BOOST_CHECK(!ValidateRCStage3RecursiveCtlBinding(
        carrier, role, &why));
    BOOST_CHECK(why.find("ctl_binding:role") != std::string::npos);

    auto commitment = carrier;
    commitment.ctl_child_commitment = U256(0xe0);
    const auto report =
        AssessRCStage3RecursiveReadiness(
            Statement(commitment.role, commitment.fixed_role_commitment),
            commitment);
    BOOST_CHECK(std::any_of(
        report.gaps.begin(), report.gaps.end(),
        [](const RCStage3RecursiveGap& gap) {
            return gap.code ==
                   RCStage3RecursiveGapCode::FixedCommitmentMismatch;
        }));
}

// The raw per-child AIR-batching challenge exactly as
// air_recurse::ExtractChildPublicInputs derives it: FromChallengeBytes3 over
// AirChallengeDigestSelected(kAirChallengeP2Activated, seed, "airq_lambda",
// {trace_commit}, {N, quotient_len, W}).
Fp3 DeriveAirLambda(const uint256& seed,
                    const air_recurse::ChildPublicInputs& pin)
{
    const uint256 trace_commit = Fri3AlgDigestToUint256(pin.rt_root);
    const std::vector<uint256> roots{trace_commit};
    const uint256 d = air_quotient::AirChallengeDigestSelected(
        air_quotient::kAirChallengeP2Activated, seed, "airq_lambda", roots,
        {pin.child_n_rows, pin.child_quotient_len, pin.child_w});
    return gkr_field::FromChallengeBytes3(d.data());
}

// P4: the Fiat-Shamir point must bind the recursion node/slot position so
// (a) distinct positions derive distinct challenges and (b) a child receipt
// proved at one (node_id, slot_index) is rejected when replayed at another.
BOOST_AUTO_TEST_CASE(fs_point_binds_node_and_slot_position_p4)
{
    const RCStage3RecursiveProof carrier = Carrier();
    const RCStage3SuccinctProof statement =
        Statement(carrier.role, carrier.fixed_role_commitment);

    // --- Role seed is position-unique across the tree. ---
    const RCStage3RecursivePosition pos_a{/*node_id=*/10, /*slot_index=*/0};
    const RCStage3RecursivePosition pos_b{/*node_id=*/77, /*slot_index=*/3};
    const uint256 seed_a = ComputeRCStage3RecursiveRoleSeed(
        statement, carrier.role, carrier.fixed_role_commitment, pos_a);
    const uint256 seed_b = ComputeRCStage3RecursiveRoleSeed(
        statement, carrier.role, carrier.fixed_role_commitment, pos_b);
    // Different node/slot -> different FS base (previously collidable).
    BOOST_CHECK(seed_a != seed_b);
    // Same position is deterministic.
    BOOST_CHECK(seed_a == ComputeRCStage3RecursiveRoleSeed(
                              statement, carrier.role,
                              carrier.fixed_role_commitment, pos_a));
    // Slot alone distinguishes two children of the SAME node.
    const RCStage3RecursivePosition slot0{/*node_id=*/10, /*slot_index=*/0};
    const RCStage3RecursivePosition slot1{/*node_id=*/10, /*slot_index=*/1};
    BOOST_CHECK(ComputeRCStage3RecursiveChildFsPoint(
                    seed_a, carrier.role, slot0) !=
                ComputeRCStage3RecursiveChildFsPoint(
                    seed_a, carrier.role, slot1));

    // --- Cross-slot receipt replay. ---
    const uint256 base = seed_a;  // node aggregate FS base
    air_recurse::ChildPublicInputs receipt = ChildPin();
    // A genuine receipt commits the challenge derived at ITS true position A.
    const uint256 point_a =
        ComputeRCStage3RecursiveChildFsPoint(base, carrier.role, pos_a);
    receipt.air_lambda = DeriveAirLambda(point_a, receipt);

    std::string why;
    // Accepted at the true (node A, slot i).
    BOOST_CHECK(VerifyRCStage3RecursiveChildFsBinding(
        base, carrier.role, pos_a, receipt, &why));
    // Rejected when replayed at a different (node B, slot j) — the exact
    // cross-slot replay the adversarial review flagged.
    BOOST_CHECK(!VerifyRCStage3RecursiveChildFsBinding(
        base, carrier.role, pos_b, receipt, &why));
    BOOST_CHECK(why.find("child_fs_binding:air_lambda_position_mismatch") !=
                std::string::npos);

    // --- Pre-fix baseline: without position binding the challenge is derived
    // straight from the raw base seed, so it is identical at every position and
    // the replay above WOULD have passed. This models the unbound FS point. ---
    const Fp3 unbound = DeriveAirLambda(base, receipt);
    BOOST_CHECK(gkr_field::Eq(unbound, DeriveAirLambda(base, receipt)));
    // The unbound challenge does NOT equal the position-bound one, i.e. the fix
    // actually changes the derived challenge.
    BOOST_CHECK(!gkr_field::Eq(unbound, receipt.air_lambda));
    // And the two positions collapse to the SAME unbound challenge (the replay
    // hole), whereas their position-bound points differ.
    BOOST_CHECK(ComputeRCStage3RecursiveChildFsPoint(base, carrier.role, pos_a) !=
                ComputeRCStage3RecursiveChildFsPoint(base, carrier.role, pos_b));
}

// ---------------------------------------------------------------------------
// FIRST genuine constraints_resolved flip (CS-level): the resolver returns real
// C_ρ for CoupledPermutation, pinning each opening block to the endpoint
// AUTHORITY ROOT the child pin committed. Honest witness (from the child's real
// committed column) satisfies the resolved CS; any child/opening tamper fails.
// This is CS-level (CountWitnessViolationsOnH); the full FRI round-trip is the
// aggregation/g2 leg.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_at_cs_level)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0x2bad10ULL));
    const uint32_t path_len = 3; // rows = 4
    const RCStage3RoleAirProduct product =
        BuildRCStage3CoupledPermutationRoleAir(cell, 0, path_len, nullptr);
    BOOST_REQUIRE(product.ok);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 2U);

    // A child pin that carries the authority roots the child genuinely committed
    // (in required-endpoint order), at the resolved shape.
    ar::ChildPublicInputs pin;
    pin.child_n_rows = path_len + 1;
    pin.child_w = product.cs.n_columns;
    pin.endpoint_authority_roots = product.endpoint_committed_roots;

    // The resolver returns real C_ρ (no complete_air_unavailable).
    air_quotient::AirConstraintSystem<Fp3> resolved;
    std::string why;
    const bool ok = ResolveCurrentRCStage3RelationConstraintSystem(
        RCStage3RelationRole::CoupledPermutation, pin, resolved, &why);
    BOOST_REQUIRE_MESSAGE(ok, why);
    BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
    BOOST_CHECK_EQUAL(resolved.n_rows, pin.child_n_rows);
    BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);

    // Completeness gate is satisfied: one in-trace opening block per endpoint.
    BOOST_CHECK_EQUAL(
        RCStage3RequiredInCsOpeningBlocks(RCStage3RelationRole::CoupledPermutation),
        2U);
    BOOST_CHECK_EQUAL(RCStage3CountInCsOpeningBlocks(resolved), 2U);

    // CS-LEVEL FLIP: the honest witness (built from the same committed column the
    // pin's authority roots authenticate) satisfies the RESOLVER's C_ρ.
    uint32_t first_row = 0;
    std::string first_name;
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(resolved, product.witness, &first_row,
                                      &first_name),
        0U);

    // Tamper the child cell / an opening sibling -> the resolved C_ρ rejects.
    {
        auto w = product.witness;
        w[coupled_air_col::COPY_OUTPUT][0] =
            gf::Add(w[coupled_air_col::COPY_OUTPUT][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
    }
    {
        auto w = product.witness;
        w[2U + 266U][0] = gf::Add(w[2U + 266U][0], gf::Fp3::One()); // sibling lane
        BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
    }

    // Substituting a wrong authority root in the pin re-pins the opening block to
    // a root the honest column does NOT fold to -> the resolved C_ρ rejects the
    // same honest witness (proves the root is bound to the pin, not canonical).
    {
        ar::ChildPublicInputs bad = pin;
        bad.endpoint_authority_roots[0][0] =
            gf::FromU64(bad.endpoint_authority_roots[0][0] + 1);
        air_quotient::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledPermutation, bad, other, nullptr));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) > 0);
    }

    // Negatives: missing authority roots and a non-scalar-openable role both fail
    // closed (no fabricated flip).
    {
        ar::ChildPublicInputs empty_roots = pin;
        empty_roots.endpoint_authority_roots.clear();
        air_quotient::AirConstraintSystem<Fp3> none;
        BOOST_CHECK(!ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledPermutation, empty_roots, none, nullptr));
    }
    {
        // A different role with the Permutation pin (wrong root count/shape)
        // fails closed (no fabricated resolution).
        air_quotient::AirConstraintSystem<Fp3> none;
        std::string bwhy;
        BOOST_CHECK(!ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledExtract, pin, none, &bwhy));
    }
}

// CoupledMix is the second fully-scalar-openable coupled role (3 endpoints:
// Input/Arithmetic/Output). Its C_ρ carries the real 64-bit add/subtract adder
// kernel + 3 opening blocks, and the honest adder witness flips it at CS level.
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_coupled_mix)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;
    BOOST_CHECK(RCStage3RoleIsInCsScalarOpenable(RCStage3RelationRole::CoupledMix));
    BOOST_CHECK_EQUAL(
        RCStage3RequiredInCsOpeningBlocks(RCStage3RelationRole::CoupledMix), 3U);

    // Assemble Mix C_ρ with a satisfying adder witness.
    const RCStage3RoleAirProduct product =
        BuildRCStage3CoupledScalarRoleAir(RCStage3RelationRole::CoupledMix, 0, 3);
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 3U);
    BOOST_CHECK_EQUAL(product.cs.n_columns,
                      coupled_air_col::MIX_NUM_COLS + 3U * kRCStage3OpeningWidth);
    // The assembled product itself is satisfied by the honest adder witness.
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(product.cs, product.witness), 0U);

    // The RESOLVER rebuilds the same C_ρ from the pin's authority roots.
    ar::ChildPublicInputs pin;
    pin.child_n_rows = 4; // path_len = 3
    pin.child_w = product.cs.n_columns;
    pin.endpoint_authority_roots = product.endpoint_committed_roots;

    air_quotient::AirConstraintSystem<Fp3> resolved;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledMix, pin, resolved, &why),
        why);
    BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
    BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
    BOOST_CHECK_EQUAL(RCStage3CountInCsOpeningBlocks(resolved), 3U);

    // CS-LEVEL FLIP: honest adder witness satisfies the resolver's C_ρ.
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(resolved, product.witness), 0U);

    // Tamper the arithmetic sum limb (breaks the adder + its opening alias).
    {
        auto w = product.witness;
        w[coupled_air_col::MIX_SUM_LIMB][0] =
            gf::Add(w[coupled_air_col::MIX_SUM_LIMB][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
    }
    // Wrong root count fails closed (no fabricated flip).
    {
        ar::ChildPublicInputs bad = pin;
        bad.endpoint_authority_roots.resize(2);
        air_quotient::AirConstraintSystem<Fp3> none;
        BOOST_CHECK(!ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledMix, bad, none, nullptr));
    }
}

// First MIXED scalar+wired role FLIP: CoupledGemm's resolver returns real C_ρ
// (A/B/Y scalar openings + SignedRange wired ledger-fold closer) from the pin's
// authority roots, and the honest composed witness flips it at CS level.
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_coupled_gemm)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const RCStage3RoleAirProduct product = BuildRCStage3CoupledGemmRoleAir();
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 4U);

    ar::ChildPublicInputs pin;
    pin.child_n_rows = 8; // wired closer + path_len-7 openings
    pin.child_w = product.cs.n_columns;
    pin.endpoint_authority_roots = product.endpoint_committed_roots;

    air_quotient::AirConstraintSystem<Fp3> resolved;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledGemm, pin, resolved, &why),
        why);
    BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
    BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
    BOOST_CHECK_EQUAL(resolved.n_rows, 8U);
    BOOST_CHECK_EQUAL(
        RCStage3RequiredInCsOpeningBlocks(RCStage3RelationRole::CoupledGemm), 4U);
    BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved), 4U);

    // CS-LEVEL FLIP: honest composed witness satisfies the resolver's C_ρ.
    uint32_t fr = 0;
    std::string fn;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(resolved, product.witness, &fr, &fn) == 0,
        "gemm flip violated " + fn + " row " + std::to_string(fr));

    // Tamper the GEMM operand A -> reject.
    {
        auto w = product.witness;
        w[coupled_air_col::GEMM_A][0] =
            gf::Add(w[coupled_air_col::GEMM_A][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
    }
    // Wrong pin authority root for the wired SignedRange endpoint -> resolver
    // rebuilds C_ρ pinned to a different fold root; honest witness rejects.
    {
        ar::ChildPublicInputs badpin = pin;
        badpin.endpoint_authority_roots[3][0] =
            gf::FromU64(badpin.endpoint_authority_roots[3][0] + 1);
        air_quotient::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::CoupledGemm, badpin, other, nullptr));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) > 0);
    }
}

// EpisodeGemm: first role with TWO wired closers (Sumcheck + SignedRange) plus
// A/B/Y scalar openings. Resolver returns real C_ρ from the pin's 5 authority
// roots; the honest composed witness flips it at CS level.
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_episode_gemm)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const RCStage3RoleAirProduct product = BuildRCStage3EpisodeGemmRoleAir();
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 5U);

    ar::ChildPublicInputs pin;
    pin.child_n_rows = 8;
    pin.child_w = product.cs.n_columns;
    pin.endpoint_authority_roots = product.endpoint_committed_roots;

    air_quotient::AirConstraintSystem<Fp3> resolved;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::EpisodeGemm, pin, resolved, &why),
        why);
    BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
    BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
    BOOST_CHECK_EQUAL(resolved.n_rows, 8U);
    // Completeness: 5 closers (3 scalar openings + 2 wired) == 5 endpoints.
    BOOST_CHECK_EQUAL(
        RCStage3RequiredInCsOpeningBlocks(RCStage3RelationRole::EpisodeGemm), 5U);
    BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved), 5U);

    // CS-LEVEL FLIP.
    uint32_t fr = 0;
    std::string fn;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(resolved, product.witness, &fr, &fn) == 0,
        "episode gemm flip violated " + fn + " row " + std::to_string(fr));

    // Tamper: wrong pin authority root for the Sumcheck wired endpoint (index 3)
    // -> resolver rebuilds C_ρ pinned to a different fold root; honest rejects.
    {
        ar::ChildPublicInputs badpin = pin;
        badpin.endpoint_authority_roots[3][0] =
            gf::FromU64(badpin.endpoint_authority_roots[3][0] + 1);
        air_quotient::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::EpisodeGemm, badpin, other, nullptr));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) > 0);
    }
    // Tamper the GEMM operand A cell -> reject.
    {
        auto w = product.witness;
        w[1][0] = gf::Add(w[1][0], gf::Fp3::One()); // kernel col 1 == A
        BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
    }
}

// EpisodeWiring: Copy scalar opening + three wired ledger-fold closers
// (Transpose/Residual/RoundOrder) on 16 shared rows. Resolver returns real C_ρ
// from the pin's 4 authority roots; the honest composed witness flips it.
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_episode_wiring)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const RCStage3RoleAirProduct product = BuildRCStage3EpisodeWiringRoleAir();
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE_EQUAL(product.endpoint_committed_roots.size(), 4U);

    ar::ChildPublicInputs pin;
    pin.child_n_rows = 16;
    pin.child_w = product.cs.n_columns;
    pin.endpoint_authority_roots = product.endpoint_committed_roots;

    air_quotient::AirConstraintSystem<Fp3> resolved;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::EpisodeWiring, pin, resolved, &why),
        why);
    BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
    BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
    BOOST_CHECK_EQUAL(resolved.n_rows, 16U);
    // Completeness: 4 closers (1 scalar opening + 3 wired) == 4 endpoints.
    BOOST_CHECK_EQUAL(
        RCStage3RequiredInCsOpeningBlocks(RCStage3RelationRole::EpisodeWiring),
        4U);
    BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved), 4U);

    // CS-LEVEL FLIP.
    uint32_t fr = 0;
    std::string fn;
    BOOST_CHECK_MESSAGE(
        ar::CountWitnessViolationsOnH(resolved, product.witness, &fr, &fn) == 0,
        "episode wiring flip violated " + fn + " row " + std::to_string(fr));

    // Tamper: wrong pin authority root for the RoundOrder wired endpoint (idx 3).
    {
        ar::ChildPublicInputs badpin = pin;
        badpin.endpoint_authority_roots[3][0] =
            gf::FromU64(badpin.endpoint_authority_roots[3][0] + 1);
        air_quotient::AirConstraintSystem<Fp3> other;
        BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
            RCStage3RelationRole::EpisodeWiring, badpin, other, nullptr));
        BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) > 0);
    }
    // Tamper the Copy kernel cell -> reject.
    {
        auto w = product.witness;
        w[0][0] = gf::Add(w[0][0], gf::Fp3::One());
        BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
    }
}

// Pure §4 stream roles (all endpoints stream): the resolver returns real C_ρ
// composed of one light stream binding fragment per endpoint, pinned to the
// pin's SHA256d authority root; the heavy SHA fold is the deferred child.
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_stream_roles)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    const RCStage3RelationRole roles[] = {
        RCStage3RelationRole::CoupledBarrier,
        RCStage3RelationRole::CoupledDigest,
        RCStage3RelationRole::EpisodeTileTree,
        RCStage3RelationRole::EpisodeDigest};

    for (const RCStage3RelationRole role : roles) {
        BOOST_CHECK(RCStage3RoleIsPureStream(role));
        const RCStage3RoleAirProduct product =
            BuildRCStage3PureStreamRoleAir(role);
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
        const uint32_t n_ep =
            static_cast<uint32_t>(product.endpoint_committed_roots.size());
        BOOST_REQUIRE(n_ep >= 3U);

        ar::ChildPublicInputs pin;
        pin.child_n_rows = 2;
        pin.child_w = product.cs.n_columns;
        pin.endpoint_authority_roots = product.endpoint_committed_roots;

        air_quotient::AirConstraintSystem<Fp3> resolved;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            ResolveCurrentRCStage3RelationConstraintSystem(role, pin, resolved,
                                                           &why),
            why);
        BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
        BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
        BOOST_CHECK_EQUAL(RCStage3RequiredInCsOpeningBlocks(role), n_ep);
        BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved), n_ep);

        // CS-LEVEL FLIP: honest stream witness satisfies the resolver's C_ρ.
        uint32_t fr = 0;
        std::string fn;
        BOOST_CHECK_MESSAGE(
            ar::CountWitnessViolationsOnH(resolved, product.witness, &fr, &fn) ==
                0,
            std::string("stream flip violated ") + fn);

        // Wrong pin authority root for endpoint 0 -> resolver rebuilds pinned to
        // a different SHA root; honest witness rejects.
        {
            ar::ChildPublicInputs badpin = pin;
            badpin.endpoint_authority_roots[0][0] ^= 0x1ULL;
            air_quotient::AirConstraintSystem<Fp3> other;
            BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
                role, badpin, other, nullptr));
            BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) >
                        0);
        }
    }
}

// Mixed kernel+scalar+STREAM coupled roles: CoupledExchange (copy kernel +
// Input/Output scalar + HashXof stream) and CoupledBank (dequant nibble kernel +
// Pages scalar + SeedXof + CoupledBankRoot §4 SHA256d streams) on 8 shared rows.
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_coupled_mixed)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    for (const RCStage3RelationRole role :
         {RCStage3RelationRole::CoupledExchange,
          RCStage3RelationRole::CoupledBank}) {
        const RCStage3RoleAirProduct product =
            BuildRCStage3CoupledMixedRoleAir(role);
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
        const uint32_t n_ep =
            static_cast<uint32_t>(product.endpoint_committed_roots.size());
        BOOST_REQUIRE_EQUAL(n_ep, 3U);

        ar::ChildPublicInputs pin;
        pin.child_n_rows = 8;
        pin.child_w = product.cs.n_columns;
        pin.endpoint_authority_roots = product.endpoint_committed_roots;

        air_quotient::AirConstraintSystem<Fp3> resolved;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            ResolveCurrentRCStage3RelationConstraintSystem(role, pin, resolved,
                                                           &why),
            why);
        BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
        BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
        BOOST_CHECK_EQUAL(RCStage3RequiredInCsOpeningBlocks(role), n_ep);
        BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved), n_ep);

        uint32_t fr = 0;
        std::string fn;
        BOOST_CHECK_MESSAGE(
            ar::CountWitnessViolationsOnH(resolved, product.witness, &fr, &fn) ==
                0,
            std::string("mixed flip violated ") + fn);

        // Wrong pin root for endpoint 0 -> reject.
        {
            ar::ChildPublicInputs badpin = pin;
            badpin.endpoint_authority_roots[0][0] ^= 0x1ULL;
            air_quotient::AirConstraintSystem<Fp3> other;
            BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
                role, badpin, other, nullptr));
            BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) >
                        0);
        }
        // Tamper kernel col 0 -> reject.
        {
            auto w = product.witness;
            w[0][0] = gf::Add(w[0][0], gf::Fp3::One());
            BOOST_CHECK(ar::CountWitnessViolationsOnH(resolved, w) > 0);
        }
    }
}

// No-kernel roles: EpisodeDeterministicBuilder (Params opening + SeedChain/
// OperandXof stream + BuilderTrace wired) and CoupledExtract/EpisodeExtract
// (Input/Sampler/Scale/Output openings + ChaCha stream; the heavy sampler AIR
// is the deferred recursive child).
BOOST_AUTO_TEST_CASE(resolver_returns_real_crho_and_flips_for_no_kernel_roles)
{
    namespace ar = air_recurse;
    namespace gf = gkr_field;

    for (const RCStage3RelationRole role :
         {RCStage3RelationRole::EpisodeDeterministicBuilder,
          RCStage3RelationRole::CoupledExtract,
          RCStage3RelationRole::EpisodeExtract}) {
        const RCStage3RoleAirProduct product =
            BuildRCStage3NoKernelRoleAir(role);
        BOOST_REQUIRE_MESSAGE(product.ok, product.note);
        const uint32_t n_ep =
            static_cast<uint32_t>(product.endpoint_committed_roots.size());
        BOOST_REQUIRE(n_ep >= 4U);

        ar::ChildPublicInputs pin;
        pin.child_n_rows = 8;
        pin.child_w = product.cs.n_columns;
        pin.endpoint_authority_roots = product.endpoint_committed_roots;

        air_quotient::AirConstraintSystem<Fp3> resolved;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            ResolveCurrentRCStage3RelationConstraintSystem(role, pin, resolved,
                                                           &why),
            why);
        BOOST_CHECK(why.find("complete_air_unavailable") == std::string::npos);
        BOOST_CHECK_EQUAL(resolved.n_columns, pin.child_w);
        BOOST_CHECK_EQUAL(RCStage3RequiredInCsOpeningBlocks(role), n_ep);
        BOOST_CHECK_EQUAL(RCStage3CountInCsClosers(resolved), n_ep);

        uint32_t fr = 0;
        std::string fn;
        BOOST_CHECK_MESSAGE(
            ar::CountWitnessViolationsOnH(resolved, product.witness, &fr, &fn) ==
                0,
            std::string("no-kernel flip violated ") + fn);

        // Wrong pin root for the last endpoint -> reject.
        {
            ar::ChildPublicInputs badpin = pin;
            badpin.endpoint_authority_roots.back()[0] ^= 0x1ULL;
            air_quotient::AirConstraintSystem<Fp3> other;
            BOOST_REQUIRE(ResolveCurrentRCStage3RelationConstraintSystem(
                role, badpin, other, nullptr));
            BOOST_CHECK(ar::CountWitnessViolationsOnH(other, product.witness) >
                        0);
        }
    }
}

// ===========================================================================
// g2 COMPUTE LEG: the FULL FRI round-trip over a RESOLVED single-role C_ρ.
//
// The CS-level flips above prove the honest witness satisfies the resolved C_ρ
// (CountWitnessViolationsOnH == 0).  This is the missing next step: feed that
// exact (C_ρ, witness) into the production quotient/FRI prover
// AirQuotientProve<Fp3, AlgB3> and round-trip the emitted proof through
// AirQuotientVerify<Fp3, AlgB3>.  Prove -> Verify(accept) -> tamper-reject ->
// wrong-seed-reject on the SMALLEST fully-scalar-openable coupled roles.  This
// is the single-node analog of ProveAggregate; it verifies the recursion
// mechanism end-to-end for one role.
// ===========================================================================
namespace {
using AlgB3 = air_quotient::AirFriBackendAlg<gkr_field::Fp3>;

double SecondsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0)
        .count();
}

void RunSingleRoleFullFriRoundtrip(const char* tag,
                                   const RCStage3RoleAirProduct& product)
{
    namespace gf = gkr_field;
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    // Precondition: the honest witness satisfies the resolved C_ρ on H.
    BOOST_REQUIRE_EQUAL(
        air_recurse::CountWitnessViolationsOnH(product.cs, product.witness), 0U);

    const air_quotient::AirConstraintSystem<gf::Fp3>& cs = product.cs;
    const uint256 seed = U256(0x5a);

    // PROVE: real batched-FRI commitment of trace+quotient over the role C_ρ.
    // The honest witness satisfies every rule on H, so the quotient division is
    // EXACT and the prover emits a genuine batched-FRI trace commitment.
    const auto t0 = std::chrono::steady_clock::now();
    const auto proved =
        air_quotient::AirQuotientProve<gf::Fp3, AlgB3>(
            cs, product.witness, seed, {});
    const double prove_s = SecondsSince(t0);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK(proved.division_exact); // exact iff every rule holds on every row
    BOOST_REQUIRE(!proved.proof.batch.queries.empty());

    std::string why;
    const auto v0 = std::chrono::steady_clock::now();
    const bool accept =
        air_quotient::AirQuotientVerify<gf::Fp3, AlgB3>(
            cs, proved.proof, seed, &why);
    const double verify_s = SecondsSince(v0);

    BOOST_TEST_MESSAGE(
        std::string("G2_ROLE_ROUNDTRIP ") + tag
        << " rows=" << cs.n_rows
        << " cols=" << cs.n_columns
        << " constraints=" << cs.constraints.size()
        << " prove_s=" << prove_s
        << " verify_s=" << verify_s
        << " accept=" << accept
        << " division_exact=" << proved.division_exact
        << " why=\"" << why << "\"");

    // NORMALIZED STATE: the role C_ρ's verifier-owned preprocessed columns (the
    // opening index-bit column, the sponge terminal-squeeze selector, and the
    // wired root-equality-bus selectors) are OOD-pinned (canonical values bound
    // through the batch dual-OOD DEEP evals) rather than bound by a per-column
    // Merkle root.  The row-wise AlgB3 recursion FRI backend supports exactly
    // this mode, so the role now PROVES *and* VERIFIES standalone.
    BOOST_CHECK_MESSAGE(cs.preprocessed_roots.empty(),
                        "role C_ρ must carry no per-column preprocessed roots");
    BOOST_CHECK(cs.preprocessed_pin_ood);
    BOOST_CHECK(!cs.preprocessed.empty());
    BOOST_CHECK_MESSAGE(accept, "role C_ρ must FRI-verify: " + why);

    // SOUNDNESS: a tampered child cell breaks exact division / the OOD-pinned
    // binding, so no genuine accept survives (the OOD pin binds the same data a
    // committed root would have).
    {
        auto w = product.witness;
        w[0][0] = gf::Add(w[0][0], gf::Fp3::One());
        const auto bad =
            air_quotient::AirQuotientProve<gf::Fp3, AlgB3>(cs, w, seed, {});
        const bool bad_accept =
            bad.ok && bad.division_exact &&
            air_quotient::AirQuotientVerify<gf::Fp3, AlgB3>(cs, bad.proof, seed,
                                                            nullptr);
        BOOST_CHECK_MESSAGE(!bad_accept, "tampered role witness must reject");
    }
}
} // namespace

BOOST_AUTO_TEST_CASE(g2_coupled_permutation_full_fri_roundtrip)
{
    namespace gf = gkr_field;
    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0x2bad10ULL));
    RunSingleRoleFullFriRoundtrip(
        "CoupledPermutation",
        BuildRCStage3CoupledPermutationRoleAir(cell, 0, /*path_len=*/3, nullptr));
}

BOOST_AUTO_TEST_CASE(g2_coupled_mix_full_fri_roundtrip)
{
    RunSingleRoleFullFriRoundtrip(
        "CoupledMix",
        BuildRCStage3CoupledScalarRoleAir(RCStage3RelationRole::CoupledMix, 0,
                                          /*path_len=*/3, nullptr));
}

BOOST_AUTO_TEST_SUITE_END()
