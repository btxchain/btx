// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_verifier_air.h>
#include <matmul/matmul_v4_rc_stage3_fs_selection_air.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace nr = matmul::v4::rc::narrow_recurse;
namespace va = matmul::v4::rc::stage3_verifier_air;
namespace rc = matmul::v4::rc;
namespace alg_hash = matmul::v4::rc::alg_hash;
namespace fs = matmul::v4::rc::stage3_fs_selection_air;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_verifier_air_tests)

namespace {

nr::NarrowChildShape ToyShape()
{
    nr::NarrowChildShape shape;
    shape.child_w = 1;
    shape.child_n_rows = 2;
    shape.child_n_coeffs = 2;
    shape.child_n_lde = 32;
    shape.merkle_depth = 5;
    shape.n_folds = 1;
    shape.queries = 1;
    shape.child_constraints = 1;
    shape.arity = 1;
    return shape;
}

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::Fri3AlgDigest Digest(gf::Fp value)
{
    return {value, value + 1, value + 2, value + 3};
}

va::AlgAirProof ToyProof(const nr::NarrowChildShape& shape)
{
    va::AlgAirProof proof;
    auto& batch = proof.batch;
    // PR-89 g4 ACTIVATION: follow the live lane version.
    batch.version = rc::kRCFri3AlgActiveBatchProofVersion;
    batch.blowup = rc::kRCFriBlowup;
    batch.n_coeffs = shape.child_n_coeffs;
    batch.row_commit.root = Digest(10);
    batch.row_commit.n_leaves = shape.child_n_lde;
    batch.column_len.assign(shape.child_w + 1, shape.child_n_rows);
    batch.lambda = gf::Fp3{11, 12, 13};
    batch.z1 = gf::Fp3{14, 15, 16};
    batch.z2 = gf::Fp3{17, 18, 19};
    batch.evals_z1.assign(shape.child_w + 1, gf::Fp3{20, 21, 22});
    batch.evals_z2.assign(shape.child_w + 1, gf::Fp3{23, 24, 25});
    batch.w1 = gf::Fp3{26, 27, 28};
    batch.w2 = gf::Fp3{29, 30, 31};
    for (uint32_t layer = 0; layer <= shape.n_folds; ++layer) {
        batch.fold_layers.push_back(
            {Digest(40 + layer),
             shape.child_n_lde >> layer});
        if (layer < shape.n_folds) {
            batch.fold_challenges.push_back(
                gf::Fp3{50 + layer, 60 + layer, 70 + layer});
        }
    }
    for (uint32_t query = 0; query < shape.queries; ++query) {
        rc::Fri3AlgBatchQuery q;
        q.index = query % shape.child_n_lde;
        q.row.values.assign(shape.child_w + 1, gf::Fp3{80, 81, 82});
        q.row.siblings.assign(shape.merkle_depth, Digest(90));
        for (uint32_t layer = 0; layer < shape.n_folds; ++layer) {
            rc::Fri3AlgFoldStep step;
            step.even_index = q.index;
            step.odd_index =
                q.index + (shape.child_n_lde >> (layer + 1));
            step.even = gf::Fp3{100, 101, 102};
            step.odd = gf::Fp3{103, 104, 105};
            step.even_siblings.assign(
                shape.merkle_depth - layer, Digest(110));
            step.odd_siblings.assign(
                shape.merkle_depth - layer, Digest(120));
            q.steps.push_back(std::move(step));
        }
        batch.queries.push_back(std::move(q));
    }
    batch.final_value = gf::Fp3{130, 131, 132};
    proof.trace_commit = Filled(0xa0);
    proof.next_openings.resize(shape.queries);
    for (uint32_t query = 0; query < shape.queries; ++query) {
        rc::air_quotient::AirAlgRowPath current;
        current.index = query;
        current.values.assign(shape.child_w + 1, gf::Fp3{140, 141, 142});
        current.siblings.assign(shape.merkle_depth, Digest(150));
        rc::air_quotient::AirAlgRowPath next;
        next.index = query + 1;
        next.siblings.assign(shape.merkle_depth, Digest(160));
        proof.next_openings[query] = {
            std::move(current), std::move(next)};
    }
    return proof;
}

aq::AirConstraintSystem<gf::Fp3> ToyChildSystem()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name = "stage3.verifier.test.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0], gf::Sub(cur[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(boolean));
    return cs;
}

aq::AirConstraintSystem<gf::Fp3> ToySplitRapSystem()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 2;
    for (uint32_t column = 0; column < 2; ++column) {
        aq::AirConstraint<gf::Fp3> boolean;
        boolean.name =
            "stage3.verifier.test.split_rap_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval =
            [column](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[column],
                    gf::Sub(
                        cur[column],
                        gf::Fp3::One()));
            };
        cs.constraints.push_back(
            std::move(boolean));
    }
    return cs;
}

va::AlgAirProof HonestToyProof(const uint256& seed)
{
    const auto cs = ToyChildSystem();
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    return proved.proof;
}

/**
 * Honest bounded-OOD + SHA256d-squeeze FRI batch under the active short-FS
 * absorb layout. Production Fri3AlgBatchCommit keeps Poseidon2 squeezes;
 * this canary exists so every_digest_matches_claim can be measured without
 * AlignAlgAirProofOodToBoundedShaScheduleV1 rewriting claims.
 */
va::AlgAirProof HonestBoundedShaFsCanaryProof(const uint256& seed)
{
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()},
        {gf::Fp3::One(), gf::Fp3::FromFp(3)}};
    const rc::Fri3AlgBatchCommitResult committed =
        rc::Fri3AlgShaFsBoundedOodCanaryBatchCommit(columns, seed);
    BOOST_REQUIRE_MESSAGE(
        committed.ok && !committed.proof.queries.empty(),
        committed.note);
    va::AlgAirProof proof;
    proof.batch = committed.proof;
    proof.trace_commit = Filled(0xa1);
    const auto& shape_batch = proof.batch;
    const uint32_t depth = [&]() {
        uint32_t d = 0;
        uint32_t n = shape_batch.row_commit.n_leaves;
        while (n > 1) {
            n >>= 1;
            ++d;
        }
        return d;
    }();
    const uint32_t columns_w =
        static_cast<uint32_t>(shape_batch.column_len.size());
    proof.next_openings.resize(shape_batch.queries.size());
    for (uint32_t qi = 0; qi < shape_batch.queries.size(); ++qi) {
        rc::air_quotient::AirAlgRowPath current;
        current.index = shape_batch.queries[qi].index;
        current.values.assign(columns_w, gf::Fp3::One());
        current.siblings.assign(depth, Digest(200));
        rc::air_quotient::AirAlgRowPath next;
        next.index =
            (current.index + 1) % shape_batch.row_commit.n_leaves;
        // Trace-binding slot: values stay empty (witness shape gate).
        next.siblings.assign(depth, Digest(210));
        proof.next_openings[qi] = {
            std::move(current), std::move(next)};
    }
    return proof;
}

nr::NarrowChildShape ShapeForProof(
    const va::AlgAirProof& proof)
{
    nr::NarrowChildShape shape;
    shape.child_w =
        static_cast<uint32_t>(proof.batch.column_len.size() - 1);
    shape.child_n_rows = 2;
    shape.child_n_coeffs = proof.batch.n_coeffs;
    shape.child_n_lde =
        proof.batch.n_coeffs * proof.batch.blowup;
    uint32_t depth = shape.child_n_lde;
    while (depth > 1) {
        depth >>= 1;
        ++shape.merkle_depth;
    }
    shape.n_folds =
        static_cast<uint32_t>(proof.batch.fold_challenges.size());
    shape.queries =
        static_cast<uint32_t>(proof.batch.queries.size());
    shape.child_constraints = 1;
    shape.arity = 1;
    return shape;
}

rc::RCStage3CtlChildPin CtlPin()
{
    rc::RCStage3CtlChildPin pin;
    pin.role = rc::RCStage3RelationRole::EpisodeGemm;
    pin.bus_id = 9;
    pin.event_count = 2;
    pin.send_count = 1;
    pin.receive_count = 1;
    pin.schedule_commitment = Filled(0xb0);
    pin.trace_commitment = Filled(0xb1);
    pin.auxiliary_commitment = Filled(0xb2);
    pin.challenge_commitment = Filled(0xb3);
    return pin;
}

std::vector<std::vector<gf::Fp3>> DualColumns()
{
    return {
        {gf::Fp3::FromFp(1), gf::Fp3::FromFp(2),
         gf::Fp3::FromFp(3), gf::Fp3::FromFp(4)},
        {gf::Fp3::FromFp(5), gf::Fp3::FromFp(6),
         gf::Fp3::FromFp(7)}};
}

} // namespace

BOOST_AUTO_TEST_CASE(production_q192_schedule_matches_fixed_point_planner)
{
    nr::NarrowVcsConfig config;
    config.poseidon_strategy =
        nr::PoseidonLaneStrategy::DecomposedX2X4X6;
    config.child_packing = nr::ChildPacking::VerticalRows;
    nr::NarrowChildShape leaf = nr::ProductionEpisodeChildShape();
    leaf.queries = 192;
    const nr::NarrowVcsPlan leaf_plan =
        nr::BuildNarrowVcsPlan(leaf, config);
    BOOST_REQUIRE(leaf_plan.valid);
    const nr::NarrowChildShape recursive_child =
        nr::NextRecursiveChildShape(leaf_plan);
    const nr::NarrowVcsPlan expected =
        nr::BuildNarrowVcsPlan(recursive_child, config);
    BOOST_REQUIRE(expected.valid);

    const va::VerifierProgram program =
        va::BuildCanonicalVerifierProgram(recursive_child);
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    BOOST_CHECK_EQUAL(program.active_rows, 416104U);
    BOOST_CHECK_EQUAL(program.active_rows, expected.active_rows);
    BOOST_CHECK_EQUAL(program.trace_rows, 1U << 19);
    BOOST_CHECK_EQUAL(program.trace_rows, expected.trace_rows);
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::ValidateCanonicalVerifierProgram(program, &why), why);

    const va::FiatShamirProgram fs_program =
        va::BuildCanonicalFiatShamirProgram(recursive_child);
    BOOST_REQUIRE(fs_program.valid);
    BOOST_CHECK(!fs_program.scheduler_capacity_sufficient);
    BOOST_CHECK_GT(fs_program.minimum_sha256_compression_blocks,
                   fs_program.scheduled_rows);
    BOOST_CHECK_LT(
        fs_program.streaming_sha256_compression_blocks,
        fs_program.minimum_sha256_compression_blocks);
    const uint64_t naive_vertical_rows =
        program.active_rows -
        recursive_child.arity * fs_program.scheduled_rows +
        recursive_child.arity *
            fs_program.minimum_sha256_compression_blocks;
    const uint64_t non_fs_rows_per_child =
        (program.active_rows -
         recursive_child.arity * fs_program.scheduled_rows) /
        recursive_child.arity;
    const uint64_t naive_parallel_rows =
        non_fs_rows_per_child +
        fs_program.minimum_sha256_compression_blocks;
    // PR-89 g4 ACTIVATION MOVED THIS NUMBER, and the check is rewritten to
    // the measured post-activation value rather than loosened.
    //
    // The old lower bound (> 2^19) was asserting that a naive vertical SHA
    // replay of the child transcript does NOT fit the parent -- the problem
    // statement.  Activating the short-transcript lane removes the 4*W and
    // 48*W bodies from every challenge preimage, so at this shape the naive
    // vertical cost is now 422,136 rows, BELOW 2^19.  Asserting the old bound
    // would now be asserting that the saving did not happen.
    //
    // What still has to hold, and is what this test is for: the naive vertical
    // schedule is still the EXPENSIVE arrangement -- strictly worse than the
    // parallel one -- and still inside the 2^20 envelope.
    BOOST_CHECK_LE(naive_vertical_rows, uint64_t{1} << 20);
    BOOST_CHECK_GT(naive_vertical_rows, naive_parallel_rows);
    BOOST_CHECK_LE(naive_parallel_rows, uint64_t{1} << 19);

    nr::NarrowVcsConfig parallel_config;
    parallel_config.poseidon_strategy =
        nr::PoseidonLaneStrategy::DecomposedX2X4X6;
    parallel_config.child_packing =
        nr::ChildPacking::ParallelLanes;
    const nr::NarrowVcsPlan parallel =
        nr::BuildNarrowVcsPlan(
            recursive_child, parallel_config);
    BOOST_REQUIRE(parallel.valid);
    BOOST_CHECK_LE(parallel.parent_width,
                   rc::kRCFri3AlgBatchMaxColumns);
    const auto exact_scenarios =
        va::AssessExactVerifierScheduleScenarios(
            recursive_child);
    BOOST_REQUIRE_EQUAL(exact_scenarios.size(), 2U);
    const auto& vertical = exact_scenarios[0];
    const auto& packed = exact_scenarios[1];
    BOOST_CHECK(
        vertical.packing ==
        va::VerifierChildPacking::VerticalRows);
    BOOST_CHECK_EQUAL(
        vertical.active_rows,
        recursive_child.arity *
            (non_fs_rows_per_child +
             fs_program.streaming_sha256_compression_blocks));
    BOOST_CHECK_EQUAL(vertical.trace_rows, 1U << 19);
    BOOST_CHECK(vertical.lde_cap_met);
    BOOST_CHECK(vertical.backend_shape_supported);
    BOOST_CHECK(vertical.executable_layout);
    BOOST_CHECK(
        packed.packing ==
        va::VerifierChildPacking::ParallelLanes);
    BOOST_CHECK_EQUAL(
        packed.active_rows,
        non_fs_rows_per_child +
            fs_program.streaming_sha256_compression_blocks);
    BOOST_CHECK_EQUAL(packed.trace_rows, 1U << 18);
    BOOST_CHECK(packed.column_cap_met);
    BOOST_CHECK(packed.lde_cap_met);
    BOOST_CHECK(packed.backend_shape_supported);
    BOOST_CHECK(!packed.executable_layout);
    BOOST_CHECK_EQUAL(packed.width, parallel.parent_width);
    BOOST_TEST_MESSAGE(
        "production recursive FS scheduled_rows="
        << fs_program.scheduled_rows
        << " naive_sha256_blocks="
        << fs_program.minimum_sha256_compression_blocks
        << " streaming_sha256_blocks="
        << fs_program.streaming_sha256_compression_blocks
        << " absorbed_bytes=" << fs_program.absorbed_bytes
        << " naive_vertical_rows=" << naive_vertical_rows
        << " naive_parallel_rows=" << naive_parallel_rows
        << " streaming_vertical_rows=" << vertical.active_rows
        << " streaming_parallel_rows=" << packed.active_rows
        << " parallel_width=" << parallel.parent_width);
}

BOOST_AUTO_TEST_CASE(schedule_rejects_omission_reorder_and_metadata_mutation)
{
    const va::VerifierProgram canonical =
        va::BuildCanonicalVerifierProgram(ToyShape());
    BOOST_REQUIRE(canonical.valid);
    std::string why;

    auto omitted = canonical;
    omitted.rows.erase(omitted.rows.begin() + 3);
    BOOST_CHECK(!va::ValidateCanonicalVerifierProgram(omitted, &why));

    auto reordered = canonical;
    std::swap(reordered.rows[1], reordered.rows[2]);
    BOOST_CHECK(!va::ValidateCanonicalVerifierProgram(reordered, &why));

    auto metadata = canonical;
    ++metadata.rows[0].step;
    BOOST_CHECK(!va::ValidateCanonicalVerifierProgram(metadata, &why));

    auto padding = canonical;
    padding.rows.back().kind = va::ProgramRowKind::Boundary;
    BOOST_CHECK(!va::ValidateCanonicalVerifierProgram(padding, &why));
}

BOOST_AUTO_TEST_CASE(all_non_hash_chips_have_an_honest_air_roundtrip)
{
    const va::VerifierProgram program =
        va::BuildCanonicalVerifierProgram(ToyShape());
    BOOST_REQUIRE(program.valid);
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        va::BuildVerifierScalarSystem(program, cs, &why), why);
    BOOST_CHECK_EQUAL(cs.n_columns, 27U);
    BOOST_CHECK_EQUAL(cs.constraints.size(), 19U);

    const std::vector<va::ScalarRowWitness> witness =
        va::BuildDeterministicScalarWitness(program);
    BOOST_REQUIRE(!witness.empty());
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        va::BuildVerifierScalarWitness(
            program, witness, columns, &why),
        why);
    BOOST_CHECK_EQUAL(
        va::CountVerifierScalarViolations(cs, columns), 0U);

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x93);
    const auto proof =
        aq::AirQuotientProve<gf::Fp3>(cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(proof.ok, proof.note);
    BOOST_REQUIRE(proof.division_exact);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            cs, proof.proof, seed, &why),
        why);
}

BOOST_AUTO_TEST_CASE(every_scalar_family_mutation_is_rejected)
{
    const va::VerifierProgram program =
        va::BuildCanonicalVerifierProgram(ToyShape());
    BOOST_REQUIRE(program.valid);
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_REQUIRE(
        va::BuildVerifierScalarSystem(program, cs, &why));
    const auto honest = va::BuildDeterministicScalarWitness(program);
    BOOST_REQUIRE(!honest.empty());

    for (uint32_t op = 0; op < va::kScalarOpCount; ++op) {
        auto mutated = honest;
        const auto expected = static_cast<va::ScalarOp>(op);
        const auto it = std::find_if(
            mutated.begin(), mutated.end(),
            [expected](const va::ScalarRowWitness& row) {
                return row.op == expected;
            });
        BOOST_REQUIRE(it != mutated.end());
        if (expected == va::ScalarOp::MerkleRoute) {
            it->left[0] =
                gf::Add(it->left[0], gf::Fp3{1, 2, 3});
        } else if (expected == va::ScalarOp::PerPointIdentity) {
            it->a = gf::Add(it->a, gf::Fp3{1, 2, 3});
        } else {
            it->out = gf::Add(it->out, gf::Fp3{1, 2, 3});
        }
        std::vector<std::vector<gf::Fp3>> columns;
        BOOST_REQUIRE(
            va::BuildVerifierScalarWitness(
                program, mutated, columns, &why));
        BOOST_CHECK_GT(
            va::CountVerifierScalarViolations(cs, columns), 0U);
    }
}

BOOST_AUTO_TEST_CASE(witness_requires_exact_program_order)
{
    const va::VerifierProgram program =
        va::BuildCanonicalVerifierProgram(ToyShape());
    BOOST_REQUIRE(program.valid);
    auto witness = va::BuildDeterministicScalarWitness(program);
    BOOST_REQUIRE_GT(witness.size(), 2U);
    std::swap(witness[0], witness[1]);
    std::vector<std::vector<gf::Fp3>> columns;
    std::string why;
    BOOST_CHECK(!va::BuildVerifierScalarWitness(
        program, witness, columns, &why));
    BOOST_CHECK(why.find("scalar_row_order") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fiat_shamir_manifest_is_exact_and_exposes_row_underbudget)
{
    const nr::NarrowChildShape shape = ToyShape();
    const va::FiatShamirProgram program =
        va::BuildCanonicalFiatShamirProgram(shape);
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    // PR-89 g4 ACTIVATION: the (child_w + 1) per-column
    // AbsorbOodEvaluationPair events collapse to ONE
    // AbsorbOodEvalCommitment event, so the canonical event count drops by
    // child_w.  Written as a formula, not a magic number, so it stays
    // meaningful at other shapes.
    BOOST_CHECK(rc::kRCFri3AlgShortFsActivatedV1);
    BOOST_CHECK_EQUAL(program.events.size(), 16U - shape.child_w);
    BOOST_CHECK_EQUAL(
        std::count_if(
            program.events.begin(), program.events.end(),
            [](const va::FiatShamirEventSpec& e) {
                return e.kind ==
                       va::FiatShamirEventKind::AbsorbOodEvalCommitment;
            }),
        1);
    BOOST_CHECK_EQUAL(
        std::count_if(
            program.events.begin(), program.events.end(),
            [](const va::FiatShamirEventSpec& e) {
                return e.kind ==
                       va::FiatShamirEventKind::AbsorbOodEvaluationPair;
            }),
        0);
    BOOST_CHECK_EQUAL(
        program.scheduled_rows, nr::FiatShamirReplayRows(shape));
    BOOST_CHECK_GT(program.minimum_sha256_compression_blocks,
                   program.scheduled_rows);
    BOOST_CHECK_LT(
        program.streaming_sha256_compression_blocks,
        program.minimum_sha256_compression_blocks);
    BOOST_CHECK(!program.scheduler_capacity_sufficient);
    BOOST_CHECK(!program.rejection_loop_bounded);
    BOOST_CHECK(!program.commitment.IsNull());
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::ValidateCanonicalFiatShamirProgram(program, &why), why);

    auto omitted = program;
    omitted.events.erase(omitted.events.begin() + 5);
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(omitted, &why));

    auto reordered = program;
    std::swap(reordered.events[1], reordered.events[2]);
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(reordered, &why));

    auto bytes = program;
    ++bytes.events[6].absorbed_bytes;
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(bytes, &why));
}

BOOST_AUTO_TEST_CASE(fixed_ood_schedule_bound_matches_field_analysis)
{
    // Fp3 over Goldilocks (p = 2^64-2^32+1 > 2^63): a uniform OOD draw lands on
    // the base-field line (c1==c2==0) with probability 1/p^2 <= 2^-126.
    const auto k1 = va::ComputeFixedOodScheduleBound(1);
    BOOST_CHECK_EQUAL(k1.per_draw_reject_bits, 126U);
    BOOST_CHECK_EQUAL(k1.all_rejected_bits, 126U);
    // K=1 clears a 100-bit target but NOT the 128-bit target.
    BOOST_CHECK(va::ComputeFixedOodScheduleBound(1, 63, 2, 100).bounded);
    BOOST_CHECK(!va::ComputeFixedOodScheduleBound(1, 63, 2, 128).bounded);
    // K=2 clears the 128-bit target (all-rejected <= 2^-252) with margin.
    const auto k2 = va::ComputeFixedOodScheduleBound(2);
    BOOST_CHECK_EQUAL(k2.all_rejected_bits, 252U);
    BOOST_CHECK(k2.bounded);
    // K=0 is the legacy unbounded while(true) sampler: never bounded, even at a
    // trivial 1-bit target.
    BOOST_CHECK(!va::ComputeFixedOodScheduleBound(0).bounded);
    BOOST_CHECK(!va::ComputeFixedOodScheduleBound(0, 63, 2, 1).bounded);
}

BOOST_AUTO_TEST_CASE(first_acceptable_ood_index_selector)
{
    const gf::Fp3 line0 = gf::Fp3{7, 0, 0}; // base-field line -> rejected
    const gf::Fp3 line1 = gf::Fp3{9, 0, 0}; // base-field line -> rejected
    const gf::Fp3 good0 = gf::Fp3{1, 2, 0}; // off the line -> accepted
    const gf::Fp3 good1 = gf::Fp3{3, 0, 5}; // off the line -> accepted

    // (a) honest draw: first candidate already acceptable -> selects index 0.
    BOOST_CHECK_EQUAL(
        va::SelectFirstAcceptableOodIndex({good0, good1}, nullptr), 0U);
    // first candidate on the line -> selector advances to the next -> index 1.
    BOOST_CHECK_EQUAL(
        va::SelectFirstAcceptableOodIndex({line0, good1}, nullptr), 1U);
    // z2 distinctness (z2 != z1): skip the duplicate, pick the next distinct.
    BOOST_CHECK_EQUAL(
        va::SelectFirstAcceptableOodIndex({good0, good1}, &good0), 1U);
    // (b) the negligible failure event: every candidate rejected -> exhausted.
    BOOST_CHECK_EQUAL(
        va::SelectFirstAcceptableOodIndex({line0, line1}, nullptr), 2U);
}

BOOST_AUTO_TEST_CASE(bounded_fs_program_flips_rejection_loop_bounded_with_proof)
{
    nr::NarrowChildShape shape = ToyShape();
    shape.queries = 2;
    const va::FiatShamirProgram v3 =
        va::BuildCanonicalFiatShamirProgram(shape);
    BOOST_REQUIRE(v3.valid);
    BOOST_CHECK_EQUAL(v3.ood_candidates, 0U);
    BOOST_CHECK(!v3.rejection_loop_bounded);
    // See fiat_shamir_manifest_is_exact_...: one commitment event replaces the
    // (child_w + 1) per-column absorbs after activation.
    BOOST_CHECK_EQUAL(v3.events.size(), 14U + shape.queries);

    const va::FiatShamirProgram bounded =
        va::BuildBoundedFiatShamirProgram(shape, 2);
    BOOST_REQUIRE_MESSAGE(bounded.valid, bounded.note);
    BOOST_CHECK_EQUAL(bounded.ood_candidates, 2U);
    // K=2 fixed schedule with proven <= 2^-252 all-rejected failure.
    BOOST_CHECK(bounded.rejection_loop_bounded);
    // One extra candidate draw per OOD challenge (z1,z2) vs V3's single draw.
    BOOST_CHECK_EQUAL(bounded.events.size(), v3.events.size() + 2U);
    // Distinct transcript format binds to a distinct commitment.
    BOOST_CHECK(bounded.commitment != v3.commitment);
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::ValidateCanonicalFiatShamirProgram(bounded, &why), why);
    auto wrong_domain = bounded;
    wrong_domain.child_domain_tag[0] ^= 1;
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(wrong_domain, &why));
    auto wrong_squeeze = bounded;
    wrong_squeeze.child_sha256d_challenges = false;
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(wrong_squeeze, &why));
    auto wrong_authority = bounded;
    wrong_authority.authority_eligible = true;
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(wrong_authority, &why));

    // A hand-flipped bound flag (no fixed schedule) is rejected as noncanonical.
    auto forged = v3;
    forged.rejection_loop_bounded = true;
    BOOST_CHECK(
        !va::ValidateCanonicalFiatShamirProgram(forged, &why));

    // K=1 does NOT clear the 128-bit target and is not a registered v9
    // protocol. Probability analysis remains available without manufacturing
    // a noncanonical proof program.
    const va::FiatShamirProgram k1 =
        va::BuildBoundedFiatShamirProgram(shape, 1);
    BOOST_CHECK(!k1.valid);
    BOOST_CHECK(!va::ComputeFixedOodScheduleBound(1).bounded);
}

// g2 SHA-FS chip: bounded K-window SHA execution sets fixed_schedule when
// rejection_loop_bounded; gap assessor inventories remaining Executable
// blockers. Does NOT flip kVerifierFiatShamirAirExecutable / Ready.
BOOST_AUTO_TEST_CASE(
    bounded_fs_sha_execution_fixed_schedule_and_chip_gap_inventory)
{
    const uint256 seed = Filled(0xcd);
    va::AlgAirProof proof = HonestToyProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);

    const va::FiatShamirProgram v3 =
        va::BuildCanonicalFiatShamirProgram(shape);
    BOOST_REQUIRE(v3.valid);
    BOOST_CHECK_EQUAL(v3.ood_candidates, 0U);
    BOOST_CHECK(!v3.rejection_loop_bounded);
    // Legacy V3 SHA inventory: when the plan builds, fixed_schedule stays false.
    {
        const va::FiatShamirShaExecutionPlanV1 v3_plan =
            va::BuildFiatShamirShaExecutionPlanV1(
                v3, seed, proof);
        if (v3_plan.valid) {
            BOOST_CHECK(!v3_plan.fixed_schedule);
            BOOST_CHECK(!v3_plan.recursively_consumed);
        } else {
            BOOST_TEST_MESSAGE(
                "v3_sha_plan_open:" << v3_plan.note);
        }
    }

    // Bounded v9 is an exact Q=2/K=2 SHA inner-FRI canary. It must never be
    // inferred from, or aligned onto, the live P2/Q192 proof.
    proof = HonestBoundedShaFsCanaryProof(seed);
    const nr::NarrowChildShape canary_shape = ShapeForProof(proof);
    const va::FiatShamirProgram bounded =
        va::BuildBoundedFiatShamirProgram(
            canary_shape, va::kRCFiatShamirOodCandidateSchedule);
    BOOST_REQUIRE(bounded.valid);
    BOOST_CHECK(bounded.canary_only);
    BOOST_CHECK(!bounded.authority_eligible);
    BOOST_CHECK(bounded.rejection_loop_bounded);
    const va::FiatShamirShaExecutionPlanV1 b_plan =
        va::BuildFiatShamirShaExecutionPlanV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(
        b_plan.note
        << " fixed=" << b_plan.fixed_schedule
        << " digests=" << b_plan.every_digest_matches_claim
        << " origins=" << b_plan.proof_codec_byte_origins_complete
        << " calls=" << b_plan.calls);
    // Chip deliverable: bounded K-window lays a fixed schedule. Full plan.valid
    // may still be false when unrelated transcript residuals (e.g. airq map)
    // leave every_digest_matches_claim open — inventory that honestly.
    BOOST_CHECK(b_plan.fixed_schedule);
    BOOST_CHECK(b_plan.exact_domain_tags_and_order);
    BOOST_CHECK(b_plan.exact_sha256d_padding_and_chaining);
    BOOST_CHECK(b_plan.proof_codec_byte_origins_complete);
    BOOST_CHECK(!b_plan.recursively_consumed);
    BOOST_CHECK_GE(
        b_plan.calls,
        2U * va::kRCFiatShamirOodCandidateSchedule);

    const va::VerifierFiatShamirAirChipGapV1 gap =
        va::AssessVerifierFiatShamirAirChipGapV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(gap.note);
    BOOST_CHECK(gap.bounded_ood_program_legislated);
    BOOST_CHECK(gap.bounded_ood_rejection_loop_bounded);
    BOOST_CHECK(gap.sha_fixed_schedule);
    BOOST_CHECK(gap.sha_codec_origins_complete);
    BOOST_CHECK(gap.sha_recursively_consumed);
    BOOST_CHECK(gap.challenge_selection_air_constrained);
    BOOST_CHECK(gap.air_backed_all_kinds_reconstructed);
    BOOST_CHECK(gap.non_sha_challenges_recursively_consumed);
    BOOST_CHECK(!gap.authority_eligible);
    BOOST_CHECK(gap.whole_verifier_sha_equations_in_air);
    BOOST_TEST_MESSAGE(
        "FS_GAP open=" << gap.open_predicates
        << " bounded_ood=" << gap.bounded_ood_program_legislated
        << "/" << gap.bounded_ood_rejection_loop_bounded
        << " sha_plan=" << gap.sha_execution_plan_valid
        << " fixed=" << gap.sha_fixed_schedule
        << " codec=" << gap.sha_codec_origins_complete
        << " sha_rec=" << gap.sha_recursively_consumed
        << " nonsha_rec=" << gap.non_sha_challenges_recursively_consumed
        << " sel_air=" << gap.challenge_selection_air_constrained
        << " kinds8=" << gap.air_backed_all_kinds_reconstructed
        << " whole_sha=" << gap.whole_verifier_sha_equations_in_air
        << " auth=" << gap.authority_eligible
        << " blocker=" << gap.active_config_fs_blocker
        << " ready=" << gap.executable_ready
        << " note=" << gap.note);
    BOOST_CHECK(!gap.executable_ready);
    BOOST_CHECK_EQUAL(gap.active_config_fs_blocker, "canary_only");
    BOOST_CHECK_GE(gap.open_predicates, 1U);
    BOOST_CHECK(gap.note.find("consensus_open") == std::string::npos);
    static_assert(!va::kVerifierFiatShamirAirExecutable);
}

// Honest SHA-squeeze + K=2 OOD canary: every_digest_matches_claim without Align.
// Production ActiveConfig keeps Poseidon2 squeezes; Executable stays false.
BOOST_AUTO_TEST_CASE(
    bounded_sha_fs_canary_every_digest_matches_claim_on_honest_proof)
{
    const uint256 seed = Filled(0xce);
    const va::AlgAirProof proof = HonestBoundedShaFsCanaryProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);
    BOOST_CHECK_EQUAL(shape.queries, 2U);
    BOOST_CHECK_EQUAL(
        proof.batch.version,
        rc::kRCFri3AlgShaFsCanaryProofVersion);
    BOOST_CHECK_NE(
        proof.batch.version,
        rc::kRCFri3AlgActiveBatchProofVersion);
    std::string native_why;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgShaFsBoundedOodCanaryBatchVerify(
            proof.batch, seed, &native_why),
        native_why);
    auto wrong_version = proof.batch;
    wrong_version.version =
        rc::kRCFri3AlgActiveBatchProofVersion;
    BOOST_CHECK(
        !rc::Fri3AlgShaFsBoundedOodCanaryBatchVerify(
            wrong_version, seed, &native_why));
    auto missing_query = proof.batch;
    missing_query.queries.pop_back();
    BOOST_CHECK(
        !rc::Fri3AlgShaFsBoundedOodCanaryBatchVerify(
            missing_query, seed, &native_why));

    const va::FiatShamirProgram bounded =
        va::BuildBoundedFiatShamirProgram(
            shape, va::kRCFiatShamirOodCandidateSchedule);
    BOOST_REQUIRE(bounded.valid);
    BOOST_CHECK(bounded.rejection_loop_bounded);
    BOOST_CHECK_EQUAL(
        bounded.ood_candidates, va::kRCFiatShamirOodCandidateSchedule);
    const va::FiatShamirProgram active_for_same_shape =
        va::BuildCanonicalFiatShamirProgram(shape);
    BOOST_REQUIRE(active_for_same_shape.valid);
    BOOST_CHECK(
        !va::BuildFiatShamirWitness(
             active_for_same_shape, seed, proof)
             .valid);

    // No Align: z/w/lambda come from the honest canary prover.
    const va::FiatShamirShaExecutionPlanV1 plan =
        va::BuildFiatShamirShaExecutionPlanV1(bounded, seed, proof);
    BOOST_TEST_MESSAGE(
        plan.note
        << " fixed=" << plan.fixed_schedule
        << " digests=" << plan.every_digest_matches_claim
        << " valid=" << plan.valid
        << " calls=" << plan.calls);
    BOOST_REQUIRE_MESSAGE(
        plan.every_digest_matches_claim, plan.note);
    BOOST_CHECK(plan.fixed_schedule);
    BOOST_CHECK(plan.exact_domain_tags_and_order);
    BOOST_CHECK(plan.exact_sha256d_padding_and_chaining);
    BOOST_CHECK(plan.proof_codec_byte_origins_complete);
    BOOST_CHECK(plan.valid);
    BOOST_CHECK(!plan.recursively_consumed);

    const va::VerifierFiatShamirAirChipGapV1 gap =
        va::AssessVerifierFiatShamirAirChipGapV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(gap.note);
    BOOST_CHECK(gap.sha_execution_plan_valid);
    BOOST_CHECK(gap.sha_fixed_schedule);
    BOOST_CHECK(gap.sha_codec_origins_complete);
    BOOST_CHECK(gap.sha_recursively_consumed);
    BOOST_CHECK(gap.challenge_selection_air_constrained);
    BOOST_CHECK(gap.air_backed_all_kinds_reconstructed);
    BOOST_CHECK(gap.whole_verifier_sha_equations_in_air);
    BOOST_CHECK(!gap.executable_ready);
    BOOST_CHECK(gap.non_sha_challenges_recursively_consumed);
    BOOST_CHECK(!gap.authority_eligible);
    BOOST_CHECK_EQUAL(gap.active_config_fs_blocker, "canary_only");
    BOOST_CHECK_EQUAL(gap.open_predicates, 1U);
    // Reverted cheat used consensus_open as a passing conjunct; must not return.
    BOOST_CHECK(gap.note.find("consensus_open") == std::string::npos);
    static_assert(!va::kVerifierFiatShamirAirExecutable);
    static_assert(!va::kVerifierAirConsensusAuthority);
}

// Light opt-in: fs_selection_air ChallengeTable binds SHA digests to consumed
// challenges on the honest bounded canary; consumed tamper goes red.
BOOST_AUTO_TEST_CASE(
    bounded_sha_fs_canary_challenge_selection_air_join)
{
    const uint256 seed = Filled(0xcf);
    const va::AlgAirProof proof = HonestBoundedShaFsCanaryProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);
    const va::FiatShamirProgram bounded =
        va::BuildBoundedFiatShamirProgram(
            shape, va::kRCFiatShamirOodCandidateSchedule);
    BOOST_REQUIRE(bounded.valid);

    const va::FiatShamirChallengeSelectionAirJoinV1 join =
        va::MeasureFiatShamirChallengeSelectionAirJoinV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(join.note);
    BOOST_REQUIRE_MESSAGE(join.constrained, join.note);
    BOOST_CHECK(join.digest_plan_ready);
    BOOST_CHECK(join.table_valid);
    BOOST_CHECK(join.tamper_rejects);
    BOOST_CHECK_EQUAL(join.table_violations, 0U);
    BOOST_CHECK_GE(join.draws, 6U);
    BOOST_CHECK_EQUAL(join.rows_bound_to_consumed, join.draws);
    static_assert(!va::kVerifierFiatShamirAirExecutable);
}

// Light opt-in: all eight FS challenge kinds reconstruct in-AIR from SHA
// digests on the honest bounded canary; one-input tamper diverges.
BOOST_AUTO_TEST_CASE(
    bounded_sha_fs_canary_air_backed_all_kinds_reconstructed)
{
    const uint256 seed = Filled(0xd0);
    const va::AlgAirProof proof = HonestBoundedShaFsCanaryProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);
    const va::FiatShamirProgram bounded =
        va::BuildBoundedFiatShamirProgram(
            shape, va::kRCFiatShamirOodCandidateSchedule);
    BOOST_REQUIRE(bounded.valid);

    const va::FiatShamirAirBackedAllKindsV1 kinds =
        va::MeasureFiatShamirAirBackedAllKindsV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(kinds.note);
    BOOST_REQUIRE_MESSAGE(kinds.reconstructed, kinds.note);
    BOOST_CHECK(kinds.digest_plan_ready);
    BOOST_CHECK(kinds.covers_all_challenge_types);
    BOOST_CHECK(kinds.values_match_consumed);
    BOOST_CHECK(kinds.tamper_diverges);
    BOOST_CHECK_EQUAL(kinds.kinds_reconstructed, 8U);
    BOOST_CHECK_EQUAL(
        kinds.values_bound_to_consumed, kinds.kinds_required);
    static_assert(!va::kVerifierFiatShamirAirExecutable);
}

// Light opt-in: MultiRow SHA schedule + vertical boundary AIRs + arity-4
// join consume every FS SHA call on the honest bounded canary.
BOOST_AUTO_TEST_CASE(
    bounded_sha_fs_canary_sha_recursively_consumed)
{
    const uint256 seed = Filled(0xd1);
    const va::AlgAirProof proof = HonestBoundedShaFsCanaryProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);
    const va::FiatShamirProgram bounded =
        va::BuildBoundedFiatShamirProgram(
            shape, va::kRCFiatShamirOodCandidateSchedule);
    BOOST_REQUIRE(bounded.valid);

    const va::FiatShamirShaRecursivelyConsumedV1 recursive =
        va::MeasureFiatShamirShaRecursivelyConsumedV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(recursive.note);
    BOOST_REQUIRE_MESSAGE(recursive.consumed, recursive.note);
    BOOST_CHECK(recursive.digest_plan_ready);
    BOOST_CHECK(recursive.schedule_exact);
    BOOST_CHECK(recursive.arity_four_join_complete);
    BOOST_CHECK(recursive.shard_boundary_airs_execute);
    BOOST_CHECK(recursive.join_tamper_rejects);
    BOOST_CHECK(recursive.boundary_tamper_rejects);
    BOOST_CHECK_GT(recursive.sha_calls, 0U);
    BOOST_CHECK_EQUAL(
        recursive.calls_boundary_air_green, recursive.sha_calls);
    BOOST_CHECK_EQUAL(
        recursive.shards_joined, recursive.parent_shards);

    const va::VerifierFiatShamirAirChipGapV1 gap =
        va::AssessVerifierFiatShamirAirChipGapV1(
            bounded, seed, proof);
    BOOST_TEST_MESSAGE(gap.note);
    BOOST_CHECK(gap.sha_recursively_consumed);
    BOOST_CHECK(gap.challenge_selection_air_constrained);
    BOOST_CHECK(gap.air_backed_all_kinds_reconstructed);
    BOOST_CHECK(gap.whole_verifier_sha_equations_in_air);
    BOOST_CHECK(!gap.executable_ready);
    BOOST_CHECK(gap.non_sha_challenges_recursively_consumed);
    BOOST_CHECK(!gap.authority_eligible);
    BOOST_CHECK_EQUAL(gap.active_config_fs_blocker, "canary_only");
    BOOST_CHECK_EQUAL(gap.open_predicates, 1U);
    static_assert(!va::kVerifierFiatShamirAirExecutable);
}

// Fail-closed: honest SHA canary never closes executable_ready via
// consensus-authority-still-open theater. authority_eligible stays the
// production-path conjunct; only ActiveConfig / non-canary (e.g. V10)
// programs can turn it green.
BOOST_AUTO_TEST_CASE(
    sha_canary_never_closes_executable_via_consensus_open)
{
    const uint256 seed = Filled(0xce);
    const va::AlgAirProof canary_proof =
        HonestBoundedShaFsCanaryProof(seed);
    const nr::NarrowChildShape canary_shape =
        ShapeForProof(canary_proof);
    const va::FiatShamirProgram canary =
        va::BuildBoundedFiatShamirProgram(
            canary_shape, va::kRCFiatShamirOodCandidateSchedule);
    BOOST_REQUIRE(canary.valid);
    BOOST_CHECK(canary.canary_only);
    BOOST_CHECK(!canary.authority_eligible);

    const va::VerifierFiatShamirAirChipGapV1 canary_gap =
        va::AssessVerifierFiatShamirAirChipGapV1(
            canary, seed, canary_proof);
    BOOST_TEST_MESSAGE(canary_gap.note);
    // Technical SHA conjuncts may be green on the canary...
    BOOST_CHECK(canary_gap.sha_execution_plan_valid);
    BOOST_CHECK(canary_gap.sha_fixed_schedule);
    BOOST_CHECK(canary_gap.whole_verifier_sha_equations_in_air);
    BOOST_CHECK(canary_gap.non_sha_challenges_recursively_consumed);
    // ...but authority_eligible / executable_ready must stay closed.
    BOOST_CHECK(!canary_gap.authority_eligible);
    BOOST_CHECK_EQUAL(canary_gap.active_config_fs_blocker, "canary_only");
    BOOST_CHECK_GE(canary_gap.open_predicates, 1U);
    BOOST_CHECK(!canary_gap.executable_ready);
    // Consensus authority remaining open is NOT a chip-closing conjunct.
    static_assert(!va::kVerifierAirConsensusAuthority);
    static_assert(!va::kVerifierFiatShamirAirExecutable);

    // ActiveConfig Canonical on Q=192 closes authority_eligible; living
    // blocker documents the unbounded OOD residual (not canary theater).
    nr::NarrowChildShape active_shape = canary_shape;
    active_shape.queries = rc::kRCFri3AlgNumQueries;
    const va::FiatShamirProgram active =
        va::BuildCanonicalFiatShamirProgram(active_shape);
    BOOST_REQUIRE(active.valid);
    BOOST_CHECK(!active.canary_only);
    BOOST_CHECK(active.authority_eligible);
    BOOST_CHECK_EQUAL(active.ood_candidates, 0U);
    BOOST_CHECK(!active.rejection_loop_bounded);
    BOOST_CHECK_EQUAL(
        active.child_proof_version,
        rc::kRCFri3AlgActiveBatchProofVersion);

    const va::AlgAirProof active_proof = ToyProof(active_shape);
    const va::VerifierFiatShamirAirChipGapV1 active_gap =
        va::AssessVerifierFiatShamirAirChipGapV1(
            active, seed, active_proof);
    BOOST_TEST_MESSAGE(active_gap.note);
    BOOST_CHECK(active_gap.authority_eligible);
    BOOST_CHECK_EQUAL(
        active_gap.active_config_fs_blocker,
        "unbounded_ood_rejection_loop");
    BOOST_CHECK(!active_gap.bounded_ood_program_legislated);
    BOOST_CHECK(!active_gap.executable_ready);
    BOOST_CHECK_GE(active_gap.open_predicates, 1U);
}

// Additive V10 P2/Q192/K=2 FS program: authority_eligible + bounded OOD
// measure green on the production-shaped Poseidon2 path; SHA-AIR conjuncts
// remain the living blocker (not another SHA canary). Executable stays false.
BOOST_AUTO_TEST_CASE(
    p2_q192_k2_v10_fs_program_closes_authority_eligible_not_executable)
{
    BOOST_CHECK(!rc::kRCFri3AlgP2Q192K2ActivatedV10);
    static_assert(!va::kVerifierFiatShamirAirExecutable);

    nr::NarrowChildShape shape;
    shape.child_w = 1;
    shape.child_n_rows = 2;
    shape.child_n_coeffs = 2;
    shape.child_n_lde = 32;
    shape.merkle_depth = 5;
    shape.n_folds = 1;
    shape.queries = rc::kRCFri3AlgNumQueries;
    shape.child_constraints = 1;
    shape.arity = 1;

    const va::FiatShamirProgram v10 =
        va::BuildP2Q192K2V10FiatShamirProgram(shape);
    BOOST_REQUIRE_MESSAGE(v10.valid, v10.note);
    BOOST_CHECK(va::ValidateCanonicalFiatShamirProgram(v10));
    BOOST_CHECK(!v10.canary_only);
    BOOST_CHECK(v10.authority_eligible);
    BOOST_CHECK(!v10.child_sha256d_challenges);
    BOOST_CHECK(v10.child_short_transcript_commitments);
    BOOST_CHECK_EQUAL(
        v10.ood_candidates, rc::kRCFri3AlgP2Q192K2OodCandidatesV10);
    BOOST_CHECK(v10.rejection_loop_bounded);
    BOOST_CHECK_EQUAL(
        v10.child_proof_version,
        rc::kRCFri3AlgP2Q192K2ProofVersionV10);
    BOOST_CHECK_EQUAL(
        v10.child_domain_tag, rc::kRCFri3AlgP2Q192K2DomainTagV10);
    // Canary builder on the same Q192 shape must refuse (requires Q=2).
    BOOST_CHECK(
        !va::BuildBoundedFiatShamirProgram(
             shape, va::kRCFiatShamirOodCandidateSchedule)
             .valid);

    // Concrete V10 proof path (existing additive producer). Shape must
    // match the committed batch so BuildP2Q192K2V10FiatShamirProgram stays
    // valid (column_len.size()-1 == child_w).
    const uint256 seed = Filled(0xd2);
    std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::FromFp(3), gf::Fp3::FromFp(5)},
        {gf::Fp3::FromFp(7), gf::Fp3::FromFp(11)}};
    const auto committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(columns, seed);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    va::AlgAirProof proof;
    proof.batch = committed.proof;
    proof.trace_commit = Filled(0xa2);
    const nr::NarrowChildShape proof_shape = ShapeForProof(proof);
    BOOST_CHECK_EQUAL(proof_shape.queries, rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(proof_shape.child_w, 1U);
    const va::FiatShamirProgram v10_proof_program =
        va::BuildP2Q192K2V10FiatShamirProgram(proof_shape);
    BOOST_REQUIRE_MESSAGE(
        v10_proof_program.valid, v10_proof_program.note);

    const va::VerifierFiatShamirAirChipGapV1 gap =
        va::AssessVerifierFiatShamirAirChipGapV1(
            v10_proof_program, seed, proof);
    BOOST_TEST_MESSAGE(gap.note);
    BOOST_CHECK(gap.authority_eligible);
    BOOST_CHECK(gap.bounded_ood_program_legislated);
    BOOST_CHECK(gap.bounded_ood_rejection_loop_bounded);
    BOOST_CHECK_EQUAL(
        gap.active_config_fs_blocker,
        "p2_squeeze_sha_execution_plan_inapplicable");
    // SHA-AIR chip path does not apply to Poseidon2 V10.
    BOOST_CHECK(!gap.sha_execution_plan_valid);
    BOOST_CHECK(!gap.sha_fixed_schedule);
    BOOST_CHECK(!gap.whole_verifier_sha_equations_in_air);
    BOOST_CHECK(!gap.executable_ready);
    BOOST_CHECK_GE(gap.open_predicates, 1U);
}

BOOST_AUTO_TEST_CASE(fiat_shamir_witness_binds_every_claim_without_claiming_sha_air)
{
    const nr::NarrowChildShape shape = ToyShape();
    const va::FiatShamirProgram program =
        va::BuildCanonicalFiatShamirProgram(shape);
    const va::AlgAirProof proof = ToyProof(shape);
    const uint256 seed = Filled(0xc0);
    const va::FiatShamirWitness witness =
        va::BuildFiatShamirWitness(program, seed, proof);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);
    BOOST_CHECK(witness.claims_bound_to_child_proof);
    BOOST_CHECK(!witness.sha256_equations_checked);
    BOOST_CHECK_EQUAL(witness.events.size(), program.events.size());
    BOOST_CHECK(!witness.witness_commitment.IsNull());

    auto lambda = proof;
    lambda.batch.lambda =
        gf::Add(lambda.batch.lambda, gf::Fp3::One());
    const auto changed =
        va::BuildFiatShamirWitness(program, seed, lambda);
    BOOST_REQUIRE(changed.valid);
    BOOST_CHECK(changed.witness_commitment !=
                witness.witness_commitment);

    const auto other_seed =
        va::BuildFiatShamirWitness(program, Filled(0xc1), proof);
    BOOST_REQUIRE(other_seed.valid);
    BOOST_CHECK(other_seed.witness_commitment !=
                witness.witness_commitment);
}

BOOST_AUTO_TEST_CASE(fs_seed_ownership_bus_binds_parent_binding_digest)
{
    // Edge 1: bind the 32-byte child transcript seed to the parent's AlgHash
    // binding digest h_cj across the field-domain boundary.
    const rc::Fri3AlgDigest h_cj = Digest(0x1234);
    const va::FiatShamirSeedOwnershipBusV1 bus =
        va::BuildFiatShamirSeedOwnershipBusV1(h_cj);
    BOOST_REQUIRE_MESSAGE(bus.valid, bus.note);
    BOOST_CHECK(bus.canonical_roundtrip);

    // The owned seed image IS the canonical LE-limb packing of h_cj.
    const uint256 packed = rc::Fri3AlgDigestToUint256(h_cj);
    BOOST_CHECK(bus.owned_seed == packed);

    // All 32 seed bytes carry the ParentBindingDigest origin, in offset order.
    for (uint32_t byte = 0; byte < 32; ++byte) {
        BOOST_CHECK(
            bus.byte_origins[byte].kind ==
            va::FiatShamirShaByteOriginKindV1::ParentBindingDigest);
        BOOST_CHECK_EQUAL(bus.byte_origins[byte].byte_offset, byte);
    }

    // Honest case: a seed equal to the packing is OWNED (0 byte violations).
    BOOST_CHECK_EQUAL(
        va::FiatShamirSeedBusViolations(bus, packed), 0U);
    // A caller-arbitrary seed is NOT owned by the binding digest.
    BOOST_CHECK_GT(
        va::FiatShamirSeedBusViolations(bus, Filled(0xab)), 0U);

    // Tamper: bumping one limb of h_cj changes the owned seed image and the
    // commitment, so the previously-owned seed no longer binds.
    rc::Fri3AlgDigest tampered = h_cj;
    tampered[1] = tampered[1] + 1;
    const va::FiatShamirSeedOwnershipBusV1 tampered_bus =
        va::BuildFiatShamirSeedOwnershipBusV1(tampered);
    BOOST_REQUIRE(tampered_bus.valid);
    BOOST_CHECK(tampered_bus.owned_seed != bus.owned_seed);
    BOOST_CHECK(tampered_bus.commitment != bus.commitment);
    BOOST_CHECK_GT(
        va::FiatShamirSeedBusViolations(tampered_bus, packed), 0U);

    // End-to-end: h_cj genuinely drives the child transcript.  A canonical FS
    // witness seeded from the honest owned seed and one seeded from the
    // tampered owned seed produce DIFFERENT transcript commitments.
    const nr::NarrowChildShape shape = ToyShape();
    const va::FiatShamirProgram program =
        va::BuildCanonicalFiatShamirProgram(shape);
    const va::AlgAirProof proof = ToyProof(shape);
    const va::FiatShamirWitness w_owned =
        va::BuildFiatShamirWitness(program, bus.owned_seed, proof);
    const va::FiatShamirWitness w_tampered =
        va::BuildFiatShamirWitness(
            program, tampered_bus.owned_seed, proof);
    BOOST_REQUIRE(w_owned.valid);
    BOOST_REQUIRE(w_tampered.valid);
    BOOST_CHECK(
        w_owned.witness_commitment != w_tampered.witness_commitment);
}

namespace {
va::FiatShamirChallengeReconstructionInputV1 OodInput(
    va::FiatShamirEventKind kind,
    const std::array<uint64_t, 8>& words)
{
    va::FiatShamirChallengeReconstructionInputV1 in;
    in.kind = kind;
    in.ood_words = words;
    return in;
}
va::FiatShamirChallengeReconstructionInputV1 DirectInput(
    va::FiatShamirEventKind kind, unsigned char seed)
{
    va::FiatShamirChallengeReconstructionInputV1 in;
    in.kind = kind;
    for (uint32_t i = 0; i < 24; ++i) {
        in.direct_bytes[i] =
            static_cast<unsigned char>(seed + 5 * i);
    }
    return in;
}
va::FiatShamirChallengeReconstructionInputV1 QueryInput()
{
    va::FiatShamirChallengeReconstructionInputV1 in;
    in.kind = va::FiatShamirEventKind::ChallengeQueryIndex;
    in.query_bytes = {0x11, 0x22, 0x33, 0x44};
    in.query_modulus = 32;
    return in;
}
} // namespace

BOOST_AUTO_TEST_CASE(
    fs_air_backed_witness_reconstructs_ood_subset_in_air)
{
    // Reduced consensus-path variant: the OOD challenges z1,z2 are reconstructed
    // IN-AIR from their SHA-derived digest words via the selection decoder
    // (selected_value is constrained to the first three accepted words), NOT
    // copied from the proof batch.  Subset coverage (2 of 8) -> the AIR-backed
    // sha256_equations_checked must stay false.
    const std::array<uint64_t, 8> z1_words{
        7, 11, 13, 17, 19, 23, 29, 31};
    const std::array<uint64_t, 8> z2_words{
        101, 103, 107, 109, 113, 127, 131, 137};
    const std::vector<va::FiatShamirChallengeReconstructionInputV1>
        covered{
            OodInput(va::FiatShamirEventKind::ChallengeZ1, z1_words),
            OodInput(va::FiatShamirEventKind::ChallengeZ2, z2_words)};

    const auto w =
        va::BuildFiatShamirAirBackedWitnessV1(covered);
    BOOST_REQUIRE_MESSAGE(w.valid, w.note);
    BOOST_CHECK_EQUAL(w.reconstructed_challenge_types, 2U);
    BOOST_CHECK_EQUAL(w.total_challenge_types, 8U);
    BOOST_CHECK(!w.covers_all_challenge_types);
    BOOST_CHECK(!w.sha256_equations_checked);
    BOOST_CHECK(w.all_covered_reconstructions_constrained);

    // The carried challenge is the constrained decoder output, not a host copy.
    const fs::WitnessV1 sel1 = fs::BuildWitnessV1(z1_words);
    BOOST_REQUIRE(sel1.valid);
    BOOST_CHECK(gf::Eq(w.reconstructed_values[0], sel1.selected_value));

    // Tamper: changing a digest word changes the reconstructed challenge.
    std::array<uint64_t, 8> z1_tampered = z1_words;
    z1_tampered[0] = 8;
    const std::vector<va::FiatShamirChallengeReconstructionInputV1>
        covered2{
            OodInput(va::FiatShamirEventKind::ChallengeZ1, z1_tampered),
            OodInput(va::FiatShamirEventKind::ChallengeZ2, z2_words)};
    const auto w2 =
        va::BuildFiatShamirAirBackedWitnessV1(covered2);
    BOOST_REQUIRE(w2.valid);
    BOOST_CHECK(
        !gf::Eq(w2.reconstructed_values[0],
                w.reconstructed_values[0]));

    const auto empty =
        va::BuildFiatShamirAirBackedWitnessV1({});
    BOOST_CHECK(!empty.valid);
    BOOST_CHECK(!empty.covers_all_challenge_types);
}

BOOST_AUTO_TEST_CASE(
    fs_air_backed_witness_reconstructs_all_eight_kinds_in_air)
{
    // Full-KIND coverage at reduced shape: every one of the eight challenge
    // kinds is reconstructed IN-AIR via its decoder -- z1/z2 (OOD selection),
    // query-index (query decoder), and airq-lambda/lambda/w1/w2/fold-beta (the
    // direct byte->Fp3 decoder). Decoder coverage alone must not claim that
    // upstream SHA/Poseidon equations are equality-linked.
    const std::array<uint64_t, 8> z_words{
        7, 11, 13, 17, 19, 23, 29, 31};
    const std::vector<va::FiatShamirChallengeReconstructionInputV1>
        all_eight{
            OodInput(va::FiatShamirEventKind::ChallengeZ1, z_words),
            OodInput(va::FiatShamirEventKind::ChallengeZ2, z_words),
            QueryInput(),
            DirectInput(
                va::FiatShamirEventKind::ChallengeAirQuotientLambda,
                0x10),
            DirectInput(va::FiatShamirEventKind::ChallengeLambda, 0x20),
            DirectInput(va::FiatShamirEventKind::ChallengeW1, 0x30),
            DirectInput(va::FiatShamirEventKind::ChallengeW2, 0x40),
            DirectInput(va::FiatShamirEventKind::ChallengeFold, 0x50)};

    const auto w =
        va::BuildFiatShamirAirBackedWitnessV1(all_eight);
    BOOST_REQUIRE_MESSAGE(w.valid, w.note);
    BOOST_CHECK_EQUAL(w.reconstructed_challenge_types, 8U);
    BOOST_CHECK_EQUAL(w.total_challenge_types, 8U);
    BOOST_CHECK(w.covers_all_challenge_types);
    BOOST_CHECK(w.challenge_decoders_checked);
    BOOST_CHECK(!w.sha256_equations_checked);
    BOOST_CHECK(w.all_covered_reconstructions_constrained);

    // The direct-decoded challenges equal FromChallengeBytes3 of their bytes
    // (in-AIR reconstruction == the canonical map, no host extraction).
    const auto lambda_in =
        DirectInput(va::FiatShamirEventKind::ChallengeLambda, 0x20);
    const auto d =
        fs::BuildDirectChallengeWitnessV1(lambda_in.direct_bytes);
    BOOST_REQUIRE(d.valid);
    BOOST_CHECK(gf::Eq(w.reconstructed_values[4], d.value));

    // Tamper a direct challenge's bytes -> its reconstructed value changes.
    auto tampered = all_eight;
    tampered[3].direct_bytes[0] ^= 0xFFu; // airq-lambda
    const auto w_tam =
        va::BuildFiatShamirAirBackedWitnessV1(tampered);
    BOOST_REQUIRE(w_tam.valid);
    BOOST_CHECK(
        !gf::Eq(w_tam.reconstructed_values[3],
                w.reconstructed_values[3]));

    // Missing one kind (drop fold-beta) -> not all covered -> flag stays false.
    std::vector<va::FiatShamirChallengeReconstructionInputV1> seven(
        all_eight.begin(), all_eight.end() - 1);
    const auto w7 =
        va::BuildFiatShamirAirBackedWitnessV1(seven);
    BOOST_REQUIRE(w7.valid);
    BOOST_CHECK_EQUAL(w7.reconstructed_challenge_types, 7U);
    BOOST_CHECK(!w7.covers_all_challenge_types);
    BOOST_CHECK(!w7.sha256_equations_checked);
}

BOOST_AUTO_TEST_CASE(authoritative_transcript_replay_rejects_proof_carried_challenges)
{
    const uint256 seed = Filled(0xc4);
    const va::AlgAirProof proof = HonestToyProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);
    const va::FiatShamirProgram program =
        va::BuildCanonicalFiatShamirProgram(shape);
    const va::FiatShamirWitness witness =
        va::BuildFiatShamirWitness(program, seed, proof);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);

    const va::FiatShamirReplayResult replay =
        va::ReplayFiatShamirWitness(
            program, seed, proof, witness);
    BOOST_CHECK(replay.canonical_program);
    BOOST_CHECK(replay.witness_matches_proof);
    BOOST_CHECK(replay.air_quotient_challenge_replayed);
    BOOST_CHECK(replay.fri_transcript_replayed);
    BOOST_CHECK(!replay.rejection_loop_bounded);
    BOOST_CHECK(!replay.complete_for_recursive_air);

    auto tampered = proof;
    tampered.batch.lambda =
        gf::Add(tampered.batch.lambda, gf::Fp3::One());
    const va::FiatShamirWitness tampered_witness =
        va::BuildFiatShamirWitness(
            program, seed, tampered);
    BOOST_REQUIRE(tampered_witness.valid);
    const va::FiatShamirReplayResult rejected =
        va::ReplayFiatShamirWitness(
            program, seed, tampered, tampered_witness);
    BOOST_CHECK(!rejected.fri_transcript_replayed);
    BOOST_CHECK(
        rejected.note.find("fri_replay:") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(whole_host_witness_consumes_native_children_and_vcs)
{
    const uint256 seed = Filled(0xc6);
    const auto child_cs = ToyChildSystem();
    const va::AlgAirProof proof = HonestToyProof(seed);
    const nr::NarrowChildShape shape = ShapeForProof(proof);
    const va::VerifierProgram program =
        va::BuildCanonicalVerifierProgram(shape);
    BOOST_REQUIRE(program.valid);
    const rc::RCStage3CtlChildPin ctl = CtlPin();

    const va::WholeVerifierWitness whole =
        va::BuildWholeVerifierWitness(
            program, child_cs, seed, {proof}, {ctl});
    BOOST_REQUIRE_MESSAGE(whole.valid, whole.note);
    BOOST_CHECK(whole.all_transcripts_replayed);
    BOOST_CHECK(whole.all_native_children_accepted);
    BOOST_CHECK(whole.algebraic_mirror_satisfied);
    BOOST_CHECK_EQUAL(whole.algebraic_violations, 0U);
    BOOST_CHECK_GT(whole.child_proof_bytes, 0U);
    BOOST_CHECK(whole.legacy_q192_v3_only);
    BOOST_CHECK(!whole.dual_q128_v5_target_supported);
    BOOST_CHECK(!whole.recursive_air_complete);

    auto tampered = proof;
    tampered.batch.queries[0].row.values[0] =
        gf::Add(
            tampered.batch.queries[0].row.values[0],
            gf::Fp3::One());
    const va::WholeVerifierWitness rejected =
        va::BuildWholeVerifierWitness(
            program, child_cs, seed, {tampered}, {ctl});
    BOOST_CHECK(!rejected.valid);
    BOOST_CHECK(!rejected.all_native_children_accepted);
}

BOOST_AUTO_TEST_CASE(v5_dual_host_witness_joins_transcript_and_native_verifier)
{
    const uint256 seed = Filled(0xc8);
    const auto committed =
        rc::Fri3AlgDualBatchCommit(
            DualColumns(), seed, 41);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);

    const va::DualQ128HostVerifierWitness witness =
        va::BuildDualQ128HostVerifierWitness(
            committed.proof, seed);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);
    BOOST_CHECK(witness.transcript.valid);
    BOOST_CHECK(witness.native_proof_accepted);
    BOOST_CHECK_EQUAL(
        witness.proof_bytes, committed.proof_bytes);
    BOOST_CHECK(
        !witness.recursive_proof_api_supports_v5);
    BOOST_CHECK(!witness.recursive_air_complete);

    // Query openings are not Fiat-Shamir challenges, so the finite
    // transcript still replays; the authoritative proof verifier must reject.
    auto opening = committed.proof;
    opening.lane[0].queries[0].row.values[0] =
        gf::Add(
            opening.lane[0].queries[0].row.values[0],
            gf::Fp3::One());
    const auto opening_rejected =
        va::BuildDualQ128HostVerifierWitness(
            opening, seed);
    BOOST_CHECK(!opening_rejected.valid);
    BOOST_CHECK(opening_rejected.transcript.valid);
    BOOST_CHECK(!opening_rejected.native_proof_accepted);

    auto challenge = committed.proof;
    challenge.lane[1].lambda =
        gf::Add(
            challenge.lane[1].lambda,
            gf::Fp3::One());
    const auto challenge_rejected =
        va::BuildDualQ128HostVerifierWitness(
            challenge, seed);
    BOOST_CHECK(!challenge_rejected.valid);
    BOOST_CHECK(!challenge_rejected.transcript.valid);
}

BOOST_AUTO_TEST_CASE(host_row_binding_covers_child_openings_ctl_and_program_metadata)
{
    const nr::NarrowChildShape shape = ToyShape();
    const va::VerifierProgram program =
        va::BuildCanonicalVerifierProgram(shape);
    BOOST_REQUIRE(program.valid);
    const va::AlgAirProof proof = ToyProof(shape);
    const rc::RCStage3CtlChildPin ctl = CtlPin();
    const uint256 seed = Filled(0xd0);
    const va::VerifierProofBinding binding =
        va::BuildVerifierProofBinding(
            program, seed, {proof}, {ctl});
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    BOOST_CHECK_EQUAL(binding.rows.size(), program.active_rows);
    BOOST_CHECK_EQUAL(binding.child_proof_commitments.size(), 1U);
    BOOST_CHECK_EQUAL(
        binding.fiat_shamir_witness_commitments.size(), 1U);
    BOOST_CHECK_EQUAL(binding.ctl_child_commitments.size(), 1U);
    BOOST_CHECK(!binding.scheduler_capacity_sufficient);
    BOOST_CHECK(binding.proof_equations_air_bound);
    BOOST_REQUIRE_EQUAL(binding.payload_roots.size(), 1U);
    BOOST_CHECK(!binding.payload_roots.front().IsNull());
    const va::VerifierProofRowsPayloadBusV1 payload =
        va::BuildVerifierProofRowsPayloadBusV1(proof);
    BOOST_REQUIRE_MESSAGE(payload.valid, payload.note);
    BOOST_CHECK(payload.sponge_authenticated);
    BOOST_CHECK(payload.forgery_rejected);
    BOOST_CHECK_MESSAGE(
        binding.payload_roots.front() == payload.payload_root,
        "payload_root mismatch");
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::ValidateVerifierProofRowsPayloadBusV1(proof, payload, &why),
        why);
    BOOST_CHECK_MESSAGE(
        va::ValidateVerifierProofBinding(
            program, seed, {proof}, {ctl}, binding, &why),
        why);

    auto opening = proof;
    opening.next_openings[0][0].values[0] =
        gf::Add(opening.next_openings[0][0].values[0],
                gf::Fp3::One());
    BOOST_CHECK(
        !va::ValidateVerifierProofBinding(
            program, seed, {opening}, {ctl}, binding, &why));

    auto ctl_terminal = ctl;
    ctl_terminal.terminal.alpha1_sum = gf::Fp3::One();
    BOOST_CHECK(
        !va::ValidateVerifierProofBinding(
            program, seed, {proof}, {ctl_terminal}, binding, &why));

    auto source = program;
    source.rows[0].source = va::ProgramRowSource::FoldEvenLeaf;
    BOOST_CHECK(
        !va::ValidateVerifierProofBinding(
            source, seed, {proof}, {ctl}, binding, &why));
}

BOOST_AUTO_TEST_CASE(completeness_flags_name_the_remaining_hash_gap)
{
    static_assert(va::kVerifierFixedSchedulerExecutable);
    static_assert(va::kVerifierScalarAirExecutable);
    static_assert(va::kWholeVerifierHostDifferentialExecutable);
    static_assert(va::kWholeVerifierLegacyV3HostDifferentialExecutable);
    static_assert(
        !va::kWholeVerifierDualQ128V5HostDifferentialExecutable);
    static_assert(va::kDualQ128V5HostTranscriptExecutable);
    static_assert(!va::kVerifierFiatShamirAirExecutable);
    static_assert(va::kVerifierProofRowsBoundInAir);
    static_assert(!va::kWholeVerifierWitnessExecutable);
    static_assert(
        va::kMultiRowV2SplitRapVerifierAirLocalExecutable);
    static_assert(
        !va::kMultiRowV2SplitRapVerifierAirRecursiveAuthority);
    static_assert(!va::kVerifierAirConsensusAuthority);
}

BOOST_AUTO_TEST_CASE(
    multi_row_v2_split_rap_program_is_exact_and_parameterized)
{
    const auto cs = ToySplitRapSystem();
    const auto program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            cs, {0});
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    BOOST_CHECK_EQUAL(program.version, 1U);
    BOOST_CHECK_EQUAL(program.trace_rows, 2U);
    BOOST_CHECK_EQUAL(program.trace_columns, 2U);
    BOOST_CHECK_EQUAL(program.n_coeffs, 2U);
    BOOST_CHECK_EQUAL(program.n_lde, 32U);
    BOOST_CHECK_EQUAL(program.merkle_depth, 5U);
    BOOST_CHECK_EQUAL(program.fold_count, 1U);
    BOOST_CHECK_EQUAL(
        program.query_count,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(program.group_widths[0], 1U);
    BOOST_CHECK_EQUAL(program.group_widths[1], 1U);
    BOOST_CHECK_EQUAL(program.group_widths[2], 1U);
    BOOST_CHECK_GT(program.poseidon_permutation_rows, 0U);
    BOOST_CHECK_LE(
        program.poseidon_permutation_rows,
        program.air_rows);
    BOOST_CHECK(program.exact_three_group_partition);
    BOOST_CHECK(program.independent_pcs_alpha_schedule);
    BOOST_CHECK(program.current_next_schedule_complete);
    BOOST_CHECK(program.quotient_identity_scheduled);
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
            cs, program, &why),
        why);

    auto role_attack = program;
    ++role_attack.group_widths[0];
    BOOST_CHECK(
        !va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
            cs, role_attack, &why));

    auto order_attack = program;
    std::swap(
        order_attack.rows[0],
        order_attack.rows[1]);
    BOOST_CHECK(
        !va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
            cs, order_attack, &why));

    auto omission_attack = program;
    omission_attack.rows.erase(
        omission_attack.rows.begin() + 3);
    BOOST_CHECK(
        !va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
            cs, omission_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    multi_row_v2_split_rap_local_executable_gap_closes)
{
    const auto cs = ToySplitRapSystem();
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()},
        {gf::Fp3::One(), gf::Fp3::Zero()}};
    const std::vector<uint32_t> base_indices{0};
    const uint256 seed = Filled(0xdd);
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns, base_indices, seed);
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    const auto program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            cs, base_indices);
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    const auto gap =
        va::AssessMultiRowV2SplitRapLocalExecutableGapV1(
            cs, program, proved.proof, seed);
    BOOST_TEST_MESSAGE(gap.note);
    BOOST_CHECK(gap.canonical_program);
    BOOST_CHECK(gap.host_verifier_accepted);
    BOOST_CHECK(gap.local_witness_valid);
    BOOST_CHECK(gap.local_witness_verified);
    BOOST_CHECK(gap.openings_and_identities_checked);
    BOOST_CHECK(gap.poseidon_layout_constrained);
    BOOST_CHECK(gap.sha_schedule_exact);
    BOOST_CHECK(gap.claimed_tamper_rejects);
    BOOST_CHECK(gap.recursive_authority_still_open);
    BOOST_CHECK_EQUAL(gap.open_predicates, 0U);
    BOOST_CHECK(gap.local_executable_ready);
    static_assert(
        va::kMultiRowV2SplitRapVerifierAirLocalExecutable);
    static_assert(
        !va::kMultiRowV2SplitRapVerifierAirRecursiveAuthority);
}

BOOST_AUTO_TEST_CASE(
    multi_row_v2_airq_child_exact_local_mirror_optional)
{
    const char* enabled =
        std::getenv(
            "BTX_RUN_STAGE3_MULTI_ROW_V2_VERIFIER_AIR");
    if (enabled == nullptr ||
        std::string{enabled} != "1") {
        BOOST_TEST_MESSAGE(
            "MultiRow-V2 verifier AIR proof skipped "
            "(BTX_RUN_STAGE3_MULTI_ROW_V2_VERIFIER_AIR!=1)");
        return;
    }
    const auto cs = ToySplitRapSystem();
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()},
        {gf::Fp3::One(), gf::Fp3::Zero()}};
    const std::vector<uint32_t> base_indices{0};
    const uint256 seed = Filled(0xdd);
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns, base_indices, seed);
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    const auto program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            cs, base_indices);
    BOOST_REQUIRE_MESSAGE(program.valid, program.note);
    const auto witness =
        va::BuildMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proved.proof, seed);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);
    BOOST_CHECK(witness.canonical_program);
    BOOST_CHECK(witness.host_verifier_accepted);
    BOOST_CHECK(witness.transcript_replayed_exactly);
    BOOST_CHECK(
        witness.all_independent_pcs_alphas_derived);
    BOOST_CHECK(
        witness.all_current_next_openings_bound);
    BOOST_CHECK(witness.all_merkle_paths_replayed);
    BOOST_CHECK(
        witness.all_deep_fold_identities_checked);
    BOOST_CHECK(
        witness.all_quotient_identities_checked);
    BOOST_CHECK(
        witness.alg_hash_poseidon_permutations_constrained);
    BOOST_REQUIRE(
        witness.poseidon_alias_plan.valid);
    BOOST_CHECK(
        witness.poseidon_alias_plan
            .exact_permutation_order);
    BOOST_CHECK(
        witness.poseidon_alias_plan
            .layout_aliases_complete);
    BOOST_CHECK(
        !witness.poseidon_alias_plan
             .semantic_aliases_complete);
    BOOST_CHECK_EQUAL(
        witness.poseidon_alias_plan
            .permutation_count,
        program.poseidon_permutation_rows);
    BOOST_CHECK_EQUAL(
        witness.poseidon_alias_plan
            .layout_input_alias_cells,
        12U * program.poseidon_permutation_rows);
    BOOST_CHECK_EQUAL(
        witness.poseidon_alias_plan
            .layout_output_alias_cells,
        12U * program.poseidon_permutation_rows);
    BOOST_REQUIRE(
        witness.transcript_sha_plan.valid);
    BOOST_CHECK(
        witness.transcript_sha_plan.exact_call_order);
    BOOST_CHECK(
        witness.transcript_sha_plan
            .every_compression_sharded_once);
    BOOST_CHECK(
        witness.transcript_sha_plan
            .shard_capacity_respected);
    BOOST_CHECK(
        witness.transcript_sha_plan
            .arity_four_manifest_complete);
    BOOST_CHECK_GT(
        witness.transcript_sha_plan.sha256d_calls,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_LT(
        witness.transcript_sha_plan
            .unique_total_compressions,
        witness.transcript_sha_plan
            .naive_compressions);
    for (const auto& shard :
         witness.transcript_sha_plan.shards) {
        BOOST_CHECK_GT(shard.compression_count, 0U);
        BOOST_CHECK_LE(shard.compression_count, 63U);
    }
    BOOST_CHECK_MESSAGE(
        va::ValidateMultiRowV2TranscriptShaPlanV1(
            witness.transcript_sha_plan),
        witness.transcript_sha_plan.note);
    BOOST_CHECK_EQUAL(
        witness.transcript_sha_plan.proof_owned_shards,
        0U);
    BOOST_CHECK_EQUAL(
        witness.transcript_sha_plan
            .recursively_consumed_shards,
        0U);
    BOOST_CHECK(
        !witness.transcript_sha_plan
             .sha_shard_proofs_execute);
    BOOST_CHECK(
        !witness
             .alg_hash_io_aliases_to_proof_rows_complete);
    BOOST_CHECK(!witness.sha_transcript_air_constrained);
    BOOST_CHECK(!witness.parent_hash_chips_execute);
    BOOST_CHECK_EQUAL(
        witness.normalized_recursive_cells, 0U);
    BOOST_CHECK(!witness.production_authority_ready);
    BOOST_CHECK_EQUAL(
        va::CountVerifierScalarViolations(
            witness.constraint_system,
            witness.witness_columns),
        0U);
    const auto outputs =
        va::ExportMultiRowV2SplitRapVerifierOutputsV1(
            witness);
    BOOST_CHECK_EQUAL(
        outputs.size(), witness.exported_cells);
    BOOST_CHECK(!outputs.empty());
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proved.proof, seed,
            witness, &why),
        why);

    auto value_attack = witness;
    value_attack.witness_columns[
        va::kMultiRowV2Claimed0][0] =
            gf::Add(
                value_attack.witness_columns[
                    va::kMultiRowV2Claimed0][0],
                gf::Fp3::One());
    BOOST_CHECK_GT(
        va::CountVerifierScalarViolations(
            value_attack.constraint_system,
            value_attack.witness_columns),
        0U);
    BOOST_CHECK(
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proved.proof, seed,
            value_attack, &why));

    auto permutation_attack = witness;
    permutation_attack.witness_columns[
        va::kMultiRowV2VerifierColumns][0] =
            gf::Add(
                permutation_attack.witness_columns[
                    va::kMultiRowV2VerifierColumns][0],
                gf::Fp3::One());
    BOOST_CHECK_GT(
        va::CountVerifierScalarViolations(
            permutation_attack.constraint_system,
            permutation_attack.witness_columns),
        0U);
    BOOST_CHECK(
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proved.proof, seed,
            permutation_attack, &why));

    auto sha_digest_attack = witness;
    sha_digest_attack.transcript_sha_plan
        .calls.front().digest.begin()[0] ^= 1U;
    BOOST_CHECK(
        !va::ValidateMultiRowV2TranscriptShaPlanV1(
            sha_digest_attack.transcript_sha_plan,
            &why));
    BOOST_CHECK(
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proved.proof, seed,
            sha_digest_attack, &why));

    auto sha_shard_relabel = witness;
    BOOST_REQUIRE(
        !sha_shard_relabel.transcript_sha_plan
             .shards.empty());
    ++sha_shard_relabel.transcript_sha_plan
          .shards.front().shard;
    BOOST_CHECK(
        !va::ValidateMultiRowV2TranscriptShaPlanV1(
            sha_shard_relabel.transcript_sha_plan,
            &why));

    auto poseidon_alias_attack = witness;
    BOOST_REQUIRE(
        !poseidon_alias_attack.poseidon_alias_plan
             .permutations.empty());
    poseidon_alias_attack.poseidon_alias_plan
        .permutations.front().input[0] =
            gf::Add(
                poseidon_alias_attack.poseidon_alias_plan
                    .permutations.front().input[0],
                gf::FromU64(1));
    BOOST_CHECK(
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proved.proof, seed,
            poseidon_alias_attack, &why));

    auto proof_attack = proved.proof;
    proof_attack.batch.queries[0]
        .group_rows[0].values[0] =
            gf::Add(
                proof_attack.batch.queries[0]
                    .group_rows[0].values[0],
                gf::Fp3::One());
    const auto rejected =
        va::BuildMultiRowV2SplitRapVerifierWitnessV1(
            cs, program, proof_attack, seed);
    BOOST_CHECK(!rejected.valid);
}

BOOST_AUTO_TEST_CASE(
    chunk_rlc_v1_postcommit_partition_and_attacks)
{
    constexpr uint32_t COLUMNS = 520;
    constexpr uint32_t ROWS = 4;
    std::vector<std::vector<gf::Fp3>> columns(
        COLUMNS,
        std::vector<gf::Fp3>(
            ROWS, gf::Fp3::Zero()));
    for (uint32_t column = 0;
         column < COLUMNS; ++column) {
        for (uint32_t row = 0; row < ROWS; ++row) {
            columns[column][row] = {
                gf::FromU64(
                    17 + 13 * column + row),
                gf::FromU64(
                    29 + column + 7 * row),
                gf::FromU64(
                    41 + 3 * column + 5 * row)};
        }
    }
    const std::vector<uint32_t> queries{0, 3};
    const uint256 seed = Filled(0xe1);
    const auto statement =
        va::BuildChunkRlcPcsStatementV1(
            columns, queries, 1, 256, seed);
    BOOST_REQUIRE_MESSAGE(
        statement.valid, statement.note);
    BOOST_CHECK_EQUAL(statement.version, 1U);
    BOOST_CHECK_EQUAL(statement.trace_rows, ROWS);
    BOOST_CHECK_EQUAL(
        statement.total_columns, COLUMNS);
    BOOST_CHECK_EQUAL(statement.chunk_columns, 256U);
    BOOST_CHECK_EQUAL(statement.chunk_count, 3U);
    BOOST_CHECK(statement.exact_column_partition);
    BOOST_CHECK(
        statement.commitments_precede_challenges);
    BOOST_CHECK(
        statement
            .independent_post_commit_coefficients);
    BOOST_CHECK(
        statement
            .one_current_next_rlc_per_chunk_query);
    BOOST_CHECK(
        statement.arity_four_receipt_tree_complete);
    BOOST_CHECK(
        !statement.original_constraint_relation_bound);
    BOOST_CHECK(
        !statement
             .cross_chunk_constraint_manifest_complete);
    BOOST_CHECK(!statement.original_quotient_linked);
    BOOST_CHECK_EQUAL(
        statement.recursively_consumed_receipts, 0U);
    BOOST_CHECK(
        !statement
             .normalized_recursive_consumption_complete);
    BOOST_CHECK(!statement.production_authority_ready);
    BOOST_REQUIRE_EQUAL(statement.receipts.size(), 3U);
    BOOST_CHECK_EQUAL(
        statement.receipts[0].first_column, 0U);
    BOOST_CHECK_EQUAL(
        statement.receipts[0].column_count, 256U);
    BOOST_CHECK_EQUAL(
        statement.receipts[1].first_column, 256U);
    BOOST_CHECK_EQUAL(
        statement.receipts[1].column_count, 256U);
    BOOST_CHECK_EQUAL(
        statement.receipts[2].first_column, 512U);
    BOOST_CHECK_EQUAL(
        statement.receipts[2].column_count, 8U);
    for (const auto& receipt : statement.receipts) {
        BOOST_CHECK(
            receipt
                .full_chunk_committed_before_coefficients);
        BOOST_CHECK(
            receipt
                .independent_coefficients_derived_post_commit);
        BOOST_CHECK(
            receipt.local_rlc_relation_satisfied);
        BOOST_CHECK(
            receipt.current_next_openings_complete);
        BOOST_CHECK_EQUAL(
            receipt.openings.size(), queries.size());
        BOOST_CHECK_EQUAL(
            va::CountVerifierScalarViolations(
                receipt.local_relation,
                receipt.local_relation_columns),
            0U);
    }
    std::string why;
    BOOST_CHECK_MESSAGE(
        va::VerifyChunkRlcPcsStatementV1(
            columns, queries, statement, &why),
        why);

    // Adaptive-kernel attempt: preserve the old chunk's RLC at row zero
    // with deltas (+alpha_1, -alpha_0). The full-chunk precommit changes
    // first, so the rebuilt post-commit coefficient vector also changes.
    auto adaptive_columns = columns;
    const auto alpha0 =
        statement.receipts[0]
            .independent_coefficients[0];
    const auto alpha1 =
        statement.receipts[0]
            .independent_coefficients[1];
    adaptive_columns[0][0] =
        gf::Add(adaptive_columns[0][0], alpha1);
    adaptive_columns[1][0] =
        gf::Sub(adaptive_columns[1][0], alpha0);
    gf::Fp3 old_schedule_rlc = gf::Fp3::Zero();
    for (uint32_t local = 0; local < 256; ++local) {
        old_schedule_rlc = gf::Add(
            old_schedule_rlc,
            gf::Mul(
                statement.receipts[0]
                    .independent_coefficients[local],
                adaptive_columns[local][0]));
    }
    BOOST_CHECK(gf::Eq(
        old_schedule_rlc,
        statement.receipts[0]
            .openings[0].current_value));
    const auto adaptive =
        va::BuildChunkRlcPcsStatementV1(
            adaptive_columns, queries,
            1, 256, seed);
    BOOST_REQUIRE_MESSAGE(adaptive.valid, adaptive.note);
    BOOST_CHECK(
        adaptive.ordered_precommit_statement !=
        statement.ordered_precommit_statement);
    BOOST_CHECK(
        adaptive.receipts[0].coefficient_statement !=
        statement.receipts[0].coefficient_statement);
    BOOST_CHECK(
        !va::VerifyChunkRlcPcsStatementV1(
            adaptive_columns, queries,
            statement, &why));

    auto cross_chunk = columns;
    std::swap(cross_chunk[255], cross_chunk[256]);
    BOOST_CHECK(
        !va::VerifyChunkRlcPcsStatementV1(
            cross_chunk, queries,
            statement, &why));

    auto omission = statement;
    omission.receipts.erase(
        omission.receipts.begin() + 1);
    BOOST_CHECK(
        !va::VerifyChunkRlcPcsStatementV1(
            columns, queries, omission, &why));

    auto reorder = statement;
    std::swap(
        reorder.receipts[0],
        reorder.receipts[1]);
    BOOST_CHECK(
        !va::VerifyChunkRlcPcsStatementV1(
            columns, queries, reorder, &why));

    auto false_closure_claim = statement;
    false_closure_claim
        .original_constraint_relation_bound = true;
    false_closure_claim
        .cross_chunk_constraint_manifest_complete = true;
    false_closure_claim.original_quotient_linked = true;
    BOOST_CHECK(
        !va::VerifyChunkRlcPcsStatementV1(
            columns, queries,
            false_closure_claim, &why));
}

BOOST_AUTO_TEST_CASE(
    chunk_rlc_cost_selects_512_and_exposes_timing_gate)
{
    const auto selection =
        va::AssessChunkRlcCostSelectionV1(
            124802, 65536, 192, 20);
    BOOST_REQUIRE_MESSAGE(
        selection.valid, selection.note);
    BOOST_CHECK_EQUAL(
        selection.candidates[0].chunk_columns,
        256U);
    BOOST_CHECK_EQUAL(
        selection.candidates[0].chunk_count,
        488U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1].chunk_columns,
        512U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1].chunk_count,
        244U);
    BOOST_CHECK_EQUAL(
        selection.selected_chunk_columns, 512U);
    BOOST_CHECK(
        !selection.candidates[0].selected);
    BOOST_CHECK(selection.candidates[1].selected);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .maximum_leaf_relation_width,
        513U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .normalized_root_width,
        501U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .normalized_root_active_rows,
        32384U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .normalized_root_trace_rows,
        32768U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .aggregation_nodes,
        82U);
    BOOST_CHECK(
        selection.candidates[1].leaf_domain_exact);
    BOOST_CHECK(
        selection.candidates[1].cost_arithmetic_exact);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .leaf_max_composed_degree,
        65535U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1].leaf_quotient_len,
        1U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1].leaf_n_coeffs,
        65536U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1].leaf_n_lde,
        1048576U);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .all_leaf_base_witness_bytes,
        UINT64_C(196680351744));
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .all_leaf_lde_column_bytes,
        UINT64_C(3153026088960));
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .estimated_all_leaf_proof_bytes,
        UINT64_C(1945109472));
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .estimated_root_opening_bytes,
        UINT64_C(1019904));
    BOOST_CHECK(
        selection.candidates[1].backend_caps_met);
    BOOST_CHECK(
        !selection.candidates[1]
             .original_constraint_relation_bound);
    BOOST_CHECK(
        !selection.candidates[1]
             .cross_chunk_constraint_manifest_complete);
    BOOST_CHECK(
        !selection.candidates[1]
             .original_quotient_linked);
    BOOST_CHECK_EQUAL(
        selection.candidates[1]
            .root_verifier_target_micros,
        900000U);
    BOOST_CHECK(
        !selection.candidates[1].timing_measured);
    BOOST_CHECK(
        !selection.candidates[1].timing_target_met);
    static_assert(!va::kChunkRlcPcsV1ProductionAuthority);
}

BOOST_AUTO_TEST_CASE(
    chunk_rlc_leaf_domain_is_quotient_degree_derived_and_fails_closed)
{
    const auto make_relation =
        [](uint32_t degree) {
            aq::AirConstraintSystem<gf::Fp3> cs;
            cs.n_rows = uint32_t{1} << 19;
            cs.n_columns = 2;
            aq::AirConstraint<gf::Fp3> constraint;
            constraint.name =
                "test.chunk_rlc.degree_boundary";
            constraint.kind = aq::AirKind::kEverywhere;
            constraint.alg_degree = degree;
            constraint.eval =
                [](const std::vector<gf::Fp3>&,
                   const std::vector<gf::Fp3>&) {
                    return gf::Fp3::Zero();
                };
            cs.constraints.push_back(
                std::move(constraint));
            return cs;
        };

    const auto degree_three =
        va::AssessChunkRlcLeafDomainV1(
            make_relation(3));
    BOOST_REQUIRE_MESSAGE(
        degree_three.valid,
        degree_three.note);
    BOOST_CHECK(
        degree_three.exact_quotient_degree_accounting);
    BOOST_CHECK(
        degree_three.backend_lde_cap_met);
    BOOST_CHECK_EQUAL(
        degree_three.max_composed_degree,
        uint64_t{3} *
            ((uint64_t{1} << 19) - 1));
    BOOST_CHECK_EQUAL(
        degree_three.quotient_len,
        (uint32_t{1} << 20) - 2);
    BOOST_CHECK_EQUAL(
        degree_three.n_coeffs,
        uint32_t{1} << 20);
    BOOST_CHECK_EQUAL(
        degree_three.n_lde,
        uint32_t{1} << 24);

    // Raising the same canonical relation family to degree five crosses
    // the 2^24 LDE cap.  A trace-only estimate would still claim 2^23.
    const auto degree_five =
        va::AssessChunkRlcLeafDomainV1(
            make_relation(5));
    BOOST_REQUIRE_MESSAGE(
        degree_five.valid,
        degree_five.note);
    BOOST_CHECK(
        degree_five.exact_quotient_degree_accounting);
    BOOST_CHECK(
        !degree_five.backend_lde_cap_met);
    BOOST_CHECK_EQUAL(
        degree_five.quotient_len,
        (uint32_t{1} << 21) - 4);
    BOOST_CHECK_EQUAL(
        degree_five.n_coeffs,
        uint32_t{1} << 21);
    BOOST_CHECK_EQUAL(
        degree_five.n_lde,
        uint32_t{1} << 25);

    const auto unrepresentable =
        va::AssessChunkRlcLeafDomainV1(
            make_relation(
                std::numeric_limits<uint32_t>::max()));
    BOOST_CHECK(!unrepresentable.valid);
    BOOST_CHECK(
        !unrepresentable.exact_quotient_degree_accounting);
    BOOST_CHECK_EQUAL(unrepresentable.n_coeffs, 0U);
    BOOST_CHECK_EQUAL(unrepresentable.n_lde, 0U);
}

BOOST_AUTO_TEST_CASE(
    chunk_rlc_poseidon_inputs_are_literal_columns)
{
    const gf::Fp3 value{
        gf::FromU64(7),
        gf::FromU64(11),
        gf::FromU64(13)};
    const auto leaf =
        va::BuildChunkRlcInterleavedLeafV1(
            value, 3);
    BOOST_REQUIRE_MESSAGE(leaf.valid, leaf.note);
    BOOST_CHECK(
        leaf.proof_value_is_literal_permutation_input);
    BOOST_CHECK(
        !leaf.sibling_is_literal_permutation_input);
    BOOST_CHECK_EQUAL(leaf.value_input_base, 0U);
    BOOST_CHECK(gf::Eq(
        leaf.columns[leaf.value_input_base][0],
        gf::Fp3::FromFp(value.c0)));
    BOOST_CHECK(gf::Eq(
        leaf.columns[leaf.value_input_base + 1][0],
        gf::Fp3::FromFp(value.c1)));
    BOOST_CHECK(gf::Eq(
        leaf.columns[leaf.value_input_base + 2][0],
        gf::Fp3::FromFp(value.c2)));
    BOOST_CHECK_EQUAL(
        va::CountVerifierScalarViolations(
            leaf.constraint_system,
            leaf.columns),
        0U);
    auto leaf_attack = leaf.columns;
    leaf_attack[leaf.value_input_base][0] =
        gf::Add(
            leaf_attack[leaf.value_input_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        va::CountVerifierScalarViolations(
            leaf.constraint_system,
            leaf_attack),
        0U);

    const alg_hash::Digest accumulator{
        gf::FromU64(2), gf::FromU64(3),
        gf::FromU64(5), gf::FromU64(7)};
    const alg_hash::Digest sibling{
        gf::FromU64(11), gf::FromU64(13),
        gf::FromU64(17), gf::FromU64(19)};
    const auto node =
        va::BuildChunkRlcInterleavedNodeV1(
            accumulator, sibling, false);
    BOOST_REQUIRE_MESSAGE(node.valid, node.note);
    BOOST_CHECK(
        node.proof_value_is_literal_permutation_input);
    BOOST_CHECK(
        node.sibling_is_literal_permutation_input);
    BOOST_CHECK_EQUAL(node.value_input_base, 0U);
    BOOST_CHECK_EQUAL(node.sibling_input_base, 4U);
    for (uint32_t limb = 0; limb < 4; ++limb) {
        BOOST_CHECK(gf::Eq(
            node.columns[
                node.sibling_input_base + limb][0],
            gf::Fp3::FromFp(sibling[limb])));
    }
    BOOST_CHECK_EQUAL(
        va::CountVerifierScalarViolations(
            node.constraint_system,
            node.columns),
        0U);
}

BOOST_AUTO_TEST_SUITE_END()
