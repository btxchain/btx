// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>

#include <algorithm>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_backend {
namespace {

gf::Fp3 F(uint64_t value)
{
    return {value, value + 1, value + 2};
}

struct Fixture {
    TracePrecommitV1 precommit;
    ProveResultV1 proved;
};

Fixture BuildFixture()
{
    constexpr uint32_t rows = 256;
    std::vector<gf::Fp3> base(rows, gf::Fp3::Zero());
    std::vector<gf::Fp3> dependent(rows, gf::Fp3::Zero());
    for (uint32_t i = 0; i < rows; ++i) {
        base[i] = F(3 * i + 1);
        dependent[i] = F(7 * i + 11);
    }
    Fixture out;
    out.precommit = PrecommitTraceV1(
        {base}, {dependent},
        rows, 2, 32, rows, {0}, uint256::ONE);
    if (!out.precommit.valid) return out;
    // Rq is constructed only after the transcript returned air_lambda.
    std::vector<gf::Fp3> quotient(32, gf::Fp3::Zero());
    quotient[0] = out.precommit.air_constraint_lambda;
    for (uint32_t i = 1; i < quotient.size(); ++i) {
        quotient[i] = F(13 * i + 17);
    }
    out.proved =
        CompleteWithQuotientV1(out.precommit, quotient);
    return out;
}

air_quotient::AirConstraintSystem<gf::Fp3> TransitionAir()
{
    namespace aq = air_quotient;
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 256;
    cs.n_columns = 2;
    cs.constraints.push_back({
        "counter_step", aq::AirKind::kTransition, 1,
        [](const auto& cur, const auto& next) {
            return gf::Sub(
                gf::Sub(next[0], cur[0]), gf::Fp3::One());
        }});
    cs.constraints.push_back({
        "double_counter", aq::AirKind::kEverywhere, 1,
        [](const auto& cur, const auto&) {
            return gf::Sub(
                cur[1],
                gf::Mul(cur[0], gf::Fp3::FromFp(2)));
        }});
    return cs;
}

std::vector<std::vector<gf::Fp3>> TransitionTrace()
{
    std::vector<std::vector<gf::Fp3>> out(
        2, std::vector<gf::Fp3>(256));
    for (uint32_t row = 0; row < 256; ++row) {
        out[0][row] = gf::Fp3::FromFp(row + 9);
        out[1][row] =
            gf::Mul(out[0][row], gf::Fp3::FromFp(2));
    }
    return out;
}

void RequireFixture(const Fixture& fixture)
{
    BOOST_REQUIRE_MESSAGE(
        fixture.precommit.valid, fixture.precommit.note);
    BOOST_REQUIRE(
        fixture.precommit.transcript_derived_before_quotient);
    BOOST_REQUIRE_MESSAGE(fixture.proved.ok, fixture.proved.note);
    BOOST_REQUIRE(fixture.proved.self_verified);
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_multirow_v11_backend_tests)

BOOST_AUTO_TEST_CASE(
    two_phase_roundtrip_q192_with_replacement_and_new_codec)
{
    const auto fixture = BuildFixture();
    RequireFixture(fixture);
    BOOST_CHECK(gf::Eq(
        fixture.precommit.air_constraint_lambda,
        fixture.proved.proof.envelope.split.air_constraint_lambda));
    BOOST_CHECK(fixture.proved.q192_with_replacement);
    BOOST_CHECK_EQUAL(
        fixture.proved.proof.envelope.split.batch.queries.size(),
        p2::kQueriesV1);

    std::set<uint32_t> unique;
    for (const auto& query :
         fixture.proved.proof.envelope.split.batch.queries) {
        unique.insert(query.index);
    }
    // Sampling is expressly with replacement. A duplicate is allowed, not
    // required for every seed; this pins that no deduplication occurred.
    BOOST_CHECK_LE(unique.size(), p2::kQueriesV1);

    std::vector<unsigned char> wire;
    const size_t bytes = SerializeV1(fixture.proved.proof, wire);
    BOOST_REQUIRE_EQUAL(bytes, wire.size());
    BOOST_CHECK_NE(
        uint32_t{wire[0]} |
            (uint32_t{wire[1]} << 8) |
            (uint32_t{wire[2]} << 16) |
            (uint32_t{wire[3]} << 24),
        air_quotient::kAirQuotientSplitRapRowsProofMagic);
    std::string why;
    const auto decoded = DeserializeV1(wire, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    p2::ReceiptV1 receipt;
    BOOST_REQUIRE_MESSAGE(VerifyV1(*decoded, &receipt, &why), why);
    BOOST_CHECK(receipt.valid);
    BOOST_CHECK(receipt.q192_with_replacement);
    BOOST_CHECK_EQUAL(bytes, fixture.proved.proof_bytes);

    const auto readiness = CurrentReadinessV1();
    BOOST_CHECK(readiness.two_phase_air_lambda_executable);
    BOOST_CHECK(readiness.poseidon_transcript_executable);
    BOOST_CHECK(readiness.sequential_fold_challenges_executable);
    BOOST_CHECK(readiness.q192_k2_with_replacement_executable);
    BOOST_CHECK(readiness.current_and_next_openings_executable);
    BOOST_CHECK(readiness.canonical_versioned_codec_executable);
    BOOST_CHECK(readiness.split_rap_air_quotient_dispatch_executable);
    BOOST_CHECK(!readiness.same_parent_transcript_aliases_executable);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    root_current_opening_fold_and_query_tampers_reject)
{
    const auto fixture = BuildFixture();
    RequireFixture(fixture);
    std::string why;

    auto root = fixture.proved.proof;
    root.envelope.split.batch.groups[0].row_commit.root[0] ^=
        1;
    BOOST_CHECK(!VerifyV1(root, nullptr, &why));

    auto opening = fixture.proved.proof;
    opening.envelope.split.batch.queries[0]
        .group_rows[0].values[0].c0 ^= 1;
    BOOST_CHECK(!VerifyV1(opening, nullptr, &why));

    auto fold_root = fixture.proved.proof;
    fold_root.envelope.split.batch.fold_layers[0].root[1] ^= 1;
    BOOST_CHECK(!VerifyV1(fold_root, nullptr, &why));

    auto fold_path = fixture.proved.proof;
    fold_path.envelope.split.batch.queries[0]
        .steps[0].even_siblings[0][2] ^= 1;
    BOOST_CHECK(!VerifyV1(fold_path, nullptr, &why));

    auto query = fixture.proved.proof;
    query.envelope.split.batch.queries[0].index ^=
        1;
    BOOST_CHECK(!VerifyV1(query, nullptr, &why));

    auto next = fixture.proved.proof;
    next.envelope.split.next_trace_group_rows[0][0]
        .siblings[0][3] ^= 1;
    BOOST_CHECK(!VerifyV1(next, nullptr, &why));
}

BOOST_AUTO_TEST_CASE(
    transcript_scalar_and_sequential_fold_order_tampers_reject)
{
    const auto fixture = BuildFixture();
    RequireFixture(fixture);
    std::string why;

    auto lambda = fixture.proved.proof;
    lambda.envelope.split.air_constraint_lambda.c0 ^= 1;
    BOOST_CHECK(!VerifyV1(lambda, nullptr, &why));

    auto coefficient = fixture.proved.proof;
    coefficient.envelope.split.batch.lambda.c1 ^= 1;
    BOOST_CHECK(!VerifyV1(coefficient, nullptr, &why));

    auto ood = fixture.proved.proof;
    ood.envelope.split.batch.z1.c2 ^= 1;
    BOOST_CHECK(!VerifyV1(ood, nullptr, &why));

    auto folds = fixture.proved.proof;
    BOOST_REQUIRE_GE(
        folds.envelope.split.batch.fold_challenges.size(), 2U);
    std::swap(
        folds.envelope.split.batch.fold_challenges[0],
        folds.envelope.split.batch.fold_challenges[1]);
    BOOST_CHECK(!VerifyV1(folds, nullptr, &why));
}

BOOST_AUTO_TEST_CASE(
    codec_rejects_trailing_wrong_domain_and_goldilocks_alias)
{
    const auto fixture = BuildFixture();
    RequireFixture(fixture);
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(SerializeV1(fixture.proved.proof, wire) != 0);

    auto trailing = wire;
    trailing.push_back(0);
    BOOST_CHECK(!DeserializeV1(trailing).has_value());

    auto domain = wire;
    domain[12] ^= 1;
    BOOST_CHECK(!DeserializeV1(domain).has_value());

    auto noncanonical = fixture.proved.proof;
    noncanonical.envelope.split.batch.evals_z1[0].c0 =
        gf::kP;
    std::vector<unsigned char> rejected;
    BOOST_CHECK_EQUAL(SerializeV1(noncanonical, rejected), 0U);
    BOOST_CHECK(rejected.empty());
}

BOOST_AUTO_TEST_CASE(
    quotient_cannot_be_completed_without_valid_precommit)
{
    TracePrecommitV1 invalid;
    std::vector<gf::Fp3> quotient(32, gf::Fp3::Zero());
    const auto proved = CompleteWithQuotientV1(invalid, quotient);
    BOOST_CHECK(!proved.ok);

    constexpr uint32_t rows = 256;
    std::vector<gf::Fp3> column(rows, F(1));
    const auto null_seed = PrecommitTraceV1(
        {column}, {column}, rows, 2, 32, rows, {0}, uint256{});
    BOOST_CHECK(!null_seed.valid);
}

BOOST_AUTO_TEST_CASE(
    nontrivial_transition_air_roundtrip_and_proof_level_rejects)
{
    const auto cs = TransitionAir();
    const auto trace = TransitionTrace();
    const auto proved =
        ProveAirQuotientV1(cs, trace, {0}, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK(proved.division_exact);
    BOOST_CHECK(proved.quotient_built_after_v11_lambda);
    BOOST_REQUIRE(proved.proximity.ok);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyAirQuotientV1(
            cs, proved.proximity.proof, {0}, uint256::ONE, &why),
        why);

    auto wrong_relation = cs;
    wrong_relation.constraints[0].eval =
        [](const auto& cur, const auto& next) {
            return gf::Sub(next[0], cur[0]);
        };
    BOOST_CHECK(!VerifyAirQuotientV1(
        wrong_relation, proved.proximity.proof, {0}, uint256::ONE, &why));

    auto next = proved.proximity.proof;
    next.envelope.split.next_trace_group_rows[0][0]
        .values[0].c0 ^= 1;
    BOOST_CHECK(!VerifyAirQuotientV1(
        cs, next, {0}, uint256::ONE, &why));

    auto quotient = proved.proximity.proof;
    quotient.envelope.split.batch.queries[0]
        .group_rows[2].values[0].c1 ^= 1;
    BOOST_CHECK(!VerifyAirQuotientV1(
        cs, quotient, {0}, uint256::ONE, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_backend
