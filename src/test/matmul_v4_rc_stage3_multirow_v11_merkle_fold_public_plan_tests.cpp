// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <hash.h>

#include <boost/test/unit_test.hpp>

namespace rc =
    matmul::v4::rc;
namespace uv =
    rc::stage3_multirow_v11_unified_verifier_air;
namespace proof_abi =
    rc::stage3_multirow_v11_proof_abi;
namespace aq = rc::air_quotient;
namespace backend =
    rc::stage3_multirow_v11_backend;
namespace gf = rc::gkr_field;
namespace mf =
    rc::stage3_multirow_v11_merkle_fold;
namespace rv =
    rc::stage3_multirow_v11_recursive_verifier;
namespace tp =
    rc::stage3_multirow_p2_transcript;

namespace {

using gf::Fp3;

uint256 Seed(uint32_t tag)
{
    HashWriter hash;
    hash <<
        "BTX/RC/STAGE3/MERKLE-FOLD/PUBLIC-PLAN/TEST";
    hash << tag;
    return hash.GetHash();
}

aq::AirConstraintSystem<Fp3> ChildAir()
{
    aq::AirConstraintSystem<Fp3> out;
    out.n_rows = 1024;
    out.n_columns = 2;
    out.constraints.push_back({
        "step", aq::AirKind::kTransition, 1,
        [](const auto& current,
           const auto& next) {
            return gf::Sub(
                gf::Sub(next[0], current[0]),
                Fp3::One());
        }});
    out.constraints.push_back({
        "twice", aq::AirKind::kEverywhere, 1,
        [](const auto& current,
           const auto&) {
            return gf::Sub(
                current[1],
                gf::Mul(
                    current[0],
                    gf::FromU64_3(2)));
        }});
    return out;
}

std::vector<std::vector<Fp3>>
ChildTrace(uint32_t offset)
{
    std::vector<std::vector<Fp3>> out(
        2,
        std::vector<Fp3>(1024));
    for (uint32_t row = 0;
         row < 1024; ++row) {
        out[0][row] =
            gf::FromU64_3(offset + row);
        out[1][row] =
            gf::Mul(
                out[0][row],
                gf::FromU64_3(2));
    }
    return out;
}

struct ChildShardV1 {
    proof_abi::DecodedV1 decoded{};
    mf::ShardProductV1 shard{};
};

ChildShardV1 BuildShard(
    uint32_t offset,
    uint32_t seed_tag)
{
    const auto proved =
        backend::ProveAirQuotientV1(
            ChildAir(),
            ChildTrace(offset),
            {0},
            Seed(seed_tag));
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    tp::ReceiptV1 receipt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(
            proved.proximity.proof,
            &receipt,
            &why),
        why);
    std::vector<uint32_t> words;
    BOOST_REQUIRE_MESSAGE(
        proof_abi::EncodeCanonicalV1(
            proved.proximity.proof.envelope,
            words, nullptr, &why),
        why);
    const auto decoded =
        proof_abi::DecodeCanonicalV1(
            words, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    ChildShardV1 out;
    out.decoded = *decoded;
    out.shard =
        mf::BuildShardV1(
            out.decoded,
            receipt,
            0, 1);
    BOOST_REQUIRE_MESSAGE(
        out.shard.valid,
        out.shard.note);
    return out;
}

bool SameFp3(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t i = 0;
         i < left.size(); ++i) {
        if (!gf::Eq(left[i], right[i])) {
            return false;
        }
    }
    return true;
}

bool SameConstraintShape(
    const aq::AirConstraintSystem<Fp3>& left,
    const aq::AirConstraintSystem<Fp3>& right)
{
    if (left.n_rows != right.n_rows ||
        left.n_columns != right.n_columns ||
        left.constraints.size() !=
            right.constraints.size() ||
        left.preprocessed.size() !=
            right.preprocessed.size()) {
        return false;
    }
    for (uint32_t ordinal = 0;
         ordinal <
             left.constraints.size();
         ++ordinal) {
        if (left.constraints[ordinal].kind !=
                right.constraints[ordinal].kind ||
            left.constraints[ordinal].alg_degree !=
                right.constraints[ordinal].alg_degree) {
            return false;
        }
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_merkle_fold_public_plan_tests)

BOOST_AUTO_TEST_CASE(
    distinct_child_proofs_share_one_public_plan_and_reject_substitution)
{
    const ChildShardV1 first =
        BuildShard(11, 1);
    const ChildShardV1 second =
        BuildShard(73, 2);
    BOOST_CHECK(
        first.decoded.envelope.split.batch
                .groups[0].row_commit.root !=
        second.decoded.envelope.split.batch
                .groups[0].row_commit.root);

    const auto shape_a =
        uv::BuildMerkleFoldPublicShapeV1(
            first.decoded);
    const auto shape_b =
        uv::BuildMerkleFoldPublicShapeV1(
            second.decoded);
    BOOST_REQUIRE_MESSAGE(
        shape_a.valid, shape_a.note);
    BOOST_REQUIRE_MESSAGE(
        shape_b.valid, shape_b.note);
    BOOST_CHECK(
        shape_a.proof_values_excluded);
    BOOST_CHECK(shape_a == shape_b);

    const rv::QueryRangeV1 range{
        0, 0, 1};
    const auto plan_a =
        uv::BuildMerkleFoldPublicPlanV1(
            shape_a, range);
    const auto plan_b =
        uv::BuildMerkleFoldPublicPlanV1(
            shape_b, range);
    BOOST_REQUIRE_MESSAGE(
        plan_a.valid, plan_a.note);
    BOOST_REQUIRE_MESSAGE(
        plan_b.valid, plan_b.note);
    BOOST_CHECK(plan_a.proof_independent);
    BOOST_CHECK_EQUAL(
        plan_a.hash_real_rows,
        first.shard.hash_real_rows);
    BOOST_CHECK_EQUAL(
        plan_a.hash_trace_rows,
        first.shard.hash_trace_rows);
    BOOST_CHECK_EQUAL(
        plan_a.fold_real_rows,
        first.shard.fold_real_rows);
    BOOST_CHECK_EQUAL(
        plan_a.fold_trace_rows,
        first.shard.fold_trace_rows);
    BOOST_CHECK(
        plan_a.hash_program ==
        plan_b.hash_program);
    BOOST_CHECK(
        plan_a.fold_program ==
        plan_b.fold_program);
    BOOST_CHECK(
        plan_a.hash_program_root ==
        plan_b.hash_program_root);
    BOOST_CHECK(
        plan_a.fold_program_root ==
        plan_b.fold_program_root);
    BOOST_CHECK(
        SameConstraintShape(
            plan_a.hash_cs,
            plan_b.hash_cs));
    BOOST_CHECK(
        SameConstraintShape(
            plan_a.fold_cs,
            plan_b.fold_cs));
    BOOST_CHECK(
        plan_a.hash_cs.preprocessed.empty());
    BOOST_CHECK(
        plan_a.fold_cs.preprocessed.empty());

    const auto first_phase =
        uv::MaterializeMerkleFoldCanonicalPhasesV1(
            plan_a,
            first.decoded,
            first.shard);
    const auto second_phase =
        uv::MaterializeMerkleFoldCanonicalPhasesV1(
            plan_a,
            second.decoded,
            second.shard);
    BOOST_REQUIRE_MESSAGE(
        first_phase.valid,
        first_phase.note);
    BOOST_REQUIRE_MESSAGE(
        second_phase.valid,
        second_phase.note);
    BOOST_CHECK(
        first_phase.proof_tape_ordinary);
    BOOST_CHECK(
        second_phase.proof_tape_ordinary);
    bool hash_witness_differs = false;
    for (uint32_t column = 0;
         column <
             first_phase.hash_columns.size() &&
         !hash_witness_differs;
         ++column) {
        hash_witness_differs =
            !SameFp3(
                first_phase.hash_columns[column],
                second_phase.hash_columns[column]);
    }
    BOOST_CHECK(hash_witness_differs);

    auto row_substitution = plan_a;
    ++row_substitution.hash_real_rows;
    BOOST_CHECK(
        !uv::MaterializeMerkleFoldCanonicalPhasesV1(
             row_substitution,
             first.decoded,
             first.shard).valid);

    auto root_substitution = plan_a;
    root_substitution.hash_program_root[0] =
        gf::Add(
            root_substitution.hash_program_root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !uv::MaterializeMerkleFoldCanonicalPhasesV1(
             root_substitution,
             first.decoded,
             first.shard).valid);

    auto cs_substitution = plan_a;
    ++cs_substitution.fold_cs.n_rows;
    BOOST_CHECK(
        !uv::MaterializeMerkleFoldCanonicalPhasesV1(
             cs_substitution,
             first.decoded,
             first.shard).valid);

    auto shape_substitution = plan_a;
    ++shape_substitution.shape.group_columns[0];
    BOOST_CHECK(
        !uv::MaterializeMerkleFoldCanonicalPhasesV1(
             shape_substitution,
             first.decoded,
             first.shard).valid);

    auto proof_shape_substitution =
        first.shard;
    ++proof_shape_substitution.hash_real_rows;
    BOOST_CHECK(
        !uv::MaterializeMerkleFoldCanonicalPhasesV1(
             plan_a,
             first.decoded,
             proof_shape_substitution).valid);
}

BOOST_AUTO_TEST_SUITE_END()
