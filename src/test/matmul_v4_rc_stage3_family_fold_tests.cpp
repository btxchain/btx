// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_family_fold.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace rc = matmul::v4::rc;
namespace ff = rc::stage3_family_fold;
namespace gf = rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_family_fold_tests,
    BasicTestingSetup)

namespace {

uint256 Filled(uint8_t value)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.data()[i] = value;
    }
    return out;
}

ff::AuthenticatedLinearFamilyFoldMetadataV1 Metadata()
{
    ff::AuthenticatedLinearFamilyFoldMetadataV1 out;
    out.family_index = 7;
    out.role_index = 3;
    out.committed_shards = 2;
    out.rows_per_shard = 2;
    out.program_registry_alg_root = Filled(0x31);
    out.family_statement_binding = Filled(0x72);
    return out;
}

std::vector<std::vector<rc::Fp3>> Shards()
{
    return {
        {gf::FromU64_3(3), gf::FromU64_3(5)},
        {gf::FromU64_3(11), gf::FromU64_3(17)},
    };
}

bool SameVector(const std::vector<rc::Fp3>& a,
                const std::vector<rc::Fp3>& b)
{
    if (a.size() != b.size()) return false;
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (!gf::Eq(a[i], b[i])) return false;
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(honest_fold_is_bound_by_ordered_multirow_fri)
{
    const auto proved =
        ff::ProveAuthenticatedLinearFamilyFoldV1(
            Metadata(), Shards());
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    std::string why;
    BOOST_CHECK_MESSAGE(
        ff::VerifyAuthenticatedLinearFamilyFoldV1(
            proved.public_inputs, proved.proof, &why),
        why);

    BOOST_CHECK_EQUAL(proved.proof.batch.groups.size(), 3U);
    BOOST_CHECK_EQUAL(proved.proof.batch.column_len.size(), 4U);
    BOOST_CHECK_EQUAL(
        proved.proof.evaluation_argument.f_column, 2U);
    BOOST_CHECK_EQUAL(
        proved.proof.evaluation_argument.g_column, 3U);
}

BOOST_AUTO_TEST_CASE(source_root_precedes_beta_and_fold_root_precedes_rho)
{
    const auto proved =
        ff::ProveAuthenticatedLinearFamilyFoldV1(
            Metadata(), Shards());
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    std::vector<rc::Fp3> beta_before;
    std::string why;
    BOOST_REQUIRE(
        ff::DeriveAuthenticatedLinearFamilyBetaV1(
            proved.public_inputs, beta_before, &why));

    auto changed_fold_root =
        proved.proof.batch.groups[1].row_commit.root;
    changed_fold_root[0] =
        gf::Add(changed_fold_root[0], gf::FromU64(1));
    std::vector<rc::Fp3> beta_after;
    BOOST_REQUIRE(
        ff::DeriveAuthenticatedLinearFamilyBetaV1(
            proved.public_inputs, beta_after, &why));
    BOOST_CHECK(SameVector(beta_before, beta_after));

    std::vector<rc::Fp3> rho_before;
    std::vector<rc::Fp3> rho_after;
    BOOST_REQUIRE(
        ff::DeriveAuthenticatedLinearFamilyRhoV1(
            proved.public_inputs,
            proved.proof.batch.groups[1].row_commit.root,
            beta_before, rho_before, &why));
    BOOST_REQUIRE(
        ff::DeriveAuthenticatedLinearFamilyRhoV1(
            proved.public_inputs, changed_fold_root,
            beta_before, rho_after, &why));
    BOOST_CHECK(!SameVector(rho_before, rho_after));
}

BOOST_AUTO_TEST_CASE(post_beta_false_fold_is_rejected)
{
    const auto honest =
        ff::ProveAuthenticatedLinearFamilyFoldV1(
            Metadata(), Shards());
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    std::vector<rc::Fp3> beta;
    std::string why;
    BOOST_REQUIRE(
        ff::DeriveAuthenticatedLinearFamilyBetaV1(
            honest.public_inputs, beta, &why));
    std::vector<rc::Fp3> false_fold;
    BOOST_REQUIRE(
        ff::ComputeAuthenticatedLinearFamilyFoldV1(
            Shards(), beta, false_fold, &why));
    for (auto& value : false_fold) {
        value = gf::Add(value, gf::FromU64_3(1));
    }

    const auto forged =
        ff::ProveAuthenticatedLinearFamilyFoldCandidateV1(
            Metadata(), Shards(), false_fold);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!ff::VerifyAuthenticatedLinearFamilyFoldV1(
        forged.public_inputs, forged.proof, &why));
    BOOST_CHECK(why.find("eval:") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(public_statement_and_all_three_roots_are_binding)
{
    const auto proved =
        ff::ProveAuthenticatedLinearFamilyFoldV1(
            Metadata(), Shards());
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    std::string why;

    auto wrong_statement = proved.public_inputs;
    wrong_statement.metadata.family_statement_binding.data()[0] ^= 1;
    BOOST_CHECK(!ff::VerifyAuthenticatedLinearFamilyFoldV1(
        wrong_statement, proved.proof, &why));

    auto wrong_source = proved.public_inputs;
    wrong_source.source_root[0] =
        gf::Add(wrong_source.source_root[0], gf::FromU64(1));
    BOOST_CHECK(!ff::VerifyAuthenticatedLinearFamilyFoldV1(
        wrong_source, proved.proof, &why));

    auto wrong_aux = proved.proof;
    wrong_aux.batch.groups[1].row_commit.root[0] =
        gf::Add(
            wrong_aux.batch.groups[1].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(!ff::VerifyAuthenticatedLinearFamilyFoldV1(
        proved.public_inputs, wrong_aux, &why));

    auto wrong_quotient = proved.proof;
    wrong_quotient.batch.groups[2].row_commit.root[0] =
        gf::Add(
            wrong_quotient.batch.groups[2].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(!ff::VerifyAuthenticatedLinearFamilyFoldV1(
        proved.public_inputs, wrong_quotient, &why));

    auto wrong_value = proved.proof;
    wrong_value.evaluation =
        gf::Add(wrong_value.evaluation, gf::FromU64_3(1));
    BOOST_CHECK(!ff::VerifyAuthenticatedLinearFamilyFoldV1(
        proved.public_inputs, wrong_value, &why));
}

BOOST_AUTO_TEST_CASE(linear_trace_fold_is_not_a_nonlinear_air_proof)
{
    const auto audit =
        ff::BuildNonlinearTraceFoldCounterexampleV1();
    BOOST_CHECK(audit.unequal);
    BOOST_CHECK(gf::Eq(
        audit.fold_then_square, gf::FromU64_3(9)));
    BOOST_CHECK(gf::Eq(
        audit.square_then_fold, gf::FromU64_3(7)));
    BOOST_CHECK(ff::kAuthenticatedLinearFamilyFoldExecutable);
    BOOST_CHECK(!ff::kAuthenticatedLinearFamilyFoldPreservesNonlinearAir);
    BOOST_CHECK(ff::kAuthenticatedFamilyResidualZeroFoldExecutable);
    BOOST_CHECK(!ff::kAuthenticatedFamilyResidualOracleBoundToConstraintVm);
    BOOST_CHECK(!ff::kAuthenticatedFamilyQuotientIdentityExecutable);
    BOOST_CHECK(!ff::kAuthenticatedFamilyBackendProductionSelectable);
}

BOOST_AUTO_TEST_CASE(residual_family_zero_identity_is_executable)
{
    const std::vector<std::vector<rc::Fp3>> zero_residuals{
        {rc::Fp3::Zero(), rc::Fp3::Zero()},
        {rc::Fp3::Zero(), rc::Fp3::Zero()},
    };
    const auto zero =
        ff::ProveAuthenticatedZeroResidualFamilyFoldV1(
            Metadata(), zero_residuals);
    BOOST_REQUIRE_MESSAGE(zero.ok, zero.note);
    std::string why;
    BOOST_CHECK_MESSAGE(
        ff::VerifyAuthenticatedZeroResidualFamilyFoldV1(
            zero.public_inputs, zero.proof, &why),
        why);

    auto nonzero_residuals = zero_residuals;
    // A constant-one row residual makes its rho evaluation exactly one; no
    // deterministic fixture can accidentally hit a Schwartz--Zippel root.
    for (auto& shard : nonzero_residuals) {
        for (auto& value : shard) value = gf::FromU64_3(1);
    }
    const auto nonzero =
        ff::ProveAuthenticatedZeroResidualFamilyFoldV1(
            Metadata(), nonzero_residuals);
    BOOST_REQUIRE_MESSAGE(nonzero.ok, nonzero.note);
    BOOST_CHECK(
        ff::VerifyAuthenticatedLinearFamilyFoldV1(
            nonzero.public_inputs, nonzero.proof, &why));
    BOOST_CHECK(
        !ff::VerifyAuthenticatedZeroResidualFamilyFoldV1(
            nonzero.public_inputs, nonzero.proof, &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:family_linear_fold:residual_evaluation_nonzero");
}

BOOST_AUTO_TEST_CASE(proof_section_codec_is_canonical_and_bounded)
{
    const auto proved =
        ff::ProveAuthenticatedLinearFamilyFoldV1(
            Metadata(), Shards());
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_EQUAL(
        ff::SerializeAuthenticatedLinearFamilyFoldProofV1(
            proved.proof, bytes),
        bytes.size());
    BOOST_CHECK(
        bytes.size() <
        ff::kAuthenticatedLinearFamilyFoldMaxProofBytes);
    const auto decoded =
        ff::DeserializeAuthenticatedLinearFamilyFoldProofV1(bytes);
    BOOST_REQUIRE(decoded.has_value());
    std::string why;
    BOOST_CHECK_MESSAGE(
        ff::VerifyAuthenticatedLinearFamilyFoldV1(
            proved.public_inputs, *decoded, &why),
        why);

    auto noncanonical = bytes;
    // First Fp3 limb starts immediately after magic/version/reserved.
    for (uint32_t i = 8; i < 16; ++i) noncanonical[i] = 0xff;
    BOOST_CHECK(
        !ff::DeserializeAuthenticatedLinearFamilyFoldProofV1(
             noncanonical).has_value());

    auto reserved = bytes;
    reserved[6] = 1;
    BOOST_CHECK(
        !ff::DeserializeAuthenticatedLinearFamilyFoldProofV1(
             reserved).has_value());

    auto truncated = bytes;
    truncated.pop_back();
    BOOST_CHECK(
        !ff::DeserializeAuthenticatedLinearFamilyFoldProofV1(
             truncated).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
