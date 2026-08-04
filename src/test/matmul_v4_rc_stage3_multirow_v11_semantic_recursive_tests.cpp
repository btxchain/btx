// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_semantic_recursive.h>

#include <chrono>
#include <cstdlib>

namespace {

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;
namespace recursive =
    matmul::v4::rc::multirow_v11_semantic_recursive;

uint256 P2Root(uint32_t tag)
{
    std::vector<gf::Fp> lanes;
    for (uint32_t i = 0; i < 16; ++i) {
        lanes.push_back(
            gf::FromU64(
                0x10000U * tag + i));
    }
    return matmul::v4::rc::Fri3AlgDigestToUint256(
        rc::alg_hash::SpongeHashFp(lanes));
}

std::vector<rc::RCStage3RoleAirProduct> Roles()
{
    using Role = rc::RCStage3RelationRole;
    std::vector<rc::RCStage3RoleAirProduct> out;
    out.push_back(
        rc::BuildRCStage3NoKernelRoleAir(
            Role::EpisodeDeterministicBuilder));
    out.push_back(rc::BuildRCStage3EpisodeGemmRoleAir());
    out.push_back(
        rc::BuildRCStage3NoKernelRoleAir(
            Role::EpisodeExtract));
    out.push_back(
        rc::BuildRCStage3EpisodeWiringRoleAir());
    out.push_back(
        rc::BuildRCStage3PureStreamRoleAir(
            Role::EpisodeTileTree));
    out.push_back(
        rc::BuildRCStage3PureStreamRoleAir(
            Role::EpisodeDigest));
    out.push_back(
        rc::BuildRCStage3CoupledMixedRoleAir(
            Role::CoupledBank));
    out.push_back(rc::BuildRCStage3CoupledGemmRoleAir());
    out.push_back(
        rc::BuildRCStage3CoupledMixedRoleAir(
            Role::CoupledExchange));
    out.push_back(
        rc::BuildRCStage3CoupledScalarRoleAir(
            Role::CoupledPermutation, 0, 7));
    out.push_back(
        rc::BuildRCStage3CoupledScalarRoleAir(
            Role::CoupledMix, 0, 7));
    out.push_back(
        rc::BuildRCStage3NoKernelRoleAir(
            Role::CoupledExtract));
    out.push_back(
        rc::BuildRCStage3PureStreamRoleAir(
            Role::CoupledBarrier));
    out.push_back(
        rc::BuildRCStage3PureStreamRoleAir(
            Role::CoupledDigest));
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_semantic_recursive_tests)

BOOST_AUTO_TEST_CASE(
    exact_31_plus_21_parent_is_bounded_and_satisfied)
{
    const auto roles = Roles();
    const uint256 statement = P2Root(1);
    const uint256 program = P2Root(2);
    const uint256 transcript = P2Root(3);
    const auto product =
        recursive::BuildProductV1(
            roles, statement, program, transcript);
    BOOST_REQUIRE_MESSAGE(
        product.valid_foundation, product.note);
    BOOST_CHECK_EQUAL(product.blocks.size(), 52U);
    BOOST_CHECK_EQUAL(product.literal_pairs.size(), 52U);
    BOOST_CHECK_EQUAL(product.existing_outputs, 31U);
    BOOST_CHECK_EQUAL(product.heavy_outputs, 21U);
    BOOST_CHECK_EQUAL(product.trace_rows, 512U);
    BOOST_CHECK_LT(product.trace_columns, 2048U);
    BOOST_CHECK_EQUAL(product.max_degree, 2U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.common_roots_constrained);
    BOOST_CHECK(
        product.producer_consumer_equality_constrained);
    BOOST_CHECK(product.canonical_u32_constrained);
    BOOST_CHECK(product.ordered_poseidon_root_constrained);
    BOOST_CHECK(product.exact_r0_root_pinned);
    BOOST_CHECK(
        !product.child_verifier_cells_connected);
    BOOST_CHECK(!product.recursive_authority);
    std::string why;
    BOOST_CHECK_MESSAGE(
        recursive::ValidateProductV1(
            product, roles, statement,
            program, transcript, &why),
        why);
    BOOST_TEST_MESSAGE(
        "semantic recursive parent rows="
        << product.trace_rows
        << " columns=" << product.trace_columns
        << " constraints=" << product.constraints
        << " degree=" << product.max_degree
        << " hash_rows=" << product.hash_rows);
}

BOOST_AUTO_TEST_CASE(
    omission_duplicate_reorder_role_and_ordinal_reject)
{
    auto roles = Roles();
    const uint256 statement = P2Root(4);
    const uint256 program = P2Root(5);
    const uint256 transcript = P2Root(6);
    std::string why;
    auto omitted = roles;
    omitted.pop_back();
    BOOST_CHECK(
        recursive::BuildReceiptOutputBlocksV1(
            omitted, statement, program,
            transcript, &why).empty());

    auto duplicate = roles;
    duplicate[1] = duplicate[0];
    BOOST_CHECK(
        recursive::BuildReceiptOutputBlocksV1(
            duplicate, statement, program,
            transcript, &why).empty());

    auto reorder = roles;
    std::swap(reorder[0], reorder[1]);
    BOOST_CHECK(
        recursive::BuildReceiptOutputBlocksV1(
            reorder, statement, program,
            transcript, &why).empty());

    const auto canonical =
        recursive::BuildProductV1(
            roles, statement, program, transcript);
    BOOST_REQUIRE(canonical.valid_foundation);
    auto role = canonical.columns;
    const uint32_t first_row = 2;
    role[canonical.layout.role][first_row] =
        gf::Add(
            role[canonical.layout.role][first_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        recursive::RecountViolationsV1(
            canonical, role),
        0U);

    auto ordinal = canonical.columns;
    ordinal[canonical.layout.ordinal][first_row] =
        gf::Add(
            ordinal[canonical.layout.ordinal][first_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        recursive::RecountViolationsV1(
            canonical, ordinal),
        0U);
}

BOOST_AUTO_TEST_CASE(
    root_and_simultaneous_pair_mutations_reject_r0_and_air)
{
    const auto roles = Roles();
    const uint256 statement = P2Root(7);
    const uint256 program = P2Root(8);
    const uint256 transcript = P2Root(9);
    const auto product =
        recursive::BuildProductV1(
            roles, statement, program, transcript);
    BOOST_REQUIRE(product.valid_foundation);
    const uint32_t first_row = 2;

    auto root = product.columns;
    root[product.layout.statement_base][first_row] =
        gf::Add(
            root[product.layout.statement_base][first_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        recursive::RecountViolationsV1(
            product, root),
        0U);

    auto simultaneous = product.columns;
    simultaneous[
        product.layout.producer_base][first_row] =
        gf::Add(
            simultaneous[
                product.layout.producer_base][first_row],
            gf::Fp3::One());
    simultaneous[
        product.layout.consumer_base][first_row] =
        simultaneous[
            product.layout.producer_base][first_row];
    // Equality alone survives, but the bit decomposition and immutable R0
    // expected row both reject the two-sided mutation.
    BOOST_CHECK_GT(
        recursive::RecountViolationsV1(
            product, simultaneous),
        0U);
}

BOOST_AUTO_TEST_CASE(
    raw_and_persisted_x_plus_p_are_rejected)
{
    auto roles = Roles();
    const uint256 statement = P2Root(10);
    const uint256 program = P2Root(11);
    const uint256 transcript = P2Root(12);
    // Raw role-root alias: x and x+p are the same field element but the
    // canonical role-product adapter rejects the representation.
    roles[0].endpoint_committed_roots[0][0] += gf::kP;
    std::string why;
    BOOST_CHECK(
        recursive::BuildReceiptOutputBlocksV1(
            roles, statement, program,
            transcript, &why).empty());

    auto noncanonical_program = program;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        noncanonical_program.data()[byte] =
            static_cast<unsigned char>(
                (gf::kP >> (8U * byte)) & 0xffU);
    }
    BOOST_CHECK(
        recursive::BuildReceiptOutputBlocksV1(
            Roles(), statement,
            noncanonical_program,
            transcript, &why).empty());
}

BOOST_AUTO_TEST_CASE(
    optional_parent_split_rap_proof_and_proof_level_rejects)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_V11_SEMANTIC_RECURSIVE_PROOF") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V11_SEMANTIC_RECURSIVE_PROOF=1 "
            "for parent Split-RAP proof measurement");
        return;
    }
    const auto roles = Roles();
    const auto product =
        recursive::BuildProductV1(
            roles, P2Root(13),
            P2Root(14), P2Root(15));
    BOOST_REQUIRE(product.valid_foundation);
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            product.parent_fs_seed);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    const auto verify_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proved.proof,
            product.preprocessed_columns,
            product.parent_fs_seed, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();
    std::vector<unsigned char> bytes;
    const size_t written =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, bytes);
    BOOST_REQUIRE_EQUAL(written, bytes.size());
    BOOST_CHECK_LE(
        written, rc::kRCStage3MaxProofBytes);
    BOOST_TEST_MESSAGE(
        "semantic recursive proof bytes="
        << written
        << " prove_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(
               prove_end - prove_start).count()
        << " verify_ms="
        << std::chrono::duration_cast<
               std::chrono::milliseconds>(
               verify_end - verify_start).count());

    auto root = proved.proof;
    BOOST_REQUIRE(!root.batch.groups.empty());
    root.batch.groups[0].row_commit.root[0] =
        gf::Add(
            root.batch.groups[0].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            product.cs, root,
            product.preprocessed_columns,
            product.parent_fs_seed, &why));

    const auto forged_rejects =
        [&product, &why](const auto& columns) {
            const auto forged =
                aq::AirQuotientProveRowsSplitRap(
                    product.cs, columns,
                    product.preprocessed_columns,
                    product.parent_fs_seed);
            return
                !forged.ok ||
                !forged.division_exact ||
                !aq::AirQuotientVerifyRowsSplitRap(
                    product.cs, forged.proof,
                    product.preprocessed_columns,
                    product.parent_fs_seed, &why);
        };
    const uint32_t first_row = 2;
    auto forged_role = product.columns;
    forged_role[
        product.layout.role][first_row] =
        gf::Add(
            forged_role[
                product.layout.role][first_row],
            gf::Fp3::One());
    BOOST_CHECK(forged_rejects(forged_role));

    auto forged_ordinal = product.columns;
    forged_ordinal[
        product.layout.ordinal][first_row] =
        gf::Add(
            forged_ordinal[
                product.layout.ordinal][first_row],
            gf::Fp3::One());
    BOOST_CHECK(forged_rejects(forged_ordinal));

    auto forged_columns = product.columns;
    forged_columns[
        product.layout.producer_base][first_row] =
        gf::Add(
            forged_columns[
                product.layout.producer_base][first_row],
            gf::Fp3::One());
    forged_columns[
        product.layout.consumer_base][first_row] =
        forged_columns[
            product.layout.producer_base][first_row];
    BOOST_CHECK(forged_rejects(forged_columns));
}

BOOST_AUTO_TEST_SUITE_END()
