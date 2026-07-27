// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace ar = matmul::v4::rc::air_recurse;
namespace gf = matmul::v4::rc::gkr_field;
namespace col = matmul::v4::rc::coupled_air_col;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_coupled_air_tests, BasicTestingSetup)

namespace {

using Fp3 = gf::Fp3;
using Columns = std::vector<std::vector<Fp3>>;

constexpr std::array<rc::RCStage3RelationRole, 8> ROLES{
    rc::RCStage3RelationRole::CoupledBank,
    rc::RCStage3RelationRole::CoupledGemm,
    rc::RCStage3RelationRole::CoupledExchange,
    rc::RCStage3RelationRole::CoupledPermutation,
    rc::RCStage3RelationRole::CoupledMix,
    rc::RCStage3RelationRole::CoupledExtract,
    rc::RCStage3RelationRole::CoupledBarrier,
    rc::RCStage3RelationRole::CoupledDigest,
};

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

rc::RCStage3CoupledShape Shape()
{
    return rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(), rc::MakeMediumV4RCCoupOptions());
}

Columns EmptyColumns(const rc::air_quotient::AirConstraintSystem<Fp3>& cs)
{
    return Columns(cs.n_columns, std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
}

uint32_t Violations(const rc::RCStage3CoupledAirEntry& entry,
                    const Columns& columns)
{
    return ar::CountWitnessViolationsOnH(entry.constraints, columns);
}

bool HasGap(const rc::RCStage3CoupledAirEntry& entry,
            rc::RCStage3CoupledAirGapCode code)
{
    return std::any_of(entry.gaps.begin(), entry.gaps.end(),
                       [code](const auto& gap) { return gap.code == code; });
}

void SetLimbBits(Columns& columns, uint32_t row, uint32_t limb,
                 uint16_t value)
{
    columns[limb][row] = U(value);
    for (uint32_t bit = 0; bit < 16; ++bit) {
        columns[col::MIX_BITS + limb * 16U + bit][row] =
            U((value >> bit) & 1U);
    }
}

void SetMixRow(Columns& columns, uint32_t row, uint64_t a, uint64_t b)
{
    const uint64_t sum = a + b;
    const uint64_t diff = b - a;
    for (uint32_t limb = 0; limb < 4; ++limb) {
        SetLimbBits(columns, row, col::MIX_A_LIMB + limb,
                    static_cast<uint16_t>(a >> (16U * limb)));
        SetLimbBits(columns, row, col::MIX_B_LIMB + limb,
                    static_cast<uint16_t>(b >> (16U * limb)));
        SetLimbBits(columns, row, col::MIX_SUM_LIMB + limb,
                    static_cast<uint16_t>(sum >> (16U * limb)));
        SetLimbBits(columns, row, col::MIX_DIFF_LIMB + limb,
                    static_cast<uint16_t>(diff >> (16U * limb)));
    }

    uint32_t carry = 0;
    uint32_t borrow = 0;
    for (uint32_t limb = 0; limb < 4; ++limb) {
        const uint32_t av = static_cast<uint16_t>(a >> (16U * limb));
        const uint32_t bv = static_cast<uint16_t>(b >> (16U * limb));
        const uint32_t total = av + bv + carry;
        carry = total >> 16;
        columns[col::MIX_CARRY + limb][row] = U(carry);

        const uint32_t subtrahend = av + borrow;
        borrow = bv < subtrahend ? 1U : 0U;
        columns[col::MIX_BORROW + limb][row] = U(borrow);
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(registry_has_exact_roles_coverage_and_residuals)
{
    const auto shape = Shape();
    const Fp3 gamma{3, 5, 7};
    const Fp3 alpha{11, 13, 17};
    const auto entries =
        rc::AssessRCStage3CoupledAirRegistry(shape, gamma, alpha, 2);
    BOOST_REQUIRE_EQUAL(entries.size(), ROLES.size());

    for (size_t i = 0; i < entries.size(); ++i) {
        BOOST_CHECK(entries[i].role == ROLES[i]);
        const auto expected =
            rc::ExpectedRCStage3CoupledRelationCounts(ROLES[i], shape);
        BOOST_REQUIRE(expected.has_value());
        BOOST_CHECK(entries[i].coverage.required == *expected);
        BOOST_CHECK(!entries[i].proof_only_complete);
        BOOST_CHECK(!entries[i].gaps.empty());
        BOOST_CHECK(HasGap(entries[i],
                           rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
        if (i < 6) {
            BOOST_CHECK(entries[i].constraint_system_available);
            BOOST_CHECK(entries[i].coverage.kernel == *expected);
            BOOST_CHECK(entries[i].constraints.n_columns > 0);
            BOOST_CHECK(!entries[i].constraints.constraints.empty());
        } else {
            BOOST_CHECK(!entries[i].constraint_system_available);
            BOOST_CHECK_EQUAL(entries[i].coverage.kernel.primary, 0U);
            BOOST_CHECK_EQUAL(entries[i].coverage.kernel.secondary, 0U);
        }
    }

    // Measured BankSeedXof / BankPageInclusion prototypes retire those two
    // CoupledBank-local AirGap codes; exchange/perm/mix schedule prototypes
    // retire PublicScheduleBinding (+ MaterialExchangeHashXof). Universal
    // bridge/aggregation remain.
    BOOST_CHECK(rc::kRCStage3CoupledBankSeedXofPrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledBankPageInclusionPrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledExchangeSchedulePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledPermutationSchedulePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledMixSchedulePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledMaterialExchangeHashXofPrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledExtractChaChaScalePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledExtractInt64RangePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledBarrierSha256dPrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledDigestSha256dPrototypeExecuted);
    BOOST_CHECK(!HasGap(entries[0], rc::RCStage3CoupledAirGapCode::BankSeedXof));
    BOOST_CHECK(!HasGap(entries[0], rc::RCStage3CoupledAirGapCode::BankPageInclusion));
    BOOST_CHECK(HasGap(entries[0],
                       rc::RCStage3CoupledAirGapCode::CommitmentOpeningBridge));
    BOOST_CHECK(!HasGap(entries[2],
                        rc::RCStage3CoupledAirGapCode::PublicScheduleBinding));
    BOOST_CHECK(!HasGap(entries[2],
                        rc::RCStage3CoupledAirGapCode::MaterialExchangeHashXof));
    BOOST_CHECK(!HasGap(entries[3],
                        rc::RCStage3CoupledAirGapCode::PublicScheduleBinding));
    BOOST_CHECK(!HasGap(entries[4],
                        rc::RCStage3CoupledAirGapCode::PublicScheduleBinding));
    BOOST_CHECK(!HasGap(entries[5],
                        rc::RCStage3CoupledAirGapCode::ExtractChaChaAndScaleSha));
    BOOST_CHECK(!HasGap(entries[5],
                        rc::RCStage3CoupledAirGapCode::ExtractInt64AndRangeLookups));
    BOOST_CHECK(!HasGap(entries[6], rc::RCStage3CoupledAirGapCode::BarrierSha256d));
    BOOST_CHECK(!HasGap(entries[7], rc::RCStage3CoupledAirGapCode::DigestSha256d));
    BOOST_CHECK(HasGap(entries[2],
                       rc::RCStage3CoupledAirGapCode::CommitmentOpeningBridge));
    BOOST_CHECK(HasGap(entries[3],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[4],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[5],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[6],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[7],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));

    std::string why;
    BOOST_CHECK(!rc::RCStage3CoupledAirRegistryReady(shape, gamma, alpha, &why));
    BOOST_CHECK(why.find("residual_gaps") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(registry_rejects_bad_role_shape_and_extract_scale)
{
    rc::RCStage3CoupledAirEntry entry;
    std::string why;
    auto request = rc::RCStage3CoupledAirRequest{
        rc::RCStage3RelationRole::EpisodeGemm, Shape(), Fp3::One(), Fp3::One(), 0};
    BOOST_CHECK(!rc::ResolveRCStage3CoupledAir(request, entry, &why));

    request.role = rc::RCStage3RelationRole::CoupledExtract;
    request.extract_scale_e = 4;
    BOOST_CHECK(!rc::ResolveRCStage3CoupledAir(request, entry, &why));

    request.extract_scale_e = 0;
    request.shape.full_bank_schedule = false;
    BOOST_CHECK(!rc::ResolveRCStage3CoupledAir(request, entry, &why));
}

BOOST_AUTO_TEST_CASE(bank_kernel_rejects_dequant_and_table_mutations)
{
    rc::RCStage3CoupledAirEntry entry;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledAir(
        {rc::RCStage3RelationRole::CoupledBank, Shape(), Fp3::One(), Fp3::One(), 0},
        entry));
    Columns columns = EmptyColumns(entry.constraints);
    const rc::gkr_air::TableTM tm;
    constexpr uint32_t nibble = 11;
    constexpr uint32_t scale_e = 2;
    for (uint32_t row = 0; row < entry.constraints.n_rows; ++row) {
        columns[col::BANK_NIB][row] = U(nibble);
        for (uint32_t bit = 0; bit < 4; ++bit) {
            columns[col::BANK_NB0 + bit][row] = U((nibble >> bit) & 1U);
        }
        columns[col::BANK_ACC][row] = U(tm.acc[nibble]);
        columns[col::BANK_MU][row] = gf::FromSigned3(tm.mu[nibble]);
        columns[col::BANK_E0][row] = U(scale_e & 1U);
        columns[col::BANK_E1][row] = U((scale_e >> 1U) & 1U);
        columns[col::BANK_OUT][row] =
            gf::FromSigned3(static_cast<int64_t>(tm.mu[nibble]) * 4);
    }
    BOOST_CHECK_EQUAL(Violations(entry, columns), 0U);

    Columns bad_out = columns;
    bad_out[col::BANK_OUT][0] = gf::Add(bad_out[col::BANK_OUT][0], Fp3::One());
    BOOST_CHECK(Violations(entry, bad_out) > 0);

    Columns bad_mu = columns;
    bad_mu[col::BANK_MU][1] = gf::Add(bad_mu[col::BANK_MU][1], Fp3::One());
    BOOST_CHECK(Violations(entry, bad_mu) > 0);
}

BOOST_AUTO_TEST_CASE(gemm_kernel_rejects_operand_and_accumulator_mutations)
{
    rc::RCStage3CoupledAirEntry entry;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledAir(
        {rc::RCStage3RelationRole::CoupledGemm, Shape(), Fp3::One(), Fp3::One(), 0},
        entry));
    Columns columns = EmptyColumns(entry.constraints);
    Fp3 acc = Fp3::Zero();
    for (uint32_t row = 0; row < entry.constraints.n_rows; ++row) {
        const Fp3 a = gf::FromSigned3(static_cast<int64_t>(row % 5) - 2);
        const Fp3 b = gf::FromSigned3(static_cast<int64_t>(row % 7) - 3);
        columns[col::GEMM_A][row] = a;
        columns[col::GEMM_B][row] = b;
        columns[col::GEMM_ACTIVE][row] = Fp3::One();
        acc = gf::Add(acc, gf::Mul(a, b));
        columns[col::GEMM_ACC][row] = acc;
    }
    for (uint32_t row = 0; row < entry.constraints.n_rows; ++row) {
        columns[col::GEMM_OUT][row] = acc;
    }
    BOOST_CHECK_EQUAL(Violations(entry, columns), 0U);

    Columns bad_operand = columns;
    bad_operand[col::GEMM_A][7] =
        gf::Add(bad_operand[col::GEMM_A][7], Fp3::One());
    BOOST_CHECK(Violations(entry, bad_operand) > 0);

    Columns bad_acc = columns;
    bad_acc[col::GEMM_ACC][11] =
        gf::Add(bad_acc[col::GEMM_ACC][11], Fp3::One());
    BOOST_CHECK(Violations(entry, bad_acc) > 0);
}

BOOST_AUTO_TEST_CASE(copy_kernels_reject_mapped_value_mutations)
{
    for (const auto role : {rc::RCStage3RelationRole::CoupledExchange,
                            rc::RCStage3RelationRole::CoupledPermutation}) {
        rc::RCStage3CoupledAirEntry entry;
        BOOST_REQUIRE(rc::ResolveRCStage3CoupledAir(
            {role, Shape(), Fp3::One(), Fp3::One(), 0}, entry));
        Columns columns = EmptyColumns(entry.constraints);
        for (uint32_t row = 0; row < entry.constraints.n_rows; ++row) {
            columns[col::COPY_INPUT][row] = U(90 + row);
            columns[col::COPY_OUTPUT][row] = U(90 + row);
        }
        BOOST_CHECK_EQUAL(Violations(entry, columns), 0U);
        columns[col::COPY_OUTPUT][1] =
            gf::Add(columns[col::COPY_OUTPUT][1], Fp3::One());
        BOOST_CHECK(Violations(entry, columns) > 0);
    }
}

BOOST_AUTO_TEST_CASE(mix_kernel_enforces_uint64_wrap_not_field_wrap)
{
    rc::RCStage3CoupledAirEntry entry;
    BOOST_REQUIRE(rc::ResolveRCStage3CoupledAir(
        {rc::RCStage3RelationRole::CoupledMix, Shape(), Fp3::One(), Fp3::One(), 0},
        entry));
    Columns columns = EmptyColumns(entry.constraints);
    SetMixRow(columns, 0, UINT64_C(0xfffffffffffffff9), UINT64_C(0x17));
    SetMixRow(columns, 1, UINT64_C(0x8000000000000001), UINT64_C(0x7ffffffffffffff0));
    BOOST_CHECK_EQUAL(Violations(entry, columns), 0U);

    Columns bad_sum = columns;
    bad_sum[col::MIX_SUM_LIMB + 2][0] =
        gf::Add(bad_sum[col::MIX_SUM_LIMB + 2][0], Fp3::One());
    BOOST_CHECK(Violations(entry, bad_sum) > 0);

    Columns bad_carry = columns;
    bad_carry[col::MIX_CARRY][1] = U(2);
    BOOST_CHECK(Violations(entry, bad_carry) > 0);
}

BOOST_AUTO_TEST_CASE(extract_barrier_digest_local_gaps_cleared_after_engines_ready)
{
    // Role-local Extract/Barrier/Digest AirGaps retire via measured prototypes
    // + engines Ready; universal bridge/aggregation remain. Barrier/Digest still
    // lack immutable AirConstraintSystem resolvers.
    BOOST_CHECK(rc::kRCStage3CoupledRelationEnginesReady);
    const auto entries =
        rc::AssessRCStage3CoupledAirRegistry(Shape(), Fp3{3, 5, 7}, Fp3{11, 13, 17});
    BOOST_REQUIRE_EQUAL(entries.size(), 8U);
    BOOST_CHECK(rc::kRCStage3CoupledExtractChaChaScalePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledExtractInt64RangePrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledBarrierSha256dPrototypeExecuted);
    BOOST_CHECK(rc::kRCStage3CoupledDigestSha256dPrototypeExecuted);
    BOOST_CHECK(!HasGap(entries[5],
                        rc::RCStage3CoupledAirGapCode::ExtractChaChaAndScaleSha));
    BOOST_CHECK(!HasGap(entries[5],
                        rc::RCStage3CoupledAirGapCode::ExtractInt64AndRangeLookups));
    BOOST_CHECK(!HasGap(entries[6],
                        rc::RCStage3CoupledAirGapCode::BarrierSha256d));
    BOOST_CHECK(!HasGap(entries[7],
                        rc::RCStage3CoupledAirGapCode::DigestSha256d));
    BOOST_CHECK(entries[5].local_kernel_complete);
    BOOST_CHECK(entries[5].constraint_system_available);
    BOOST_CHECK(!entries[6].constraint_system_available);
    BOOST_CHECK(!entries[7].constraint_system_available);
    BOOST_CHECK(HasGap(entries[5],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[6],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[7],
                       rc::RCStage3CoupledAirGapCode::RecursiveAggregation));
    BOOST_CHECK(HasGap(entries[5],
                       rc::RCStage3CoupledAirGapCode::CommitmentOpeningBridge) ||
                HasGap(entries[6],
                       rc::RCStage3CoupledAirGapCode::CommitmentOpeningBridge) ||
                HasGap(entries[7],
                       rc::RCStage3CoupledAirGapCode::CommitmentOpeningBridge));
}

BOOST_AUTO_TEST_SUITE_END()
