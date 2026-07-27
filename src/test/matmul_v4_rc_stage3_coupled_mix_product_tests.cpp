// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_mix_product.h>

#include <array>

namespace {

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
namespace col = rc::coupled_air_col;
using gf::Fp3;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = 4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0xff);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
    return out;
}

rc::RCStage3CoupledShape Shape()
{
    rc::RCStage3CoupledShape out;
    out.barriers = 4;
    out.lobes = 1;
    out.lobe_width = 32;
    out.bank_pages = 1;
    out.rows_per_lobe = 1;
    out.pages_per_barrier_lobe = 1;
    out.transcript_version = 4;
    out.full_bank_schedule = true;
    return out;
}

std::vector<std::vector<int64_t>> Inputs()
{
    std::vector<std::vector<int64_t>> out(
        4, std::vector<int64_t>(32));
    for (uint32_t barrier = 0;
         barrier < out.size(); ++barrier) {
        for (uint32_t i = 0;
             i < out[barrier].size(); ++i) {
            out[barrier][i] =
                int64_t{barrier} * 100 +
                int64_t{i} - 16;
        }
    }
    return out;
}

rc::RCCoupParams Params(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCCoupParams out;
    out.barriers = shape.barriers;
    out.lobes = shape.lobes;
    out.lobe_width = shape.lobe_width;
    out.bank_pages = shape.bank_pages;
    out.rows_per_lobe = shape.rows_per_lobe;
    out.pages_per_barrier_lobe =
        shape.pages_per_barrier_lobe;
    return out;
}

uint32_t BitColumn(uint32_t limb, uint32_t bit)
{
    return col::MIX_BITS + limb * 16U + bit;
}

void SetArithmeticRow(
    std::vector<Fp3>& row, uint64_t a, uint64_t b)
{
    const std::array<uint64_t, 4> words{
        a, b, a + b, b - a};
    for (uint32_t family = 0;
         family < words.size(); ++family) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            const uint32_t value =
                (words[family] >> (16U * limb)) &
                0xffffU;
            const uint32_t limb_index =
                family * 4 + limb;
            row[limb_index] = U(value);
            for (uint32_t bit = 0; bit < 16; ++bit) {
                row[BitColumn(limb_index, bit)] =
                    U((value >> bit) & 1U);
            }
        }
    }
    uint32_t carry{0};
    uint32_t borrow{0};
    for (uint32_t limb = 0; limb < 4; ++limb) {
        const uint32_t av =
            static_cast<uint16_t>(a >> (16U * limb));
        const uint32_t bv =
            static_cast<uint16_t>(b >> (16U * limb));
        const uint32_t total = av + bv + carry;
        carry = total >> 16;
        row[col::MIX_CARRY + limb] = U(carry);
        const uint32_t subtrahend = av + borrow;
        borrow = bv < subtrahend ? 1U : 0U;
        row[col::MIX_BORROW + limb] = U(borrow);
    }
    row[rc::kRCStage3CoupledMixActive] = Fp3::One();
}

uint64_t ConstraintViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<Fp3>& row)
{
    uint64_t out{0};
    for (const auto& constraint : cs.constraints) {
        if (!gf::IsZero(constraint.eval(row, row))) ++out;
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_mix_product_tests)

BOOST_AUTO_TEST_CASE(
    audit_is_locally_complete_and_fail_closed_transitively)
{
    const auto audit =
        rc::CurrentRCStage3CoupledMixProductAudit();
    BOOST_CHECK(audit.immutable_full_butterfly_schedule);
    BOOST_CHECK(audit.mix_seed_and_mask_sha_executed);
    BOOST_CHECK(audit.index_relabelling_bound);
    BOOST_CHECK(audit.complete_u64_limb_range_executed);
    BOOST_CHECK(audit.signed_overflow_excluded);
    BOOST_CHECK(
        audit.all_sum_difference_arithmetic_executed);
    BOOST_CHECK(audit.stage_state_equality_executed);
    BOOST_CHECK(
        audit.endpoints_39_40_41_bounded_local_complete);
    BOOST_CHECK(!audit.producer_provenance_complete);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_CASE(
    exact_schedule_covers_both_patterns_and_rejects_omission_reorder_index_value_and_root_attacks)
{
    const auto statement = Statement();
    const auto shape = Shape();
    const auto inputs = Inputs();
    std::string why;
    rc::RCStage3CoupledMixProduct honest;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledMixProduct(
            statement, shape, inputs, honest, &why),
        why);
    BOOST_REQUIRE_EQUAL(honest.state_cells, 32U);
    BOOST_REQUIRE_EQUAL(honest.barrier_seeds.size(), 4U);
    BOOST_REQUIRE_EQUAL(honest.schedule.size(), 320U);
    BOOST_REQUIRE_EQUAL(honest.output_states.size(), 4U);
    BOOST_CHECK(!honest.u64_wrap);
    BOOST_CHECK_EQUAL(honest.schedule[0].logical_stage, 0U);
    BOOST_CHECK_EQUAL(honest.schedule[0].pattern, 0U);
    BOOST_CHECK_EQUAL(
        honest.schedule[80].barrier, 1U);
    BOOST_CHECK_EQUAL(
        honest.schedule[80].logical_stage, 4U);
    BOOST_CHECK_EQUAL(
        honest.schedule[80].pattern, 1U);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, honest, &why),
        why);
    // Harness-only differential check against the immutable consensus tail.
    // Construct each pre-permutation state whose balanced-permutation output
    // is exactly this product's endpoint-39 opening; ApplyCoupledBarrierTail
    // leaves `acc` at post-mix when material exchange rounds are disabled.
    rc::RCCoupOptions options;
    options.transcript_version = shape.transcript_version;
    options.full_bank_schedule = shape.full_bank_schedule;
    options.material_exchange = false;
    options.exchange_rounds = 0;
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const auto pi =
            rc::DeriveCoupledBalancedPermutation(
                statement.public_inputs.sigma,
                barrier, Params(shape),
                shape.transcript_version);
        BOOST_REQUIRE_EQUAL(pi.size(), honest.state_cells);
        std::vector<int64_t> consensus_input(
            honest.state_cells);
        for (uint32_t i = 0; i < honest.state_cells; ++i) {
            consensus_input[i] =
                honest.input_states[barrier][pi[i]];
        }
        std::vector<int8_t> extracted(
            honest.state_cells);
        BOOST_REQUIRE(
            rc::ApplyCoupledBarrierTail(
                statement.public_inputs.sigma,
                barrier, Params(shape),
                consensus_input, extracted,
                nullptr, options));
        BOOST_CHECK(
            consensus_input ==
            honest.output_states[barrier]);
    }

    auto omitted = honest;
    omitted.schedule.pop_back();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, omitted, &why));

    auto reordered = honest;
    std::swap(
        reordered.schedule[0], reordered.schedule[1]);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, reordered, &why));

    auto index_attack = honest;
    index_attack.schedule[0].pi ^=
        index_attack.schedule[0].stride;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, index_attack, &why));

    auto seed_attack = honest;
    seed_attack.barrier_seeds[0].mask ^= 1U;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, seed_attack, &why));

    auto input_attack = honest;
    ++input_attack.input_states[0][0];
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, input_attack, &why));

    auto output_attack = honest;
    ++output_attack.output_states[3][31];
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, output_attack, &why));

    auto root_attack = honest;
    root_attack.arithmetic_pin.column_roots[
        col::MIX_SUM_LIMB].root = H(0xa1);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, root_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    signed_kernel_rejects_overflow_while_wrap_kernel_accepts_the_same_exact_u64_row)
{
    rc::RCStage3CoupledMixPin pin;
    pin.statement_commitment = H(0x11);
    pin.shape_commitment = H(0x22);
    pin.sigma = H(0x33);
    pin.schedule_commitment = H(0x44);
    pin.logical_rows = 2;
    pin.n_rows = 2;
    pin.n_coeffs = 4;
    pin.column_roots.resize(
        rc::kRCStage3CoupledMixColumns);
    for (uint32_t i = 0;
        i < pin.column_roots.size(); ++i) {
        pin.column_roots[i] = {
            i, H(static_cast<uint8_t>(
                   (i % 254U) + 1U))};
    }
    pin.pin_commitment =
        rc::ComputeRCStage3CoupledMixPinCommitment(pin);
    aq::AirConstraintSystem<Fp3> signed_cs;
    BOOST_REQUIRE(
        rc::BuildRCStage3CoupledMixConstraintSystem(
            pin, signed_cs));
    std::vector<Fp3> row(
        rc::kRCStage3CoupledMixColumns, Fp3::Zero());
    SetArithmeticRow(
        row, UINT64_C(0x7fffffffffffffff), 1);
    BOOST_CHECK(ConstraintViolations(signed_cs, row) > 0);

    pin.u64_wrap = true;
    pin.n_coeffs = 2;
    pin.pin_commitment =
        rc::ComputeRCStage3CoupledMixPinCommitment(pin);
    aq::AirConstraintSystem<Fp3> wrap_cs;
    BOOST_REQUIRE(
        rc::BuildRCStage3CoupledMixConstraintSystem(
            pin, wrap_cs));
    row[rc::kRCStage3CoupledMixWrap] = Fp3::One();
    BOOST_CHECK_EQUAL(
        ConstraintViolations(wrap_cs, row), 0U);
}

BOOST_AUTO_TEST_CASE(
    full_seed_and_arithmetic_proofs_execute_and_reject_proof_or_digest_substitution)
{
    const auto statement = Statement();
    const auto shape = Shape();
    std::string why;
    rc::RCStage3CoupledMixProduct honest;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledMixProduct(
            statement, shape, Inputs(), honest, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledMixProduct(
            statement, shape, honest, &why),
        why);

    auto proof_root = honest;
    proof_root.arithmetic_proof.batch.columns[
        col::MIX_DIFF_LIMB].root = H(0xb1);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledMixProduct(
            statement, shape, proof_root, &why));

    auto digest_attack = honest;
    digest_attack.barrier_seeds[0]
        .mask_block.manifest.digest[0] ^= 1U;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledMixProduct(
            statement, shape, digest_attack, &why));
}

BOOST_AUTO_TEST_SUITE_END()
