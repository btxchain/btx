// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_bank_hash_bridge.h>

#include <array>
#include <cstdlib>

namespace {

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

uint256 Seed(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

struct TinyBank {
    rc::RCStage3CoupledBankDequantPin pin;
    std::vector<std::vector<gf::Fp3>> columns;
};

TinyBank BuildTinyBank()
{
    TinyBank out;
    constexpr uint32_t rows = 2;
    out.columns.assign(
        rc::kRCStage3CoupledBankDequantColumns,
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));
    const std::array<int32_t, rows> mantissa{
        -3, 5};
    const std::array<uint32_t, rows> scale{
        1, 3};
    for (uint32_t row = 0; row < rows; ++row) {
        const uint32_t b0 = scale[row] & 1U;
        const uint32_t b1 =
            (scale[row] >> 1) & 1U;
        const uint32_t factor =
            uint32_t{1} << scale[row];
        out.columns[
            rc::kRCStage3CoupledBankMantissa][row] =
            gf::FromSigned3(mantissa[row]);
        out.columns[
            rc::kRCStage3CoupledBankRepeatedScale][row] =
            gf::FromU64_3(scale[row]);
        out.columns[
            rc::kRCStage3CoupledBankScaleBit0][row] =
            gf::FromU64_3(b0);
        out.columns[
            rc::kRCStage3CoupledBankScaleBit1][row] =
            gf::FromU64_3(b1);
        out.columns[
            rc::kRCStage3CoupledBankScaleFactor][row] =
            gf::FromU64_3(factor);
        out.columns[
            rc::kRCStage3CoupledBankOutput][row] =
            gf::FromSigned3(
                mantissa[row] *
                static_cast<int32_t>(factor));
    }
    out.pin.statement_commitment = Seed(0x31);
    out.pin.shape_commitment = Seed(0x32);
    out.pin.sigma = Seed(0x33);
    out.pin.page_index = 7;
    out.pin.logical_rows = rows;
    out.pin.n_rows = rows;
    out.pin.n_coeffs = rows;
    auto root_columns = out.columns;
    root_columns.emplace_back(
        rows, gf::Fp3::Zero());
    aq::AirConstraintSystem<gf::Fp3> row_shape;
    row_shape.n_rows = rows;
    row_shape.n_columns = root_columns.size();
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            row_shape, root_columns,
            {0, 1, 2, 3, 4, 5});
    BOOST_REQUIRE(r0.valid);
    out.pin.r0_row_group_root =
        r0.base_row_commitment;
    out.pin.pin_commitment =
        rc::ComputeRCStage3CoupledBankDequantPinCommitment(
            out.pin);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_bank_hash_bridge_tests)

BOOST_AUTO_TEST_CASE(
    signed_output_range_rejection_is_fast_and_exact)
{
    const TinyBank bank = BuildTinyBank();
    const std::vector<uint8_t> prefix{
        0x42, 0x54, 0x58};
    auto invalid_signed_columns = bank.columns;
    invalid_signed_columns[
        rc::kRCStage3CoupledBankOutput][0] =
        gf::FromU64_3(128);
    rc::RCStage3CoupledBankHashBridgeProofV1
        invalid_signed_proof;
    std::string why;
    BOOST_CHECK(
        !rc::ProveRCStage3CoupledBankHashBridgeV1(
            bank.pin, invalid_signed_columns,
            prefix, Seed(0x44),
            invalid_signed_proof, &why));
    BOOST_CHECK(
        why.find("producer_signed_range") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    signed_output_alg_hash_to_sha_first_pass_roundtrip_and_mutations)
{
    // The real Q192 Split-RAP SHA child is intentionally opt-in. Even the
    // minimum two-instance/2048-row vertical SHA witness exceeded the
    // bounded 90-second development run on the reference machine. Keep the
    // exact root/value/prefix/terminal mutation canaries compiled without
    // making ordinary unit runs execute a known non-production prover.
    if (std::getenv(
            "BTX_RUN_STAGE3_BANK_HASH_BRIDGE_PROVER") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_BANK_HASH_BRIDGE_PROVER=1 "
            "to run the exact Q192 bridge roundtrip");
        return;
    }
    const TinyBank bank = BuildTinyBank();
    BOOST_REQUIRE(
        !bank.pin.pin_commitment.IsNull());
    const std::vector<uint8_t> prefix{
        0x42, 0x54, 0x58};
    const uint256 fs_seed = Seed(0x44);
    rc::RCStage3CoupledBankHashBridgeProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankHashBridgeV1(
            bank.pin, bank.columns,
            prefix, fs_seed, proof, &why),
        why);
    BOOST_CHECK_EQUAL(proof.bank_byte_count, 2U);
    BOOST_CHECK_EQUAL(proof.first_pass_blocks, 1U);
    BOOST_CHECK(
        !proof.bank_byte_alg_hash_root.IsNull());
    BOOST_CHECK(!proof.sha_r0_root.IsNull());
    BOOST_CHECK(
        proof.bank_byte_alg_hash_root !=
        proof.sha_r0_root);
    BOOST_REQUIRE_EQUAL(proof.pins.size(), 2U);
    BOOST_CHECK_EQUAL(proof.pins[0].send_count, 2U);
    BOOST_CHECK_EQUAL(proof.pins[1].receive_count, 2U);

    const auto audit =
        rc::VerifyRCStage3CoupledBankHashBridgeV1(
            bank.pin, prefix, fs_seed, proof);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(
        audit.signed_output_range_and_u8_same_trace);
    BOOST_CHECK(audit.producer_ctl_value_same_trace);
    BOOST_CHECK(audit.bank_byte_alg_hash_root_verified);
    BOOST_CHECK(audit.sha_first_pass_bytes_epoch_r0);
    BOOST_CHECK(audit.sha_nonbank_bytes_pinned);
    BOOST_CHECK(audit.sha_ctl_value_same_trace);
    BOOST_CHECK(audit.shared_post_r0_challenges);
    BOOST_CHECK(audit.producer_split_rap_verified);
    BOOST_CHECK(audit.sha_split_rap_verified);
    BOOST_CHECK(audit.dual_lane_terminal_equality);
    BOOST_CHECK(audit.local_bridge_executable);
    BOOST_CHECK(audit.endpoint28_producer_root_bound);
    BOOST_CHECK(
        !audit.normalized_child_verifiers_execute);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.authority);

    auto wrong_prefix = prefix;
    wrong_prefix[1] ^= 1U;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankHashBridgeV1(
             bank.pin, wrong_prefix,
             fs_seed, proof)
             .valid);

    auto wrong_terminal = proof;
    wrong_terminal.pins[1].terminal.alpha1_sum =
        gf::Add(
            wrong_terminal.pins[1]
                .terminal.alpha1_sum,
            gf::Fp3::One());
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankHashBridgeV1(
             bank.pin, prefix, fs_seed,
             wrong_terminal)
             .valid);

    auto wrong_producer_root = proof;
    wrong_producer_root.producer_proof.batch
        .groups[0].row_commit.root[0] =
        gf::Add(
            wrong_producer_root.producer_proof.batch
                .groups[0].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankHashBridgeV1(
             bank.pin, prefix, fs_seed,
             wrong_producer_root)
             .valid);

    auto wrong_sha_root = proof;
    wrong_sha_root.sha_proof.batch
        .groups[0].row_commit.root[0] =
        gf::Add(
            wrong_sha_root.sha_proof.batch
                .groups[0].row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankHashBridgeV1(
             bank.pin, prefix, fs_seed,
             wrong_sha_root)
             .valid);

}

BOOST_AUTO_TEST_SUITE_END()
