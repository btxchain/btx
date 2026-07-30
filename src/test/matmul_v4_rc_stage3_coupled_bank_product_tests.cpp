// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>

#include <array>
#include <cstring>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{bytes.data(), bytes.size()}};
}

CBlockHeader Header()
{
    CBlockHeader out;
    out.nVersion = 7;
    out.hashPrevBlock = H(0x10);
    out.hashMerkleRoot = H(0x20);
    out.nTime = 123456;
    out.nBits = 0x207fffffU;
    out.nNonce = 99;
    out.nNonce64 = 123;
    out.seed_a = H(0x30);
    out.seed_b = H(0x40);
    out.matmul_digest = H(0x50);
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

rc::RCStage3SuccinctProof Statement(const CBlockHeader& header)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = header.nBits;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = 4;
    out.public_inputs.header_commitment =
        rc::RCStage3HeaderCommitment(header);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0xff);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
    return out;
}

rc::RCCoupParams Params(const rc::RCStage3CoupledShape& shape)
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

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_bank_product_tests)

BOOST_AUTO_TEST_CASE(
    audit_reports_exact_bounded_local_closure_and_fail_closed_outer_gaps)
{
    const auto audit =
        rc::CurrentRCStage3CoupledBankProductAudit();
    BOOST_CHECK(audit.immutable_all_page_schedule);
    BOOST_CHECK(audit.bank_seed_sha_executed);
    BOOST_CHECK(audit.page_seed_sha_executed);
    BOOST_CHECK(audit.mantissa_and_scale_xof_executed);
    BOOST_CHECK(
        audit.xof_to_page_dequant_equality_executed);
    BOOST_CHECK(audit.proof_owned_page_memory_root);
    BOOST_CHECK(
        audit.endpoint29_source_root_equality_executable);
    BOOST_CHECK(
        audit.endpoints_27_28_bounded_local_complete);
    BOOST_CHECK(!audit.production_streaming_complete);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
}

BOOST_AUTO_TEST_CASE(
    bounded_v1_rejects_a_shape_larger_than_its_exact_source_tree_cap)
{
    const auto header = Header();
    const auto statement = Statement(header);
    auto shape = Shape();
    shape.lobe_width = 4096;
    shape.bank_pages = 2;
    rc::RCStage3CoupledBankProduct product;
    std::string why;
    BOOST_CHECK(
        !rc::BuildRCStage3CoupledBankProduct(
            statement, header, shape, product, &why));
    BOOST_CHECK(
        why.find("build_public_shape") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    endpoint28_flat_endpoint29_source_equality_is_value_exact)
{
    const auto header = Header();
    const auto statement = Statement(header);
    const auto shape = Shape();
    std::string why;
    rc::RCStage3CoupledBankProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankProduct(
            statement, header, shape, product, &why),
        why);
    std::vector<uint8_t> page_bytes;
    for (const auto& page : product.pages) {
        for (int8_t value : page.page_bytes) {
            page_bytes.push_back(static_cast<uint8_t>(value));
        }
    }
    rc::RCStage3CoupledBankRootManifest flat;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankRootManifest(
            statement, shape, page_bytes, flat, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledBankFlatSourceEquality(
            product, flat, &why),
        why);

    auto wrong_page = product;
    wrong_page.pages[0].page_bytes[17] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankFlatSourceEquality(
            wrong_page, flat, &why));

    auto wrong_flat_value = flat;
    const auto& tags =
        rc::RCCoupDomainTagsForVersion(shape.transcript_version);
    wrong_flat_value.sha256d.preimage[
        std::strlen(tags.bank) + 17] ^= 1U;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankFlatSourceEquality(
            product, wrong_flat_value, &why));

    auto trailing = flat;
    trailing.sha256d.preimage.push_back(0);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankFlatSourceEquality(
            product, trailing, &why));

    rc::RCStage3CoupledBankRootExecution unexecuted;
    unexecuted.manifest = flat;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankFlatSourceLink(
            statement, header, shape, product,
            unexecuted, &why));
}

BOOST_AUTO_TEST_CASE(
    exact_seed_xof_page_product_executes_and_rejects_semantic_attacks)
{
    const auto header = Header();
    const auto statement = Statement(header);
    const auto shape = Shape();
    std::string why;
    rc::RCStage3CoupledBankProduct honest;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankProduct(
            statement, header, shape, honest, &why),
        why);
    BOOST_REQUIRE_EQUAL(honest.pages.size(), 1U);
    BOOST_REQUIRE_EQUAL(
        honest.pages[0].page_bytes.size(), 1024U);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledBankProduct(
            statement, header, shape, honest, &why),
        why);

    const auto native = rc::DeriveCoupledBankPage(
        header, statement.public_inputs.height, 0,
        Params(shape), shape.transcript_version);
    BOOST_CHECK(honest.pages[0].page_bytes == native);

    rc::RCStage3CoupledBankStreamManifest stream;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, honest.bank_page_byte_root,
            stream, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledBankStreamSourceLink(
            statement, header, shape, honest, stream, &why),
        why);

    auto omitted = honest;
    omitted.pages.clear();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, omitted, &why));

    auto page_index = honest;
    ++page_index.pages[0].page_index;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, page_index, &why));

    auto page_byte = honest;
    page_byte.pages[0].page_bytes[17] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, page_byte, &why));

    auto mantissa = honest;
    mantissa.pages[0].mantissa.output[9] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, mantissa, &why));

    auto scale = honest;
    scale.pages[0].scale.output[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, scale, &why));

    auto pin_root = honest;
    pin_root.pages[0].dequant_pin.r0_row_group_root =
        H(0x91);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, pin_root, &why));

    auto proof_root = honest;
    proof_root.pages[0].dequant_proof.batch.groups[0]
        .row_commit.root[0] = rc::gkr_field::FromU64(0x92);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankProduct(
            statement, header, shape, proof_root, &why));

    auto wrong_stream = stream;
    wrong_stream.bank_page_byte_root = H(0xa0);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankStreamSourceLink(
            statement, header, shape, honest,
            wrong_stream, &why));

    auto wrong_header = header;
    ++wrong_header.nTime;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankProduct(
            statement, wrong_header, shape, honest, &why));
}

BOOST_AUTO_TEST_SUITE_END()
