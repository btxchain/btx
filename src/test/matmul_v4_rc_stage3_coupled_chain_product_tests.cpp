// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_coupled_chain_product.h>
#include <matmul/matmul_v4_rc_extract.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
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
    out.transcript_version = rc::ENC_RC_V4;
    out.full_bank_schedule = true;
    out.material_exchange = false;
    out.exchange_rows = 32;
    out.exchange_rounds = 0;
    return out;
}

rc::RCStage3CoupledShape MaterialShape()
{
    auto out = Shape();
    out.material_exchange = true;
    out.exchange_rounds = 1;
    return out;
}

rc::RCStage3CoupledShape MultiPageShape()
{
    auto out = Shape();
    out.bank_pages = 2;
    out.pages_per_barrier_lobe = 2;
    return out;
}

rc::RCStage3SuccinctProof Statement(
    const CBlockHeader& header)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = header.nBits;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment =
        rc::RCStage3HeaderCommitment(header);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0xff);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
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

rc::RCCoupOptions Options(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCCoupOptions out;
    out.transcript_version = shape.transcript_version;
    out.full_bank_schedule = shape.full_bank_schedule;
    out.material_exchange = shape.material_exchange;
    out.exchange_rows = shape.exchange_rows;
    out.exchange_rounds = shape.exchange_rounds;
    out.force_signed_mix = shape.force_signed_mix;
    return out;
}

std::vector<int64_t> GemmY(
    const std::vector<int8_t>& a,
    const std::vector<int8_t>& b,
    uint32_t width)
{
    std::vector<int64_t> out(width, 0);
    for (uint32_t column = 0; column < width; ++column) {
        for (uint32_t k = 0; k < width; ++k) {
            out[column] +=
                int64_t{a[k]} *
                int64_t{b[k * width + column]};
        }
    }
    return out;
}

struct Fixture {
    CBlockHeader header;
    rc::RCStage3CoupledShape shape;
    rc::RCStage3SuccinctProof statement;
    rc::RCStage3CoupledBankProduct bank;
    std::vector<rc::RCStage3CoupledGemmOpening> openings;
    rc::RCStage3CoupledGemmProduct gemm;
    rc::RCStage3CoupledExchangePermutationWitness exchange_witness;
    rc::RCStage3CoupledExchangePermutationProduct exchange;
    rc::RCStage3CoupledMixProduct mix;
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>>
        extract_inputs;
    rc::RCStage3CoupledExtractProduct extract;
    rc::RCStage3CoupledChainProduct chain;
};

Fixture BuildFixture(
    const rc::RCStage3CoupledShape& requested = Shape())
{
    Fixture out;
    out.header = Header();
    out.shape = requested;
    out.statement = Statement(out.header);
    std::string why;
    if (!rc::BuildRCStage3CoupledBankProduct(
            out.statement, out.header, out.shape,
            out.bank, &why)) {
        throw std::runtime_error(why);
    }
    std::vector<rc::RCStage3CoupledGemmScheduleEntry>
        schedule;
    uint256 schedule_commitment;
    if (!rc::BuildRCStage3CoupledGemmSchedule(
            out.statement, out.shape, schedule,
            schedule_commitment, &why)) {
        throw std::runtime_error(why);
    }
    out.openings.resize(schedule.size());
    const uint32_t lobe_cells =
        out.shape.rows_per_lobe * out.shape.lobe_width;
    const uint32_t state_cells =
        out.shape.lobes * lobe_cells;
    std::vector<int8_t> state(state_cells, 1);
    std::vector<std::vector<int64_t>>
        permutation_inputs;
    std::vector<std::vector<int64_t>> post_mix;
    uint32_t index = 0;
    for (uint32_t barrier = 0;
         barrier < out.shape.barriers; ++barrier) {
        std::vector<int64_t> acc(state_cells, 0);
        while (index < schedule.size() &&
               schedule[index].barrier == barrier) {
            const auto& entry = schedule[index];
            auto& opening = out.openings[index];
            const auto begin =
                state.begin() +
                uint64_t{entry.lobe} * lobe_cells;
            opening.operand_a.assign(
                begin, begin + lobe_cells);
            opening.operand_b =
                out.bank.pages[entry.page_id].page_bytes;
            opening.output_y =
                GemmY(
                    opening.operand_a,
                    opening.operand_b,
                    out.shape.lobe_width);
            const uint64_t offset =
                uint64_t{entry.lobe} * lobe_cells;
            for (uint32_t cell = 0;
                 cell < lobe_cells; ++cell) {
                acc[offset + cell] +=
                    opening.output_y[cell];
            }
            ++index;
        }
        permutation_inputs.push_back(acc);
        std::vector<int8_t> next_state(state_cells);
        if (!rc::ApplyCoupledBarrierTail(
                out.statement.public_inputs.sigma,
                barrier, Params(out.shape), acc,
                next_state, nullptr, Options(out.shape))) {
            throw std::runtime_error("barrier_tail");
        }
        post_mix.push_back(acc);
        for (uint32_t offset = 0;
             offset < state_cells;
             offset += rc::kRCMxBlockLen) {
            std::array<int64_t, rc::kRCMxBlockLen>
                input{};
            std::copy_n(
                acc.begin() + offset,
                rc::kRCMxBlockLen, input.begin());
            out.extract_inputs.push_back(input);
        }
        state = std::move(next_state);
    }
    if (index != schedule.size()) {
        throw std::runtime_error("gemm_schedule");
    }
    if (!rc::BuildRCStage3CoupledGemmProduct(
            out.statement, out.shape, out.openings,
            out.gemm, &why)) {
        throw std::runtime_error(why);
    }
    for (uint32_t barrier = 0;
         barrier < out.shape.barriers; ++barrier) {
        for (uint32_t lobe = 0;
             lobe < out.shape.lobes; ++lobe) {
            const uint64_t begin =
                uint64_t{lobe} * lobe_cells;
            out.exchange_witness.fixed_exchange_inputs.
                emplace_back(
                    permutation_inputs[barrier].begin() +
                        begin,
                    permutation_inputs[barrier].begin() +
                        begin + lobe_cells);
        }
    }
    out.exchange_witness.permutation_inputs =
        permutation_inputs;
    if (!rc::BuildRCStage3CoupledExchangePermutationProduct(
            out.statement, out.shape,
            out.exchange_witness, out.exchange, &why)) {
        throw std::runtime_error(why);
    }
    std::vector<std::vector<int64_t>> mix_inputs;
    for (const auto& stage :
         out.exchange.permutation_stages) {
        mix_inputs.push_back(stage.output);
    }
    if (!rc::BuildRCStage3CoupledMixProduct(
            out.statement, out.shape, mix_inputs,
            out.mix, &why)) {
        throw std::runtime_error(why);
    }
    if (out.mix.output_states != post_mix) {
        throw std::runtime_error("mix_reference");
    }
    if (!rc::BuildRCStage3CoupledExtractProduct(
            out.statement, out.shape,
            out.extract_inputs, out.extract, &why)) {
        throw std::runtime_error(why);
    }
    if (!rc::ValidateRCStage3CoupledChainProduct(
            out.statement, out.header, out.shape,
            out.bank, out.gemm, out.exchange,
            out.mix, out.extract, out.chain, &why)) {
        throw std::runtime_error(why);
    }
    return out;
}

const Fixture& Honest()
{
    static const Fixture fixture = BuildFixture();
    return fixture;
}

const Fixture& MultiPageHonest()
{
    static const Fixture fixture =
        BuildFixture(MultiPageShape());
    return fixture;
}

Fixture BuildMaterialFixture()
{
    Fixture out;
    out.header = Header();
    out.shape = MaterialShape();
    out.statement = Statement(out.header);
    std::string why;
    if (!rc::BuildRCStage3CoupledBankProduct(
            out.statement, out.header, out.shape,
            out.bank, &why)) {
        throw std::runtime_error(why);
    }
    std::vector<rc::RCStage3CoupledGemmScheduleEntry>
        schedule;
    uint256 schedule_commitment;
    if (!rc::BuildRCStage3CoupledGemmSchedule(
            out.statement, out.shape, schedule,
            schedule_commitment, &why)) {
        throw std::runtime_error(why);
    }
    const auto extract_schedule =
        rc::BuildRCStage3CoupledExtractSchedule(
            out.statement, out.shape, &why);
    if (extract_schedule.size() != out.shape.barriers) {
        throw std::runtime_error("material_extract_schedule");
    }

    const uint32_t lobe_cells =
        out.shape.rows_per_lobe * out.shape.lobe_width;
    const uint32_t state_cells =
        out.shape.lobes * lobe_cells;
    out.openings.resize(schedule.size());
    std::vector<int8_t> state(state_cells, 1);
    std::vector<std::vector<int64_t>>
        permutation_inputs;
    std::vector<std::vector<int64_t>> post_mix;
    std::vector<std::vector<int64_t>>
        material_inputs;
    for (uint32_t barrier = 0;
         barrier < out.shape.barriers; ++barrier) {
        const auto& entry = schedule.at(barrier);
        auto& opening = out.openings[barrier];
        opening.operand_a = state;
        opening.operand_b =
            out.bank.pages[entry.page_id].page_bytes;
        opening.output_y =
            GemmY(
                opening.operand_a,
                opening.operand_b,
                out.shape.lobe_width);
        std::vector<int64_t> acc = opening.output_y;
        permutation_inputs.push_back(acc);

        auto no_round_options = Options(out.shape);
        no_round_options.exchange_rounds = 0;
        std::vector<int8_t> discarded(state_cells);
        if (!rc::ApplyCoupledBarrierTail(
                out.statement.public_inputs.sigma,
                barrier, Params(out.shape), acc,
                discarded, nullptr, no_round_options)) {
            throw std::runtime_error("material_mix_tail");
        }
        post_mix.push_back(acc);

        rc::RCStage3CoupledExchangePermutationWitness
            temporary_witness;
        temporary_witness.fixed_exchange_inputs.assign(
            out.shape.barriers * out.shape.lobes,
            std::vector<int64_t>(lobe_cells));
        temporary_witness.material_exchange_inputs.assign(
            out.shape.barriers * out.shape.exchange_rounds,
            std::vector<int64_t>(state_cells));
        temporary_witness.permutation_inputs.assign(
            out.shape.barriers,
            std::vector<int64_t>(state_cells));
        temporary_witness.material_exchange_inputs[barrier] =
            acc;
        rc::RCStage3CoupledExchangePermutationProduct
            temporary_exchange;
        if (!rc::BuildRCStage3CoupledExchangePermutationProduct(
                out.statement, out.shape,
                temporary_witness, temporary_exchange, &why)) {
            throw std::runtime_error(why);
        }
        const auto material = std::find_if(
            temporary_exchange.exchange_stages.begin(),
            temporary_exchange.exchange_stages.end(),
            [barrier](const auto& candidate) {
                return candidate.schedule.kind ==
                           rc::RCStage3CoupledExchangeStageKind::
                               MaterialRound &&
                    candidate.schedule.barrier == barrier &&
                    candidate.schedule.lobe_or_round == 0;
            });
        if (material ==
            temporary_exchange.exchange_stages.end()) {
            throw std::runtime_error("material_stage");
        }
        material_inputs.push_back(acc);
        const auto& final_state = material->output;
        std::array<int64_t, rc::kRCMxBlockLen> input{};
        std::copy(
            final_state.begin(), final_state.end(),
            input.begin());
        out.extract_inputs.push_back(input);
        state.assign(state_cells, 0);
        rc::ExtractMXTileInt64(
            extract_schedule[barrier].extract_prf,
            0, 0, final_state.data(), state.data());
    }
    if (!rc::BuildRCStage3CoupledGemmProduct(
            out.statement, out.shape, out.openings,
            out.gemm, &why)) {
        throw std::runtime_error(why);
    }
    for (const auto& instance : out.gemm.gemms) {
        out.exchange_witness.fixed_exchange_inputs.
            push_back(instance.output_y);
    }
    out.exchange_witness.material_exchange_inputs =
        material_inputs;
    out.exchange_witness.permutation_inputs =
        permutation_inputs;
    if (!rc::BuildRCStage3CoupledExchangePermutationProduct(
            out.statement, out.shape,
            out.exchange_witness, out.exchange, &why)) {
        throw std::runtime_error(why);
    }
    std::vector<std::vector<int64_t>> mix_inputs;
    for (const auto& stage :
         out.exchange.permutation_stages) {
        mix_inputs.push_back(stage.output);
    }
    if (!rc::BuildRCStage3CoupledMixProduct(
            out.statement, out.shape, mix_inputs,
            out.mix, &why) ||
        out.mix.output_states != post_mix) {
        throw std::runtime_error(
            why.empty() ? "material_mix" : why);
    }
    if (!rc::BuildRCStage3CoupledExtractProduct(
            out.statement, out.shape,
            out.extract_inputs, out.extract, &why)) {
        throw std::runtime_error(why);
    }
    if (!rc::ValidateRCStage3CoupledChainProduct(
            out.statement, out.header, out.shape,
            out.bank, out.gemm, out.exchange,
            out.mix, out.extract, out.chain, &why)) {
        throw std::runtime_error(why);
    }
    return out;
}

const Fixture& MaterialHonest()
{
    static const Fixture fixture = BuildMaterialFixture();
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_chain_product_tests)

BOOST_AUTO_TEST_CASE(
    seven_proof_owned_vector_edges_close_exactly)
{
    const auto& fixture = Honest();
    BOOST_CHECK_EQUAL(
        fixture.chain.bank_to_gemm_instances, 4U);
    BOOST_CHECK_EQUAL(
        fixture.chain.prior_extract_to_gemm_instances,
        3U);
    BOOST_CHECK_EQUAL(
        fixture.chain.gemm_to_exchange_instances, 4U);
    BOOST_CHECK_EQUAL(
        fixture.chain.permutation_to_mix_instances, 4U);
    BOOST_CHECK_EQUAL(
        fixture.chain.mix_to_extract_instances, 4U);
    BOOST_CHECK(
        !fixture.chain.product_commitment.IsNull());
    rc::RCStage3CoupledChainProduct verified;
    std::string why;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledChainProduct(
            fixture.statement, fixture.header,
            fixture.shape, fixture.bank, fixture.gemm,
            fixture.exchange, fixture.mix,
            fixture.extract, verified, &why));
    BOOST_CHECK(
        why.find("producer_proof") != std::string::npos);
    const auto audit =
        rc::CurrentRCStage3CoupledChainProductAudit();
    BOOST_CHECK_EQUAL(audit.graph_open_edges_before, 24U);
    BOOST_CHECK_EQUAL(audit.exact_edges_closed, 7U);
    BOOST_CHECK_EQUAL(audit.graph_open_edges_after, 17U);
    BOOST_CHECK(audit.actual_proof_owned_vectors_consumed);
    BOOST_CHECK(!audit.recursively_consumed);
}

BOOST_AUTO_TEST_CASE(
    mismatched_bank_gemm_exchange_mix_and_extract_vectors_reject)
{
    const auto& honest = Honest();
    std::string why;
    rc::RCStage3CoupledChainProduct chain;

    auto bad_a_openings = honest.openings;
    bad_a_openings[1].operand_a[0] ^= 1;
    bad_a_openings[1].output_y =
        GemmY(
            bad_a_openings[1].operand_a,
            bad_a_openings[1].operand_b,
            honest.shape.lobe_width);
    rc::RCStage3CoupledGemmProduct bad_a_gemm;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmProduct(
            honest.statement, honest.shape,
            bad_a_openings, bad_a_gemm, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, bad_a_gemm,
            honest.exchange, honest.mix,
            honest.extract, chain, &why));
    BOOST_CHECK(
        why.find("46_to_30") != std::string::npos);

    auto bad_openings = honest.openings;
    bad_openings[0].operand_b[0] ^= 1;
    bad_openings[0].output_y =
        GemmY(
            bad_openings[0].operand_a,
            bad_openings[0].operand_b,
            honest.shape.lobe_width);
    rc::RCStage3CoupledGemmProduct bad_gemm;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmProduct(
            honest.statement, honest.shape,
            bad_openings, bad_gemm, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, bad_gemm,
            honest.exchange, honest.mix,
            honest.extract, chain, &why));

    auto bad_exchange_witness =
        honest.exchange_witness;
    bad_exchange_witness.fixed_exchange_inputs[0][0] ^= 1;
    rc::RCStage3CoupledExchangePermutationProduct
        bad_exchange;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExchangePermutationProduct(
            honest.statement, honest.shape,
            bad_exchange_witness, bad_exchange, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, honest.gemm,
            bad_exchange, honest.mix, honest.extract,
            chain, &why));

    std::vector<std::vector<int64_t>> bad_mix_inputs;
    for (const auto& stage :
         honest.exchange.permutation_stages) {
        bad_mix_inputs.push_back(stage.output);
    }
    bad_mix_inputs[0][0] ^= 1;
    rc::RCStage3CoupledMixProduct bad_mix;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledMixProduct(
            honest.statement, honest.shape,
            bad_mix_inputs, bad_mix, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, honest.gemm,
            honest.exchange, bad_mix, honest.extract,
            chain, &why));

    auto bad_extract_inputs = honest.extract_inputs;
    bad_extract_inputs.back()[0] ^= 1;
    rc::RCStage3CoupledExtractProduct bad_extract;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExtractProduct(
            honest.statement, honest.shape,
            bad_extract_inputs, bad_extract, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, honest.gemm,
            honest.exchange, honest.mix, bad_extract,
            chain, &why));
}

BOOST_AUTO_TEST_CASE(
    material_exchange_round0_chain_and_final_extract_are_exact)
{
    const auto& honest = MaterialHonest();
    BOOST_CHECK_EQUAL(
        honest.chain.mix_to_exchange_instances, 4U);
    BOOST_CHECK_EQUAL(
        honest.chain.material_round_chain_instances, 0U);
    BOOST_CHECK_EQUAL(
        honest.chain.mix_to_extract_instances, 0U);
    BOOST_CHECK_EQUAL(
        honest.chain.exchange_to_extract_instances, 4U);

    std::string why;
    rc::RCStage3CoupledChainProduct chain;
    auto bad_exchange_witness =
        honest.exchange_witness;
    bad_exchange_witness
        .material_exchange_inputs[0][0] ^= 1;
    rc::RCStage3CoupledExchangePermutationProduct
        bad_exchange;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExchangePermutationProduct(
            honest.statement, honest.shape,
            bad_exchange_witness, bad_exchange, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, honest.gemm,
            bad_exchange, honest.mix, honest.extract,
            chain, &why));
    BOOST_CHECK(
        why.find("41_to_34") != std::string::npos);

    auto bad_extract_inputs = honest.extract_inputs;
    // Mutate the final barrier, whose Extract output is not consumed as
    // the next barrier's GEMM A.  This isolates the 36 -> 42 material-final
    // join instead of correctly failing first at the 46 -> 30 feedback join.
    bad_extract_inputs.back()[0] ^= 1;
    rc::RCStage3CoupledExtractProduct bad_extract;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExtractProduct(
            honest.statement, honest.shape,
            bad_extract_inputs, bad_extract, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, honest.gemm,
            honest.exchange, honest.mix, bad_extract,
            chain, &why));
    BOOST_CHECK(
        why.find("36_to_42") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    full_page_schedule_sums_every_gemm_before_exchange)
{
    const auto& honest = MultiPageHonest();
    BOOST_CHECK_EQUAL(
        honest.chain.bank_to_gemm_instances, 8U);
    BOOST_CHECK_EQUAL(
        honest.chain.prior_extract_to_gemm_instances,
        6U);
    BOOST_CHECK_EQUAL(
        honest.chain.gemm_to_exchange_instances, 4U);

    auto bad_openings = honest.openings;
    bad_openings[0].output_y[0] += 1;
    rc::RCStage3CoupledGemmProduct bad_gemm;
    rc::RCStage3CoupledChainProduct chain;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmProduct(
            honest.statement, honest.shape,
            bad_openings, bad_gemm, &why),
        why);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledChainProduct(
            honest.statement, honest.header,
            honest.shape, honest.bank, bad_gemm,
            honest.exchange, honest.mix,
            honest.extract, chain, &why));
    BOOST_CHECK(
        why.find("32_sum_to_34") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
