// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_coupled_chain_product.h>

#include <hash.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc {
namespace {

bool Fail(std::string* why, const char* reason)
{
    if (why) *why = reason;
    return false;
}

template <typename T>
void CommitVector(HashWriter& hash, const std::vector<T>& values)
{
    hash << static_cast<uint64_t>(values.size());
    for (const T value : values) {
        hash << static_cast<int64_t>(value);
    }
}

uint256 LinkCommitment(
    const char* domain,
    const std::vector<std::vector<int64_t>>& vectors)
{
    HashWriter hash;
    hash << domain;
    hash << static_cast<uint64_t>(vectors.size());
    for (const auto& values : vectors) {
        CommitVector(hash, values);
    }
    return hash.GetHash();
}

uint256 ByteLinkCommitment(
    const char* domain,
    const std::vector<std::vector<int8_t>>& vectors)
{
    HashWriter hash;
    hash << domain;
    hash << static_cast<uint64_t>(vectors.size());
    for (const auto& values : vectors) {
        CommitVector(hash, values);
    }
    return hash.GetHash();
}

} // namespace

bool ValidateRCStage3CoupledChainProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& bank,
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledExchangePermutationProduct& exchange,
    const RCStage3CoupledMixProduct& mix,
    const RCStage3CoupledExtractProduct& extract,
    RCStage3CoupledChainProduct& out,
    std::string* why)
{
    out = {};
    if (!ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, bank, why) ||
        !ValidateRCStage3CoupledGemmSchedule(
            statement, shape, gemm, why) ||
        !ValidateRCStage3CoupledExchangePermutationProductSchedule(
            statement, shape, exchange, why) ||
        !ValidateRCStage3CoupledMixProductSchedule(
            statement, shape, mix, why) ||
        !ValidateRCStage3CoupledExtractProductSchedule(
            statement, shape, extract, why)) {
        return Fail(why, "coupled_chain:producer_schedule");
    }

    std::vector<std::vector<int8_t>> bank_to_gemm;
    std::vector<std::vector<int8_t>> prior_extract_to_gemm;
    std::vector<std::vector<int64_t>> gemm_to_exchange;
    const uint64_t lobe_cells =
        uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    const uint64_t state_cells =
        uint64_t{shape.lobes} * lobe_cells;
    std::vector<std::vector<int8_t>> extract_outputs(
        shape.barriers,
        std::vector<int8_t>(state_cells));
    std::vector<uint32_t> next_output_tile(
        shape.barriers, 0);
    for (const auto& tile : extract.tiles) {
        if (tile.schedule.barrier >= shape.barriers ||
            tile.schedule.tile !=
                next_output_tile[tile.schedule.barrier]++) {
            return Fail(
                why, "coupled_chain:extract_output_order");
        }
        const uint64_t begin =
            uint64_t{tile.schedule.tile} *
            kRCMxBlockLen;
        if (begin > state_cells ||
            state_cells - begin < kRCMxBlockLen) {
            return Fail(
                why, "coupled_chain:extract_output_span");
        }
        std::copy(
            tile.output.begin(), tile.output.end(),
            extract_outputs[tile.schedule.barrier].begin() +
                begin);
    }
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        if (uint64_t{next_output_tile[barrier]} *
                kRCMxBlockLen != state_cells) {
            return Fail(
                why, "coupled_chain:extract_output_coverage");
        }
    }
    const uint64_t aggregate_count =
        uint64_t{shape.barriers} * shape.lobes;
    std::vector<std::vector<int64_t>> gemm_sums(
        aggregate_count,
        std::vector<int64_t>(lobe_cells, 0));
    std::vector<uint32_t> gemm_sum_terms(
        aggregate_count, 0);
    for (const auto& instance : gemm.gemms) {
        if (instance.schedule.barrier >= shape.barriers ||
            instance.schedule.lobe >= shape.lobes ||
            instance.output_y.size() != lobe_cells) {
            return Fail(why, "coupled_chain:gemm_schedule");
        }
        if (instance.schedule.barrier > 0) {
            const auto& prior = extract_outputs[
                instance.schedule.barrier - 1U];
            const uint64_t begin =
                uint64_t{instance.schedule.lobe} *
                lobe_cells;
            if (instance.operand_a.size() != lobe_cells ||
                begin > prior.size() ||
                prior.size() - begin < lobe_cells ||
                !std::equal(
                    instance.operand_a.begin(),
                    instance.operand_a.end(),
                    prior.begin() + begin)) {
                return Fail(why, "coupled_chain:46_to_30");
            }
            prior_extract_to_gemm.push_back(
                instance.operand_a);
        }
        if (instance.schedule.page_id >= bank.pages.size() ||
            instance.operand_b !=
                bank.pages[instance.schedule.page_id].page_bytes) {
            return Fail(why, "coupled_chain:28_to_31");
        }
        bank_to_gemm.push_back(instance.operand_b);
        const uint64_t aggregate_index =
            uint64_t{instance.schedule.barrier} *
                shape.lobes +
            instance.schedule.lobe;
        auto& sum = gemm_sums[aggregate_index];
        for (uint64_t cell = 0;
             cell < lobe_cells; ++cell) {
            const __int128 candidate =
                static_cast<__int128>(sum[cell]) +
                static_cast<__int128>(
                    instance.output_y[cell]);
            if (candidate <
                    std::numeric_limits<int64_t>::min() ||
                candidate >
                    std::numeric_limits<int64_t>::max()) {
                return Fail(
                    why, "coupled_chain:gemm_sum_overflow");
            }
            sum[cell] =
                static_cast<int64_t>(candidate);
        }
        ++gemm_sum_terms[aggregate_index];
    }
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0;
             lobe < shape.lobes; ++lobe) {
            const uint64_t aggregate_index =
                uint64_t{barrier} * shape.lobes + lobe;
            if (gemm_sum_terms[aggregate_index] !=
                shape.pages_per_barrier_lobe) {
                return Fail(
                    why, "coupled_chain:gemm_sum_coverage");
            }
            const auto stage = std::find_if(
                exchange.exchange_stages.begin(),
                exchange.exchange_stages.end(),
                [&](const auto& candidate) {
                    return candidate.schedule.kind ==
                               RCStage3CoupledExchangeStageKind::
                                   FixedSegment &&
                        candidate.schedule.barrier ==
                            barrier &&
                        candidate.schedule.lobe_or_round ==
                            lobe;
                });
            if (stage == exchange.exchange_stages.end() ||
                stage->input !=
                    gemm_sums[aggregate_index]) {
                return Fail(
                    why, "coupled_chain:32_sum_to_34");
            }
            gemm_to_exchange.push_back(
                gemm_sums[aggregate_index]);
        }
    }

    if (exchange.permutation_stages.size() !=
            mix.input_states.size() ||
        mix.output_states.size() != shape.barriers) {
        return Fail(why, "coupled_chain:state_count");
    }
    std::vector<std::vector<int64_t>> permutation_to_mix;
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const auto stage = std::find_if(
            exchange.permutation_stages.begin(),
            exchange.permutation_stages.end(),
            [barrier](const auto& candidate) {
                return candidate.schedule.barrier == barrier;
            });
        if (stage == exchange.permutation_stages.end() ||
            stage->output != mix.input_states[barrier]) {
            return Fail(why, "coupled_chain:38_to_39");
        }
        permutation_to_mix.push_back(stage->output);
    }

    std::vector<std::vector<int64_t>> mix_to_exchange;
    std::vector<std::vector<int64_t>> material_round_chain;
    std::vector<std::vector<int64_t>> mix_to_extract;
    std::vector<std::vector<int64_t>> exchange_to_extract;
    std::vector<const std::vector<int64_t>*> extract_sources(
        shape.barriers, nullptr);
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        const std::vector<int64_t>* current =
            &mix.output_states[barrier];
        for (uint32_t round = 0;
             round < shape.exchange_rounds; ++round) {
            const auto stage = std::find_if(
                exchange.exchange_stages.begin(),
                exchange.exchange_stages.end(),
                [barrier, round](const auto& candidate) {
                    return candidate.schedule.kind ==
                               RCStage3CoupledExchangeStageKind::
                                   MaterialRound &&
                        candidate.schedule.barrier == barrier &&
                        candidate.schedule.lobe_or_round == round;
                });
            if (stage == exchange.exchange_stages.end() ||
                stage->input != *current) {
                return Fail(
                    why, round == 0
                        ? "coupled_chain:41_to_34"
                        : "coupled_chain:material_round_chain");
            }
            if (round == 0) {
                mix_to_exchange.push_back(stage->input);
            } else {
                material_round_chain.push_back(stage->input);
            }
            current = &stage->output;
        }
        extract_sources[barrier] = current;
        if (shape.exchange_rounds == 0) {
            mix_to_extract.push_back(*current);
        } else {
            exchange_to_extract.push_back(*current);
        }
    }

    std::vector<uint32_t> next_tile(shape.barriers, 0);
    for (const auto& tile : extract.tiles) {
        if (tile.schedule.barrier >= shape.barriers ||
            tile.schedule.tile !=
                next_tile[tile.schedule.barrier]++) {
            return Fail(why, "coupled_chain:extract_order");
        }
        const auto& state =
            *extract_sources[tile.schedule.barrier];
        const uint64_t begin =
            uint64_t{tile.schedule.tile} *
            kRCMxBlockLen;
        if (begin > state.size() ||
            state.size() - begin < kRCMxBlockLen) {
            return Fail(why, "coupled_chain:extract_span");
        }
        std::vector<int64_t> values(
            state.begin() + begin,
            state.begin() + begin + kRCMxBlockLen);
        if (!std::equal(
                values.begin(), values.end(),
                tile.input.begin())) {
            return Fail(
                why, shape.exchange_rounds == 0
                    ? "coupled_chain:41_to_42"
                    : "coupled_chain:36_to_42");
        }
    }
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        if (uint64_t{next_tile[barrier]} *
                kRCMxBlockLen !=
            extract_sources[barrier]->size()) {
            return Fail(why, "coupled_chain:extract_coverage");
        }
    }

    out.bank_to_gemm_instances =
        static_cast<uint32_t>(bank_to_gemm.size());
    out.prior_extract_to_gemm_instances =
        static_cast<uint32_t>(
            prior_extract_to_gemm.size());
    out.gemm_to_exchange_instances =
        static_cast<uint32_t>(gemm_to_exchange.size());
    out.permutation_to_mix_instances =
        static_cast<uint32_t>(permutation_to_mix.size());
    out.mix_to_exchange_instances =
        static_cast<uint32_t>(mix_to_exchange.size());
    out.material_round_chain_instances =
        static_cast<uint32_t>(
            material_round_chain.size());
    out.mix_to_extract_instances =
        static_cast<uint32_t>(mix_to_extract.size());
    out.exchange_to_extract_instances =
        static_cast<uint32_t>(
            exchange_to_extract.size());
    out.bank_to_gemm_commitment =
        ByteLinkCommitment(
            "BTX_RC_STAGE3_CHAIN_28_31_V1",
            bank_to_gemm);
    out.prior_extract_to_gemm_commitment =
        ByteLinkCommitment(
            "BTX_RC_STAGE3_CHAIN_46_30_V1",
            prior_extract_to_gemm);
    out.gemm_to_exchange_commitment =
        LinkCommitment(
            "BTX_RC_STAGE3_CHAIN_32_34_V1",
            gemm_to_exchange);
    out.permutation_to_mix_commitment =
        LinkCommitment(
            "BTX_RC_STAGE3_CHAIN_38_39_V1",
            permutation_to_mix);
    out.mix_to_exchange_commitment =
        LinkCommitment(
            "BTX_RC_STAGE3_CHAIN_41_34_V1",
            mix_to_exchange);
    out.material_round_chain_commitment =
        LinkCommitment(
            "BTX_RC_STAGE3_CHAIN_MATERIAL_ROUNDS_V1",
            material_round_chain);
    out.mix_to_extract_commitment =
        LinkCommitment(
            "BTX_RC_STAGE3_CHAIN_41_42_V1",
            mix_to_extract);
    out.exchange_to_extract_commitment =
        LinkCommitment(
            "BTX_RC_STAGE3_CHAIN_36_42_V1",
            exchange_to_extract);
    HashWriter product;
    product << "BTX_RC_STAGE3_COUPLED_CHAIN_V1";
    product << out.version;
    product << out.bank_to_gemm_instances;
    product << out.prior_extract_to_gemm_instances;
    product << out.gemm_to_exchange_instances;
    product << out.permutation_to_mix_instances;
    product << out.mix_to_exchange_instances;
    product << out.material_round_chain_instances;
    product << out.mix_to_extract_instances;
    product << out.exchange_to_extract_instances;
    product << out.bank_to_gemm_commitment;
    product << out.prior_extract_to_gemm_commitment;
    product << out.gemm_to_exchange_commitment;
    product << out.permutation_to_mix_commitment;
    product << out.mix_to_exchange_commitment;
    product << out.material_round_chain_commitment;
    product << out.mix_to_extract_commitment;
    product << out.exchange_to_extract_commitment;
    out.product_commitment = product.GetHash();
    return !out.product_commitment.IsNull();
}

bool VerifyRCStage3CoupledChainProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& bank,
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledExchangePermutationProduct& exchange,
    const RCStage3CoupledMixProduct& mix,
    const RCStage3CoupledExtractProduct& extract,
    RCStage3CoupledChainProduct& out,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankProduct(
            statement, header, shape, bank, why) ||
        !VerifyRCStage3CoupledGemmProduct(
            statement, shape, gemm, why) ||
        !VerifyRCStage3CoupledExchangePermutationProduct(
            statement, shape, exchange, why) ||
        !VerifyRCStage3CoupledMixProduct(
            statement, shape, mix, why) ||
        !VerifyRCStage3CoupledExtractProduct(
            statement, shape, extract, why)) {
        return Fail(why, "coupled_chain:producer_proof");
    }
    return ValidateRCStage3CoupledChainProduct(
        statement, header, shape, bank, gemm,
        exchange, mix, extract, out, why);
}

RCStage3CoupledChainProductAudit
CurrentRCStage3CoupledChainProductAudit()
{
    RCStage3CoupledChainProductAudit out;
    out.bank_pages_to_gemm_b_exact = true;
    out.prior_extract_to_gemm_a_exact = true;
    out.gemm_y_to_exchange_input_exact = true;
    out.permutation_output_to_mix_input_exact = true;
    out.mix_output_to_material_round_exact = true;
    out.material_round_chain_exact = true;
    out.mix_output_to_extract_input_exact = true;
    out.material_output_to_extract_input_exact = true;
    out.actual_proof_owned_vectors_consumed = true;
    return out;
}

} // namespace matmul::v4::rc
