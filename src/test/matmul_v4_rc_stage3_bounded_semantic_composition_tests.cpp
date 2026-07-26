// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_composition.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_gkr_air.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <initializer_list>
#include <map>

namespace {

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace ga = matmul::v4::rc::gkr_air;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Composed;
    out.public_inputs.height = 1;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.episode_profile = 2;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.program_consensus_pin.recursive_alg_hash_root = H(0x08);
    out.public_inputs.program_consensus_pin.external_sha256d_audit_root =
        H(0x09);
    out.public_inputs.program_consensus_pin.registry_binding = H(0x0a);
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
    out.exchange_rows = 32;
    return out;
}

rc::RCEpisodeParams EpisodeParams()
{
    rc::RCEpisodeParams out;
    out.rounds = 1;
    out.d_head = 32;
    out.n_q = 32;
    out.n_ctx = 32;
    out.L_lyr = 1;
    out.d_model = 32;
    out.d_ff = 32;
    out.b_seq = 32;
    out.T_leaf = 32;
    return out;
}

rc::RCStage3GemmExtractManifest EpisodeManifest()
{
    const auto params = EpisodeParams();
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> bindings(
        layout.layers.size());
    uint8_t root = 1;
    for (auto& binding : bindings) {
        binding.extract_prf = H(root++);
        binding.operand_a_root = H(root++);
        binding.operand_b_root = H(root++);
        binding.gemm_y_root = H(root++);
        binding.extract_input_root = H(root++);
        binding.extract_output_root = H(root++);
        binding.gemm_proof_root = H(root++);
        binding.extract_recursive_root = H(root++);
        binding.scale_schedule_root = H(root++);
        binding.ctl_terminal_root = H(root++);
    }
    std::string why;
    const auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, H(0xa1), bindings, &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    return *manifest;
}

CBlockHeader Header()
{
    CBlockHeader out;
    out.nVersion = 7;
    out.hashPrevBlock = H(0x10);
    out.hashMerkleRoot = H(0x20);
    out.nTime = 123456;
    out.nBits = 0x207fffffU;
    out.nNonce = 9;
    out.nNonce64 = 10;
    out.seed_a = H(0x30);
    out.seed_b = H(0x40);
    out.matmul_digest = H(0x50);
    return out;
}

rc::RCStage3SuccinctProof BoundStatement(const CBlockHeader& header)
{
    auto out = Statement();
    out.public_inputs.n_bits = header.nBits;
    out.public_inputs.header_commitment =
        rc::RCStage3HeaderCommitment(header);
    out.public_inputs.sigma = matmul::v4::DeriveSigma(header);
    arith_uint256 target;
    target.SetCompact(header.nBits);
    out.public_inputs.target = ArithToUint256(target);
    out.public_inputs.episode_digest = H(0x55);
    const auto roles =
        rc::RequiredRCStage3RelationRoles(out.statement);
    for (uint32_t i = 0; i < roles.size(); ++i) {
        out.commitments.push_back(
            {roles[i], H(static_cast<uint8_t>(0x80 + i))});
        out.sections.push_back(
            {roles[i],
             {static_cast<uint8_t>(i), 0xa5, 0x5a}});
    }
    out.public_inputs.final_digest =
        rc::ComputeRCStage3FinalDigest(out);
    out.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(out);
    return out;
}

using TensorKey = std::pair<uint32_t, uint32_t>;

std::vector<int8_t> ExpandLeaf(
    const rc::RCGkrSampledOperandProv& ref)
{
    std::vector<int8_t> expanded;
    if (ref.x0_row_blocks) {
        const uint32_t blocks =
            ref.erows / rc::kRCX0RowBlockRows;
        for (uint32_t block = 0; block < blocks; ++block) {
            const auto values = rc::ExpandMxDequantInt8(
                rc::DeriveX0RowBlockSeed(ref.seed, block),
                rc::kRCX0RowBlockRows, ref.ecols);
            expanded.insert(
                expanded.end(), values.begin(), values.end());
        }
    } else {
        expanded = rc::ExpandMxDequantInt8(
            ref.seed, ref.erows, ref.ecols);
    }
    return expanded;
}

std::vector<int64_t> GemmY(
    const rc::RCStage3GemmExtractLayerManifest& spec,
    const std::vector<int8_t>& a,
    const std::vector<int8_t>& b)
{
    std::vector<int64_t> out(
        uint64_t{spec.m} * spec.n, 0);
    for (uint32_t row = 0; row < spec.m; ++row) {
        for (uint32_t column = 0; column < spec.n; ++column) {
            int64_t sum{0};
            for (uint32_t contraction = 0;
                 contraction < spec.k; ++contraction) {
                const int64_t av =
                    a[uint64_t{row} * spec.k + contraction];
                const int64_t bv = spec.b.transpose
                    ? b[uint64_t{column} * spec.k +
                        contraction]
                    : b[uint64_t{contraction} * spec.n +
                        column];
                sum += av * bv;
            }
            out[uint64_t{row} * spec.n + column] = sum;
        }
    }
    return out;
}

struct NativeEpisode {
    std::vector<
        rc::RCStage3EpisodeGemmLayerWitness> witnesses;
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>>
        extract_inputs;
    std::vector<ha::TileTreeManifest> trees;
    std::vector<uint256> round_roots;
    std::vector<rc::RCStage3GemmExtractLayerBindings> bindings;
};

bool BuildNativeEpisode(
    const CBlockHeader& header,
    const rc::RCStage3SuccinctProof& statement,
    const rc::RCEpisodeParams& params,
    NativeEpisode& out,
    std::string* why)
{
    out = {};
    const auto layout = rc::RCGkrTraceLayout(params);
    const std::vector<uint256> provisional_roots(
        params.rounds, H(0x5a));
    const auto provenance = rc::RCGkrEpisodeLayerProvenance(
        header, params, provisional_roots);
    if (provenance.size() != layout.layers.size()) {
        if (why) *why = "native episode provenance count";
        return false;
    }
    out.witnesses.resize(layout.layers.size());
    out.bindings.resize(layout.layers.size());
    std::map<TensorKey, std::vector<int8_t>> tensors;
    std::vector<std::vector<int8_t>> layer_outputs(
        layout.layers.size());
    std::vector<std::vector<uint8_t>> round_streams(
        params.rounds);
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size(); ++ordinal) {
        const auto& spec = layout.layers[ordinal];
        const auto& prov = provenance[ordinal];
        auto materialize =
            [&](const rc::RCGkrOperandRef& identity,
                const rc::RCGkrSampledOperandProv& source) {
                const TensorKey key{
                    identity.first_column, identity.n_chunks};
                const auto found = tensors.find(key);
                if (found != tensors.end()) return found->second;
                std::vector<int8_t> values;
                if (source.is_leaf) {
                    values = ExpandLeaf(source);
                } else if (
                    source.src_idx < layer_outputs.size()) {
                    values = layer_outputs[source.src_idx];
                }
                tensors[key] = values;
                return values;
            };
        auto& witness = out.witnesses[ordinal];
        witness.operand_a =
            materialize(spec.a, prov.a);
        witness.operand_b =
            materialize(spec.b, prov.b);
        if (witness.operand_a.size() !=
                uint64_t{spec.m} * spec.k ||
            witness.operand_b.size() !=
                uint64_t{spec.k} * spec.n) {
            if (why) *why = "native episode leaf shape";
            return false;
        }
        if (spec.residual_first_column >= 0) {
            const auto found = tensors.find({
                static_cast<uint32_t>(
                    spec.residual_first_column),
                spec.out_chunks});
            if (found == tensors.end() ||
                found->second.size() !=
                    uint64_t{spec.m} * spec.n) {
                if (why) *why = "native episode residual";
                return false;
            }
            witness.residual = found->second;
        }
        const auto y = GemmY(
            rc::RCStage3GemmExtractLayerManifest{
                .m = spec.m, .n = spec.n, .k = spec.k,
                .a = spec.a, .b = spec.b},
            witness.operand_a, witness.operand_b);
        std::vector<int8_t> outputs(y.size());
        const uint32_t blocks = spec.n / rc::kRCMxBlockLen;
        for (uint32_t row = 0; row < spec.m; ++row) {
            for (uint32_t block = 0; block < blocks; ++block) {
                std::array<int64_t, rc::kRCMxBlockLen> input{};
                for (uint32_t lane = 0;
                     lane < rc::kRCMxBlockLen; ++lane) {
                    const uint64_t cell =
                        uint64_t{row} * spec.n +
                        block * rc::kRCMxBlockLen + lane;
                    input[lane] = y[cell] +
                        (witness.residual.empty()
                             ? 0 : witness.residual[cell]);
                }
                out.extract_inputs.push_back(input);
                const ga::TilePublic tile_public{
                    prov.extract_prf, row, block};
                const auto tile =
                    ga::TraceTile(tile_public, input);
                for (uint32_t lane = 0;
                     lane < rc::kRCMxBlockLen; ++lane) {
                    const uint64_t cell =
                        uint64_t{row} * spec.n +
                        block * rc::kRCMxBlockLen + lane;
                    outputs[cell] = tile.out[lane];
                    if (rc::RCStage3EpisodeLayerIsStreamed(
                            spec.kind)) {
                        round_streams[spec.round].push_back(
                            static_cast<uint8_t>(tile.out[lane]));
                    }
                }
            }
        }
        layer_outputs[ordinal] = outputs;
        tensors[{spec.out_first_column, spec.out_chunks}] = outputs;
        out.bindings[ordinal].extract_prf =
            prov.extract_prf;
        out.bindings[ordinal].operand_a_root = H(0x31);
        out.bindings[ordinal].operand_b_root = H(0x32);
        out.bindings[ordinal].gemm_y_root = H(0x33);
        out.bindings[ordinal].extract_input_root = H(0x34);
        out.bindings[ordinal].extract_output_root = H(0x35);
        out.bindings[ordinal].gemm_proof_root = H(0x36);
        out.bindings[ordinal].extract_recursive_root = H(0x37);
        out.bindings[ordinal].scale_schedule_root = H(0x38);
        out.bindings[ordinal].ctl_terminal_root = H(0x39);
    }
    out.trees.resize(params.rounds);
    for (uint32_t round = 0; round < params.rounds; ++round) {
        if (!ha::BuildTileTreeManifest(
                round_streams[round], params.T_leaf,
                out.trees[round], why)) {
            return false;
        }
        out.round_roots.push_back(out.trees[round].root);
    }
    return out.extract_inputs.size() ==
        uint64_t{params.rounds} *
            (uint64_t{params.n_q} * params.n_ctx /
                 rc::kRCMxBlockLen +
             uint64_t{params.n_q} * params.d_head /
                 rc::kRCMxBlockLen +
             uint64_t{params.L_lyr} * params.b_seq *
                 (params.d_ff + params.d_model) /
                 rc::kRCMxBlockLen);
}

struct NativeCoupled {
    std::vector<rc::RCStage3CoupledGemmOpening>
        gemm_openings;
    rc::RCStage3CoupledExchangePermutationWitness exchange;
    std::vector<std::vector<int64_t>> mix_inputs;
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>>
        extract_inputs;
    std::vector<std::vector<uint8_t>> barrier_states;
    std::vector<uint8_t> bank_bytes;
    uint256 bank_root{};
    uint256 coupled_digest{};
};

bool BuildNativeCoupled(
    const CBlockHeader& header,
    const rc::RCStage3SuccinctProof& statement,
    const rc::RCStage3CoupledShape& shape,
    NativeCoupled& out,
    std::string* why)
{
    out = {};
    rc::RCStage3CoupledBankProduct bank;
    rc::RCStage3CoupledInitialStateProduct initial;
    if (!rc::BuildRCStage3CoupledBankProduct(
            statement, header, shape, bank, why) ||
        !rc::BuildRCStage3CoupledInitialStateProduct(
            statement, shape, initial, why)) {
        return false;
    }
    for (const auto& page : bank.pages) {
        for (int8_t byte : page.page_bytes) {
            out.bank_bytes.push_back(
                static_cast<uint8_t>(byte));
        }
    }
    std::vector<rc::RCStage3CoupledGemmScheduleEntry>
        gemm_schedule;
    uint256 gemm_schedule_commitment;
    if (!rc::BuildRCStage3CoupledGemmSchedule(
            statement, shape, gemm_schedule,
            gemm_schedule_commitment, why)) {
        return false;
    }
    const auto permutation_schedule =
        rc::BuildRCStage3CoupledPermutationSchedule(
            statement, shape, why);
    const auto extract_schedule =
        rc::BuildRCStage3CoupledExtractSchedule(
            statement, shape, why);
    const uint64_t lobe_cells =
        uint64_t{shape.rows_per_lobe} * shape.lobe_width;
    const uint64_t state_cells =
        uint64_t{shape.lobes} * lobe_cells;
    if (permutation_schedule.size() != shape.barriers ||
        extract_schedule.size() !=
            uint64_t{shape.barriers} * state_cells /
                rc::kRCMxBlockLen) {
        if (why) *why = "native coupled schedule";
        return false;
    }
    out.gemm_openings.resize(gemm_schedule.size());
    out.mix_inputs.assign(
        shape.barriers,
        std::vector<int64_t>(state_cells, 0));
    out.barrier_states.assign(
        shape.barriers,
        std::vector<uint8_t>(state_cells, 0));
    std::vector<int8_t> prior_state;
    uint32_t gemm_cursor{0};
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        std::vector<int64_t> permutation_input;
        permutation_input.reserve(state_cells);
        for (uint32_t lobe = 0; lobe < shape.lobes; ++lobe) {
            if (gemm_cursor >= gemm_schedule.size() ||
                gemm_schedule[gemm_cursor].barrier != barrier ||
                gemm_schedule[gemm_cursor].lobe != lobe) {
                if (why) *why = "native coupled gemm order";
                return false;
            }
            auto& opening = out.gemm_openings[gemm_cursor];
            if (barrier == 0) {
                opening.operand_a.assign(
                    initial.lobes[lobe].expanded_tile.begin(),
                    initial.lobes[lobe].expanded_tile.begin() +
                        lobe_cells);
            } else {
                const uint64_t begin = uint64_t{lobe} * lobe_cells;
                opening.operand_a.assign(
                    prior_state.begin() + begin,
                    prior_state.begin() + begin + lobe_cells);
            }
            const uint32_t page_id =
                gemm_schedule[gemm_cursor].page_id;
            if (page_id >= bank.pages.size()) {
                if (why) *why = "native coupled bank page";
                return false;
            }
            opening.operand_b =
                bank.pages[page_id].page_bytes;
            opening.output_y.assign(lobe_cells, 0);
            for (uint32_t row = 0;
                 row < shape.rows_per_lobe; ++row) {
                for (uint32_t column = 0;
                     column < shape.lobe_width; ++column) {
                    for (uint32_t k = 0;
                         k < shape.lobe_width; ++k) {
                        opening.output_y[
                            uint64_t{row} *
                                shape.lobe_width +
                            column] +=
                            int64_t{opening.operand_a[
                                uint64_t{row} *
                                    shape.lobe_width + k]} *
                            int64_t{opening.operand_b[
                                uint64_t{k} *
                                    shape.lobe_width +
                                column]};
                    }
                }
            }
            permutation_input.insert(
                permutation_input.end(),
                opening.output_y.begin(),
                opening.output_y.end());
            out.exchange.fixed_exchange_inputs.push_back(
                opening.output_y);
            ++gemm_cursor;
        }
        out.exchange.permutation_inputs.push_back(
            permutation_input);
        const auto& schedule = permutation_schedule[barrier];
        rc::RCCoupProofFriendlyPermutationSpec perm;
        perm.n = schedule.value_count;
        perm.bits = schedule.index_bits;
        perm.out_to_in_bit = schedule.out_to_in_bit;
        perm.xor_mask_bit = schedule.xor_mask_bit;
        auto& mix_input = out.mix_inputs[barrier];
        for (uint32_t i = 0; i < permutation_input.size(); ++i) {
            const uint32_t destination =
                rc::ApplyCoupledProofFriendlyPermutationIndex(
                    i, perm);
            if (destination >= mix_input.size()) {
                if (why) *why = "native coupled permutation";
                return false;
            }
            mix_input[destination] = permutation_input[i];
        }
        rc::RCStage3CoupledMixProduct structural_mix;
        if (!rc::BuildRCStage3CoupledMixProduct(
                statement, shape, out.mix_inputs,
                structural_mix, why)) {
            return false;
        }
        const auto& mixed = structural_mix.output_states[barrier];
        prior_state.assign(state_cells, 0);
        const uint32_t tiles =
            state_cells / rc::kRCMxBlockLen;
        for (uint32_t tile = 0; tile < tiles; ++tile) {
            const auto schedule_it = std::find_if(
                extract_schedule.begin(), extract_schedule.end(),
                [barrier, tile](const auto& entry) {
                    return entry.barrier == barrier &&
                        entry.tile == tile;
                });
            if (schedule_it == extract_schedule.end()) {
                if (why) *why = "native coupled extract order";
                return false;
            }
            std::array<int64_t, rc::kRCMxBlockLen> input{};
            std::copy_n(
                mixed.begin() +
                    uint64_t{tile} * rc::kRCMxBlockLen,
                rc::kRCMxBlockLen, input.begin());
            out.extract_inputs.push_back(input);
            const ga::TilePublic tile_public{
                schedule_it->extract_prf, 0, tile};
            const auto witness =
                ga::TraceTile(tile_public, input);
            std::copy(
                witness.out.begin(), witness.out.end(),
                prior_state.begin() +
                    uint64_t{tile} * rc::kRCMxBlockLen);
        }
        for (uint32_t i = 0; i < state_cells; ++i) {
            out.barrier_states[barrier][i] =
                static_cast<uint8_t>(prior_state[i]);
        }
    }
    if (gemm_cursor != gemm_schedule.size()) {
        if (why) *why = "native coupled gemm coverage";
        return false;
    }
    rc::RCStage3CoupledBankRootManifest bank_manifest;
    if (!rc::BuildRCStage3CoupledBankRootManifest(
            statement, shape, out.bank_bytes,
            bank_manifest, why)) {
        return false;
    }
    out.bank_root = bank_manifest.bank_root;
    std::vector<uint256> barrier_roots;
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        ha::CoupledBarrierManifest manifest;
        if (!ha::BuildCoupledBarrierManifest(
                shape.transcript_version, shape.barriers,
                barrier, out.barrier_states[barrier],
                manifest, why)) {
            return false;
        }
        barrier_roots.push_back(manifest.direct.digest);
    }
    ha::CoupledDigestManifest digest;
    if (!ha::BuildCoupledDigestManifest(
            shape.transcript_version, shape.barriers,
            out.bank_root, barrier_roots, digest, why)) {
        return false;
    }
    out.coupled_digest = digest.direct.digest;
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_bounded_semantic_composition_tests)

BOOST_AUTO_TEST_CASE(coupled_range_value_root_is_the_gemm_y_opening)
{
    const auto statement = Statement();
    const auto shape = Shape();
    rc::RCStage3CoupledSignedRangeExecution range;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledSignedRangeManifest(
            statement, shape, range.manifest, &why),
        why);
    BOOST_REQUIRE_EQUAL(range.manifest.total_output_cells, 128U);
    BOOST_REQUIRE_EQUAL(range.manifest.shard_count, 1U);

    rc::RCStage3CoupledGemmProduct gemm;
    gemm.gemms.resize(range.manifest.scheduled_gemms);
    std::vector<int64_t> all_values;
    for (uint32_t instance = 0;
         instance < gemm.gemms.size(); ++instance) {
        auto& values = gemm.gemms[instance].output_y;
        values.resize(shape.rows_per_lobe * shape.lobe_width);
        for (uint32_t i = 0; i < values.size(); ++i) {
            values[i] = static_cast<int64_t>(instance * 17 + i) - 40;
        }
        all_values.insert(
            all_values.end(), values.begin(), values.end());
    }

    range.shards.resize(1);
    auto& shard = range.shards[0];
    BOOST_REQUIRE_MESSAGE(
        rc::MakeRCStage3CoupledSignedRangePin(
            range.manifest, 0, shard.pin, &why),
        why);
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3SignedRangeColumns(
            shard.pin, all_values, columns, &why),
        why);
    for (uint32_t column = 0; column < columns.size(); ++column) {
        shard.pin.column_roots[column].root =
            aq::AirCommittedValuesRoot<gf::Fp3>(
                columns[column], shard.pin.n_rows);
    }
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledSignedRangeGemmValueEquality(
            gemm, range, &why),
        why);

    auto changed_gemm = gemm;
    ++changed_gemm.gemms[2].output_y[7];
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledSignedRangeGemmValueEquality(
            changed_gemm, range, &why));

    auto changed_root = range;
    changed_root.shards[0]
        .pin.column_roots[rc::kRCStage3RangeValue].root = H(0x91);
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledSignedRangeGemmValueEquality(
            gemm, changed_root, &why));

    auto omitted = gemm;
    omitted.gemms.pop_back();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledSignedRangeGemmValueEquality(
            omitted, range, &why));

    auto oversized_pin = range;
    oversized_pin.shards[0].pin.n_rows =
        std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(
        !rc::ValidateRCStage3CoupledSignedRangeGemmValueEquality(
            gemm, oversized_pin, &why));

    rc::RCStage3CoupledSignedRangeExecution proved;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledSignedRangeGemmLink(
            statement, shape, gemm, proved, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledSignedRangeGemmLink(
            statement, shape, gemm, proved, &why),
        why);
    auto changed_proof_value = gemm;
    ++changed_proof_value.gemms[0].output_y[0];
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledSignedRangeGemmLink(
            statement, shape, changed_proof_value, proved, &why));
}

BOOST_AUTO_TEST_CASE(episode_range_value_root_is_the_gemm_y_opening)
{
    const auto manifest = EpisodeManifest();
    rc::RCStage3EpisodeGemmProduct gemm;
    gemm.layers.resize(manifest.layers.size());
    std::vector<rc::RCStage3SignedRangeShardProof> range;
    std::string why;
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const auto& spec = manifest.layers[layer];
        auto& gemm_layer = gemm.layers[layer];
        gemm_layer.layer_ordinal = layer;
        gemm_layer.gemm_y.resize(spec.gemm_cell_count);
        for (uint32_t i = 0; i < gemm_layer.gemm_y.size(); ++i) {
            gemm_layer.gemm_y[i] =
                static_cast<int64_t>((layer * 19 + i) % 127) - 63;
        }
        const uint32_t shard_count = static_cast<uint32_t>(
            (spec.gemm_cell_count +
             rc::kRCStage3SignedRangeMaxShardRows - 1U) /
            rc::kRCStage3SignedRangeMaxShardRows);
        for (uint32_t shard_index = 0;
             shard_index < shard_count; ++shard_index) {
            const auto pin = rc::MakeRCStage3SignedRangePin(
                manifest, layer, shard_index, &why);
            BOOST_REQUIRE_MESSAGE(pin.has_value(), why);
            range.emplace_back();
            auto& shard = range.back();
            shard.pin = *pin;
            const uint64_t begin =
                static_cast<uint64_t>(shard_index) *
                rc::kRCStage3SignedRangeMaxShardRows;
            std::vector<int64_t> values(
                gemm_layer.gemm_y.begin() + begin,
                gemm_layer.gemm_y.begin() + begin +
                    shard.pin.logical_rows);
            std::vector<std::vector<gf::Fp3>> columns;
            BOOST_REQUIRE_MESSAGE(
                rc::BuildRCStage3SignedRangeColumns(
                    shard.pin, values, columns, &why),
                why);
            for (uint32_t column = 0;
                 column < columns.size(); ++column) {
                shard.pin.column_roots[column].root =
                    aq::AirCommittedValuesRoot<gf::Fp3>(
                        columns[column], shard.pin.n_rows);
            }
        }
    }
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
            manifest, gemm, range, &why),
        why);

    auto changed_gemm = gemm;
    ++changed_gemm.layers.back().gemm_y.back();
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
            manifest, changed_gemm, range, &why));

    auto changed_root = range;
    changed_root.back()
        .pin.column_roots[rc::kRCStage3RangeValue].root = H(0x92);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
            manifest, gemm, changed_root, &why));

    auto omitted = range;
    omitted.pop_back();
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
            manifest, gemm, omitted, &why));

    auto oversized_pin = range;
    oversized_pin[0].pin.n_rows =
        std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
            manifest, gemm, oversized_pin, &why));

    std::vector<rc::RCStage3SignedRangeShardProof> proved;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeSignedRangeGemmLink(
            manifest, gemm, proved, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeSignedRangeGemmLink(
            manifest, gemm, proved, &why),
        why);
    auto changed_proof_value = gemm;
    ++changed_proof_value.layers[0].gemm_y[0];
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeSignedRangeGemmLink(
            manifest, changed_proof_value, proved, &why));
}

BOOST_AUTO_TEST_CASE(
    aggregate_cannot_reach_inventory_without_executing_typed_children)
{
    auto header = Header();
    auto statement = BoundStatement(header);
    header.matmul_digest = statement.public_inputs.final_digest;
    rc::RCStage3BoundedSemanticComposition empty;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CompositionLink(statement, &why),
        why);
    BOOST_CHECK(!rc::VerifyRCStage3BoundedSemanticComposition(
        statement, header, rc::MakeToyRCEpisodeParams(),
        Shape(), empty, &why));
    BOOST_CHECK_MESSAGE(
        why.find("typed_sidecar_binding") != std::string::npos,
        why);
    BOOST_CHECK(!rc::kRCStage3BoundedSemanticCompositionAuthorityReady);
    BOOST_CHECK(
        !rc::kRCStage3BoundedSemanticCompositionRecursivelyConsumed);
    BOOST_CHECK(
        !rc::kRCStage3BoundedSemanticCompositionDurablySerialized);
    auto finalize_statement = statement;
    const auto original_transcript =
        finalize_statement.public_inputs.transcript_commitment;
    BOOST_CHECK(
        !rc::FinalizeRCStage3BoundedSemanticComposition(
            finalize_statement, header,
            rc::MakeToyRCEpisodeParams(), Shape(), empty, &why));
    BOOST_CHECK_MESSAGE(
        why.find("finalize_binding") != std::string::npos,
        why);
    BOOST_CHECK(
        finalize_statement.public_inputs.transcript_commitment ==
        original_transcript);
}

BOOST_AUTO_TEST_CASE(
    positive_fixture_plan_is_exact_and_fail_closed_on_missing_provers)
{
    auto header = Header();
    auto statement = BoundStatement(header);
    header.matmul_digest = statement.public_inputs.final_digest;
    rc::RCStage3BoundedSemanticBuildPlan plan;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3BoundedSemanticProverPlan(
            statement, header, EpisodeParams(),
            Shape(), plan, &why),
        why);

    BOOST_CHECK_EQUAL(plan.episode_layers, 4U);
    BOOST_CHECK_EQUAL(plan.episode_gemm_tiles, 128U);
    BOOST_CHECK_EQUAL(plan.episode_extract_tiles, 128U);
    BOOST_CHECK_EQUAL(plan.episode_stream_tiles, 64U);
    BOOST_CHECK_GT(plan.episode_wiring_edges, 0U);
    BOOST_CHECK_EQUAL(plan.episode_signed_range_shards, 4U);
    BOOST_CHECK_EQUAL(plan.coupled_bank_pages, 1U);
    BOOST_CHECK_EQUAL(plan.coupled_initial_lobes, 1U);
    BOOST_CHECK_EQUAL(plan.coupled_gemms, 4U);
    BOOST_CHECK_EQUAL(plan.coupled_signed_range_shards, 1U);
    BOOST_CHECK_EQUAL(plan.coupled_exchange_stages, 4U);
    BOOST_CHECK_EQUAL(plan.coupled_permutation_stages, 4U);
    BOOST_CHECK_EQUAL(plan.coupled_mix_barriers, 4U);
    BOOST_CHECK_EQUAL(plan.coupled_extract_tiles, 4U);
    BOOST_CHECK_EQUAL(plan.coupled_root_barriers, 4U);
    BOOST_REQUIRE_EQUAL(plan.families.size(), 23U);

    BOOST_CHECK(plan.missing_product_orchestrators.empty());
    BOOST_CHECK(plan.positive_fixture_buildable);
    BOOST_CHECK_MESSAGE(
        why.find("missing_product_orchestrators=") !=
            std::string::npos,
        why);

    auto changed_header = header;
    changed_header.hashPrevBlock = H(0x99);
    BOOST_CHECK(
        !rc::BuildRCStage3BoundedSemanticProverPlan(
            statement, changed_header, EpisodeParams(), Shape(),
            plan, &why));

    auto changed_statement = statement;
    changed_statement.statement =
        rc::RCStage3StatementKind::Episode;
    BOOST_CHECK(
        !rc::BuildRCStage3BoundedSemanticProverPlan(
            changed_statement, header, EpisodeParams(), Shape(),
            plan, &why));
}

BOOST_AUTO_TEST_CASE(
    native_complete_fixture_closes_episode_and_coupled_digests)
{
    auto header = Header();
    auto statement = BoundStatement(header);
    const auto params = EpisodeParams();
    auto shape = Shape();
    shape.exchange_rounds = 0;
    std::string why;
    NativeEpisode episode;
    BOOST_REQUIRE_MESSAGE(
        BuildNativeEpisode(
            header, statement, params, episode, &why),
        why);
    statement.public_inputs.episode_digest =
        rc::RCGkrEpisodeDigestFromRoots(episode.round_roots);
    NativeCoupled coupled;
    BOOST_REQUIRE_MESSAGE(
        BuildNativeCoupled(
            header, statement, shape, coupled, &why),
        why);
    statement.public_inputs.coupled_digest =
        coupled.coupled_digest;
    statement.public_inputs.final_digest =
        rc::ComputeRCStage3FinalDigest(statement);
    statement.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(statement);
    header.matmul_digest =
        statement.public_inputs.final_digest;
    BOOST_CHECK(
        statement.public_inputs.header_commitment ==
        rc::RCStage3HeaderCommitment(header));
    BOOST_CHECK(
        statement.public_inputs.sigma ==
        matmul::v4::DeriveSigma(header));
    BOOST_CHECK_EQUAL(episode.witnesses.size(), 4U);
    BOOST_CHECK_EQUAL(episode.extract_inputs.size(), 128U);
    BOOST_CHECK_EQUAL(coupled.gemm_openings.size(), 4U);
    BOOST_CHECK_EQUAL(coupled.extract_inputs.size(), 4U);
    BOOST_CHECK_EQUAL(coupled.barrier_states.size(), 4U);
    BOOST_CHECK(!coupled.bank_root.IsNull());
    BOOST_CHECK(!coupled.coupled_digest.IsNull());
}

BOOST_AUTO_TEST_CASE(
    complete_23_family_bounded_positive_aggregate_optional)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_BOUNDED_COMPLETE_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_BOUNDED_COMPLETE_PROVE=1 for "
            "the complete 23-family/52-endpoint aggregate");
        return;
    }
    auto header = Header();
    const auto params = EpisodeParams();
    auto shape = Shape();
    shape.exchange_rounds = 0;
    std::string why;

    NativeEpisode native_episode;
    rc::RCStage3SuccinctProof statement;
    bool found_pow{false};
    for (uint32_t attempt = 0; attempt < 32; ++attempt) {
        header.nNonce64 = 10 + attempt;
        statement = BoundStatement(header);
        if (!BuildNativeEpisode(
                header, statement, params,
                native_episode, &why)) {
            BOOST_FAIL(why);
            return;
        }
        statement.public_inputs.episode_digest =
            rc::RCGkrEpisodeDigestFromRoots(
                native_episode.round_roots);
        if (UintToArith256(
                statement.public_inputs.episode_digest) <=
            UintToArith256(statement.public_inputs.target)) {
            found_pow = true;
            break;
        }
    }
    BOOST_REQUIRE(found_pow);

    NativeCoupled native_coupled;
    BOOST_REQUIRE_MESSAGE(
        BuildNativeCoupled(
            header, statement, shape,
            native_coupled, &why),
        why);
    statement.public_inputs.coupled_digest =
        native_coupled.coupled_digest;
    statement.public_inputs.final_digest =
        rc::ComputeRCStage3FinalDigest(statement);
    statement.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(statement);
    header.matmul_digest =
        statement.public_inputs.final_digest;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CompositionLink(statement, &why),
        why);
    BOOST_REQUIRE(
        statement.public_inputs.header_commitment ==
        rc::RCStage3HeaderCommitment(header));
    BOOST_REQUIRE(
        statement.public_inputs.sigma ==
        matmul::v4::DeriveSigma(header));

    rc::RCStage3BoundedSemanticComposition composition;
    using BuildFamily =
        rc::RCStage3BoundedSemanticBuildFamily;
    constexpr size_t kBuildFamilyCount =
        static_cast<size_t>(
            BuildFamily::BoundedAggregateVerifier) +
        1U;
    std::array<int64_t, kBuildFamilyCount> family_prove_us{};
    std::array<bool, kBuildFamilyCount> family_prove_recorded{};
    const auto prove_all_start =
        std::chrono::steady_clock::now();
    const auto timed_prove =
        [&](std::initializer_list<BuildFamily> families,
            auto&& operation) {
            const auto start =
                std::chrono::steady_clock::now();
            const bool accepted = operation();
            const auto elapsed_us =
                std::chrono::duration_cast<
                    std::chrono::microseconds>(
                    std::chrono::steady_clock::now() -
                    start)
                    .count();
            for (const auto family : families) {
                const size_t index =
                    static_cast<size_t>(family);
                BOOST_REQUIRE_LT(index, kBuildFamilyCount);
                BOOST_REQUIRE(
                    !family_prove_recorded[index]);
                family_prove_recorded[index] = true;
                family_prove_us[index] = elapsed_us;
                BOOST_TEST_MESSAGE(
                    "STAGE3_COMPLETE_FAMILY"
                    << " family="
                    << rc::RCStage3BoundedSemanticBuildFamilyName(
                           family)
                    << " prove_us=" << elapsed_us
                    << " accepted=" << accepted
                    << " shared_prover_operation="
                    << (families.size() > 1U));
            }
            return accepted;
        };
    auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, rc::RCStage3EpisodeStatementCommitment(statement),
        native_episode.bindings, &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    composition.episode.gemm_extract_manifest = *manifest;

    BOOST_TEST_MESSAGE(
        "complete aggregate: proving episode roots and builder");
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeDigestRootChain}, [&] {
                return
                    rc::ProveRCStage3EpisodeDigestRootChain(
                        statement, params.rounds,
                        native_episode.round_roots,
                        composition.episode.root_chain,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeSeedChain}, [&] {
                return
                    rc::ProveRCStage3EpisodeBuilderSeedChainProduct(
                        statement, params,
                        composition.episode.root_chain.manifest,
                        composition.episode.seed_chain,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeOperandXof}, [&] {
                return
                    rc::ProveRCStage3EpisodeBuilderOperandXofProduct(
                        statement, params,
                        composition.episode.seed_chain,
                        composition.episode.operand_xof,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeBuilderTrace}, [&] {
                return
                    rc::ProveRCStage3EpisodeBuilderTraceProduct(
                        statement, params,
                        composition.episode.seed_chain.params_product,
                        composition.episode.seed_chain,
                        composition.episode.operand_xof,
                        composition.episode.builder_trace,
                        &why);
            }),
        why);
    std::vector<rc::RCStage3EpisodeBuilderTraceLeafOpening>
        leaf_openings;
    BOOST_REQUIRE_MESSAGE(
        rc::MaterializeRCStage3EpisodeBuilderTraceLeafOpenings(
            statement, params,
            composition.episode.seed_chain.params_product,
            composition.episode.seed_chain,
            composition.episode.operand_xof,
            composition.episode.builder_trace,
            leaf_openings, &why),
        why);
    std::map<TensorKey, std::vector<int8_t>> leaf_values;
    for (const auto& opening : leaf_openings) {
        leaf_values[{
            opening.first_column, opening.n_chunks}] =
            opening.values;
    }
    const auto layout = rc::RCGkrTraceLayout(params);
    for (uint32_t ordinal = 0;
         ordinal < layout.layers.size(); ++ordinal) {
        const auto& spec = layout.layers[ordinal];
        const auto a = leaf_values.find({
            spec.a.first_column, spec.a.n_chunks});
        if (a != leaf_values.end()) {
            BOOST_REQUIRE(
                native_episode.witnesses[ordinal].operand_a ==
                a->second);
        }
        const auto b = leaf_values.find({
            spec.b.first_column, spec.b.n_chunks});
        if (b != leaf_values.end()) {
            BOOST_REQUIRE(
                native_episode.witnesses[ordinal].operand_b ==
                b->second);
        }
    }
    BOOST_TEST_MESSAGE(
        "complete aggregate: proving vertical Extract and tile streams");
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeExtract,
             BuildFamily::EpisodeTileStream},
            [&] {
                return
                    rc::ProveRCStage3EpisodeExtractAndTileStreamProductsVertical(
                        statement,
                        composition.episode.gemm_extract_manifest,
                        native_episode.extract_inputs,
                        composition.episode.extract,
                        composition.episode.tile_stream,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeGemm}, [&] {
                return
                    rc::ProveRCStage3EpisodeGemmProduct(
                        statement,
                        composition.episode.gemm_extract_manifest,
                        native_episode.witnesses,
                        composition.episode.extract,
                        composition.episode.tile_stream,
                        composition.episode.gemm,
                        &why);
            }),
        why);
    BOOST_TEST_MESSAGE(
        "complete aggregate: closing episode links and root producers");
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeSignedRange}, [&] {
                return
                    rc::ProveRCStage3EpisodeSignedRangeGemmLink(
                        composition.episode.gemm_extract_manifest,
                        composition.episode.gemm,
                        composition.episode.signed_range,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeWiring}, [&] {
                return
                    rc::BuildRCStage3EpisodeWiringProduct(
                        statement,
                        composition.episode.gemm_extract_manifest,
                        composition.episode.gemm,
                        composition.episode.extract,
                        composition.episode.wiring,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeRoundRoots}, [&] {
                return
                    rc::ProveRCStage3EpisodeRoundRootProducerProduct(
                        statement, params.rounds,
                        composition.episode.root_chain,
                        native_episode.trees,
                        composition.episode.round_root_producers,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodeHeaderTarget}, [&] {
                return
                    rc::ProveRCStage3EpisodeHeaderTargetProduct(
                        statement,
                        composition.episode.header_target,
                        &why);
            }),
        why);
    const auto pow_pin =
        rc::BuildRCStage3EpisodePowPin(statement, &why);
    BOOST_REQUIRE_MESSAGE(pow_pin.has_value(), why);
    composition.episode.pow_pin = *pow_pin;
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::EpisodePow}, [&] {
                return rc::ProveRCStage3EpisodePow(
                    statement,
                    composition.episode.pow_proof,
                    &why);
            }),
        why);

    BOOST_TEST_MESSAGE(
        "complete aggregate: proving coupled relation families");
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledBank}, [&] {
                return
                    rc::ProveRCStage3CoupledBankProduct(
                        statement, header, shape,
                        composition.coupled.bank,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledInitialState}, [&] {
                return
                    rc::ProveRCStage3CoupledInitialStateProduct(
                        statement, shape,
                        composition.coupled.initial_state,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledGemm}, [&] {
                return
                    rc::ProveRCStage3CoupledGemmProduct(
                        statement, shape,
                        native_coupled.gemm_openings,
                        composition.coupled.gemm,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledSignedRange}, [&] {
                return
                    rc::ProveRCStage3CoupledSignedRangeGemmLink(
                        statement, shape,
                        composition.coupled.gemm,
                        composition.coupled.signed_range,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledExchangePermutation}, [&] {
                return
                    rc::ProveRCStage3CoupledExchangePermutationProduct(
                        statement, shape,
                        native_coupled.exchange,
                        composition.coupled.exchange_permutation,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledMix}, [&] {
                return
                    rc::ProveRCStage3CoupledMixProduct(
                        statement, shape,
                        native_coupled.mix_inputs,
                        composition.coupled.mix,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledExtract}, [&] {
                return
                    rc::ProveRCStage3CoupledExtractProduct(
                        statement, shape,
                        native_coupled.extract_inputs,
                        composition.coupled.extract,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledBankRoot}, [&] {
                return
                    rc::ProveRCStage3CoupledBankRootExecution(
                        statement, shape,
                        native_coupled.bank_bytes,
                        composition.coupled.bank_root,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CoupledRootChain}, [&] {
                return
                    rc::ProveRCStage3CoupledRootChain(
                        statement, shape,
                        native_coupled.bank_root,
                        native_coupled.barrier_states,
                        composition.coupled.root_chain,
                        &why);
            }),
        why);

    BOOST_TEST_MESSAGE(
        "complete aggregate: finalizing all 52 endpoints");
    const auto finalize_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        timed_prove(
            {BuildFamily::CrossProductJoins,
             BuildFamily::BoundedAggregateVerifier},
            [&] {
                return
                    rc::FinalizeRCStage3BoundedSemanticComposition(
                        statement, header, params, shape,
                        composition, &why);
            }),
        why);
    const auto finalize_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            finalize_start)
            .count();

    std::array<int64_t, kBuildFamilyCount> family_verify_us{};
    std::array<bool, kBuildFamilyCount> family_verify_recorded{};
    const auto timed_verify =
        [&](std::initializer_list<BuildFamily> families,
            auto&& operation,
            const char* scope = "isolated_family") {
            const auto start =
                std::chrono::steady_clock::now();
            const bool accepted = operation();
            const auto elapsed_us =
                std::chrono::duration_cast<
                    std::chrono::microseconds>(
                    std::chrono::steady_clock::now() -
                    start)
                    .count();
            for (const auto family : families) {
                const size_t index =
                    static_cast<size_t>(family);
                BOOST_REQUIRE_LT(index, kBuildFamilyCount);
                BOOST_REQUIRE(
                    !family_verify_recorded[index]);
                family_verify_recorded[index] = true;
                family_verify_us[index] = elapsed_us;
                BOOST_TEST_MESSAGE(
                    "STAGE3_COMPLETE_FAMILY_VERIFY"
                    << " family="
                    << rc::RCStage3BoundedSemanticBuildFamilyName(
                           family)
                    << " verify_us=" << elapsed_us
                    << " accepted=" << accepted
                    << " scope=" << scope);
            }
            return accepted;
        };

    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeHeaderTarget},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeHeaderTargetProduct(
                        statement,
                        rc::RCStage3HeaderCommitment(header),
                        header.nBits,
                        statement.public_inputs.target,
                        composition.episode.header_target, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeSeedChain},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
                        statement, params,
                        composition.episode.seed_chain, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeOperandXof},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeBuilderOperandXofProduct(
                        statement, params,
                        composition.episode.seed_chain,
                        composition.episode.operand_xof, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeBuilderTrace},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeBuilderTraceProduct(
                        statement, params,
                        composition.episode.seed_chain.params_product,
                        composition.episode.seed_chain,
                        composition.episode.operand_xof,
                        composition.episode.builder_trace, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeGemm},
            [&] {
                return rc::VerifyRCStage3EpisodeGemmProduct(
                    statement,
                    composition.episode.gemm_extract_manifest,
                    composition.episode.gemm,
                    composition.episode.extract, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeSignedRange},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeSignedRangeGemmLink(
                        composition.episode.gemm_extract_manifest,
                        composition.episode.gemm,
                        composition.episode.signed_range, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeExtract},
            [&] {
                return rc::VerifyRCStage3EpisodeExtractProduct(
                    statement,
                    composition.episode.gemm_extract_manifest,
                    composition.episode.extract,
                    composition.episode.tile_stream, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeTileStream},
            [&] {
                return rc::VerifyRCStage3EpisodeTileStreamProduct(
                    statement,
                    composition.episode.gemm_extract_manifest,
                    composition.episode.tile_stream, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeWiring},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeWiringLocalProduct(
                        statement,
                        composition.episode.gemm_extract_manifest,
                        composition.episode.gemm,
                        composition.episode.extract,
                        composition.episode.wiring, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeRoundRoots},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeRoundRootProducerProduct(
                        statement, params.rounds,
                        composition.episode.root_chain.manifest,
                        composition.episode.root_chain.round_roots_pin,
                        composition.episode.root_chain.round_roots_proof,
                        composition.episode.round_root_producers,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodeDigestRootChain},
            [&] {
                return
                    rc::VerifyRCStage3EpisodeDigestRootChain(
                        statement, params.rounds,
                        composition.episode.root_chain, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::EpisodePow},
            [&] {
                return rc::VerifyRCStage3EpisodePow(
                    statement, composition.episode.pow_pin,
                    composition.episode.pow_proof, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledBank},
            [&] {
                return rc::VerifyRCStage3CoupledBankProduct(
                    statement, header, shape,
                    composition.coupled.bank, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledInitialState},
            [&] {
                return
                    rc::VerifyRCStage3CoupledInitialStateProduct(
                        statement, shape,
                        composition.coupled.initial_state, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledGemm},
            [&] {
                return rc::VerifyRCStage3CoupledGemmProduct(
                    statement, shape,
                    composition.coupled.gemm, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledSignedRange},
            [&] {
                return
                    rc::VerifyRCStage3CoupledSignedRangeGemmLink(
                        statement, shape,
                        composition.coupled.gemm,
                        composition.coupled.signed_range, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledExchangePermutation},
            [&] {
                return
                    rc::VerifyRCStage3CoupledExchangePermutationProduct(
                        statement, shape,
                        composition.coupled.exchange_permutation,
                        &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledMix},
            [&] {
                return rc::VerifyRCStage3CoupledMixProduct(
                    statement, shape,
                    composition.coupled.mix, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledExtract},
            [&] {
                return rc::VerifyRCStage3CoupledExtractProduct(
                    statement, shape,
                    composition.coupled.extract, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledBankRoot},
            [&] {
                return
                    rc::VerifyRCStage3CoupledBankRootExecution(
                        statement, shape,
                        composition.coupled.bank_root, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CoupledRootChain},
            [&] {
                return rc::VerifyRCStage3CoupledRootChain(
                    statement, shape,
                    composition.coupled.root_chain, &why);
            }),
        why);
    BOOST_REQUIRE_MESSAGE(
        timed_verify(
            {BuildFamily::CrossProductJoins,
             BuildFamily::BoundedAggregateVerifier},
            [&] {
                return
                    rc::VerifyRCStage3BoundedSemanticComposition(
                        statement, header, params, shape,
                        composition, &why);
            },
            "complete_aggregate_shared_cross_join_seams"),
        why);

    const auto& graph =
        rc::CurrentRCStage3ProvenanceGraphAudit();
    BOOST_REQUIRE_EQUAL(graph.nodes.size(), 52U);
    BOOST_REQUIRE_EQUAL(graph.edges, 81U);
    BOOST_REQUIRE_EQUAL(graph.value_equality_edges, 81U);
    BOOST_REQUIRE_EQUAL(graph.bounded_composition_edges, 81U);
    BOOST_REQUIRE(graph.exact_52_order);
    BOOST_REQUIRE(graph.exact_public_roots_1_and_25);
    BOOST_REQUIRE(
        graph.every_non_public_node_has_a_producer);
    BOOST_REQUIRE(
        graph.no_missing_out_of_range_self_or_duplicate_producer);
    BOOST_REQUIRE_EQUAL(
        why,
        "stage3:bounded_semantic_composition:"
        "52_bounded_endpoint_sidecars_executed;"
        "81_guarded_immediate_edge_obligations_covered;"
        "production_and_recursion_disabled");
    BOOST_REQUIRE_EQUAL(
        std::count(
            family_prove_recorded.begin(),
            family_prove_recorded.end(), true),
        23);
    BOOST_REQUIRE_EQUAL(
        std::count(
            family_verify_recorded.begin(),
            family_verify_recorded.end(), true),
        23);
    BOOST_REQUIRE(
        !rc::kRCStage3BoundedSemanticCompositionProductionExecutable);
    BOOST_REQUIRE(
        !rc::kRCStage3BoundedSemanticCompositionRecursivelyConsumed);
    BOOST_REQUIRE(
        !rc::kRCStage3BoundedSemanticCompositionDurablySerialized);
    BOOST_REQUIRE(
        !rc::kRCStage3BoundedSemanticCompositionAuthorityReady);
    const int64_t verify_us =
        family_verify_us[static_cast<size_t>(
            BuildFamily::BoundedAggregateVerifier)];
    const auto prove_all_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            finalize_start - prove_all_start)
            .count();
    BOOST_TEST_MESSAGE(
        "STAGE3_COMPLETE_AGGREGATE"
        << " prove_us=" << prove_all_us
        << " finalize_us=" << finalize_us
        << " verify_us=" << verify_us
        << " prove_family_records=23"
        << " verify_family_records=23"
        << " semantic_endpoints=52"
        << " producer_edges=81"
        << " split_rap_backend=0"
        << " legacy_air_quotient_sidecars=1"
        << " bounded_execution_only=1"
        << " typed_sidecar_proof_bytes=unavailable"
        << " durable_serializer=0"
        << " authority_ready=0");
}

BOOST_AUTO_TEST_SUITE_END()
