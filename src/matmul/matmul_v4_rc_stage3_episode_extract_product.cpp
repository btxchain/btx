// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_map>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ga = gkr_air;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr uint32_t GOLDEN = 0x9E3779B9U;
constexpr uint32_t MX_BLOCK_LANE = 0x4D58424CU;
constexpr char SCALE_TAG[] = "BTX_MATEXPAND_MXSCALE_V44LT";
constexpr char MIX_PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_MIX_PIN_V1";
constexpr char MIX_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_MIX_AIR_V1";
constexpr char INPUT_TILE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_INPUT_TILE_V1";
constexpr char INPUT_LAYER_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_INPUT_LAYER_V1";
constexpr char SCALE_LAYER_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_SCALE_LAYER_V1";
constexpr char RECURSIVE_LAYER_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_RECURSIVE_LAYER_V1";
constexpr char TILE_RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_TILE_RECEIPT_V1";
constexpr char COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_PRODUCT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_extract_product:" + detail;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Episode ||
           statement.statement == RCStage3StatementKind::Composed;
}

std::vector<uint8_t> ScalePreimage(
    const uint256& prf, uint32_t row, uint32_t block)
{
    std::vector<uint8_t> out(
        SCALE_TAG, SCALE_TAG + sizeof(SCALE_TAG) - 1);
    out.insert(out.end(), prf.begin(), prf.end());
    for (uint32_t value : {row, block}) {
        for (unsigned i = 0; i < 4; ++i) {
            out.push_back(value >> (8 * i));
        }
    }
    return out;
}

uint32_t ExtractNextPowerOfTwo(uint64_t value)
{
    if (value < 2 || value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 2;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

void FillExtractBits(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t begin,
    uint32_t row,
    uint32_t value)
{
    for (uint32_t bit = 0;
         bit < kRCStage3EpisodeExtractMixBits; ++bit) {
        columns[begin + bit][row] =
            U((value >> bit) & 1U);
    }
}

bool ProveEpisodeMix(
    const uint256& statement_commitment,
    uint32_t layer_ordinal,
    uint64_t layer_tile_index,
    const ga::TileWitness& witness,
    const aq::RcSamplerBuild<Fp3>& sampler,
    RCStage3EpisodeExtractMixPin& pin,
    aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    if (!sampler.ok ||
        sampler.columns.size() != aq::kRcSamplerNumCols ||
        sampler.n_rows < kRCMxBlockLen ||
        witness.cands.size() > sampler.n_rows) {
        return Fail(why, "prove_mix_shape");
    }
    std::vector<std::vector<Fp3>> columns(
        kRCStage3EpisodeExtractMixColumns,
        std::vector<Fp3>(sampler.n_rows, Fp3::Zero()));
    for (uint32_t row = 0; row < sampler.n_rows; ++row) {
        columns[kRCStage3ExtractMixU][row] =
            sampler.columns[aq::kColUMix][row];
        columns[kRCStage3ExtractMixQ][row] =
            sampler.columns[aq::kColGoldQ][row];
        columns[kRCStage3ExtractMixV][row] =
            sampler.columns[aq::kColGoldV][row];
        columns[kRCStage3ExtractMixH][row] =
            sampler.columns[aq::kColH][row];
        if (row >= witness.cands.size()) {
            FillExtractBits(
                columns, kRCStage3ExtractMixQDifferenceBits,
                row, GOLDEN);
            continue;
        }
        const auto& candidate = witness.cands[row];
        columns[kRCStage3ExtractMixBranch][row] =
            U(candidate.branch);
        FillExtractBits(
            columns, kRCStage3ExtractMixYLoBits,
            row, candidate.y_lo);
        FillExtractBits(
            columns, kRCStage3ExtractMixYHiBits,
            row, candidate.y_hi);
        FillExtractBits(
            columns, kRCStage3ExtractMixUBits,
            row, candidate.u_mix);
        FillExtractBits(
            columns, kRCStage3ExtractMixQBits,
            row, candidate.gold_q);
        FillExtractBits(
            columns, kRCStage3ExtractMixVBits,
            row, candidate.gold_v);
        FillExtractBits(
            columns, kRCStage3ExtractMixQDifferenceBits,
            row, GOLDEN - candidate.gold_q);
    }
    pin = {};
    pin.statement_commitment = statement_commitment;
    pin.layer_ordinal = layer_ordinal;
    pin.layer_tile_index = layer_tile_index;
    pin.logical_rows =
        static_cast<uint32_t>(witness.cands.size());
    pin.n_rows = sampler.n_rows;
    pin.n_coeffs = ExtractNextPowerOfTwo(
        3 * uint64_t{sampler.n_rows} - 3);
    if (pin.n_coeffs == 0) {
        return Fail(why, "prove_mix_n_coeffs");
    }
    pin.column_roots.resize(columns.size());
    for (uint32_t column = 0; column < columns.size(); ++column) {
        pin.column_roots[column] = {
            column,
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], pin.n_coeffs)};
    }
    pin.pin_commitment =
        ComputeRCStage3EpisodeExtractMixPinCommitment(pin);
    aq::AirConstraintSystem<Fp3> cs;
    if (pin.pin_commitment.IsNull() ||
        !BuildRCStage3EpisodeExtractMixConstraintSystem(
            pin, cs, why)) {
        return Fail(why, "prove_mix_pin");
    }
    auto proved = aq::AirQuotientProve<Fp3>(
        cs, columns, ComputeRCStage3EpisodeExtractMixSeed(pin));
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, proved.note.empty()
                ? "prove_mix_quotient"
                : proved.note);
    }
    proof = std::move(proved.proof);
    return true;
}

bool ProveEpisodeHashExecution(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const ha::FixedProgram& program,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    RCStage3EpisodeExtractHashExecution& out,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!hs::ProveFlatBoundaryProofBundle(
            endpoint, statement_commitment,
            manifest_commitment, program, boundaries,
            out.proofs, why) ||
        !ProveRCStage3EpisodeHashSemanticBinding(
            statement, endpoint, boundaries,
            hs::BoundaryPort::ExternalThenFinal,
            out.binding, why)) {
        return Fail(why, "prove_hash_execution");
    }
    return true;
}

uint256 ValuesRoot(
    const std::vector<Fp3>& values, uint32_t n_coeffs)
{
    return aq::AirCommittedValuesRoot<Fp3>(
        values, n_coeffs);
}

bool ExpectedSamplerPositionRoot(
    const RCStage3EpisodeExtractTileProduct& tile,
    uint256& out,
    std::string* why)
{
    const auto& pin = tile.sampler_pin;
    if (tile.candidate_positions.size() != pin.logical_rows ||
        pin.n_rows < pin.logical_rows) {
        return Fail(why, "candidate_position_shape");
    }
    std::vector<Fp3> values(
        pin.n_rows, U(kRCMxBlockLen));
    for (uint32_t r = 0; r < pin.logical_rows; ++r) {
        if (tile.candidate_positions[r] >= kRCMxBlockLen) {
            return Fail(why, "candidate_position_range");
        }
        values[r] = U(tile.candidate_positions[r]);
    }
    out = ValuesRoot(values, pin.n_coeffs);
    return !out.IsNull() ||
           Fail(why, "candidate_position_root");
}

bool ExpectedSamplerKappaRoot(
    const RCStage3EpisodeExtractTileProduct& tile,
    uint256& out,
    std::string* why)
{
    const auto& pin = tile.sampler_pin;
    const auto& manifest = tile.chacha_manifest;
    if (manifest.output.size() * 2 < pin.logical_rows ||
        pin.n_rows < pin.logical_rows) {
        return Fail(why, "kappa_stream_short");
    }
    std::vector<Fp3> values(pin.n_rows, U(1));
    for (uint32_t r = 0; r < pin.logical_rows; ++r) {
        const uint8_t byte = manifest.output[r / 2];
        const uint8_t nibble =
            (byte >> (4 * (r & 1))) & 0x0f;
        values[r] = U(nibble);
    }
    out = ValuesRoot(values, pin.n_coeffs);
    return !out.IsNull() || Fail(why, "kappa_root");
}

bool ExpectedMixPublicRoots(
    const RCStage3EpisodeExtractTileProduct& tile,
    std::vector<uint256>& expected,
    std::string* why)
{
    const auto& sampler = tile.sampler_pin;
    const auto& pin = tile.mix_pin;
    if (tile.candidate_positions.size() != sampler.logical_rows ||
        pin.logical_rows != sampler.logical_rows ||
        pin.n_rows != sampler.n_rows ||
        pin.n_coeffs != sampler.n_coeffs ||
        pin.column_roots.size() !=
            kRCStage3EpisodeExtractMixColumns) {
        return Fail(why, "mix_public_shape");
    }
    expected.assign(
        kRCStage3EpisodeExtractMixColumns, uint256{});
    expected[kRCStage3ExtractMixU] =
        sampler.column_roots[aq::kColUMix].root;
    expected[kRCStage3ExtractMixQ] =
        sampler.column_roots[aq::kColGoldQ].root;
    expected[kRCStage3ExtractMixV] =
        sampler.column_roots[aq::kColGoldV].root;
    expected[kRCStage3ExtractMixH] =
        sampler.column_roots[aq::kColH].root;

    std::vector<std::vector<uint8_t>> columns(
        1 + 2 * kRCStage3EpisodeExtractMixBits,
        std::vector<uint8_t>(pin.n_rows, 0));
    for (uint32_t r = 0; r < pin.n_rows; ++r) {
        const bool active = r < pin.logical_rows;
        uint64_t raw = 0;
        if (active) {
            const uint8_t pos = tile.candidate_positions[r];
            if (pos >= kRCMxBlockLen) {
                return Fail(why, "mix_position");
            }
            raw = static_cast<uint64_t>(tile.input[pos]);
        }
        const uint32_t lo = static_cast<uint32_t>(raw);
        const uint32_t hi = static_cast<uint32_t>(raw >> 32);
        const bool in_range =
            (hi == 0 && (lo >> 31) == 0) ||
            (hi == UINT32_MAX && (lo >> 31) == 1);
        columns[0][r] = in_range ? 1 : 0;
        for (uint32_t bit = 0;
             bit < kRCStage3EpisodeExtractMixBits; ++bit) {
            columns[1 + bit][r] = (lo >> bit) & 1;
            columns[1 + kRCStage3EpisodeExtractMixBits + bit][r] =
                (hi >> bit) & 1;
        }
    }
    std::unordered_map<std::string, uint256> root_cache;
    const auto binary_root =
        [&](const std::vector<uint8_t>& bits) {
            const std::string key(
                reinterpret_cast<const char*>(bits.data()),
                bits.size());
            const auto found = root_cache.find(key);
            if (found != root_cache.end()) return found->second;
            std::vector<Fp3> values;
            values.reserve(bits.size());
            for (uint8_t bit : bits) values.push_back(U(bit));
            const uint256 root =
                ValuesRoot(values, pin.n_coeffs);
            root_cache.emplace(key, root);
            return root;
        };
    expected[kRCStage3ExtractMixBranch] =
        binary_root(columns[0]);
    for (uint32_t bit = 0;
         bit < kRCStage3EpisodeExtractMixBits; ++bit) {
        expected[kRCStage3ExtractMixYLoBits + bit] =
            binary_root(columns[1 + bit]);
        expected[kRCStage3ExtractMixYHiBits + bit] =
            binary_root(columns[
                1 + kRCStage3EpisodeExtractMixBits + bit]);
    }
    return true;
}

bool TileIdentity(
    const RCStage3GemmExtractLayerManifest& layer,
    uint64_t layer_tile,
    uint32_t& row,
    uint32_t& block,
    std::string* why)
{
    const uint32_t blocks_per_row =
        layer.n / kRCMxBlockLen;
    if (blocks_per_row == 0 ||
        layer_tile >= layer.extract_tile_count) {
        return Fail(why, "tile_geometry");
    }
    row = static_cast<uint32_t>(
        layer_tile / blocks_per_row);
    block = static_cast<uint32_t>(
        layer_tile % blocks_per_row);
    return row < layer.m;
}

uint256 LayerRoot(
    const char* domain,
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& roots)
{
    if (layer_ordinal >= manifest.layers.size()) return {};
    const auto& layer = manifest.layers[layer_ordinal];
    if (layer.ordinal != layer_ordinal ||
        roots.size() != layer.extract_tile_count ||
        roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << domain;
    hash << manifest.statement_commitment;
    hash << layer.ordinal;
    hash << static_cast<uint32_t>(layer.kind);
    hash << layer.round;
    hash << layer.layer;
    hash << layer.m;
    hash << layer.n;
    hash << layer.extract_tile_begin;
    hash << layer.extract_tile_count;
    for (const auto& root : roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

bool SamplerPinShape(
    const RCStage3EpisodeAirPublicPin& pin,
    const uint256& statement_commitment,
    std::string* why)
{
    if (pin.role != RCStage3RelationRole::EpisodeExtract ||
        pin.family !=
            RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1 ||
        pin.statement_commitment != statement_commitment ||
        pin.shard_index != 0 || pin.shard_count != 1 ||
        pin.logical_rows < kRCMxBlockLen ||
        pin.n_rows < pin.logical_rows ||
        pin.column_roots.size() != aq::kRcSamplerNumCols ||
        ComputeRCStage3EpisodeAirPinCommitment(pin).IsNull()) {
        return Fail(why, "sampler_pin");
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3EpisodeExtractMixPinCommitment(
    const RCStage3EpisodeExtractMixPin& pin)
{
    if (pin.version != kRCStage3EpisodeExtractProductVersion ||
        pin.statement_commitment.IsNull() ||
        pin.logical_rows < kRCMxBlockLen ||
        !IsPowerOfTwo(pin.n_rows) ||
        pin.logical_rows > pin.n_rows ||
        pin.n_rows >
            (std::numeric_limits<uint32_t>::max() +
             uint64_t{3}) / 3 ||
        pin.n_coeffs != FriNextPow2(
            3 * uint64_t{pin.n_rows} - 3) ||
        pin.column_roots.size() !=
            kRCStage3EpisodeExtractMixColumns) {
        return {};
    }
    HashWriter hash;
    hash << MIX_PIN_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.layer_ordinal;
    hash << pin.layer_tile_index;
    hash << pin.logical_rows;
    hash << pin.n_rows;
    hash << pin.n_coeffs;
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return {};
        }
        hash << i;
        hash << pin.column_roots[i].root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeExtractMixSeed(
    const RCStage3EpisodeExtractMixPin& pin)
{
    const uint256 commitment =
        ComputeRCStage3EpisodeExtractMixPinCommitment(pin);
    if (commitment.IsNull()) return {};
    HashWriter hash;
    hash << MIX_SEED_DOMAIN;
    hash << commitment;
    return hash.GetHash();
}

bool BuildRCStage3EpisodeExtractMixConstraintSystem(
    const RCStage3EpisodeExtractMixPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    return BuildRCStage3ExtractMixConstraintSystemForRole(
        RCStage3RelationRole::EpisodeExtract,
        pin, out, why);
}

bool BuildRCStage3ExtractMixConstraintSystemForRole(
    RCStage3RelationRole role,
    const RCStage3EpisodeExtractMixPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (pin.pin_commitment !=
            ComputeRCStage3EpisodeExtractMixPinCommitment(pin) ||
        pin.pin_commitment.IsNull()) {
        return Fail(why, "mix_pin");
    }
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3ExtractMixProgramTable(
            role, table, why) ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, pin.n_rows, out, why)) {
        return Fail(why, "mix_bytecode");
    }

    out.preprocessed_roots.reserve(pin.column_roots.size());
    for (const auto& root : pin.column_roots) {
        out.preprocessed_roots.emplace_back(
            root.column, root.root);
    }
    return true;
}

bool VerifyRCStage3EpisodeExtractMixProof(
    const RCStage3EpisodeExtractMixPin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3EpisodeExtractMixConstraintSystem(
            pin, cs, why) ||
        proof.batch.columns.size() !=
            kRCStage3EpisodeExtractMixColumns + 1 ||
        proof.batch.column_len.size() !=
            kRCStage3EpisodeExtractMixColumns + 1 ||
        proof.batch.n_coeffs != pin.n_coeffs) {
        return Fail(why, "mix_proof_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root !=
            pin.column_roots[i].root) {
            return Fail(why, "mix_proof_root");
        }
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof,
            ComputeRCStage3EpisodeExtractMixSeed(pin),
            &air_why)) {
        return Fail(why, "mix_air:" + air_why);
    }
    return true;
}

uint256 ComputeRCStage3EpisodeExtractInputTileRoot(
    const std::array<int64_t, kRCMxBlockLen>& input)
{
    std::vector<Fp3> values;
    values.reserve(input.size());
    for (int64_t value : input) {
        values.push_back(
            Fp3::FromFp(gf::FromSigned(value)));
    }
    const uint256 values_root =
        ValuesRoot(values, kRCMxBlockLen);
    if (values_root.IsNull()) return {};
    HashWriter hash;
    hash << INPUT_TILE_DOMAIN;
    hash << values_root;
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeExtractInputLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_tile_input_roots)
{
    return LayerRoot(
        INPUT_LAYER_DOMAIN, manifest, layer_ordinal,
        ordered_tile_input_roots);
}

uint256 ComputeRCStage3EpisodeExtractScaleLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_scale_manifest_commitments)
{
    return LayerRoot(
        SCALE_LAYER_DOMAIN, manifest, layer_ordinal,
        ordered_scale_manifest_commitments);
}

uint256 ComputeRCStage3EpisodeExtractRecursiveLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_tile_receipts)
{
    return LayerRoot(
        RECURSIVE_LAYER_DOMAIN, manifest, layer_ordinal,
        ordered_tile_receipts);
}

uint256 ComputeRCStage3EpisodeExtractTileReceiptCommitment(
    const RCStage3EpisodeExtractTileProduct& tile)
{
    const uint256 mix =
        ComputeRCStage3EpisodeExtractMixPinCommitment(
            tile.mix_pin);
    const uint256 sampler =
        ComputeRCStage3EpisodeAirPinCommitment(
            tile.sampler_pin);
    const uint256 input =
        ComputeRCStage3EpisodeExtractInputTileRoot(tile.input);
    if (mix.IsNull() || sampler.IsNull() || input.IsNull() ||
        tile.chacha_manifest.commitment.IsNull() ||
        tile.scale_manifest.commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << TILE_RECEIPT_DOMAIN;
    hash << tile.global_tile;
    hash << tile.layer_ordinal;
    hash << tile.layer_tile_index;
    hash << input;
    hash << mix;
    hash << sampler;
    hash << tile.chacha_manifest.commitment;
    hash << tile.scale_manifest.commitment;
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeExtractCollectionCommitment(
    const RCStage3EpisodeExtractProduct& product)
{
    if (product.version !=
            kRCStage3EpisodeExtractProductVersion ||
        product.statement_commitment.IsNull() ||
        product.manifest_commitment.IsNull() ||
        product.expected_tiles == 0 ||
        product.tiles.size() != product.expected_tiles) {
        return {};
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN;
    hash << product.version;
    hash << product.statement_commitment;
    hash << product.manifest_commitment;
    hash << product.expected_tiles;
    for (uint64_t i = 0; i < product.tiles.size(); ++i) {
        const auto& tile = product.tiles[i];
        if (tile.global_tile != i ||
            tile.tile_receipt_commitment.IsNull()) {
            return {};
        }
        hash << tile.tile_receipt_commitment;
    }
    return hash.GetHash();
}

static bool BuildExtractVerticalBoundaryMaterial(
    const RCStage3EpisodeExtractProduct& product,
    bool chacha,
    std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    uint256& manifest_commitment,
    std::string* why)
{
    boundaries.clear();
    manifest_commitment.SetNull();
    if (product.tiles.empty()) {
        return Fail(why, "vertical_empty_tiles");
    }
    HashWriter hash;
    hash << std::string{
        chacha
            ? "BTX_RC_STAGE3_EXTRACT_ALL_CHACHA_MANIFESTS_V1"
            : "BTX_RC_STAGE3_EXTRACT_ALL_SCALE_MANIFESTS_V1"};
    hash << product.statement_commitment;
    hash << product.expected_tiles;
    for (const auto& tile : product.tiles) {
        std::vector<ha::FixedProgramBoundaryInstance> local;
        const bool ok = chacha
            ? ha::BuildChaChaManifestBoundaryInstances(
                  tile.chacha_manifest, local, why)
            : ha::BuildShaManifestBoundaryInstances(
                  tile.scale_manifest, local, why);
        if (!ok || local.empty()) {
            boundaries.clear();
            return Fail(why, "vertical_manifest_boundaries");
        }
        hash << (chacha
            ? tile.chacha_manifest.commitment
            : tile.scale_manifest.commitment);
        boundaries.insert(
            boundaries.end(), local.begin(), local.end());
    }
    manifest_commitment = hash.GetHash();
    return !manifest_commitment.IsNull() ||
        Fail(why, "vertical_manifest_commitment");
}

static bool ProveRCStage3EpisodeExtractProductsImpl(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    bool vertical_hash_proofs,
    std::string* why)
{
    extract = {};
    tile_stream = {};
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        inputs.size() != manifest.total_extract_tiles ||
        manifest.params.rounds == 0) {
        return Fail(why, "prove_products_shape");
    }

    extract.statement_commitment = statement_commitment;
    extract.expected_tiles = manifest.total_extract_tiles;
    extract.vertical_hash_proofs = vertical_hash_proofs;
    extract.tiles.reserve(inputs.size());
    tile_stream.statement_commitment = statement_commitment;
    tile_stream.expected_rounds = manifest.params.rounds;
    tile_stream.rounds.resize(manifest.params.rounds);
    std::vector<std::vector<uint8_t>> round_streams(
        manifest.params.rounds);

    const ga::TableTM table;
    uint64_t global_tile = 0;
    uint32_t global_stream_tile = 0;
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < manifest.layers.size(); ++layer_ordinal) {
        auto& layer = manifest.layers[layer_ordinal];
        std::vector<uint256> input_roots;
        std::vector<uint256> output_roots;
        std::vector<uint256> scale_roots;
        std::vector<uint256> receipts;
        input_roots.reserve(layer.extract_tile_count);
        output_roots.reserve(layer.extract_tile_count);
        scale_roots.reserve(layer.extract_tile_count);
        receipts.reserve(layer.extract_tile_count);
        for (uint64_t layer_tile = 0;
             layer_tile < layer.extract_tile_count;
             ++layer_tile, ++global_tile) {
            uint32_t row{0};
            uint32_t block{0};
            if (global_tile >= inputs.size() ||
                !TileIdentity(
                    layer, layer_tile, row, block, why)) {
                extract = {};
                tile_stream = {};
                return Fail(why, "prove_tile_identity");
            }
            const ga::TilePublic tile_public{
                layer.bindings.extract_prf, row, block};
            const ga::TileWitness witness =
                ga::TraceTile(tile_public, inputs[global_tile]);
            if (witness.cands.empty() ||
                !ga::ByteExactVsReference(
                    tile_public, inputs[global_tile])) {
                extract = {};
                tile_stream = {};
                return Fail(why, "prove_tile_native_witness");
            }

            RCStage3EpisodeExtractTileProduct tile;
            tile.global_tile = global_tile;
            tile.layer_ordinal = layer_ordinal;
            tile.layer_tile_index = layer_tile;
            tile.input = inputs[global_tile];
            tile.candidate_positions.reserve(
                witness.cands.size());
            for (const auto& candidate : witness.cands) {
                tile.candidate_positions.push_back(
                    candidate.pos);
            }

            auto& sampler_pin = tile.sampler_pin;
            sampler_pin.role =
                RCStage3RelationRole::EpisodeExtract;
            sampler_pin.family =
                RCStage3EpisodeAirFamily::
                    ExtractSamplerCoreFp3V1;
            sampler_pin.statement_commitment =
                statement_commitment;
            sampler_pin.shard_index = 0;
            sampler_pin.shard_count = 1;
            sampler_pin.logical_rows =
                static_cast<uint32_t>(witness.cands.size());
            sampler_pin.n_rows = FriNextPow2(
                std::max<uint32_t>(
                    sampler_pin.logical_rows,
                    kRCMxBlockLen + 1));
            const auto dummy =
                aq::BuildRcSamplerConstraintSystem<Fp3>(
                    sampler_pin.n_rows, Fp3::Zero(),
                    Fp3::Zero(), witness.scale_e, table);
            sampler_pin.n_coeffs = FriNextPow2(
                std::max(
                    sampler_pin.n_rows,
                    dummy.QuotientLen()));
            sampler_pin.extract_scale_e =
                witness.scale_e;
            sampler_pin.column_roots.resize(
                aq::kRcSamplerNumCols);
            for (uint32_t column = 0;
                 column < sampler_pin.column_roots.size();
                 ++column) {
                sampler_pin.column_roots[column] = {
                    column, statement_commitment};
            }
            const uint256 sampler_seed =
                ComputeRCStage3EpisodeAirSeed(
                    statement, sampler_pin);
            const auto sampler =
                aq::BuildRcSamplerInstance<Fp3>(
                    witness, table, sampler_seed);
            if (sampler_seed.IsNull() || !sampler.ok ||
                sampler.n_rows != sampler_pin.n_rows) {
                extract = {};
                tile_stream = {};
                return Fail(
                    why, "prove_sampler:" + sampler.note);
            }
            for (uint32_t column = 0;
                 column < sampler.columns.size(); ++column) {
                sampler_pin.column_roots[column].root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        sampler.columns[column],
                        sampler_pin.n_coeffs);
            }
            auto sampler_proved = aq::AirQuotientProve<Fp3>(
                sampler.cs, sampler.columns, sampler_seed);
            if (!sampler_proved.ok ||
                !sampler_proved.division_exact) {
                extract = {};
                tile_stream = {};
                return Fail(
                    why, sampler_proved.note.empty()
                        ? "prove_sampler_quotient"
                        : sampler_proved.note);
            }
            tile.sampler_proof =
                std::move(sampler_proved.proof);
            if (!ProveEpisodeMix(
                    statement_commitment, layer_ordinal,
                    layer_tile, witness, sampler,
                    tile.mix_pin, tile.mix_proof, why)) {
                extract = {};
                tile_stream = {};
                return false;
            }

            std::array<uint8_t, 32> key{};
            std::copy_n(
                layer.bindings.extract_prf.begin(),
                key.size(), key.begin());
            if (!ha::BuildChaChaConsumptionManifest(
                    key, block ^ MX_BLOCK_LANE,
                    (static_cast<uint64_t>(row) << 32) |
                        block,
                    0, uint64_t{witness.chacha_blocks} * 64,
                    tile.chacha_manifest, why) ||
                tile.chacha_manifest.output !=
                    witness.keystream) {
                extract = {};
                tile_stream = {};
                return Fail(why, "prove_chacha_manifest");
            }
            std::vector<
                ha::FixedProgramBoundaryInstance>
                chacha_boundaries;
            if (!ha::BuildChaChaManifestBoundaryInstances(
                    tile.chacha_manifest,
                    chacha_boundaries, why)) {
                extract = {};
                tile_stream = {};
                return false;
            }
            if (vertical_hash_proofs) {
                if (!ProveRCStage3EpisodeHashSemanticBinding(
                        statement,
                        RCStage3RelationEndpoint::
                            EpisodeExtractChaCha,
                        chacha_boundaries,
                        hs::BoundaryPort::ExternalThenFinal,
                        tile.chacha.binding, why)) {
                    extract = {};
                    tile_stream = {};
                    return false;
                }
            } else if (!ProveEpisodeHashExecution(
                    statement,
                    RCStage3RelationEndpoint::
                        EpisodeExtractChaCha,
                    ha::BuildCanonicalProgram(
                        ha::ProgramKind::ChaCha20Block),
                    tile.chacha_manifest.commitment,
                    chacha_boundaries, tile.chacha, why)) {
                extract = {};
                tile_stream = {};
                return false;
            }
            if (!ha::BuildShaManifest(
                    ScalePreimage(
                        layer.bindings.extract_prf,
                        row, block),
                    ha::ShaMode::Single,
                    tile.scale_manifest, why) ||
                (tile.scale_manifest.digest[0] & 3) !=
                    witness.scale_e) {
                extract = {};
                tile_stream = {};
                return Fail(why, "prove_scale_manifest");
            }
            std::vector<
                ha::FixedProgramBoundaryInstance>
                scale_boundaries;
            if (!ha::BuildShaManifestBoundaryInstances(
                    tile.scale_manifest,
                    scale_boundaries, why)) {
                extract = {};
                tile_stream = {};
                return false;
            }
            if (vertical_hash_proofs) {
                if (!ProveRCStage3EpisodeHashSemanticBinding(
                        statement,
                        RCStage3RelationEndpoint::
                            EpisodeExtractScale,
                        scale_boundaries,
                        hs::BoundaryPort::ExternalThenFinal,
                        tile.scale.binding, why)) {
                    extract = {};
                    tile_stream = {};
                    return false;
                }
            } else if (!ProveEpisodeHashExecution(
                    statement,
                    RCStage3RelationEndpoint::
                        EpisodeExtractScale,
                    ha::BuildCanonicalProgram(
                        ha::ProgramKind::Sha256Compression),
                    tile.scale_manifest.commitment,
                    scale_boundaries, tile.scale, why)) {
                extract = {};
                tile_stream = {};
                return false;
            }

            tile.tile_receipt_commitment =
                ComputeRCStage3EpisodeExtractTileReceiptCommitment(
                    tile);
            const uint256 input_root =
                ComputeRCStage3EpisodeExtractInputTileRoot(
                    tile.input);
            if (tile.tile_receipt_commitment.IsNull() ||
                input_root.IsNull()) {
                extract = {};
                tile_stream = {};
                return Fail(why, "prove_tile_commitment");
            }
            input_roots.push_back(input_root);
            output_roots.push_back(
                sampler_pin.column_roots[
                    aq::kColOut].root);
            scale_roots.push_back(
                tile.scale_manifest.commitment);
            receipts.push_back(
                tile.tile_receipt_commitment);

            if (RCStage3EpisodeLayerIsStreamed(
                    layer.kind)) {
                auto& stream =
                    round_streams[layer.round];
                RCStage3EpisodeTileStreamShard
                    stream_tile;
                stream_tile.global_stream_tile =
                    global_stream_tile++;
                stream_tile.layer_ordinal =
                    layer_ordinal;
                stream_tile.layer_tile_index =
                    layer_tile;
                stream_tile.stream_byte_begin =
                    stream.size();
                stream_tile.pin = sampler_pin;
                stream_tile.proof =
                    tile.sampler_proof;
                for (int8_t value : witness.out) {
                    stream.push_back(
                        static_cast<uint8_t>(value));
                }
                tile_stream.tiles.push_back(
                    std::move(stream_tile));
            }
            extract.tiles.push_back(std::move(tile));
        }
        layer.bindings.extract_input_root =
            ComputeRCStage3EpisodeExtractInputLayerRoot(
                manifest, layer_ordinal, input_roots);
        layer.bindings.extract_output_root =
            ComputeRCStage3EpisodeStreamedLayerOutputRoot(
                manifest, layer_ordinal, output_roots);
        layer.bindings.scale_schedule_root =
            ComputeRCStage3EpisodeExtractScaleLayerRoot(
                manifest, layer_ordinal, scale_roots);
        layer.bindings.extract_recursive_root =
            ComputeRCStage3EpisodeExtractRecursiveLayerRoot(
                manifest, layer_ordinal, receipts);
        if (layer.bindings.extract_input_root.IsNull() ||
            layer.bindings.extract_output_root.IsNull() ||
            layer.bindings.scale_schedule_root.IsNull() ||
            layer.bindings.extract_recursive_root.IsNull()) {
            extract = {};
            tile_stream = {};
            return Fail(why, "prove_layer_roots");
        }
    }
    if (global_tile != inputs.size() ||
        global_stream_tile == 0) {
        extract = {};
        tile_stream = {};
        return Fail(why, "prove_products_inventory");
    }

    extract.manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    tile_stream.gemm_extract_manifest_commitment =
        extract.manifest_commitment;
    tile_stream.expected_stream_tiles =
        global_stream_tile;
    if (extract.manifest_commitment.IsNull()) {
        extract = {};
        tile_stream = {};
        return Fail(why, "prove_manifest_commitment");
    }
    for (uint32_t round_index = 0;
         round_index < manifest.params.rounds; ++round_index) {
        auto& round = tile_stream.rounds[round_index];
        auto& stream = round_streams[round_index];
        if (stream.empty()) {
            extract = {};
            tile_stream = {};
            return Fail(why, "prove_empty_round_stream");
        }
        round.round_index = round_index;
        round.tree.round_index = round_index;
        if (!ha::BuildTileTreeManifest(
                stream, manifest.params.T_leaf,
                round.tree.tree_manifest, why)) {
            extract = {};
            tile_stream = {};
            return Fail(why, "prove_tile_tree_manifest");
        }
        std::vector<ha::FixedProgramBoundaryInstance>
            tree_boundaries;
        if (!ha::BuildTileTreeManifestBoundaryInstances(
                round.tree.tree_manifest,
                tree_boundaries, why) ||
            !hs::ProveFlatBoundaryProofBundle(
                RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                statement_commitment,
                round.tree.tree_manifest.commitment,
                ha::BuildCanonicalProgram(
                    ha::ProgramKind::Sha256Compression),
                tree_boundaries,
                round.tree.hash_bundle, why) ||
            !ProveRCStage3EpisodeHashSemanticBinding(
                statement,
                RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                tree_boundaries,
                hs::BoundaryPort::ExternalThenFinal,
                round.tree.hash_binding, why)) {
            extract = {};
            tile_stream = {};
            return Fail(why, "prove_tile_tree_hash");
        }
        std::vector<Fp3> stream_values;
        stream_values.reserve(stream.size());
        for (uint8_t byte : stream) {
            const int64_t signed_value =
                byte < 128 ? static_cast<int64_t>(byte)
                           : static_cast<int64_t>(byte) - 256;
            stream_values.push_back(
                Fp3::FromFp(
                    gf::FromSigned(signed_value)));
        }
        const uint64_t address_begin =
            UINT64_C(0x4553000000000000) +
            static_cast<uint64_t>(round_index) *
                (UINT64_C(1) << 40);
        if (!ProveRCStage3EpisodeSemanticMemoryBundle(
                RCStage3RelationEndpoint::EpisodeTileTreeStream,
                statement_commitment, address_begin, 1,
                stream_values, round.stream_memory, why)) {
            extract = {};
            tile_stream = {};
            return Fail(why, "prove_stream_memory");
        }
    }
    if (vertical_hash_proofs) {
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        uint256 vertical_manifest;
        if (!BuildExtractVerticalBoundaryMaterial(
                extract, true, boundaries,
                vertical_manifest, why) ||
            !hs::ProveVerticalBoundaryProofBundle(
                RCStage3RelationEndpoint::EpisodeExtractChaCha,
                statement_commitment, vertical_manifest,
                ha::BuildCanonicalProgram(
                    ha::ProgramKind::ChaCha20Block),
                boundaries, extract.vertical_chacha, why) ||
            !BuildExtractVerticalBoundaryMaterial(
                extract, false, boundaries,
                vertical_manifest, why) ||
            !hs::ProveVerticalBoundaryProofBundle(
                RCStage3RelationEndpoint::EpisodeExtractScale,
                statement_commitment, vertical_manifest,
                ha::BuildCanonicalProgram(
                    ha::ProgramKind::Sha256Compression),
                boundaries, extract.vertical_scale, why)) {
            extract = {};
            tile_stream = {};
            return Fail(why, "prove_vertical_hash_bundles");
        }
    }
    extract.collection_commitment =
        ComputeRCStage3EpisodeExtractCollectionCommitment(
            extract);
    tile_stream.collection_commitment =
        ComputeRCStage3EpisodeTileStreamCollectionCommitment(
            tile_stream);
    if (extract.collection_commitment.IsNull() ||
        tile_stream.collection_commitment.IsNull() ||
        !VerifyRCStage3EpisodeExtractProduct(
            statement, manifest, extract, tile_stream, why)) {
        extract = {};
        tile_stream = {};
        return Fail(why, "prove_products_self_verify");
    }
    return true;
}

bool ProveRCStage3EpisodeExtractAndTileStreamProducts(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why)
{
    return ProveRCStage3EpisodeExtractProductsImpl(
        statement, manifest, inputs, extract, tile_stream,
        false, why);
}

bool ProveRCStage3EpisodeExtractAndTileStreamProductsVertical(
    const RCStage3SuccinctProof& statement,
    RCStage3GemmExtractManifest& manifest,
    const std::vector<std::array<int64_t, kRCMxBlockLen>>& inputs,
    RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why)
{
    return ProveRCStage3EpisodeExtractProductsImpl(
        statement, manifest, inputs, extract, tile_stream,
        true, why);
}

bool ValidateRCStage3EpisodeExtractSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& product,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (!IsEpisodeStatement(statement) ||
        statement_commitment.IsNull() ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        product.version !=
            kRCStage3EpisodeExtractProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.manifest_commitment != manifest_commitment ||
        product.expected_tiles != manifest.total_extract_tiles ||
        product.tiles.size() != manifest.total_extract_tiles) {
        return Fail(why, "public_shape");
    }
    if (product.vertical_hash_proofs &&
        (product.vertical_chacha.endpoint !=
             RCStage3RelationEndpoint::EpisodeExtractChaCha ||
         product.vertical_chacha.statement_commitment !=
             statement_commitment ||
         product.vertical_scale.endpoint !=
             RCStage3RelationEndpoint::EpisodeExtractScale ||
         product.vertical_scale.statement_commitment !=
             statement_commitment)) {
        return Fail(why, "vertical_bundle_identity");
    }

    uint64_t global_tile = 0;
    uint32_t stream_tile = 0;
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < manifest.layers.size();
         ++layer_ordinal) {
        const auto& layer = manifest.layers[layer_ordinal];
        std::vector<uint256> input_roots;
        std::vector<uint256> output_roots;
        std::vector<uint256> scale_roots;
        std::vector<uint256> receipts;
        input_roots.reserve(layer.extract_tile_count);
        output_roots.reserve(layer.extract_tile_count);
        scale_roots.reserve(layer.extract_tile_count);
        receipts.reserve(layer.extract_tile_count);

        for (uint64_t layer_tile = 0;
             layer_tile < layer.extract_tile_count;
             ++layer_tile, ++global_tile) {
            if (global_tile >= product.tiles.size()) {
                return Fail(why, "tile_omission");
            }
            const auto& tile = product.tiles[global_tile];
            uint32_t row{0};
            uint32_t block{0};
            if (tile.global_tile != global_tile ||
                tile.global_tile !=
                    layer.extract_tile_begin + layer_tile ||
                tile.layer_ordinal != layer_ordinal ||
                tile.layer_tile_index != layer_tile ||
                !TileIdentity(
                    layer, layer_tile, row, block, why) ||
                !SamplerPinShape(
                    tile.sampler_pin, statement_commitment,
                    why)) {
                return Fail(
                    why, "tile_" + std::to_string(global_tile) +
                             "_identity");
            }

            uint256 position_root;
            uint256 kappa_root;
            std::vector<uint256> expected_mix;
            const uint64_t chacha_blocks =
                (tile.sampler_pin.logical_rows + 127) / 128;
            std::array<uint8_t, 32> expected_key{};
            std::copy_n(
                layer.bindings.extract_prf.begin(),
                expected_key.size(), expected_key.begin());
            if (!ExpectedSamplerPositionRoot(
                    tile, position_root, why) ||
                !ExpectedSamplerKappaRoot(
                    tile, kappa_root, why) ||
                !ExpectedMixPublicRoots(
                    tile, expected_mix, why) ||
                tile.sampler_pin.column_roots[aq::kColPos].root !=
                    position_root ||
                tile.sampler_pin.column_roots[aq::kColKappa].root !=
                    kappa_root ||
                tile.chacha_manifest.key != expected_key ||
                tile.chacha_manifest.nonce_first !=
                    (block ^ MX_BLOCK_LANE) ||
                tile.chacha_manifest.nonce_second !=
                    ((static_cast<uint64_t>(row) << 32) |
                     block) ||
                tile.chacha_manifest.first_counter != 0 ||
                tile.chacha_manifest.output_bytes !=
                    chacha_blocks * 64 ||
                tile.chacha_manifest.commitment !=
                    ha::CommitChaChaConsumptionManifest(
                        tile.chacha_manifest) ||
                (!product.vertical_hash_proofs &&
                 (tile.chacha.proofs.endpoint !=
                      RCStage3RelationEndpoint::
                          EpisodeExtractChaCha ||
                  tile.chacha.proofs.statement_commitment !=
                      statement_commitment ||
                  tile.chacha.proofs.manifest_commitment !=
                      tile.chacha_manifest.commitment)) ||
                (product.vertical_hash_proofs &&
                 !tile.chacha.proofs.proofs.empty())) {
                return Fail(
                    why, "tile_" + std::to_string(global_tile) +
                             "_chacha_or_sampler_walk");
            }

            if (tile.mix_pin.statement_commitment !=
                    statement_commitment ||
                tile.mix_pin.layer_ordinal != layer_ordinal ||
                tile.mix_pin.layer_tile_index != layer_tile ||
                tile.mix_pin.pin_commitment !=
                    ComputeRCStage3EpisodeExtractMixPinCommitment(
                        tile.mix_pin) ||
                expected_mix.size() !=
                    tile.mix_pin.column_roots.size()) {
                return Fail(why, "mix_pin_identity");
            }
            for (uint32_t column = 0;
                 column < expected_mix.size(); ++column) {
                if (!expected_mix[column].IsNull() &&
                    tile.mix_pin.column_roots[column].root !=
                        expected_mix[column]) {
                    return Fail(
                        why, "mix_public_root_" +
                                 std::to_string(column));
                }
            }

            const std::vector<uint8_t> scale_preimage =
                ScalePreimage(
                    layer.bindings.extract_prf, row, block);
            if (tile.scale_manifest.mode != ha::ShaMode::Single ||
                tile.scale_manifest.preimage != scale_preimage ||
                tile.scale_manifest.commitment !=
                    ha::CommitShaManifest(tile.scale_manifest) ||
                (tile.scale_manifest.digest[0] & 3) !=
                    tile.sampler_pin.extract_scale_e ||
                (!product.vertical_hash_proofs &&
                 (tile.scale.proofs.endpoint !=
                      RCStage3RelationEndpoint::
                          EpisodeExtractScale ||
                  tile.scale.proofs.statement_commitment !=
                      statement_commitment ||
                  tile.scale.proofs.manifest_commitment !=
                      tile.scale_manifest.commitment)) ||
                (product.vertical_hash_proofs &&
                 !tile.scale.proofs.proofs.empty())) {
                return Fail(
                    why, "tile_" + std::to_string(global_tile) +
                             "_scale");
            }

            const uint256 input_root =
                ComputeRCStage3EpisodeExtractInputTileRoot(
                    tile.input);
            const uint256 receipt =
                ComputeRCStage3EpisodeExtractTileReceiptCommitment(
                    tile);
            if (input_root.IsNull() || receipt.IsNull() ||
                tile.tile_receipt_commitment != receipt) {
                return Fail(why, "tile_receipt");
            }
            input_roots.push_back(input_root);
            output_roots.push_back(
                tile.sampler_pin
                    .column_roots[aq::kColOut].root);
            scale_roots.push_back(
                tile.scale_manifest.commitment);
            receipts.push_back(receipt);

            if (RCStage3EpisodeLayerIsStreamed(layer.kind)) {
                if (stream_tile >= tile_stream.tiles.size() ||
                    tile_stream.tiles[stream_tile].pin !=
                        tile.sampler_pin ||
                    tile_stream.tiles[stream_tile].layer_ordinal !=
                        layer_ordinal ||
                    tile_stream.tiles[stream_tile].layer_tile_index !=
                        layer_tile) {
                    return Fail(why, "endpoint19_tile_alias");
                }
                ++stream_tile;
            }
        }

        if (ComputeRCStage3EpisodeExtractInputLayerRoot(
                manifest, layer_ordinal, input_roots) !=
                layer.bindings.extract_input_root ||
            ComputeRCStage3EpisodeStreamedLayerOutputRoot(
                manifest, layer_ordinal, output_roots) !=
                layer.bindings.extract_output_root ||
            ComputeRCStage3EpisodeExtractScaleLayerRoot(
                manifest, layer_ordinal, scale_roots) !=
                layer.bindings.scale_schedule_root ||
            ComputeRCStage3EpisodeExtractRecursiveLayerRoot(
                manifest, layer_ordinal, receipts) !=
                layer.bindings.extract_recursive_root) {
            return Fail(
                why, "layer_" + std::to_string(layer_ordinal) +
                         "_registered_root");
        }
    }
    if (global_tile != product.tiles.size() ||
        stream_tile != tile_stream.tiles.size()) {
        return Fail(why, "tile_coverage");
    }
    const uint256 collection =
        ComputeRCStage3EpisodeExtractCollectionCommitment(
            product);
    if (collection.IsNull() ||
        collection != product.collection_commitment) {
        return Fail(why, "collection_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeExtractProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& product,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    if (!ValidateRCStage3EpisodeExtractSchedule(
            statement, manifest, product, tile_stream, why)) {
        return false;
    }
    for (uint64_t i = 0; i < product.tiles.size(); ++i) {
        const auto& tile = product.tiles[i];
        if (!VerifyRCStage3EpisodeExtractMixProof(
                tile.mix_pin, tile.mix_proof, why) ||
            !VerifyRCStage3EpisodeAirShard(
                statement, tile.sampler_pin,
                tile.sampler_proof, why)) {
            return Fail(
                why, "tile_" + std::to_string(i) +
                         "_proof_execution");
        }
        if (product.vertical_hash_proofs) {
            std::vector<ha::FixedProgramBoundaryInstance>
                boundaries;
            if (!ha::BuildChaChaManifestBoundaryInstances(
                    tile.chacha_manifest, boundaries, why) ||
                !VerifyRCStage3EpisodeHashSemanticBinding(
                    statement,
                    RCStage3RelationEndpoint::
                        EpisodeExtractChaCha,
                    boundaries, tile.chacha.binding, why) ||
                !ha::BuildShaManifestBoundaryInstances(
                    tile.scale_manifest, boundaries, why) ||
                !VerifyRCStage3EpisodeHashSemanticBinding(
                    statement,
                    RCStage3RelationEndpoint::
                        EpisodeExtractScale,
                    boundaries, tile.scale.binding, why)) {
                return Fail(
                    why, "tile_" + std::to_string(i) +
                             "_vertical_semantic_execution");
            }
        } else if (!VerifyRCStage3EpisodeChaChaSemantic(
                statement,
                RCStage3RelationEndpoint::EpisodeExtractChaCha,
                tile.chacha_manifest, tile.chacha.proofs,
                tile.chacha.binding, why) ||
            !VerifyRCStage3EpisodeShaSemantic(
                statement,
                RCStage3RelationEndpoint::EpisodeExtractScale,
                tile.scale_manifest, tile.scale.proofs,
                tile.scale.binding, why)) {
            return Fail(
                why, "tile_" + std::to_string(i) +
                         "_flat_hash_execution");
        }
    }
    if (product.vertical_hash_proofs) {
        std::vector<ha::FixedProgramBoundaryInstance> boundaries;
        uint256 vertical_manifest;
        if (product.vertical_chacha.endpoint !=
                RCStage3RelationEndpoint::EpisodeExtractChaCha ||
            product.vertical_chacha.statement_commitment !=
                statement_commitment ||
            product.vertical_scale.endpoint !=
                RCStage3RelationEndpoint::EpisodeExtractScale ||
            product.vertical_scale.statement_commitment !=
                statement_commitment ||
            !BuildExtractVerticalBoundaryMaterial(
                product, true, boundaries,
                vertical_manifest, why) ||
            !hs::VerifyVerticalBoundaryProofBundle(
                ha::BuildCanonicalProgram(
                    ha::ProgramKind::ChaCha20Block),
                boundaries, vertical_manifest,
                product.vertical_chacha, why) ||
            !BuildExtractVerticalBoundaryMaterial(
                product, false, boundaries,
                vertical_manifest, why) ||
            !hs::VerifyVerticalBoundaryProofBundle(
                ha::BuildCanonicalProgram(
                    ha::ProgramKind::Sha256Compression),
                boundaries, vertical_manifest,
                product.vertical_scale, why)) {
            return Fail(why, "vertical_hash_execution");
        }
    }
    if (!VerifyRCStage3EpisodeTileStreamProduct(
            statement, manifest, tile_stream, why)) {
        return Fail(why, "endpoint19_product");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_extract_product:endpoints_10_14_exact_"
            "flat_product_ok;gemm_producer_and_recursion_pending";
    }
    return true;
}

RCStage3EpisodeExtractProductAudit
CurrentRCStage3EpisodeExtractProductAudit()
{
    RCStage3EpisodeExtractProductAudit out;
    out.exact_all_tile_schedule = true;
    out.input_opening_and_mix_air_executed = true;
    out.sampler_walk_executed = true;
    out.chacha_consumption_air_executed = true;
    out.scale_sha_air_executed = true;
    out.dequant_output_root_bound = true;
    out.endpoint19_equality_executed = true;
    out.endpoints_10_through_14_locally_complete = true;
    out.gemm_output_producer_transitively_complete = false;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "the exact flat input words and child proofs are not recursively "
        "consumed, and the registered Extract-input roots are not yet "
        "equality-linked to complete GEMM-output producers";
    return out;
}

static_assert(kRCStage3EpisodeExtractLocalRelationExecutable);
static_assert(!kRCStage3EpisodeExtractTransitivelyComplete);

} // namespace matmul::v4::rc
