// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_gkr_wiring.h>

#include <algorithm>
#include <array>
#include <limits>
#include <optional>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PIN_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_PRODUCT_V1";
constexpr char TRANSPOSE_EDGE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_TRANSPOSE_EDGE_V1";
constexpr char RESIDUAL_EDGE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_RESIDUAL_EDGE_V1";
constexpr char ORDER_EDGE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_ORDER_EDGE_V1";
constexpr char CHALLENGE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_CHALLENGE_V1";
constexpr uint64_t TRANSPOSE_ADDRESS =
    UINT64_C(0x5710000000000000);
constexpr uint64_t RESIDUAL_ADDRESS =
    UINT64_C(0x5720000000000000);
constexpr uint64_t ORDER_ADDRESS =
    UINT64_C(0x5730000000000000);
constexpr uint64_t EDGE_ADDRESS_STRIDE = UINT64_C(1) << 24;
constexpr uint64_t SLOT_ADDRESS_STRIDE = UINT64_C(1) << 21;

enum TransposeColumn : uint32_t {
    kTransposeMappedIndex = 0,
    kTransposeSourceValue,
    kTransposeDestinationIndex,
    kTransposeDestinationValue,
    kTransposeDenominatorInverse1,
    kTransposeRunningProduct1,
    kTransposeDenominatorInverse2,
    kTransposeRunningProduct2,
    kTransposeColumns,
};

enum ResidualColumn : uint32_t {
    kResidualY = 0,
    kResidualValue,
    kResidualSum,
    kResidualExtractInput,
    kResidualColumns,
};

enum OrderColumn : uint32_t {
    kOrderProducer = 0,
    kOrderConsumer,
    kOrderColumns,
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_wiring_product:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 S(int64_t value)
{
    return Fp3::FromFp(gf::FromSigned(value));
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2 ||
        value > kRCStage3EpisodeSemanticMaxRows) {
        return 0;
    }
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

uint32_t AirCommitmentLen(const AirCS& cs)
{
    const uint64_t required = std::max<uint64_t>(
        cs.n_rows, cs.QuotientLen());
    if (required == 0 ||
        required > (uint64_t{1} << 24)) {
        return 0;
    }
    uint32_t out = 1;
    while (out < required) out <<= 1;
    return out;
}

uint64_t Address(
    uint64_t base, uint32_t edge, uint32_t slot)
{
    return base +
           static_cast<uint64_t>(edge) * EDGE_ADDRESS_STRIDE +
           static_cast<uint64_t>(slot) * SLOT_ADDRESS_STRIDE;
}

std::vector<Fp3> ToField(const std::vector<int8_t>& values)
{
    std::vector<Fp3> out;
    out.reserve(values.size());
    for (int8_t value : values) out.push_back(S(value));
    return out;
}

std::vector<Fp3> ToField(const std::vector<int64_t>& values)
{
    std::vector<Fp3> out;
    out.reserve(values.size());
    for (int64_t value : values) out.push_back(S(value));
    return out;
}

void AddConstraint(
    AirCS& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

uint256 VectorRoot(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    const std::vector<Fp3>& values,
    std::string* why)
{
    const auto root =
        ComputeRCStage3EpisodeWiringVectorRootFromValues(
            statement_commitment, first_column,
            n_chunks, values, why);
    return root.has_value() ? *root : uint256{};
}

std::optional<std::pair<uint32_t, uint256>>
FindRegisteredRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t first_column,
    uint32_t through_layer)
{
    for (uint32_t i = 0;
         i <= through_layer && i < manifest.layers.size(); ++i) {
        const auto& layer = manifest.layers[i];
        if (layer.a.first_column == first_column) {
            return std::pair{
                layer.a.n_chunks,
                layer.bindings.operand_a_root};
        }
        if (layer.b.first_column == first_column) {
            return std::pair{
                layer.b.n_chunks,
                layer.bindings.operand_b_root};
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> FindProducer(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t first_column,
    uint32_t before_layer)
{
    for (uint32_t i = 0;
         i < before_layer && i < manifest.layers.size(); ++i) {
        if (manifest.layers[i].out_first_column == first_column) {
            return i;
        }
    }
    return std::nullopt;
}

bool BaseShape(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    std::string* why)
{
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (statement_commitment.IsNull() ||
        !ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why) ||
        gemm.version != kRCStage3EpisodeGemmProductVersion ||
        gemm.statement_commitment != statement_commitment ||
        gemm.manifest_commitment != manifest_commitment ||
        gemm.layers.size() != manifest.layers.size() ||
        gemm.collection_commitment.IsNull() ||
        extract.version != kRCStage3EpisodeExtractProductVersion ||
        extract.statement_commitment != statement_commitment ||
        extract.manifest_commitment != manifest_commitment ||
        extract.tiles.size() != manifest.total_extract_tiles ||
        extract.collection_commitment.IsNull()) {
        return Fail(why, "base_shape");
    }
    for (uint32_t i = 0; i < manifest.layers.size(); ++i) {
        const auto& spec = manifest.layers[i];
        const auto& layer = gemm.layers[i];
        if (layer.layer_ordinal != i ||
            layer.operand_a.size() !=
                static_cast<uint64_t>(spec.m) * spec.k ||
            layer.operand_b.size() !=
                static_cast<uint64_t>(spec.k) * spec.n ||
            layer.gemm_y.size() != spec.gemm_cell_count ||
            (spec.residual_first_column < 0
                 ? !layer.residual.empty()
                 : layer.residual.size() !=
                       spec.gemm_cell_count)) {
            return Fail(why, "base_layer_shape");
        }
    }
    return true;
}

bool ExtractInputValues(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    uint32_t layer_ordinal,
    std::vector<int64_t>& out,
    std::string* why)
{
    out.clear();
    if (layer_ordinal >= manifest.layers.size()) {
        return Fail(why, "extract_input_layer");
    }
    const auto& layer = manifest.layers[layer_ordinal];
    out.reserve(layer.gemm_cell_count);
    for (uint64_t local = 0;
         local < layer.extract_tile_count; ++local) {
        const uint64_t global = layer.extract_tile_begin + local;
        if (global >= extract.tiles.size()) {
            return Fail(why, "extract_input_omission");
        }
        const auto& tile = extract.tiles[global];
        if (tile.global_tile != global ||
            tile.layer_ordinal != layer_ordinal ||
            tile.layer_tile_index != local) {
            return Fail(why, "extract_input_order");
        }
        out.insert(
            out.end(), tile.input.begin(), tile.input.end());
    }
    return out.size() == layer.gemm_cell_count ||
           Fail(why, "extract_input_count");
}

bool ValuesMatchProducerOutput(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    uint32_t producer_ordinal,
    const std::vector<int8_t>& values,
    std::string* why)
{
    if (producer_ordinal >= manifest.layers.size()) {
        return Fail(why, "producer_layer");
    }
    const auto& producer = manifest.layers[producer_ordinal];
    if (values.size() != producer.gemm_cell_count ||
        producer.extract_tile_count * kRCMxBlockLen !=
            values.size()) {
        return Fail(why, "producer_value_count");
    }
    for (uint64_t local = 0;
         local < producer.extract_tile_count; ++local) {
        const uint64_t global =
            producer.extract_tile_begin + local;
        if (global >= extract.tiles.size()) {
            return Fail(why, "producer_tile_omission");
        }
        const auto& pin = extract.tiles[global].sampler_pin;
        if (pin.logical_rows < kRCMxBlockLen ||
            pin.n_rows < kRCMxBlockLen ||
            pin.column_roots.size() != aq::kRcSamplerNumCols) {
            return Fail(why, "producer_pin_shape");
        }
        std::vector<Fp3> expected(
            pin.n_rows, Fp3::Zero());
        for (uint32_t lane = 0;
             lane < kRCMxBlockLen; ++lane) {
            expected[lane] = S(values[
                local * kRCMxBlockLen + lane]);
        }
        if (aq::AirCommittedValuesRoot<Fp3>(
                expected, pin.n_coeffs) !=
            pin.column_roots[aq::kColOut].root) {
            return Fail(why, "producer_output_root");
        }
    }
    return true;
}

uint256 ChallengeSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    uint32_t schedule_index,
    uint32_t logical_rows,
    const std::vector<uint256>& base_roots)
{
    if (statement_commitment.IsNull() ||
        manifest_commitment.IsNull() ||
        logical_rows == 0 || base_roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << CHALLENGE_DOMAIN;
    hash << kRCStage3EpisodeWiringProductVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << statement_commitment << manifest_commitment;
    hash << schedule_index << logical_rows;
    hash << static_cast<uint32_t>(base_roots.size());
    for (const auto& root : base_roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

AirCS BuildTransposeCS(
    const RCStage3EpisodeWiringAirPin& pin)
{
    AirCS cs;
    cs.n_rows = pin.n_rows;
    cs.n_columns = kTransposeColumns;
    const std::array<std::pair<uint32_t, uint32_t>, 2> lanes{{
        {kTransposeDenominatorInverse1,
         kTransposeRunningProduct1},
        {kTransposeDenominatorInverse2,
         kTransposeRunningProduct2},
    }};
    for (uint32_t lane = 0; lane < lanes.size(); ++lane) {
        const Fp3 beta = WiringChallengeFp3(
            pin.challenge_seed, "stage3_transpose_beta",
            pin.schedule_index, lane);
        const Fp3 gamma = WiringChallengeFp3(
            pin.challenge_seed, "stage3_transpose_gamma",
            pin.schedule_index, lane);
        const uint32_t inv_col = lanes[lane].first;
        const uint32_t z_col = lanes[lane].second;
        AddConstraint(
            cs, lane == 0
                ? "transpose.denominator_inverse_1"
                : "transpose.denominator_inverse_2",
            aq::AirKind::kEverywhere, 2,
            [beta, gamma, inv_col](
                const auto& row, const auto&) {
                const Fp3 fp = gf::Add(
                    row[kTransposeDestinationValue],
                    gf::Mul(
                        beta,
                        row[kTransposeDestinationIndex]));
                return gf::Sub(
                    gf::Mul(
                        row[inv_col],
                        gf::Sub(gamma, fp)),
                    Fp3::One());
            });
        AddConstraint(
            cs, lane == 0
                ? "transpose.running_first_1"
                : "transpose.running_first_2",
            aq::AirKind::kFirstRow, 1,
            [z_col](const auto& row, const auto&) {
                return gf::Sub(row[z_col], Fp3::One());
            });
        AddConstraint(
            cs, lane == 0
                ? "transpose.running_cycle_1"
                : "transpose.running_cycle_2",
            aq::AirKind::kEverywhere, 2,
            [beta, gamma, z_col](
                const auto& row, const auto& next) {
                const Fp3 numerator = gf::Sub(
                    gamma,
                    gf::Add(
                        row[kTransposeSourceValue],
                        gf::Mul(
                            beta,
                            row[kTransposeMappedIndex])));
                const Fp3 denominator = gf::Sub(
                    gamma,
                    gf::Add(
                        row[kTransposeDestinationValue],
                        gf::Mul(
                            beta,
                            row[kTransposeDestinationIndex])));
                return gf::Sub(
                    gf::Mul(next[z_col], denominator),
                    gf::Mul(row[z_col], numerator));
            });
    }
    return cs;
}

AirCS BuildResidualCS(uint32_t n_rows)
{
    AirCS cs;
    cs.n_rows = n_rows;
    cs.n_columns = kResidualColumns;
    AddConstraint(
        cs, "residual.y_plus_residual", aq::AirKind::kEverywhere,
        1, [](const auto& row, const auto&) {
            return gf::Sub(
                row[kResidualSum],
                gf::Add(
                    row[kResidualY],
                    row[kResidualValue]));
        });
    AddConstraint(
        cs, "residual.extract_input_alias",
        aq::AirKind::kEverywhere, 1,
        [](const auto& row, const auto&) {
            return gf::Sub(
                row[kResidualExtractInput],
                row[kResidualSum]);
        });
    return cs;
}

AirCS BuildOrderCS(uint32_t n_rows)
{
    AirCS cs;
    cs.n_rows = n_rows;
    cs.n_columns = kOrderColumns;
    AddConstraint(
        cs, "round_order.producer_consumer_equality",
        aq::AirKind::kEverywhere, 1,
        [](const auto& row, const auto&) {
            return gf::Sub(
                row[kOrderProducer],
                row[kOrderConsumer]);
        });
    return cs;
}

bool PinShape(
    const RCStage3EpisodeWiringAirPin& pin,
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    uint32_t schedule_index,
    uint32_t logical_rows,
    uint32_t n_rows,
    uint32_t columns,
    std::string* why)
{
    if (pin.version != kRCStage3EpisodeWiringProductVersion ||
        pin.endpoint != endpoint ||
        pin.statement_commitment != statement_commitment ||
        pin.manifest_commitment != manifest_commitment ||
        pin.schedule_index != schedule_index ||
        pin.logical_rows != logical_rows ||
        pin.n_rows != n_rows ||
        pin.challenge_seed.IsNull() ||
        pin.column_roots.size() != columns ||
        pin.pin_commitment !=
            ComputeRCStage3EpisodeWiringAirPinCommitment(pin)) {
        return Fail(why, "pin_shape");
    }
    for (uint32_t i = 0; i < columns; ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return Fail(why, "pin_column");
        }
    }
    return true;
}

bool ProvePin(
    RCStage3EpisodeWiringAirPin& pin,
    const AirCS& cs,
    const std::vector<std::vector<Fp3>>& columns,
    aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const uint32_t n_coeffs = AirCommitmentLen(cs);
    if (n_coeffs == 0) {
        return Fail(why, "prove_pin_commitment_len");
    }
    pin.column_roots.clear();
    for (uint32_t column = 0;
         column < columns.size(); ++column) {
        pin.column_roots.push_back({
            column,
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], n_coeffs)});
    }
    pin.pin_commitment =
        ComputeRCStage3EpisodeWiringAirPinCommitment(pin);
    if (pin.pin_commitment.IsNull()) {
        return Fail(why, "prove_pin_commitment");
    }
    const auto proved = aq::AirQuotientProve<Fp3>(
        cs, columns, pin.pin_commitment);
    if (!proved.ok || !proved.division_exact) {
        return Fail(why, "prove_air:" + proved.note);
    }
    proof = proved.proof;
    return true;
}

bool VerifyPin(
    const RCStage3EpisodeWiringAirPin& pin,
    const AirCS& cs,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const uint32_t n_coeffs = AirCommitmentLen(cs);
    if (n_coeffs == 0) {
        return Fail(why, "verify_pin_commitment_len");
    }
    if (proof.batch.columns.size() !=
            pin.column_roots.size() + 1 ||
        proof.batch.column_len.size() !=
            pin.column_roots.size() + 1 ||
        proof.batch.n_coeffs != n_coeffs) {
        return Fail(why, "verify_proof_shape");
    }
    for (uint32_t column = 0;
         column < pin.column_roots.size(); ++column) {
        if (proof.batch.column_len[column] != pin.n_rows ||
            proof.batch.columns[column].root !=
            pin.column_roots[column].root) {
            return Fail(
                why,
                "verify_proof_root:" +
                    std::to_string(column));
        }
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof, pin.pin_commitment, &air_why)) {
        return Fail(why, "verify_air:" + air_why);
    }
    return true;
}

bool BuildTransposeColumns(
    const RCStage3EpisodeWiringTransposeSchedule& schedule,
    const std::vector<int8_t>& source,
    RCStage3EpisodeWiringAirPin& pin,
    std::vector<int8_t>& destination,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const uint32_t n_rows = NextPowerOfTwo(schedule.value_count);
    if (n_rows == 0 ||
        source.size() != schedule.value_count ||
        schedule.source_rows == 0 ||
        schedule.source_cols == 0 ||
        static_cast<uint64_t>(schedule.source_rows) *
                schedule.source_cols !=
            schedule.value_count) {
        return Fail(why, "transpose_column_shape");
    }
    destination.assign(schedule.value_count, 0);
    columns.assign(
        kTransposeColumns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    for (uint64_t source_index = 0;
         source_index < schedule.value_count; ++source_index) {
        const uint64_t row =
            source_index / schedule.source_cols;
        const uint64_t col =
            source_index % schedule.source_cols;
        const uint64_t destination_index =
            col * schedule.source_rows + row;
        destination[destination_index] = source[source_index];
        columns[kTransposeMappedIndex][source_index] =
            U(destination_index);
        columns[kTransposeSourceValue][source_index] =
            S(source[source_index]);
    }
    for (uint64_t index = 0;
         index < schedule.value_count; ++index) {
        columns[kTransposeDestinationIndex][index] = U(index);
        columns[kTransposeDestinationValue][index] =
            S(destination[index]);
    }
    pin.logical_rows = schedule.value_count;
    pin.n_rows = n_rows;
    const uint32_t n_coeffs =
        AirCommitmentLen(BuildTransposeCS(pin));
    if (n_coeffs == 0) {
        return Fail(why, "transpose_commitment_len");
    }
    const std::vector<uint256> base_roots{
        aq::AirCommittedValuesRoot<Fp3>(
            columns[kTransposeMappedIndex],
            n_coeffs),
        aq::AirCommittedValuesRoot<Fp3>(
            columns[kTransposeSourceValue],
            n_coeffs),
        aq::AirCommittedValuesRoot<Fp3>(
            columns[kTransposeDestinationIndex],
            n_coeffs),
        aq::AirCommittedValuesRoot<Fp3>(
            columns[kTransposeDestinationValue],
            n_coeffs),
    };
    pin.challenge_seed = ChallengeSeed(
        RCStage3RelationEndpoint::EpisodeWiringTranspose,
        pin.statement_commitment, pin.manifest_commitment,
        schedule.schedule_index, schedule.value_count,
        base_roots);
    if (pin.challenge_seed.IsNull()) {
        return Fail(why, "transpose_challenge_seed");
    }
    const std::array<std::pair<uint32_t, uint32_t>, 2> lanes{{
        {kTransposeDenominatorInverse1,
         kTransposeRunningProduct1},
        {kTransposeDenominatorInverse2,
         kTransposeRunningProduct2},
    }};
    for (uint32_t lane = 0; lane < lanes.size(); ++lane) {
        const Fp3 beta = WiringChallengeFp3(
            pin.challenge_seed, "stage3_transpose_beta",
            schedule.schedule_index, lane);
        const Fp3 gamma = WiringChallengeFp3(
            pin.challenge_seed, "stage3_transpose_gamma",
            schedule.schedule_index, lane);
        Fp3 running = Fp3::One();
        for (uint32_t row = 0; row < n_rows; ++row) {
            columns[lanes[lane].second][row] = running;
            const Fp3 numerator = gf::Sub(
                gamma,
                gf::Add(
                    columns[kTransposeSourceValue][row],
                    gf::Mul(
                        beta,
                        columns[kTransposeMappedIndex][row])));
            const Fp3 denominator = gf::Sub(
                gamma,
                gf::Add(
                    columns[kTransposeDestinationValue][row],
                    gf::Mul(
                        beta,
                        columns[kTransposeDestinationIndex][row])));
            if (gf::Eq(denominator, Fp3::Zero())) {
                return Fail(why, "transpose_challenge_pole");
            }
            columns[lanes[lane].first][row] =
                gf::Inv(denominator);
            running = gf::Mul(
                running,
                gf::Mul(numerator, gf::Inv(denominator)));
        }
        if (!gf::Eq(running, Fp3::One())) {
            return Fail(why, "transpose_product_terminal");
        }
    }
    return true;
}

bool BuildMemory(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t address,
    const std::vector<Fp3>& values,
    RCStage3EpisodeSemanticMemoryBundle& out,
    std::string* why)
{
    return ProveRCStage3EpisodeSemanticMemoryBundle(
        endpoint, statement_commitment, address, 1,
        values, out, why);
}

bool VerifyMemory(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    uint64_t address,
    const std::vector<Fp3>& values,
    const RCStage3EpisodeSemanticMemoryBundle& bundle,
    std::string* why)
{
    if (values.empty() ||
        values.size() > kRCStage3EpisodeSemanticMaxRows) {
        return Fail(why, "memory_value_count");
    }
    const uint32_t n_rows = NextPowerOfTwo(values.size());
    const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
        values, values.size(), n_rows, why);
    if (!root.has_value()) return false;
    return VerifyRCStage3EpisodeSemanticMemoryBundle(
        endpoint, statement_commitment, values.size(),
        address, 1, {*root}, bundle, why);
}

bool MemoryAliasesRoot(
    const RCStage3EpisodeSemanticMemoryBundle& bundle,
    const uint256& expected_root,
    std::string* why)
{
    if (expected_root.IsNull() ||
        bundle.shards.size() != 1 ||
        bundle.shards[0].shard_index != 0 ||
        bundle.shards[0].value_begin != 0 ||
        bundle.shards[0].manifest.canonical_value_root !=
            expected_root) {
        return Fail(why, "memory_root_alias");
    }
    return true;
}

uint256 TransposeEdgeCommitment(
    const RCStage3EpisodeWiringTransposeEdge& edge)
{
    if (edge.pin.pin_commitment.IsNull() ||
        edge.source_memory.bundle_commitment.IsNull() ||
        edge.destination_memory.bundle_commitment.IsNull() ||
        edge.transposed_vector_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << TRANSPOSE_EDGE_DOMAIN;
    hash << edge.schedule.schedule_index;
    hash << edge.schedule.layer_ordinal;
    hash << static_cast<uint8_t>(edge.schedule.slot);
    hash << edge.schedule.first_column;
    hash << edge.schedule.n_chunks;
    hash << edge.schedule.source_rows;
    hash << edge.schedule.source_cols;
    hash << edge.schedule.value_count;
    hash << edge.schedule.registered_source_root;
    hash << edge.pin.pin_commitment;
    hash << edge.source_memory.bundle_commitment;
    hash << edge.destination_memory.bundle_commitment;
    hash << edge.transposed_vector_root;
    return hash.GetHash();
}

uint256 ResidualEdgeCommitment(
    const RCStage3EpisodeWiringResidualEdge& edge)
{
    if (edge.pin.pin_commitment.IsNull() ||
        edge.y_memory.bundle_commitment.IsNull() ||
        edge.residual_memory.bundle_commitment.IsNull() ||
        edge.extract_input_memory.bundle_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << RESIDUAL_EDGE_DOMAIN;
    hash << edge.schedule.schedule_index;
    hash << edge.schedule.layer_ordinal;
    hash << edge.schedule.residual_first_column;
    hash << edge.schedule.residual_n_chunks;
    hash << edge.schedule.value_count;
    hash << edge.schedule.registered_y_root;
    hash << edge.schedule.registered_residual_root;
    hash << edge.pin.pin_commitment;
    hash << edge.y_memory.bundle_commitment;
    hash << edge.residual_memory.bundle_commitment;
    hash << edge.extract_input_memory.bundle_commitment;
    return hash.GetHash();
}

uint256 OrderEdgeCommitment(
    const RCStage3EpisodeWiringRoundOrderEdge& edge)
{
    if (edge.pin.pin_commitment.IsNull() ||
        edge.producer_memory.bundle_commitment.IsNull() ||
        edge.consumer_memory.bundle_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << ORDER_EDGE_DOMAIN;
    hash << edge.schedule.schedule_index;
    hash << edge.schedule.producer_layer_ordinal;
    hash << edge.schedule.consumer_layer_ordinal;
    hash << edge.schedule.round_index;
    hash << edge.schedule.first_column;
    hash << edge.schedule.n_chunks;
    hash << edge.schedule.value_count;
    hash << edge.schedule.registered_consumer_root;
    hash << edge.pin.pin_commitment;
    hash << edge.producer_memory.bundle_commitment;
    hash << edge.consumer_memory.bundle_commitment;
    return hash.GetHash();
}

} // namespace

aq::AirConstraintSystem<Fp3>
BuildRCStage3EpisodeWiringTransposeConstraintSystem(
    const RCStage3EpisodeWiringAirPin& pin)
{
    return BuildTransposeCS(pin);
}

std::array<Fp3, 4>
RCStage3EpisodeWiringTransposeChallengeVector(
    const uint256& challenge_seed, uint32_t schedule_index)
{
    std::array<Fp3, 4> out{};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        out[2 * lane] = WiringChallengeFp3(
            challenge_seed, "stage3_transpose_beta",
            schedule_index, lane);
        out[2 * lane + 1] = WiringChallengeFp3(
            challenge_seed, "stage3_transpose_gamma",
            schedule_index, lane);
    }
    return out;
}

std::vector<RCStage3EpisodeWiringTransposeSchedule>
BuildRCStage3EpisodeWiringTransposeSchedule(
    const RCStage3GemmExtractManifest& manifest)
{
    std::vector<RCStage3EpisodeWiringTransposeSchedule> out;
    if (!ValidateRCStage3GemmExtractManifest(manifest, nullptr)) {
        return out;
    }
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < manifest.layers.size();
         ++layer_ordinal) {
        const auto& layer = manifest.layers[layer_ordinal];
        const auto append =
            [&](RCStage3EpisodeWiringOperandSlot slot,
                const RCGkrOperandRef& ref,
                bool transpose,
                uint32_t rows, uint32_t cols,
                const uint256& root) {
                if (!transpose) return;
                RCStage3EpisodeWiringTransposeSchedule entry;
                entry.schedule_index = out.size();
                entry.layer_ordinal = layer_ordinal;
                entry.slot = slot;
                entry.first_column = ref.first_column;
                entry.n_chunks = ref.n_chunks;
                entry.source_rows = rows;
                entry.source_cols = cols;
                entry.value_count =
                    static_cast<uint64_t>(rows) * cols;
                entry.registered_source_root = root;
                out.push_back(std::move(entry));
            };
        append(
            RCStage3EpisodeWiringOperandSlot::A,
            layer.a, layer.a.transpose,
            layer.k, layer.m,
            layer.bindings.operand_a_root);
        append(
            RCStage3EpisodeWiringOperandSlot::B,
            layer.b, layer.b.transpose,
            layer.n, layer.k,
            layer.bindings.operand_b_root);
    }
    return out;
}

std::vector<RCStage3EpisodeWiringResidualSchedule>
BuildRCStage3EpisodeWiringResidualSchedule(
    const RCStage3GemmExtractManifest& manifest)
{
    std::vector<RCStage3EpisodeWiringResidualSchedule> out;
    if (!ValidateRCStage3GemmExtractManifest(manifest, nullptr)) {
        return out;
    }
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < manifest.layers.size();
         ++layer_ordinal) {
        const auto& layer = manifest.layers[layer_ordinal];
        if (layer.residual_first_column < 0) continue;
        const auto registered = FindRegisteredRoot(
            manifest,
            static_cast<uint32_t>(
                layer.residual_first_column),
            layer_ordinal);
        if (!registered.has_value()) return {};
        RCStage3EpisodeWiringResidualSchedule entry;
        entry.schedule_index = out.size();
        entry.layer_ordinal = layer_ordinal;
        entry.residual_first_column =
            layer.residual_first_column;
        entry.residual_n_chunks = registered->first;
        entry.value_count = layer.gemm_cell_count;
        entry.registered_y_root =
            layer.bindings.gemm_y_root;
        entry.registered_residual_root =
            registered->second;
        out.push_back(std::move(entry));
    }
    return out;
}

std::vector<RCStage3EpisodeWiringRoundOrderSchedule>
BuildRCStage3EpisodeWiringRoundOrderSchedule(
    const RCStage3GemmExtractManifest& manifest)
{
    std::vector<RCStage3EpisodeWiringRoundOrderSchedule> out;
    if (!ValidateRCStage3GemmExtractManifest(manifest, nullptr)) {
        return out;
    }
    for (uint32_t consumer = 0;
         consumer < manifest.layers.size(); ++consumer) {
        const auto& layer = manifest.layers[consumer];
        const auto producer = FindProducer(
            manifest, layer.a.first_column, consumer);
        if (!producer.has_value()) continue;
        RCStage3EpisodeWiringRoundOrderSchedule entry;
        entry.schedule_index = out.size();
        entry.producer_layer_ordinal = *producer;
        entry.consumer_layer_ordinal = consumer;
        entry.round_index = layer.round;
        entry.first_column = layer.a.first_column;
        entry.n_chunks = layer.a.n_chunks;
        entry.value_count =
            static_cast<uint64_t>(layer.m) * layer.k;
        entry.registered_consumer_root =
            layer.bindings.operand_a_root;
        out.push_back(std::move(entry));
    }
    return out;
}

uint256 ComputeRCStage3EpisodeWiringAirPinCommitment(
    const RCStage3EpisodeWiringAirPin& pin)
{
    if (pin.version != kRCStage3EpisodeWiringProductVersion ||
        static_cast<uint16_t>(pin.endpoint) < 16 ||
        static_cast<uint16_t>(pin.endpoint) > 18 ||
        pin.statement_commitment.IsNull() ||
        pin.manifest_commitment.IsNull() ||
        pin.logical_rows == 0 || pin.n_rows == 0 ||
        pin.challenge_seed.IsNull() ||
        pin.column_roots.empty()) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN << pin.version;
    hash << static_cast<uint16_t>(pin.endpoint);
    hash << pin.statement_commitment << pin.manifest_commitment;
    hash << pin.schedule_index;
    hash << pin.logical_rows << pin.n_rows;
    hash << pin.challenge_seed;
    hash << static_cast<uint32_t>(pin.column_roots.size());
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return {};
        }
        hash << i << pin.column_roots[i].root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeWiringProductCommitment(
    const RCStage3EpisodeWiringProduct& product)
{
    if (product.version !=
            kRCStage3EpisodeWiringProductVersion ||
        product.statement_commitment.IsNull() ||
        product.manifest_commitment.IsNull() ||
        product.gemm_product_commitment.IsNull() ||
        product.extract_product_commitment.IsNull() ||
        product.transpose_edges.empty() ||
        product.residual_edges.empty() ||
        product.round_order_edges.empty()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.manifest_commitment;
    hash << product.gemm_product_commitment;
    hash << product.extract_product_commitment;
    hash << static_cast<uint32_t>(product.transpose_edges.size());
    for (const auto& edge : product.transpose_edges) {
        if (edge.edge_commitment.IsNull()) return {};
        hash << edge.edge_commitment;
    }
    hash << static_cast<uint32_t>(product.residual_edges.size());
    for (const auto& edge : product.residual_edges) {
        if (edge.edge_commitment.IsNull()) return {};
        hash << edge.edge_commitment;
    }
    hash << static_cast<uint32_t>(
        product.round_order_edges.size());
    for (const auto& edge : product.round_order_edges) {
        if (edge.edge_commitment.IsNull()) return {};
        hash << edge.edge_commitment;
    }
    return hash.GetHash();
}

bool BuildRCStage3EpisodeWiringProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    RCStage3EpisodeWiringProduct& out,
    std::string* why)
{
    out = {};
    if (!BaseShape(statement, manifest, gemm, extract, why)) {
        return false;
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    out.gemm_product_commitment = gemm.collection_commitment;
    out.extract_product_commitment =
        extract.collection_commitment;

    const auto transpose_schedule =
        BuildRCStage3EpisodeWiringTransposeSchedule(manifest);
    for (const auto& schedule : transpose_schedule) {
        const auto& layer =
            gemm.layers[schedule.layer_ordinal];
        const auto& source =
            schedule.slot == RCStage3EpisodeWiringOperandSlot::A
            ? layer.operand_a : layer.operand_b;
        std::vector<int8_t> destination;
        std::vector<std::vector<Fp3>> columns;
        RCStage3EpisodeWiringTransposeEdge edge;
        edge.schedule = schedule;
        edge.pin.endpoint =
            RCStage3RelationEndpoint::EpisodeWiringTranspose;
        edge.pin.statement_commitment = out.statement_commitment;
        edge.pin.manifest_commitment = out.manifest_commitment;
        edge.pin.schedule_index = schedule.schedule_index;
        if (!BuildTransposeColumns(
                schedule, source, edge.pin,
                destination, columns, why)) {
            return false;
        }
        const auto source_values = ToField(source);
        const auto destination_values = ToField(destination);
        if (VectorRoot(
                out.statement_commitment,
                schedule.first_column, schedule.n_chunks,
                source_values, why) !=
                schedule.registered_source_root ||
            !BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringTranspose,
                out.statement_commitment,
                Address(
                    TRANSPOSE_ADDRESS,
                    schedule.schedule_index, 0),
                source_values, edge.source_memory, why) ||
            !BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringTranspose,
                out.statement_commitment,
                Address(
                    TRANSPOSE_ADDRESS,
                    schedule.schedule_index, 1),
                destination_values,
                edge.destination_memory, why)) {
            return Fail(why, "build_transpose_memory");
        }
        edge.transposed_vector_root = VectorRoot(
            out.statement_commitment,
            schedule.first_column, schedule.n_chunks,
            destination_values, why);
        if (edge.transposed_vector_root.IsNull() ||
            !ProvePin(
                edge.pin, BuildTransposeCS(edge.pin),
                columns, edge.proof, why)) {
            return Fail(why, "build_transpose_proof");
        }
        edge.edge_commitment = TransposeEdgeCommitment(edge);
        if (edge.edge_commitment.IsNull()) {
            return Fail(why, "build_transpose_commitment");
        }
        out.transpose_edges.push_back(std::move(edge));
    }

    const auto residual_schedule =
        BuildRCStage3EpisodeWiringResidualSchedule(manifest);
    for (const auto& schedule : residual_schedule) {
        const auto& layer =
            gemm.layers[schedule.layer_ordinal];
        std::vector<int64_t> input;
        if (!ExtractInputValues(
                manifest, extract, schedule.layer_ordinal,
                input, why) ||
            input.size() != layer.gemm_y.size()) {
            return Fail(why, "build_residual_input");
        }
        const uint32_t n_rows =
            NextPowerOfTwo(schedule.value_count);
        if (n_rows == 0) {
            return Fail(why, "build_residual_bound");
        }
        std::vector<std::vector<Fp3>> columns(
            kResidualColumns,
            std::vector<Fp3>(n_rows, Fp3::Zero()));
        for (uint64_t i = 0; i < schedule.value_count; ++i) {
            const int64_t sum =
                layer.gemm_y[i] + layer.residual[i];
            if (input[i] != sum) {
                return Fail(why, "build_residual_value");
            }
            columns[kResidualY][i] = S(layer.gemm_y[i]);
            columns[kResidualValue][i] = S(layer.residual[i]);
            columns[kResidualSum][i] = S(sum);
            columns[kResidualExtractInput][i] = S(input[i]);
        }
        RCStage3EpisodeWiringResidualEdge edge;
        edge.schedule = schedule;
        edge.pin.endpoint =
            RCStage3RelationEndpoint::EpisodeWiringResidual;
        edge.pin.statement_commitment = out.statement_commitment;
        edge.pin.manifest_commitment = out.manifest_commitment;
        edge.pin.schedule_index = schedule.schedule_index;
        edge.pin.logical_rows = schedule.value_count;
        edge.pin.n_rows = n_rows;
        const std::vector<uint256> base_roots{
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kResidualY], n_rows),
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kResidualValue], n_rows),
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kResidualExtractInput], n_rows),
        };
        edge.pin.challenge_seed = ChallengeSeed(
            RCStage3RelationEndpoint::EpisodeWiringResidual,
            out.statement_commitment, out.manifest_commitment,
            schedule.schedule_index, schedule.value_count,
            base_roots);
        RCGkrOperandRef y_ref{
            manifest.layers[schedule.layer_ordinal]
                .y_first_column,
            manifest.layers[schedule.layer_ordinal]
                .y_chunks,
            false};
        if (VectorRoot(
                out.statement_commitment,
                y_ref.first_column, y_ref.n_chunks,
                ToField(layer.gemm_y), why) !=
                schedule.registered_y_root ||
            VectorRoot(
                out.statement_commitment,
                schedule.residual_first_column,
                schedule.residual_n_chunks,
                ToField(layer.residual), why) !=
                schedule.registered_residual_root ||
            !BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                out.statement_commitment,
                Address(
                    RESIDUAL_ADDRESS,
                    schedule.schedule_index, 0),
                ToField(layer.gemm_y), edge.y_memory, why) ||
            !BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                out.statement_commitment,
                Address(
                    RESIDUAL_ADDRESS,
                    schedule.schedule_index, 1),
                ToField(layer.residual),
                edge.residual_memory, why) ||
            !BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                out.statement_commitment,
                Address(
                    RESIDUAL_ADDRESS,
                    schedule.schedule_index, 2),
                ToField(input),
                edge.extract_input_memory, why) ||
            !ProvePin(
                edge.pin, BuildResidualCS(n_rows),
                columns, edge.proof, why)) {
            return Fail(why, "build_residual_proof_or_memory");
        }
        edge.edge_commitment = ResidualEdgeCommitment(edge);
        if (edge.edge_commitment.IsNull()) {
            return Fail(why, "build_residual_commitment");
        }
        out.residual_edges.push_back(std::move(edge));
    }

    const auto order_schedule =
        BuildRCStage3EpisodeWiringRoundOrderSchedule(manifest);
    for (const auto& schedule : order_schedule) {
        const auto& values =
            gemm.layers[schedule.consumer_layer_ordinal]
                .operand_a;
        if (!ValuesMatchProducerOutput(
                manifest, extract,
                schedule.producer_layer_ordinal,
                values, why)) {
            return Fail(why, "build_order_producer");
        }
        const auto field_values = ToField(values);
        if (VectorRoot(
                out.statement_commitment,
                schedule.first_column, schedule.n_chunks,
                field_values, why) !=
                schedule.registered_consumer_root) {
            return Fail(why, "build_order_consumer_root");
        }
        const uint32_t n_rows =
            NextPowerOfTwo(schedule.value_count);
        if (n_rows == 0 ||
            values.size() != schedule.value_count) {
            return Fail(why, "build_order_bound");
        }
        std::vector<std::vector<Fp3>> columns(
            kOrderColumns,
            std::vector<Fp3>(n_rows, Fp3::Zero()));
        std::copy(
            field_values.begin(), field_values.end(),
            columns[kOrderProducer].begin());
        std::copy(
            field_values.begin(), field_values.end(),
            columns[kOrderConsumer].begin());
        RCStage3EpisodeWiringRoundOrderEdge edge;
        edge.schedule = schedule;
        edge.pin.endpoint =
            RCStage3RelationEndpoint::EpisodeWiringRoundOrder;
        edge.pin.statement_commitment = out.statement_commitment;
        edge.pin.manifest_commitment = out.manifest_commitment;
        edge.pin.schedule_index = schedule.schedule_index;
        edge.pin.logical_rows = schedule.value_count;
        edge.pin.n_rows = n_rows;
        const std::vector<uint256> base_roots{
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kOrderProducer], n_rows),
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kOrderConsumer], n_rows),
        };
        edge.pin.challenge_seed = ChallengeSeed(
            RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
            out.statement_commitment, out.manifest_commitment,
            schedule.schedule_index, schedule.value_count,
            base_roots);
        if (!BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
                out.statement_commitment,
                Address(
                    ORDER_ADDRESS,
                    schedule.schedule_index, 0),
                field_values, edge.producer_memory, why) ||
            !BuildMemory(
                RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
                out.statement_commitment,
                Address(
                    ORDER_ADDRESS,
                    schedule.schedule_index, 1),
                field_values, edge.consumer_memory, why) ||
            !ProvePin(
                edge.pin, BuildOrderCS(n_rows),
                columns, edge.proof, why)) {
            return Fail(why, "build_order_proof_or_memory");
        }
        edge.edge_commitment = OrderEdgeCommitment(edge);
        if (edge.edge_commitment.IsNull()) {
            return Fail(why, "build_order_commitment");
        }
        out.round_order_edges.push_back(std::move(edge));
    }
    out.product_commitment =
        ComputeRCStage3EpisodeWiringProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_product_commitment");
}

bool ValidateRCStage3EpisodeWiringProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeWiringProduct& product,
    std::string* why)
{
    if (!BaseShape(statement, manifest, gemm, extract, why)) {
        return false;
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    const auto transpose_schedule =
        BuildRCStage3EpisodeWiringTransposeSchedule(manifest);
    const auto residual_schedule =
        BuildRCStage3EpisodeWiringResidualSchedule(manifest);
    const auto order_schedule =
        BuildRCStage3EpisodeWiringRoundOrderSchedule(manifest);
    if (product.version !=
            kRCStage3EpisodeWiringProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.manifest_commitment != manifest_commitment ||
        product.gemm_product_commitment !=
            gemm.collection_commitment ||
        product.extract_product_commitment !=
            extract.collection_commitment ||
        product.transpose_edges.size() !=
            transpose_schedule.size() ||
        product.residual_edges.size() !=
            residual_schedule.size() ||
        product.round_order_edges.size() !=
            order_schedule.size()) {
        return Fail(why, "schedule_public_shape");
    }

    for (uint32_t i = 0; i < transpose_schedule.size(); ++i) {
        const auto& expected = transpose_schedule[i];
        const auto& edge = product.transpose_edges[i];
        const auto& layer = gemm.layers[expected.layer_ordinal];
        const auto& source =
            expected.slot == RCStage3EpisodeWiringOperandSlot::A
            ? layer.operand_a : layer.operand_b;
        std::vector<int8_t> destination;
        std::vector<std::vector<Fp3>> columns;
        RCStage3EpisodeWiringAirPin expected_pin;
        expected_pin.endpoint =
            RCStage3RelationEndpoint::EpisodeWiringTranspose;
        expected_pin.statement_commitment = statement_commitment;
        expected_pin.manifest_commitment = manifest_commitment;
        expected_pin.schedule_index = expected.schedule_index;
        if (edge.schedule != expected ||
            !BuildTransposeColumns(
                expected, source, expected_pin,
                destination, columns, why)) {
            return Fail(why, "transpose_schedule");
        }
        for (uint32_t column = 0;
             column < columns.size(); ++column) {
            expected_pin.column_roots.push_back({
                column,
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[column],
                    AirCommitmentLen(
                        BuildTransposeCS(expected_pin)))});
        }
        expected_pin.pin_commitment =
            ComputeRCStage3EpisodeWiringAirPinCommitment(
                expected_pin);
        if (!PinShape(
                edge.pin,
                RCStage3RelationEndpoint::EpisodeWiringTranspose,
                statement_commitment, manifest_commitment,
                i, expected.value_count, expected_pin.n_rows,
                kTransposeColumns, why) ||
            edge.pin.pin_commitment !=
                expected_pin.pin_commitment ||
            VectorRoot(
                statement_commitment,
                expected.first_column, expected.n_chunks,
                ToField(source), why) !=
                expected.registered_source_root ||
            edge.transposed_vector_root != VectorRoot(
                statement_commitment,
                expected.first_column, expected.n_chunks,
                ToField(destination), why) ||
            !MemoryAliasesRoot(
                edge.source_memory,
                edge.pin.column_roots[
                    kTransposeSourceValue].root,
                why) ||
            !MemoryAliasesRoot(
                edge.destination_memory,
                edge.pin.column_roots[
                    kTransposeDestinationValue].root,
                why) ||
            edge.edge_commitment !=
                TransposeEdgeCommitment(edge)) {
            return Fail(why, "transpose_roots");
        }
        for (uint32_t column = 0;
             column < kTransposeColumns; ++column) {
            if (edge.pin.column_roots[column].root !=
                expected_pin.column_roots[column].root) {
                return Fail(why, "transpose_column_root");
            }
        }
    }

    for (uint32_t i = 0; i < residual_schedule.size(); ++i) {
        const auto& expected = residual_schedule[i];
        const auto& edge = product.residual_edges[i];
        const auto& layer = gemm.layers[expected.layer_ordinal];
        std::vector<int64_t> input;
        if (edge.schedule != expected ||
            !ExtractInputValues(
                manifest, extract, expected.layer_ordinal,
                input, why)) {
            return Fail(why, "residual_schedule");
        }
        const uint32_t n_rows =
            NextPowerOfTwo(expected.value_count);
        std::vector<std::vector<Fp3>> columns(
            kResidualColumns,
            std::vector<Fp3>(n_rows, Fp3::Zero()));
        for (uint64_t row = 0;
             row < expected.value_count; ++row) {
            columns[kResidualY][row] = S(layer.gemm_y[row]);
            columns[kResidualValue][row] =
                S(layer.residual[row]);
            columns[kResidualSum][row] =
                S(layer.gemm_y[row] + layer.residual[row]);
            columns[kResidualExtractInput][row] = S(input[row]);
        }
        const std::vector<uint256> base_roots{
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kResidualY], n_rows),
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kResidualValue], n_rows),
            aq::AirCommittedValuesRoot<Fp3>(
                columns[kResidualExtractInput], n_rows),
        };
        const uint256 expected_challenge_seed = ChallengeSeed(
            RCStage3RelationEndpoint::EpisodeWiringResidual,
            statement_commitment, manifest_commitment,
            expected.schedule_index, expected.value_count,
            base_roots);
        const auto& spec =
            manifest.layers[expected.layer_ordinal];
        if (!PinShape(
                edge.pin,
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                statement_commitment, manifest_commitment,
                i, expected.value_count, n_rows,
                kResidualColumns, why) ||
            edge.pin.challenge_seed != expected_challenge_seed ||
            VectorRoot(
                statement_commitment,
                spec.y_first_column, spec.y_chunks,
                ToField(layer.gemm_y), why) !=
                expected.registered_y_root ||
            VectorRoot(
                statement_commitment,
                expected.residual_first_column,
                expected.residual_n_chunks,
                ToField(layer.residual), why) !=
                expected.registered_residual_root ||
            !MemoryAliasesRoot(
                edge.y_memory,
                edge.pin.column_roots[kResidualY].root,
                why) ||
            !MemoryAliasesRoot(
                edge.residual_memory,
                edge.pin.column_roots[kResidualValue].root,
                why) ||
            !MemoryAliasesRoot(
                edge.extract_input_memory,
                edge.pin.column_roots[
                    kResidualExtractInput].root,
                why) ||
            edge.edge_commitment !=
                ResidualEdgeCommitment(edge)) {
            return Fail(why, "residual_roots");
        }
        for (uint32_t column = 0;
             column < kResidualColumns; ++column) {
            if (edge.pin.column_roots[column].root !=
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[column], n_rows)) {
                return Fail(why, "residual_column_root");
            }
        }
    }

    for (uint32_t i = 0; i < order_schedule.size(); ++i) {
        const auto& expected = order_schedule[i];
        const auto& edge = product.round_order_edges[i];
        const auto& values =
            gemm.layers[expected.consumer_layer_ordinal]
                .operand_a;
        const uint32_t n_rows =
            NextPowerOfTwo(expected.value_count);
        std::vector<Fp3> padded(n_rows, Fp3::Zero());
        const auto field_values = ToField(values);
        std::copy(
            field_values.begin(), field_values.end(),
            padded.begin());
        const uint256 root =
            aq::AirCommittedValuesRoot<Fp3>(padded, n_rows);
        const uint256 expected_challenge_seed = ChallengeSeed(
            RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
            statement_commitment, manifest_commitment,
            expected.schedule_index, expected.value_count,
            {root, root});
        if (edge.schedule != expected ||
            !ValuesMatchProducerOutput(
                manifest, extract,
                expected.producer_layer_ordinal,
                values, why) ||
            !PinShape(
                edge.pin,
                RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
                statement_commitment, manifest_commitment,
                i, expected.value_count, n_rows,
                kOrderColumns, why) ||
            edge.pin.challenge_seed != expected_challenge_seed ||
            edge.pin.column_roots[0].root != root ||
            edge.pin.column_roots[1].root != root ||
            VectorRoot(
                statement_commitment,
                expected.first_column, expected.n_chunks,
                field_values, why) !=
                expected.registered_consumer_root ||
            !MemoryAliasesRoot(
                edge.producer_memory,
                edge.pin.column_roots[kOrderProducer].root,
                why) ||
            !MemoryAliasesRoot(
                edge.consumer_memory,
                edge.pin.column_roots[kOrderConsumer].root,
                why) ||
            edge.edge_commitment != OrderEdgeCommitment(edge)) {
            return Fail(why, "order_schedule_or_root");
        }
    }
    if (product.product_commitment !=
        ComputeRCStage3EpisodeWiringProductCommitment(product)) {
        return Fail(why, "product_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeWiringLocalProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeWiringProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3EpisodeWiringProductSchedule(
            statement, manifest, gemm, extract,
            product, why)) {
        return false;
    }
    for (const auto& edge : product.transpose_edges) {
        const auto& layer =
            gemm.layers[edge.schedule.layer_ordinal];
        const auto& source =
            edge.schedule.slot ==
                RCStage3EpisodeWiringOperandSlot::A
            ? layer.operand_a : layer.operand_b;
        std::vector<int8_t> destination;
        std::vector<std::vector<Fp3>> columns;
        auto pin = edge.pin;
        if (!BuildTransposeColumns(
                edge.schedule, source, pin,
                destination, columns, why) ||
            !VerifyPin(
                edge.pin, BuildTransposeCS(edge.pin),
                edge.proof, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringTranspose,
                product.statement_commitment,
                Address(
                    TRANSPOSE_ADDRESS,
                    edge.schedule.schedule_index, 0),
                ToField(source), edge.source_memory, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringTranspose,
                product.statement_commitment,
                Address(
                    TRANSPOSE_ADDRESS,
                    edge.schedule.schedule_index, 1),
                ToField(destination),
                edge.destination_memory, why)) {
            return false;
        }
    }
    for (const auto& edge : product.residual_edges) {
        const auto& layer =
            gemm.layers[edge.schedule.layer_ordinal];
        std::vector<int64_t> input;
        if (!ExtractInputValues(
                manifest, extract,
                edge.schedule.layer_ordinal, input, why) ||
            !VerifyPin(
                edge.pin, BuildResidualCS(edge.pin.n_rows),
                edge.proof, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                product.statement_commitment,
                Address(
                    RESIDUAL_ADDRESS,
                    edge.schedule.schedule_index, 0),
                ToField(layer.gemm_y), edge.y_memory, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                product.statement_commitment,
                Address(
                    RESIDUAL_ADDRESS,
                    edge.schedule.schedule_index, 1),
                ToField(layer.residual),
                edge.residual_memory, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringResidual,
                product.statement_commitment,
                Address(
                    RESIDUAL_ADDRESS,
                    edge.schedule.schedule_index, 2),
                ToField(input),
                edge.extract_input_memory, why)) {
            return false;
        }
    }
    for (const auto& edge : product.round_order_edges) {
        const auto values = ToField(
            gemm.layers[edge.schedule.consumer_layer_ordinal]
                .operand_a);
        if (!VerifyPin(
                edge.pin, BuildOrderCS(edge.pin.n_rows),
                edge.proof, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
                product.statement_commitment,
                Address(
                    ORDER_ADDRESS,
                    edge.schedule.schedule_index, 0),
                values, edge.producer_memory, why) ||
            !VerifyMemory(
                RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
                product.statement_commitment,
                Address(
                    ORDER_ADDRESS,
                    edge.schedule.schedule_index, 1),
                values, edge.consumer_memory, why)) {
            return false;
        }
    }
    return true;
}

RCStage3EpisodeWiringProductAudit
CurrentRCStage3EpisodeWiringProductAudit()
{
    RCStage3EpisodeWiringProductAudit out;
    out.exact_lambda_transpose_schedule = true;
    out.dual_transpose_permutation_executable = true;
    out.transpose_memory_aliases_executable = true;
    out.exact_residual_schedule = true;
    out.residual_addition_executable = true;
    out.residual_memory_aliases_executable = true;
    out.exact_round_order_schedule = true;
    out.every_producer_consumer_edge_executable = true;
    out.round_order_memory_aliases_executable = true;
    out.endpoints_16_through_18_bounded_local_complete =
        kRCStage3EpisodeWiringBoundedLocalExecutable;
    out.external_producer_provenance_complete = false;
    out.production_streaming_complete =
        kRCStage3EpisodeWiringProductionStreamingComplete;
    out.recursively_consumed =
        kRCStage3EpisodeWiringRecursivelyConsumed;
    out.transitively_complete = false;
    out.remaining =
        "external builder/GEMM/Extract producer proofs are not consumed by "
        "this local product; vectors above 2^20 require segmented "
        "permutation terminals, and normalized recursion remains";
    return out;
}

static_assert(kRCStage3EpisodeWiringBoundedLocalExecutable);
static_assert(!kRCStage3EpisodeWiringProductionStreamingComplete);
static_assert(!kRCStage3EpisodeWiringRecursivelyConsumed);

} // namespace matmul::v4::rc
