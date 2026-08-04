// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_initial_state_product.h>

#include <hash.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr uint8_t MANTISSA_DOMAIN = 0x6d;
constexpr uint8_t SCALE_DOMAIN = 0x65;
constexpr char LOBE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_INITIAL_LOBE_V1";
constexpr char ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_INITIAL_ENDPOINT_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_INITIAL_PRODUCT_V1";
constexpr char LINK_DOMAIN[] =
    "BTX_RC_STAGE3_CHAIN_25_30_V1";
constexpr uint32_t DEQUANT_SPLITRAP_COLUMNS =
    kRCStage3CoupledBankDequantColumns + 1;

const std::vector<uint32_t>& DequantBaseColumns()
{
    static const std::vector<uint32_t> columns{
        0, 1, 2, 3, 4, 5};
    return columns;
}

bool Fail(std::string* why, const std::string& reason)
{
    if (why) {
        *why = "stage3:coupled_initial_state:" + reason;
    }
    return false;
}

bool IsCoupled(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool IsPowerOfTwo(uint64_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 S(int64_t value)
{
    return Fp3::FromFp(gf::FromSigned(value));
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

std::vector<uint8_t> LobeSeedPreimage(
    const RCStage3CoupledShape& shape,
    const uint256& sigma,
    uint32_t lobe)
{
    const char* tag =
        RCCoupDomainTagsForVersion(
            shape.transcript_version).lobe;
    std::vector<uint8_t> out(
        reinterpret_cast<const uint8_t*>(tag),
        reinterpret_cast<const uint8_t*>(tag) +
            std::strlen(tag));
    out.insert(out.end(), sigma.begin(), sigma.end());
    AppendLe32(out, lobe);
    return out;
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

bool BuildColumns(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialLobeProduct& lobe,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const uint64_t logical =
        uint64_t{shape.lobe_width} * shape.lobe_width;
    const uint64_t scales =
        uint64_t{shape.lobe_width} *
        (shape.lobe_width / kRCMxBlockLen);
    if (!IsPowerOfTwo(logical) ||
        lobe.expanded_tile.size() != logical ||
        lobe.mantissa.output.size() != logical ||
        lobe.scale.output.size() != scales ||
        lobe.dequant_pin.logical_rows != logical ||
        lobe.dequant_pin.n_rows != logical ||
        lobe.dequant_pin.n_coeffs != logical) {
        return Fail(why, "columns_shape");
    }
    columns.assign(
        DEQUANT_SPLITRAP_COLUMNS,
        std::vector<Fp3>(logical, Fp3::Zero()));
    const uint32_t blocks =
        shape.lobe_width / kRCMxBlockLen;
    for (uint32_t row = 0; row < shape.lobe_width; ++row) {
        for (uint32_t column = 0;
             column < shape.lobe_width; ++column) {
            const uint64_t index =
                uint64_t{row} * shape.lobe_width + column;
            const uint64_t scale_index =
                uint64_t{row} * blocks +
                column / kRCMxBlockLen;
            const uint8_t scale =
                lobe.scale.output[scale_index];
            if (scale > 3) return Fail(why, "scale");
            const int8_t mantissa =
                static_cast<int8_t>(
                    lobe.mantissa.output[index]);
            const int8_t output =
                static_cast<int8_t>(
                    int32_t{mantissa} *
                    (int32_t{1} << scale));
            if (output != lobe.expanded_tile[index]) {
                return Fail(why, "dequant_value");
            }
            columns[kRCStage3CoupledBankMantissa][index] =
                S(mantissa);
            columns[kRCStage3CoupledBankRepeatedScale][index] =
                U(scale);
            columns[kRCStage3CoupledBankScaleBit0][index] =
                U(scale & 1U);
            columns[kRCStage3CoupledBankScaleBit1][index] =
                U((scale >> 1) & 1U);
            columns[kRCStage3CoupledBankScaleFactor][index] =
                U(uint8_t{1} << scale);
            columns[kRCStage3CoupledBankOutput][index] =
                S(output);
        }
    }
    return true;
}

bool CounterShape(
    const ha::CounterXofManifest& manifest,
    const uint256& seed,
    uint8_t domain,
    ha::CounterXofMode mode,
    uint64_t count,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    return (manifest.seed == seed &&
            manifest.domain == domain &&
            manifest.mode == mode &&
            manifest.output_count == count &&
            manifest.output.size() == count &&
            manifest.commitment ==
                ha::CommitCounterXofManifest(manifest) &&
            ha::BuildCounterXofManifestBoundaryInstances(
                manifest, boundaries, why) &&
            !boundaries.empty()) ||
           Fail(why, "counter_shape");
}

bool ShaShape(
    const RCStage3CoupledBankHashExecution& execution,
    const std::vector<uint8_t>& preimage,
    const uint256& statement_commitment,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    return (execution.manifest.mode == ha::ShaMode::Single &&
            execution.manifest.preimage == preimage &&
            execution.manifest.commitment ==
                ha::CommitShaManifest(execution.manifest) &&
            ha::BuildShaManifestBoundaryInstances(
                execution.manifest, boundaries, why) &&
            boundaries.size() == 1 &&
            execution.proof.endpoint ==
                RCStage3RelationEndpoint::CoupledGemmOperandA &&
            execution.proof.statement_commitment ==
                statement_commitment &&
            execution.proof.manifest_commitment ==
                execution.manifest.commitment) ||
           Fail(why, "sha_shape");
}

bool ProveBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    hs::FlatBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.proofs.resize(boundaries.size());
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness witness;
        if (!ha::BuildProgramWitness(
                program, boundaries[i].external_values,
                witness, why) ||
            !ha::ProveFixedProgramProvenanceAir(
                program, witness,
                boundaries[i].external_values,
                boundaries[i].final_words,
                hs::ComputeBoundaryProofSeed(
                    endpoint, statement_commitment,
                    manifest_commitment, i,
                    boundaries.size()),
                out.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

uint256 LobeReceipt(
    const RCStage3CoupledInitialLobeProduct& lobe)
{
    if (lobe.lobe_seed.manifest.commitment.IsNull() ||
        lobe.mantissa.commitment.IsNull() ||
        lobe.scale.commitment.IsNull() ||
        lobe.expanded_tile.empty() ||
        lobe.dequant_pin.pin_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << LOBE_DOMAIN;
    hash << kRCStage3CoupledInitialStateProductVersion;
    hash << lobe.lobe;
    hash << lobe.lobe_seed.manifest.commitment;
    hash << lobe.mantissa.commitment;
    hash << lobe.scale.commitment;
    hash << lobe.dequant_pin.pin_commitment;
    hash << lobe.dequant_pin.r0_row_group_root;
    return hash.GetHash();
}

uint256 InitialRoot(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& product)
{
    if (product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.lobes.size() != shape.lobes) {
        return {};
    }
    HashWriter hash;
    hash << ENDPOINT_DOMAIN;
    hash << kRCStage3CoupledInitialStateProductVersion;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma;
    hash << shape.rows_per_lobe;
    hash << shape.lobe_width;
    hash << static_cast<uint32_t>(product.lobes.size());
    const uint64_t active =
        uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    for (const auto& lobe : product.lobes) {
        if (lobe.lobe >= shape.lobes ||
            lobe.expanded_tile.size() < active ||
            lobe.receipt_commitment.IsNull()) {
            return {};
        }
        hash << lobe.lobe << lobe.receipt_commitment;
        hash << active;
        for (uint64_t i = 0; i < active; ++i) {
            hash << static_cast<int64_t>(
                lobe.expanded_tile[i]);
        }
    }
    return hash.GetHash();
}

uint256 ProductCommitment(
    const RCStage3CoupledInitialStateProduct& product)
{
    if (product.version !=
            kRCStage3CoupledInitialStateProductVersion ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.sigma.IsNull() || product.lobes.empty() ||
        product.initial_state_endpoint_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma;
    hash << static_cast<uint32_t>(product.lobes.size());
    for (const auto& lobe : product.lobes) {
        hash << lobe.receipt_commitment;
    }
    hash << product.initial_state_endpoint_root;
    return hash.GetHash();
}

} // namespace

bool BuildRCStage3CoupledInitialStateProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledInitialStateProduct& out,
    std::string* why)
{
    out = {};
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledGemm, shape, why);
    const uint64_t cells =
        uint64_t{shape.lobe_width} * shape.lobe_width;
    const uint64_t scales =
        uint64_t{shape.lobe_width} *
        (shape.lobe_width / kRCMxBlockLen);
    if (!IsCoupled(statement) ||
        statement.public_inputs.header_commitment.IsNull() ||
        statement.public_inputs.sigma.IsNull() ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        !counts.has_value() || !IsPowerOfTwo(cells) ||
        cells > std::numeric_limits<uint32_t>::max() ||
        cells > kRCStage3CoupledBankStreamTestMaxBytes) {
        return Fail(why, "public_shape");
    }
    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape_commitment =
        CommitRCStage3CoupledShape(shape);
    out.sigma = statement.public_inputs.sigma;
    for (uint32_t lobe_index = 0;
         lobe_index < shape.lobes; ++lobe_index) {
        RCStage3CoupledInitialLobeProduct lobe;
        lobe.lobe = lobe_index;
        if (!ha::BuildShaManifest(
                LobeSeedPreimage(
                    shape, out.sigma, lobe_index),
                ha::ShaMode::Single,
                lobe.lobe_seed.manifest, why)) {
            return Fail(why, "lobe_seed");
        }
        lobe.lobe_seed.proof.endpoint =
            RCStage3RelationEndpoint::CoupledGemmOperandA;
        lobe.lobe_seed.proof.statement_commitment =
            out.statement_commitment;
        lobe.lobe_seed.proof.manifest_commitment =
            lobe.lobe_seed.manifest.commitment;
        const uint256 seed =
            DigestUint(lobe.lobe_seed.manifest.digest);
        if (!ha::BuildCounterXofManifest(
                seed, MANTISSA_DOMAIN,
                ha::CounterXofMode::MantissaE2M1,
                cells, lobe.mantissa, why) ||
            !ha::BuildCounterXofManifest(
                seed, SCALE_DOMAIN,
                ha::CounterXofMode::Scale2Bit,
                scales, lobe.scale, why)) {
            return Fail(why, "xof");
        }
        for (auto pair : {
                 std::pair{
                     &lobe.mantissa,
                     &lobe.mantissa_proof},
                 std::pair{
                     &lobe.scale,
                     &lobe.scale_proof}}) {
            pair.second->endpoint =
                RCStage3RelationEndpoint::CoupledGemmOperandA;
            pair.second->statement_commitment =
                out.statement_commitment;
            pair.second->manifest_commitment =
                pair.first->commitment;
        }
        lobe.expanded_tile.resize(cells);
        const uint32_t blocks =
            shape.lobe_width / kRCMxBlockLen;
        for (uint32_t row = 0;
             row < shape.lobe_width; ++row) {
            for (uint32_t column = 0;
                 column < shape.lobe_width; ++column) {
                const uint64_t index =
                    uint64_t{row} *
                        shape.lobe_width + column;
                const uint64_t scale_index =
                    uint64_t{row} * blocks +
                    column / kRCMxBlockLen;
                lobe.expanded_tile[index] =
                    static_cast<int8_t>(
                        int32_t{static_cast<int8_t>(
                            lobe.mantissa.output[index])} *
                        (int32_t{1} <<
                         lobe.scale.output[scale_index]));
            }
        }
        auto& pin = lobe.dequant_pin;
        pin.statement_commitment =
            out.statement_commitment;
        pin.shape_commitment = out.shape_commitment;
        pin.sigma = out.sigma;
        pin.page_index = lobe_index;
        pin.logical_rows = cells;
        pin.n_rows = cells;
        pin.n_coeffs = cells;
        std::vector<std::vector<Fp3>> columns;
        if (!BuildColumns(
                shape, lobe, columns, why)) {
            return false;
        }
        aq::AirConstraintSystem<Fp3> row_shape;
        row_shape.n_rows = pin.n_rows;
        row_shape.n_columns =
            DEQUANT_SPLITRAP_COLUMNS;
        const auto r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                row_shape, columns,
                DequantBaseColumns());
        if (!r0.valid ||
            r0.base_row_commitment.IsNull()) {
            return Fail(
                why, "build_r0:" + r0.note);
        }
        pin.r0_row_group_root =
            r0.base_row_commitment;
        pin.pin_commitment =
            ComputeRCStage3CoupledBankDequantPinCommitment(
                pin);
        lobe.receipt_commitment = LobeReceipt(lobe);
        if (pin.pin_commitment.IsNull() ||
            lobe.receipt_commitment.IsNull()) {
            return Fail(why, "receipt");
        }
        out.lobes.push_back(std::move(lobe));
    }
    out.initial_state_endpoint_root =
        InitialRoot(shape, out);
    out.product_commitment =
        ProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "product");
}

bool ProveRCStage3CoupledInitialStateProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledInitialStateProduct& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledInitialStateProduct(
            statement, shape, out, why)) {
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    for (auto& lobe : out.lobes) {
        if (!ha::BuildShaManifestBoundaryInstances(
                lobe.lobe_seed.manifest,
                boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::CoupledGemmOperandA,
                out.statement_commitment,
                lobe.lobe_seed.manifest.commitment,
                boundaries, lobe.lobe_seed.proof, why) ||
            !ha::BuildCounterXofManifestBoundaryInstances(
                lobe.mantissa, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::CoupledGemmOperandA,
                out.statement_commitment,
                lobe.mantissa.commitment,
                boundaries, lobe.mantissa_proof, why) ||
            !ha::BuildCounterXofManifestBoundaryInstances(
                lobe.scale, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::CoupledGemmOperandA,
                out.statement_commitment,
                lobe.scale.commitment,
                boundaries, lobe.scale_proof, why)) {
            return Fail(why, "hash_prove");
        }
        std::vector<std::vector<Fp3>> columns;
        aq::AirConstraintSystem<Fp3> cs;
        if (!BuildColumns(
                shape, lobe, columns, why) ||
            !BuildRCStage3CoupledBankDequantConstraintSystem(
                lobe.dequant_pin, cs, why)) {
            return false;
        }
        const auto retained_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                cs, columns,
                DequantBaseColumns());
        if (!retained_r0.valid ||
            retained_r0.base_row_commitment !=
                lobe.dequant_pin.r0_row_group_root) {
            return Fail(why, "dequant_r0");
        }
        auto proved =
            aq::AirQuotientProveRowsSplitRap(
            cs, columns, DequantBaseColumns(),
            ComputeRCStage3CoupledBankDequantSeed(
                lobe.dequant_pin),
            {}, &retained_r0);
        if (!proved.ok || !proved.division_exact) {
            return Fail(why, "dequant_prove");
        }
        lobe.dequant_proof = std::move(proved.proof);
    }
    return true;
}

bool ValidateRCStage3CoupledInitialStateProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& product,
    std::string* why)
{
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint64_t cells =
        uint64_t{shape.lobe_width} * shape.lobe_width;
    const uint64_t scales =
        uint64_t{shape.lobe_width} *
        (shape.lobe_width / kRCMxBlockLen);
    if (!IsCoupled(statement) ||
        statement.public_inputs.header_commitment.IsNull() ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        product.version !=
            kRCStage3CoupledInitialStateProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.shape_commitment != shape_commitment ||
        product.sigma != statement.public_inputs.sigma ||
        product.lobes.size() != shape.lobes ||
        !IsPowerOfTwo(cells) ||
        cells > kRCStage3CoupledBankStreamTestMaxBytes) {
        return Fail(why, "schedule_shape");
    }
    for (uint32_t i = 0;
         i < product.lobes.size(); ++i) {
        const auto& lobe = product.lobes[i];
        if (lobe.lobe != i ||
            !ShaShape(
                lobe.lobe_seed,
                LobeSeedPreimage(shape, product.sigma, i),
                statement_commitment, why)) {
            return Fail(why, "schedule_seed");
        }
        const uint256 seed =
            DigestUint(lobe.lobe_seed.manifest.digest);
        if (!CounterShape(
                lobe.mantissa, seed, MANTISSA_DOMAIN,
                ha::CounterXofMode::MantissaE2M1,
                cells, why) ||
            !CounterShape(
                lobe.scale, seed, SCALE_DOMAIN,
                ha::CounterXofMode::Scale2Bit,
                scales, why) ||
            lobe.mantissa_proof.endpoint !=
                RCStage3RelationEndpoint::CoupledGemmOperandA ||
            lobe.scale_proof.endpoint !=
                RCStage3RelationEndpoint::CoupledGemmOperandA ||
            lobe.mantissa_proof.statement_commitment !=
                statement_commitment ||
            lobe.scale_proof.statement_commitment !=
                statement_commitment ||
            lobe.mantissa_proof.manifest_commitment !=
                lobe.mantissa.commitment ||
            lobe.scale_proof.manifest_commitment !=
                lobe.scale.commitment) {
            return Fail(why, "schedule_xof");
        }
        const auto& pin = lobe.dequant_pin;
        if (pin.statement_commitment != statement_commitment ||
            pin.shape_commitment != shape_commitment ||
            pin.sigma != product.sigma ||
            pin.page_index != i ||
            pin.logical_rows != cells ||
            pin.n_rows != cells ||
            pin.n_coeffs != cells ||
            pin.pin_commitment !=
                ComputeRCStage3CoupledBankDequantPinCommitment(
                    pin)) {
            return Fail(why, "schedule_pin");
        }
        std::vector<std::vector<Fp3>> columns;
        if (!BuildColumns(shape, lobe, columns, why)) {
            return false;
        }
        aq::AirConstraintSystem<Fp3> row_shape;
        row_shape.n_rows = pin.n_rows;
        row_shape.n_columns =
            DEQUANT_SPLITRAP_COLUMNS;
        const auto expected_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                row_shape, columns,
                DequantBaseColumns());
        if (!expected_r0.valid ||
            pin.r0_row_group_root !=
                expected_r0.base_row_commitment) {
            return Fail(why, "row_root");
        }
        if (lobe.receipt_commitment !=
            LobeReceipt(lobe)) {
            return Fail(why, "lobe_receipt");
        }
    }
    if (product.initial_state_endpoint_root !=
            InitialRoot(shape, product) ||
        product.product_commitment !=
            ProductCommitment(product)) {
        return Fail(why, "roots");
    }
    return true;
}

bool VerifyRCStage3CoupledInitialStateProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledInitialStateProductSchedule(
            statement, shape, product, why)) {
        return false;
    }
    for (const auto& lobe : product.lobes) {
        if (!hs::VerifyShaManifestBundle(
                RCStage3RelationEndpoint::CoupledGemmOperandA,
                lobe.lobe_seed.manifest,
                lobe.lobe_seed.proof, why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::CoupledGemmOperandA,
                lobe.mantissa,
                lobe.mantissa_proof, why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::CoupledGemmOperandA,
                lobe.scale,
                lobe.scale_proof, why) ||
            !VerifyRCStage3CoupledBankDequantProof(
                lobe.dequant_pin,
                lobe.dequant_proof, why)) {
            return Fail(why, "proof");
        }
    }
    return true;
}

bool ValidateRCStage3CoupledInitialStateGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& initial,
    const RCStage3CoupledGemmProduct& gemm,
    uint256& link_commitment,
    std::string* why)
{
    link_commitment.SetNull();
    if (!ValidateRCStage3CoupledInitialStateProductSchedule(
            statement, shape, initial, why) ||
        !ValidateRCStage3CoupledGemmSchedule(
            statement, shape, gemm, why)) {
        return Fail(why, "link_schedule");
    }
    const uint64_t active =
        uint64_t{shape.rows_per_lobe} *
        shape.lobe_width;
    std::vector<uint32_t> seen(shape.lobes, 0);
    HashWriter hash;
    hash << LINK_DOMAIN;
    hash << initial.product_commitment;
    hash << gemm.product_commitment;
    for (const auto& instance : gemm.gemms) {
        if (instance.schedule.barrier != 0) continue;
        if (instance.schedule.lobe >= initial.lobes.size()) {
            return Fail(why, "link_lobe");
        }
        const auto& source =
            initial.lobes[instance.schedule.lobe]
                .expanded_tile;
        if (source.size() < active ||
            instance.operand_a.size() != active ||
            !std::equal(
                instance.operand_a.begin(),
                instance.operand_a.end(),
                source.begin())) {
            return Fail(why, "25_to_30");
        }
        ++seen[instance.schedule.lobe];
        hash << instance.schedule.schedule_index;
        hash << instance.schedule.lobe;
        hash << instance.schedule.page_slot;
        hash << active;
        for (int8_t value : instance.operand_a) {
            hash << static_cast<int64_t>(value);
        }
    }
    for (uint32_t count : seen) {
        if (count != shape.pages_per_barrier_lobe) {
            return Fail(why, "link_coverage");
        }
    }
    link_commitment = hash.GetHash();
    return !link_commitment.IsNull() ||
           Fail(why, "link_commitment");
}

bool VerifyRCStage3CoupledInitialStateGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& initial,
    const RCStage3CoupledGemmProduct& gemm,
    uint256& link_commitment,
    std::string* why)
{
    if (!VerifyRCStage3CoupledInitialStateProduct(
            statement, shape, initial, why) ||
        !VerifyRCStage3CoupledGemmProduct(
            statement, shape, gemm, why)) {
        return Fail(why, "producer_proof");
    }
    return ValidateRCStage3CoupledInitialStateGemmLink(
        statement, shape, initial, gemm,
        link_commitment, why);
}

RCStage3CoupledInitialStateProductAudit
CurrentRCStage3CoupledInitialStateProductAudit()
{
    RCStage3CoupledInitialStateProductAudit out;
    out.lobe_seed_sha_executable = true;
    out.mantissa_scale_xof_executable = true;
    out.dequant_executable = true;
    out.complete_initial_state_root = true;
    out.every_barrier0_gemm_a_slice_equal = true;
    return out;
}

} // namespace matmul::v4::rc
