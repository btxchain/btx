// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>

#include <hash.h>

#include <algorithm>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_SCHEDULE_V1";
constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_DOT_PIN_V1";
constexpr char AIR_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_DOT_AIR_V1";
constexpr char INSTANCE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_INSTANCE_V1";
constexpr char ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_ENDPOINT_V1";
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_PRODUCT_V1";
constexpr char COMPACT_INSTANCE_DOMAIN_V2[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_COMPACT_INSTANCE_V2";
constexpr char COMPACT_PROJECTION_DOMAIN_V2[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_COMPACT_PROJECTION_V2";
constexpr char COMPACT_ENDPOINT_DOMAIN_V2[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_COMPACT_ENDPOINT_V2";
constexpr char COMPACT_PRODUCT_DOMAIN_V2[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_COMPACT_PRODUCT_V2";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_gemm_product:" + detail;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value < 2) return 2;
    if (value > (uint64_t{1} << 31)) return 0;
    uint64_t out = 1;
    while (out < value) out <<= 1;
    return static_cast<uint32_t>(out);
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 S(int64_t value)
{
    return Fp3::FromFp(gf::FromSigned(value));
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

RCCoupParams ParamsFromShape(const RCStage3CoupledShape& shape)
{
    RCCoupParams out;
    out.barriers = shape.barriers;
    out.lobes = shape.lobes;
    out.lobe_width = shape.lobe_width;
    out.bank_pages = shape.bank_pages;
    out.rows_per_lobe = shape.rows_per_lobe;
    out.pages_per_barrier_lobe =
        shape.pages_per_barrier_lobe;
    return out;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
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

template <typename T>
uint256 VectorRoot(const std::vector<T>& values)
{
    if (values.empty()) return {};
    std::vector<Fp3> field;
    field.reserve(values.size());
    for (const T value : values) {
        field.push_back(S(static_cast<int64_t>(value)));
    }
    const uint32_t n_coeffs =
        NextPowerOfTwo(field.size());
    if (n_coeffs == 0) return {};
    return aq::AirCommittedValuesRoot<Fp3>(
        field, n_coeffs);
}

uint256 EndpointRoot(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& shape_commitment,
    const uint256& schedule_commitment,
    const std::vector<RCStage3CoupledGemmInstanceProduct>& gemms,
    uint32_t which)
{
    if (statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        schedule_commitment.IsNull() ||
        gemms.empty() || which > 2) {
        return {};
    }
    HashWriter hash;
    hash << ENDPOINT_DOMAIN;
    hash << kRCStage3CoupledGemmProductVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << statement_commitment << shape_commitment;
    hash << schedule_commitment;
    hash << static_cast<uint64_t>(gemms.size());
    for (const auto& gemm : gemms) {
        hash << gemm.schedule.schedule_index;
        hash << (which == 0
                     ? gemm.operand_a_root
                     : which == 1
                         ? gemm.operand_b_root
                         : gemm.output_y_root);
    }
    return hash.GetHash();
}

uint256 InstanceReceipt(
    const RCStage3CoupledGemmInstanceProduct& gemm)
{
    if (gemm.operand_a.empty() || gemm.operand_b.empty() ||
        gemm.output_y.empty() || gemm.tiles.empty() ||
        gemm.operand_a_root.IsNull() ||
        gemm.operand_b_root.IsNull() ||
        gemm.output_y_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << INSTANCE_DOMAIN;
    hash << kRCStage3CoupledGemmProductVersion;
    hash << gemm.schedule.schedule_index;
    hash << gemm.schedule.barrier << gemm.schedule.lobe;
    hash << gemm.schedule.page_slot << gemm.schedule.page_id;
    hash << gemm.operand_a_root << gemm.operand_b_root;
    hash << gemm.output_y_root;
    hash << static_cast<uint64_t>(gemm.tiles.size());
    for (uint64_t i = 0; i < gemm.tiles.size(); ++i) {
        const auto& tile = gemm.tiles[i];
        const uint256 pin =
            ComputeRCStage3CoupledGemmDotPinCommitment(tile.pin);
        if (tile.output_tile_index != i || pin.IsNull()) return {};
        hash << tile.output_tile_index << pin;
    }
    return hash.GetHash();
}

uint256 ProductCommitment(
    const RCStage3CoupledGemmProduct& product)
{
    if (product.version !=
            kRCStage3CoupledGemmProductVersion ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.schedule_commitment.IsNull() ||
        product.gemms.empty() ||
        product.operand_a_endpoint_root.IsNull() ||
        product.operand_b_endpoint_root.IsNull() ||
        product.output_y_endpoint_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.sigma << product.schedule_commitment;
    hash << product.expected_gemms;
    hash << product.expected_output_tiles;
    hash << static_cast<uint64_t>(product.gemms.size());
    for (uint64_t i = 0; i < product.gemms.size(); ++i) {
        if (product.gemms[i].schedule.schedule_index != i ||
            product.gemms[i].instance_receipt_commitment.IsNull()) {
            return {};
        }
        hash << product.gemms[i].instance_receipt_commitment;
    }
    hash << product.operand_a_endpoint_root;
    hash << product.operand_b_endpoint_root;
    hash << product.output_y_endpoint_root;
    return hash.GetHash();
}

bool BuildTileColumns(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmInstanceProduct& gemm,
    uint64_t tile_index,
    uint32_t n_rows,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const uint32_t width = shape.lobe_width;
    const uint32_t rows = shape.rows_per_lobe;
    if (width == 0 || width % kRCMxBlockLen != 0 ||
        gemm.operand_a.size() != uint64_t{rows} * width ||
        gemm.operand_b.size() != uint64_t{width} * width ||
        gemm.output_y.size() != uint64_t{rows} * width ||
        tile_index >= uint64_t{rows} *
            (width / kRCMxBlockLen) ||
        n_rows < uint64_t{width} * kRCMxBlockLen) {
        return Fail(why, "tile_shape");
    }
    const uint32_t blocks_per_row =
        width / kRCMxBlockLen;
    const uint32_t output_row =
        tile_index / blocks_per_row;
    const uint32_t output_block =
        tile_index % blocks_per_row;
    columns.assign(
        kRCStage3CoupledGemmColumns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    for (uint32_t lane = 0;
         lane < kRCMxBlockLen; ++lane) {
        const uint32_t output_column =
            output_block * kRCMxBlockLen + lane;
        int64_t accumulator = 0;
        for (uint32_t contraction = 0;
             contraction < width; ++contraction) {
            const uint32_t trace_row =
                lane * width + contraction;
            const int8_t a = gemm.operand_a[
                uint64_t{output_row} * width + contraction];
            const int8_t b = gemm.operand_b[
                uint64_t{contraction} * width + output_column];
            if (a < -48 || a > 48 || b < -48 || b > 48) {
                return Fail(why, "operand_range");
            }
            const int64_t product =
                static_cast<int64_t>(a) * b;
            columns[kRCStage3CoupledGemmActive][trace_row] =
                Fp3::One();
            columns[kRCStage3CoupledGemmStart][trace_row] =
                U(contraction == 0);
            columns[kRCStage3CoupledGemmEnd][trace_row] =
                U(contraction + 1 == width);
            columns[kRCStage3CoupledGemmA][trace_row] = S(a);
            columns[kRCStage3CoupledGemmB][trace_row] = S(b);
            columns[
                kRCStage3CoupledGemmAccumulatorBefore]
                [trace_row] = S(accumulator);
            columns[kRCStage3CoupledGemmProduct][trace_row] =
                S(product);
            accumulator += product;
            columns[
                kRCStage3CoupledGemmAccumulatorAfter]
                [trace_row] = S(accumulator);
            if (contraction + 1 == width) {
                columns[kRCStage3CoupledGemmY][trace_row] =
                    S(gemm.output_y[
                        uint64_t{output_row} * width +
                        output_column]);
            }
        }
    }
    return true;
}

bool ExpectedOpeningRoots(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmInstanceProduct& gemm,
    const RCStage3CoupledGemmDotPin& pin,
    uint64_t tile_index,
    std::vector<uint256>& out,
    std::string* why)
{
    std::vector<std::vector<Fp3>> columns;
    if (!BuildTileColumns(
            shape, gemm, tile_index, pin.n_rows,
            columns, why)) {
        return false;
    }
    out.clear();
    for (uint32_t column = 0;
         column <= kRCStage3CoupledGemmY; ++column) {
        out.push_back(aq::AirCommittedValuesRoot<Fp3>(
            columns[column], pin.n_coeffs));
    }
    return true;
}

uint256 CompactProjectionRootV2(
    const RCStage3CoupledGemmCompactInstanceV2& instance,
    uint32_t trace_column)
{
    if (instance.version !=
            kRCStage3CoupledGemmCompactProductVersionV2 ||
        instance.tiles.empty() ||
        trace_column >= kRCStage3CoupledGemmColumns) {
        return {};
    }
    HashWriter hash;
    hash << COMPACT_PROJECTION_DOMAIN_V2
         << kRCStage3CoupledGemmCompactProductVersionV2
         << trace_column
         << instance.schedule.schedule_index
         << instance.schedule.barrier
         << instance.schedule.lobe
         << instance.schedule.page_slot
         << instance.schedule.page_id
         << static_cast<uint64_t>(instance.tiles.size());
    for (uint64_t i = 0; i < instance.tiles.size(); ++i) {
        const auto& tile = instance.tiles[i];
        if (tile.output_tile_index != i ||
            tile.pin.column_roots.size() !=
                kRCStage3CoupledGemmColumns ||
            tile.pin.column_roots[trace_column].column !=
                trace_column ||
            tile.pin.column_roots[trace_column].root.IsNull()) {
            return {};
        }
        hash << i
             << tile.pin.column_roots[trace_column].root;
    }
    return hash.GetHash();
}

uint256 CompactInstanceCommitmentV2(
    const RCStage3CoupledGemmCompactInstanceV2& instance)
{
    if (instance.version !=
            kRCStage3CoupledGemmCompactProductVersionV2 ||
        instance.tiles.empty() ||
        instance.operand_a_trace_root.IsNull() ||
        instance.operand_b_trace_root.IsNull() ||
        instance.output_y_trace_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << COMPACT_INSTANCE_DOMAIN_V2 << instance.version
         << instance.schedule.schedule_index
         << instance.schedule.barrier
         << instance.schedule.lobe
         << instance.schedule.page_slot
         << instance.schedule.page_id
         << instance.operand_a_trace_root
         << instance.operand_b_trace_root
         << instance.output_y_trace_root
         << static_cast<uint64_t>(instance.tiles.size());
    for (uint64_t i = 0; i < instance.tiles.size(); ++i) {
        const auto& tile = instance.tiles[i];
        const uint256 pin =
            ComputeRCStage3CoupledGemmDotPinCommitment(tile.pin);
        if (tile.output_tile_index != i || pin.IsNull()) {
            return {};
        }
        hash << i << pin;
    }
    return hash.GetHash();
}

uint256 CompactEndpointRootV2(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledGemmCompactProductV2& product,
    uint32_t which)
{
    if (product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.schedule_commitment.IsNull() ||
        product.gemms.empty() || which > 2) {
        return {};
    }
    HashWriter hash;
    hash << COMPACT_ENDPOINT_DOMAIN_V2
         << kRCStage3CoupledGemmCompactProductVersionV2
         << static_cast<uint16_t>(endpoint)
         << product.statement_commitment
         << product.shape_commitment
         << product.schedule_commitment
         << static_cast<uint64_t>(product.gemms.size());
    for (const auto& gemm : product.gemms) {
        hash << gemm.schedule.schedule_index
             << (which == 0
                     ? gemm.operand_a_trace_root
                     : which == 1
                         ? gemm.operand_b_trace_root
                         : gemm.output_y_trace_root);
    }
    return hash.GetHash();
}

uint256 CompactProductCommitmentV2(
    const RCStage3CoupledGemmCompactProductV2& product)
{
    if (product.version !=
            kRCStage3CoupledGemmCompactProductVersionV2 ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.schedule_commitment.IsNull() ||
        product.gemms.empty() ||
        product.operand_a_endpoint_root.IsNull() ||
        product.operand_b_endpoint_root.IsNull() ||
        product.output_y_endpoint_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << COMPACT_PRODUCT_DOMAIN_V2 << product.version
         << product.statement_commitment
         << product.shape_commitment
         << product.sigma
         << product.schedule_commitment
         << product.expected_gemms
         << product.expected_output_tiles
         << static_cast<uint64_t>(product.gemms.size());
    for (uint64_t i = 0; i < product.gemms.size(); ++i) {
        if (product.gemms[i].schedule.schedule_index != i ||
            product.gemms[i].instance_commitment.IsNull()) {
            return {};
        }
        hash << product.gemms[i].instance_commitment;
    }
    hash << product.operand_a_endpoint_root
         << product.operand_b_endpoint_root
         << product.output_y_endpoint_root;
    return hash.GetHash();
}

bool ExpectedCompactSelectorRootsV2(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmDotPin& pin,
    std::array<uint256, 3>& out,
    std::string* why)
{
    if (pin.n_rows <
            uint64_t{shape.lobe_width} * kRCMxBlockLen ||
        pin.n_coeffs != pin.n_rows) {
        return Fail(why, "compact_selector_shape");
    }
    std::array<std::vector<Fp3>, 3> columns;
    for (auto& column : columns) {
        column.assign(pin.n_rows, Fp3::Zero());
    }
    for (uint32_t lane = 0;
         lane < kRCMxBlockLen; ++lane) {
        for (uint32_t contraction = 0;
             contraction < shape.lobe_width; ++contraction) {
            const uint32_t row =
                lane * shape.lobe_width + contraction;
            columns[0][row] = Fp3::One();
            columns[1][row] = U(contraction == 0);
            columns[2][row] =
                U(contraction + 1 == shape.lobe_width);
        }
    }
    for (uint32_t i = 0; i < columns.size(); ++i) {
        out[i] = aq::AirCommittedValuesRoot<Fp3>(
            columns[i], pin.n_coeffs);
        if (out[i].IsNull()) {
            return Fail(why, "compact_selector_root");
        }
    }
    return true;
}

bool ValidateCompactInstanceV2(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmScheduleEntry& expected_schedule,
    const uint256& statement_commitment,
    const uint256& shape_commitment,
    const uint256& schedule_commitment,
    const RCStage3CoupledGemmCompactInstanceV2& instance,
    bool verify_proofs,
    std::string* why)
{
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        (shape.lobe_width / kRCMxBlockLen);
    if (instance.version !=
            kRCStage3CoupledGemmCompactProductVersionV2 ||
        instance.schedule != expected_schedule ||
        instance.tiles.size() != tiles_per_gemm ||
        instance.operand_a_trace_root !=
            CompactProjectionRootV2(
                instance, kRCStage3CoupledGemmA) ||
        instance.operand_b_trace_root !=
            CompactProjectionRootV2(
                instance, kRCStage3CoupledGemmB) ||
        instance.output_y_trace_root !=
            CompactProjectionRootV2(
                instance, kRCStage3CoupledGemmY) ||
        instance.instance_commitment !=
            CompactInstanceCommitmentV2(instance)) {
        return Fail(why, "compact_instance_identity");
    }

    std::array<uint256, 3> selector_roots{};
    if (instance.tiles.empty() ||
        !ExpectedCompactSelectorRootsV2(
            shape, instance.tiles.front().pin,
            selector_roots, why)) {
        return false;
    }
    const uint32_t blocks_per_row =
        shape.lobe_width / kRCMxBlockLen;
    for (uint64_t tile_index = 0;
         tile_index < instance.tiles.size(); ++tile_index) {
        const auto& tile = instance.tiles[tile_index];
        const auto& pin = tile.pin;
        if (tile.output_tile_index != tile_index ||
            pin.statement_commitment != statement_commitment ||
            pin.shape_commitment != shape_commitment ||
            pin.schedule_commitment != schedule_commitment ||
            pin.schedule_index !=
                expected_schedule.schedule_index ||
            pin.output_tile_index != tile_index ||
            pin.contraction_size != shape.lobe_width ||
            pin.logical_rows !=
                uint64_t{shape.lobe_width} *
                    kRCMxBlockLen ||
            pin.column_roots.size() !=
                kRCStage3CoupledGemmColumns ||
            pin.pin_commitment !=
                ComputeRCStage3CoupledGemmDotPinCommitment(pin)) {
            return Fail(why, "compact_tile_pin");
        }
        for (uint32_t selector = 0;
             selector < selector_roots.size();
             ++selector) {
            if (pin.column_roots[selector].root !=
                selector_roots[selector]) {
                return Fail(why, "compact_selector_substitution");
            }
        }

        // A is shared across every output block in one output row. B is
        // shared across every output row for one output block. These root
        // equalities prevent a collection of individually valid tile proofs
        // from describing mutually inconsistent matrices.
        const uint64_t row_first =
            (tile_index / blocks_per_row) *
            blocks_per_row;
        if (pin.column_roots[kRCStage3CoupledGemmA].root !=
            instance.tiles[row_first]
                .pin.column_roots[kRCStage3CoupledGemmA].root) {
            return Fail(why, "compact_operand_a_cross_tile");
        }
        const uint64_t block_first =
            tile_index % blocks_per_row;
        if (pin.column_roots[kRCStage3CoupledGemmB].root !=
            instance.tiles[block_first]
                .pin.column_roots[kRCStage3CoupledGemmB].root) {
            return Fail(why, "compact_operand_b_cross_row");
        }
        if (verify_proofs &&
            !VerifyRCStage3CoupledGemmDotProof(
                pin, tile.proof, why)) {
            return Fail(
                why, "compact_tile_proof_" +
                         std::to_string(tile_index));
        }
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3CoupledGemmDotPinCommitment(
    const RCStage3CoupledGemmDotPin& pin)
{
    if (pin.version !=
            kRCStage3CoupledGemmProductVersion ||
        pin.statement_commitment.IsNull() ||
        pin.shape_commitment.IsNull() ||
        pin.schedule_commitment.IsNull() ||
        pin.contraction_size == 0 ||
        pin.logical_rows !=
            uint64_t{pin.contraction_size} *
                kRCMxBlockLen ||
        !IsPowerOfTwo(pin.n_rows) ||
        pin.n_rows < pin.logical_rows ||
        pin.n_coeffs != pin.n_rows ||
        pin.column_roots.size() !=
            kRCStage3CoupledGemmColumns) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN << pin.version;
    hash << pin.statement_commitment << pin.shape_commitment;
    hash << pin.schedule_commitment;
    hash << pin.schedule_index << pin.output_tile_index;
    hash << pin.contraction_size << pin.logical_rows;
    hash << pin.n_rows << pin.n_coeffs;
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (pin.column_roots[i].column != i ||
            pin.column_roots[i].root.IsNull()) {
            return {};
        }
        hash << i << pin.column_roots[i].root;
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3CoupledGemmDotSeed(
    const RCStage3CoupledGemmDotPin& pin)
{
    const uint256 commitment =
        ComputeRCStage3CoupledGemmDotPinCommitment(pin);
    if (commitment.IsNull()) return {};
    HashWriter hash;
    hash << AIR_SEED_DOMAIN << commitment;
    return hash.GetHash();
}

bool BuildRCStage3CoupledGemmDotConstraintSystem(
    const RCStage3CoupledGemmDotPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (pin.pin_commitment !=
            ComputeRCStage3CoupledGemmDotPinCommitment(pin) ||
        pin.pin_commitment.IsNull()) {
        return Fail(why, "dot_pin");
    }
    out.n_rows = pin.n_rows;
    out.n_columns = kRCStage3CoupledGemmColumns;
    for (uint32_t column : {
             kRCStage3CoupledGemmActive,
             kRCStage3CoupledGemmStart,
             kRCStage3CoupledGemmEnd}) {
        AddConstraint(
            out, "coupled.gemm.boolean",
            aq::AirKind::kEverywhere, 2,
            [column](const std::vector<Fp3>& row,
                     const std::vector<Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(row[column], Fp3::One()));
            });
    }
    AddConstraint(
        out, "coupled.gemm.product",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3CoupledGemmActive],
                gf::Sub(
                    row[kRCStage3CoupledGemmProduct],
                    gf::Mul(
                        row[kRCStage3CoupledGemmA],
                        row[kRCStage3CoupledGemmB])));
        });
    AddConstraint(
        out, "coupled.gemm.accumulate",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3CoupledGemmActive],
                gf::Sub(
                    row[kRCStage3CoupledGemmAccumulatorAfter],
                    gf::Add(
                        row[kRCStage3CoupledGemmAccumulatorBefore],
                        row[kRCStage3CoupledGemmProduct])));
        });
    AddConstraint(
        out, "coupled.gemm.start_zero",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3CoupledGemmStart],
                row[kRCStage3CoupledGemmAccumulatorBefore]);
        });
    AddConstraint(
        out, "coupled.gemm.end_y",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                row[kRCStage3CoupledGemmEnd],
                gf::Sub(
                    row[kRCStage3CoupledGemmY],
                    row[kRCStage3CoupledGemmAccumulatorAfter]));
        });
    for (uint32_t column : {
             kRCStage3CoupledGemmA,
             kRCStage3CoupledGemmB}) {
        AddConstraint(
            out, "coupled.gemm.operand_padding_zero",
            aq::AirKind::kEverywhere, 2,
            [column](const std::vector<Fp3>& row,
                     const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[kRCStage3CoupledGemmActive]),
                    row[column]);
            });
    }
    AddConstraint(
        out, "coupled.gemm.y_nonterminal_zero",
        aq::AirKind::kEverywhere, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    row[kRCStage3CoupledGemmEnd]),
                row[kRCStage3CoupledGemmY]);
        });
    AddConstraint(
        out, "coupled.gemm.chain",
        aq::AirKind::kTransition, 2,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>& next) {
            return gf::Mul(
                gf::Mul(
                    row[kRCStage3CoupledGemmActive],
                    gf::Sub(
                        Fp3::One(),
                        row[kRCStage3CoupledGemmEnd])),
                gf::Sub(
                    next[
                        kRCStage3CoupledGemmAccumulatorBefore],
                    row[
                        kRCStage3CoupledGemmAccumulatorAfter]));
        });
    for (uint32_t column : {
             kRCStage3CoupledGemmProduct,
             kRCStage3CoupledGemmAccumulatorBefore,
             kRCStage3CoupledGemmAccumulatorAfter}) {
        AddConstraint(
            out, "coupled.gemm.padding_zero",
            aq::AirKind::kEverywhere, 2,
            [column](const std::vector<Fp3>& row,
                     const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[kRCStage3CoupledGemmActive]),
                    row[column]);
            });
    }
    for (const auto& root : pin.column_roots) {
        out.preprocessed_roots.emplace_back(
            root.column, root.root);
    }
    return true;
}

bool VerifyRCStage3CoupledGemmDotProof(
    const RCStage3CoupledGemmDotPin& pin,
    const aq::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3CoupledGemmDotConstraintSystem(
            pin, cs, why) ||
        proof.batch.columns.size() !=
            kRCStage3CoupledGemmColumns + 1 ||
        proof.batch.column_len.size() !=
            kRCStage3CoupledGemmColumns + 1 ||
        proof.batch.n_coeffs != pin.n_coeffs) {
        return Fail(why, "dot_proof_shape");
    }
    for (uint32_t i = 0; i < pin.column_roots.size(); ++i) {
        if (proof.batch.columns[i].root !=
            pin.column_roots[i].root) {
            return Fail(why, "dot_proof_root");
        }
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof, ComputeRCStage3CoupledGemmDotSeed(pin),
            &air_why)) {
        return Fail(why, "dot_air:" + air_why);
    }
    return true;
}

bool BuildRCStage3CoupledGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::vector<RCStage3CoupledGemmScheduleEntry>& out,
    uint256& schedule_commitment,
    std::string* why)
{
    out.clear();
    schedule_commitment.SetNull();
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledGemm, shape, why);
    if (!IsCoupledStatement(statement) ||
        statement.public_inputs.sigma.IsNull() ||
        !counts.has_value()) {
        return Fail(why, "schedule_public_shape");
    }
    const RCCoupParams params = ParamsFromShape(shape);
    out.reserve(counts->primary);
    for (uint32_t barrier = 0;
         barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0;
             lobe < shape.lobes; ++lobe) {
            const auto pages = SelectCoupledBankPageIds(
                barrier, lobe, params,
                statement.public_inputs.sigma,
                shape.full_bank_schedule,
                shape.transcript_version);
            if (pages.size() !=
                shape.pages_per_barrier_lobe) {
                return Fail(why, "schedule_page_count");
            }
            for (uint32_t slot = 0; slot < pages.size(); ++slot) {
                if (pages[slot] >= shape.bank_pages) {
                    return Fail(why, "schedule_page_id");
                }
                out.push_back({
                    out.size(), barrier, lobe, slot,
                    pages[slot]});
            }
        }
    }
    if (out.size() != counts->primary) {
        return Fail(why, "schedule_count");
    }
    HashWriter hash;
    hash << SCHEDULE_DOMAIN;
    hash << kRCStage3CoupledGemmProductVersion;
    hash << CommitRCStage3CoupledStatement(
        statement.public_inputs);
    hash << CommitRCStage3CoupledShape(shape);
    hash << statement.public_inputs.sigma;
    hash << static_cast<uint64_t>(out.size());
    for (const auto& entry : out) {
        hash << entry.schedule_index << entry.barrier;
        hash << entry.lobe << entry.page_slot << entry.page_id;
    }
    schedule_commitment = hash.GetHash();
    return !schedule_commitment.IsNull() ||
           Fail(why, "schedule_commitment");
}

bool BuildRCStage3CoupledGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    RCStage3CoupledGemmProduct& out,
    std::string* why)
{
    out = {};
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why) ||
        openings.size() != schedule.size()) {
        return Fail(why, "build_schedule_or_openings");
    }
    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape_commitment = CommitRCStage3CoupledShape(shape);
    out.sigma = statement.public_inputs.sigma;
    out.schedule_commitment = schedule_commitment;
    out.expected_gemms = schedule.size();
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        (shape.lobe_width / kRCMxBlockLen);
    out.expected_output_tiles =
        tiles_per_gemm * schedule.size();
    out.gemms.reserve(schedule.size());
    for (uint64_t index = 0;
         index < schedule.size(); ++index) {
        RCStage3CoupledGemmInstanceProduct gemm;
        gemm.schedule = schedule[index];
        gemm.operand_a = openings[index].operand_a;
        gemm.operand_b = openings[index].operand_b;
        gemm.output_y = openings[index].output_y;
        if (gemm.operand_a.size() !=
                uint64_t{shape.rows_per_lobe} *
                    shape.lobe_width ||
            gemm.operand_b.size() !=
                uint64_t{shape.lobe_width} *
                    shape.lobe_width ||
            gemm.output_y.size() !=
                uint64_t{shape.rows_per_lobe} *
                    shape.lobe_width) {
            return Fail(why, "build_opening_shape");
        }
        gemm.operand_a_root = VectorRoot(gemm.operand_a);
        gemm.operand_b_root = VectorRoot(gemm.operand_b);
        gemm.output_y_root = VectorRoot(gemm.output_y);
        if (gemm.operand_a_root.IsNull() ||
            gemm.operand_b_root.IsNull() ||
            gemm.output_y_root.IsNull()) {
            return Fail(why, "build_opening_root");
        }
        for (uint64_t tile_index = 0;
             tile_index < tiles_per_gemm; ++tile_index) {
            RCStage3CoupledGemmTileProof tile;
            tile.output_tile_index = tile_index;
            auto& pin = tile.pin;
            pin.statement_commitment =
                out.statement_commitment;
            pin.shape_commitment = out.shape_commitment;
            pin.schedule_commitment = out.schedule_commitment;
            pin.schedule_index = index;
            pin.output_tile_index = tile_index;
            pin.contraction_size = shape.lobe_width;
            pin.logical_rows =
                shape.lobe_width * kRCMxBlockLen;
            pin.n_rows = NextPowerOfTwo(pin.logical_rows);
            pin.n_coeffs = pin.n_rows;
            std::vector<std::vector<Fp3>> columns;
            if (pin.n_rows == 0 ||
                !BuildTileColumns(
                    shape, gemm, tile_index, pin.n_rows,
                    columns, why)) {
                return false;
            }
            for (uint32_t column = 0;
                 column < columns.size(); ++column) {
                pin.column_roots.push_back({
                    column,
                    aq::AirCommittedValuesRoot<Fp3>(
                        columns[column], pin.n_coeffs)});
            }
            pin.pin_commitment =
                ComputeRCStage3CoupledGemmDotPinCommitment(pin);
            if (pin.pin_commitment.IsNull()) {
                return Fail(why, "build_dot_pin");
            }
            gemm.tiles.push_back(std::move(tile));
        }
        gemm.instance_receipt_commitment =
            InstanceReceipt(gemm);
        if (gemm.instance_receipt_commitment.IsNull()) {
            return Fail(why, "build_instance_receipt");
        }
        out.gemms.push_back(std::move(gemm));
    }
    out.operand_a_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledGemmOperandA,
        out.statement_commitment, out.shape_commitment,
        out.schedule_commitment, out.gemms, 0);
    out.operand_b_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledGemmOperandB,
        out.statement_commitment, out.shape_commitment,
        out.schedule_commitment, out.gemms, 1);
    out.output_y_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledGemmOutputY,
        out.statement_commitment, out.shape_commitment,
        out.schedule_commitment, out.gemms, 2);
    out.product_commitment = ProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_product_commitment");
}

bool ProveRCStage3CoupledGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<RCStage3CoupledGemmOpening>& openings,
    RCStage3CoupledGemmProduct& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledGemmProduct(
            statement, shape, openings, out, why)) {
        return false;
    }
    for (auto& gemm : out.gemms) {
        for (auto& tile : gemm.tiles) {
            std::vector<std::vector<Fp3>> columns;
            if (!BuildTileColumns(
                    shape, gemm, tile.output_tile_index,
                    tile.pin.n_rows, columns, why)) {
                return false;
            }
            aq::AirConstraintSystem<Fp3> cs;
            if (!BuildRCStage3CoupledGemmDotConstraintSystem(
                    tile.pin, cs, why)) {
                return false;
            }
            const auto proved = aq::AirQuotientProve<Fp3>(
                cs, columns,
                ComputeRCStage3CoupledGemmDotSeed(tile.pin));
            if (!proved.ok || !proved.division_exact) {
                return Fail(
                    why, "prove_dot:" + proved.note);
            }
            tile.proof = proved.proof;
        }
    }
    return true;
}

bool ValidateRCStage3CoupledGemmSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& product,
    std::string* why)
{
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why)) {
        return false;
    }
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        (shape.lobe_width / kRCMxBlockLen);
    if (product.version !=
            kRCStage3CoupledGemmProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.shape_commitment != shape_commitment ||
        product.sigma != statement.public_inputs.sigma ||
        product.schedule_commitment != schedule_commitment ||
        product.expected_gemms != schedule.size() ||
        product.expected_output_tiles !=
            tiles_per_gemm * schedule.size() ||
        product.gemms.size() != schedule.size()) {
        return Fail(why, "product_public_shape");
    }
    for (uint64_t index = 0;
         index < schedule.size(); ++index) {
        const auto& gemm = product.gemms[index];
        if (gemm.schedule != schedule[index] ||
            gemm.operand_a.size() !=
                uint64_t{shape.rows_per_lobe} *
                    shape.lobe_width ||
            gemm.operand_b.size() !=
                uint64_t{shape.lobe_width} *
                    shape.lobe_width ||
            gemm.output_y.size() !=
                uint64_t{shape.rows_per_lobe} *
                    shape.lobe_width ||
            gemm.tiles.size() != tiles_per_gemm ||
            gemm.operand_a_root !=
                VectorRoot(gemm.operand_a) ||
            gemm.operand_b_root !=
                VectorRoot(gemm.operand_b) ||
            gemm.output_y_root !=
                VectorRoot(gemm.output_y)) {
            return Fail(why, "instance_opening_or_shape");
        }
        for (uint64_t tile_index = 0;
             tile_index < tiles_per_gemm; ++tile_index) {
            const auto& tile = gemm.tiles[tile_index];
            const auto& pin = tile.pin;
            if (tile.output_tile_index != tile_index ||
                pin.statement_commitment !=
                    statement_commitment ||
                pin.shape_commitment != shape_commitment ||
                pin.schedule_commitment !=
                    schedule_commitment ||
                pin.schedule_index != index ||
                pin.output_tile_index != tile_index ||
                pin.contraction_size != shape.lobe_width ||
                pin.logical_rows !=
                    uint64_t{shape.lobe_width} *
                        kRCMxBlockLen ||
                pin.pin_commitment !=
                    ComputeRCStage3CoupledGemmDotPinCommitment(
                        pin)) {
                return Fail(why, "dot_pin_identity");
            }
            std::vector<uint256> expected;
            if (!ExpectedOpeningRoots(
                    shape, gemm, pin, tile_index,
                    expected, why)) {
                return false;
            }
            for (uint32_t column = 0;
                 column < expected.size(); ++column) {
                if (pin.column_roots[column].root !=
                    expected[column]) {
                    return Fail(why, "dot_opening_root");
                }
            }
        }
        if (gemm.instance_receipt_commitment !=
            InstanceReceipt(gemm)) {
            return Fail(why, "instance_receipt");
        }
    }
    if (product.operand_a_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledGemmOperandA,
            statement_commitment, shape_commitment,
            schedule_commitment, product.gemms, 0) ||
        product.operand_b_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledGemmOperandB,
            statement_commitment, shape_commitment,
            schedule_commitment, product.gemms, 1) ||
        product.output_y_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledGemmOutputY,
            statement_commitment, shape_commitment,
            schedule_commitment, product.gemms, 2) ||
        product.product_commitment !=
            ProductCommitment(product)) {
        return Fail(why, "endpoint_or_product_root");
    }
    return true;
}

bool VerifyRCStage3CoupledGemmProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledGemmSchedule(
            statement, shape, product, why)) {
        return false;
    }
    for (const auto& gemm : product.gemms) {
        for (const auto& tile : gemm.tiles) {
            if (!VerifyRCStage3CoupledGemmDotProof(
                    tile.pin, tile.proof, why)) {
                return Fail(
                    why, "gemm_" +
                             std::to_string(
                                 gemm.schedule.schedule_index) +
                             "_tile_" +
                             std::to_string(
                                 tile.output_tile_index));
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_gemm_product:endpoints_30_32_"
            "exact_flat_product_ok;producer_graph_and_recursion_pending";
    }
    return true;
}

bool ProveRCStage3CoupledGemmCompactInstanceV2(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    uint64_t schedule_index,
    const RCStage3CoupledGemmOpening& opening,
    RCStage3CoupledGemmCompactInstanceV2& out,
    std::string* why)
{
    out = {};
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why) ||
        schedule_index >= schedule.size() ||
        opening.operand_a.size() !=
            uint64_t{shape.rows_per_lobe} *
                shape.lobe_width ||
        opening.operand_b.size() !=
            uint64_t{shape.lobe_width} *
                shape.lobe_width ||
        opening.output_y.size() !=
            uint64_t{shape.rows_per_lobe} *
                shape.lobe_width) {
        return Fail(why, "compact_prove_input");
    }

    // The native values live only for this call. All retained fields below
    // are proof objects or commitments derived from their committed traces.
    RCStage3CoupledGemmInstanceProduct native;
    native.schedule = schedule[schedule_index];
    native.operand_a = opening.operand_a;
    native.operand_b = opening.operand_b;
    native.output_y = opening.output_y;

    out.schedule = native.schedule;
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        (shape.lobe_width / kRCMxBlockLen);
    out.tiles.reserve(tiles_per_gemm);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    for (uint64_t tile_index = 0;
         tile_index < tiles_per_gemm; ++tile_index) {
        RCStage3CoupledGemmTileProof tile;
        tile.output_tile_index = tile_index;
        auto& pin = tile.pin;
        pin.statement_commitment = statement_commitment;
        pin.shape_commitment = shape_commitment;
        pin.schedule_commitment = schedule_commitment;
        pin.schedule_index = schedule_index;
        pin.output_tile_index = tile_index;
        pin.contraction_size = shape.lobe_width;
        pin.logical_rows =
            shape.lobe_width * kRCMxBlockLen;
        pin.n_rows = NextPowerOfTwo(pin.logical_rows);
        pin.n_coeffs = pin.n_rows;
        std::vector<std::vector<Fp3>> columns;
        if (pin.n_rows == 0 ||
            !BuildTileColumns(
                shape, native, tile_index,
                pin.n_rows, columns, why)) {
            return false;
        }
        for (uint32_t column = 0;
             column < columns.size(); ++column) {
            pin.column_roots.push_back({
                column,
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[column], pin.n_coeffs)});
        }
        pin.pin_commitment =
            ComputeRCStage3CoupledGemmDotPinCommitment(pin);
        aq::AirConstraintSystem<Fp3> cs;
        if (pin.pin_commitment.IsNull() ||
            !BuildRCStage3CoupledGemmDotConstraintSystem(
                pin, cs, why)) {
            return false;
        }
        const auto proved = aq::AirQuotientProve<Fp3>(
            cs, columns,
            ComputeRCStage3CoupledGemmDotSeed(pin));
        if (!proved.ok || !proved.division_exact) {
            return Fail(
                why, "compact_prove_dot:" + proved.note);
        }
        tile.proof = proved.proof;
        out.tiles.push_back(std::move(tile));
    }

    out.operand_a_trace_root =
        CompactProjectionRootV2(
            out, kRCStage3CoupledGemmA);
    out.operand_b_trace_root =
        CompactProjectionRootV2(
            out, kRCStage3CoupledGemmB);
    out.output_y_trace_root =
        CompactProjectionRootV2(
            out, kRCStage3CoupledGemmY);
    out.instance_commitment =
        CompactInstanceCommitmentV2(out);
    if (out.instance_commitment.IsNull() ||
        !ValidateCompactInstanceV2(
            shape, schedule[schedule_index],
            statement_commitment, shape_commitment,
            schedule_commitment, out,
            /*verify_proofs=*/true, why)) {
        out = {};
        return false;
    }
    return true;
}

bool FinalizeRCStage3CoupledGemmCompactProductV2(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    std::vector<RCStage3CoupledGemmCompactInstanceV2> instances,
    RCStage3CoupledGemmCompactProductV2& out,
    std::string* why)
{
    out = {};
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why) ||
        instances.size() != schedule.size()) {
        return Fail(why, "compact_finalize_schedule");
    }
    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape_commitment =
        CommitRCStage3CoupledShape(shape);
    out.sigma = statement.public_inputs.sigma;
    out.schedule_commitment = schedule_commitment;
    out.expected_gemms = schedule.size();
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        (shape.lobe_width / kRCMxBlockLen);
    out.expected_output_tiles =
        tiles_per_gemm * schedule.size();
    for (uint64_t i = 0; i < instances.size(); ++i) {
        if (!ValidateCompactInstanceV2(
                shape, schedule[i],
                out.statement_commitment,
                out.shape_commitment,
                out.schedule_commitment,
                instances[i],
                /*verify_proofs=*/true, why)) {
            return false;
        }
    }
    out.gemms = std::move(instances);
    out.operand_a_endpoint_root =
        CompactEndpointRootV2(
            RCStage3RelationEndpoint::CoupledGemmOperandA,
            out, 0);
    out.operand_b_endpoint_root =
        CompactEndpointRootV2(
            RCStage3RelationEndpoint::CoupledGemmOperandB,
            out, 1);
    out.output_y_endpoint_root =
        CompactEndpointRootV2(
            RCStage3RelationEndpoint::CoupledGemmOutputY,
            out, 2);
    out.product_commitment =
        CompactProductCommitmentV2(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "compact_finalize_commitment");
}

bool VerifyRCStage3CoupledGemmCompactProductV2(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmCompactProductV2& product,
    std::string* why)
{
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule,
            schedule_commitment, why)) {
        return false;
    }
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint64_t tiles_per_gemm =
        uint64_t{shape.rows_per_lobe} *
        (shape.lobe_width / kRCMxBlockLen);
    if (product.version !=
            kRCStage3CoupledGemmCompactProductVersionV2 ||
        product.statement_commitment !=
            statement_commitment ||
        product.shape_commitment != shape_commitment ||
        product.sigma != statement.public_inputs.sigma ||
        product.schedule_commitment != schedule_commitment ||
        product.expected_gemms != schedule.size() ||
        product.expected_output_tiles !=
            tiles_per_gemm * schedule.size() ||
        product.gemms.size() != schedule.size()) {
        return Fail(why, "compact_product_public_shape");
    }
    for (uint64_t i = 0; i < schedule.size(); ++i) {
        if (!ValidateCompactInstanceV2(
                shape, schedule[i],
                statement_commitment, shape_commitment,
                schedule_commitment, product.gemms[i],
                /*verify_proofs=*/true, why)) {
            return false;
        }
    }
    if (product.operand_a_endpoint_root !=
            CompactEndpointRootV2(
                RCStage3RelationEndpoint::
                    CoupledGemmOperandA,
                product, 0) ||
        product.operand_b_endpoint_root !=
            CompactEndpointRootV2(
                RCStage3RelationEndpoint::
                    CoupledGemmOperandB,
                product, 1) ||
        product.output_y_endpoint_root !=
            CompactEndpointRootV2(
                RCStage3RelationEndpoint::
                    CoupledGemmOutputY,
                product, 2) ||
        product.product_commitment !=
            CompactProductCommitmentV2(product)) {
        return Fail(why, "compact_endpoint_or_product_root");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_gemm_product:"
            "compact_v2_proof_only_exact_schedule_ok;"
            "producer_ctl_and_recursive_consumption_pending";
    }
    return true;
}

RCStage3CoupledGemmCompactStreamingV2::
RCStage3CoupledGemmCompactStreamingV2(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape)
    : m_statement(statement), m_shape(shape)
{
    std::string why;
    if (!BuildRCStage3CoupledGemmSchedule(
            m_statement, m_shape, m_schedule,
            m_schedule_commitment, &why)) {
        Reject("constructor:" + why);
    } else {
        m_instances.reserve(m_schedule.size());
    }
}

void RCStage3CoupledGemmCompactStreamingV2::Reject(
    const std::string& detail)
{
    if (m_error.empty()) m_error = detail;
}

void RCStage3CoupledGemmCompactStreamingV2::OnGemm(
    const RCCoupGemmProofWitnessView& view)
{
    if (!m_error.empty()) return;
    if (m_next_schedule_index >= m_schedule.size() ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr) {
        Reject("callback_pointer_or_count");
        return;
    }
    const auto& expected =
        m_schedule[m_next_schedule_index];
    if (view.barrier != expected.barrier ||
        view.lobe != expected.lobe ||
        view.page_id != expected.page_id ||
        view.rows != m_shape.rows_per_lobe ||
        view.width != m_shape.lobe_width) {
        Reject("callback_schedule_or_shape");
        return;
    }
    const uint64_t a_cells =
        uint64_t{view.rows} * view.width;
    const uint64_t b_cells =
        uint64_t{view.width} * view.width;
    const uint64_t y_cells = a_cells;
    if (a_cells >
            std::numeric_limits<size_t>::max() ||
        b_cells >
            std::numeric_limits<size_t>::max() ||
        y_cells >
            std::numeric_limits<size_t>::max() ||
        y_cells >
            std::numeric_limits<uint64_t>::max() /
                sizeof(int64_t) ||
        b_cells >
            std::numeric_limits<uint64_t>::max() -
                a_cells ||
        a_cells + b_cells >
            std::numeric_limits<uint64_t>::max() -
                y_cells * sizeof(int64_t)) {
        Reject("callback_native_size");
        return;
    }
    m_peak_native_bytes = std::max(
        m_peak_native_bytes,
        a_cells + b_cells +
            y_cells * sizeof(int64_t));

    RCStage3CoupledGemmOpening opening;
    opening.operand_a.assign(
        view.operand_a,
        view.operand_a + a_cells);
    opening.operand_b.assign(
        view.operand_b,
        view.operand_b + b_cells);
    opening.output_y.assign(
        view.gemm_y,
        view.gemm_y + y_cells);
    RCStage3CoupledGemmCompactInstanceV2 instance;
    std::string why;
    if (!ProveRCStage3CoupledGemmCompactInstanceV2(
            m_statement, m_shape,
            m_next_schedule_index, opening,
            instance, &why)) {
        Reject("callback_prove:" + why);
        return;
    }
    m_instances.push_back(std::move(instance));
    ++m_next_schedule_index;
}

bool RCStage3CoupledGemmCompactStreamingV2::Complete(
    std::string* why) const
{
    if (!m_error.empty()) {
        return Fail(
            why, "compact_stream:" + m_error);
    }
    if (m_next_schedule_index != m_schedule.size() ||
        m_instances.size() != m_schedule.size()) {
        return Fail(why, "compact_stream:incomplete");
    }
    return true;
}

bool RCStage3CoupledGemmCompactStreamingV2::Finalize(
    RCStage3CoupledGemmCompactProductV2& out,
    std::string* why) const
{
    if (!Complete(why) ||
        !FinalizeRCStage3CoupledGemmCompactProductV2(
            m_statement, m_shape,
            m_instances, out, why) ||
        !VerifyRCStage3CoupledGemmCompactProductV2(
            m_statement, m_shape, out, why)) {
        out = {};
        return false;
    }
    return true;
}

RCStage3CoupledGemmProductAudit
CurrentRCStage3CoupledGemmProductAudit()
{
    RCStage3CoupledGemmProductAudit out;
    out.immutable_shape_derived_schedule = true;
    out.every_a_opening_bound = true;
    out.every_b_opening_bound = true;
    out.every_y_opening_bound = true;
    out.every_dot_air_executed = true;
    out.endpoints_30_through_32_locally_complete = true;
    out.bank_page_producer_provenance_complete = false;
    out.prior_state_producer_provenance_complete = false;
    out.production_streaming_complete = true;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "B roots are not yet equality-linked to endpoint-28 bank pages; "
        "A roots are not linked to the initial-lobe/extract state graph; "
        "compact V2 proves the complete canonical callback schedule in the "
        "primary coupled sink and the normalized builder verifies its "
        "proof-only receipt, but its endpoint roots are not yet equality-"
        "consumed inside the normalized recursive parent";
    return out;
}

static_assert(kRCStage3CoupledGemmLocalProductExecutable);
static_assert(!kRCStage3CoupledGemmTransitivelyComplete);

} // namespace matmul::v4::rc
