// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>
#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_verifier_air.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <limits>

namespace matmul::v4::rc::recursive_fixedpoint {
namespace {

namespace gf = gkr_field;
namespace va = stage3_verifier_air;
namespace rh = recursive_hierarchy;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_fixedpoint:" + detail;
    }
    return false;
}

uint64_t CeilDiv(uint64_t n, uint64_t d)
{
    return n / d + (n % d != 0 ? 1 : 0);
}

uint32_t NextPow2(uint64_t n)
{
    uint64_t out = 1;
    while (out < std::max<uint64_t>(2, n)) {
        if (out > (uint64_t{1} << 30)) return 0;
        out <<= 1;
    }
    return static_cast<uint32_t>(out);
}

uint32_t Log2Exact(uint32_t n)
{
    if (n == 0 || (n & (n - 1)) != 0) return 0;
    uint32_t out = 0;
    while (n > 1) {
        n >>= 1;
        ++out;
    }
    return out;
}

constexpr gf::Fp kOmega2_32 =
    UINT64_C(0x185629dcda58878c);

gf::Fp PowFp(gf::Fp base, uint64_t exponent)
{
    gf::Fp out = 1;
    base = gf::Canonical(base);
    while (exponent > 0) {
        if ((exponent & 1u) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp3 PowFp3(Fp3 base, uint64_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent > 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp3 DomainPoint(uint32_t n, uint32_t index)
{
    const uint32_t logn = Log2Exact(n);
    const gf::Fp omega =
        PowFp(kOmega2_32, uint64_t{1} << (32 - logn));
    return Fp3::FromFp(PowFp(omega, index));
}

uint64_t RowLeafRowsForValues(uint32_t n_values)
{
    return (3 * uint64_t{n_values} + 1) / ah::kAlgHashRate + 1;
}

uint64_t FoldRows(const nr::NarrowChildShape& child)
{
    const uint64_t nf = child.n_folds;
    const uint64_t depth_sum =
        nf * child.merkle_depth - (nf * (nf - 1)) / 2;
    return 2 * (nf + depth_sum) + nf;
}

uint32_t ConstraintTemplates(
    nr::PoseidonLaneStrategy strategy)
{
    uint32_t hash = 151;
    if (strategy == nr::PoseidonLaneStrategy::DecomposedX2X4) {
        hash += 2 * ar::kPermSboxCells;
    } else if (
        strategy ==
        nr::PoseidonLaneStrategy::DecomposedX2X4X6) {
        hash += 3 * ar::kPermSboxCells;
    }
    // Current, next and trace row paths; fold; DEEP; point; FS.
    return 4 * hash + 24 + 24;
}

CompleteFixedPointLevel BuildLevel(
    const nr::NarrowChildShape& child,
    nr::PoseidonLaneStrategy strategy,
    uint32_t physical_lanes)
{
    CompleteFixedPointLevel out;
    out.child_width = child.child_w;
    out.child_rows = child.child_n_rows;
    out.child_coeffs = child.child_n_coeffs;
    out.child_lde = child.child_n_lde;
    if (child.child_w == 0 || child.child_n_rows < 2 ||
        child.child_n_coeffs < child.child_n_rows ||
        child.child_n_lde !=
            uint64_t{child.child_n_coeffs} * kRCFriBlowup ||
        child.merkle_depth != Log2Exact(child.child_n_lde) ||
        child.n_folds != Log2Exact(child.child_n_coeffs) ||
        child.queries == 0 || child.child_constraints == 0 ||
        child.arity != 2 || physical_lanes == 0 ||
        physical_lanes > 4 ||
        (4 % physical_lanes) != 0) {
        return out;
    }

    const nr::NarrowLaneLayout lane =
        nr::CanonicalNarrowLaneLayout(strategy);
    std::string lane_why;
    if (!lane.IsCanonical(&lane_why)) return out;
    const uint64_t width =
        uint64_t{physical_lanes} * lane.width;
    if (width > std::numeric_limits<uint32_t>::max()) return out;
    out.parent_width = static_cast<uint32_t>(width);

    out.current_row_rows =
        RowLeafRowsForValues(child.child_w + 1) +
        child.merkle_depth;
    out.next_row_rows = out.current_row_rows;
    out.trace_binding_rows =
        RowLeafRowsForValues(child.child_w) +
        child.merkle_depth;
    out.fold_rows = FoldRows(child);
    out.deep_rows =
        CeilDiv(uint64_t{child.child_w} + 1,
                nr::kNarrowStreamBatch);
    out.per_point_rows =
        CeilDiv(child.child_constraints,
                uint64_t{nr::kNarrowStreamBatch} *
                    physical_lanes) +
        1;
    out.fiat_shamir_rows = nr::FiatShamirReplayRows(child);
    const uint64_t per_query =
        out.current_row_rows + out.next_row_rows +
        out.trace_binding_rows + out.fold_rows +
        out.deep_rows + out.per_point_rows + 2;
    const uint64_t per_child =
        per_query * child.queries + out.fiat_shamir_rows;
    // V5 has two ordered Q128 proofs per logical child. A binary aggregation
    // parent therefore executes four ordinary verifier lanes.
    constexpr uint32_t kV5VerifierLanes = 4;
    const uint32_t waves =
        kV5VerifierLanes / physical_lanes;
    out.active_rows = per_child * waves;
    out.trace_rows = NextPow2(out.active_rows);
    if (out.trace_rows == 0) return out;

    out.max_degree =
        nr::CanonicalPoseidonConstraintProfile(strategy)
            .gated_max_degree;
    const uint64_t quotient =
        uint64_t{out.max_degree - 1} *
        (out.trace_rows - 1);
    if (quotient > std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.quotient_len = static_cast<uint32_t>(quotient);
    out.parent_coeffs = NextPow2(
        std::max<uint64_t>(out.trace_rows, quotient));
    if (out.parent_coeffs == 0 ||
        uint64_t{out.parent_coeffs} * kRCFriBlowup >
            std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.parent_lde = out.parent_coeffs * kRCFriBlowup;
    // Each physical lane has the same fixed constraint templates. The scalar
    // evaluator processes kNarrowStreamBatch constraints per physical lane per
    // row, so both the manifest count and the row denominator scale here.
    out.parent_constraints =
        ConstraintTemplates(strategy) * physical_lanes;
    out.columns_supported =
        out.parent_width <= kRCFri3AlgBatchMaxColumns;
    out.lde_supported =
        uint64_t{out.parent_lde} <=
        (uint64_t{1} << kRCFriMaxLdeLog2);
    out.valid = true;
    return out;
}

nr::NarrowChildShape NextShape(
    const nr::NarrowChildShape& prior,
    const CompleteFixedPointLevel& level)
{
    nr::NarrowChildShape out;
    if (!level.valid) return out;
    out.child_w = level.parent_width;
    out.child_n_rows = level.trace_rows;
    out.child_n_coeffs = level.parent_coeffs;
    out.child_n_lde = level.parent_lde;
    out.merkle_depth = Log2Exact(level.parent_lde);
    out.n_folds = Log2Exact(level.parent_coeffs);
    out.queries = prior.queries;
    out.child_constraints = level.parent_constraints;
    out.arity = 2;
    return out;
}

void AddPreprocessed(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(column, std::move(values));
}

bool ProgramRowsEqual(
    const HashOpeningProgramRow& a,
    const HashOpeningProgramRow& b)
{
    if (a.kind != b.kind ||
        a.link_to_sponge != b.link_to_sponge ||
        a.link_to_merkle != b.link_to_merkle ||
        a.terminal != b.terminal ||
        a.direction != b.direction ||
        a.child != b.child ||
        a.index != b.index ||
        a.query != b.query ||
        a.fold_layer != b.fold_layer ||
        a.fold_side != b.fold_side ||
        a.fold_terminal != b.fold_terminal ||
        a.current_row_sponge !=
            b.current_row_sponge ||
        a.next_row_sponge !=
            b.next_row_sponge ||
        a.current_word_offset !=
            b.current_word_offset ||
        a.absorbed_is_pinned != b.absorbed_is_pinned ||
        a.expected_root != b.expected_root) {
        return false;
    }
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        if (!gf::Eq(a.absorbed_pin[lane],
                    b.absorbed_pin[lane])) {
            return false;
        }
    }
    return true;
}

aq::AirConstraint<Fp3> Gate(
    const char* name,
    uint32_t degree,
    uint32_t selector,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> residual,
    aq::AirKind kind = aq::AirKind::kEverywhere)
{
    aq::AirConstraint<Fp3> out;
    out.name = name;
    out.kind = kind;
    out.alg_degree = degree + 1;
    out.eval =
        [selector, residual = std::move(residual)](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            return gf::Mul(cur[selector],
                           residual(cur, next));
        };
    return out;
}

void AppendSpongeProgram(
    HashOpeningProgram& program,
    uint32_t n_values,
    uint32_t index,
    uint32_t depth,
    const ah::Digest& root,
    bool current_row_sponge,
    bool next_row_sponge,
    uint32_t query)
{
    const uint32_t words = 3 * n_values + 1;
    const uint32_t blocks =
        words / ah::kAlgHashRate + 1;
    for (uint32_t block = 0; block < blocks; ++block) {
        HashOpeningProgramRow row;
        row.kind = block == 0
            ? HashRowKind::SpongeFirst
            : HashRowKind::SpongeContinue;
        row.index = index;
        row.query = query;
        row.current_row_sponge =
            current_row_sponge;
        row.next_row_sponge =
            next_row_sponge;
        row.current_word_offset =
            block * ah::kAlgHashRate;
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            const uint32_t pos =
                block * ah::kAlgHashRate + lane;
            if (pos == words - 1) {
                row.absorbed_is_pinned[lane] = true;
                row.absorbed_pin[lane] =
                    Fp3::FromFp(gf::FromU64(index));
            } else if (pos == words) {
                row.absorbed_is_pinned[lane] = true;
                row.absorbed_pin[lane] = Fp3::One();
            } else if (pos > words) {
                row.absorbed_is_pinned[lane] = true;
                row.absorbed_pin[lane] = Fp3::Zero();
            }
        }
        program.rows.push_back(std::move(row));
    }
    for (uint32_t level = 0; level < depth; ++level) {
        HashOpeningProgramRow row;
        row.kind = HashRowKind::MerkleCompress;
        row.direction = ((index >> level) & 1u) != 0;
        program.rows.push_back(std::move(row));
    }
    if (depth == 0) {
        program.rows.back().terminal = true;
        program.rows.back().expected_root = root;
    } else {
        const size_t first_merkle =
            program.rows.size() - depth;
        program.rows[first_merkle - 1].link_to_merkle = true;
        for (size_t i = first_merkle;
             i + 1 < program.rows.size(); ++i) {
            program.rows[i].link_to_merkle = true;
        }
        program.rows.back().terminal = true;
        program.rows.back().expected_root = root;
    }
    const size_t first_sponge =
        program.rows.size() - depth - blocks;
    for (size_t i = first_sponge;
         i + 1 < first_sponge + blocks; ++i) {
        program.rows[i].link_to_sponge = true;
    }
}

void AppendSingleValueProgram(
    HashOpeningProgram& program,
    uint32_t index,
    uint32_t depth,
    const ah::Digest& root,
    uint32_t query,
    uint32_t fold_layer,
    uint8_t fold_side)
{
    HashOpeningProgramRow leaf;
    leaf.kind = HashRowKind::SingleValueLeaf;
    leaf.index = index;
    leaf.query = query;
    leaf.fold_layer = fold_layer;
    leaf.fold_side = fold_side;
    program.rows.push_back(std::move(leaf));
    for (uint32_t level = 0; level < depth; ++level) {
        HashOpeningProgramRow row;
        row.kind = HashRowKind::MerkleCompress;
        row.direction = ((index >> level) & 1u) != 0;
        row.query = query;
        row.fold_layer = fold_layer;
        row.fold_side = fold_side;
        program.rows.push_back(std::move(row));
    }
    if (depth == 0) {
        program.rows.back().terminal = true;
        program.rows.back().expected_root = root;
    } else {
        const size_t first_merkle =
            program.rows.size() - depth;
        program.rows[first_merkle - 1].link_to_merkle = true;
        for (size_t i = first_merkle;
             i + 1 < program.rows.size(); ++i) {
            program.rows[i].link_to_merkle = true;
        }
        program.rows.back().terminal = true;
        program.rows.back().expected_root = root;
    }
    program.rows.back().fold_terminal = true;
}

ah::State CompressState(
    const ah::Digest& acc,
    const ah::Digest& sibling,
    bool direction)
{
    ah::State state{};
    const ah::Digest& left = direction ? sibling : acc;
    const ah::Digest& right = direction ? acc : sibling;
    for (uint32_t i = 0; i < ah::kAlgHashDigestLen; ++i) {
        state[i] = left[i];
        state[ah::kAlgHashDigestLen + i] = right[i];
    }
    state[2 * ah::kAlgHashDigestLen] =
        ah::GetAlgHashConstants().node_domain;
    return state;
}

void WritePermutation(
    const HashOpeningLayout& layout,
    const ah::State& input,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t row)
{
    const ar::PermWitness witness =
        ar::BuildPermWitness(input);
    std::vector<Fp3> row_values(
        layout.End(), Fp3::Zero());
    ar::WritePermWitness(
        layout.perm, witness, row_values);
    for (uint32_t col = layout.perm.base;
         col < layout.perm.End(); ++col) {
        columns[col][row] = row_values[col];
    }
    for (uint32_t s = 0; s < ar::kPermSboxCells; ++s) {
        const Fp3 x =
            ar::PermSboxInput(layout.perm, row_values, s);
        const Fp3 x2 = gf::Mul(x, x);
        const Fp3 x4 = gf::Mul(x2, x2);
        const Fp3 x6 = gf::Mul(x4, x2);
        columns[layout.x2_base + s][row] = x2;
        columns[layout.x4_base + s][row] = x4;
        columns[layout.x6_base + s][row] = x6;
    }
}

void SetDigest(
    const ar::PermWitness& witness,
    ah::Digest& out)
{
    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        out[lane] = witness.output[lane];
    }
}

bool AppendSpongeWitness(
    const HashOpeningLayout& layout,
    const std::vector<Fp3>& values,
    uint32_t index,
    const std::vector<ah::Digest>& siblings,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t& cursor,
    uint32_t trace_rows)
{
    std::vector<gf::Fp> words;
    words.reserve(3 * values.size() + 1 +
                  ah::kAlgHashRate);
    for (const Fp3& value : values) {
        words.push_back(gf::Canonical(value.c0));
        words.push_back(gf::Canonical(value.c1));
        words.push_back(gf::Canonical(value.c2));
    }
    words.push_back(gf::FromU64(index));
    words.push_back(gf::FromU64(1));
    while (words.size() % ah::kAlgHashRate != 0) {
        words.push_back(gf::FromU64(0));
    }

    ah::State state{};
    for (size_t offset = 0; offset < words.size();
         offset += ah::kAlgHashRate) {
        if (cursor >= trace_rows) return false;
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            const Fp3 absorbed =
                Fp3::FromFp(words[offset + lane]);
            columns[layout.absorbed_pin_base + lane][cursor] =
                absorbed;
            state[lane] =
                gf::Add(state[lane], words[offset + lane]);
        }
        WritePermutation(layout, state, columns, cursor);
        ar::PermWitness witness =
            ar::BuildPermWitness(state);
        state = witness.output;
        ++cursor;
    }

    ah::Digest acc{};
    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        acc[lane] = state[lane];
    }
    uint32_t path_index = index;
    for (const ah::Digest& sibling : siblings) {
        if (cursor >= trace_rows) return false;
        const bool direction = (path_index & 1u) != 0;
        const ah::State input =
            CompressState(acc, sibling, direction);
        WritePermutation(layout, input, columns, cursor);
        const ar::PermWitness witness =
            ar::BuildPermWitness(input);
        SetDigest(witness, acc);
        path_index >>= 1;
        ++cursor;
    }
    return true;
}

bool AppendSingleValueWitness(
    const HashOpeningLayout& layout,
    const Fp3& value,
    uint32_t index,
    const std::vector<ah::Digest>& siblings,
    std::vector<std::vector<Fp3>>& columns,
    uint32_t& cursor,
    uint32_t trace_rows)
{
    if (cursor >= trace_rows) return false;
    ah::State state{};
    state[0] = gf::Canonical(value.c0);
    state[1] = gf::Canonical(value.c1);
    state[2] = gf::Canonical(value.c2);
    state[3] = gf::FromU64(index);
    state[4] = ah::GetAlgHashConstants().leaf_domain;
    WritePermutation(layout, state, columns, cursor);
    ar::PermWitness witness = ar::BuildPermWitness(state);
    ah::Digest acc{};
    SetDigest(witness, acc);
    ++cursor;
    uint32_t path_index = index;
    for (const ah::Digest& sibling : siblings) {
        if (cursor >= trace_rows) return false;
        const bool direction = (path_index & 1u) != 0;
        const ah::State input =
            CompressState(acc, sibling, direction);
        WritePermutation(layout, input, columns, cursor);
        witness = ar::BuildPermWitness(input);
        SetDigest(witness, acc);
        path_index >>= 1;
        ++cursor;
    }
    return true;
}

} // namespace

uint256 ComputeNormalizedCoupledBankRowPinCommitment(
    const NormalizedCoupledBankRowPin& pin)
{
    if (pin.version != 1 ||
        pin.source_pin_commitment.IsNull() ||
        pin.n_rows < 2 ||
        (pin.n_rows & (pin.n_rows - 1)) != 0 ||
        pin.n_coeffs != pin.n_rows ||
        pin.trace_row_commitment.IsNull() ||
        !aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            pin.trace_row_commitment)) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_COUPLED_BANK_NORMALIZED_ROW_PIN_V1";
    hash << pin.version << pin.source_pin_commitment;
    hash << pin.n_rows << pin.n_coeffs;
    hash << pin.trace_row_commitment;
    return hash.GetHash();
}

bool BuildNormalizedCoupledBankConstraintSystem(
    const RCStage3CoupledBankDequantPin& source_pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledBankDequantConstraintSystem(
            source_pin, out, why)) {
        return false;
    }
    // The production relation builder carries one Split-RAP-only Rdep
    // auxiliary column constrained to zero.  The normalized AlgHash receipt
    // is the historical single-group six-column ABI: its batch contains
    // those six trace columns plus the quotient.  Strip the auxiliary rule
    // atomically with the row-group pin rather than leaving a half-migrated
    // seven-column C/S whose proof codec has eight batch columns.
    if (out.n_columns !=
            kRCStage3CoupledBankDequantColumns + 1 ||
        out.constraints.empty() ||
        out.constraints.back().name == nullptr ||
        std::string(out.constraints.back().name) !=
            "coupled.bank.splitrap_aux_zero") {
        return Fail(
            why,
            "normalized_bank_splitrap_aux_shape");
    }
    out.constraints.pop_back();
    out.n_columns =
        kRCStage3CoupledBankDequantColumns;
    // A multi-column AlgHash proof contains one row commitment and no
    // per-column roots. Keep the exact five relation constraints, but remove
    // the incompatible SHA/per-column pin. The row pin and proof verifier
    // below bind the whole ordered trace; a later CTL terminal must establish
    // equality to the registered semantic endpoint roots.
    out.preprocessed_roots.clear();
    out.preprocessed_row_group_roots.clear();
    return true;
}

bool BuildNormalizedCoupledBankRowPin(
    const RCStage3CoupledBankDequantPin& source_pin,
    const AlgAirProof& proof,
    NormalizedCoupledBankRowPin& out,
    std::string* why)
{
    out = {};
    const uint256 source_commitment =
        ComputeRCStage3CoupledBankDequantPinCommitment(
            source_pin);
    if (source_commitment.IsNull() ||
        source_pin.pin_commitment != source_commitment ||
        proof.batch.n_coeffs != source_pin.n_coeffs ||
        proof.batch.column_len.size() !=
            kRCStage3CoupledBankDequantColumns + 1 ||
        proof.trace_commit.IsNull() ||
        !aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            proof.trace_commit)) {
        return Fail(why, "normalized_bank_row_pin_shape");
    }
    out.source_pin_commitment = source_commitment;
    out.n_rows = source_pin.n_rows;
    out.n_coeffs = source_pin.n_coeffs;
    out.trace_row_commitment = proof.trace_commit;
    out.pin_commitment =
        ComputeNormalizedCoupledBankRowPinCommitment(out);
    return !out.pin_commitment.IsNull() ||
        Fail(why, "normalized_bank_row_pin_commitment");
}

bool VerifyNormalizedCoupledBankProof(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (row_pin.source_pin_commitment !=
            source_pin.pin_commitment ||
        row_pin.n_rows != source_pin.n_rows ||
        row_pin.n_coeffs != source_pin.n_coeffs ||
        row_pin.trace_row_commitment != proof.trace_commit ||
        row_pin.pin_commitment !=
            ComputeNormalizedCoupledBankRowPinCommitment(
                row_pin) ||
        row_pin.pin_commitment.IsNull()) {
        return Fail(why, "normalized_bank_row_pin");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildNormalizedCoupledBankConstraintSystem(
            source_pin, cs, why)) {
        return false;
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            cs, proof, fs_seed, &air_why)) {
        return Fail(
            why, "normalized_bank_air:" + air_why);
    }
    return true;
}

namespace {

bool CanonicalNormalizedSlotMetadata(
    const NormalizedRoleChildSlot& slot,
    uint16_t ordinal)
{
    const auto& order = RCStage3UnifiedRoleOrder();
    if (ordinal >= order.size() ||
        slot.version != kNormalizedSemanticRootV1Version ||
        slot.scheme !=
            NormalizedSemanticRootScheme::
                NormalizedAlgHashTerminalV1 ||
        slot.ordinal != ordinal ||
        slot.role != order[ordinal]) {
        return false;
    }
    const auto& endpoints =
        RequiredRCStage3RelationEndpoints(slot.role);
    if (endpoints.empty() ||
        endpoints.size() >
            std::numeric_limits<uint16_t>::max() ||
        slot.endpoint_count != endpoints.size() ||
        slot.first_endpoint !=
            static_cast<uint16_t>(endpoints.front())) {
        return false;
    }
    for (size_t i = 0; i < endpoints.size(); ++i) {
        if (static_cast<uint16_t>(endpoints[i]) !=
            slot.first_endpoint + i) {
            return false;
        }
    }
    return true;
}

bool CompleteNormalizedSlotBinding(
    const NormalizedRoleChildSlot& slot,
    uint16_t ordinal)
{
    return
        CanonicalNormalizedSlotMetadata(slot, ordinal) &&
        !slot.statement_commitment.IsNull() &&
        !slot.program_table_commitment.IsNull() &&
        !slot.child_trace_row_root.IsNull() &&
        !slot.child_proof_commitment.IsNull() &&
        !slot.terminal_bus_commitment.IsNull() &&
        !slot.normalized_semantic_root.IsNull() &&
        slot.normalized_semantic_root ==
            ComputeNormalizedSemanticRootV1(slot) &&
        !slot.slot_commitment.IsNull() &&
        slot.slot_commitment ==
            ComputeNormalizedRoleChildSlotCommitment(slot);
}

uint32_t Uint256Limb32(
    const uint256& value,
    uint32_t limb)
{
    const unsigned char* bytes = value.data() + 4 * limb;
    return uint32_t{bytes[0]} |
           (uint32_t{bytes[1]} << 8) |
           (uint32_t{bytes[2]} << 16) |
           (uint32_t{bytes[3]} << 24);
}

} // namespace

bool BuildNormalizedAlgAirProofFieldTranscriptV1(
    const AlgAirProof& proof,
    std::vector<gf::Fp>& out,
    uint32_t* batch_codec_bytes,
    uint32_t* batch_codec_words,
    uint32_t* supplemental_field_count,
    std::string* why)
{
    out.clear();
    std::vector<unsigned char> batch;
    const size_t encoded =
        SerializeFri3AlgBatchProof(
            proof.batch, batch);
    if (encoded == 0 ||
        encoded != batch.size() ||
        encoded >
            std::numeric_limits<uint32_t>::max() ||
        proof.trace_commit.IsNull() ||
        !aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            proof.trace_commit)) {
        return Fail(
            why,
            "normalized_alg_air_field_transcript_shape");
    }

    const uint32_t byte_count =
        static_cast<uint32_t>(encoded);
    const uint32_t word_count =
        static_cast<uint32_t>(
            CeilDiv(byte_count, 4));
    std::vector<gf::Fp> supplemental;
    supplemental.reserve(
        9 + proof.next_openings.size() * 4);
    for (uint32_t limb = 0; limb < 8; ++limb) {
        supplemental.push_back(
            gf::FromU64(
                Uint256Limb32(
                    proof.trace_commit, limb)));
    }
    supplemental.push_back(gf::FromU64(
        proof.next_openings.size()));
    for (const auto& paths :
         proof.next_openings) {
        supplemental.push_back(gf::FromU64(
            paths.size()));
        for (const auto& path : paths) {
            supplemental.push_back(
                gf::FromU64(path.index));
            supplemental.push_back(gf::FromU64(
                path.values.size()));
            for (const Fp3& value :
                 path.values) {
                supplemental.push_back(
                    gf::Canonical(value.c0));
                supplemental.push_back(
                    gf::Canonical(value.c1));
                supplemental.push_back(
                    gf::Canonical(value.c2));
            }
            supplemental.push_back(gf::FromU64(
                path.siblings.size()));
            for (const ah::Digest& sibling :
                 path.siblings) {
                for (const gf::Fp limb : sibling) {
                    supplemental.push_back(
                        gf::Canonical(limb));
                }
            }
        }
    }
    if (supplemental.size() >
        std::numeric_limits<uint32_t>::max()) {
        return Fail(
            why,
            "normalized_alg_air_field_transcript_overflow");
    }

    // "BTXAPF1" and "IELDSV1", collision-free base-field domain lanes.
    out.reserve(
        6 + word_count +
        supplemental.size());
    out.push_back(
        UINT64_C(0x0031465041585442));
    out.push_back(
        UINT64_C(0x315653444c454946));
    out.push_back(gf::FromU64(
        kNormalizedAlgAirProofFieldBusVersion));
    out.push_back(gf::FromU64(byte_count));
    out.push_back(gf::FromU64(word_count));
    for (uint32_t word = 0;
         word < word_count; ++word) {
        uint32_t packed = 0;
        for (uint32_t byte = 0;
             byte < 4; ++byte) {
            const uint32_t offset =
                4 * word + byte;
            if (offset < byte_count) {
                packed |=
                    uint32_t{batch[offset]}
                    << (8 * byte);
            }
        }
        out.push_back(gf::FromU64(packed));
    }
    out.push_back(gf::FromU64(
        supplemental.size()));
    out.insert(
        out.end(),
        supplemental.begin(),
        supplemental.end());

    if (batch_codec_bytes != nullptr) {
        *batch_codec_bytes = byte_count;
    }
    if (batch_codec_words != nullptr) {
        *batch_codec_words = word_count;
    }
    if (supplemental_field_count != nullptr) {
        *supplemental_field_count =
            static_cast<uint32_t>(
                supplemental.size());
    }
    return !out.empty();
}

uint256 ComputeNormalizedAlgAirProofCommitment(
    const AlgAirProof& proof)
{
    std::vector<gf::Fp> transcript;
    if (!BuildNormalizedAlgAirProofFieldTranscriptV1(
            proof, transcript, nullptr,
            nullptr, nullptr, nullptr)) {
        return {};
    }
    return aq::AirFriBackendAlg<Fp3>::PackDigest(
        ah::SpongeHashFp(transcript));
}

bool BuildNormalizedTerminalBusFieldTranscriptV1(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    std::vector<gf::Fp>& out,
    std::string* why)
{
    out.clear();
    if (child_index >= pins.size() ||
        child_index >= manifest.participants.size() ||
        pins.size() != manifest.participants.size()) {
        return Fail(why, "normalized_terminal_bus_transcript_shape");
    }
    const uint256 composition =
        CommitRCStage3CtlComposition(manifest, pins);
    const uint256 child =
        CommitRCStage3CtlChildPin(pins[child_index]);
    const uint256 schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    if (composition.IsNull() || child.IsNull() ||
        schedule_commitment.IsNull() ||
        schedule_commitment !=
            pins[child_index].schedule_commitment ||
        pins[child_index].role !=
            manifest.participants[child_index].role) {
        return Fail(why, "normalized_terminal_bus_transcript_pins");
    }
    out.push_back(gf::FromU64(0x54424d31ULL));
    out.push_back(gf::FromU64(0x4e425553ULL));
    out.push_back(gf::FromU64(kNormalizedSemanticRootV1Version));
    out.push_back(gf::FromU64(manifest.bus_id));
    out.push_back(gf::FromU64(static_cast<uint32_t>(child_index)));
    out.push_back(gf::FromU64(
        static_cast<uint16_t>(pins[child_index].role)));
    const uint256* digests[3] = {
        &composition, &child, &schedule_commitment};
    for (const uint256* digest : digests) {
        for (uint32_t limb = 0; limb < 8; ++limb) {
            out.push_back(gf::FromU64(Uint256Limb32(*digest, limb)));
        }
    }
    if (out.size() != 30) {
        out.clear();
        return Fail(why, "normalized_terminal_bus_transcript_count");
    }
    return true;
}

uint256 ComputeNormalizedTerminalBusCommitment(
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule)
{
    std::vector<gf::Fp> transcript;
    if (!BuildNormalizedTerminalBusFieldTranscriptV1(
            manifest, pins, child_index, schedule,
            transcript, nullptr)) {
        return {};
    }
    return aq::AirFriBackendAlg<Fp3>::PackDigest(
        ah::SpongeHashFp(transcript));
}

bool BuildNormalizedSemanticRootInputsV1(
    const NormalizedRoleChildSlot& slot,
    std::vector<gf::Fp>& out,
    std::string* why)
{
    out.clear();
    if (slot.version !=
            kNormalizedSemanticRootV1Version ||
        slot.scheme !=
            NormalizedSemanticRootScheme::
                NormalizedAlgHashTerminalV1 ||
        slot.endpoint_count == 0 ||
        slot.first_endpoint == 0 ||
        slot.statement_commitment.IsNull() ||
        slot.program_table_commitment.IsNull() ||
        slot.child_trace_row_root.IsNull() ||
        slot.child_proof_commitment.IsNull() ||
        slot.terminal_bus_commitment.IsNull()) {
        return Fail(
            why,
            "normalized_semantic_root_inputs_shape");
    }
    out.reserve(
        kNormalizedSemanticRootInputLanes);
    out.push_back(
        kNormalizedSemanticRootDomainLane0);
    out.push_back(
        kNormalizedSemanticRootDomainLane1);
    out.push_back(gf::FromU64(slot.version));
    out.push_back(gf::FromU64(
        static_cast<uint8_t>(slot.scheme)));
    out.push_back(gf::FromU64(slot.ordinal));
    out.push_back(gf::FromU64(
        static_cast<uint16_t>(slot.role)));
    out.push_back(gf::FromU64(slot.first_endpoint));
    out.push_back(gf::FromU64(slot.endpoint_count));

    const std::array<const uint256*, 5> digests{
        &slot.statement_commitment,
        &slot.program_table_commitment,
        &slot.child_trace_row_root,
        &slot.child_proof_commitment,
        &slot.terminal_bus_commitment,
    };
    for (const uint256* digest : digests) {
        for (uint32_t limb = 0; limb < 8; ++limb) {
            out.push_back(gf::FromU64(
                Uint256Limb32(*digest, limb)));
        }
    }
    if (out.size() !=
        kNormalizedSemanticRootInputLanes) {
        out.clear();
        return Fail(
            why,
            "normalized_semantic_root_inputs_count");
    }
    return true;
}

uint256 ComputeNormalizedSemanticRootV1(
    const NormalizedRoleChildSlot& slot)
{
    std::vector<gf::Fp> inputs;
    if (!BuildNormalizedSemanticRootInputsV1(
            slot, inputs, nullptr)) {
        return {};
    }
    return aq::AirFriBackendAlg<Fp3>::PackDigest(
        ah::SpongeHashFp(inputs));
}

uint256 ComputeNormalizedRoleChildSlotCommitment(
    const NormalizedRoleChildSlot& slot)
{
    const uint256 semantic =
        ComputeNormalizedSemanticRootV1(slot);
    if (semantic.IsNull() ||
        slot.normalized_semantic_root != semantic) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_ROLE_CHILD_SLOT_V1";
    hash << slot.version;
    hash << static_cast<uint8_t>(slot.scheme);
    hash << slot.ordinal;
    hash << static_cast<uint16_t>(slot.role);
    hash << slot.first_endpoint;
    hash << slot.endpoint_count;
    hash << slot.statement_commitment;
    hash << slot.program_table_commitment;
    hash << slot.child_trace_row_root;
    hash << slot.child_proof_commitment;
    hash << slot.terminal_bus_commitment;
    hash << slot.normalized_semantic_root;
    return hash.GetHash();
}

uint256 ComputeNormalizedRoleChildRegistryCommitment(
    const NormalizedRoleChildRegistry& registry)
{
    if (registry.version !=
            kNormalizedRoleChildRegistryVersion ||
        registry.slots.size() !=
            kRCStage3UnifiedRoleCount) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_ROLE_CHILD_REGISTRY_V1";
    hash << registry.version;
    hash << static_cast<uint16_t>(registry.slots.size());
    for (uint16_t ordinal = 0;
         ordinal < registry.slots.size(); ++ordinal) {
        const auto& slot = registry.slots[ordinal];
        if (!CompleteNormalizedSlotBinding(
                slot, ordinal)) {
            return {};
        }
        hash << slot.slot_commitment;
    }
    return hash.GetHash();
}

NormalizedRoleChildRegistry
BuildCanonicalNormalizedRoleChildRegistrySchedule()
{
    NormalizedRoleChildRegistry out;
    const auto& order = RCStage3UnifiedRoleOrder();
    out.slots.reserve(order.size());
    for (uint16_t ordinal = 0;
         ordinal < order.size(); ++ordinal) {
        NormalizedRoleChildSlot slot;
        slot.ordinal = ordinal;
        slot.role = order[ordinal];
        const auto& endpoints =
            RequiredRCStage3RelationEndpoints(slot.role);
        if (!endpoints.empty() &&
            endpoints.size() <=
                std::numeric_limits<uint16_t>::max()) {
            slot.first_endpoint =
                static_cast<uint16_t>(
                    endpoints.front());
            slot.endpoint_count =
                static_cast<uint16_t>(
                    endpoints.size());
        }
        out.slots.push_back(std::move(slot));
    }
    return out;
}

bool InstallNormalizedRoleChildSlot(
    NormalizedRoleChildRegistry& registry,
    const NormalizedRoleChildSlot& slot,
    std::string* why)
{
    if (registry.version !=
            kNormalizedRoleChildRegistryVersion ||
        registry.slots.size() !=
            kRCStage3UnifiedRoleCount ||
        slot.ordinal >= registry.slots.size() ||
        !CompleteNormalizedSlotBinding(
            slot, slot.ordinal)) {
        return Fail(
            why, "normalized_registry_install_slot");
    }
    for (uint16_t ordinal = 0;
         ordinal < registry.slots.size(); ++ordinal) {
        if (!CanonicalNormalizedSlotMetadata(
                registry.slots[ordinal], ordinal)) {
            return Fail(
                why,
                "normalized_registry_schedule");
        }
    }
    registry.slots[slot.ordinal] = slot;
    registry.registry_commitment =
        ComputeNormalizedRoleChildRegistryCommitment(
            registry);
    return true;
}

NormalizedRoleChildRegistryAudit
AssessNormalizedRoleChildRegistry(
    const NormalizedRoleChildRegistry& registry)
{
    NormalizedRoleChildRegistryAudit out;
    out.scheduled_roles =
        static_cast<uint16_t>(
            std::min<size_t>(
                registry.slots.size(),
                std::numeric_limits<uint16_t>::max()));
    out.canonical_order_and_intervals =
        registry.version ==
            kNormalizedRoleChildRegistryVersion &&
        registry.slots.size() ==
            kRCStage3UnifiedRoleCount;
    out.normalized_v1_only =
        out.canonical_order_and_intervals;
    if (out.canonical_order_and_intervals) {
        for (uint16_t ordinal = 0;
             ordinal < registry.slots.size();
             ++ordinal) {
            const auto& slot = registry.slots[ordinal];
            if (!CanonicalNormalizedSlotMetadata(
                    slot, ordinal)) {
                out.canonical_order_and_intervals = false;
            }
            if (slot.scheme !=
                NormalizedSemanticRootScheme::
                    NormalizedAlgHashTerminalV1) {
                out.normalized_v1_only = false;
            }
            if (CompleteNormalizedSlotBinding(
                    slot, ordinal)) {
                ++out.normalized_v1_bound_roles;
            }
        }
    }
    out.missing_or_invalid_roles =
        kRCStage3UnifiedRoleCount >
                out.normalized_v1_bound_roles
        ? kRCStage3UnifiedRoleCount -
            out.normalized_v1_bound_roles
        : 0;
    out.binding_complete =
        out.canonical_order_and_intervals &&
        out.normalized_v1_only &&
        out.normalized_v1_bound_roles ==
            kRCStage3UnifiedRoleCount &&
        !registry.registry_commitment.IsNull() &&
        registry.registry_commitment ==
            ComputeNormalizedRoleChildRegistryCommitment(
                registry);
    // Commitments are not recursive verifier executions.
    out.recursively_consumed_roles = 0;
    out.recursive_consumption_complete = false;
    out.note =
        out.binding_complete
        ? "stage3:recursive_fixedpoint:"
          "normalized_registry_binding_complete_"
          "recursive_consumption_open"
        : "stage3:recursive_fixedpoint:"
          "normalized_registry_fail_closed_missing_or_unproved";
    return out;
}

bool VerifyNormalizedRoleChildRegistryBinding(
    const NormalizedRoleChildRegistry& registry,
    std::string* why)
{
    const auto audit =
        AssessNormalizedRoleChildRegistry(registry);
    if (!audit.binding_complete) {
        return Fail(
            why,
            "normalized_registry_missing_or_unproved");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "normalized_registry_binding_ok_"
            "recursive_consumption_open";
    }
    return true;
}

uint256 ComputeNormalizedEndpointTerminalBusCommitment(
    const NormalizedEndpointTerminalBusV1& terminal)
{
    if (terminal.version !=
            kNormalizedTerminalTranscriptV1Version ||
        terminal.instance_count == 0 ||
        terminal.manifest_root.IsNull() ||
        terminal.proof_root.IsNull() ||
        terminal.semantic_root.IsNull() ||
        terminal.proof_column_root.IsNull() ||
        terminal.recursive_child_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_ENDPOINT_TERMINAL_V1";
    hash << terminal.version;
    hash << terminal.global_ordinal;
    hash << terminal.role_ordinal;
    hash << terminal.endpoint_ordinal;
    hash << static_cast<uint16_t>(terminal.role);
    hash << static_cast<uint16_t>(terminal.endpoint);
    hash << terminal.instance_count;
    hash << terminal.manifest_root;
    hash << terminal.proof_root;
    hash << terminal.semantic_root;
    hash << terminal.proof_column_root;
    hash << terminal.recursive_child_commitment;
    return hash.GetHash();
}

uint256 ComputeNormalizedRoleTerminalBusCommitment(
    const NormalizedRoleTerminalBusV1& terminal,
    const std::vector<NormalizedEndpointTerminalBusV1>&
        endpoints)
{
    const uint32_t begin =
        terminal.first_endpoint_ordinal;
    const uint32_t end =
        begin + terminal.endpoint_count;
    if (terminal.version !=
            kNormalizedTerminalTranscriptV1Version ||
        terminal.endpoint_count == 0 ||
        end > endpoints.size() ||
        terminal.relation_commitment.IsNull() ||
        terminal.relation_statement_root.IsNull() ||
        terminal.endpoint_multiproof_root.IsNull()) {
        return {};
    }
    RCStage3RelationRoleClosure reconstructed;
    reconstructed.role = terminal.role;
    reconstructed.relation_commitment =
        terminal.relation_commitment;
    reconstructed.relation_statement_root =
        terminal.relation_statement_root;
    reconstructed.endpoint_multiproof_root =
        terminal.endpoint_multiproof_root;
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_ROLE_TERMINAL_V1";
    hash << terminal.version;
    hash << terminal.role_ordinal;
    hash << static_cast<uint16_t>(terminal.role);
    hash << terminal.first_endpoint_ordinal;
    hash << terminal.endpoint_count;
    hash << terminal.relation_commitment;
    hash << terminal.relation_statement_root;
    hash << terminal.endpoint_multiproof_root;
    for (uint32_t ordinal = begin;
         ordinal < end; ++ordinal) {
        const auto& endpoint = endpoints[ordinal];
        if (endpoint.global_ordinal != ordinal ||
            endpoint.role_ordinal !=
                terminal.role_ordinal ||
            endpoint.role != terminal.role ||
            endpoint.terminal_commitment.IsNull() ||
            endpoint.terminal_commitment !=
                ComputeNormalizedEndpointTerminalBusCommitment(
                    endpoint)) {
            return {};
        }
        reconstructed.endpoints.push_back({
            endpoint.endpoint,
            endpoint.instance_count,
            endpoint.manifest_root,
            endpoint.proof_root,
            endpoint.semantic_root,
            endpoint.proof_column_root,
            endpoint.recursive_child_commitment,
        });
        hash << endpoint.terminal_commitment;
    }
    if (terminal.endpoint_multiproof_root !=
        ComputeRCStage3RelationRoleMultiproofRoot(
            reconstructed)) {
        return {};
    }
    return hash.GetHash();
}

uint256 ComputeNormalizedTerminalTranscriptCommitment(
    const NormalizedTerminalTranscriptV1& transcript)
{
    if (transcript.version !=
            kNormalizedTerminalTranscriptV1Version ||
        transcript.endpoints.size() !=
            kNormalizedTerminalTranscriptEndpointCount ||
        transcript.roles.size() !=
            kNormalizedTerminalTranscriptRoleCount ||
        transcript.unified_root_seed.IsNull() ||
        transcript.statement_commitment.IsNull() ||
        transcript.ctl_proof_bundle_commitment.IsNull() ||
        transcript.composition_link_commitment.IsNull() ||
        transcript.final_digest_manifest_root.IsNull() ||
        transcript.final_digest_proof_root.IsNull() ||
        transcript.final_digest_semantic_root.IsNull() ||
        transcript.
            final_digest_recursive_child_commitment.IsNull() ||
        transcript.source_closure_commitment.IsNull()) {
        return {};
    }
    const auto& order = RCStage3UnifiedRoleOrder();
    uint16_t next_endpoint = 0;
    for (uint16_t role_ordinal = 0;
         role_ordinal < transcript.roles.size();
         ++role_ordinal) {
        const auto& role = transcript.roles[role_ordinal];
        const auto& required =
            RequiredRCStage3RelationEndpoints(
                order[role_ordinal]);
        if (role.version !=
                kNormalizedTerminalTranscriptV1Version ||
            role.role_ordinal != role_ordinal ||
            role.role != order[role_ordinal] ||
            role.first_endpoint_ordinal != next_endpoint ||
            role.endpoint_count != required.size() ||
            role.terminal_commitment.IsNull() ||
            role.terminal_commitment !=
                ComputeNormalizedRoleTerminalBusCommitment(
                    role, transcript.endpoints)) {
            return {};
        }
        for (uint16_t endpoint_ordinal = 0;
             endpoint_ordinal < required.size();
             ++endpoint_ordinal) {
            const auto& endpoint =
                transcript.endpoints[next_endpoint];
            if (endpoint.version !=
                    kNormalizedTerminalTranscriptV1Version ||
                endpoint.global_ordinal != next_endpoint ||
                endpoint.role_ordinal != role_ordinal ||
                endpoint.endpoint_ordinal !=
                    endpoint_ordinal ||
                endpoint.role != role.role ||
                endpoint.endpoint !=
                    required[endpoint_ordinal] ||
                endpoint.terminal_commitment.IsNull() ||
                endpoint.terminal_commitment !=
                    ComputeNormalizedEndpointTerminalBusCommitment(
                        endpoint)) {
                return {};
            }
            ++next_endpoint;
        }
    }
    if (next_endpoint !=
        kNormalizedTerminalTranscriptEndpointCount) {
        return {};
    }
    RCStage3RelationClosureV1 reconstructed;
    reconstructed.unified_root_seed =
        transcript.unified_root_seed;
    reconstructed.statement_commitment =
        transcript.statement_commitment;
    reconstructed.ctl_proof_bundle_commitment =
        transcript.ctl_proof_bundle_commitment;
    reconstructed.composition_link_commitment =
        transcript.composition_link_commitment;
    reconstructed.final_digest_manifest_root =
        transcript.final_digest_manifest_root;
    reconstructed.final_digest_proof_root =
        transcript.final_digest_proof_root;
    reconstructed.final_digest_semantic_root =
        transcript.final_digest_semantic_root;
    reconstructed.final_digest_recursive_child_commitment =
        transcript.final_digest_recursive_child_commitment;
    reconstructed.roles.reserve(transcript.roles.size());
    for (const auto& role : transcript.roles) {
        RCStage3RelationRoleClosure source_role;
        source_role.role = role.role;
        source_role.relation_commitment =
            role.relation_commitment;
        source_role.relation_statement_root =
            role.relation_statement_root;
        source_role.endpoint_multiproof_root =
            role.endpoint_multiproof_root;
        const uint32_t end =
            role.first_endpoint_ordinal +
            role.endpoint_count;
        for (uint32_t ordinal =
                 role.first_endpoint_ordinal;
             ordinal < end; ++ordinal) {
            const auto& endpoint =
                transcript.endpoints[ordinal];
            source_role.endpoints.push_back({
                endpoint.endpoint,
                endpoint.instance_count,
                endpoint.manifest_root,
                endpoint.proof_root,
                endpoint.semantic_root,
                endpoint.proof_column_root,
                endpoint.recursive_child_commitment,
            });
        }
        reconstructed.roles.push_back(
            std::move(source_role));
    }
    if (transcript.source_closure_commitment !=
        ComputeRCStage3RelationClosureCommitment(
            reconstructed)) {
        return {};
    }

    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_TERMINAL_TRANSCRIPT_V1";
    hash << transcript.version;
    hash << static_cast<uint16_t>(
        transcript.endpoints.size());
    hash << static_cast<uint16_t>(
        transcript.roles.size());
    for (const auto& endpoint : transcript.endpoints) {
        hash << endpoint.terminal_commitment;
    }
    for (const auto& role : transcript.roles) {
        hash << role.terminal_commitment;
    }
    hash << transcript.unified_root_seed;
    hash << transcript.statement_commitment;
    hash << transcript.ctl_proof_bundle_commitment;
    hash << transcript.composition_link_commitment;
    hash << transcript.final_digest_manifest_root;
    hash << transcript.final_digest_proof_root;
    hash << transcript.final_digest_semantic_root;
    hash <<
        transcript.final_digest_recursive_child_commitment;
    hash << transcript.source_closure_commitment;
    return hash.GetHash();
}

bool BuildNormalizedTerminalTranscriptV1(
    const RCStage3RelationClosureV1& closure,
    NormalizedTerminalTranscriptV1& out,
    std::string* why)
{
    out = {};
    if (closure.magic !=
            kRCStage3RelationClosureMagic ||
        closure.version !=
            kRCStage3RelationClosureVersion ||
        closure.strategy !=
            RCStage3RelationClosureStrategy::
                HashBoundMultiproof ||
        closure.roles.size() !=
            kNormalizedTerminalTranscriptRoleCount ||
        closure.closure_commitment.IsNull() ||
        closure.closure_commitment !=
            ComputeRCStage3RelationClosureCommitment(
                closure)) {
        return Fail(
            why,
            "normalized_terminal_source_closure");
    }
    const auto& order = RCStage3UnifiedRoleOrder();
    out.endpoints.reserve(
        kNormalizedTerminalTranscriptEndpointCount);
    out.roles.reserve(
        kNormalizedTerminalTranscriptRoleCount);
    uint16_t global_endpoint = 0;
    for (uint16_t role_ordinal = 0;
         role_ordinal < closure.roles.size();
         ++role_ordinal) {
        const auto& source_role =
            closure.roles[role_ordinal];
        const auto& required =
            RequiredRCStage3RelationEndpoints(
                order[role_ordinal]);
        if (source_role.role != order[role_ordinal] ||
            source_role.endpoints.size() !=
                required.size() ||
            source_role.endpoint_multiproof_root.IsNull() ||
            source_role.endpoint_multiproof_root !=
                ComputeRCStage3RelationRoleMultiproofRoot(
                    source_role)) {
            return Fail(
                why,
                "normalized_terminal_role_order_or_root");
        }
        NormalizedRoleTerminalBusV1 role;
        role.role_ordinal = role_ordinal;
        role.role = source_role.role;
        role.first_endpoint_ordinal = global_endpoint;
        role.endpoint_count =
            static_cast<uint16_t>(required.size());
        role.relation_commitment =
            source_role.relation_commitment;
        role.relation_statement_root =
            source_role.relation_statement_root;
        role.endpoint_multiproof_root =
            source_role.endpoint_multiproof_root;
        for (uint16_t endpoint_ordinal = 0;
             endpoint_ordinal < required.size();
             ++endpoint_ordinal) {
            const auto& source_endpoint =
                source_role.endpoints[endpoint_ordinal];
            if (source_endpoint.endpoint !=
                required[endpoint_ordinal]) {
                return Fail(
                    why,
                    "normalized_terminal_endpoint_order");
            }
            NormalizedEndpointTerminalBusV1 endpoint;
            endpoint.global_ordinal = global_endpoint;
            endpoint.role_ordinal = role_ordinal;
            endpoint.endpoint_ordinal =
                endpoint_ordinal;
            endpoint.role = source_role.role;
            endpoint.endpoint =
                source_endpoint.endpoint;
            endpoint.instance_count =
                source_endpoint.instance_count;
            endpoint.manifest_root =
                source_endpoint.manifest_root;
            endpoint.proof_root =
                source_endpoint.proof_root;
            endpoint.semantic_root =
                source_endpoint.semantic_root;
            endpoint.proof_column_root =
                source_endpoint.proof_column_root;
            endpoint.recursive_child_commitment =
                source_endpoint.
                    recursive_child_commitment;
            endpoint.terminal_commitment =
                ComputeNormalizedEndpointTerminalBusCommitment(
                    endpoint);
            if (endpoint.terminal_commitment.IsNull()) {
                return Fail(
                    why,
                    "normalized_terminal_incomplete_endpoint");
            }
            out.endpoints.push_back(
                std::move(endpoint));
            ++global_endpoint;
        }
        role.terminal_commitment =
            ComputeNormalizedRoleTerminalBusCommitment(
                role, out.endpoints);
        if (role.terminal_commitment.IsNull()) {
            return Fail(
                why,
                "normalized_terminal_incomplete_role");
        }
        out.roles.push_back(std::move(role));
    }
    if (global_endpoint !=
        kNormalizedTerminalTranscriptEndpointCount) {
        out = {};
        return Fail(
            why,
            "normalized_terminal_endpoint_total");
    }
    out.unified_root_seed =
        closure.unified_root_seed;
    out.statement_commitment =
        closure.statement_commitment;
    out.ctl_proof_bundle_commitment =
        closure.ctl_proof_bundle_commitment;
    out.composition_link_commitment =
        closure.composition_link_commitment;
    out.final_digest_manifest_root =
        closure.final_digest_manifest_root;
    out.final_digest_proof_root =
        closure.final_digest_proof_root;
    out.final_digest_semantic_root =
        closure.final_digest_semantic_root;
    out.final_digest_recursive_child_commitment =
        closure.final_digest_recursive_child_commitment;
    out.source_closure_commitment =
        closure.closure_commitment;
    out.transcript_commitment =
        ComputeNormalizedTerminalTranscriptCommitment(
            out);
    if (out.transcript_commitment.IsNull()) {
        out = {};
        return Fail(
            why,
            "normalized_terminal_transcript_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "normalized_terminal_transcript_14_roles_"
            "52_endpoints_binding_complete_"
            "recursive_children_open";
    }
    return true;
}

NormalizedTerminalTranscriptAudit
AssessNormalizedTerminalTranscriptV1(
    const NormalizedTerminalTranscriptV1& transcript)
{
    NormalizedTerminalTranscriptAudit out;
    out.scheduled_roles =
        static_cast<uint16_t>(
            std::min<size_t>(
                transcript.roles.size(),
                std::numeric_limits<uint16_t>::max()));
    out.scheduled_endpoints =
        static_cast<uint16_t>(
            std::min<size_t>(
                transcript.endpoints.size(),
                std::numeric_limits<uint16_t>::max()));
    const auto& order = RCStage3UnifiedRoleOrder();
    out.canonical_role_order =
        transcript.roles.size() ==
            kNormalizedTerminalTranscriptRoleCount;
    out.canonical_endpoint_order =
        transcript.endpoints.size() ==
            kNormalizedTerminalTranscriptEndpointCount;
    out.all_terminal_commitments_recomputed =
        out.canonical_role_order &&
        out.canonical_endpoint_order;
    uint16_t global_endpoint = 0;
    if (out.all_terminal_commitments_recomputed) {
        for (uint16_t role_ordinal = 0;
             role_ordinal < transcript.roles.size();
             ++role_ordinal) {
            const auto& role =
                transcript.roles[role_ordinal];
            const auto& required =
                RequiredRCStage3RelationEndpoints(
                    order[role_ordinal]);
            if (role.role_ordinal != role_ordinal ||
                role.role != order[role_ordinal] ||
                role.first_endpoint_ordinal !=
                    global_endpoint ||
                role.endpoint_count != required.size()) {
                out.canonical_role_order = false;
            }
            for (uint16_t endpoint_ordinal = 0;
                 endpoint_ordinal < required.size();
                 ++endpoint_ordinal) {
                if (global_endpoint >=
                    transcript.endpoints.size()) {
                    out.canonical_endpoint_order = false;
                    break;
                }
                const auto& endpoint =
                    transcript.endpoints[
                        global_endpoint];
                if (endpoint.global_ordinal !=
                        global_endpoint ||
                    endpoint.role_ordinal !=
                        role_ordinal ||
                    endpoint.endpoint_ordinal !=
                        endpoint_ordinal ||
                    endpoint.role != role.role ||
                    endpoint.endpoint !=
                        required[endpoint_ordinal] ||
                    endpoint.terminal_commitment !=
                        ComputeNormalizedEndpointTerminalBusCommitment(
                            endpoint)) {
                    out.canonical_endpoint_order = false;
                    out.all_terminal_commitments_recomputed =
                        false;
                }
                ++global_endpoint;
            }
            if (role.terminal_commitment !=
                ComputeNormalizedRoleTerminalBusCommitment(
                    role, transcript.endpoints)) {
                out.all_terminal_commitments_recomputed =
                    false;
            }
        }
    }
    if (global_endpoint !=
        kNormalizedTerminalTranscriptEndpointCount) {
        out.canonical_endpoint_order = false;
    }
    out.source_closure_binding =
        !transcript.source_closure_commitment.IsNull() &&
        !transcript.transcript_commitment.IsNull() &&
        transcript.transcript_commitment ==
            ComputeNormalizedTerminalTranscriptCommitment(
                transcript);
    out.binding_complete =
        out.canonical_role_order &&
        out.canonical_endpoint_order &&
        out.all_terminal_commitments_recomputed &&
        out.source_closure_binding;

    if (out.canonical_endpoint_order) {
        const auto cell_audit =
            CurrentRCStage3RelationEndpointCellAudit();
        for (const auto& endpoint : transcript.endpoints) {
            const auto found = std::find_if(
                cell_audit.begin(), cell_audit.end(),
                [&endpoint](const auto& cell) {
                    return
                        cell.role == endpoint.role &&
                        cell.endpoint ==
                            endpoint.endpoint;
                });
            if (found != cell_audit.end() &&
                found->semantic_relation_complete) {
                ++out.locally_semantic_complete_endpoints;
            }
        }
    }
    // A commitment naming a child is not execution of that child.  No
    // executable multi-segment verifier input exists in this V1 transcript.
    out.recursively_child_proof_owned_endpoints = 0;
    out.recursively_child_proof_owned_roles = 0;
    out.recursive_consumption_complete = false;
    out.blocker =
        out.binding_complete
        ? "normalized_recursive_children_not_executable:"
          "52_endpoint_children_and_14_multisegment_"
          "role_verifiers_unconsumed"
        : "normalized_terminal_transcript_binding_incomplete";
    return out;
}

NormalizedTerminalTranscriptAttachment
AttachNormalizedTerminalTranscriptV1(
    FoldBusComposition& composition,
    const NormalizedTerminalTranscriptV1& transcript)
{
    NormalizedTerminalTranscriptAttachment out;
    out.layout =
        NormalizedTerminalTranscriptLayout(
            composition.combined.n_columns);
    const auto audit =
        AssessNormalizedTerminalTranscriptV1(
            transcript);
    if (!composition.valid ||
        !audit.binding_complete) {
        out.blocker =
            !audit.binding_complete
            ? audit.blocker
            : "normalized_parent_composition_invalid";
        return out;
    }
    if (composition.combined.n_rows <
        NormalizedTerminalTranscriptLayout::
            kRequiredRows) {
        out.blocker =
            "normalized_parent_needs_69_vertical_rows";
        return out;
    }

    using Row =
        std::array<uint64_t,
            NormalizedTerminalTranscriptLayout::
                kScalarCells>;
    using Digests =
        std::array<uint256,
            NormalizedTerminalTranscriptLayout::
                kDigestCount>;
    const uint32_t n_rows =
        composition.combined.n_rows;
    std::vector<Row> scalars(
        n_rows, Row{});
    std::vector<Digests> digests(
        n_rows, Digests{});
    auto set_common =
        [&](uint32_t row,
            NormalizedTerminalTranscriptRowKind kind,
            uint16_t global_ordinal,
            uint16_t role_ordinal,
            uint16_t endpoint_ordinal,
            RCStage3RelationRole role,
            RCStage3RelationEndpoint endpoint,
            uint64_t instance_count) {
            scalars[row][0] = 1;
            scalars[row][1] =
                static_cast<uint8_t>(kind);
            scalars[row][2] =
                kNormalizedTerminalTranscriptV1Version;
            scalars[row][3] = global_ordinal;
            scalars[row][4] = role_ordinal;
            scalars[row][5] = endpoint_ordinal;
            scalars[row][6] =
                static_cast<uint16_t>(role);
            scalars[row][7] =
                static_cast<uint16_t>(endpoint);
            scalars[row][8] =
                static_cast<uint32_t>(
                    instance_count);
            scalars[row][9] =
                static_cast<uint32_t>(
                    instance_count >> 32);
        };

    for (const auto& endpoint :
         transcript.endpoints) {
        const uint32_t row =
            endpoint.global_ordinal;
        set_common(
            row,
            NormalizedTerminalTranscriptRowKind::
                Endpoint,
            endpoint.global_ordinal,
            endpoint.role_ordinal,
            endpoint.endpoint_ordinal,
            endpoint.role,
            endpoint.endpoint,
            endpoint.instance_count);
        digests[row] = {
            endpoint.manifest_root,
            endpoint.proof_root,
            endpoint.semantic_root,
            endpoint.proof_column_root,
            endpoint.recursive_child_commitment,
            endpoint.terminal_commitment,
        };
    }
    for (const auto& role : transcript.roles) {
        const uint32_t row =
            kNormalizedTerminalTranscriptEndpointCount +
            role.role_ordinal;
        const auto& required =
            RequiredRCStage3RelationEndpoints(
                role.role);
        set_common(
            row,
            NormalizedTerminalTranscriptRowKind::Role,
            static_cast<uint16_t>(row),
            role.role_ordinal,
            role.first_endpoint_ordinal,
            role.role,
            required.front(),
            role.endpoint_count);
        digests[row] = {
            role.relation_commitment,
            role.relation_statement_root,
            role.endpoint_multiproof_root,
            role.terminal_commitment,
            {},
            {},
        };
    }
    const uint32_t header_row =
        kNormalizedTerminalTranscriptEndpointCount +
        kNormalizedTerminalTranscriptRoleCount;
    set_common(
        header_row,
        NormalizedTerminalTranscriptRowKind::
            ClosureHeader,
        static_cast<uint16_t>(header_row),
        transcript.version, 0,
        RCStage3UnifiedRoleOrder().front(),
        RequiredRCStage3RelationEndpoints(
            RCStage3UnifiedRoleOrder().front()).front(),
        kNormalizedTerminalTranscriptEndpointCount);
    // The closure ABI is fixed, but is still mapped rather than inferred:
    // magic, version, strategy, role count and endpoint count.
    scalars[header_row][4] =
        kRCStage3RelationClosureMagic;
    scalars[header_row][5] =
        kRCStage3RelationClosureVersion;
    scalars[header_row][6] =
        static_cast<uint8_t>(
            RCStage3RelationClosureStrategy::
                HashBoundMultiproof);
    scalars[header_row][7] =
        kNormalizedTerminalTranscriptRoleCount;
    digests[header_row] = {
        transcript.unified_root_seed,
        transcript.statement_commitment,
        transcript.ctl_proof_bundle_commitment,
        transcript.source_closure_commitment,
        {},
        {},
    };
    const uint32_t final_row = header_row + 1;
    set_common(
        final_row,
        NormalizedTerminalTranscriptRowKind::
            FinalDigest,
        static_cast<uint16_t>(final_row),
        0, 0,
        RCStage3UnifiedRoleOrder().back(),
        RequiredRCStage3RelationEndpoints(
            RCStage3UnifiedRoleOrder().back()).back(),
        0);
    digests[final_row] = {
        transcript.composition_link_commitment,
        transcript.final_digest_manifest_root,
        transcript.final_digest_proof_root,
        transcript.final_digest_semantic_root,
        transcript.
            final_digest_recursive_child_commitment,
        transcript.source_closure_commitment,
    };
    const uint32_t registry_row = final_row + 1;
    set_common(
        registry_row,
        NormalizedTerminalTranscriptRowKind::Registry,
        static_cast<uint16_t>(registry_row),
        transcript.version, 0,
        RCStage3UnifiedRoleOrder().front(),
        RequiredRCStage3RelationEndpoints(
            RCStage3UnifiedRoleOrder().front()).front(),
        (uint64_t{
             kNormalizedTerminalTranscriptRoleCount}
             << 32) |
            kNormalizedTerminalTranscriptEndpointCount);
    digests[registry_row] = {
        transcript.transcript_commitment,
        transcript.source_closure_commitment,
        {},
        {},
        {},
        {},
    };

    composition.combined.n_columns =
        out.layout.End();
    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            n_rows, Fp3::Zero()));
    composition.combined.preprocessed_pin_ood = true;
    for (uint32_t cell = 0;
         cell <
            NormalizedTerminalTranscriptLayout::kCells;
         ++cell) {
        const uint32_t witness =
            out.layout.Witness(cell);
        const uint32_t expected =
            out.layout.Expected(cell);
        for (uint32_t row = 0;
             row < n_rows; ++row) {
            Fp3 value = Fp3::Zero();
            if (cell <
                NormalizedTerminalTranscriptLayout::
                    kScalarCells) {
                value = Fp3::FromFp(
                    gf::FromU64(
                        scalars[row][cell]));
            } else {
                const uint32_t digest_cell =
                    cell -
                    NormalizedTerminalTranscriptLayout::
                        kScalarCells;
                const uint32_t digest =
                    digest_cell /
                    NormalizedTerminalTranscriptLayout::
                        kDigestLimbs;
                const uint32_t limb =
                    digest_cell %
                    NormalizedTerminalTranscriptLayout::
                        kDigestLimbs;
                value = Fp3::FromFp(
                    gf::FromU64(
                        Uint256Limb32(
                            digests[row][digest],
                            limb)));
            }
            composition.columns[witness][row] = value;
            composition.columns[expected][row] = value;
        }
        composition.combined.preprocessed.emplace_back(
            expected,
            composition.columns[expected]);
        aq::AirConstraint<Fp3> constraint;
        constraint.name =
            "stage3.fixedpoint.normalized_terminal_"
            "transcript_cell_equality";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 1;
        constraint.eval =
            [witness, expected](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    current[witness],
                    current[expected]);
            };
        composition.combined.constraints.push_back(
            std::move(constraint));
        ++out.equality_constraints;
    }
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    if (composition.violations != 0) {
        composition.valid = false;
        out.blocker =
            "normalized_terminal_parent_air_violation";
        return out;
    }
    out.locally_constrained_roles =
        kNormalizedTerminalTranscriptRoleCount;
    out.locally_constrained_endpoints =
        kNormalizedTerminalTranscriptEndpointCount;
    out.locally_semantic_complete_endpoints =
        audit.locally_semantic_complete_endpoints;
    out.recursively_child_proof_owned_roles =
        audit.recursively_child_proof_owned_roles;
    out.recursively_child_proof_owned_endpoints =
        audit.recursively_child_proof_owned_endpoints;
    out.ordered_coverage = true;
    out.transcript_commitment_bound = true;
    out.valid = true;
    out.blocker =
        "normalized_parent_local_binding_complete:"
        "recursive_child_ownership_0_of_14_roles_"
        "0_of_52_endpoints";
    return out;
}

NormalizedCoupledBankTerminalExecution
ExecuteNormalizedCoupledBankTerminal(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed,
    const RCStage3CtlManifest& ctl_manifest,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    size_t ctl_child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& ctl_proof)
{
    NormalizedCoupledBankTerminalExecution out;
    const auto registry =
        BuildCanonicalNormalizedRoleChildRegistrySchedule();
    const auto& order = RCStage3UnifiedRoleOrder();
    const auto it = std::find(
        order.begin(), order.end(),
        RCStage3RelationRole::CoupledBank);
    if (it == order.end()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_role_missing";
        return out;
    }
    const size_t canonical_index =
        static_cast<size_t>(
            std::distance(order.begin(), it));
    if (ctl_child_index != canonical_index ||
        ctl_manifest.participants.size() != order.size() ||
        ctl_pins.size() != order.size() ||
        registry.slots.size() != order.size()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_ctl_registry_shape";
        return out;
    }
    for (size_t index = 0;
         index < order.size(); ++index) {
        if (ctl_manifest.participants[index].role !=
                order[index] ||
            ctl_pins[index].role != order[index]) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_bank_ctl_role_order";
            return out;
        }
    }
    std::string child_why;
    if (!VerifyNormalizedCoupledBankProof(
            source_pin, row_pin, proof,
            fs_seed, &child_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_child:" + child_why;
        return out;
    }
    out.normalized_child_proof_verified = true;
    std::string ctl_why;
    if (!VerifyRCStage3CtlChildAirProof(
            ctl_manifest, ctl_pins, ctl_child_index,
            schedule, ctl_proof, &ctl_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_ctl_child:" + ctl_why;
        return out;
    }
    out.ctl_child_proof_verified = true;
    if (!VerifyRCStage3CtlPublicPinComposition(
            ctl_manifest, ctl_pins, &ctl_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_ctl_terminal:" + ctl_why;
        return out;
    }
    out.public_terminal_composition_verified = true;

    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3CoupledBankDequantProgramTable(
            source_pin, table, &child_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_program:" + child_why;
        return out;
    }
    out.ctl_child_index =
        static_cast<uint32_t>(ctl_child_index);
    out.slot = registry.slots[canonical_index];
    out.slot.statement_commitment =
        source_pin.statement_commitment;
    out.slot.program_table_commitment =
        constraint_bytecode::CommitProgramTable(table);
    out.slot.child_trace_row_root =
        row_pin.trace_row_commitment;
    out.slot.child_proof_commitment =
        ComputeNormalizedAlgAirProofCommitment(proof);
    out.slot.terminal_bus_commitment =
        ComputeNormalizedTerminalBusCommitment(
            ctl_manifest, ctl_pins,
            ctl_child_index, schedule);
    out.slot.normalized_semantic_root =
        ComputeNormalizedSemanticRootV1(out.slot);
    out.slot.slot_commitment =
        ComputeNormalizedRoleChildSlotCommitment(
            out.slot);
    out.valid =
        out.normalized_child_proof_verified &&
        out.ctl_child_proof_verified &&
        out.public_terminal_composition_verified &&
        CompleteNormalizedSlotBinding(
            out.slot,
            static_cast<uint16_t>(canonical_index));
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_bank_semantic_root_v1_ok_"
          "legacy_sha_bridge_open"
        : "stage3:recursive_fixedpoint:"
          "normalized_bank_semantic_root_v1_invalid";
    return out;
}

bool AttachNormalizedCoupledBankTerminalBinding(
    FoldBusComposition& composition,
    BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    NormalizedCoupledBankTerminalExecution& execution,
    NormalizedRoleTerminalLayout* layout_out,
    std::string* why)
{
    if (!composition.valid || !interpreter.valid ||
        !execution.valid ||
        execution.parent_terminal_bound ||
        execution.legacy_sha_alg_bridge ||
        execution.slot.role !=
            RCStage3RelationRole::CoupledBank ||
        execution.slot.program_table_commitment !=
            interpreter.program_commitment ||
        execution.slot.child_trace_row_root !=
            row_pin.trace_row_commitment ||
        execution.slot.normalized_semantic_root !=
            ComputeNormalizedSemanticRootV1(
                execution.slot) ||
        execution.slot.slot_commitment !=
            ComputeNormalizedRoleChildSlotCommitment(
                execution.slot) ||
        !interpreter.
            same_trace_relation_cell_logup_export) {
        return Fail(
            why,
            "normalized_bank_parent_terminal_input");
    }
    const NormalizedRoleTerminalLayout layout(
        composition.combined.n_columns);
    const uint32_t n_rows =
        composition.combined.n_rows;
    composition.combined.n_columns = layout.End();
    composition.columns.resize(
        layout.End(),
        std::vector<Fp3>(
            n_rows, Fp3::Zero()));
    composition.combined.preprocessed_pin_ood = true;
    for (uint32_t limb = 0; limb < 8; ++limb) {
        const uint32_t value =
            Uint256Limb32(
                execution.slot.
                    normalized_semantic_root,
                limb);
        const Fp3 expected =
            Fp3::FromFp(gf::FromU64(value));
        const uint32_t column =
            layout.RootLimb(limb);
        std::fill(
            composition.columns[column].begin(),
            composition.columns[column].end(),
            expected);
        composition.combined.preprocessed.emplace_back(
            column, composition.columns[column]);
        aq::AirConstraint<Fp3> constraint;
        constraint.name =
            "stage3.fixedpoint.normalized_semantic_root_limb";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 1;
        constraint.eval =
            [column, expected](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    current[column], expected);
            };
        composition.combined.constraints.push_back(
            std::move(constraint));
    }
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    if (composition.violations != 0) {
        composition.valid = false;
        return Fail(
            why,
            "normalized_bank_parent_terminal_air");
    }
    interpreter.normalized_v1_role_terminal_binding =
        true;
    interpreter.normalized_v1_semantic_root =
        execution.slot.normalized_semantic_root;
    // Endpoint-28 / SHA↔AlgHash terminal equality is owned by
    // AttachNormalizedEndpointTerminalEqualityV1; the V1 pin alone does not
    // imply it.
    interpreter.role_semantic_root_terminal_equality =
        false;
    execution.parent_terminal_bound = true;
    if (layout_out != nullptr) {
        *layout_out = layout;
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_parent_terminal_v1_bound_"
            "endpoint_terminal_equality_open";
    }
    return true;
}

NormalizedEndpointTerminalEqualityAttachmentV1
AttachNormalizedEndpointTerminalEqualityV1(
    FoldBusComposition& composition,
    BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedRoleTerminalLayout& terminal_layout,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge)
{
    NormalizedEndpointTerminalEqualityAttachmentV1 out;
    out.terminal_layout = terminal_layout;
    out.constraint_base = static_cast<uint32_t>(
        composition.combined.constraints.size());

    const bool child_trace_root_proof_owned =
        composition.valid &&
        composition.hash.valid &&
        composition.hash.proof_derived &&
        composition.hash.native_child_accepted &&
        composition.hash.program.trace_root_opening &&
        row_pin.trace_row_commitment ==
            execution.slot.child_trace_row_root &&
        row_pin.trace_row_commitment ==
            aq::AirFriBackendAlg<Fp3>::PackDigest(
                composition.hash.program.
                    public_inputs.rt_root);
    out.child_trace_root_proof_owned =
        child_trace_root_proof_owned;

    const auto expected_root =
        aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            execution.slot.normalized_semantic_root);
    out.sponge_output_equals_role_root =
        semantic_sponge.valid &&
        semantic_sponge.output_equals_candidate_semantic_root &&
        semantic_sponge.output_root ==
            execution.slot.normalized_semantic_root &&
        semantic_sponge.output_root ==
            interpreter.normalized_v1_semantic_root &&
        expected_root.has_value();

    if (!composition.valid ||
        !interpreter.valid ||
        !execution.valid ||
        !execution.parent_terminal_bound ||
        execution.legacy_sha_alg_bridge ||
        interpreter.role_semantic_root_terminal_equality ||
        !interpreter.normalized_v1_role_terminal_binding ||
        interpreter.normalized_v1_semantic_root !=
            execution.slot.normalized_semantic_root ||
        execution.slot.role !=
            RCStage3RelationRole::CoupledBank ||
        execution.slot.first_endpoint != 27 ||
        execution.slot.endpoint_count != 3 ||
        execution.slot.normalized_semantic_root !=
            ComputeNormalizedSemanticRootV1(
                execution.slot) ||
        !child_trace_root_proof_owned ||
        !out.sponge_output_equals_role_root ||
        terminal_layout.End() >
            composition.combined.n_columns ||
        semantic_sponge.layout.End() >
            composition.combined.n_columns ||
        composition.columns.size() !=
            composition.combined.n_columns) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "endpoint_terminal_equality_input";
        return out;
    }

    // Verify pin columns already hold the SHA-byte u32 limbs of the root.
    for (uint32_t limb = 0; limb < 8; ++limb) {
        const uint32_t column =
            terminal_layout.RootLimb(limb);
        const Fp3 expected =
            Fp3::FromFp(
                gf::FromU64(
                    Uint256Limb32(
                        execution.slot.
                            normalized_semantic_root,
                        limb)));
        if (column >= composition.columns.size() ||
            composition.columns[column].size() !=
                composition.combined.n_rows) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "endpoint_terminal_equality_pin_layout";
            return out;
        }
        for (uint32_t row = 0;
             row < composition.combined.n_rows;
             ++row) {
            if (!gf::Eq(
                    composition.columns[column][row],
                    expected)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "endpoint_terminal_equality_pin_mismatch";
                return out;
            }
        }
    }

    constexpr gf::Fp TWO32 = UINT64_C(1) << 32;
    const ar::PermLayout final_permutation =
        semantic_sponge.layout.Permutation(
            kNormalizedSemanticRootSpongeBlocks - 1);
    for (uint32_t limb = 0;
         limb < ah::kAlgHashDigestLen;
         ++limb) {
        aq::AirConstraint<Fp3> packing;
        packing.name =
            "stage3.fixedpoint.endpoint_terminal_equality."
            "sha_alg_hash_packing";
        packing.kind = aq::AirKind::kEverywhere;
        packing.alg_degree = 1;
        const uint32_t low =
            terminal_layout.RootLimb(2 * limb);
        const uint32_t high =
            terminal_layout.RootLimb(2 * limb + 1);
        packing.eval =
            [final_permutation, limb, low, high](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    ar::PermOutputLane(
                        final_permutation, row, limb),
                    gf::Add(
                        row[low],
                        gf::Mul(
                            Fp3::FromFp(TWO32),
                            row[high])));
            };
        composition.combined.constraints.push_back(
            std::move(packing));
        ++out.sha_alg_packing_constraints;
    }

    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations = composition.violations;
    out.sha_alg_hash_packing_linked =
        out.sha_alg_packing_constraints ==
            ah::kAlgHashDigestLen &&
        out.violations == 0;
    out.role_semantic_root_terminal_equality =
        out.child_trace_root_proof_owned &&
        out.sponge_output_equals_role_root &&
        out.sha_alg_hash_packing_linked;
    out.legacy_sha_alg_bridge =
        out.role_semantic_root_terminal_equality;
    out.valid =
        kNormalizedEndpointTerminalEqualityExecutable &&
        out.role_semantic_root_terminal_equality &&
        out.legacy_sha_alg_bridge &&
        out.added_constraints == 4 &&
        out.violations == 0;
    if (out.valid) {
        interpreter.role_semantic_root_terminal_equality =
            true;
        execution.legacy_sha_alg_bridge = true;
    }
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "endpoint_terminal_equality_ok;"
          "sha_alg_hash_packing_linked;"
          "endpoint28_child_trace_root_proof_owned;"
          "complete_fp=false"
        : "stage3:recursive_fixedpoint:"
          "endpoint_terminal_equality_invalid";
    return out;
}

bool ValidateNormalizedEndpointTerminalEqualityV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedRoleTerminalLayout& terminal_layout,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const NormalizedEndpointTerminalEqualityAttachmentV1&
        attachment,
    std::string* why)
{
    if (!attachment.valid ||
        attachment.version != 1 ||
        !attachment.role_semantic_root_terminal_equality ||
        !attachment.legacy_sha_alg_bridge ||
        !attachment.sha_alg_hash_packing_linked ||
        !attachment.child_trace_root_proof_owned ||
        !attachment.sponge_output_equals_role_root ||
        attachment.sha_alg_packing_constraints != 4 ||
        attachment.added_constraints != 4 ||
        attachment.violations != 0 ||
        !interpreter.role_semantic_root_terminal_equality ||
        !execution.legacy_sha_alg_bridge ||
        !interpreter.normalized_v1_role_terminal_binding ||
        interpreter.normalized_v1_semantic_root !=
            execution.slot.normalized_semantic_root ||
        attachment.terminal_layout.normalized_root_limb_base !=
            terminal_layout.normalized_root_limb_base ||
        !semantic_sponge.valid ||
        !semantic_sponge.output_equals_candidate_semantic_root ||
        semantic_sponge.output_root !=
            execution.slot.normalized_semantic_root) {
        return Fail(
            why,
            "endpoint_terminal_equality_attachment_shape");
    }

    const bool child_trace_root_proof_owned =
        composition.valid &&
        composition.hash.valid &&
        composition.hash.proof_derived &&
        composition.hash.native_child_accepted &&
        composition.hash.program.trace_root_opening &&
        row_pin.trace_row_commitment ==
            execution.slot.child_trace_row_root &&
        row_pin.trace_row_commitment ==
            aq::AirFriBackendAlg<Fp3>::PackDigest(
                composition.hash.program.
                    public_inputs.rt_root);
    if (!child_trace_root_proof_owned) {
        return Fail(
            why,
            "endpoint_terminal_equality_trace_root");
    }

    constexpr gf::Fp TWO32 = UINT64_C(1) << 32;
    const auto expected_root =
        aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            execution.slot.normalized_semantic_root);
    if (!expected_root.has_value()) {
        return Fail(
            why,
            "endpoint_terminal_equality_root_unpack");
    }
    const ar::PermLayout final_permutation =
        semantic_sponge.layout.Permutation(
            kNormalizedSemanticRootSpongeBlocks - 1);
    for (uint32_t limb = 0;
         limb < ah::kAlgHashDigestLen;
         ++limb) {
        const uint32_t low =
            terminal_layout.RootLimb(2 * limb);
        const uint32_t high =
            terminal_layout.RootLimb(2 * limb + 1);
        if (low >= composition.columns.size() ||
            high >= composition.columns.size()) {
            return Fail(
                why,
                "endpoint_terminal_equality_columns");
        }
        const Fp3 digest =
            Fp3::FromFp(
                gf::Canonical((*expected_root)[limb]));
        for (uint32_t r = 0;
             r < composition.combined.n_rows;
             ++r) {
            const Fp3 packed = gf::Add(
                composition.columns[low][r],
                gf::Mul(
                    Fp3::FromFp(TWO32),
                    composition.columns[high][r]));
            if (!gf::Eq(packed, digest)) {
                return Fail(
                    why,
                    "endpoint_terminal_equality_packing");
            }
        }
    }
    // Spot-check sponge output on row 0; AIR violations cover every row.
    {
        std::vector<Fp3> row0(
            composition.combined.n_columns,
            Fp3::Zero());
        for (uint32_t col = 0;
             col < composition.combined.n_columns;
             ++col) {
            row0[col] = composition.columns[col][0];
        }
        for (uint32_t limb = 0;
             limb < ah::kAlgHashDigestLen;
             ++limb) {
            const Fp3 digest =
                Fp3::FromFp(
                    gf::Canonical((*expected_root)[limb]));
            if (!gf::Eq(
                    ar::PermOutputLane(
                        final_permutation, row0, limb),
                    digest)) {
                return Fail(
                    why,
                    "endpoint_terminal_equality_sponge_output");
            }
        }
    }

    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0) {
        return Fail(
            why,
            "endpoint_terminal_equality_air");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "endpoint_terminal_equality_validated";
    }
    return true;
}

NormalizedSemanticAlgHashParentAudit
AssessNormalizedSemanticAlgHashParentClosure(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution)
{
    NormalizedSemanticAlgHashParentAudit out;
    out.required_input_lanes = 48;
    out.sponge_blocks =
        out.required_input_lanes /
            ah::kAlgHashRate +
        1;
    out.additional_permutation_columns =
        out.sponge_blocks *
        ar::kPermCellsPerPerm;
    out.canonical_alg_hash_available =
        ah::kAlgHashRate == 8 &&
        ar::kPermCellsPerPerm == 130 &&
        out.sponge_blocks == 7 &&
        out.additional_permutation_columns == 910;

    const auto add =
        [&](const char* field,
            uint32_t lanes,
            NormalizedAlgHashInputSource source,
            bool bound,
            const char* detail) {
            out.fields.push_back(
                {field, lanes, source, bound, detail});
            if (source ==
                NormalizedAlgHashInputSource::
                    VerifierConstant) {
                out.verifier_constant_lanes += lanes;
            } else if (
                source ==
                    NormalizedAlgHashInputSource::
                        ProofAuthenticated &&
                bound) {
                out.proof_authenticated_lanes += lanes;
            } else {
                out.missing_proof_bus_lanes += lanes;
            }
        };

    add(
        "domain",
        2,
        NormalizedAlgHashInputSource::VerifierConstant,
        true,
        "two frozen normalized-root V2 domain lanes");
    add(
        "version_scheme_ordinal_role_interval",
        6,
        NormalizedAlgHashInputSource::VerifierConstant,
        true,
        "canonical registry metadata");
    add(
        "statement_commitment_u32",
        8,
        NormalizedAlgHashInputSource::VerifierConstant,
        !execution.slot.statement_commitment.IsNull(),
        "verifier-owned public statement commitment");
    add(
        "program_table_commitment_u32",
        8,
        NormalizedAlgHashInputSource::VerifierConstant,
        execution.slot.program_table_commitment ==
            interpreter.program_commitment &&
            !interpreter.program_commitment.IsNull(),
        "verifier-reconstructed canonical bytecode table");

    const bool trace_root_mapped =
        composition.valid &&
        composition.hash.valid &&
        composition.hash.proof_derived &&
        composition.hash.native_child_accepted &&
        composition.hash.program.trace_root_opening &&
        row_pin.trace_row_commitment ==
            execution.slot.child_trace_row_root &&
        row_pin.trace_row_commitment ==
            aq::AirFriBackendAlg<Fp3>::PackDigest(
                composition.hash.program.
                    public_inputs.rt_root);
    out.child_trace_root_mapped = trace_root_mapped;
    add(
        "child_trace_row_root_u32",
        8,
        NormalizedAlgHashInputSource::ProofAuthenticated,
        trace_root_mapped,
        trace_root_mapped
            ? "four authenticated AlgHash digest limbs admit a "
              "verifier-owned exact u32 decomposition"
            : "trace-root terminal is not linked to the slot");

    // Base path (no ProofFieldBus): commitment lanes stay MissingProofBus.
    // AttachNormalizedAlgAirProofFieldBusV1 streams the ordered transcript
    // and derives+links the commitment; call
    // PromoteNormalizedSemanticProofCommitmentFromFieldBusV1 afterward.
    // A copied public hash alone would remain a claim, not a binding.
    out.child_proof_commitment_mapped = false;
    add(
        "child_proof_commitment_u32",
        8,
        NormalizedAlgHashInputSource::MissingProofBus,
        false,
        "missing ProofFieldBus-derived commitment export from the V_CS");

    // The selected CTL child is verified natively before this parent is
    // built. Its proof, global composition and terminal cells are not a
    // recursively verified child of this parent, so the SHA commitment has
    // no proof-authenticated limb source here.
    out.terminal_bus_commitment_mapped = false;
    add(
        "terminal_bus_commitment_u32",
        8,
        NormalizedAlgHashInputSource::MissingProofBus,
        false,
        "missing normalized CTL child verifier and terminal-cell export");

    out.slot_binding_valid =
        execution.slot.ordinal <
            kRCStage3UnifiedRoleCount &&
        CompleteNormalizedSlotBinding(
            execution.slot,
            execution.slot.ordinal) &&
        execution.slot.child_trace_row_root ==
            row_pin.trace_row_commitment &&
        execution.slot.program_table_commitment ==
            interpreter.program_commitment &&
        execution.slot.normalized_semantic_root ==
            interpreter.normalized_v1_semantic_root;
    out.external_root_pin_only =
        interpreter.normalized_v1_role_terminal_binding &&
        !interpreter.
            role_semantic_root_terminal_equality;
    out.in_parent_derivation_complete =
        out.canonical_alg_hash_available &&
        out.slot_binding_valid &&
        out.child_trace_root_mapped &&
        out.child_proof_commitment_mapped &&
        out.terminal_bus_commitment_mapped &&
        out.missing_proof_bus_lanes == 0;
    out.blocker =
        out.in_parent_derivation_complete
        ? "stage3:recursive_fixedpoint:"
          "normalized_semantic_alg_hash_parent_complete"
        : "stage3:recursive_fixedpoint:"
          "normalized_semantic_alg_hash_blocked:"
          "8_child_proof_commitment_lanes_and_"
          "8_terminal_bus_commitment_lanes_have_no_"
          "proof_authenticated_parent_source";
    return out;
}

NormalizedSemanticRootSpongeAttachmentV1
AttachNormalizedSemanticRootSpongeV1(
    FoldBusComposition& composition,
    const NormalizedRoleChildSlot& slot)
{
    NormalizedSemanticRootSpongeAttachmentV1 out;
    out.layout =
        NormalizedSemanticRootSpongeLayout(
            composition.combined.n_columns);
    out.output_root =
        ComputeNormalizedSemanticRootV1(slot);
    out.input_lanes =
        kNormalizedSemanticRootInputLanes;
    out.sponge_blocks =
        kNormalizedSemanticRootSpongeBlocks;
    out.permutation_columns =
        kNormalizedSemanticRootPermutationColumns;
    out.constraint_base =
        static_cast<uint32_t>(
            composition.combined.constraints.size());

    std::vector<gf::Fp> inputs;
    const auto expected_root =
        aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            slot.normalized_semantic_root);
    if (!composition.valid ||
        composition.combined.n_rows < 2 ||
        composition.columns.size() !=
            composition.combined.n_columns ||
        !BuildNormalizedSemanticRootInputsV1(
            slot, inputs, nullptr) ||
        out.output_root.IsNull() ||
        slot.normalized_semantic_root !=
            out.output_root ||
        !expected_root.has_value()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_semantic_sponge_input";
        return out;
    }

    const uint32_t rows =
        composition.combined.n_rows;
    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            rows, Fp3::Zero()));
    composition.combined.n_columns =
        out.layout.End();
    composition.combined.preprocessed_pin_ood =
        true;

    for (uint32_t lane = 0;
         lane < inputs.size(); ++lane) {
        std::vector<Fp3> expected(
            rows,
            Fp3::FromFp(inputs[lane]));
        composition.columns[
            out.layout.Input(lane)] =
                expected;
        composition.combined.preprocessed.emplace_back(
            out.layout.Input(lane),
            std::move(expected));
    }

    // Materialize the exact seven-block SpongeHashFp witness once and repeat
    // it over the parent domain. These are statement-global values, so the
    // repeated-row form is canonical.
    ah::State state{};
    for (uint32_t block = 0;
         block < kNormalizedSemanticRootSpongeBlocks;
         ++block) {
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate;
             ++lane) {
            const uint32_t position =
                block * ah::kAlgHashRate + lane;
            const gf::Fp absorbed =
                position <
                    kNormalizedSemanticRootInputLanes
                ? inputs[position]
                : (position ==
                           kNormalizedSemanticRootInputLanes
                       ? gf::Fp{1}
                       : gf::Fp{0});
            state[lane] =
                gf::Add(state[lane], absorbed);
        }
        const ar::PermWitness witness =
            ar::BuildPermWitness(state);
        std::vector<Fp3> row_values(
            out.layout.End(), Fp3::Zero());
        ar::WritePermWitness(
            out.layout.Permutation(block),
            witness, row_values);
        for (uint32_t cell = 0;
             cell < ar::kPermCellsPerPerm;
             ++cell) {
            auto& column =
                composition.columns[
                    out.layout.Permutation(block).base +
                    cell];
            std::fill(
                column.begin(), column.end(),
                row_values[
                    out.layout.Permutation(block).base +
                    cell]);
        }
        state = witness.output;
    }

    const auto append =
        [&](aq::AirConstraint<Fp3> constraint) {
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t block = 0;
         block < kNormalizedSemanticRootSpongeBlocks;
         ++block) {
        const ar::PermLayout current =
            out.layout.Permutation(block);
        for (auto& constraint :
             ar::BuildPermRoundConstraints(current)) {
            append(std::move(constraint));
        }

        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate;
             ++lane) {
            const uint32_t position =
                block * ah::kAlgHashRate + lane;
            aq::AirConstraint<Fp3> absorb;
            absorb.kind = aq::AirKind::kEverywhere;
            absorb.alg_degree = 1;
            const uint32_t input_column =
                current.InputCol(lane);
            if (position <
                    kNormalizedSemanticRootInputLanes) {
                absorb.name =
                    "stage3.fixedpoint.normalized_semantic_"
                    "sponge.absorb_input";
                const uint32_t source_column =
                    out.layout.Input(position);
                if (block == 0) {
                    absorb.eval =
                        [input_column, source_column](
                            const std::vector<Fp3>& row,
                            const std::vector<Fp3>&) {
                            return gf::Sub(
                                row[input_column],
                                row[source_column]);
                        };
                } else {
                    const ar::PermLayout previous =
                        out.layout.Permutation(
                            block - 1);
                    absorb.eval =
                        [input_column, source_column,
                         previous, lane](
                            const std::vector<Fp3>& row,
                            const std::vector<Fp3>&) {
                            return gf::Sub(
                                row[input_column],
                                gf::Add(
                                    ar::PermOutputLane(
                                        previous, row,
                                        lane),
                                    row[source_column]));
                        };
                }
                ++out.input_equality_constraints;
            } else {
                absorb.name =
                    "stage3.fixedpoint.normalized_semantic_"
                    "sponge.full_padding";
                const Fp3 padding =
                    position ==
                        kNormalizedSemanticRootInputLanes
                    ? Fp3::One()
                    : Fp3::Zero();
                const ar::PermLayout previous =
                    out.layout.Permutation(
                        block - 1);
                absorb.eval =
                    [input_column, previous,
                     lane, padding](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Sub(
                            row[input_column],
                            gf::Add(
                                ar::PermOutputLane(
                                    previous, row,
                                    lane),
                                padding));
                    };
                ++out.padding_constraints;
            }
            append(std::move(absorb));
        }

        for (uint32_t lane =
                 ah::kAlgHashRate;
             lane < ah::kAlgHashT; ++lane) {
            aq::AirConstraint<Fp3> capacity;
            capacity.name =
                "stage3.fixedpoint.normalized_semantic_"
                "sponge.capacity_carry";
            capacity.kind =
                aq::AirKind::kEverywhere;
            capacity.alg_degree = 1;
            const uint32_t input_column =
                current.InputCol(lane);
            if (block == 0) {
                capacity.eval =
                    [input_column](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return row[input_column];
                    };
            } else {
                const ar::PermLayout previous =
                    out.layout.Permutation(
                        block - 1);
                capacity.eval =
                    [input_column, previous, lane](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Sub(
                            row[input_column],
                            ar::PermOutputLane(
                                previous, row, lane));
                    };
            }
            append(std::move(capacity));
            ++out.capacity_carry_constraints;
        }
    }

    const ar::PermLayout final_permutation =
        out.layout.Permutation(
            kNormalizedSemanticRootSpongeBlocks - 1);
    for (uint32_t limb = 0;
         limb < ah::kAlgHashDigestLen;
         ++limb) {
        aq::AirConstraint<Fp3> output;
        output.name =
            "stage3.fixedpoint.normalized_semantic_"
            "sponge.output_root";
        output.kind = aq::AirKind::kEverywhere;
        output.alg_degree = 1;
        const Fp3 expected =
            Fp3::FromFp(
                gf::Canonical(
                    (*expected_root)[limb]));
        output.eval =
            [final_permutation, limb, expected](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    ar::PermOutputLane(
                        final_permutation, row,
                        limb),
                    expected);
            };
        append(std::move(output));
        ++out.output_constraints;
    }

    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    out.verifier_constant_lanes = 24;
    out.proof_authenticated_lanes = 8;
    out.externally_pinned_missing_bus_lanes = 16;
    out.exact_order =
        out.input_equality_constraints ==
            kNormalizedSemanticRootInputLanes;
    out.exact_full_padding_block =
        out.padding_constraints ==
            ah::kAlgHashRate;
    out.all_inputs_constrained =
        out.exact_order &&
        out.verifier_constant_lanes +
            out.proof_authenticated_lanes +
            out.externally_pinned_missing_bus_lanes ==
                kNormalizedSemanticRootInputLanes;
    out.output_equals_candidate_semantic_root =
        aq::AirFriBackendAlg<Fp3>::PackDigest(
            ah::Digest{
                state[0], state[1],
                state[2], state[3]}) ==
        slot.normalized_semantic_root;
    out.all_inputs_recursively_proof_owned = false;
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations = composition.violations;
    out.valid =
        out.input_lanes == 48 &&
        out.sponge_blocks == 7 &&
        out.permutation_columns == 910 &&
        out.added_constraints ==
            7 * ar::kPermSboxCells +
            48 + 8 + 7 * 4 + 4 &&
        out.exact_order &&
        out.exact_full_padding_block &&
        out.all_inputs_constrained &&
        out.output_equals_candidate_semantic_root &&
        !out.all_inputs_recursively_proof_owned &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_semantic_alg_hash_sponge_ok;"
          "48_inputs_7_blocks_910_permutation_columns;"
          "16_inputs_remain_external_local_pins;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_semantic_alg_hash_sponge_invalid";
    return out;
}

bool ValidateNormalizedSemanticRootSpongeV1(
    const FoldBusComposition& composition,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1& attachment,
    std::string* why)
{
    std::vector<gf::Fp> inputs;
    if (!attachment.valid ||
        attachment.version !=
            kNormalizedSemanticRootV1Version ||
        !BuildNormalizedSemanticRootInputsV1(
            slot, inputs, why) ||
        attachment.output_root !=
            ComputeNormalizedSemanticRootV1(slot) ||
        attachment.output_root !=
            slot.normalized_semantic_root ||
        attachment.input_lanes != 48 ||
        attachment.sponge_blocks != 7 ||
        attachment.permutation_columns != 910 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        composition.columns.size() !=
            composition.combined.n_columns ||
        attachment.added_constraints !=
            7 * ar::kPermSboxCells +
            48 + 8 + 7 * 4 + 4 ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.input_equality_constraints != 48 ||
        attachment.padding_constraints != 8 ||
        attachment.capacity_carry_constraints != 28 ||
        attachment.output_constraints != 4 ||
        attachment.verifier_constant_lanes != 24 ||
        attachment.proof_authenticated_lanes != 8 ||
        attachment.externally_pinned_missing_bus_lanes != 16 ||
        !attachment.exact_order ||
        !attachment.exact_full_padding_block ||
        !attachment.all_inputs_constrained ||
        !attachment.output_equals_candidate_semantic_root ||
        attachment.all_inputs_recursively_proof_owned) {
        return Fail(
            why,
            "normalized_semantic_sponge_shape");
    }

    for (uint32_t lane = 0;
         lane < inputs.size(); ++lane) {
        const uint32_t column =
            attachment.layout.Input(lane);
        if (column >= composition.columns.size()) {
            return Fail(
                why,
                "normalized_semantic_sponge_input_column");
        }
        const auto pin = std::find_if(
            composition.combined.preprocessed.begin(),
            composition.combined.preprocessed.end(),
            [column](const auto& item) {
                return item.first == column;
            });
        if (pin ==
                composition.combined.preprocessed.end() ||
            pin->second.size() !=
                composition.combined.n_rows ||
            composition.columns[column].size() !=
                composition.combined.n_rows) {
            return Fail(
                why,
                "normalized_semantic_sponge_input_pin");
        }
        const Fp3 expected =
            Fp3::FromFp(inputs[lane]);
        for (uint32_t row = 0;
             row < composition.combined.n_rows;
             ++row) {
            if (!gf::Eq(
                    pin->second[row], expected) ||
                !gf::Eq(
                    composition.columns[column][row],
                    expected)) {
                return Fail(
                    why,
                    "normalized_semantic_sponge_input_value");
            }
        }
    }
    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0 ||
        attachment.violations != 0) {
        return Fail(
            why,
            "normalized_semantic_sponge_air");
    }
    return true;
}

NormalizedAlgAirProofFieldBusAttachmentV1
AttachNormalizedAlgAirProofFieldBusV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge)
{
    NormalizedAlgAirProofFieldBusAttachmentV1 out;
    out.layout =
        NormalizedAlgAirProofFieldBusLayout(
            composition.combined.n_columns);
    out.parent_rows =
        composition.combined.n_rows;
    out.added_columns =
        out.layout.End() -
        out.layout.field_base;
    out.constraint_base =
        static_cast<uint32_t>(
            composition.combined.constraints.size());

    std::vector<gf::Fp> transcript;
    if (!BuildNormalizedAlgAirProofFieldTranscriptV1(
            proof, transcript,
            &out.batch_codec_bytes,
            &out.batch_codec_words,
            &out.supplemental_fields,
            nullptr)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_proof_field_bus_transcript";
        return out;
    }
    out.transcript_fields =
        static_cast<uint32_t>(
            transcript.size());
    out.active_sponge_rows =
        static_cast<uint32_t>(
            transcript.size() /
                kNormalizedAlgAirProofFieldBusRate +
            1);
    out.proof_commitment =
        aq::AirFriBackendAlg<Fp3>::PackDigest(
            ah::SpongeHashFp(transcript));
    const auto expected_root =
        aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            slot.child_proof_commitment);
    if (!composition.valid ||
        !semantic_sponge.valid ||
        semantic_sponge.layout.End() !=
            out.layout.field_base ||
        out.parent_rows < 2 ||
        out.active_sponge_rows >
            out.parent_rows ||
        out.proof_commitment.IsNull() ||
        out.proof_commitment !=
            slot.child_proof_commitment ||
        out.proof_commitment !=
            ComputeNormalizedAlgAirProofCommitment(
                proof) ||
        !expected_root.has_value()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_proof_field_bus_public_binding";
        return out;
    }

    std::vector<gf::Fp> padded =
        transcript;
    padded.push_back(gf::Fp{1});
    while (padded.size() %
               kNormalizedAlgAirProofFieldBusRate !=
           0) {
        padded.push_back(gf::Fp{0});
    }
    if (padded.size() !=
        uint64_t{out.active_sponge_rows} *
            kNormalizedAlgAirProofFieldBusRate) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_proof_field_bus_padding";
        return out;
    }

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns =
        out.layout.End();
    composition.combined.preprocessed_pin_ood =
        true;
    for (uint32_t row = 0;
         row < out.active_sponge_rows;
         ++row) {
        for (uint32_t lane = 0;
             lane <
                 kNormalizedAlgAirProofFieldBusRate;
             ++lane) {
            composition.columns[
                out.layout.Field(lane)][row] =
                Fp3::FromFp(
                    padded[
                        uint64_t{row} *
                            kNormalizedAlgAirProofFieldBusRate +
                        lane]);
        }
        composition.columns[
            out.layout.active][row] =
            Fp3::One();
    }
    composition.columns[
        out.layout.terminal]
        [out.active_sponge_rows - 1] =
            Fp3::One();
    for (uint32_t lane = 0;
         lane <
             kNormalizedAlgAirProofFieldBusRate;
         ++lane) {
        composition.combined.preprocessed.emplace_back(
            out.layout.Field(lane),
            composition.columns[
                out.layout.Field(lane)]);
    }
    composition.combined.preprocessed.emplace_back(
        out.layout.active,
        composition.columns[out.layout.active]);
    composition.combined.preprocessed.emplace_back(
        out.layout.terminal,
        composition.columns[out.layout.terminal]);

    ah::State state{};
    for (uint32_t row = 0;
         row < out.parent_rows; ++row) {
        ah::State input{};
        if (row <
            out.active_sponge_rows) {
            input = state;
            for (uint32_t lane = 0;
                 lane <
                     kNormalizedAlgAirProofFieldBusRate;
                 ++lane) {
                input[lane] =
                    gf::Add(
                        input[lane],
                        composition.columns[
                            out.layout.Field(lane)]
                            [row].c0);
            }
        }
        const ar::PermWitness witness =
            ar::BuildPermWitness(input);
        for (uint32_t cell = 0;
             cell < ar::kPermCellsPerPerm;
             ++cell) {
            composition.columns[
                out.layout.permutation.base +
                cell][row] =
                Fp3::FromFp(
                    witness.cells[cell]);
        }
        if (row <
            out.active_sponge_rows) {
            state = witness.output;
        }
    }

    const auto append =
        [&](aq::AirConstraint<Fp3> constraint) {
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (auto& constraint :
         ar::BuildPermRoundConstraints(
             out.layout.permutation)) {
        append(std::move(constraint));
    }

    for (const uint32_t selector :
         std::array<uint32_t, 2>{
             out.layout.active,
             out.layout.terminal}) {
        aq::AirConstraint<Fp3> boolean;
        boolean.name =
            "stage3.fixedpoint.normalized_proof_field_bus."
            "selector_boolean";
        boolean.kind =
            aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval =
            [selector](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[selector],
                    gf::Sub(
                        row[selector],
                        Fp3::One()));
            };
        append(std::move(boolean));
    }
    {
        aq::AirConstraint<Fp3> terminal_active;
        terminal_active.name =
            "stage3.fixedpoint.normalized_proof_field_bus."
            "terminal_implies_active";
        terminal_active.kind =
            aq::AirKind::kEverywhere;
        terminal_active.alg_degree = 2;
        const uint32_t active =
            out.layout.active;
        const uint32_t terminal =
            out.layout.terminal;
        terminal_active.eval =
            [active, terminal](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[terminal],
                    gf::Sub(
                        Fp3::One(),
                        row[active]));
            };
        append(std::move(terminal_active));
    }

    for (uint32_t lane = 0;
         lane < ah::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> first;
        first.name =
            "stage3.fixedpoint.normalized_proof_field_bus."
            "first_input";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        const uint32_t input_column =
            out.layout.permutation.InputCol(lane);
        if (lane <
            kNormalizedAlgAirProofFieldBusRate) {
            const uint32_t field =
                out.layout.Field(lane);
            first.eval =
                [input_column, field](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        row[input_column],
                        row[field]);
                };
        } else {
            first.eval =
                [input_column](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return row[input_column];
                };
        }
        append(std::move(first));
    }

    for (uint32_t lane = 0;
         lane < ah::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> transition;
        transition.name =
            "stage3.fixedpoint.normalized_proof_field_bus."
            "sponge_transition";
        transition.kind =
            aq::AirKind::kTransition;
        transition.alg_degree = 2;
        const uint32_t input_column =
            out.layout.permutation.InputCol(lane);
        const uint32_t active =
            out.layout.active;
        const ar::PermLayout permutation =
            out.layout.permutation;
        if (lane <
            kNormalizedAlgAirProofFieldBusRate) {
            const uint32_t field =
                out.layout.Field(lane);
            transition.eval =
                [input_column, active,
                 permutation, lane, field](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    return gf::Mul(
                        next[active],
                        gf::Sub(
                            next[input_column],
                            gf::Add(
                                ar::PermOutputLane(
                                    permutation,
                                    row, lane),
                                next[field])));
                };
        } else {
            transition.eval =
                [input_column, active,
                 permutation, lane](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    return gf::Mul(
                        next[active],
                        gf::Sub(
                            next[input_column],
                            ar::PermOutputLane(
                                permutation,
                                row, lane)));
                };
        }
        append(std::move(transition));
    }

    constexpr gf::Fp TWO32 =
        UINT64_C(1) << 32;
    for (uint32_t limb = 0;
         limb < ah::kAlgHashDigestLen;
         ++limb) {
        aq::AirConstraint<Fp3> root;
        root.name =
            "stage3.fixedpoint.normalized_proof_field_bus."
            "output_root";
        root.kind = aq::AirKind::kEverywhere;
        root.alg_degree = 2;
        const uint32_t terminal =
            out.layout.terminal;
        const ar::PermLayout permutation =
            out.layout.permutation;
        const Fp3 expected =
            Fp3::FromFp(
                (*expected_root)[limb]);
        root.eval =
            [terminal, permutation,
             limb, expected](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[terminal],
                    gf::Sub(
                        ar::PermOutputLane(
                            permutation,
                            row, limb),
                        expected));
            };
        append(std::move(root));

        aq::AirConstraint<Fp3> semantic;
        semantic.name =
            "stage3.fixedpoint.normalized_proof_field_bus."
            "semantic_u32_link";
        semantic.kind =
            aq::AirKind::kEverywhere;
        semantic.alg_degree = 2;
        const uint32_t low =
            semantic_sponge.layout.Input(
                32 + 2 * limb);
        const uint32_t high =
            semantic_sponge.layout.Input(
                33 + 2 * limb);
        semantic.eval =
            [terminal, permutation, limb,
             low, high](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[terminal],
                    gf::Sub(
                        ar::PermOutputLane(
                            permutation,
                            row, limb),
                        gf::Add(
                            row[low],
                            gf::Mul(
                                Fp3::FromFp(TWO32),
                                row[high]))));
            };
        append(std::move(semantic));
    }

    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    out.exact_codec_bytes_bound = true;
    out.all_supplemental_fields_bound = true;
    out.row_fold_ood_deep_query_path_fields_present =
        out.batch_codec_bytes != 0 &&
        out.batch_codec_words != 0 &&
        out.supplemental_fields != 0;
    out.proof_commitment_derived_in_parent = true;
    out.proof_commitment_semantic_lanes_linked = true;
    out.proof_fields_sourced_from_verifier_chips =
        false;
    out.complete_fiat_shamir_replay_in_parent =
        false;
    out.ctl_commitment_sourced_from_child_verifier =
        false;
    out.recursively_consumed = false;
    out.residuals = {
        "batch_codec_word_to_parsed_field_decoder_and_equality_map",
        "all_parsed_fields_to_hash_fold_deep_verifier_chip_outputs",
        "sha256d_air_quotient_and_fri_fiat_shamir_replay",
        "normalized_ctl_child_verifier_and_terminal_commitment_bus",
    };
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations =
        composition.violations;
    out.valid =
        out.added_columns ==
            kNormalizedAlgAirProofFieldBusRate +
            2 + ar::kPermCellsPerPerm &&
        out.added_constraints ==
            ar::kPermSboxCells +
            2 + 1 + ah::kAlgHashT +
            ah::kAlgHashT + 4 + 4 &&
        out.exact_codec_bytes_bound &&
        out.all_supplemental_fields_bound &&
        out.row_fold_ood_deep_query_path_fields_present &&
        out.proof_commitment_derived_in_parent &&
        out.proof_commitment_semantic_lanes_linked &&
        !out.proof_fields_sourced_from_verifier_chips &&
        !out.complete_fiat_shamir_replay_in_parent &&
        !out.ctl_commitment_sourced_from_child_verifier &&
        !out.recursively_consumed &&
        out.residuals.size() == 4 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_all_proof_field_bus_ok;"
          "codec_and_supplemental_fields_committed;"
          "semantic_proof_commitment_lanes_linked;"
          "field_decoder_fs_and_ctl_child_residuals_open;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_all_proof_field_bus_invalid";
    return out;
}

bool ValidateNormalizedAlgAirProofFieldBusV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const NormalizedAlgAirProofFieldBusAttachmentV1& attachment,
    std::string* why)
{
    std::vector<gf::Fp> transcript;
    uint32_t codec_bytes = 0;
    uint32_t codec_words = 0;
    uint32_t supplemental = 0;
    if (!attachment.valid ||
        attachment.version !=
            kNormalizedAlgAirProofFieldBusVersion ||
        !semantic_sponge.valid ||
        !BuildNormalizedAlgAirProofFieldTranscriptV1(
            proof, transcript,
            &codec_bytes, &codec_words,
            &supplemental, why) ||
        attachment.proof_commitment !=
            ComputeNormalizedAlgAirProofCommitment(
                proof) ||
        attachment.proof_commitment !=
            slot.child_proof_commitment ||
        attachment.transcript_fields !=
            transcript.size() ||
        attachment.batch_codec_bytes !=
            codec_bytes ||
        attachment.batch_codec_words !=
            codec_words ||
        attachment.supplemental_fields !=
            supplemental ||
        attachment.active_sponge_rows !=
            transcript.size() /
                kNormalizedAlgAirProofFieldBusRate +
            1 ||
        attachment.parent_rows !=
            composition.combined.n_rows ||
        attachment.added_columns != 140 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.added_constraints != 153 ||
        !attachment.exact_codec_bytes_bound ||
        !attachment.all_supplemental_fields_bound ||
        !attachment.
            row_fold_ood_deep_query_path_fields_present ||
        !attachment.proof_commitment_derived_in_parent ||
        !attachment.
            proof_commitment_semantic_lanes_linked ||
        attachment.proof_fields_sourced_from_verifier_chips ||
        attachment.complete_fiat_shamir_replay_in_parent ||
        attachment.ctl_commitment_sourced_from_child_verifier ||
        attachment.recursively_consumed ||
        attachment.residuals.size() != 4) {
        return Fail(
            why,
            "normalized_proof_field_bus_shape");
    }

    std::vector<gf::Fp> padded =
        transcript;
    padded.push_back(gf::Fp{1});
    while (padded.size() %
               kNormalizedAlgAirProofFieldBusRate !=
           0) {
        padded.push_back(gf::Fp{0});
    }
    std::array<
        const std::vector<Fp3>*,
        kNormalizedAlgAirProofFieldBusRate + 2>
        public_columns{};
    for (uint32_t lane = 0;
         lane <
             kNormalizedAlgAirProofFieldBusRate;
         ++lane) {
        const uint32_t column =
            attachment.layout.Field(lane);
        const auto pin = std::find_if(
            composition.combined.preprocessed.begin(),
            composition.combined.preprocessed.end(),
            [column](const auto& item) {
                return item.first == column;
            });
        if (pin ==
                composition.combined.preprocessed.end() ||
            pin->second.size() !=
                composition.combined.n_rows) {
            return Fail(
                why,
                "normalized_proof_field_bus_preprocessed");
        }
        public_columns[lane] =
            &pin->second;
    }
    const std::array<uint32_t, 2> selectors{
        attachment.layout.active,
        attachment.layout.terminal};
    for (uint32_t index = 0;
         index < selectors.size(); ++index) {
        const uint32_t column =
            selectors[index];
        const auto pin = std::find_if(
            composition.combined.preprocessed.begin(),
            composition.combined.preprocessed.end(),
            [column](const auto& item) {
                return item.first == column;
            });
        if (pin ==
                composition.combined.preprocessed.end() ||
            pin->second.size() !=
                composition.combined.n_rows) {
            return Fail(
                why,
                "normalized_proof_field_bus_preprocessed");
        }
        public_columns[
            kNormalizedAlgAirProofFieldBusRate +
            index] =
                &pin->second;
    }
    for (uint32_t row = 0;
         row < composition.combined.n_rows;
         ++row) {
        const bool active =
            row < attachment.active_sponge_rows;
        const bool terminal =
            active &&
            row + 1 ==
                attachment.active_sponge_rows;
        if (!gf::Eq(
                composition.columns[
                    attachment.layout.active][row],
                active
                    ? Fp3::One()
                    : Fp3::Zero()) ||
            !gf::Eq(
                (*public_columns[
                    kNormalizedAlgAirProofFieldBusRate])
                    [row],
                active
                    ? Fp3::One()
                    : Fp3::Zero()) ||
            !gf::Eq(
                composition.columns[
                    attachment.layout.terminal][row],
                terminal
                    ? Fp3::One()
                    : Fp3::Zero()) ||
            !gf::Eq(
                (*public_columns[
                    kNormalizedAlgAirProofFieldBusRate +
                    1])[row],
                terminal
                    ? Fp3::One()
                    : Fp3::Zero())) {
            return Fail(
                why,
                "normalized_proof_field_bus_schedule");
        }
        for (uint32_t lane = 0;
             lane <
                 kNormalizedAlgAirProofFieldBusRate;
             ++lane) {
            const gf::Fp expected =
                active
                ? padded[
                      uint64_t{row} *
                          kNormalizedAlgAirProofFieldBusRate +
                      lane]
                : gf::Fp{0};
            if (!gf::Eq(
                    composition.columns[
                        attachment.layout.Field(lane)]
                        [row],
                    Fp3::FromFp(expected)) ||
                !gf::Eq(
                    (*public_columns[lane])[row],
                    Fp3::FromFp(expected))) {
                return Fail(
                    why,
                    "normalized_proof_field_bus_value");
            }
        }
    }
    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0 ||
        attachment.violations != 0) {
        return Fail(
            why,
            "normalized_proof_field_bus_air");
    }
    return true;
}

namespace {

std::optional<Fri3AlgBatchProof>
DeserializeNormalizedAlgAirBatchCodecV1(
    const Fri3AlgBatchProof& proof,
    const std::vector<unsigned char>& encoded)
{
    if (proof.version ==
            kRCFri3AlgSafeQ192K2ProofVersionV13) {
        return
            DeserializeFri3AlgSafeQ192K2V13BatchProof(
                encoded);
    }
    if (proof.version ==
            kRCFri3AlgP2Q192K2ProofVersionV10) {
        return
            DeserializeFri3AlgP2Q192K2V10BatchProof(
                encoded);
    }
    if (proof.version !=
            kRCFri3AlgActiveBatchProofVersion) {
        return std::nullopt;
    }
    return DeserializeFri3AlgBatchProof(encoded);
}

} // namespace

bool ValidateNormalizedAlgAirBatchCodecBytesV1(
    const Fri3AlgBatchProof& proof,
    const std::vector<unsigned char>& encoded,
    std::string* why)
{
    std::vector<unsigned char> expected;
    if (SerializeFri3AlgBatchProof(
            proof, expected) == 0 ||
        expected != encoded) {
        return Fail(
            why,
            "normalized_batch_codec_not_exact_proof_encoding");
    }
    const auto decoded =
        DeserializeNormalizedAlgAirBatchCodecV1(
            proof, encoded);
    if (!decoded.has_value()) {
        return Fail(
            why,
            "normalized_batch_codec_parse");
    }
    std::vector<unsigned char> roundtrip;
    if (SerializeFri3AlgBatchProof(
            *decoded, roundtrip) != encoded.size() ||
        roundtrip != encoded) {
        return Fail(
            why,
            "normalized_batch_codec_noncanonical_or_trailing");
    }
    return true;
}

bool BuildNormalizedAlgAirBatchCodecMapV1(
    const Fri3AlgBatchProof& proof,
    NormalizedAlgAirBatchCodecMapV1& out,
    std::string* why)
{
    out = {};
    std::vector<unsigned char> encoded;
    if (SerializeFri3AlgBatchProof(
            proof, encoded) == 0 ||
        encoded.size() >
            std::numeric_limits<uint32_t>::max() ||
        (encoded.size() % 4) != 0 ||
        !ValidateNormalizedAlgAirBatchCodecBytesV1(
            proof, encoded, why)) {
        return false;
    }
    const auto decoded =
        DeserializeNormalizedAlgAirBatchCodecV1(
            proof, encoded);
    if (!decoded.has_value()) {
        return Fail(
            why,
            "normalized_batch_codec_map_parse");
    }

    out.codec_bytes =
        static_cast<uint32_t>(encoded.size());
    out.codec_words =
        static_cast<uint32_t>(encoded.size() / 4);
    out.entries.reserve(out.codec_words);
    uint32_t cursor = 0;
    uint32_t semantic = 0;
    const auto append_word =
        [&](NormalizedAlgAirCodecWordKind kind,
            uint32_t ordinal, bool consumed) {
            if (cursor >
                out.codec_bytes - 4) {
                return false;
            }
            const uint32_t value =
                uint32_t{encoded[cursor]} |
                (uint32_t{encoded[cursor + 1]} << 8) |
                (uint32_t{encoded[cursor + 2]} << 16) |
                (uint32_t{encoded[cursor + 3]} << 24);
            out.entries.push_back({
                static_cast<uint32_t>(
                    out.entries.size()),
                cursor,
                value,
                ordinal,
                kind,
                consumed,
            });
            cursor += 4;
            out.chip_consumed_words +=
                consumed ? 1 : 0;
            return true;
        };
    const auto append_u32 =
        [&](bool consumed) {
            const uint32_t ordinal = semantic++;
            return append_word(
                NormalizedAlgAirCodecWordKind::U32,
                ordinal, consumed);
        };
    const auto append_u64 =
        [&](bool consumed) {
            const uint32_t ordinal = semantic++;
            return
                append_word(
                    NormalizedAlgAirCodecWordKind::U64Low,
                    ordinal, consumed) &&
                append_word(
                    NormalizedAlgAirCodecWordKind::U64High,
                    ordinal, consumed);
        };
    const auto append_fp =
        [&](bool consumed) {
            const uint32_t ordinal = semantic++;
            if (!append_word(
                    NormalizedAlgAirCodecWordKind::FpLow,
                    ordinal, consumed) ||
                !append_word(
                    NormalizedAlgAirCodecWordKind::FpHigh,
                    ordinal, consumed)) {
                return false;
            }
            ++out.fp_elements;
            return true;
        };
    const auto append_fp3 =
        [&](bool consumed) {
            return append_fp(consumed) &&
                append_fp(consumed) &&
                append_fp(consumed);
        };
    const auto append_digest =
        [&](bool consumed) {
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen;
                 ++limb) {
                if (!append_fp(consumed)) {
                    return false;
                }
            }
            return true;
        };
    const auto& batch = *decoded;
    // Magic/version and the PoW nonce are codec binding, not outputs of the
    // currently executable hash/fold/DEEP chips. All remaining words affect
    // an existing verifier schedule, public scalar, opening or path.
    if (!append_u32(false) ||
        !append_u32(false) ||
        !append_u64(false) ||
        !append_u32(true) ||
        !append_u32(true) ||
        !append_digest(true) ||
        !append_u32(true) ||
        !append_u32(true)) {
        return Fail(why, "normalized_batch_codec_map_header");
    }
    for (size_t i = 0;
         i < batch.column_len.size(); ++i) {
        if (!append_u32(true)) {
            return Fail(why, "normalized_batch_codec_map_column_len");
        }
    }
    if (!append_fp3(true) ||
        !append_fp3(true) ||
        !append_fp3(true) ||
        !append_u32(true)) {
        return Fail(why, "normalized_batch_codec_map_challenge");
    }
    for (size_t i = 0;
         i < batch.evals_z1.size(); ++i) {
        if (!append_fp3(true)) {
            return Fail(why, "normalized_batch_codec_map_eval_z1");
        }
    }
    if (!append_u32(true)) {
        return Fail(why, "normalized_batch_codec_map_eval_z2_count");
    }
    for (size_t i = 0;
         i < batch.evals_z2.size(); ++i) {
        if (!append_fp3(true)) {
            return Fail(why, "normalized_batch_codec_map_eval_z2");
        }
    }
    if (!append_fp3(true) ||
        !append_fp3(true) ||
        !append_u32(true)) {
        return Fail(why, "normalized_batch_codec_map_deep");
    }
    for (size_t layer = 0;
         layer < batch.fold_layers.size(); ++layer) {
        const bool hash_opening_owned =
            layer < batch.fold_challenges.size();
        if (!append_digest(hash_opening_owned) ||
            !append_u32(true)) {
            return Fail(why, "normalized_batch_codec_map_fold_layer");
        }
    }
    if (!append_fp3(true) ||
        !append_u32(true)) {
        return Fail(why, "normalized_batch_codec_map_final");
    }
    for (size_t i = 0;
         i < batch.fold_challenges.size(); ++i) {
        if (!append_fp3(true)) {
            return Fail(why, "normalized_batch_codec_map_fold_challenge");
        }
    }
    if (!append_u32(true)) {
        return Fail(why, "normalized_batch_codec_map_query_count");
    }
    for (const auto& query : batch.queries) {
        if (!append_u32(true) ||
            !append_u32(true)) {
            return Fail(why, "normalized_batch_codec_map_query");
        }
        for (size_t i = 0;
             i < query.row.values.size(); ++i) {
            if (!append_fp3(true)) {
                return Fail(why, "normalized_batch_codec_map_row_value");
            }
        }
        if (!append_u32(true)) {
            return Fail(why, "normalized_batch_codec_map_row_path_count");
        }
        for (size_t i = 0;
             i < query.row.siblings.size(); ++i) {
            if (!append_digest(true)) {
                return Fail(why, "normalized_batch_codec_map_row_path");
            }
        }
        if (!append_u32(true)) {
            return Fail(why, "normalized_batch_codec_map_step_count");
        }
        for (const auto& step : query.steps) {
            if (!append_u32(true) ||
                !append_u32(true) ||
                !append_fp3(true) ||
                !append_fp3(true) ||
                !append_u32(true)) {
                return Fail(why, "normalized_batch_codec_map_step");
            }
            for (size_t i = 0;
                 i < step.even_siblings.size(); ++i) {
                if (!append_digest(true)) {
                    return Fail(why, "normalized_batch_codec_map_even_path");
                }
            }
            if (!append_u32(true)) {
                return Fail(why, "normalized_batch_codec_map_odd_count");
            }
            for (size_t i = 0;
                 i < step.odd_siblings.size(); ++i) {
                if (!append_digest(true)) {
                    return Fail(why, "normalized_batch_codec_map_odd_path");
                }
            }
        }
    }

    // A second, lossless semantic view groups the three base-field limbs of
    // each Fp3 value into the extension element consumed by the verifier
    // chips. This is the granularity required for literal same-row aliases:
    // an Fp3 witness cell cannot soundly be projected to c0/c1/c2 by an Fp3
    // AIR constraint, while reconstructing c0+u*c1+u^2*c2 is native.
    uint32_t token_word = 0;
    uint32_t token_address = 1;
    const auto token_u32 =
        [&](NormalizedAlgAirCodecOwnerFamily owner,
            bool consumed) {
            if (token_word >= out.entries.size()) {
                return false;
            }
            out.semantic_tokens.push_back({
                token_address++,
                token_word,
                Fp3::FromFp(gf::FromU64(
                    out.entries[token_word].value)),
                NormalizedAlgAirCodecTokenKind::U32,
                owner,
                consumed,
            });
            ++token_word;
            return true;
        };
    const auto token_u64 =
        [&]() {
            if (token_word + 1 >=
                    out.entries.size()) {
                return false;
            }
            token_word += 2;
            return true;
        };
    const auto read_fp =
        [&](uint32_t word,
            gf::Fp& value) {
            if (word + 1 >= out.entries.size() ||
                out.entries[word].kind !=
                    NormalizedAlgAirCodecWordKind::FpLow ||
                out.entries[word + 1].kind !=
                    NormalizedAlgAirCodecWordKind::FpHigh) {
                return false;
            }
            const uint64_t raw =
                uint64_t{out.entries[word].value} |
                (uint64_t{
                     out.entries[word + 1].value}
                 << 32);
            if (raw >= gf::kP) {
                return false;
            }
            value = raw;
            return true;
        };
    const auto token_fp =
        [&](NormalizedAlgAirCodecOwnerFamily owner,
            bool consumed) {
            gf::Fp value = 0;
            if (!read_fp(token_word, value)) {
                return false;
            }
            out.semantic_tokens.push_back({
                token_address++,
                token_word,
                Fp3::FromFp(value),
                NormalizedAlgAirCodecTokenKind::Fp,
                owner,
                consumed,
            });
            token_word += 2;
            return true;
        };
    const auto token_fp3 =
        [&](NormalizedAlgAirCodecOwnerFamily owner,
            bool consumed) {
            gf::Fp c0 = 0;
            gf::Fp c1 = 0;
            gf::Fp c2 = 0;
            if (!read_fp(token_word, c0) ||
                !read_fp(token_word + 2, c1) ||
                !read_fp(token_word + 4, c2)) {
                return false;
            }
            out.semantic_tokens.push_back({
                token_address++,
                token_word,
                Fp3{c0, c1, c2},
                NormalizedAlgAirCodecTokenKind::Fp3,
                owner,
                consumed,
            });
            token_word += 6;
            return true;
        };
    const auto token_digest =
        [&](NormalizedAlgAirCodecOwnerFamily owner,
            bool consumed) {
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen;
                 ++limb) {
                if (!token_fp(owner, consumed)) {
                    return false;
                }
            }
            return true;
        };
    using Owner = NormalizedAlgAirCodecOwnerFamily;
    if (!token_u32(Owner::None, false) ||
        !token_u32(Owner::None, false) ||
        !token_u64() ||
        !token_u32(Owner::Scheduler, true) ||
        !token_u32(Owner::Scheduler, true) ||
        !token_digest(Owner::HashOpening, true) ||
        !token_u32(Owner::Scheduler, true) ||
        !token_u32(Owner::Scheduler, true)) {
        return Fail(why, "normalized_batch_codec_token_header");
    }
    for (size_t i = 0;
         i < batch.column_len.size(); ++i) {
        if (!token_u32(Owner::Deep, true)) {
            return Fail(why, "normalized_batch_codec_token_column_len");
        }
    }
    if (!token_fp3(Owner::Deep, true) ||
        !token_fp3(Owner::Deep, true) ||
        !token_fp3(Owner::Deep, true) ||
        !token_u32(Owner::Scheduler, true)) {
        return Fail(why, "normalized_batch_codec_token_challenge");
    }
    for (size_t i = 0;
         i < batch.evals_z1.size(); ++i) {
        if (!token_fp3(Owner::Deep, true)) {
            return Fail(why, "normalized_batch_codec_token_eval_z1");
        }
    }
    if (!token_u32(Owner::Scheduler, true)) {
        return Fail(why, "normalized_batch_codec_token_eval_z2_count");
    }
    for (size_t i = 0;
         i < batch.evals_z2.size(); ++i) {
        if (!token_fp3(Owner::Deep, true)) {
            return Fail(why, "normalized_batch_codec_token_eval_z2");
        }
    }
    if (!token_fp3(Owner::Deep, true) ||
        !token_fp3(Owner::Deep, true) ||
        !token_u32(Owner::Scheduler, true)) {
        return Fail(why, "normalized_batch_codec_token_deep");
    }
    for (size_t i = 0;
         i < batch.fold_layers.size(); ++i) {
        // The terminal constant layer (index == fold_challenges.size()) is
        // absorbed into Fiat-Shamir and checked via final_value; it is NOT
        // one of the n_folds hash-opening expected roots (see
        // air_recurse ChildPublicInputs::fold_roots). Mark it unconsumed so
        // remote-export does not demand a parent chip source for it.
        const bool hash_opening_owned =
            i < batch.fold_challenges.size();
        if (!token_digest(
                Owner::HashOpening, hash_opening_owned) ||
            !token_u32(Owner::Scheduler, true)) {
            return Fail(why, "normalized_batch_codec_token_fold_layer");
        }
    }
    if (!token_fp3(Owner::Fold, true) ||
        !token_u32(Owner::Scheduler, true)) {
        return Fail(why, "normalized_batch_codec_token_final");
    }
    for (size_t i = 0;
         i < batch.fold_challenges.size(); ++i) {
        if (!token_fp3(Owner::Fold, true)) {
            return Fail(why, "normalized_batch_codec_token_fold_challenge");
        }
    }
    if (!token_u32(Owner::Scheduler, true)) {
        return Fail(why, "normalized_batch_codec_token_query_count");
    }
    for (const auto& query : batch.queries) {
        if (!token_u32(Owner::HashOpening, true) ||
            !token_u32(Owner::Scheduler, true)) {
            return Fail(why, "normalized_batch_codec_token_query");
        }
        for (size_t i = 0;
             i < query.row.values.size(); ++i) {
            if (!token_fp3(Owner::HashOpening, true)) {
                return Fail(why, "normalized_batch_codec_token_row_value");
            }
        }
        if (!token_u32(Owner::Scheduler, true)) {
            return Fail(why, "normalized_batch_codec_token_row_path_count");
        }
        for (size_t i = 0;
             i < query.row.siblings.size(); ++i) {
            if (!token_digest(Owner::HashOpening, true)) {
                return Fail(why, "normalized_batch_codec_token_row_path");
            }
        }
        if (!token_u32(Owner::Scheduler, true)) {
            return Fail(why, "normalized_batch_codec_token_step_count");
        }
        for (const auto& step : query.steps) {
            if (!token_u32(Owner::Fold, true) ||
                !token_u32(Owner::Fold, true) ||
                !token_fp3(Owner::Fold, true) ||
                !token_fp3(Owner::Fold, true) ||
                !token_u32(Owner::Scheduler, true)) {
                return Fail(why, "normalized_batch_codec_token_step");
            }
            for (size_t i = 0;
                 i < step.even_siblings.size(); ++i) {
                if (!token_digest(Owner::HashOpening, true)) {
                    return Fail(why, "normalized_batch_codec_token_even_path");
                }
            }
            if (!token_u32(Owner::Scheduler, true)) {
                return Fail(why, "normalized_batch_codec_token_odd_count");
            }
            for (size_t i = 0;
                 i < step.odd_siblings.size(); ++i) {
                if (!token_digest(Owner::HashOpening, true)) {
                    return Fail(why, "normalized_batch_codec_token_odd_path");
                }
            }
        }
    }

    out.exact_dense_coverage =
        cursor == out.codec_bytes &&
        out.entries.size() == out.codec_words &&
        token_word == out.codec_words &&
        !out.semantic_tokens.empty();
    out.exact_little_endian = true;
    out.canonical_roundtrip = true;
    out.no_trailing_bytes = true;
    out.valid =
        out.exact_dense_coverage &&
        out.exact_little_endian &&
        out.canonical_roundtrip &&
        out.no_trailing_bytes &&
        out.codec_words != 0 &&
        out.fp_elements != 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_batch_codec_dense_canonical_map_ok"
        : "stage3:recursive_fixedpoint:"
          "normalized_batch_codec_dense_map_invalid";
    if (!out.valid) {
        return Fail(
            why,
            "normalized_batch_codec_dense_map");
    }
    return true;
}

NormalizedSemanticAlgHashParentAudit
PromoteNormalizedSemanticProofCommitmentFromFieldBusV1(
    const NormalizedSemanticAlgHashParentAudit& base,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedRoleChildSlot& slot)
{
    NormalizedSemanticAlgHashParentAudit out = base;
    const bool closable =
        proof_bus.valid &&
        proof_bus.proof_commitment_derived_in_parent &&
        proof_bus.proof_commitment_semantic_lanes_linked &&
        !proof_bus.proof_commitment.IsNull() &&
        proof_bus.proof_commitment ==
            slot.child_proof_commitment &&
        !out.child_proof_commitment_mapped;
    if (!closable) {
        return out;
    }

    out.child_proof_commitment_mapped = true;
    out.proof_authenticated_lanes = 0;
    out.missing_proof_bus_lanes = 0;
    out.verifier_constant_lanes = 0;
    for (auto& field : out.fields) {
        if (field.field == "child_proof_commitment_u32") {
            field.source =
                NormalizedAlgHashInputSource::ProofAuthenticated;
            field.all_lanes_bound = true;
            field.detail =
                "ProofFieldBus derives commitment from ordered transcript "
                "and links eight u32 semantic sponge lanes";
        }
        if (field.source ==
            NormalizedAlgHashInputSource::VerifierConstant) {
            out.verifier_constant_lanes += field.input_lanes;
        } else if (
            field.source ==
                NormalizedAlgHashInputSource::ProofAuthenticated &&
            field.all_lanes_bound) {
            out.proof_authenticated_lanes += field.input_lanes;
        } else {
            out.missing_proof_bus_lanes += field.input_lanes;
        }
    }
    out.in_parent_derivation_complete =
        out.canonical_alg_hash_available &&
        out.slot_binding_valid &&
        out.child_trace_root_mapped &&
        out.child_proof_commitment_mapped &&
        out.terminal_bus_commitment_mapped &&
        out.missing_proof_bus_lanes == 0;
    out.blocker =
        out.in_parent_derivation_complete
            ? "stage3:recursive_fixedpoint:"
              "normalized_semantic_alg_hash_parent_complete"
            : "stage3:recursive_fixedpoint:"
              "normalized_semantic_alg_hash_blocked:"
              "8_terminal_bus_commitment_lanes_have_no_"
              "proof_authenticated_parent_source;"
              "proof_commitment_bus_closed_via_proof_field_bus";
    return out;
}

NormalizedTerminalBusCommitmentBusAttachmentV1
AttachNormalizedTerminalBusCommitmentBusV1(
    FoldBusComposition& composition,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge)
{
    NormalizedTerminalBusCommitmentBusAttachmentV1 out;
    out.layout =
        NormalizedAlgAirProofFieldBusLayout(
            composition.combined.n_columns);
    out.parent_rows = composition.combined.n_rows;
    out.added_columns =
        out.layout.End() - out.layout.field_base;
    out.constraint_base = static_cast<uint32_t>(
        composition.combined.constraints.size());

    std::vector<gf::Fp> transcript;
    if (!BuildNormalizedTerminalBusFieldTranscriptV1(
            manifest, pins, child_index, schedule,
            transcript, nullptr)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_terminal_bus_transcript";
        return out;
    }
    out.transcript_fields =
        static_cast<uint32_t>(transcript.size());
    out.active_sponge_rows =
        static_cast<uint32_t>(
            transcript.size() /
                kNormalizedAlgAirProofFieldBusRate +
            1);
    out.terminal_bus_commitment =
        aq::AirFriBackendAlg<Fp3>::PackDigest(
            ah::SpongeHashFp(transcript));
    const auto expected_root =
        aq::AirFriBackendAlg<Fp3>::UnpackDigest(
            slot.terminal_bus_commitment);
    if (!composition.valid ||
        !semantic_sponge.valid ||
        out.parent_rows < 2 ||
        out.active_sponge_rows > out.parent_rows ||
        out.terminal_bus_commitment.IsNull() ||
        out.terminal_bus_commitment !=
            slot.terminal_bus_commitment ||
        out.terminal_bus_commitment !=
            ComputeNormalizedTerminalBusCommitment(
                manifest, pins, child_index, schedule) ||
        !expected_root.has_value()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_terminal_bus_public_binding";
        return out;
    }

    std::vector<gf::Fp> padded = transcript;
    padded.push_back(gf::Fp{1});
    while (padded.size() %
               kNormalizedAlgAirProofFieldBusRate != 0) {
        padded.push_back(gf::Fp{0});
    }
    if (padded.size() !=
        uint64_t{out.active_sponge_rows} *
            kNormalizedAlgAirProofFieldBusRate) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_terminal_bus_padding";
        return out;
    }

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns = out.layout.End();
    composition.combined.preprocessed_pin_ood = true;
    for (uint32_t row = 0; row < out.active_sponge_rows; ++row) {
        for (uint32_t lane = 0;
             lane < kNormalizedAlgAirProofFieldBusRate; ++lane) {
            composition.columns[out.layout.Field(lane)][row] =
                Fp3::FromFp(padded[
                    uint64_t{row} *
                        kNormalizedAlgAirProofFieldBusRate +
                    lane]);
        }
        composition.columns[out.layout.active][row] = Fp3::One();
    }
    composition.columns[out.layout.terminal]
        [out.active_sponge_rows - 1] = Fp3::One();
    for (uint32_t lane = 0;
         lane < kNormalizedAlgAirProofFieldBusRate; ++lane) {
        composition.combined.preprocessed.emplace_back(
            out.layout.Field(lane),
            composition.columns[out.layout.Field(lane)]);
    }
    composition.combined.preprocessed.emplace_back(
        out.layout.active,
        composition.columns[out.layout.active]);
    composition.combined.preprocessed.emplace_back(
        out.layout.terminal,
        composition.columns[out.layout.terminal]);

    ah::State state{};
    for (uint32_t row = 0; row < out.parent_rows; ++row) {
        ah::State input{};
        if (row < out.active_sponge_rows) {
            input = state;
            for (uint32_t lane = 0;
                 lane < kNormalizedAlgAirProofFieldBusRate; ++lane) {
                input[lane] = gf::Add(
                    input[lane],
                    composition.columns[out.layout.Field(lane)][row].c0);
            }
        }
        const ar::PermWitness witness = ar::BuildPermWitness(input);
        for (uint32_t cell = 0; cell < ar::kPermCellsPerPerm; ++cell) {
            composition.columns[
                out.layout.permutation.base + cell][row] =
                Fp3::FromFp(witness.cells[cell]);
        }
        if (row < out.active_sponge_rows) {
            state = witness.output;
        }
    }

    const auto append = [&](aq::AirConstraint<Fp3> constraint) {
        composition.combined.constraints.push_back(std::move(constraint));
    };
    for (auto& constraint :
         ar::BuildPermRoundConstraints(out.layout.permutation)) {
        append(std::move(constraint));
    }
    for (const uint32_t selector :
         std::array<uint32_t, 2>{out.layout.active, out.layout.terminal}) {
        aq::AirConstraint<Fp3> boolean;
        boolean.name =
            "stage3.fixedpoint.normalized_terminal_bus.selector_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval = [selector](
                           const std::vector<Fp3>& row,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                row[selector],
                gf::Sub(row[selector], Fp3::One()));
        };
        append(std::move(boolean));
    }
    {
        aq::AirConstraint<Fp3> terminal_active;
        terminal_active.name =
            "stage3.fixedpoint.normalized_terminal_bus.terminal_implies_active";
        terminal_active.kind = aq::AirKind::kEverywhere;
        terminal_active.alg_degree = 2;
        const uint32_t active = out.layout.active;
        const uint32_t terminal = out.layout.terminal;
        terminal_active.eval = [active, terminal](
                                   const std::vector<Fp3>& row,
                                   const std::vector<Fp3>&) {
            return gf::Mul(
                row[terminal],
                gf::Sub(Fp3::One(), row[active]));
        };
        append(std::move(terminal_active));
    }
    for (uint32_t lane = 0; lane < ah::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> first;
        first.name =
            "stage3.fixedpoint.normalized_terminal_bus.first_input";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        const uint32_t input_column =
            out.layout.permutation.InputCol(lane);
        if (lane < kNormalizedAlgAirProofFieldBusRate) {
            const uint32_t field = out.layout.Field(lane);
            first.eval = [input_column, field](
                             const std::vector<Fp3>& row,
                             const std::vector<Fp3>&) {
                return gf::Sub(row[input_column], row[field]);
            };
        } else {
            first.eval = [input_column](
                             const std::vector<Fp3>& row,
                             const std::vector<Fp3>&) {
                return row[input_column];
            };
        }
        append(std::move(first));
    }
    for (uint32_t lane = 0; lane < ah::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> transition;
        transition.name =
            "stage3.fixedpoint.normalized_terminal_bus.sponge_transition";
        transition.kind = aq::AirKind::kTransition;
        transition.alg_degree = 2;
        const uint32_t input_column =
            out.layout.permutation.InputCol(lane);
        const uint32_t active = out.layout.active;
        const ar::PermLayout permutation = out.layout.permutation;
        if (lane < kNormalizedAlgAirProofFieldBusRate) {
            const uint32_t field = out.layout.Field(lane);
            transition.eval = [input_column, active, permutation, lane,
                               field](
                                  const std::vector<Fp3>& row,
                                  const std::vector<Fp3>& next) {
                return gf::Mul(
                    next[active],
                    gf::Sub(
                        next[input_column],
                        gf::Add(
                            ar::PermOutputLane(permutation, row, lane),
                            next[field])));
            };
        } else {
            transition.eval = [input_column, active, permutation, lane](
                                  const std::vector<Fp3>& row,
                                  const std::vector<Fp3>& next) {
                return gf::Mul(
                    next[active],
                    gf::Sub(
                        next[input_column],
                        ar::PermOutputLane(permutation, row, lane)));
            };
        }
        append(std::move(transition));
    }

    constexpr gf::Fp TWO32 = UINT64_C(1) << 32;
    for (uint32_t limb = 0; limb < ah::kAlgHashDigestLen; ++limb) {
        aq::AirConstraint<Fp3> root;
        root.name =
            "stage3.fixedpoint.normalized_terminal_bus.output_root";
        root.kind = aq::AirKind::kEverywhere;
        root.alg_degree = 2;
        const uint32_t terminal = out.layout.terminal;
        const ar::PermLayout permutation = out.layout.permutation;
        const Fp3 expected = Fp3::FromFp((*expected_root)[limb]);
        root.eval = [terminal, permutation, limb, expected](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
            return gf::Mul(
                row[terminal],
                gf::Sub(
                    ar::PermOutputLane(permutation, row, limb),
                    expected));
        };
        append(std::move(root));

        aq::AirConstraint<Fp3> semantic;
        semantic.name =
            "stage3.fixedpoint.normalized_terminal_bus.semantic_u32_link";
        semantic.kind = aq::AirKind::kEverywhere;
        semantic.alg_degree = 2;
        const uint32_t low = semantic_sponge.layout.Input(40 + 2 * limb);
        const uint32_t high = semantic_sponge.layout.Input(41 + 2 * limb);
        semantic.eval = [terminal, permutation, limb, low, high](
                            const std::vector<Fp3>& row,
                            const std::vector<Fp3>&) {
            return gf::Mul(
                row[terminal],
                gf::Sub(
                    ar::PermOutputLane(permutation, row, limb),
                    gf::Add(
                        row[low],
                        gf::Mul(Fp3::FromFp(TWO32), row[high]))));
        };
        append(std::move(semantic));
    }

    out.added_constraints = static_cast<uint32_t>(
        composition.combined.constraints.size()) -
        out.constraint_base;
    out.terminal_bus_commitment_derived_in_parent = true;
    out.terminal_bus_semantic_lanes_linked = true;
    out.ctl_child_verified_in_parent_air = false;
    out.recursively_consumed = false;
    out.residuals = {
        "normalized_ctl_child_verifier_in_parent_air",
    };
    composition.violations = CountHashOpeningViolations(
        composition.combined, composition.columns);
    out.violations = composition.violations;
    out.valid =
        out.added_columns ==
            kNormalizedAlgAirProofFieldBusRate + 2 +
                ar::kPermCellsPerPerm &&
        out.added_constraints ==
            ar::kPermSboxCells + 2 + 1 + ah::kAlgHashT +
                ah::kAlgHashT + 4 + 4 &&
        out.terminal_bus_commitment_derived_in_parent &&
        out.terminal_bus_semantic_lanes_linked &&
        !out.ctl_child_verified_in_parent_air &&
        !out.recursively_consumed &&
        out.residuals.size() == 1 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_terminal_bus_commitment_bus_ok;"
          "semantic_terminal_lanes_linked;"
          "ctl_child_verifier_residual_open;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_terminal_bus_commitment_bus_invalid";
    return out;
}

bool ValidateNormalizedTerminalBusCommitmentBusV1(
    const FoldBusComposition& composition,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const NormalizedTerminalBusCommitmentBusAttachmentV1&
        attachment,
    std::string* why)
{
    std::vector<gf::Fp> transcript;
    if (!attachment.valid ||
        attachment.version !=
            kNormalizedTerminalBusCommitmentBusVersion ||
        !semantic_sponge.valid ||
        !BuildNormalizedTerminalBusFieldTranscriptV1(
            manifest, pins, child_index, schedule,
            transcript, why) ||
        attachment.terminal_bus_commitment !=
            ComputeNormalizedTerminalBusCommitment(
                manifest, pins, child_index, schedule) ||
        attachment.terminal_bus_commitment !=
            slot.terminal_bus_commitment ||
        attachment.transcript_fields != transcript.size() ||
        attachment.active_sponge_rows !=
            transcript.size() /
                    kNormalizedAlgAirProofFieldBusRate +
                1 ||
        attachment.parent_rows != composition.combined.n_rows ||
        attachment.added_columns != 140 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.added_constraints != 153 ||
        !attachment.terminal_bus_commitment_derived_in_parent ||
        !attachment.terminal_bus_semantic_lanes_linked ||
        attachment.ctl_child_verified_in_parent_air ||
        attachment.recursively_consumed ||
        attachment.residuals.size() != 1) {
        return Fail(why, "normalized_terminal_bus_shape");
    }
    return true;
}

NormalizedSemanticAlgHashParentAudit
PromoteNormalizedSemanticTerminalBusFromCommitmentBusV1(
    const NormalizedSemanticAlgHashParentAudit& base,
    const NormalizedTerminalBusCommitmentBusAttachmentV1&
        terminal_bus,
    const NormalizedRoleChildSlot& slot)
{
    NormalizedSemanticAlgHashParentAudit out = base;
    const bool closable =
        terminal_bus.valid &&
        terminal_bus.terminal_bus_commitment_derived_in_parent &&
        terminal_bus.terminal_bus_semantic_lanes_linked &&
        !terminal_bus.terminal_bus_commitment.IsNull() &&
        terminal_bus.terminal_bus_commitment ==
            slot.terminal_bus_commitment &&
        !out.terminal_bus_commitment_mapped;
    if (!closable) {
        return out;
    }

    out.terminal_bus_commitment_mapped = true;
    out.proof_authenticated_lanes = 0;
    out.missing_proof_bus_lanes = 0;
    out.verifier_constant_lanes = 0;
    for (auto& field : out.fields) {
        if (field.field == "terminal_bus_commitment_u32") {
            field.source =
                NormalizedAlgHashInputSource::ProofAuthenticated;
            field.all_lanes_bound = true;
            field.detail =
                "TerminalBusCommitmentBus derives commitment from CTL "
                "composition/child/schedule limbs and links eight u32 "
                "semantic sponge lanes";
        }
        if (field.source ==
            NormalizedAlgHashInputSource::VerifierConstant) {
            out.verifier_constant_lanes += field.input_lanes;
        } else if (
            field.source ==
                NormalizedAlgHashInputSource::ProofAuthenticated &&
            field.all_lanes_bound) {
            out.proof_authenticated_lanes += field.input_lanes;
        } else {
            out.missing_proof_bus_lanes += field.input_lanes;
        }
    }
    out.in_parent_derivation_complete =
        out.canonical_alg_hash_available &&
        out.slot_binding_valid &&
        out.child_trace_root_mapped &&
        out.child_proof_commitment_mapped &&
        out.terminal_bus_commitment_mapped &&
        out.missing_proof_bus_lanes == 0;
    out.blocker =
        out.in_parent_derivation_complete
            ? "stage3:recursive_fixedpoint:"
              "normalized_semantic_alg_hash_parent_complete;"
              "terminal_bus_closed_via_commitment_bus;"
              "ctl_child_verifier_still_host_only"
            : "stage3:recursive_fixedpoint:"
              "normalized_semantic_alg_hash_blocked_after_terminal_promote";
    return out;
}


NormalizedAlgAirCodecDecoderAttachmentV1
AttachNormalizedAlgAirCodecDecoderV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus)
{
    NormalizedAlgAirCodecDecoderAttachmentV1 out;
    out.layout =
        NormalizedAlgAirCodecDecoderLayout(
            composition.combined.n_columns);
    out.parent_rows =
        composition.combined.n_rows;
    out.added_columns =
        out.layout.End() - out.layout.base;
    out.constraint_base =
        static_cast<uint32_t>(
            composition.combined.constraints.size());
    if (!proof_bus.valid ||
        proof_bus.layout.End() != out.layout.base ||
        !BuildNormalizedAlgAirBatchCodecMapV1(
            proof.batch, out.map, nullptr) ||
        out.map.codec_bytes !=
            proof_bus.batch_codec_bytes ||
        out.map.codec_words !=
            proof_bus.batch_codec_words ||
        uint64_t{5} + out.map.codec_words >
            uint64_t{proof_bus.active_sponge_rows} *
                kNormalizedAlgAirProofFieldBusRate) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_batch_codec_decoder_shape";
        return out;
    }

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns =
        out.layout.End();
    composition.combined.preprocessed_pin_ood =
        true;

    std::array<std::vector<Fp3>,
               kNormalizedAlgAirCodecWordLanes>
        active;
    std::array<std::vector<Fp3>,
               kNormalizedAlgAirCodecWordLanes>
        fp_low;
    std::array<
        std::array<std::vector<Fp3>,
                   kNormalizedAlgAirCodecBytesPerWord>,
        kNormalizedAlgAirCodecWordLanes>
        valid_byte;
    for (uint32_t lane = 0;
         lane < kNormalizedAlgAirCodecWordLanes;
         ++lane) {
        active[lane].assign(
            out.parent_rows, Fp3::Zero());
        fp_low[lane].assign(
            out.parent_rows, Fp3::Zero());
        for (uint32_t byte = 0;
             byte <
                 kNormalizedAlgAirCodecBytesPerWord;
             ++byte) {
            valid_byte[lane][byte].assign(
                out.parent_rows, Fp3::Zero());
        }
    }

    constexpr uint32_t TRANSCRIPT_CODEC_BEGIN = 5;
    constexpr gf::Fp U32_MAX =
        UINT64_C(0xffffffff);
    for (uint32_t word = 0;
         word < out.map.codec_words; ++word) {
        const uint64_t position =
            uint64_t{TRANSCRIPT_CODEC_BEGIN} + word;
        const uint32_t row =
            static_cast<uint32_t>(
                position /
                    kNormalizedAlgAirCodecWordLanes);
        const uint32_t lane =
            static_cast<uint32_t>(
                position %
                    kNormalizedAlgAirCodecWordLanes);
        if (row >= out.parent_rows) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_batch_codec_decoder_rows";
            return out;
        }
        active[lane][row] = Fp3::One();
        ++out.active_word_slots;
        const auto& entry = out.map.entries[word];
        for (uint32_t byte = 0;
             byte <
                 kNormalizedAlgAirCodecBytesPerWord;
             ++byte) {
            const uint32_t offset = 4 * word + byte;
            if (offset < out.map.codec_bytes) {
                valid_byte[lane][byte][row] =
                    Fp3::One();
                ++out.valid_byte_slots;
            }
            const uint32_t value =
                (entry.value >> (8 * byte)) & 0xff;
            composition.columns[
                out.layout.Byte(lane, byte)][row] =
                    Fp3::FromFp(gf::FromU64(value));
            for (uint32_t bit = 0;
                 bit <
                     kNormalizedAlgAirCodecBitsPerByte;
                 ++bit) {
                composition.columns[
                    out.layout.Bit(
                        lane, byte, bit)][row] =
                    Fp3::FromFp(gf::FromU64(
                        (value >> bit) & 1u));
            }
        }
        if (entry.kind ==
                NormalizedAlgAirCodecWordKind::FpLow) {
            if (word + 1 >= out.map.entries.size() ||
                out.map.entries[word + 1].kind !=
                    NormalizedAlgAirCodecWordKind::FpHigh) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "normalized_batch_codec_decoder_fp_pair";
                return out;
            }
            fp_low[lane][row] = Fp3::One();
            ++out.canonical_fp_elements;
            const uint32_t high =
                out.map.entries[word + 1].value;
            const gf::Fp delta =
                gf::Sub(
                    U32_MAX,
                    gf::FromU64(high));
            const bool is_max = high == UINT32_MAX;
            composition.columns[
                out.layout.HighIsMax(lane)][row] =
                    is_max
                    ? Fp3::One()
                    : Fp3::Zero();
            composition.columns[
                out.layout.HighDeltaInverse(lane)]
                [row] =
                    is_max
                    ? Fp3::Zero()
                    : Fp3::FromFp(gf::Inv(delta));
        }
    }
    if (out.active_word_slots !=
            out.map.codec_words ||
        out.valid_byte_slots !=
            out.map.codec_bytes ||
        out.canonical_fp_elements !=
            out.map.fp_elements) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_batch_codec_decoder_inventory";
        return out;
    }

    for (uint32_t lane = 0;
         lane < kNormalizedAlgAirCodecWordLanes;
         ++lane) {
        composition.columns[
            out.layout.Active(lane)] =
                active[lane];
        composition.columns[
            out.layout.FpLow(lane)] =
                fp_low[lane];
        composition.combined.preprocessed.emplace_back(
            out.layout.Active(lane),
            std::move(active[lane]));
        composition.combined.preprocessed.emplace_back(
            out.layout.FpLow(lane),
            std::move(fp_low[lane]));
        for (uint32_t byte = 0;
             byte <
                 kNormalizedAlgAirCodecBytesPerWord;
             ++byte) {
            composition.columns[
                out.layout.ValidByte(lane, byte)] =
                    valid_byte[lane][byte];
            composition.combined.preprocessed.emplace_back(
                out.layout.ValidByte(lane, byte),
                std::move(valid_byte[lane][byte]));
        }
    }

    const auto append =
        [&](aq::AirConstraint<Fp3> constraint) {
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t lane = 0;
         lane < kNormalizedAlgAirCodecWordLanes;
         ++lane) {
        for (uint32_t byte = 0;
             byte <
                 kNormalizedAlgAirCodecBytesPerWord;
             ++byte) {
            for (uint32_t bit = 0;
                 bit <
                     kNormalizedAlgAirCodecBitsPerByte;
                 ++bit) {
                aq::AirConstraint<Fp3> boolean;
                boolean.name =
                    "stage3.fixedpoint.normalized_codec."
                    "bit_boolean";
                boolean.kind =
                    aq::AirKind::kEverywhere;
                boolean.alg_degree = 2;
                const uint32_t column =
                    out.layout.Bit(
                        lane, byte, bit);
                boolean.eval =
                    [column](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[column],
                            gf::Sub(
                                row[column],
                                Fp3::One()));
                    };
                append(std::move(boolean));
            }
            {
                aq::AirConstraint<Fp3> reconstruct;
                reconstruct.name =
                    "stage3.fixedpoint.normalized_codec."
                    "byte_le_bits";
                reconstruct.kind =
                    aq::AirKind::kEverywhere;
                reconstruct.alg_degree = 1;
                const uint32_t byte_column =
                    out.layout.Byte(lane, byte);
                const NormalizedAlgAirCodecDecoderLayout
                    layout = out.layout;
                reconstruct.eval =
                    [layout, lane, byte, byte_column](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        Fp3 value = Fp3::Zero();
                        for (uint32_t bit = 0;
                             bit <
                                 kNormalizedAlgAirCodecBitsPerByte;
                             ++bit) {
                            value = gf::Add(
                                value,
                                gf::Mul(
                                    Fp3::FromFp(
                                        gf::FromU64(
                                            uint32_t{1}
                                            << bit)),
                                    row[layout.Bit(
                                        lane, byte,
                                        bit)]));
                        }
                        return gf::Sub(
                            row[byte_column], value);
                    };
                append(std::move(reconstruct));
            }
            {
                aq::AirConstraint<Fp3> padding;
                padding.name =
                    "stage3.fixedpoint.normalized_codec."
                    "invalid_byte_zero";
                padding.kind =
                    aq::AirKind::kEverywhere;
                padding.alg_degree = 2;
                const uint32_t byte_column =
                    out.layout.Byte(lane, byte);
                const uint32_t valid =
                    out.layout.ValidByte(lane, byte);
                padding.eval =
                    [byte_column, valid](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            gf::Sub(
                                Fp3::One(),
                                row[valid]),
                            row[byte_column]);
                    };
                append(std::move(padding));
            }
        }
        {
            aq::AirConstraint<Fp3> word;
            word.name =
                "stage3.fixedpoint.normalized_codec."
                "word_le_bytes";
            word.kind = aq::AirKind::kEverywhere;
            word.alg_degree = 2;
            const uint32_t active_column =
                out.layout.Active(lane);
            const uint32_t source =
                proof_bus.layout.Field(lane);
            const NormalizedAlgAirCodecDecoderLayout
                layout = out.layout;
            word.eval =
                [active_column, source,
                 layout, lane](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    Fp3 value = Fp3::Zero();
                    gf::Fp power = 1;
                    for (uint32_t byte = 0;
                         byte <
                             kNormalizedAlgAirCodecBytesPerWord;
                         ++byte) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                Fp3::FromFp(power),
                                row[layout.Byte(
                                    lane, byte)]));
                        power *= 256;
                    }
                    return gf::Mul(
                        row[active_column],
                        gf::Sub(row[source], value));
                };
            append(std::move(word));
        }

        const uint32_t fp_selector =
            out.layout.FpLow(lane);
        const uint32_t low_source =
            proof_bus.layout.Field(lane);
        const uint32_t high_source =
            proof_bus.layout.Field(
                (lane + 1) %
                    kNormalizedAlgAirCodecWordLanes);
        const uint32_t is_max =
            out.layout.HighIsMax(lane);
        const uint32_t inverse =
            out.layout.HighDeltaInverse(lane);
        const aq::AirKind fp_kind =
            lane + 1 <
                    kNormalizedAlgAirCodecWordLanes
                ? aq::AirKind::kEverywhere
                : aq::AirKind::kTransition;
        const auto high_value =
            [high_source, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                return lane + 1 <
                        kNormalizedAlgAirCodecWordLanes
                    ? row[high_source]
                    : next[high_source];
            };
        {
            aq::AirConstraint<Fp3> boolean;
            boolean.name =
                "stage3.fixedpoint.normalized_codec."
                "fp_high_is_max_boolean";
            boolean.kind = fp_kind;
            boolean.alg_degree = 3;
            boolean.eval =
                [fp_selector, is_max](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[fp_selector],
                        gf::Mul(
                            row[is_max],
                            gf::Sub(
                                row[is_max],
                                Fp3::One())));
                };
            append(std::move(boolean));
        }
        {
            aq::AirConstraint<Fp3> zero;
            zero.name =
                "stage3.fixedpoint.normalized_codec."
                "fp_high_is_max_sound";
            zero.kind = fp_kind;
            zero.alg_degree = 3;
            zero.eval =
                [fp_selector, is_max,
                 high_value](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    const Fp3 delta =
                        gf::Sub(
                            Fp3::FromFp(U32_MAX),
                            high_value(row, next));
                    return gf::Mul(
                        row[fp_selector],
                        gf::Mul(
                            delta,
                            row[is_max]));
                };
            append(std::move(zero));
        }
        {
            aq::AirConstraint<Fp3> nonzero;
            nonzero.name =
                "stage3.fixedpoint.normalized_codec."
                "fp_high_delta_inverse";
            nonzero.kind = fp_kind;
            nonzero.alg_degree = 3;
            nonzero.eval =
                [fp_selector, is_max, inverse,
                 high_value](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    const Fp3 delta =
                        gf::Sub(
                            Fp3::FromFp(U32_MAX),
                            high_value(row, next));
                    return gf::Mul(
                        row[fp_selector],
                        gf::Sub(
                            gf::Mul(
                                delta,
                                row[inverse]),
                            gf::Sub(
                                Fp3::One(),
                                row[is_max])));
                };
            append(std::move(nonzero));
        }
        {
            aq::AirConstraint<Fp3> canonical;
            canonical.name =
                "stage3.fixedpoint.normalized_codec."
                "fp_goldilocks_canonical";
            canonical.kind = fp_kind;
            canonical.alg_degree = 3;
            canonical.eval =
                [fp_selector, is_max, low_source](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[fp_selector],
                        gf::Mul(
                            row[is_max],
                            row[low_source]));
                };
            append(std::move(canonical));
        }
    }
    for (const auto [lane, expected] :
         std::array<std::pair<uint32_t, uint32_t>, 2>{
             std::pair<uint32_t, uint32_t>{
                 3, out.map.codec_bytes},
             std::pair<uint32_t, uint32_t>{
                 4, out.map.codec_words}}) {
        aq::AirConstraint<Fp3> header;
        header.name =
            "stage3.fixedpoint.normalized_codec."
            "exact_length_header";
        header.kind = aq::AirKind::kFirstRow;
        header.alg_degree = 1;
        const uint32_t source =
            proof_bus.layout.Field(lane);
        header.eval =
            [source, expected](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    row[source],
                    Fp3::FromFp(
                        gf::FromU64(expected)));
            };
        append(std::move(header));
    }

    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    out.exact_length_constrained = true;
    out.every_word_decomposed = true;
    out.every_byte_range_checked = true;
    out.little_endian_recomposition_constrained = true;
    out.final_word_padding_zero = true;
    out.every_fp_encoding_canonical = true;
    out.no_unconsumed_codec_bytes = true;
    out.every_chip_consumer_equality_mapped = false;
    out.complete_fiat_shamir_replay_in_parent = false;
    out.recursively_consumed = false;
    out.residuals = {
        "decoded_fields_to_remote_hash_fold_deep_query_path_cells_logup",
        "sha256d_air_quotient_and_fri_fiat_shamir_replay",
        "normalized_ctl_child_verifier_and_terminal_commitment_bus",
    };
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations = composition.violations;
    out.valid =
        out.added_columns == 352 &&
        out.added_constraints == 362 &&
        out.exact_length_constrained &&
        out.every_word_decomposed &&
        out.every_byte_range_checked &&
        out.little_endian_recomposition_constrained &&
        out.final_word_padding_zero &&
        out.every_fp_encoding_canonical &&
        out.no_unconsumed_codec_bytes &&
        !out.every_chip_consumer_equality_mapped &&
        !out.complete_fiat_shamir_replay_in_parent &&
        !out.recursively_consumed &&
        out.residuals.size() == 3 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_batch_codec_decoder_ok;"
          "exact_length_range_endian_canonicality_closed;"
          "remote_chip_logup_fs_ctl_residuals_open;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_batch_codec_decoder_invalid";
    return out;
}

bool ValidateNormalizedAlgAirCodecDecoderV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedAlgAirCodecDecoderAttachmentV1& attachment,
    std::string* why)
{
    NormalizedAlgAirBatchCodecMapV1 map;
    if (!attachment.valid ||
        attachment.version !=
            kNormalizedAlgAirBatchCodecMapVersion ||
        !proof_bus.valid ||
        !BuildNormalizedAlgAirBatchCodecMapV1(
            proof.batch, map, why) ||
        !map.valid ||
        attachment.map.codec_bytes != map.codec_bytes ||
        attachment.map.codec_words != map.codec_words ||
        attachment.map.fp_elements != map.fp_elements ||
        attachment.map.entries.size() !=
            map.entries.size() ||
        attachment.map.semantic_tokens.size() !=
            map.semantic_tokens.size() ||
        attachment.parent_rows !=
            composition.combined.n_rows ||
        attachment.active_word_slots != map.codec_words ||
        attachment.valid_byte_slots != map.codec_bytes ||
        attachment.canonical_fp_elements !=
            map.fp_elements ||
        attachment.added_columns != 352 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.added_constraints != 362 ||
        !attachment.exact_length_constrained ||
        !attachment.every_word_decomposed ||
        !attachment.every_byte_range_checked ||
        !attachment.
            little_endian_recomposition_constrained ||
        !attachment.final_word_padding_zero ||
        !attachment.every_fp_encoding_canonical ||
        !attachment.no_unconsumed_codec_bytes ||
        attachment.every_chip_consumer_equality_mapped ||
        attachment.complete_fiat_shamir_replay_in_parent ||
        attachment.recursively_consumed ||
        attachment.residuals.size() != 3) {
        return Fail(
            why,
            "normalized_batch_codec_decoder_shape");
    }
    for (uint32_t word = 0;
         word < map.codec_words; ++word) {
        const auto& lhs = attachment.map.entries[word];
        const auto& rhs = map.entries[word];
        if (lhs.word_index != rhs.word_index ||
            lhs.byte_offset != rhs.byte_offset ||
            lhs.value != rhs.value ||
            lhs.semantic_ordinal != rhs.semantic_ordinal ||
            lhs.kind != rhs.kind ||
            lhs.consumed_by_existing_verifier_chip !=
                rhs.consumed_by_existing_verifier_chip) {
            return Fail(
                why,
                "normalized_batch_codec_decoder_map");
        }
    }
    for (uint32_t token = 0;
         token < map.semantic_tokens.size();
         ++token) {
        const auto& lhs =
            attachment.map.semantic_tokens[token];
        const auto& rhs =
            map.semantic_tokens[token];
        if (lhs.address != rhs.address ||
            lhs.word_index != rhs.word_index ||
            !gf::Eq(lhs.value, rhs.value) ||
            lhs.kind != rhs.kind ||
            lhs.owner != rhs.owner ||
            lhs.consumed_by_existing_verifier_chip !=
                rhs.consumed_by_existing_verifier_chip) {
            return Fail(
                why,
                "normalized_batch_codec_decoder_token");
        }
    }

    constexpr uint32_t TRANSCRIPT_CODEC_BEGIN = 5;
    for (uint32_t row = 0;
         row < composition.combined.n_rows;
         ++row) {
        for (uint32_t lane = 0;
             lane <
                 kNormalizedAlgAirCodecWordLanes;
             ++lane) {
            const uint64_t position =
                uint64_t{row} *
                    kNormalizedAlgAirCodecWordLanes +
                lane;
            const bool is_word =
                position >= TRANSCRIPT_CODEC_BEGIN &&
                position <
                    uint64_t{TRANSCRIPT_CODEC_BEGIN} +
                        map.codec_words;
            const uint32_t word =
                is_word
                ? static_cast<uint32_t>(
                      position -
                      TRANSCRIPT_CODEC_BEGIN)
                : 0;
            const bool is_fp_low =
                is_word &&
                map.entries[word].kind ==
                    NormalizedAlgAirCodecWordKind::FpLow;
            const auto preprocessed_value =
                [&](uint32_t column)
                    -> const std::vector<Fp3>* {
                    const auto pin = std::find_if(
                        composition.combined.preprocessed.begin(),
                        composition.combined.preprocessed.end(),
                        [column](const auto& item) {
                            return item.first == column;
                        });
                    return pin ==
                            composition.combined.preprocessed.end()
                        ? nullptr
                        : &pin->second;
                };
            const auto* active =
                preprocessed_value(
                    attachment.layout.Active(lane));
            const auto* fp_low =
                preprocessed_value(
                    attachment.layout.FpLow(lane));
            if (active == nullptr ||
                fp_low == nullptr ||
                active->size() !=
                    composition.combined.n_rows ||
                fp_low->size() !=
                    composition.combined.n_rows ||
                !gf::Eq(
                    (*active)[row],
                    is_word
                        ? Fp3::One()
                        : Fp3::Zero()) ||
                !gf::Eq(
                    (*fp_low)[row],
                    is_fp_low
                        ? Fp3::One()
                        : Fp3::Zero()) ||
                !gf::Eq(
                    composition.columns[
                        attachment.layout.Active(lane)]
                        [row],
                    (*active)[row]) ||
                !gf::Eq(
                    composition.columns[
                        attachment.layout.FpLow(lane)]
                        [row],
                    (*fp_low)[row])) {
                return Fail(
                    why,
                    "normalized_batch_codec_decoder_selector");
            }
            for (uint32_t byte = 0;
                 byte <
                     kNormalizedAlgAirCodecBytesPerWord;
                 ++byte) {
                const bool is_valid =
                    is_word &&
                    4 * word + byte <
                        map.codec_bytes;
                const uint32_t expected =
                    is_word
                    ? (map.entries[word].value >>
                           (8 * byte)) &
                          0xff
                    : 0;
                const auto* valid =
                    preprocessed_value(
                        attachment.layout.ValidByte(
                            lane, byte));
                if (valid == nullptr ||
                    valid->size() !=
                        composition.combined.n_rows ||
                    !gf::Eq(
                        (*valid)[row],
                        is_valid
                            ? Fp3::One()
                            : Fp3::Zero()) ||
                    !gf::Eq(
                        composition.columns[
                            attachment.layout.ValidByte(
                                lane, byte)][row],
                        (*valid)[row]) ||
                    !gf::Eq(
                        composition.columns[
                            attachment.layout.Byte(
                                lane, byte)][row],
                        Fp3::FromFp(
                            gf::FromU64(expected)))) {
                    return Fail(
                        why,
                        "normalized_batch_codec_decoder_byte");
                }
                for (uint32_t bit = 0;
                     bit <
                         kNormalizedAlgAirCodecBitsPerByte;
                     ++bit) {
                    if (!gf::Eq(
                            composition.columns[
                                attachment.layout.Bit(
                                    lane, byte, bit)]
                                [row],
                            Fp3::FromFp(
                                gf::FromU64(
                                    (expected >> bit) &
                                    1u)))) {
                        return Fail(
                            why,
                            "normalized_batch_codec_decoder_bit");
                    }
                }
            }
        }
    }
    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0 ||
        attachment.violations != 0) {
        return Fail(
            why,
            "normalized_batch_codec_decoder_air");
    }
    return true;
}

namespace {

struct NormalizedCodecSemanticEvent {
    uint32_t address{0};
    uint32_t word_index{0};
    Fp3 value{};
    NormalizedAlgAirCodecTokenKind kind{
        NormalizedAlgAirCodecTokenKind::U32};
};

bool BuildNormalizedCodecSemanticEvents(
    const NormalizedAlgAirBatchCodecMapV1& map,
    std::vector<NormalizedCodecSemanticEvent>& out)
{
    out.clear();
    if (!map.valid ||
        map.entries.size() != map.codec_words) {
        return false;
    }
    out.reserve(map.semantic_tokens.size());
    for (const auto& token :
         map.semantic_tokens) {
        if (!token.
                consumed_by_existing_verifier_chip) {
            continue;
        }
        out.push_back({
            token.address,
            token.word_index,
            token.value,
            token.kind,
        });
    }
    std::vector<uint32_t> addresses;
    addresses.reserve(out.size());
    for (const auto& event : out) {
        if (event.address == 0) {
            return false;
        }
        addresses.push_back(event.address);
    }
    std::sort(addresses.begin(), addresses.end());
    return !out.empty() &&
        std::adjacent_find(
            addresses.begin(), addresses.end()) ==
            addresses.end();
}

bool EqChallenges(
    const FoldBusChallenges& lhs,
    const FoldBusChallenges& rhs)
{
    return
        gf::Eq(lhs.gamma1, rhs.gamma1) &&
        gf::Eq(lhs.gamma2, rhs.gamma2) &&
        gf::Eq(lhs.alpha1, rhs.alpha1) &&
        gf::Eq(lhs.alpha2, rhs.alpha2);
}

} // namespace

NormalizedAlgAirCodecCtlAttachmentV1
AttachNormalizedAlgAirCodecCtlV1(
    FoldBusComposition& composition,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder)
{
    NormalizedAlgAirCodecCtlAttachmentV1 out;
    out.layout =
        NormalizedAlgAirCodecCtlLayout(
            composition.combined.n_columns);
    out.parent_rows =
        composition.combined.n_rows;
    out.added_columns =
        out.layout.End() - out.layout.base;
    out.constraint_base =
        static_cast<uint32_t>(
            composition.combined.constraints.size());
    std::vector<NormalizedCodecSemanticEvent> events;
    if (!decoder.valid ||
        proof_bus.layout.End() !=
            decoder.layout.base ||
        decoder.layout.End() != out.layout.base ||
        !BuildNormalizedCodecSemanticEvents(
            decoder.map, events) ||
        events.size() >
            uint64_t{out.parent_rows} *
                NormalizedAlgAirCodecCtlLayout::kPorts) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_codec_ctl_shape";
        return out;
    }
    out.semantic_events =
        static_cast<uint32_t>(events.size());

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns =
        out.layout.End();
    composition.combined.preprocessed_pin_ood =
        true;
    for (const auto& event : events) {
        constexpr uint32_t TRANSCRIPT_CODEC_BEGIN = 5;
        const uint64_t position =
            uint64_t{TRANSCRIPT_CODEC_BEGIN} +
            event.word_index;
        const uint32_t row =
            static_cast<uint32_t>(
                position /
                    NormalizedAlgAirCodecCtlLayout::kPorts);
        const uint32_t port =
            static_cast<uint32_t>(
                position %
                    NormalizedAlgAirCodecCtlLayout::kPorts);
        if (row >= out.parent_rows ||
            !gf::IsZero(
                composition.columns[
                    out.layout.Active(false, port)]
                    [row])) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_codec_ctl_producer_collision";
            return out;
        }
        composition.columns[
            out.layout.Value(false, port)][row] =
                event.value;
        composition.columns[
            out.layout.Address(false, port)][row] =
                Fp3::FromFp(
                    gf::FromU64(event.address));
        composition.columns[
            out.layout.Active(false, port)][row] =
                Fp3::One();
        composition.columns[
            out.layout.ProducerFp3(port)][row] =
                event.kind ==
                        NormalizedAlgAirCodecTokenKind::Fp3
                    ? Fp3::One()
                    : Fp3::Zero();
        ++out.producer_events;
    }
    for (uint32_t ordinal = 0;
         ordinal < events.size(); ++ordinal) {
        const uint32_t row =
            ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t port =
            ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        composition.columns[
            out.layout.Value(true, port)][row] =
                events[ordinal].value;
        composition.columns[
            out.layout.Address(true, port)][row] =
                Fp3::FromFp(gf::FromU64(
                    events[ordinal].address));
        composition.columns[
            out.layout.Active(true, port)][row] =
                Fp3::One();
        ++out.consumer_events;
    }
    if (out.producer_events != out.semantic_events ||
        out.consumer_events != out.semantic_events) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_codec_ctl_inventory";
        return out;
    }

    std::vector<uint256> roots;
    roots.reserve(6 *
        NormalizedAlgAirCodecCtlLayout::kPorts);
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_NORMALIZED_CODEC_CTL_PRECOMMIT_V1";
    precommit << proof_bus.proof_commitment;
    precommit << out.parent_rows;
    precommit << out.semantic_events;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 3>{
                     out.layout.Value(
                         consumer, port),
                     out.layout.Address(
                         consumer, port),
                     out.layout.Active(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        composition.columns[column],
                        out.parent_rows);
                if (root.IsNull()) {
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "normalized_codec_ctl_precommit";
                    return out;
                }
                roots.push_back(root);
                precommit << root;
            }
        }
    }
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        const uint32_t column =
            out.layout.ProducerFp3(port);
        composition.combined.preprocessed.emplace_back(
            column,
            composition.columns[column]);
    }
    out.prechallenge_commitment =
        precommit.GetHash();
    const auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    out.prechallenge_commitment,
                    label, roots,
                    {out.parent_rows,
                     out.semantic_events});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    out.challenges.gamma1 =
        challenge("normalized_codec_ctl_gamma1");
    out.challenges.gamma2 =
        challenge("normalized_codec_ctl_gamma2");
    out.challenges.alpha1 =
        challenge("normalized_codec_ctl_alpha1");
    out.challenges.alpha2 =
        challenge("normalized_codec_ctl_alpha2");

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    out.denominator_nonzero = true;
    for (uint32_t row = 0;
         row < out.parent_rows; ++row) {
        composition.columns[
            out.layout.running1][row] = running1;
        composition.columns[
            out.layout.running2][row] = running2;
        Fp3 contribution1 = Fp3::Zero();
        Fp3 contribution2 = Fp3::Zero();
        for (const bool consumer :
             std::array<bool, 2>{false, true}) {
            const Fp3 sign = consumer
                ? Fp3::FromFp(gf::Neg(1))
                : Fp3::One();
            for (uint32_t port = 0;
                 port <
                     NormalizedAlgAirCodecCtlLayout::kPorts;
                 ++port) {
                const Fp3 active =
                    composition.columns[
                        out.layout.Active(
                            consumer, port)][row];
                if (gf::IsZero(active)) {
                    continue;
                }
                const Fp3 address =
                    composition.columns[
                        out.layout.Address(
                            consumer, port)][row];
                const Fp3 value =
                    composition.columns[
                        out.layout.Value(
                            consumer, port)][row];
                const Fp3 key1 =
                    gf::Add(
                        address,
                        gf::Mul(
                            out.challenges.gamma1,
                            value));
                const Fp3 key2 =
                    gf::Add(
                        address,
                        gf::Mul(
                            out.challenges.gamma2,
                            value));
                const Fp3 denominator1 =
                    gf::Sub(
                        out.challenges.alpha1,
                        key1);
                const Fp3 denominator2 =
                    gf::Sub(
                        out.challenges.alpha2,
                        key2);
                if (gf::IsZero(denominator1) ||
                    gf::IsZero(denominator2)) {
                    out.denominator_nonzero = false;
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "normalized_codec_ctl_zero_denominator";
                    return out;
                }
                const Fp3 inverse1 =
                    gf::Inv(denominator1);
                const Fp3 inverse2 =
                    gf::Inv(denominator2);
                composition.columns[
                    out.layout.Inverse1(
                        consumer, port)][row] =
                            inverse1;
                composition.columns[
                    out.layout.Inverse2(
                        consumer, port)][row] =
                            inverse2;
                contribution1 =
                    gf::Add(
                        contribution1,
                        gf::Mul(sign, inverse1));
                contribution2 =
                    gf::Add(
                        contribution2,
                        gf::Mul(sign, inverse2));
            }
        }
        running1 = gf::Add(
            running1, contribution1);
        running2 = gf::Add(
            running2, contribution2);
    }

    // Addresses/selectors and the provisional consumer values are canonical
    // verifier pins. Producer values remain witness cells and are equality
    // aliased to the decoded proof words below.
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 2>{
                     out.layout.Address(
                         consumer, port),
                     out.layout.Active(
                         consumer, port)}) {
                composition.combined.preprocessed.emplace_back(
                    column,
                    composition.columns[column]);
            }
            if (consumer) {
                const uint32_t column =
                    out.layout.Value(true, port);
                composition.combined.preprocessed.emplace_back(
                    column,
                    composition.columns[column]);
            }
        }
    }

    const auto append =
        [&](aq::AirConstraint<Fp3> constraint) {
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            {
                aq::AirConstraint<Fp3> boolean;
                boolean.name =
                    "stage3.fixedpoint.normalized_codec_ctl."
                    "active_boolean";
                boolean.kind =
                    aq::AirKind::kEverywhere;
                boolean.alg_degree = 2;
                const uint32_t active =
                    out.layout.Active(
                        consumer, port);
                boolean.eval =
                    [active](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[active],
                            gf::Sub(
                                row[active],
                                Fp3::One()));
                    };
                append(std::move(boolean));
            }
            for (uint32_t lane = 0;
                 lane < 2; ++lane) {
                aq::AirConstraint<Fp3> inverse;
                inverse.name =
                    "stage3.fixedpoint.normalized_codec_ctl."
                    "inverse";
                inverse.kind =
                    aq::AirKind::kEverywhere;
                inverse.alg_degree = 2;
                const uint32_t active =
                    out.layout.Active(
                        consumer, port);
                const uint32_t address =
                    out.layout.Address(
                        consumer, port);
                const uint32_t value =
                    out.layout.Value(
                        consumer, port);
                const uint32_t inverse_column =
                    lane == 0
                    ? out.layout.Inverse1(
                          consumer, port)
                    : out.layout.Inverse2(
                          consumer, port);
                const Fp3 gamma =
                    lane == 0
                    ? out.challenges.gamma1
                    : out.challenges.gamma2;
                const Fp3 alpha =
                    lane == 0
                    ? out.challenges.alpha1
                    : out.challenges.alpha2;
                inverse.eval =
                    [active, address, value,
                     inverse_column, gamma, alpha](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        const Fp3 key =
                            gf::Add(
                                row[address],
                                gf::Mul(
                                    gamma,
                                    row[value]));
                        return gf::Sub(
                            row[active],
                            gf::Mul(
                                row[inverse_column],
                                gf::Sub(alpha, key)));
                    };
                append(std::move(inverse));
            }
        }
    }
    constexpr gf::Fp TWO32 =
        UINT64_C(1) << 32;
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        aq::AirConstraint<Fp3> alias;
        alias.name =
            "stage3.fixedpoint.normalized_codec_ctl."
            "producer_decoder_alias";
        alias.kind =
            port + 5 <
                    NormalizedAlgAirCodecCtlLayout::kPorts
                ? aq::AirKind::kEverywhere
                : aq::AirKind::kTransition;
        alias.alg_degree = 3;
        const uint32_t active =
            out.layout.Active(false, port);
        const uint32_t value =
            out.layout.Value(false, port);
        const uint32_t fp =
            decoder.layout.FpLow(port);
        const uint32_t fp3 =
            out.layout.ProducerFp3(port);
        const NormalizedAlgAirProofFieldBusLayout
            proof_layout = proof_bus.layout;
        alias.eval =
            [active, value, fp, fp3, port,
             proof_layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                const auto word =
                    [&](uint32_t offset) {
                        const uint32_t absolute =
                            port + offset;
                        const uint32_t lane =
                            absolute %
                            NormalizedAlgAirCodecCtlLayout::
                                kPorts;
                        return absolute <
                                NormalizedAlgAirCodecCtlLayout::
                                    kPorts
                            ? row[proof_layout.Field(lane)]
                            : next[proof_layout.Field(lane)];
                    };
                const auto component =
                    [&](uint32_t offset) {
                        return gf::Add(
                            word(offset),
                            gf::Mul(
                                Fp3::FromFp(TWO32),
                                word(offset + 1)));
                    };
                const Fp3 c0 =
                    gf::Add(
                        word(0),
                        gf::Mul(
                            row[fp],
                            gf::Mul(
                                Fp3::FromFp(TWO32),
                                word(1))));
                const Fp3 u{0, 1, 0};
                const Fp3 u2{0, 0, 1};
                const Fp3 extension_tail =
                    gf::Add(
                        gf::Mul(u, component(2)),
                        gf::Mul(u2, component(4)));
                const Fp3 source =
                    gf::Add(
                        c0,
                        gf::Mul(
                            row[fp3],
                            extension_tail));
                return gf::Mul(
                    row[active],
                    gf::Sub(row[value], source));
            };
        append(std::move(alias));
    }
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        const uint32_t running =
            lane == 0
            ? out.layout.running1
            : out.layout.running2;
        aq::AirConstraint<Fp3> transition;
        transition.name =
            "stage3.fixedpoint.normalized_codec_ctl."
            "running";
        transition.kind =
            aq::AirKind::kTransition;
        transition.alg_degree = 2;
        const NormalizedAlgAirCodecCtlLayout
            layout = out.layout;
        transition.eval =
            [layout, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                Fp3 contribution = Fp3::Zero();
                for (const bool consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign = consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedAlgAirCodecCtlLayout::
                                 kPorts;
                         ++port) {
                        contribution = gf::Add(
                            contribution,
                            gf::Mul(
                                sign,
                                gf::Mul(
                                    row[layout.Active(
                                        consumer, port)],
                                    row[lane == 0
                                        ? layout.Inverse1(
                                              consumer,
                                              port)
                                        : layout.Inverse2(
                                              consumer,
                                              port)])));
                    }
                }
                return gf::Sub(
                    next[running],
                    gf::Add(
                        row[running],
                        contribution));
            };
        append(std::move(transition));

        aq::AirConstraint<Fp3> first;
        first.name =
            "stage3.fixedpoint.normalized_codec_ctl."
            "first";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        first.eval =
            [running](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return row[running];
            };
        append(std::move(first));

        aq::AirConstraint<Fp3> terminal;
        terminal.name =
            "stage3.fixedpoint.normalized_codec_ctl."
            "terminal";
        terminal.kind = aq::AirKind::kLastRow;
        terminal.alg_degree = 2;
        terminal.eval =
            [layout, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 result = row[running];
                for (const bool consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign = consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedAlgAirCodecCtlLayout::
                                 kPorts;
                         ++port) {
                        result = gf::Add(
                            result,
                            gf::Mul(
                                sign,
                                gf::Mul(
                                    row[layout.Active(
                                        consumer, port)],
                                    row[lane == 0
                                        ? layout.Inverse1(
                                              consumer,
                                              port)
                                        : layout.Inverse2(
                                              consumer,
                                              port)])));
                    }
                }
                return result;
            };
        append(std::move(terminal));
    }

    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    out.exact_semantic_addresses = true;
    out.exact_multiplicity_one = true;
    out.dual_rational_identity_terminal_zero =
        gf::IsZero(running1) &&
        gf::IsZero(running2);
    out.decoder_values_aliased = true;
    out.consumer_values_sourced_from_remote_chips =
        false;
    out.complete_fiat_shamir_replay_in_parent =
        false;
    out.recursively_consumed = false;
    out.residuals = {
        "replace_canonical_consumer_pins_with_owning_hash_fold_deep_query_path_cells",
        "sha256d_air_quotient_and_fri_fiat_shamir_replay",
        "normalized_ctl_child_verifier_and_terminal_commitment_bus",
    };
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations = composition.violations;
    out.valid =
        out.added_columns == 90 &&
        out.added_constraints == 62 &&
        out.semantic_events != 0 &&
        out.producer_events == out.semantic_events &&
        out.consumer_events == out.semantic_events &&
        out.exact_semantic_addresses &&
        out.exact_multiplicity_one &&
        out.dual_rational_identity_terminal_zero &&
        out.denominator_nonzero &&
        out.decoder_values_aliased &&
        !out.consumer_values_sourced_from_remote_chips &&
        !out.complete_fiat_shamir_replay_in_parent &&
        !out.recursively_consumed &&
        out.residuals.size() == 3 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_codec_dual_logup_ok;"
          "exact_addresses_and_multiplicity_closed;"
          "remote_chip_alias_fs_ctl_residuals_open;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_codec_dual_logup_invalid";
    return out;
}

bool ValidateNormalizedAlgAirCodecCtlV1(
    const FoldBusComposition& composition,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& attachment,
    std::string* why)
{
    std::vector<NormalizedCodecSemanticEvent> events;
    if (!attachment.valid ||
        attachment.version !=
            kNormalizedAlgAirBatchCodecMapVersion ||
        !proof_bus.valid ||
        !decoder.valid ||
        !BuildNormalizedCodecSemanticEvents(
            decoder.map, events) ||
        attachment.semantic_events != events.size() ||
        attachment.producer_events != events.size() ||
        attachment.consumer_events != events.size() ||
        attachment.parent_rows !=
            composition.combined.n_rows ||
        attachment.added_columns != 90 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.added_constraints != 62 ||
        !attachment.exact_semantic_addresses ||
        !attachment.exact_multiplicity_one ||
        !attachment.
            dual_rational_identity_terminal_zero ||
        !attachment.denominator_nonzero ||
        !attachment.decoder_values_aliased ||
        attachment.
            consumer_values_sourced_from_remote_chips ||
        attachment.complete_fiat_shamir_replay_in_parent ||
        attachment.recursively_consumed ||
        attachment.residuals.size() != 3 ||
        attachment.prechallenge_commitment.IsNull()) {
        return Fail(
            why,
            "normalized_codec_ctl_shape");
    }

    std::vector<std::vector<Fp3>> expected_columns(
        attachment.layout.End() -
            attachment.layout.base,
        std::vector<Fp3>(
            attachment.parent_rows,
            Fp3::Zero()));
    const auto local =
        [&](uint32_t column) -> std::vector<Fp3>& {
            return expected_columns[
                column - attachment.layout.base];
        };
    for (const auto& event : events) {
        constexpr uint32_t TRANSCRIPT_CODEC_BEGIN = 5;
        const uint64_t position =
            uint64_t{TRANSCRIPT_CODEC_BEGIN} +
            event.word_index;
        const uint32_t row =
            static_cast<uint32_t>(
                position /
                    NormalizedAlgAirCodecCtlLayout::kPorts);
        const uint32_t port =
            static_cast<uint32_t>(
                position %
                    NormalizedAlgAirCodecCtlLayout::kPorts);
        local(attachment.layout.Value(
            false, port))[row] = event.value;
        local(attachment.layout.Address(
            false, port))[row] =
                Fp3::FromFp(
                    gf::FromU64(event.address));
        local(attachment.layout.Active(
            false, port))[row] = Fp3::One();
        local(attachment.layout.ProducerFp3(port))[row] =
            event.kind ==
                    NormalizedAlgAirCodecTokenKind::Fp3
                ? Fp3::One()
                : Fp3::Zero();
    }
    for (uint32_t ordinal = 0;
         ordinal < events.size(); ++ordinal) {
        const uint32_t row =
            ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t port =
            ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        local(attachment.layout.Value(
            true, port))[row] =
                events[ordinal].value;
        local(attachment.layout.Address(
            true, port))[row] =
                Fp3::FromFp(gf::FromU64(
                    events[ordinal].address));
        local(attachment.layout.Active(
            true, port))[row] = Fp3::One();
    }

    std::vector<uint256> roots;
    roots.reserve(6 *
        NormalizedAlgAirCodecCtlLayout::kPorts);
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_NORMALIZED_CODEC_CTL_PRECOMMIT_V1";
    precommit << proof_bus.proof_commitment;
    precommit << attachment.parent_rows;
    precommit << attachment.semantic_events;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 3>{
                     attachment.layout.Value(
                         consumer, port),
                     attachment.layout.Address(
                         consumer, port),
                     attachment.layout.Active(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        local(column),
                        attachment.parent_rows);
                if (root.IsNull()) {
                    return Fail(
                        why,
                        "normalized_codec_ctl_precommit");
                }
                roots.push_back(root);
                precommit << root;
            }
        }
    }
    const uint256 expected_precommit =
        precommit.GetHash();
    const auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    expected_precommit,
                    label, roots,
                    {attachment.parent_rows,
                     attachment.semantic_events});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    const FoldBusChallenges expected_challenges{
        challenge("normalized_codec_ctl_gamma1"),
        challenge("normalized_codec_ctl_gamma2"),
        challenge("normalized_codec_ctl_alpha1"),
        challenge("normalized_codec_ctl_alpha2"),
    };
    if (attachment.prechallenge_commitment !=
            expected_precommit ||
        !EqChallenges(
            attachment.challenges,
            expected_challenges)) {
        return Fail(
            why,
            "normalized_codec_ctl_challenge");
    }

    for (uint32_t row = 0;
         row < attachment.parent_rows;
         ++row) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            const uint32_t column =
                attachment.layout.ProducerFp3(port);
            if (!gf::Eq(
                    composition.columns[column][row],
                    local(column)[row])) {
                return Fail(
                    why,
                    "normalized_codec_ctl_fp3_selector");
            }
        }
        for (const bool consumer :
             std::array<bool, 2>{false, true}) {
            for (uint32_t port = 0;
                 port <
                     NormalizedAlgAirCodecCtlLayout::kPorts;
                 ++port) {
                for (const uint32_t column :
                     std::array<uint32_t, 3>{
                         attachment.layout.Value(
                             consumer, port),
                         attachment.layout.Address(
                             consumer, port),
                         attachment.layout.Active(
                             consumer, port)}) {
                    if (!gf::Eq(
                            composition.columns[column][row],
                            local(column)[row])) {
                        return Fail(
                            why,
                            "normalized_codec_ctl_event");
                    }
                }
            }
        }
    }
    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0 ||
        attachment.violations != 0) {
        return Fail(
            why,
            "normalized_codec_ctl_air");
    }
    return true;
}

namespace {

enum class RemoteExportFamily : uint8_t {
    HashValue,
    QueryIndex,
    AuthenticationPath,
    Root,
    FoldValue,
};

struct NormalizedRemoteExportRef {
    uint32_t address{0};
    Fp3 value{};
    uint32_t row{0};
    uint32_t source_kind{0};
    RemoteExportFamily family{
        RemoteExportFamily::HashValue};
};

struct QueryRemoteLocations {
    uint32_t current_start{0};
    uint32_t current_blocks{0};
    uint32_t current_terminal{0};
    struct Fold {
        uint32_t even_leaf{0};
        uint32_t even_terminal{0};
        uint32_t odd_leaf{0};
        uint32_t odd_terminal{0};
    };
    std::vector<Fold> folds;
};

bool BuildNormalizedRemoteExportRefs(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirBatchCodecMapV1& map,
    std::vector<NormalizedRemoteExportRef>& refs,
    uint32_t& deep_remaining,
    uint32_t& scheduler_remaining,
    uint32_t& fs_remaining,
    std::string* fail_tag = nullptr)
{
    const auto fail = [&](const char* tag) {
        if (fail_tag != nullptr) {
            *fail_tag = tag;
        }
        return false;
    };
    refs.clear();
    deep_remaining = 0;
    scheduler_remaining = 0;
    fs_remaining = 0;
    if (!composition.valid ||
        !map.valid ||
        proof.batch.queries.empty() ||
        proof.next_openings.size() !=
            proof.batch.queries.size()) {
        return fail("remote_export_map_pre");
    }
    for (const auto& token : map.semantic_tokens) {
        if (!token.consumed_by_existing_verifier_chip) {
            continue;
        }
        switch (token.owner) {
        case NormalizedAlgAirCodecOwnerFamily::Deep:
            ++deep_remaining;
            break;
        case NormalizedAlgAirCodecOwnerFamily::Scheduler:
            ++scheduler_remaining;
            break;
        case NormalizedAlgAirCodecOwnerFamily::FiatShamir:
            ++fs_remaining;
            break;
        default:
            break;
        }
    }
    std::vector<const NormalizedAlgAirCodecSemanticTokenV1*>
        token_at_word(map.codec_words, nullptr);
    for (const auto& token : map.semantic_tokens) {
        if (token.word_index >= token_at_word.size() ||
            token_at_word[token.word_index] != nullptr) {
            return false;
        }
        token_at_word[token.word_index] = &token;
    }
    const auto token_at =
        [&](uint32_t word,
            NormalizedAlgAirCodecTokenKind kind)
            -> const NormalizedAlgAirCodecSemanticTokenV1* {
            if (word >= token_at_word.size() ||
                token_at_word[word] == nullptr ||
                token_at_word[word]->kind != kind) {
                return nullptr;
            }
            return token_at_word[word];
        };
    const auto blocks_for =
        [](uint32_t values) {
            return (3 * values + 1) /
                       ah::kAlgHashRate +
                1;
        };
    std::vector<QueryRemoteLocations> locations(
        proof.batch.queries.size());
    uint32_t trace_cursor = 0;
    for (uint32_t query = 0;
         query < proof.batch.queries.size();
         ++query) {
        const auto& item =
            proof.batch.queries[query];
        if (proof.next_openings[query].size() != 2) {
            return false;
        }
        auto& location = locations[query];
        location.current_start = trace_cursor;
        location.current_blocks =
            blocks_for(item.row.values.size());
        if (item.row.siblings.empty()) {
            return false;
        }
        location.current_terminal =
            trace_cursor +
            location.current_blocks +
            item.row.siblings.size() - 1;
        trace_cursor +=
            location.current_blocks +
            item.row.siblings.size();
        const auto& next =
            proof.next_openings[query][0];
        trace_cursor +=
            blocks_for(next.values.size()) +
            next.siblings.size();
        const auto& trace =
            proof.next_openings[query][1];
        if (item.row.values.empty()) {
            return false;
        }
        trace_cursor +=
            blocks_for(
                item.row.values.size() - 1) +
            trace.siblings.size();
        location.folds.resize(item.steps.size());
        for (uint32_t layer = 0;
             layer < item.steps.size();
             ++layer) {
            const auto& step = item.steps[layer];
            if (step.even_siblings.empty() ||
                step.odd_siblings.empty()) {
                return false;
            }
            auto& fold = location.folds[layer];
            fold.even_leaf = trace_cursor;
            fold.even_terminal =
                trace_cursor +
                step.even_siblings.size();
            trace_cursor +=
                1 + step.even_siblings.size();
            fold.odd_leaf = trace_cursor;
            fold.odd_terminal =
                trace_cursor +
                step.odd_siblings.size();
            trace_cursor +=
                1 + step.odd_siblings.size();
        }
    }
    if (trace_cursor !=
            composition.hash.program.active_rows ||
        trace_cursor >
            composition.combined.n_rows) {
        if (fail_tag != nullptr) {
            *fail_tag =
                "remote_export_map_active_rows"
                ";cursor=" +
                std::to_string(trace_cursor) +
                ";active=" +
                std::to_string(
                    composition.hash.program.active_rows) +
                ";parent_rows=" +
                std::to_string(
                    composition.combined.n_rows);
        }
        return false;
    }
    const auto append =
        [&](const NormalizedAlgAirCodecSemanticTokenV1*
                token,
            uint32_t row, uint32_t source_kind,
            RemoteExportFamily family) {
            if (token == nullptr ||
                !token->
                    consumed_by_existing_verifier_chip ||
                row >= composition.combined.n_rows ||
                source_kind >=
                    kNormalizedAlgAirRemoteSourceKindCount) {
                return false;
            }
            refs.push_back({
                token->address,
                token->value,
                row,
                source_kind,
                family,
            });
            return true;
        };
    uint32_t word = 0;
    const auto skip_u32 = [&]() {
        if (word + 1 > map.codec_words) {
            return false;
        }
        ++word;
        return true;
    };
    const auto skip_u64 = [&]() {
        if (word + 2 > map.codec_words) {
            return false;
        }
        word += 2;
        return true;
    };
    const auto skip_fp = [&]() {
        if (word + 2 > map.codec_words) {
            return false;
        }
        word += 2;
        return true;
    };
    const auto skip_fp3 = [&]() {
        if (word + 6 > map.codec_words) {
            return false;
        }
        word += 6;
        return true;
    };
    if (!skip_u32() || !skip_u32() || !skip_u64() ||
        !skip_u32() || !skip_u32()) {
        return false;
    }
    // One row-root copy is sufficient because every current/next path is
    // already constrained to the same root by the hash-opening chip.
    for (uint32_t limb = 0;
         limb < ah::kAlgHashDigestLen;
         ++limb) {
        const auto* token =
            token_at(
                word,
                NormalizedAlgAirCodecTokenKind::Fp);
        if (!append(
                token,
                locations[0].current_terminal,
                25 + limb,
                RemoteExportFamily::Root) ||
            !skip_fp()) {
            return false;
        }
    }
    if (!skip_u32() || !skip_u32()) {
        return false;
    }
    for (size_t i = 0;
         i < proof.batch.column_len.size(); ++i) {
        if (!skip_u32()) return false;
    }
    if (!skip_fp3() || !skip_fp3() ||
        !skip_fp3() || !skip_u32()) {
        return false;
    }
    for (size_t i = 0;
         i < proof.batch.evals_z1.size(); ++i) {
        if (!skip_fp3()) return false;
    }
    if (!skip_u32()) return false;
    for (size_t i = 0;
         i < proof.batch.evals_z2.size(); ++i) {
        if (!skip_fp3()) return false;
    }
    if (!skip_fp3() || !skip_fp3() ||
        !skip_u32()) {
        return false;
    }
    for (uint32_t layer = 0;
         layer < proof.batch.fold_layers.size();
         ++layer) {
        // Layers [0, n_folds) have matching query fold steps. The terminal
        // constant layer (index == n_folds == fold_challenges.size()) has no
        // step; its digest is not hash-opening-consumed (see codec map) so
        // only the scheduler n_leaves word is walked here via skip.
        if (layer < locations[0].folds.size()) {
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen;
                 ++limb) {
                const auto* token =
                    token_at(
                        word,
                        NormalizedAlgAirCodecTokenKind::Fp);
                if (!append(
                        token,
                        locations[0].folds[layer].
                            even_terminal,
                        25 + limb,
                        RemoteExportFamily::Root) ||
                    !skip_fp()) {
                    return fail("remote_export_map_fold_root");
                }
            }
        } else {
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen;
                 ++limb) {
                if (!skip_fp()) {
                    return fail("remote_export_map_terminal_layer_root");
                }
            }
        }
        if (!skip_u32()) {
            return fail("remote_export_map_fold_n_leaves");
        }
    }
    {
        const auto* token =
            token_at(
                word,
                NormalizedAlgAirCodecTokenKind::Fp3);
        if (locations[0].folds.empty() ||
            !append(
                token,
                locations[0].folds.back().
                    odd_terminal,
                30,
                RemoteExportFamily::FoldValue) ||
            !skip_fp3()) {
            return false;
        }
    }
    if (!skip_u32()) return false;
    for (uint32_t layer = 0;
         layer < proof.batch.fold_challenges.size();
         ++layer) {
        const auto* token =
            token_at(
                word,
                NormalizedAlgAirCodecTokenKind::Fp3);
        if (layer >= locations[0].folds.size() ||
            !append(
                token,
                locations[0].folds[layer].
                    odd_terminal,
                29,
                RemoteExportFamily::FoldValue) ||
            !skip_fp3()) {
            return false;
        }
    }
    if (!skip_u32()) return false;
    for (uint32_t query = 0;
         query < proof.batch.queries.size();
         ++query) {
        const auto& item =
            proof.batch.queries[query];
        const auto& location = locations[query];
        {
            const auto* token =
                token_at(
                    word,
                    NormalizedAlgAirCodecTokenKind::U32);
            const uint32_t position =
                3 * item.row.values.size();
            if (!append(
                    token,
                    location.current_start +
                        position /
                            ah::kAlgHashRate,
                    position %
                        ah::kAlgHashRate,
                    RemoteExportFamily::QueryIndex) ||
                !skip_u32()) {
                return false;
            }
        }
        if (!skip_u32()) return false;
        for (uint32_t value = 0;
             value < item.row.values.size();
             ++value) {
            const auto* token =
                token_at(
                    word,
                    NormalizedAlgAirCodecTokenKind::Fp3);
            const uint32_t position = 3 * value;
            if (!append(
                    token,
                    location.current_start +
                        position /
                            ah::kAlgHashRate,
                    8 + position %
                        ah::kAlgHashRate,
                    RemoteExportFamily::HashValue) ||
                !skip_fp3()) {
                return false;
            }
        }
        if (!skip_u32()) return false;
        for (uint32_t level = 0;
             level < item.row.siblings.size();
             ++level) {
            const uint32_t row =
                location.current_start +
                location.current_blocks + level;
            const bool direction =
                composition.hash.program.rows[row].
                    direction;
            for (uint32_t limb = 0;
                 limb < ah::kAlgHashDigestLen;
                 ++limb) {
                const auto* token =
                    token_at(
                        word,
                        NormalizedAlgAirCodecTokenKind::Fp);
                const uint32_t input_lane =
                    (direction ? 0 : 4) + limb;
                if (!append(
                        token, row,
                        16 + input_lane,
                        RemoteExportFamily::
                            AuthenticationPath) ||
                    !skip_fp()) {
                    return false;
                }
            }
        }
        if (!skip_u32()) return false;
        for (uint32_t layer = 0;
             layer < item.steps.size();
             ++layer) {
            const auto& step = item.steps[layer];
            const auto& fold = location.folds[layer];
            const auto* even_index =
                token_at(
                    word,
                    NormalizedAlgAirCodecTokenKind::U32);
            if (!append(
                    even_index, fold.even_leaf,
                    16 + 3,
                    RemoteExportFamily::FoldValue) ||
                !skip_u32()) {
                return false;
            }
            const auto* odd_index =
                token_at(
                    word,
                    NormalizedAlgAirCodecTokenKind::U32);
            if (!append(
                    odd_index, fold.odd_leaf,
                    16 + 3,
                    RemoteExportFamily::FoldValue) ||
                !skip_u32()) {
                return false;
            }
            const auto* even =
                token_at(
                    word,
                    NormalizedAlgAirCodecTokenKind::Fp3);
            if (!append(
                    even, fold.even_leaf,
                    24,
                    RemoteExportFamily::FoldValue) ||
                !skip_fp3()) {
                return false;
            }
            const auto* odd =
                token_at(
                    word,
                    NormalizedAlgAirCodecTokenKind::Fp3);
            if (!append(
                    odd, fold.odd_leaf,
                    24,
                    RemoteExportFamily::FoldValue) ||
                !skip_fp3()) {
                return false;
            }
            if (!skip_u32()) return false;
            for (uint32_t level = 0;
                 level < step.even_siblings.size();
                 ++level) {
                const uint32_t row =
                    fold.even_leaf + 1 + level;
                const bool direction =
                    composition.hash.program.rows[row].
                        direction;
                for (uint32_t limb = 0;
                     limb < ah::kAlgHashDigestLen;
                     ++limb) {
                    const auto* token =
                        token_at(
                            word,
                            NormalizedAlgAirCodecTokenKind::Fp);
                    if (!append(
                            token, row,
                            16 +
                                (direction ? 0 : 4) +
                                limb,
                            RemoteExportFamily::
                                AuthenticationPath) ||
                        !skip_fp()) {
                        return false;
                    }
                }
            }
            if (!skip_u32()) return false;
            for (uint32_t level = 0;
                 level < step.odd_siblings.size();
                 ++level) {
                const uint32_t row =
                    fold.odd_leaf + 1 + level;
                const bool direction =
                    composition.hash.program.rows[row].
                        direction;
                for (uint32_t limb = 0;
                     limb < ah::kAlgHashDigestLen;
                     ++limb) {
                    const auto* token =
                        token_at(
                            word,
                            NormalizedAlgAirCodecTokenKind::Fp);
                    if (!append(
                            token, row,
                            16 +
                                (direction ? 0 : 4) +
                                limb,
                            RemoteExportFamily::
                                AuthenticationPath) ||
                        !skip_fp()) {
                        return false;
                    }
                }
            }
        }
    }
    if (word != map.codec_words) {
        if (fail_tag != nullptr) {
            *fail_tag = "remote_export_map_word_cursor;word=" +
                std::to_string(word) + ";codec_words=" +
                std::to_string(map.codec_words);
        }
        return false;
    }
    std::vector<uint32_t> addresses;
    addresses.reserve(refs.size());
    for (const auto& ref : refs) {
        addresses.push_back(ref.address);
    }
    std::sort(addresses.begin(), addresses.end());
    if (refs.empty()) {
        return fail("remote_export_map_empty_refs");
    }
    if (std::adjacent_find(
            addresses.begin(), addresses.end()) !=
            addresses.end()) {
        return fail("remote_export_map_dup_address");
    }
    if (fail_tag != nullptr) {
        fail_tag->clear();
    }
    return true;
}

Fp3 NormalizedRemoteSourceValue(
    const FoldBusComposition& composition,
    const NormalizedRemoteExportRef& ref)
{
    const HashOpeningLayout hash_layout =
        HashOpeningLayoutAt(
            composition.hash.column_base);
    if (ref.source_kind < 8) {
        return composition.columns[
            hash_layout.absorbed_pin_base +
            ref.source_kind][ref.row];
    }
    if (ref.source_kind < 16) {
        const uint32_t start =
            ref.source_kind - 8;
        const auto coordinate =
            [&](uint32_t offset) {
                const uint32_t absolute =
                    start + offset;
                const uint32_t row =
                    ref.row +
                    absolute / ah::kAlgHashRate;
                const uint32_t lane =
                    absolute % ah::kAlgHashRate;
                return composition.columns[
                    hash_layout.absorbed_pin_base +
                    lane][row];
            };
        const Fp3 u{0, 1, 0};
        const Fp3 u2{0, 0, 1};
        return gf::Add(
            coordinate(0),
            gf::Add(
                gf::Mul(u, coordinate(1)),
                gf::Mul(u2, coordinate(2))));
    }
    if (ref.source_kind < 24) {
        return composition.columns[
            hash_layout.perm.InputCol(
                ref.source_kind - 16)]
            [ref.row];
    }
    if (ref.source_kind == 24) {
        const Fp3 u{0, 1, 0};
        const Fp3 u2{0, 0, 1};
        return gf::Add(
            composition.columns[
                hash_layout.perm.InputCol(0)]
                [ref.row],
            gf::Add(
                gf::Mul(
                    u,
                    composition.columns[
                        hash_layout.perm.InputCol(1)]
                        [ref.row]),
                gf::Mul(
                    u2,
                    composition.columns[
                        hash_layout.perm.InputCol(2)]
                        [ref.row])));
    }
    if (ref.source_kind < 29) {
        return composition.columns[
            hash_layout.expected_root_base +
            (ref.source_kind - 25)][ref.row];
    }
    if (ref.source_kind == 29) {
        return composition.columns[
            composition.bus.beta][ref.row];
    }
    return composition.columns[
        composition.bus.folded][ref.row];
}

} // namespace

NormalizedAlgAirRemoteExportAttachmentV1
AttachNormalizedAlgAirRemoteExportsV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl)
{
    NormalizedAlgAirRemoteExportAttachmentV1 out;
    out.layout =
        NormalizedAlgAirRemoteExportLayout(
            composition.combined.n_columns);
    out.parent_rows =
        composition.combined.n_rows;
    out.added_columns =
        out.layout.End() - out.layout.bus.base;
    out.constraint_base =
        static_cast<uint32_t>(
            composition.combined.constraints.size());
    std::vector<NormalizedRemoteExportRef> refs;
    if (!codec_ctl.valid) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_remote_export_codec_ctl";
        return out;
    }
    if (codec_ctl.layout.End() != out.layout.bus.base) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_remote_export_layout"
            ";ctl_end=" +
            std::to_string(codec_ctl.layout.End()) +
            ";bus_base=" +
            std::to_string(out.layout.bus.base);
        return out;
    }
    std::string map_fail;
    if (!BuildNormalizedRemoteExportRefs(
            composition, proof, decoder.map,
            refs, out.deep_tokens_remaining,
            out.scheduler_tokens_remaining,
            out.fiat_shamir_tokens_remaining,
            &map_fail)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_remote_export_map";
        if (!map_fail.empty()) {
            out.note.push_back(';');
            out.note += map_fail;
        }
        return out;
    }
    out.remote_events =
        static_cast<uint32_t>(refs.size());
    std::vector<NormalizedCodecSemanticEvent> all_events;
    if (!BuildNormalizedCodecSemanticEvents(
            decoder.map, all_events)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_remote_export_codec_events";
        return out;
    }
    std::vector<uint32_t> event_ordinal(
        decoder.map.semantic_tokens.size() + 1,
        UINT32_MAX);
    for (uint32_t ordinal = 0;
         ordinal < all_events.size();
         ++ordinal) {
        if (all_events[ordinal].address >=
                event_ordinal.size()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_remote_export_address";
            return out;
        }
        event_ordinal[
            all_events[ordinal].address] = ordinal;
    }

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns =
        out.layout.End();
    std::vector<std::array<bool,
        NormalizedAlgAirCodecCtlLayout::kPorts>>
        occupied(out.parent_rows);
    for (const auto& ref : refs) {
        uint32_t port = 0;
        while (port <
                   NormalizedAlgAirCodecCtlLayout::kPorts &&
               occupied[ref.row][port]) {
            ++port;
        }
        if (port ==
                NormalizedAlgAirCodecCtlLayout::kPorts ||
            ref.row + 1 >= out.parent_rows) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_remote_export_row_ports";
            return out;
        }
        occupied[ref.row][port] = true;
        const Fp3 source =
            NormalizedRemoteSourceValue(
                composition, ref);
        if (!gf::Eq(source, ref.value)) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_remote_export_source_value";
            return out;
        }
        composition.columns[
            out.layout.bus.Value(false, port)]
            [ref.row] = source;
        composition.columns[
            out.layout.bus.Address(false, port)]
            [ref.row] =
                Fp3::FromFp(
                    gf::FromU64(ref.address));
        composition.columns[
            out.layout.bus.Active(false, port)]
            [ref.row] = Fp3::One();
        composition.columns[
            out.layout.SourceSelector(
                port, ref.source_kind)]
            [ref.row] = Fp3::One();
        const uint32_t ordinal =
            event_ordinal[ref.address];
        if (ordinal == UINT32_MAX) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_remote_export_consumer_missing";
            return out;
        }
        const uint32_t consumer_row =
            ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t consumer_port =
            ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        composition.columns[
            out.layout.bus.Value(
                true, consumer_port)]
            [consumer_row] =
                composition.columns[
                    codec_ctl.layout.Value(
                        true, consumer_port)]
                    [consumer_row];
        composition.columns[
            out.layout.bus.Address(
                true, consumer_port)]
            [consumer_row] =
                composition.columns[
                    codec_ctl.layout.Address(
                        true, consumer_port)]
                    [consumer_row];
        composition.columns[
            out.layout.bus.Active(
                true, consumer_port)]
            [consumer_row] = Fp3::One();
        switch (ref.family) {
        case RemoteExportFamily::HashValue:
            ++out.hash_opening_value_events;
            break;
        case RemoteExportFamily::QueryIndex:
            ++out.query_index_events;
            break;
        case RemoteExportFamily::AuthenticationPath:
            ++out.authentication_path_events;
            break;
        case RemoteExportFamily::Root:
            ++out.root_events;
            break;
        case RemoteExportFamily::FoldValue:
            ++out.fold_value_events;
            break;
        }
    }

    std::vector<uint256> roots;
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_NORMALIZED_REMOTE_EXPORT_PRECOMMIT_V1";
    precommit << codec_ctl.prechallenge_commitment;
    precommit << out.parent_rows;
    precommit << out.remote_events;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 3>{
                     out.layout.bus.Value(
                         consumer, port),
                     out.layout.bus.Address(
                         consumer, port),
                     out.layout.bus.Active(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        composition.columns[column],
                        out.parent_rows);
                if (root.IsNull()) {
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "normalized_remote_export_precommit";
                    return out;
                }
                roots.push_back(root);
                precommit << root;
            }
        }
    }
    out.prechallenge_commitment =
        precommit.GetHash();
    const auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    out.prechallenge_commitment,
                    label, roots,
                    {out.parent_rows,
                     out.remote_events});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    out.challenges.gamma1 =
        challenge("normalized_remote_export_gamma1");
    out.challenges.gamma2 =
        challenge("normalized_remote_export_gamma2");
    out.challenges.alpha1 =
        challenge("normalized_remote_export_alpha1");
    out.challenges.alpha2 =
        challenge("normalized_remote_export_alpha2");

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    out.denominator_nonzero = true;
    for (uint32_t row = 0;
         row < out.parent_rows; ++row) {
        composition.columns[
            out.layout.bus.running1][row] =
                running1;
        composition.columns[
            out.layout.bus.running2][row] =
                running2;
        Fp3 contribution1 = Fp3::Zero();
        Fp3 contribution2 = Fp3::Zero();
        for (const bool consumer :
             std::array<bool, 2>{false, true}) {
            const Fp3 sign = consumer
                ? Fp3::FromFp(gf::Neg(1))
                : Fp3::One();
            for (uint32_t port = 0;
                 port <
                     NormalizedAlgAirCodecCtlLayout::kPorts;
                 ++port) {
                if (gf::IsZero(
                        composition.columns[
                            out.layout.bus.Active(
                                consumer, port)]
                            [row])) {
                    continue;
                }
                const Fp3 address =
                    composition.columns[
                        out.layout.bus.Address(
                            consumer, port)][row];
                const Fp3 value =
                    composition.columns[
                        out.layout.bus.Value(
                            consumer, port)][row];
                const Fp3 d1 =
                    gf::Sub(
                        out.challenges.alpha1,
                        gf::Add(
                            address,
                            gf::Mul(
                                out.challenges.gamma1,
                                value)));
                const Fp3 d2 =
                    gf::Sub(
                        out.challenges.alpha2,
                        gf::Add(
                            address,
                            gf::Mul(
                                out.challenges.gamma2,
                                value)));
                if (gf::IsZero(d1) || gf::IsZero(d2)) {
                    out.denominator_nonzero = false;
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "normalized_remote_export_zero_denominator";
                    return out;
                }
                const Fp3 inv1 = gf::Inv(d1);
                const Fp3 inv2 = gf::Inv(d2);
                composition.columns[
                    out.layout.bus.Inverse1(
                        consumer, port)][row] =
                            inv1;
                composition.columns[
                    out.layout.bus.Inverse2(
                        consumer, port)][row] =
                            inv2;
                contribution1 = gf::Add(
                    contribution1,
                    gf::Mul(sign, inv1));
                contribution2 = gf::Add(
                    contribution2,
                    gf::Mul(sign, inv2));
            }
        }
        running1 = gf::Add(
            running1, contribution1);
        running2 = gf::Add(
            running2, contribution2);
    }

    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 2>{
                     out.layout.bus.Address(
                         consumer, port),
                     out.layout.bus.Active(
                         consumer, port)}) {
                composition.combined.preprocessed.emplace_back(
                    column,
                    composition.columns[column]);
            }
        }
    }
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        for (uint32_t kind = 0;
             kind <
                 kNormalizedAlgAirRemoteSourceKindCount;
             ++kind) {
            const uint32_t column =
                out.layout.SourceSelector(port, kind);
            composition.combined.preprocessed.emplace_back(
                column,
                composition.columns[column]);
        }
    }

    const auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            const uint32_t active =
                out.layout.bus.Active(
                    consumer, port);
            add(
                "stage3.fixedpoint.normalized_remote.active_boolean",
                aq::AirKind::kEverywhere, 2,
                [active](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[active],
                        gf::Sub(
                            row[active],
                            Fp3::One()));
                });
            for (uint32_t lane = 0;
                 lane < 2; ++lane) {
                const uint32_t address =
                    out.layout.bus.Address(
                        consumer, port);
                const uint32_t value =
                    out.layout.bus.Value(
                        consumer, port);
                const uint32_t inverse =
                    lane == 0
                    ? out.layout.bus.Inverse1(
                          consumer, port)
                    : out.layout.bus.Inverse2(
                          consumer, port);
                const Fp3 gamma = lane == 0
                    ? out.challenges.gamma1
                    : out.challenges.gamma2;
                const Fp3 alpha = lane == 0
                    ? out.challenges.alpha1
                    : out.challenges.alpha2;
                add(
                    "stage3.fixedpoint.normalized_remote.inverse",
                    aq::AirKind::kEverywhere, 2,
                    [active, address, value,
                     inverse, gamma, alpha](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Sub(
                            row[active],
                            gf::Mul(
                                row[inverse],
                                gf::Sub(
                                    alpha,
                                    gf::Add(
                                        row[address],
                                        gf::Mul(
                                            gamma,
                                            row[value])))));
                    });
            }
        }
    }
    const HashOpeningLayout hash_layout =
        HashOpeningLayoutAt(
            composition.hash.column_base);
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        const uint32_t active =
            out.layout.bus.Active(false, port);
        const uint32_t value =
            out.layout.bus.Value(false, port);
        const NormalizedAlgAirRemoteExportLayout
            layout = out.layout;
        add(
            "stage3.fixedpoint.normalized_remote.source_onehot",
            aq::AirKind::kEverywhere, 1,
            [layout, port, active](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t kind = 0;
                     kind <
                         kNormalizedAlgAirRemoteSourceKindCount;
                     ++kind) {
                    sum = gf::Add(
                        sum,
                        row[layout.SourceSelector(
                            port, kind)]);
                }
                return gf::Sub(row[active], sum);
            });
        add(
            "stage3.fixedpoint.normalized_remote.literal_alias",
            aq::AirKind::kTransition, 2,
            [layout, hash_layout,
             bus = composition.bus,
             port, value](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                const Fp3 u{0, 1, 0};
                const Fp3 u2{0, 0, 1};
                Fp3 selected = Fp3::Zero();
                for (uint32_t lane = 0;
                     lane < 8; ++lane) {
                    selected = gf::Add(
                        selected,
                        gf::Mul(
                            row[layout.SourceSelector(
                                port, lane)],
                            row[
                                hash_layout.
                                    absorbed_pin_base +
                                lane]));
                    const auto coordinate =
                        [&](uint32_t offset) {
                            const uint32_t absolute =
                                lane + offset;
                            return absolute < 8
                                ? row[
                                      hash_layout.
                                          absorbed_pin_base +
                                      absolute]
                                : next[
                                      hash_layout.
                                          absorbed_pin_base +
                                      (absolute % 8)];
                        };
                    const Fp3 fp3 =
                        gf::Add(
                            coordinate(0),
                            gf::Add(
                                gf::Mul(
                                    u, coordinate(1)),
                                gf::Mul(
                                    u2,
                                    coordinate(2))));
                    selected = gf::Add(
                        selected,
                        gf::Mul(
                            row[layout.SourceSelector(
                                port, 8 + lane)],
                            fp3));
                    selected = gf::Add(
                        selected,
                        gf::Mul(
                            row[layout.SourceSelector(
                                port, 16 + lane)],
                            row[hash_layout.perm.
                                    InputCol(lane)]));
                }
                const Fp3 perm_fp3 =
                    gf::Add(
                        row[hash_layout.perm.InputCol(0)],
                        gf::Add(
                            gf::Mul(
                                u,
                                row[hash_layout.perm.
                                        InputCol(1)]),
                            gf::Mul(
                                u2,
                                row[hash_layout.perm.
                                        InputCol(2)])));
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        row[layout.SourceSelector(
                            port, 24)],
                        perm_fp3));
                for (uint32_t limb = 0;
                     limb < 4; ++limb) {
                    selected = gf::Add(
                        selected,
                        gf::Mul(
                            row[layout.SourceSelector(
                                port, 25 + limb)],
                            row[
                                hash_layout.
                                    expected_root_base +
                                limb]));
                }
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        row[layout.SourceSelector(
                            port, 29)],
                        row[bus.beta]));
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        row[layout.SourceSelector(
                            port, 30)],
                        row[bus.folded]));
                return gf::Sub(row[value], selected);
            });
        for (uint32_t field = 0;
             field < 2; ++field) {
            const uint32_t remote =
                field == 0
                ? out.layout.bus.Value(true, port)
                : out.layout.bus.Address(true, port);
            const uint32_t codec =
                field == 0
                ? codec_ctl.layout.Value(true, port)
                : codec_ctl.layout.Address(true, port);
            const uint32_t active =
                out.layout.bus.Active(true, port);
            add(
                "stage3.fixedpoint.normalized_remote.codec_consumer_alias",
                aq::AirKind::kEverywhere, 2,
                [remote, codec, active](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[active],
                        gf::Sub(
                            row[remote], row[codec]));
                });
        }
    }
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        const uint32_t running =
            lane == 0
            ? out.layout.bus.running1
            : out.layout.bus.running2;
        const NormalizedAlgAirCodecCtlLayout
            bus = out.layout.bus;
        add(
            "stage3.fixedpoint.normalized_remote.running",
            aq::AirKind::kTransition, 2,
            [bus, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                Fp3 contribution = Fp3::Zero();
                for (const bool consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign = consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedAlgAirCodecCtlLayout::
                                 kPorts;
                         ++port) {
                        contribution = gf::Add(
                            contribution,
                            gf::Mul(
                                sign,
                                gf::Mul(
                                    row[bus.Active(
                                        consumer, port)],
                                    row[lane == 0
                                        ? bus.Inverse1(
                                              consumer,
                                              port)
                                        : bus.Inverse2(
                                              consumer,
                                              port)])));
                    }
                }
                return gf::Sub(
                    next[running],
                    gf::Add(
                        row[running],
                        contribution));
            });
        add(
            "stage3.fixedpoint.normalized_remote.first",
            aq::AirKind::kFirstRow, 1,
            [running](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return row[running];
            });
        add(
            "stage3.fixedpoint.normalized_remote.terminal",
            aq::AirKind::kLastRow, 2,
            [bus, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 result = row[running];
                for (const bool consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign = consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedAlgAirCodecCtlLayout::
                                 kPorts;
                         ++port) {
                        result = gf::Add(
                            result,
                            gf::Mul(
                                sign,
                                gf::Mul(
                                    row[bus.Active(
                                        consumer, port)],
                                    row[lane == 0
                                        ? bus.Inverse1(
                                              consumer,
                                              port)
                                        : bus.Inverse2(
                                              consumer,
                                              port)])));
                    }
                }
                return result;
            });
    }

    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    out.literal_same_row_aliases = true;
    out.every_direct_opening_query_path_root_fold_owned =
        out.hash_opening_value_events != 0 &&
        out.query_index_events != 0 &&
        out.authentication_path_events != 0 &&
        out.root_events != 0 &&
        out.fold_value_events != 0 &&
        out.hash_opening_value_events +
                out.query_index_events +
                out.authentication_path_events +
                out.root_events +
                out.fold_value_events ==
            out.remote_events;
    out.dual_rational_identity_terminal_zero =
        gf::IsZero(running1) &&
        gf::IsZero(running2);
    out.derived_deep_inputs_remote_owned = false;
    out.every_codec_consumer_remote_owned = false;
    out.complete_fiat_shamir_replay_in_parent = false;
    out.recursively_consumed = false;
    out.residuals = {
        "derived_deep_input_cells_lambda_z_evals_weights_lengths",
        "scheduler_shape_and_count_cells",
        "sha256d_air_quotient_and_fri_fiat_shamir_replay",
        "normalized_ctl_child_verifier_and_terminal_commitment_bus",
    };
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations = composition.violations;
    out.valid =
        out.added_columns == 338 &&
        out.added_constraints == 86 &&
        out.remote_events != 0 &&
        out.literal_same_row_aliases &&
        out.
            every_direct_opening_query_path_root_fold_owned &&
        out.dual_rational_identity_terminal_zero &&
        out.denominator_nonzero &&
        !out.derived_deep_inputs_remote_owned &&
        !out.every_codec_consumer_remote_owned &&
        !out.complete_fiat_shamir_replay_in_parent &&
        !out.recursively_consumed &&
        out.residuals.size() == 4 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_literal_remote_exports_ok;"
          "opening_query_path_root_fold_owned;"
          "deep_scheduler_fs_ctl_residuals_open;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_literal_remote_exports_invalid";
    return out;
}

bool ValidateNormalizedAlgAirRemoteExportsV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& attachment,
    std::string* why)
{
    std::vector<NormalizedRemoteExportRef> refs;
    uint32_t deep = 0;
    uint32_t scheduler = 0;
    uint32_t fs = 0;
    if (!attachment.valid ||
        !decoder.valid ||
        !codec_ctl.valid ||
        !BuildNormalizedRemoteExportRefs(
            composition, proof, decoder.map,
            refs, deep, scheduler, fs) ||
        attachment.remote_events != refs.size() ||
        attachment.deep_tokens_remaining != deep ||
        attachment.scheduler_tokens_remaining !=
            scheduler ||
        attachment.fiat_shamir_tokens_remaining != fs ||
        attachment.parent_rows !=
            composition.combined.n_rows ||
        attachment.added_columns != 338 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.added_constraints != 86 ||
        !attachment.literal_same_row_aliases ||
        !attachment.
            every_direct_opening_query_path_root_fold_owned ||
        !attachment.
            dual_rational_identity_terminal_zero ||
        !attachment.denominator_nonzero ||
        attachment.derived_deep_inputs_remote_owned ||
        attachment.every_codec_consumer_remote_owned ||
        attachment.complete_fiat_shamir_replay_in_parent ||
        attachment.recursively_consumed ||
        attachment.residuals.size() != 4) {
        return Fail(
            why,
            "normalized_remote_export_shape");
    }
    std::vector<uint256> roots;
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_NORMALIZED_REMOTE_EXPORT_PRECOMMIT_V1";
    precommit << codec_ctl.prechallenge_commitment;
    precommit << attachment.parent_rows;
    precommit << attachment.remote_events;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 3>{
                     attachment.layout.bus.Value(
                         consumer, port),
                     attachment.layout.bus.Address(
                         consumer, port),
                     attachment.layout.bus.Active(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        composition.columns[column],
                        attachment.parent_rows);
                if (root.IsNull()) {
                    return Fail(
                        why,
                        "normalized_remote_export_precommit");
                }
                roots.push_back(root);
                precommit << root;
            }
        }
    }
    const uint256 expected_precommit =
        precommit.GetHash();
    const auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    expected_precommit,
                    label, roots,
                    {attachment.parent_rows,
                     attachment.remote_events});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    const FoldBusChallenges expected_challenges{
        challenge("normalized_remote_export_gamma1"),
        challenge("normalized_remote_export_gamma2"),
        challenge("normalized_remote_export_alpha1"),
        challenge("normalized_remote_export_alpha2"),
    };
    if (attachment.prechallenge_commitment !=
            expected_precommit ||
        !EqChallenges(
            attachment.challenges,
            expected_challenges)) {
        return Fail(
            why,
            "normalized_remote_export_challenge");
    }
    for (const auto& ref : refs) {
        if (!gf::Eq(
                NormalizedRemoteSourceValue(
                    composition, ref),
                ref.value)) {
            return Fail(
                why,
                "normalized_remote_export_literal");
        }
    }
    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0 ||
        attachment.violations != 0) {
        return Fail(
            why,
            "normalized_remote_export_air");
    }
    return true;
}

namespace {

enum class SchedulerTokenCategory : uint8_t {
    Shape,
    Fold,
    Query,
    PathLength,
};

struct NormalizedSchedulerTokenRef {
    uint32_t address{0};
    Fp3 value{};
    SchedulerTokenCategory category{
        SchedulerTokenCategory::Shape};
};

bool BuildNormalizedSchedulerTokenRefs(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirBatchCodecMapV1& map,
    std::vector<NormalizedSchedulerTokenRef>& refs)
{
    refs.clear();
    if (!composition.valid ||
        !map.valid ||
        map.codec_words == 0) {
        return false;
    }
    const auto& pi =
        composition.hash.program.public_inputs;
    const uint32_t batch_width =
        pi.child_w + 1;
    const uint32_t folds = pi.n_folds;
    const uint32_t queries =
        static_cast<uint32_t>(
            pi.query_index.size());
    if (!pi.ok ||
        pi.child_n_coeffs == 0 ||
        pi.child_n_lde == 0 ||
        pi.child_n_lde %
                pi.child_n_coeffs !=
            0 ||
        proof.batch.column_len.size() !=
            batch_width ||
        proof.batch.evals_z1.size() !=
            batch_width ||
        proof.batch.evals_z2.size() !=
            batch_width ||
        proof.batch.fold_layers.size() != folds + 1 ||
        proof.batch.fold_challenges.size() != folds ||
        proof.batch.queries.size() != queries) {
        return false;
    }
    std::vector<const NormalizedAlgAirCodecSemanticTokenV1*>
        token_at_word(map.codec_words, nullptr);
    for (const auto& token : map.semantic_tokens) {
        if (token.word_index >= token_at_word.size() ||
            token_at_word[token.word_index] != nullptr) {
            return false;
        }
        token_at_word[token.word_index] = &token;
    }
    uint32_t word = 0;
    const auto skip =
        [&](uint32_t words) {
            if (words > map.codec_words - word) {
                return false;
            }
            word += words;
            return true;
        };
    const auto append =
        [&](uint32_t expected,
            SchedulerTokenCategory category) {
            if (word >= token_at_word.size()) {
                return false;
            }
            const auto* token =
                token_at_word[word];
            if (token == nullptr ||
                token->kind !=
                    NormalizedAlgAirCodecTokenKind::U32 ||
                token->owner !=
                    NormalizedAlgAirCodecOwnerFamily::
                        Scheduler ||
                !token->
                    consumed_by_existing_verifier_chip ||
                !gf::Eq(
                    token->value,
                    Fp3::FromFp(
                        gf::FromU64(expected)))) {
                return false;
            }
            refs.push_back({
                token->address,
                Fp3::FromFp(
                    gf::FromU64(expected)),
                category,
            });
            ++word;
            return true;
        };

    // magic, version, nonce.
    if (!skip(1) || !skip(1) || !skip(2) ||
        !append(
            pi.child_n_lde /
                pi.child_n_coeffs,
            SchedulerTokenCategory::Shape) ||
        !append(
            pi.child_n_coeffs,
            SchedulerTokenCategory::Shape) ||
        !skip(8) ||
        !append(
            pi.child_n_lde,
            SchedulerTokenCategory::Shape) ||
        !append(
            batch_width,
            SchedulerTokenCategory::Shape) ||
        !skip(batch_width) ||
        !skip(18) ||
        !append(
            batch_width,
            SchedulerTokenCategory::Shape) ||
        !skip(6 * batch_width) ||
        !append(
            batch_width,
            SchedulerTokenCategory::Shape) ||
        !skip(6 * batch_width) ||
        !skip(12) ||
        !append(
            folds + 1,
            SchedulerTokenCategory::Fold)) {
        return false;
    }
    for (uint32_t layer = 0;
         layer < folds + 1; ++layer) {
        if (!skip(8) ||
            !append(
                pi.child_n_lde >> layer,
                SchedulerTokenCategory::Fold)) {
            return false;
        }
    }
    if (!skip(6) ||
        !append(
            folds,
            SchedulerTokenCategory::Fold) ||
        !skip(6 * folds) ||
        !append(
            queries,
            SchedulerTokenCategory::Query)) {
        return false;
    }
    for (uint32_t query = 0;
         query < queries; ++query) {
        if (!skip(1) ||
            !append(
                batch_width,
                SchedulerTokenCategory::Query) ||
            !skip(6 * batch_width) ||
            !append(
                pi.merkle_depth,
                SchedulerTokenCategory::PathLength) ||
            !skip(8 * pi.merkle_depth) ||
            !append(
                folds,
                SchedulerTokenCategory::Query)) {
            return false;
        }
        for (uint32_t layer = 0;
             layer < folds; ++layer) {
            const uint32_t depth =
                pi.merkle_depth - layer;
            if (!skip(2) ||
                !skip(12) ||
                !append(
                    depth,
                    SchedulerTokenCategory::PathLength) ||
                !skip(8 * depth) ||
                !append(
                    depth,
                    SchedulerTokenCategory::PathLength) ||
                !skip(8 * depth)) {
                return false;
            }
        }
    }
    if (word != map.codec_words) {
        return false;
    }
    uint32_t expected_scheduler = 0;
    for (const auto& token : map.semantic_tokens) {
        expected_scheduler +=
            token.owner ==
                    NormalizedAlgAirCodecOwnerFamily::
                        Scheduler &&
                token.
                    consumed_by_existing_verifier_chip
            ? 1
            : 0;
    }
    if (refs.size() != expected_scheduler) {
        return false;
    }
    std::vector<uint32_t> addresses;
    addresses.reserve(refs.size());
    for (const auto& ref : refs) {
        addresses.push_back(ref.address);
    }
    std::sort(addresses.begin(), addresses.end());
    return !refs.empty() &&
        std::adjacent_find(
            addresses.begin(), addresses.end()) ==
            addresses.end();
}

} // namespace

NormalizedAlgAirSchedulerTokenAttachmentV1
AttachNormalizedAlgAirSchedulerTokensV1(
    FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports)
{
    NormalizedAlgAirSchedulerTokenAttachmentV1 out;
    out.layout =
        NormalizedAlgAirCodecCtlLayout(
            composition.combined.n_columns);
    out.parent_rows =
        composition.combined.n_rows;
    out.added_columns =
        out.layout.End() - out.layout.base;
    out.constraint_base =
        static_cast<uint32_t>(
            composition.combined.constraints.size());
    std::vector<NormalizedSchedulerTokenRef> refs;
    std::vector<NormalizedCodecSemanticEvent> all_events;
    if (!remote_exports.valid ||
        remote_exports.layout.End() !=
            out.layout.base ||
        !BuildNormalizedSchedulerTokenRefs(
            composition, proof, decoder.map,
            refs) ||
        !BuildNormalizedCodecSemanticEvents(
            decoder.map, all_events) ||
        refs.size() >
            uint64_t{out.parent_rows} *
                NormalizedAlgAirCodecCtlLayout::kPorts) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_scheduler_token_map";
        return out;
    }
    out.scheduler_tokens =
        static_cast<uint32_t>(refs.size());
    std::vector<uint32_t> event_ordinal(
        decoder.map.semantic_tokens.size() + 1,
        UINT32_MAX);
    for (uint32_t ordinal = 0;
         ordinal < all_events.size();
         ++ordinal) {
        if (all_events[ordinal].address >=
                event_ordinal.size()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_scheduler_event_address";
            return out;
        }
        event_ordinal[
            all_events[ordinal].address] = ordinal;
    }

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns =
        out.layout.End();
    for (uint32_t ordinal = 0;
         ordinal < refs.size(); ++ordinal) {
        const auto& ref = refs[ordinal];
        const uint32_t producer_row =
            ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t producer_port =
            ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        composition.columns[
            out.layout.Value(
                false, producer_port)]
            [producer_row] = ref.value;
        composition.columns[
            out.layout.Address(
                false, producer_port)]
            [producer_row] =
                Fp3::FromFp(
                    gf::FromU64(ref.address));
        composition.columns[
            out.layout.Active(
                false, producer_port)]
            [producer_row] = Fp3::One();
        const uint32_t codec_ordinal =
            event_ordinal[ref.address];
        if (codec_ordinal == UINT32_MAX) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_scheduler_codec_event";
            return out;
        }
        const uint32_t consumer_row =
            codec_ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t consumer_port =
            codec_ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        composition.columns[
            out.layout.Value(
                true, consumer_port)]
            [consumer_row] =
                composition.columns[
                    codec_ctl.layout.Value(
                        true, consumer_port)]
                    [consumer_row];
        composition.columns[
            out.layout.Address(
                true, consumer_port)]
            [consumer_row] =
                composition.columns[
                    codec_ctl.layout.Address(
                        true, consumer_port)]
                    [consumer_row];
        composition.columns[
            out.layout.Active(
                true, consumer_port)]
            [consumer_row] = Fp3::One();
        switch (ref.category) {
        case SchedulerTokenCategory::Shape:
            ++out.shape_tokens;
            break;
        case SchedulerTokenCategory::Fold:
            ++out.fold_schedule_tokens;
            break;
        case SchedulerTokenCategory::Query:
            ++out.query_schedule_tokens;
            break;
        case SchedulerTokenCategory::PathLength:
            ++out.path_length_tokens;
            break;
        }
    }

    std::vector<uint256> roots;
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_NORMALIZED_SCHEDULER_TOKEN_PRECOMMIT_V1";
    precommit << codec_ctl.prechallenge_commitment;
    precommit << out.parent_rows;
    precommit << out.scheduler_tokens;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 3>{
                     out.layout.Value(
                         consumer, port),
                     out.layout.Address(
                         consumer, port),
                     out.layout.Active(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        composition.columns[column],
                        out.parent_rows);
                if (root.IsNull()) {
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "normalized_scheduler_precommit";
                    return out;
                }
                roots.push_back(root);
                precommit << root;
            }
        }
    }
    out.prechallenge_commitment =
        precommit.GetHash();
    const auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    out.prechallenge_commitment,
                    label, roots,
                    {out.parent_rows,
                     out.scheduler_tokens});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    out.challenges.gamma1 =
        challenge("normalized_scheduler_gamma1");
    out.challenges.gamma2 =
        challenge("normalized_scheduler_gamma2");
    out.challenges.alpha1 =
        challenge("normalized_scheduler_alpha1");
    out.challenges.alpha2 =
        challenge("normalized_scheduler_alpha2");

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    out.denominator_nonzero = true;
    for (uint32_t row = 0;
         row < out.parent_rows; ++row) {
        composition.columns[
            out.layout.running1][row] = running1;
        composition.columns[
            out.layout.running2][row] = running2;
        Fp3 contribution1 = Fp3::Zero();
        Fp3 contribution2 = Fp3::Zero();
        for (const bool consumer :
             std::array<bool, 2>{false, true}) {
            const Fp3 sign = consumer
                ? Fp3::FromFp(gf::Neg(1))
                : Fp3::One();
            for (uint32_t port = 0;
                 port <
                     NormalizedAlgAirCodecCtlLayout::kPorts;
                 ++port) {
                if (gf::IsZero(
                        composition.columns[
                            out.layout.Active(
                                consumer, port)]
                            [row])) {
                    continue;
                }
                const Fp3 address =
                    composition.columns[
                        out.layout.Address(
                            consumer, port)][row];
                const Fp3 value =
                    composition.columns[
                        out.layout.Value(
                            consumer, port)][row];
                const Fp3 d1 =
                    gf::Sub(
                        out.challenges.alpha1,
                        gf::Add(
                            address,
                            gf::Mul(
                                out.challenges.gamma1,
                                value)));
                const Fp3 d2 =
                    gf::Sub(
                        out.challenges.alpha2,
                        gf::Add(
                            address,
                            gf::Mul(
                                out.challenges.gamma2,
                                value)));
                if (gf::IsZero(d1) ||
                    gf::IsZero(d2)) {
                    out.denominator_nonzero = false;
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "normalized_scheduler_zero_denominator";
                    return out;
                }
                const Fp3 inv1 = gf::Inv(d1);
                const Fp3 inv2 = gf::Inv(d2);
                composition.columns[
                    out.layout.Inverse1(
                        consumer, port)][row] = inv1;
                composition.columns[
                    out.layout.Inverse2(
                        consumer, port)][row] = inv2;
                contribution1 = gf::Add(
                    contribution1,
                    gf::Mul(sign, inv1));
                contribution2 = gf::Add(
                    contribution2,
                    gf::Mul(sign, inv2));
            }
        }
        running1 = gf::Add(
            running1, contribution1);
        running2 = gf::Add(
            running2, contribution2);
    }

    // The scheduler side is canonical public-program data. Consumer values
    // remain witness cells, equality-aliased to the codec below.
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        for (const uint32_t column :
             std::array<uint32_t, 3>{
                 out.layout.Value(false, port),
                 out.layout.Address(false, port),
                 out.layout.Active(false, port)}) {
            composition.combined.preprocessed.emplace_back(
                column,
                composition.columns[column]);
        }
        for (const uint32_t column :
             std::array<uint32_t, 2>{
                 out.layout.Address(true, port),
                 out.layout.Active(true, port)}) {
            composition.combined.preprocessed.emplace_back(
                column,
                composition.columns[column]);
        }
    }

    const auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            const uint32_t active =
                out.layout.Active(consumer, port);
            add(
                "stage3.fixedpoint.normalized_scheduler.active_boolean",
                aq::AirKind::kEverywhere, 2,
                [active](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[active],
                        gf::Sub(
                            row[active],
                            Fp3::One()));
                });
            for (uint32_t lane = 0;
                 lane < 2; ++lane) {
                const uint32_t address =
                    out.layout.Address(consumer, port);
                const uint32_t value =
                    out.layout.Value(consumer, port);
                const uint32_t inverse =
                    lane == 0
                    ? out.layout.Inverse1(
                          consumer, port)
                    : out.layout.Inverse2(
                          consumer, port);
                const Fp3 gamma = lane == 0
                    ? out.challenges.gamma1
                    : out.challenges.gamma2;
                const Fp3 alpha = lane == 0
                    ? out.challenges.alpha1
                    : out.challenges.alpha2;
                add(
                    "stage3.fixedpoint.normalized_scheduler.inverse",
                    aq::AirKind::kEverywhere, 2,
                    [active, address, value,
                     inverse, gamma, alpha](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Sub(
                            row[active],
                            gf::Mul(
                                row[inverse],
                                gf::Sub(
                                    alpha,
                                    gf::Add(
                                        row[address],
                                        gf::Mul(
                                            gamma,
                                            row[value])))));
                    });
            }
        }
    }
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        const uint32_t active =
            out.layout.Active(true, port);
        for (uint32_t field = 0;
             field < 2; ++field) {
            const uint32_t scheduler =
                field == 0
                ? out.layout.Value(true, port)
                : out.layout.Address(true, port);
            const uint32_t codec =
                field == 0
                ? codec_ctl.layout.Value(true, port)
                : codec_ctl.layout.Address(true, port);
            add(
                "stage3.fixedpoint.normalized_scheduler.codec_alias",
                aq::AirKind::kEverywhere, 2,
                [active, scheduler, codec](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[active],
                        gf::Sub(
                            row[scheduler],
                            row[codec]));
                });
        }
    }
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        const uint32_t running =
            lane == 0
            ? out.layout.running1
            : out.layout.running2;
        const NormalizedAlgAirCodecCtlLayout
            layout = out.layout;
        add(
            "stage3.fixedpoint.normalized_scheduler.running",
            aq::AirKind::kTransition, 2,
            [layout, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                Fp3 contribution = Fp3::Zero();
                for (const bool consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign = consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedAlgAirCodecCtlLayout::
                                 kPorts;
                         ++port) {
                        contribution = gf::Add(
                            contribution,
                            gf::Mul(
                                sign,
                                gf::Mul(
                                    row[layout.Active(
                                        consumer, port)],
                                    row[lane == 0
                                        ? layout.Inverse1(
                                              consumer,
                                              port)
                                        : layout.Inverse2(
                                              consumer,
                                              port)])));
                    }
                }
                return gf::Sub(
                    next[running],
                    gf::Add(
                        row[running],
                        contribution));
            });
        add(
            "stage3.fixedpoint.normalized_scheduler.first",
            aq::AirKind::kFirstRow, 1,
            [running](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return row[running];
            });
        add(
            "stage3.fixedpoint.normalized_scheduler.terminal",
            aq::AirKind::kLastRow, 2,
            [layout, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 result = row[running];
                for (const bool consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign = consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedAlgAirCodecCtlLayout::
                                 kPorts;
                         ++port) {
                        result = gf::Add(
                            result,
                            gf::Mul(
                                sign,
                                gf::Mul(
                                    row[layout.Active(
                                        consumer, port)],
                                    row[lane == 0
                                        ? layout.Inverse1(
                                              consumer,
                                              port)
                                        : layout.Inverse2(
                                              consumer,
                                              port)])));
                    }
                }
                return result;
            });
    }

    const auto& pi =
        composition.hash.program.public_inputs;
    out.sha256d_challenge_outputs_remaining =
        6 + pi.n_folds +
        pi.query_index.size();
    out.sha256d_nonce_inputs_remaining = 1;
    out.ctl_child_terminal_items_remaining = 1;
    out.added_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size()) -
        out.constraint_base;
    out.values_derived_from_public_program = true;
    out.exact_scheduler_addresses = true;
    out.every_scheduler_token_owned =
        out.scheduler_tokens != 0 &&
        out.shape_tokens +
                out.fold_schedule_tokens +
                out.query_schedule_tokens +
                out.path_length_tokens ==
            out.scheduler_tokens;
    out.dual_rational_identity_terminal_zero =
        gf::IsZero(running1) &&
        gf::IsZero(running2);
    out.complete_fiat_shamir_replay_in_parent = false;
    out.ctl_commitment_sourced_from_child_verifier =
        false;
    out.recursively_consumed = false;
    out.residuals = {
        "deep_derivation_chip_input_and_output_relations",
        "sha256d_air_quotient_and_fri_fiat_shamir_replay",
        "normalized_ctl_child_verifier_and_terminal_commitment_bus",
    };
    composition.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.violations = composition.violations;
    out.valid =
        out.added_columns == 90 &&
        out.added_constraints == 70 &&
        out.values_derived_from_public_program &&
        out.exact_scheduler_addresses &&
        out.every_scheduler_token_owned &&
        out.dual_rational_identity_terminal_zero &&
        out.denominator_nonzero &&
        out.sha256d_challenge_outputs_remaining != 0 &&
        out.sha256d_nonce_inputs_remaining == 1 &&
        out.ctl_child_terminal_items_remaining == 1 &&
        !out.complete_fiat_shamir_replay_in_parent &&
        !out.ctl_commitment_sourced_from_child_verifier &&
        !out.recursively_consumed &&
        out.residuals.size() == 3 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_scheduler_public_program_ownership_ok;"
          "all_shape_count_path_length_tokens_logup_bound;"
          "deep_fs_ctl_residuals_open;"
          "recursive_counters_unchanged"
        : "stage3:recursive_fixedpoint:"
          "normalized_scheduler_token_invalid";
    return out;
}

bool ValidateNormalizedAlgAirSchedulerTokensV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports,
    const NormalizedAlgAirSchedulerTokenAttachmentV1& attachment,
    std::string* why)
{
    std::vector<NormalizedSchedulerTokenRef> refs;
    if (!attachment.valid ||
        !decoder.valid ||
        !codec_ctl.valid ||
        !remote_exports.valid ||
        !BuildNormalizedSchedulerTokenRefs(
            composition, proof, decoder.map,
            refs) ||
        attachment.scheduler_tokens != refs.size() ||
        attachment.parent_rows !=
            composition.combined.n_rows ||
        attachment.added_columns != 90 ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.constraint_base +
                attachment.added_constraints !=
            composition.combined.constraints.size() ||
        attachment.added_constraints != 70 ||
        !attachment.values_derived_from_public_program ||
        !attachment.exact_scheduler_addresses ||
        !attachment.every_scheduler_token_owned ||
        !attachment.
            dual_rational_identity_terminal_zero ||
        !attachment.denominator_nonzero ||
        attachment.complete_fiat_shamir_replay_in_parent ||
        attachment.
            ctl_commitment_sourced_from_child_verifier ||
        attachment.recursively_consumed ||
        attachment.residuals.size() != 3) {
        return Fail(
            why,
            "normalized_scheduler_token_shape");
    }
    uint32_t shape = 0;
    uint32_t fold = 0;
    uint32_t query = 0;
    uint32_t path = 0;
    for (const auto& ref : refs) {
        switch (ref.category) {
        case SchedulerTokenCategory::Shape:
            ++shape;
            break;
        case SchedulerTokenCategory::Fold:
            ++fold;
            break;
        case SchedulerTokenCategory::Query:
            ++query;
            break;
        case SchedulerTokenCategory::PathLength:
            ++path;
            break;
        }
    }
    const auto& pi =
        composition.hash.program.public_inputs;
    if (attachment.shape_tokens != shape ||
        attachment.fold_schedule_tokens != fold ||
        attachment.query_schedule_tokens != query ||
        attachment.path_length_tokens != path ||
        attachment.sha256d_challenge_outputs_remaining !=
            6 + pi.n_folds +
                pi.query_index.size() ||
        attachment.sha256d_nonce_inputs_remaining != 1 ||
        attachment.ctl_child_terminal_items_remaining !=
            1) {
        return Fail(
            why,
            "normalized_scheduler_token_inventory");
    }

    std::vector<NormalizedCodecSemanticEvent> all_events;
    if (!BuildNormalizedCodecSemanticEvents(
            decoder.map, all_events)) {
        return Fail(
            why,
            "normalized_scheduler_token_events");
    }
    std::vector<uint32_t> event_ordinal(
        decoder.map.semantic_tokens.size() + 1,
        UINT32_MAX);
    for (uint32_t ordinal = 0;
         ordinal < all_events.size();
         ++ordinal) {
        event_ordinal[
            all_events[ordinal].address] = ordinal;
    }
    std::vector<std::vector<Fp3>> expected(
        attachment.added_columns,
        std::vector<Fp3>(
            attachment.parent_rows,
            Fp3::Zero()));
    const auto local =
        [&](uint32_t column)
            -> std::vector<Fp3>& {
            return expected[
                column - attachment.layout.base];
        };
    for (uint32_t ordinal = 0;
         ordinal < refs.size(); ++ordinal) {
        const auto& ref = refs[ordinal];
        const uint32_t producer_row =
            ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t producer_port =
            ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        local(attachment.layout.Value(
            false, producer_port))[producer_row] =
                ref.value;
        local(attachment.layout.Address(
            false, producer_port))[producer_row] =
                Fp3::FromFp(
                    gf::FromU64(ref.address));
        local(attachment.layout.Active(
            false, producer_port))[producer_row] =
                Fp3::One();
        const uint32_t codec_ordinal =
            event_ordinal[ref.address];
        const uint32_t consumer_row =
            codec_ordinal /
                NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t consumer_port =
            codec_ordinal %
                NormalizedAlgAirCodecCtlLayout::kPorts;
        local(attachment.layout.Value(
            true, consumer_port))[consumer_row] =
                ref.value;
        local(attachment.layout.Address(
            true, consumer_port))[consumer_row] =
                Fp3::FromFp(
                    gf::FromU64(ref.address));
        local(attachment.layout.Active(
            true, consumer_port))[consumer_row] =
                Fp3::One();
    }
    std::vector<uint256> roots;
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_NORMALIZED_SCHEDULER_TOKEN_PRECOMMIT_V1";
    precommit << codec_ctl.prechallenge_commitment;
    precommit << attachment.parent_rows;
    precommit << attachment.scheduler_tokens;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            for (const uint32_t column :
                 std::array<uint32_t, 3>{
                     attachment.layout.Value(
                         consumer, port),
                     attachment.layout.Address(
                         consumer, port),
                     attachment.layout.Active(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        local(column),
                        attachment.parent_rows);
                if (root.IsNull()) {
                    return Fail(
                        why,
                        "normalized_scheduler_precommit");
                }
                roots.push_back(root);
                precommit << root;
            }
        }
    }
    const uint256 expected_precommit =
        precommit.GetHash();
    const auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    expected_precommit,
                    label, roots,
                    {attachment.parent_rows,
                     attachment.scheduler_tokens});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    const FoldBusChallenges expected_challenges{
        challenge("normalized_scheduler_gamma1"),
        challenge("normalized_scheduler_gamma2"),
        challenge("normalized_scheduler_alpha1"),
        challenge("normalized_scheduler_alpha2"),
    };
    if (attachment.prechallenge_commitment !=
            expected_precommit ||
        !EqChallenges(
            attachment.challenges,
            expected_challenges)) {
        return Fail(
            why,
            "normalized_scheduler_challenge");
    }
    for (uint32_t port = 0;
         port <
             NormalizedAlgAirCodecCtlLayout::kPorts;
         ++port) {
        for (const uint32_t column :
             std::array<uint32_t, 5>{
                 attachment.layout.Value(false, port),
                 attachment.layout.Address(false, port),
                 attachment.layout.Active(false, port),
                 attachment.layout.Address(true, port),
                 attachment.layout.Active(true, port)}) {
            const auto pin = std::find_if(
                composition.combined.preprocessed.begin(),
                composition.combined.preprocessed.end(),
                [column](const auto& item) {
                    return item.first == column;
                });
            if (pin ==
                    composition.combined.preprocessed.end() ||
                pin->second.size() !=
                    attachment.parent_rows ||
                !std::equal(
                    pin->second.begin(),
                    pin->second.end(),
                    local(column).begin(),
                    [](const Fp3& lhs,
                       const Fp3& rhs) {
                        return gf::Eq(lhs, rhs);
                    })) {
                return Fail(
                    why,
                    "normalized_scheduler_public_pin");
            }
        }
    }
    for (uint32_t row = 0;
         row < attachment.parent_rows;
         ++row) {
        for (const bool consumer :
             std::array<bool, 2>{false, true}) {
            for (uint32_t port = 0;
                 port <
                     NormalizedAlgAirCodecCtlLayout::kPorts;
                 ++port) {
                for (const uint32_t column :
                     std::array<uint32_t, 3>{
                         attachment.layout.Value(
                             consumer, port),
                         attachment.layout.Address(
                             consumer, port),
                         attachment.layout.Active(
                             consumer, port)}) {
                    if (!gf::Eq(
                            composition.columns[column][row],
                            local(column)[row])) {
                        return Fail(
                            why,
                            "normalized_scheduler_token_event");
                    }
                }
            }
        }
    }
    if (CountHashOpeningViolations(
            composition.combined,
            composition.columns) != 0 ||
        attachment.violations != 0) {
        return Fail(
            why,
            "normalized_scheduler_token_air");
    }
    return true;
}

NormalizedDeepDerivationPlanV1
AssessNormalizedDeepDerivation64PlanV1(
    const AlgAirProof& proof,
    uint32_t available_parent_rows,
    uint32_t current_parent_columns)
{
    NormalizedDeepDerivationPlanV1 out;
    out.batch_width =
        static_cast<uint32_t>(
            proof.batch.column_len.size());
    out.queries =
        static_cast<uint32_t>(
            proof.batch.queries.size());
    out.available_parent_rows =
        available_parent_rows;
    out.current_parent_columns =
        current_parent_columns;
    out.shared_power_columns =
        kNormalizedDeepSharedPowerColumns;
    out.columns_per_port =
        kNormalizedDeepColumnsPerPort;
    out.bus_columns =
        kNormalizedDeepInputReadOutputBusColumns;
    out.added_columns =
        kNormalizedDeepDerivationAddedColumns;
    if (out.batch_width == 0 ||
        out.queries == 0 ||
        proof.batch.evals_z1.size() !=
            out.batch_width ||
        proof.batch.evals_z2.size() !=
            out.batch_width ||
        proof.batch.n_coeffs == 0 ||
        available_parent_rows < 2 ||
        current_parent_columns >
            kRCFri3AlgBatchMaxColumns ||
        current_parent_columns >
            std::numeric_limits<uint32_t>::max() -
                out.added_columns) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_plan_shape";
        return out;
    }
    out.query_item_sites =
        uint64_t{out.batch_width} * out.queries;
    // All ports on one row share one parameterized query-x table, so a row
    // may not straddle queries. The three eight-lane LogUp buses can require
    // more rows than the arithmetic ports at narrow endpoint-28 width.
    const uint64_t derivation_rows =
        uint64_t{out.queries} *
        CeilDiv(
            out.batch_width,
            kNormalizedDeepDerivationPorts);
    out.input_table_tokens =
        uint64_t{5} +
        3 * uint64_t{out.batch_width} +
        out.queries;
    // Seven per-site reads plus w1/w2 once per query.
    out.repeated_input_reads =
        7 * out.query_item_sites +
        2 * uint64_t{out.queries};
    out.ux_output_events =
        out.query_item_sites;
    out.inverse_output_events =
        2 * uint64_t{out.queries};
    out.aggregate_output_events =
        2 * uint64_t{out.queries};
    const uint64_t input_bus_rows =
        CeilDiv(
            std::max(
                out.input_table_tokens,
                out.repeated_input_reads),
            NormalizedDeepLogUpLayoutV1::
                kEventPorts);
    const uint64_t read_bus_rows =
        CeilDiv(
            std::max<uint64_t>(
                out.queries,
                out.query_item_sites),
            NormalizedDeepLogUpLayoutV1::
                kEventPorts);
    const uint64_t output_bus_rows =
        CeilDiv(
            out.query_item_sites +
                5 * uint64_t{out.queries},
            NormalizedDeepLogUpLayoutV1::
                kEventPorts);
    const uint64_t rows =
        std::max(
            {derivation_rows, input_bus_rows,
             read_bus_rows, output_bus_rows});
    if (rows >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_plan_rows";
        return out;
    }
    out.active_rows =
        static_cast<uint32_t>(rows);
    out.final_parent_columns =
        current_parent_columns +
        out.added_columns;
    out.shared_z_power_tables = true;
    out.per_query_x_power_table = true;
    out.shift_binary_accumulators = true;
    out.lambda_item_recurrence = true;
    out.input_multiplicity_logup_required = true;
    out.output_logup_required = true;
    out.row_cap_supported =
        out.active_rows <= available_parent_rows;
    out.column_cap_supported =
        out.final_parent_columns <=
            kRCFri3AlgBatchMaxColumns;
    out.executable = false;
    out.valid =
        out.row_cap_supported &&
        out.column_cap_supported &&
        out.query_item_sites != 0 &&
        out.input_table_tokens != 0 &&
        out.ux_output_events ==
            out.query_item_sites &&
        !out.executable;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_deep64_exact_shape_fits;"
          "shared_power_tables_required;"
          "constraints_and_witness_builder_open"
        : "stage3:recursive_fixedpoint:"
          "normalized_deep64_shape_exceeds_cap";
    return out;
}

namespace {

struct NormalizedDeepEventV1 {
    uint64_t address{0};
    Fp3 value{};
    uint64_t multiplicity{1};
};

struct NormalizedDeepSiteV1 {
    uint32_t query{0};
    uint32_t item{0};
    uint32_t shift{0};
    Fp3 x{};
    Fp3 lambda_power{};
    Fp3 x_shift{};
    Fp3 z1_shift{};
    Fp3 z2_shift{};
    Fp3 v1_running{};
    Fp3 v2_running{};
    Fp3 ux_running{};
    Fp3 invd1{};
    Fp3 invd2{};
    Fp3 deep{};
    Fp3 opened{};
    bool output{false};
};

struct NormalizedDeepEventFamiliesV1 {
    std::array<
        std::vector<NormalizedDeepEventV1>, 3>
        producer;
    std::array<
        std::vector<NormalizedDeepEventV1>, 3>
        consumer;
};

bool BuildNormalizedDeepSitesV1(
    const AlgAirProof& proof,
    std::vector<NormalizedDeepSiteV1>& sites,
    NormalizedDeepEventFamiliesV1& events)
{
    sites.clear();
    events = {};
    const auto& batch = proof.batch;
    const uint32_t width =
        static_cast<uint32_t>(
            batch.column_len.size());
    const uint32_t queries =
        static_cast<uint32_t>(
            batch.queries.size());
    if (batch.version !=
            kRCFri3AlgActiveBatchProofVersion ||
        width == 0 ||
        queries == 0 ||
        batch.evals_z1.size() != width ||
        batch.evals_z2.size() != width ||
        batch.n_coeffs < 2 ||
        (batch.n_coeffs &
         (batch.n_coeffs - 1)) != 0 ||
        batch.fold_layers.empty() ||
        batch.fold_layers[0].n_leaves !=
            batch.n_coeffs * kRCFriBlowup) {
        return false;
    }
    const uint64_t site_count =
        uint64_t{width} * queries;
    if (site_count >
        std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    sites.reserve(
        static_cast<size_t>(site_count));

    // Input-table addresses are collision-free and family separated.
    constexpr uint64_t GLOBAL_BASE = 1;
    constexpr uint64_t ITEM_BASE = 1024;
    constexpr uint64_t QUERY_BASE = 1ULL << 24;
    const std::array<Fp3, 5> globals{
        batch.lambda, batch.z1, batch.z2,
        batch.w1, batch.w2};
    for (uint32_t global = 0;
         global < globals.size(); ++global) {
        const uint64_t multiplicity =
            global < 3
            ? site_count
            : queries;
        events.producer[0].push_back({
            GLOBAL_BASE + global,
            globals[global],
            multiplicity,
        });
    }
    for (uint32_t item = 0;
         item < width; ++item) {
        events.producer[0].push_back({
            ITEM_BASE + 3 * uint64_t{item},
            Fp3::FromFp(gf::FromU64(
                batch.column_len[item])),
            queries,
        });
        events.producer[0].push_back({
            ITEM_BASE + 3 * uint64_t{item} + 1,
            batch.evals_z1[item], queries,
        });
        events.producer[0].push_back({
            ITEM_BASE + 3 * uint64_t{item} + 2,
            batch.evals_z2[item], queries,
        });
    }

    for (uint32_t query = 0;
         query < queries; ++query) {
        const auto& opened =
            batch.queries[query];
        if (opened.index >=
                batch.fold_layers[0].n_leaves ||
            opened.row.values.size() != width ||
            opened.steps.empty()) {
            return false;
        }
        const Fp3 x =
            DomainPoint(
                batch.fold_layers[0].n_leaves,
                opened.index);
        const Fp3 d1 =
            gf::Sub(x, batch.z1);
        const Fp3 d2 =
            gf::Sub(x, batch.z2);
        if (gf::IsZero(d1) ||
            gf::IsZero(d2)) {
            return false;
        }
        const Fp3 invd1 = gf::Inv(d1);
        const Fp3 invd2 = gf::Inv(d2);
        events.producer[0].push_back({
            QUERY_BASE + query,
            Fp3::FromFp(
                gf::FromU64(opened.index)),
            width,
        });
        events.producer[1].push_back({
            uint64_t{query} + 1,
            x, width,
        });
        Fp3 lambda_power = Fp3::One();
        Fp3 v1 = Fp3::Zero();
        Fp3 v2 = Fp3::Zero();
        Fp3 ux = Fp3::Zero();
        for (uint32_t item = 0;
             item < width; ++item) {
            if (batch.column_len[item] == 0 ||
                batch.column_len[item] >
                    batch.n_coeffs) {
                return false;
            }
            const uint32_t shift =
                batch.n_coeffs -
                batch.column_len[item];
            const Fp3 x_shift =
                PowFp3(x, shift);
            const Fp3 z1_shift =
                PowFp3(batch.z1, shift);
            const Fp3 z2_shift =
                PowFp3(batch.z2, shift);
            v1 = gf::Add(
                v1,
                gf::Mul(
                    gf::Mul(
                        lambda_power,
                        z1_shift),
                    batch.evals_z1[item]));
            v2 = gf::Add(
                v2,
                gf::Mul(
                    gf::Mul(
                        lambda_power,
                        z2_shift),
                    batch.evals_z2[item]));
            ux = gf::Add(
                ux,
                gf::Mul(
                    gf::Mul(
                        lambda_power,
                        x_shift),
                    opened.row.values[item]));
            const bool output =
                item + 1 == width;
            const Fp3 deep =
                output
                ? gf::Add(
                      gf::Mul(
                          batch.w1,
                          gf::Mul(
                              gf::Sub(ux, v1),
                              invd1)),
                      gf::Mul(
                          batch.w2,
                          gf::Mul(
                              gf::Sub(ux, v2),
                              invd2)))
                : Fp3::Zero();
            Fp3 opened_deep = Fp3::Zero();
            if (output) {
                const uint32_t half =
                    batch.fold_layers[0]
                        .n_leaves /
                    2;
                opened_deep =
                    opened.index < half
                    ? opened.steps[0].even
                    : opened.steps[0].odd;
                if (!gf::Eq(
                        deep, opened_deep)) {
                    return false;
                }
            }
            sites.push_back({
                query, item, shift, x,
                lambda_power, x_shift,
                z1_shift, z2_shift,
                v1, v2, ux, invd1, invd2,
                deep, opened_deep, output,
            });

            const uint64_t site =
                uint64_t{query} * width + item;
            for (const auto& event :
                 std::array<NormalizedDeepEventV1, 7>{
                     NormalizedDeepEventV1{
                         GLOBAL_BASE, batch.lambda, 1},
                     NormalizedDeepEventV1{
                         GLOBAL_BASE + 1, batch.z1, 1},
                     NormalizedDeepEventV1{
                         GLOBAL_BASE + 2, batch.z2, 1},
                     NormalizedDeepEventV1{
                         ITEM_BASE + 3 * uint64_t{item},
                         Fp3::FromFp(gf::FromU64(
                             batch.column_len[item])),
                         1},
                     NormalizedDeepEventV1{
                         ITEM_BASE + 3 * uint64_t{item} + 1,
                         batch.evals_z1[item], 1},
                     NormalizedDeepEventV1{
                         ITEM_BASE + 3 * uint64_t{item} + 2,
                         batch.evals_z2[item], 1},
                     NormalizedDeepEventV1{
                         QUERY_BASE + query,
                         Fp3::FromFp(
                             gf::FromU64(opened.index)),
                         1}}) {
                events.consumer[0].push_back(event);
            }
            events.consumer[1].push_back({
                uint64_t{query} + 1, x, 1});
            // U-prefix output for every item.
            events.producer[2].push_back({
                site + 1, ux, 1});
            events.consumer[2].push_back({
                site + 1, ux, 1});
            lambda_power =
                gf::Mul(
                    lambda_power,
                    batch.lambda);
        }
        // w1/w2 are read once by the final query aggregation.
        events.consumer[0].push_back({
            GLOBAL_BASE + 3, batch.w1, 1});
        events.consumer[0].push_back({
            GLOBAL_BASE + 4, batch.w2, 1});
        const uint64_t output_base =
            site_count +
            5 * uint64_t{query} + 1;
        const Fp3 deep =
            sites.back().deep;
        for (const auto& event :
             std::array<NormalizedDeepEventV1, 5>{
                 NormalizedDeepEventV1{
                     output_base, v1, 1},
                 NormalizedDeepEventV1{
                     output_base + 1, v2, 1},
                 NormalizedDeepEventV1{
                     output_base + 2, invd1, 1},
                 NormalizedDeepEventV1{
                     output_base + 3, invd2, 1},
                 NormalizedDeepEventV1{
                     output_base + 4, deep, 1}}) {
            events.producer[2].push_back(event);
            events.consumer[2].push_back(event);
        }
    }
    return sites.size() == site_count;
}

bool DeepEventFits(
    const std::vector<NormalizedDeepEventV1>& events,
    uint32_t rows)
{
    return events.size() <=
        uint64_t{rows} *
            NormalizedDeepLogUpLayoutV1::
                kEventPorts;
}

uint256 DeepBusPrecommitV1(
    const aq::AirConstraintSystem<Fp3>& chip,
    const std::vector<std::vector<Fp3>>& columns,
    const NormalizedDeepLogUpLayoutV1& layout,
    const char* label,
    std::vector<uint256>* roots_out)
{
    std::vector<uint256> roots;
    roots.reserve(
        6 *
        NormalizedDeepLogUpLayoutV1::
            kEventPorts);
    HashWriter writer;
    writer <<
        "BTX_RC_STAGE3_NORMALIZED_DEEP_LOGUP_PRECOMMIT_V1";
    writer << std::string(label);
    writer << chip.n_rows;
    for (const bool consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedDeepLogUpLayoutV1::
                     kEventPorts;
             ++port) {
            for (uint32_t column :
                 std::array<uint32_t, 3>{
                     layout.Value(consumer, port),
                     layout.Address(consumer, port),
                     layout.Multiplicity(
                         consumer, port)}) {
                const uint256 root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        columns[column],
                        chip.n_rows);
                if (root.IsNull()) return {};
                roots.push_back(root);
                writer << root;
            }
        }
    }
    if (roots_out != nullptr) {
        *roots_out = roots;
    }
    return writer.GetHash();
}

FoldBusChallenges DeepBusChallengesV1(
    const uint256& precommit,
    const std::vector<uint256>& roots,
    const char* label,
    uint32_t rows,
    uint32_t producer_events,
    uint32_t consumer_events)
{
    const auto challenge =
        [&](const char* suffix) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    precommit, suffix, roots,
                    {rows, producer_events,
                     consumer_events});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    const std::string base(label);
    return {
        challenge(
            (base + ".gamma1").c_str()),
        challenge(
            (base + ".gamma2").c_str()),
        challenge(
            (base + ".alpha1").c_str()),
        challenge(
            (base + ".alpha2").c_str()),
    };
}

bool PopulateNormalizedDeepBusV1(
    NormalizedDeepDerivationAttachmentV1& out,
    uint32_t family,
    const char* label,
    const NormalizedDeepLogUpLayoutV1& layout,
    const std::vector<NormalizedDeepEventV1>& producer,
    const std::vector<NormalizedDeepEventV1>& consumer)
{
    if (family >= 3 ||
        !DeepEventFits(producer, out.trace_rows) ||
        !DeepEventFits(consumer, out.trace_rows)) {
        return false;
    }
    for (const bool is_consumer :
         std::array<bool, 2>{false, true}) {
        const auto& source =
            is_consumer ? consumer : producer;
        for (uint32_t ordinal = 0;
             ordinal < source.size();
             ++ordinal) {
            const uint32_t row =
                ordinal /
                NormalizedDeepLogUpLayoutV1::
                    kEventPorts;
            const uint32_t port =
                ordinal %
                NormalizedDeepLogUpLayoutV1::
                    kEventPorts;
            const auto& event = source[ordinal];
            if (event.address == 0 ||
                event.multiplicity == 0) {
                return false;
            }
            out.columns[
                layout.Value(
                    is_consumer, port)][row] =
                event.value;
            out.columns[
                layout.Address(
                    is_consumer, port)][row] =
                Fp3::FromFp(
                    gf::FromU64(event.address));
            out.columns[
                layout.Multiplicity(
                    is_consumer, port)][row] =
                Fp3::FromFp(
                    gf::FromU64(
                        event.multiplicity));
        }
    }
    std::vector<uint256> roots;
    out.bus_precommitments[family] =
        DeepBusPrecommitV1(
            out.chip, out.columns,
            layout, label, &roots);
    if (out.bus_precommitments[family]
            .IsNull()) {
        return false;
    }
    out.bus_challenges[family] =
        DeepBusChallengesV1(
            out.bus_precommitments[family],
            roots, label, out.trace_rows,
            static_cast<uint32_t>(
                producer.size()),
            static_cast<uint32_t>(
                consumer.size()));
    const auto& challenges =
        out.bus_challenges[family];
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < out.trace_rows; ++row) {
        out.columns[layout.running1][row] =
            running1;
        out.columns[layout.running2][row] =
            running2;
        Fp3 contribution1 = Fp3::Zero();
        Fp3 contribution2 = Fp3::Zero();
        for (const bool is_consumer :
             std::array<bool, 2>{false, true}) {
            const Fp3 sign =
                is_consumer
                ? Fp3::FromFp(gf::Neg(1))
                : Fp3::One();
            for (uint32_t port = 0;
                 port <
                     NormalizedDeepLogUpLayoutV1::
                         kEventPorts;
                 ++port) {
                const Fp3 multiplicity =
                    out.columns[
                        layout.Multiplicity(
                            is_consumer, port)][row];
                if (gf::IsZero(multiplicity)) {
                    continue;
                }
                const Fp3 address =
                    out.columns[
                        layout.Address(
                            is_consumer, port)][row];
                const Fp3 value =
                    out.columns[
                        layout.Value(
                            is_consumer, port)][row];
                for (uint32_t lane = 0;
                     lane < 2; ++lane) {
                    const Fp3 gamma =
                        lane == 0
                        ? challenges.gamma1
                        : challenges.gamma2;
                    const Fp3 alpha =
                        lane == 0
                        ? challenges.alpha1
                        : challenges.alpha2;
                    const Fp3 denominator =
                        gf::Sub(
                            alpha,
                            gf::Add(
                                address,
                                gf::Mul(gamma, value)));
                    if (gf::IsZero(denominator)) {
                        return false;
                    }
                    const Fp3 scaled_inverse =
                        gf::Mul(
                            multiplicity,
                            gf::Inv(denominator));
                    out.columns[
                        lane == 0
                        ? layout.Inverse1(
                              is_consumer, port)
                        : layout.Inverse2(
                              is_consumer, port)][row] =
                            scaled_inverse;
                    if (lane == 0) {
                        contribution1 =
                            gf::Add(
                                contribution1,
                                gf::Mul(
                                    sign,
                                    scaled_inverse));
                    } else {
                        contribution2 =
                            gf::Add(
                                contribution2,
                                gf::Mul(
                                    sign,
                                    scaled_inverse));
                    }
                }
            }
        }
        running1 =
            gf::Add(running1, contribution1);
        running2 =
            gf::Add(running2, contribution2);
    }
    if (!gf::IsZero(running1) ||
        !gf::IsZero(running2)) {
        return false;
    }

    // Schedule/address/multiplicity and the reference consumer values are
    // verifier pins in this pilot. Producer values remain witness cells for
    // the later decoder/remote-source equality attachment.
    for (const bool is_consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedDeepLogUpLayoutV1::
                     kEventPorts;
             ++port) {
            for (uint32_t column :
                 std::array<uint32_t, 2>{
                     layout.Address(
                         is_consumer, port),
                     layout.Multiplicity(
                         is_consumer, port)}) {
                out.chip.preprocessed.emplace_back(
                    column, out.columns[column]);
            }
            if (is_consumer) {
                const uint32_t column =
                    layout.Value(true, port);
                out.chip.preprocessed.emplace_back(
                    column, out.columns[column]);
            }
        }
    }
    const auto append =
        [&](aq::AirConstraint<Fp3> constraint) {
            out.chip.constraints.push_back(
                std::move(constraint));
        };
    for (const bool is_consumer :
         std::array<bool, 2>{false, true}) {
        for (uint32_t port = 0;
             port <
                 NormalizedDeepLogUpLayoutV1::
                     kEventPorts;
             ++port) {
            for (uint32_t lane = 0;
                 lane < 2; ++lane) {
                aq::AirConstraint<Fp3> inverse;
                inverse.name =
                    "stage3.fixedpoint.deep64.bus.inverse";
                inverse.kind =
                    aq::AirKind::kEverywhere;
                inverse.alg_degree = 2;
                const uint32_t value =
                    layout.Value(
                        is_consumer, port);
                const uint32_t address =
                    layout.Address(
                        is_consumer, port);
                const uint32_t multiplicity =
                    layout.Multiplicity(
                        is_consumer, port);
                const uint32_t inverse_column =
                    lane == 0
                    ? layout.Inverse1(
                          is_consumer, port)
                    : layout.Inverse2(
                          is_consumer, port);
                const Fp3 gamma =
                    lane == 0
                    ? challenges.gamma1
                    : challenges.gamma2;
                const Fp3 alpha =
                    lane == 0
                    ? challenges.alpha1
                    : challenges.alpha2;
                inverse.eval =
                    [value, address,
                     multiplicity,
                     inverse_column,
                     gamma, alpha](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        const Fp3 denominator =
                            gf::Sub(
                                alpha,
                                gf::Add(
                                    row[address],
                                    gf::Mul(
                                        gamma,
                                        row[value])));
                        return gf::Sub(
                            row[multiplicity],
                            gf::Mul(
                                denominator,
                                row[inverse_column]));
                    };
                append(std::move(inverse));
            }
        }
    }
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        const uint32_t running =
            lane == 0
            ? layout.running1
            : layout.running2;
        aq::AirConstraint<Fp3> transition;
        transition.name =
            "stage3.fixedpoint.deep64.bus.running";
        transition.kind =
            aq::AirKind::kTransition;
        transition.alg_degree = 1;
        transition.eval =
            [layout, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                Fp3 contribution =
                    Fp3::Zero();
                for (const bool is_consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign =
                        is_consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedDeepLogUpLayoutV1::
                                 kEventPorts;
                         ++port) {
                        const Fp3 inverse =
                            row[lane == 0
                                ? layout.Inverse1(
                                      is_consumer,
                                      port)
                                : layout.Inverse2(
                                      is_consumer,
                                      port)];
                        contribution =
                            gf::Add(
                                contribution,
                                gf::Mul(
                                    sign, inverse));
                    }
                }
                return gf::Sub(
                    next[running],
                    gf::Add(
                        row[running],
                        contribution));
            };
        append(std::move(transition));

        aq::AirConstraint<Fp3> first;
        first.name =
            "stage3.fixedpoint.deep64.bus.first";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        first.eval =
            [running](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return row[running];
            };
        append(std::move(first));

        aq::AirConstraint<Fp3> terminal;
        terminal.name =
            "stage3.fixedpoint.deep64.bus.terminal";
        terminal.kind = aq::AirKind::kLastRow;
        terminal.alg_degree = 1;
        terminal.eval =
            [layout, running, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 result = row[running];
                for (const bool is_consumer :
                     std::array<bool, 2>{
                         false, true}) {
                    const Fp3 sign =
                        is_consumer
                        ? Fp3::FromFp(gf::Neg(1))
                        : Fp3::One();
                    for (uint32_t port = 0;
                         port <
                             NormalizedDeepLogUpLayoutV1::
                                 kEventPorts;
                         ++port) {
                        result = gf::Add(
                            result,
                            gf::Mul(
                                sign,
                                row[lane == 0
                                    ? layout.Inverse1(
                                          is_consumer,
                                          port)
                                    : layout.Inverse2(
                                          is_consumer,
                                          port)]));
                    }
                }
                return result;
            };
        append(std::move(terminal));
    }
    return true;
}

} // namespace

NormalizedDeepDerivationAttachmentV1
BuildNormalizedDeepDerivationPilotV1(
    const AlgAirProof& proof,
    uint32_t requested_ports)
{
    NormalizedDeepDerivationAttachmentV1 out;
    out.requested_ports = requested_ports;
    out.layout =
        NormalizedDeepDerivationLayoutV1(
            requested_ports);
    out.batch_width =
        static_cast<uint32_t>(
            proof.batch.column_len.size());
    out.queries =
        static_cast<uint32_t>(
            proof.batch.queries.size());
    out.query_item_sites =
        uint64_t{out.batch_width} *
        out.queries;
    if ((requested_ports != 1 &&
         requested_ports !=
             kNormalizedDeepDerivationPorts) ||
        out.batch_width == 0 ||
        out.queries == 0 ||
        (requested_ports ==
             kNormalizedDeepDerivationPorts &&
         out.batch_width >
             kNormalizedDeepDerivationPorts) ||
        out.layout.End() >
            kRCFri3AlgBatchMaxColumns) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep_pilot_shape";
        return out;
    }
    std::vector<NormalizedDeepSiteV1> sites;
    NormalizedDeepEventFamiliesV1 events;
    if (!BuildNormalizedDeepSitesV1(
            proof, sites, events)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep_pilot_sites";
        return out;
    }
    out.active_derivation_rows =
        requested_ports == 1
        ? static_cast<uint32_t>(
              out.query_item_sites)
        : out.queries;
    uint64_t active_rows =
        out.active_derivation_rows;
    for (uint32_t family = 0;
         family < 3; ++family) {
        active_rows = std::max(
            active_rows,
            CeilDiv(
                std::max(
                    events.producer[family].size(),
                    events.consumer[family].size()),
                NormalizedDeepLogUpLayoutV1::
                    kEventPorts));
    }
    if (active_rows >
        (uint64_t{1} <<
         kRCFriMaxColumnLog2)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep_pilot_rows";
        return out;
    }
    out.trace_rows =
        NextPow2(
            static_cast<uint32_t>(
                std::max<uint64_t>(
                    2, active_rows)));
    if (out.trace_rows == 0) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep_pilot_trace";
        return out;
    }
    out.added_columns = out.layout.End();
    out.chip.n_rows = out.trace_rows;
    out.chip.n_columns = out.added_columns;
    out.chip.preprocessed_pin_ood = true;
    out.columns.assign(
        out.added_columns,
        std::vector<Fp3>(
            out.trace_rows, Fp3::Zero()));

    const auto& batch = proof.batch;
    const uint32_t n_lde =
        batch.fold_layers[0].n_leaves;
    const uint32_t log_lde =
        Log2Exact(n_lde);
    if (log_lde == 0 || log_lde > 32) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep_pilot_domain";
        return out;
    }
    const gf::Fp omega =
        PowFp(
            kOmega2_32,
            uint64_t{1} <<
                (32 - log_lde));

    // Shared tables and port witness. One-port streams sites. The full-width
    // schedule keeps every query on one row so all active ports share x.
    for (uint32_t row = 0;
         row < out.active_derivation_rows;
         ++row) {
        const uint32_t query =
            requested_ports == 1
            ? sites[row].query
            : row;
        const uint32_t query_index =
            batch.queries[query].index;
        out.columns[
            out.layout.shared.QueryProduct(0)]
            [row] = Fp3::One();
        Fp3 z1_square = batch.z1;
        Fp3 z2_square = batch.z2;
        Fp3 omega_square =
            Fp3::FromFp(omega);
        Fp3 query_product = Fp3::One();
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            out.columns[
                out.layout.shared.Z1Square(bit)]
                [row] = z1_square;
            out.columns[
                out.layout.shared.Z2Square(bit)]
                [row] = z2_square;
            const bool selected =
                ((query_index >> bit) & 1U) != 0;
            out.columns[
                out.layout.shared.QueryIndexBit(bit)]
                [row] =
                selected
                ? Fp3::One()
                : Fp3::Zero();
            if (selected) {
                query_product =
                    gf::Mul(
                        query_product,
                        omega_square);
            }
            out.columns[
                out.layout.shared.QueryProduct(
                    bit + 1)][row] =
                        query_product;
            z1_square =
                gf::Mul(z1_square, z1_square);
            z2_square =
                gf::Mul(z2_square, z2_square);
            omega_square =
                gf::Mul(
                    omega_square,
                    omega_square);
        }
        Fp3 x_square = query_product;
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            out.columns[
                out.layout.shared.XSquare(bit)]
                [row] = x_square;
            x_square =
                gf::Mul(x_square, x_square);
        }
        const uint32_t port_limit =
            requested_ports == 1
            ? 1
            : out.batch_width;
        for (uint32_t port = 0;
             port < port_limit; ++port) {
            const uint32_t site_index =
                requested_ports == 1
                ? row
                : query * out.batch_width +
                      port;
            const auto& site =
                sites[site_index];
            const auto layout =
                out.layout.Port(port);
            out.columns[layout.active][row] =
                Fp3::One();
            out.columns[layout.item][row] =
                Fp3::FromFp(
                    gf::FromU64(site.item));
            out.columns[layout.column_len][row] =
                Fp3::FromFp(gf::FromU64(
                    batch.column_len[site.item]));
            out.columns[layout.row_value][row] =
                batch.queries[site.query]
                    .row.values[site.item];
            out.columns[layout.eval_z1][row] =
                batch.evals_z1[site.item];
            out.columns[layout.eval_z2][row] =
                batch.evals_z2[site.item];
            out.columns[layout.lambda_power][row] =
                site.lambda_power;
            out.columns[layout.XProduct(0)][row] =
                Fp3::One();
            out.columns[layout.Z1Product(0)][row] =
                Fp3::One();
            out.columns[layout.Z2Product(0)][row] =
                Fp3::One();
            Fp3 xp = Fp3::One();
            Fp3 z1p = Fp3::One();
            Fp3 z2p = Fp3::One();
            for (uint32_t bit = 0;
                 bit < 32; ++bit) {
                const bool selected =
                    ((site.shift >> bit) & 1U) != 0;
                out.columns[
                    layout.ShiftBit(bit)][row] =
                    selected
                    ? Fp3::One()
                    : Fp3::Zero();
                if (selected) {
                    xp = gf::Mul(
                        xp,
                        out.columns[
                            out.layout.shared
                                .XSquare(bit)]
                            [row]);
                    z1p = gf::Mul(
                        z1p,
                        out.columns[
                            out.layout.shared
                                .Z1Square(bit)]
                            [row]);
                    z2p = gf::Mul(
                        z2p,
                        out.columns[
                            out.layout.shared
                                .Z2Square(bit)]
                            [row]);
                }
                out.columns[
                    layout.XProduct(bit + 1)]
                    [row] = xp;
                out.columns[
                    layout.Z1Product(bit + 1)]
                    [row] = z1p;
                out.columns[
                    layout.Z2Product(bit + 1)]
                    [row] = z2p;
            }
            if (!gf::Eq(xp, site.x_shift) ||
                !gf::Eq(z1p, site.z1_shift) ||
                !gf::Eq(z2p, site.z2_shift)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "normalized_deep_pilot_products";
                return out;
            }
            out.columns[layout.v1_running][row] =
                site.v1_running;
            out.columns[layout.v2_running][row] =
                site.v2_running;
            out.columns[layout.ux_running][row] =
                site.ux_running;
            out.columns[layout.invd1][row] =
                site.invd1;
            out.columns[layout.invd2][row] =
                site.invd2;
            out.columns[layout.deep_value][row] =
                site.deep;
            out.columns[
                layout.opened_deep_value][row] =
                    site.opened;
            out.columns[
                layout.output_selector][row] =
                site.output
                ? Fp3::One()
                : Fp3::Zero();
        }
    }

    const auto append =
        [&](const char* name,
            aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            out.chip.constraints.push_back(
                std::move(constraint));
        };

    // The active-row schedule and query-index bits are verifier-known in
    // this standalone pilot.  The later recursive attachment replaces these
    // pins with equality-constrained decoder cells.
    const auto shared = out.layout.shared;
    const uint32_t query_active =
        shared.QueryProduct(0);
    out.chip.preprocessed.emplace_back(
        query_active,
        out.columns[query_active]);
    append(
        "stage3.fixedpoint.deep64.query_product_first",
        aq::AirKind::kEverywhere, 2,
        [query_active](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[query_active],
                gf::Sub(
                    row[query_active],
                    Fp3::One()));
        });

    gf::Fp omega_square = omega;
    for (uint32_t bit = 0; bit < 32; ++bit) {
        const uint32_t index_bit =
            shared.QueryIndexBit(bit);
        out.chip.preprocessed.emplace_back(
            index_bit,
            out.columns[index_bit]);
        append(
            "stage3.fixedpoint.deep64.query_index_bit",
            aq::AirKind::kEverywhere, 3,
            [query_active, index_bit](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[query_active],
                    gf::Mul(
                        row[index_bit],
                        gf::Sub(
                            row[index_bit],
                            Fp3::One())));
            });

        for (uint32_t table = 0;
             table < 2; ++table) {
            const uint32_t column =
                table == 0
                ? shared.Z1Square(bit)
                : shared.Z2Square(bit);
            const Fp3 initial =
                table == 0
                ? batch.z1
                : batch.z2;
            if (bit == 0) {
                append(
                    "stage3.fixedpoint.deep64.z_square_first",
                    aq::AirKind::kEverywhere, 2,
                    [query_active, column, initial](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[query_active],
                            gf::Sub(
                                row[column],
                                initial));
                    });
            } else {
                const uint32_t prior =
                    table == 0
                    ? shared.Z1Square(bit - 1)
                    : shared.Z2Square(bit - 1);
                append(
                    "stage3.fixedpoint.deep64.z_square",
                    aq::AirKind::kEverywhere, 3,
                    [query_active, column, prior](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[query_active],
                            gf::Sub(
                                row[column],
                                gf::Mul(
                                    row[prior],
                                    row[prior])));
                    });
            }
        }

        const uint32_t product_before =
            shared.QueryProduct(bit);
        const uint32_t product_after =
            shared.QueryProduct(bit + 1);
        const Fp3 omega_bit =
            Fp3::FromFp(omega_square);
        append(
            "stage3.fixedpoint.deep64.query_x_product",
            aq::AirKind::kEverywhere, 4,
            [query_active, index_bit,
             product_before, product_after,
             omega_bit](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 selected =
                    gf::Add(
                        Fp3::One(),
                        gf::Mul(
                            row[index_bit],
                            gf::Sub(
                                omega_bit,
                                Fp3::One())));
                return gf::Mul(
                    row[query_active],
                    gf::Sub(
                        row[product_after],
                        gf::Mul(
                            row[product_before],
                            selected)));
            });

        const uint32_t x_square =
            shared.XSquare(bit);
        if (bit == 0) {
            const uint32_t x =
                shared.QueryProduct(32);
            append(
                "stage3.fixedpoint.deep64.x_square_first",
                aq::AirKind::kEverywhere, 2,
                [query_active, x_square, x](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[query_active],
                        gf::Sub(
                            row[x_square],
                            row[x]));
                });
        } else {
            const uint32_t prior =
                shared.XSquare(bit - 1);
            append(
                "stage3.fixedpoint.deep64.x_square",
                aq::AirKind::kEverywhere, 3,
                [query_active, x_square, prior](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[query_active],
                        gf::Sub(
                            row[x_square],
                            gf::Mul(
                                row[prior],
                                row[prior])));
                });
        }
        omega_square =
            gf::Mul(
                omega_square,
                omega_square);
    }

    const auto accumulation_term =
        [](const NormalizedDeepPortLayoutV1& layout,
           const std::vector<Fp3>& row,
           uint32_t lane) {
            const uint32_t product =
                lane == 0
                ? layout.Z1Product(32)
                : lane == 1
                ? layout.Z2Product(32)
                : layout.XProduct(32);
            const uint32_t value =
                lane == 0
                ? layout.eval_z1
                : lane == 1
                ? layout.eval_z2
                : layout.row_value;
            return gf::Mul(
                gf::Mul(
                    row[layout.lambda_power],
                    row[product]),
                row[value]);
        };

    for (uint32_t port = 0;
         port < requested_ports; ++port) {
        const auto layout =
            out.layout.Port(port);
        for (uint32_t schedule_column :
             std::array<uint32_t, 8>{
                 layout.active,
                 layout.item,
                 layout.column_len,
                 layout.row_value,
                 layout.eval_z1,
                 layout.eval_z2,
                 layout.opened_deep_value,
                 layout.output_selector}) {
            out.chip.preprocessed.emplace_back(
                schedule_column,
                out.columns[schedule_column]);
        }
        append(
            "stage3.fixedpoint.deep64.port_active_boolean",
            aq::AirKind::kEverywhere, 2,
            [layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.active],
                    gf::Sub(
                        row[layout.active],
                        Fp3::One()));
            });
        if (port == 0) {
            append(
                "stage3.fixedpoint.deep64.port_shared_active",
                aq::AirKind::kEverywhere, 1,
                [layout, query_active](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        row[layout.active],
                        row[query_active]);
                });
        }
        append(
            "stage3.fixedpoint.deep64.output_boolean",
            aq::AirKind::kEverywhere, 2,
            [layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.output_selector],
                    gf::Sub(
                        row[layout.output_selector],
                        Fp3::One()));
            });
        append(
            "stage3.fixedpoint.deep64.output_implies_active",
            aq::AirKind::kEverywhere, 2,
            [layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.output_selector],
                    gf::Sub(
                        row[layout.active],
                        Fp3::One()));
            });
        append(
            "stage3.fixedpoint.deep64.shift_reconstruct",
            aq::AirKind::kEverywhere, 3,
            [layout, n = batch.n_coeffs](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 shift = Fp3::Zero();
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    shift = gf::Add(
                        shift,
                        gf::Mul(
                            Fp3::FromFp(
                                gf::FromU64(
                                    uint64_t{1}
                                    << bit)),
                            row[layout.ShiftBit(bit)]));
                }
                return gf::Mul(
                    row[layout.active],
                    gf::Sub(
                        gf::Add(
                            row[layout.column_len],
                            shift),
                        Fp3::FromFp(
                            gf::FromU64(n))));
            });

        for (uint32_t product = 0;
             product < 3; ++product) {
            const uint32_t initial =
                product == 0
                ? layout.XProduct(0)
                : product == 1
                ? layout.Z1Product(0)
                : layout.Z2Product(0);
            append(
                "stage3.fixedpoint.deep64.product_first",
                aq::AirKind::kEverywhere, 2,
                [layout, initial](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.active],
                        gf::Sub(
                            row[initial],
                            Fp3::One()));
                });
        }
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            const uint32_t shift_bit =
                layout.ShiftBit(bit);
            append(
                "stage3.fixedpoint.deep64.shift_bit",
                aq::AirKind::kEverywhere, 3,
                [layout, shift_bit](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.active],
                        gf::Mul(
                            row[shift_bit],
                            gf::Sub(
                                row[shift_bit],
                                Fp3::One())));
                });
            for (uint32_t product = 0;
                 product < 3; ++product) {
                const uint32_t before =
                    product == 0
                    ? layout.XProduct(bit)
                    : product == 1
                    ? layout.Z1Product(bit)
                    : layout.Z2Product(bit);
                const uint32_t after =
                    product == 0
                    ? layout.XProduct(bit + 1)
                    : product == 1
                    ? layout.Z1Product(bit + 1)
                    : layout.Z2Product(bit + 1);
                const uint32_t square =
                    product == 0
                    ? shared.XSquare(bit)
                    : product == 1
                    ? shared.Z1Square(bit)
                    : shared.Z2Square(bit);
                append(
                    "stage3.fixedpoint.deep64.shift_product",
                    aq::AirKind::kEverywhere, 4,
                    [layout, shift_bit, before,
                     after, square](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        const Fp3 selected =
                            gf::Add(
                                Fp3::One(),
                                gf::Mul(
                                    row[shift_bit],
                                    gf::Sub(
                                        row[square],
                                        Fp3::One())));
                        return gf::Mul(
                            row[layout.active],
                            gf::Sub(
                                row[after],
                                gf::Mul(
                                    row[before],
                                    selected)));
                    });
            }
        }

        for (uint32_t lane = 0;
             lane < 2; ++lane) {
            const uint32_t inverse =
                lane == 0
                ? layout.invd1
                : layout.invd2;
            const Fp3 z =
                lane == 0
                ? batch.z1
                : batch.z2;
            const uint32_t x =
                shared.QueryProduct(32);
            append(
                "stage3.fixedpoint.deep64.inverse",
                aq::AirKind::kEverywhere, 3,
                [layout, inverse, x, z](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.active],
                        gf::Sub(
                            gf::Mul(
                                gf::Sub(row[x], z),
                                row[inverse]),
                            Fp3::One()));
                });
        }
        append(
            "stage3.fixedpoint.deep64.deep_identity",
            aq::AirKind::kEverywhere, 4,
            [layout, w1 = batch.w1,
             w2 = batch.w2](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 expected =
                    gf::Add(
                        gf::Mul(
                            w1,
                            gf::Mul(
                                gf::Sub(
                                    row[layout.ux_running],
                                    row[layout.v1_running]),
                                row[layout.invd1])),
                        gf::Mul(
                            w2,
                            gf::Mul(
                                gf::Sub(
                                    row[layout.ux_running],
                                    row[layout.v2_running]),
                                row[layout.invd2])));
                return gf::Mul(
                    row[layout.output_selector],
                    gf::Sub(
                        row[layout.deep_value],
                        expected));
            });
        append(
            "stage3.fixedpoint.deep64.opened_deep",
            aq::AirKind::kEverywhere, 2,
            [layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.output_selector],
                    gf::Sub(
                        row[layout.deep_value],
                        row[layout.opened_deep_value]));
            });

        if (requested_ports ==
                kNormalizedDeepDerivationPorts) {
            if (port == 0) {
                append(
                    "stage3.fixedpoint.deep64.lambda_horizontal_first",
                    aq::AirKind::kEverywhere, 2,
                    [layout](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[layout.active],
                            gf::Sub(
                                row[layout.lambda_power],
                                Fp3::One()));
                    });
                for (uint32_t lane = 0;
                     lane < 3; ++lane) {
                    const uint32_t running =
                        lane == 0
                        ? layout.v1_running
                        : lane == 1
                        ? layout.v2_running
                        : layout.ux_running;
                    append(
                        "stage3.fixedpoint.deep64.accumulator_horizontal_first",
                        aq::AirKind::kEverywhere, 4,
                        [layout, running, lane,
                         accumulation_term](
                            const std::vector<Fp3>& row,
                            const std::vector<Fp3>&) {
                            return gf::Mul(
                                row[layout.active],
                                gf::Sub(
                                    row[running],
                                    accumulation_term(
                                        layout, row, lane)));
                        });
                }
            } else {
                const auto prior =
                    out.layout.Port(port - 1);
                append(
                    "stage3.fixedpoint.deep64.lambda_horizontal",
                    aq::AirKind::kEverywhere, 3,
                    [layout, prior,
                     lambda = batch.lambda](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[layout.active],
                            gf::Sub(
                                row[layout.lambda_power],
                                gf::Mul(
                                    row[prior.lambda_power],
                                    lambda)));
                    });
                append(
                    "stage3.fixedpoint.deep64.active_horizontal_prefix",
                    aq::AirKind::kEverywhere, 2,
                    [layout, prior](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Mul(
                            row[layout.active],
                            gf::Sub(
                                row[prior.active],
                                Fp3::One()));
                    });
                for (uint32_t lane = 0;
                     lane < 3; ++lane) {
                    const uint32_t running =
                        lane == 0
                        ? layout.v1_running
                        : lane == 1
                        ? layout.v2_running
                        : layout.ux_running;
                    const uint32_t prior_running =
                        lane == 0
                        ? prior.v1_running
                        : lane == 1
                        ? prior.v2_running
                        : prior.ux_running;
                    append(
                        "stage3.fixedpoint.deep64.accumulator_horizontal",
                        aq::AirKind::kEverywhere, 4,
                        [layout, running,
                         prior_running, lane,
                         accumulation_term](
                            const std::vector<Fp3>& row,
                            const std::vector<Fp3>&) {
                            return gf::Mul(
                                row[layout.active],
                                gf::Sub(
                                    row[running],
                                    gf::Add(
                                        row[prior_running],
                                        accumulation_term(
                                            layout, row,
                                            lane))));
                        });
                }
            }
        } else {
            append(
                "stage3.fixedpoint.deep64.lambda_vertical_first",
                aq::AirKind::kFirstRow, 1,
                [layout](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        row[layout.lambda_power],
                        Fp3::One());
                });
            for (uint32_t lane = 0;
                 lane < 3; ++lane) {
                const uint32_t running =
                    lane == 0
                    ? layout.v1_running
                    : lane == 1
                    ? layout.v2_running
                    : layout.ux_running;
                append(
                    "stage3.fixedpoint.deep64.accumulator_vertical_first",
                    aq::AirKind::kFirstRow, 3,
                    [layout, running, lane,
                     accumulation_term](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>&) {
                        return gf::Sub(
                            row[running],
                            accumulation_term(
                                layout, row, lane));
                    });
            }
            append(
                "stage3.fixedpoint.deep64.lambda_vertical",
                aq::AirKind::kTransition, 4,
                [layout, lambda = batch.lambda](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    const Fp3 reset =
                        row[layout.output_selector];
                    const Fp3 expected =
                        gf::Add(
                            reset,
                            gf::Mul(
                                gf::Sub(
                                    Fp3::One(), reset),
                                gf::Mul(
                                    row[layout.lambda_power],
                                    lambda)));
                    return gf::Mul(
                        next[layout.active],
                        gf::Sub(
                            next[layout.lambda_power],
                            expected));
                });
            for (uint32_t lane = 0;
                 lane < 3; ++lane) {
                const uint32_t running =
                    lane == 0
                    ? layout.v1_running
                    : lane == 1
                    ? layout.v2_running
                    : layout.ux_running;
                append(
                    "stage3.fixedpoint.deep64.accumulator_vertical",
                    aq::AirKind::kTransition, 5,
                    [layout, running, lane,
                     accumulation_term](
                        const std::vector<Fp3>& row,
                        const std::vector<Fp3>& next) {
                        const Fp3 carry =
                            gf::Mul(
                                gf::Sub(
                                    Fp3::One(),
                                    row[
                                        layout
                                            .output_selector]),
                                row[running]);
                        return gf::Mul(
                            next[layout.active],
                            gf::Sub(
                                next[running],
                                gf::Add(
                                    carry,
                                    accumulation_term(
                                        layout, next,
                                        lane))));
                    });
            }
        }
    }

    out.input_table_events =
        events.producer[0].size();
    out.input_read_events =
        events.consumer[0].size();
    out.query_x_events =
        events.consumer[1].size();
    out.output_events =
        events.producer[2].size();
    if (!PopulateNormalizedDeepBusV1(
            out, 0, "input",
            out.layout.input_bus,
            events.producer[0],
            events.consumer[0]) ||
        !PopulateNormalizedDeepBusV1(
            out, 1, "read",
            out.layout.read_bus,
            events.producer[1],
            events.consumer[1]) ||
        !PopulateNormalizedDeepBusV1(
            out, 2, "output",
            out.layout.output_bus,
            events.producer[2],
            events.consumer[2])) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep_pilot_logup";
        return out;
    }

    out.added_constraints =
        static_cast<uint32_t>(
            out.chip.constraints.size());
    out.violations =
        CountHashOpeningViolations(
            out.chip, out.columns);
    out.shared_z1_z2_square_tables = true;
    out.parameterized_query_x_table = true;
    out.shift_bits_and_three_products = true;
    out.lambda_v_inverse_recurrences = true;
    out.input_logup_terminal_zero = true;
    out.read_logup_terminal_zero = true;
    out.output_logup_terminal_zero = true;
    out.denominator_nonzero = true;
    out.witness_built = true;
    out.full_64_port_relation_closed = false;
    out.executable = false;
    out.recursive_endpoints_consumed = 0;
    out.recursive_roles_consumed = 0;
    out.recursively_consumed = false;
    out.residuals = {
        "proof-decoder cells are not yet same-trace aliases",
        "fold opening output is pilot-pinned, not recursively consumed",
        "bus terminals are not yet joined to the unified recursive root",
    };
    out.valid =
        out.version == 1 &&
        out.added_columns == out.layout.End() &&
        out.added_columns <=
            kRCFri3AlgBatchMaxColumns &&
        out.active_derivation_rows != 0 &&
        out.trace_rows >=
            out.active_derivation_rows &&
        out.added_constraints != 0 &&
        out.violations == 0 &&
        out.input_logup_terminal_zero &&
        out.read_logup_terminal_zero &&
        out.output_logup_terminal_zero &&
        out.witness_built &&
        !out.full_64_port_relation_closed &&
        !out.executable &&
        out.recursive_endpoints_consumed == 0 &&
        out.recursive_roles_consumed == 0 &&
        !out.recursively_consumed;
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_deep_pilot_executable_local_air;"
          "recursive_attachment_open"
        : "stage3:recursive_fixedpoint:"
          "normalized_deep_pilot_violation";
    return out;
}

bool ValidateNormalizedDeepDerivationPilotV1(
    const AlgAirProof& proof,
    const NormalizedDeepDerivationAttachmentV1& attachment,
    std::string* why)
{
    const auto fail =
        [&](const char* reason) {
            if (why != nullptr) *why = reason;
            return false;
        };
    if (!attachment.valid ||
        attachment.version != 1 ||
        (attachment.requested_ports != 1 &&
         attachment.requested_ports !=
             kNormalizedDeepDerivationPorts) ||
        attachment.executable ||
        attachment.full_64_port_relation_closed ||
        attachment.recursive_endpoints_consumed != 0 ||
        attachment.recursive_roles_consumed != 0 ||
        attachment.recursively_consumed ||
        attachment.violations != 0) {
        return fail("normalized_deep_pilot_flags");
    }
    const auto expected =
        BuildNormalizedDeepDerivationPilotV1(
            proof, attachment.requested_ports);
    if (!expected.valid ||
        expected.layout.shared.base !=
            attachment.layout.shared.base ||
        expected.layout.port_base !=
            attachment.layout.port_base ||
        expected.layout.ports !=
            attachment.layout.ports ||
        expected.layout.input_bus.base !=
            attachment.layout.input_bus.base ||
        expected.layout.read_bus.base !=
            attachment.layout.read_bus.base ||
        expected.layout.output_bus.base !=
            attachment.layout.output_bus.base ||
        expected.layout.End() !=
            attachment.layout.End() ||
        expected.chip.n_rows !=
            attachment.chip.n_rows ||
        expected.chip.n_columns !=
            attachment.chip.n_columns ||
        expected.added_constraints !=
            attachment.added_constraints ||
        attachment.chip.constraints.size() !=
            attachment.added_constraints ||
        expected.chip.constraints.size() !=
            attachment.chip.constraints.size() ||
        expected.chip.preprocessed.size() !=
            attachment.chip.preprocessed.size() ||
        expected.input_table_events !=
            attachment.input_table_events ||
        expected.input_read_events !=
            attachment.input_read_events ||
        expected.query_x_events !=
            attachment.query_x_events ||
        expected.output_events !=
            attachment.output_events ||
        expected.bus_precommitments !=
            attachment.bus_precommitments) {
        return fail("normalized_deep_pilot_shape");
    }
    for (uint32_t index = 0;
         index < expected.chip.constraints.size();
         ++index) {
        const auto& lhs =
            expected.chip.constraints[index];
        const auto& rhs =
            attachment.chip.constraints[index];
        if (std::string(lhs.name) !=
                std::string(rhs.name) ||
            lhs.kind != rhs.kind ||
            lhs.alg_degree != rhs.alg_degree ||
            !rhs.eval) {
            return fail(
                "normalized_deep_pilot_constraint");
        }
    }
    for (uint32_t index = 0;
         index < expected.chip.preprocessed.size();
         ++index) {
        const auto& lhs =
            expected.chip.preprocessed[index];
        const auto& rhs =
            attachment.chip.preprocessed[index];
        if (lhs.first != rhs.first ||
            lhs.second.size() != rhs.second.size()) {
            return fail(
                "normalized_deep_pilot_preprocessed");
        }
        for (uint32_t row = 0;
             row < lhs.second.size(); ++row) {
            if (!gf::Eq(
                    lhs.second[row],
                    rhs.second[row])) {
                return fail(
                    "normalized_deep_pilot_preprocessed");
            }
        }
    }
    for (uint32_t family = 0;
         family < 3; ++family) {
        if (!EqChallenges(
                expected.bus_challenges[family],
                attachment.bus_challenges[family])) {
            return fail(
                "normalized_deep_pilot_challenge");
        }
    }
    if (expected.columns.size() !=
            attachment.columns.size()) {
        return fail("normalized_deep_pilot_columns");
    }
    for (uint32_t column = 0;
         column < expected.columns.size();
         ++column) {
        if (expected.columns[column].size() !=
                attachment.columns[column].size()) {
            return fail(
                "normalized_deep_pilot_column_rows");
        }
        for (uint32_t row = 0;
             row < expected.columns[column].size();
             ++row) {
            if (!gf::Eq(
                    expected.columns[column][row],
                    attachment.columns[column][row])) {
                return fail(
                    "normalized_deep_pilot_witness");
            }
        }
    }
    if (CountHashOpeningViolations(
            expected.chip,
            attachment.columns) != 0) {
        return fail("normalized_deep_pilot_air");
    }
    return true;
}

namespace {

enum class NormalizedDeepSourceLaneV1 : uint32_t {
    Lambda = 0,
    Z1 = 1,
    Z2 = 2,
    ColumnLen = 3,
    EvalZ1 = 4,
    EvalZ2 = 5,
    W1 = 6,
    W2 = 7,
    QueryIndex = 8,
    RowValue = 9,
    OpenedDeep = 10,
};

struct NormalizedDeepCanonicalSourcesV1 {
    const NormalizedAlgAirCodecSemanticTokenV1*
        lambda{nullptr};
    const NormalizedAlgAirCodecSemanticTokenV1*
        z1{nullptr};
    const NormalizedAlgAirCodecSemanticTokenV1*
        z2{nullptr};
    const NormalizedAlgAirCodecSemanticTokenV1*
        w1{nullptr};
    const NormalizedAlgAirCodecSemanticTokenV1*
        w2{nullptr};
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        column_len;
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        eval_z1;
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        eval_z2;
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        query_index;
    std::vector<std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>>
        row_value;
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        opened_deep;
};

uint32_t NormalizedDeepTokenWordsV1(
    NormalizedAlgAirCodecTokenKind kind)
{
    switch (kind) {
    case NormalizedAlgAirCodecTokenKind::U32:
        return 1;
    case NormalizedAlgAirCodecTokenKind::Fp:
        return 2;
    case NormalizedAlgAirCodecTokenKind::Fp3:
        return 6;
    }
    return 0;
}

bool BuildNormalizedDeepCanonicalSourcesV1(
    const AlgAirProof& proof,
    const NormalizedAlgAirBatchCodecMapV1& map,
    NormalizedDeepCanonicalSourcesV1& out)
{
    out = {};
    const auto& batch = proof.batch;
    const uint32_t width =
        static_cast<uint32_t>(
            batch.column_len.size());
    const uint32_t queries =
        static_cast<uint32_t>(
            batch.queries.size());
    if (!map.valid ||
        map.codec_words == 0 ||
        width == 0 ||
        queries == 0 ||
        batch.evals_z1.size() != width ||
        batch.evals_z2.size() != width) {
        return false;
    }
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        token_at_word(map.codec_words, nullptr);
    for (const auto& token : map.semantic_tokens) {
        if (token.word_index >=
                token_at_word.size() ||
            token_at_word[token.word_index] !=
                nullptr) {
            return false;
        }
        token_at_word[token.word_index] = &token;
    }
    uint32_t word = 0;
    const auto skip =
        [&](uint64_t count) {
            if (count >
                uint64_t{map.codec_words - word}) {
                return false;
            }
            word += static_cast<uint32_t>(count);
            return true;
        };
    const auto take =
        [&](NormalizedAlgAirCodecTokenKind kind,
            NormalizedAlgAirCodecOwnerFamily owner,
            const Fp3& expected)
            -> const NormalizedAlgAirCodecSemanticTokenV1* {
            if (word >= token_at_word.size()) {
                return nullptr;
            }
            const auto* token =
                token_at_word[word];
            const uint32_t words =
                NormalizedDeepTokenWordsV1(kind);
            if (token == nullptr ||
                words == 0 ||
                token->kind != kind ||
                token->owner != owner ||
                !token->
                    consumed_by_existing_verifier_chip ||
                !gf::Eq(token->value, expected) ||
                words > map.codec_words - word) {
                return nullptr;
            }
            word += words;
            return token;
        };

    // magic, version, nonce, blowup, n_coeffs, row root, n_lde and
    // column_len vector length.
    if (!skip(2 + 2 + 1 + 1 + 8 + 1 + 1)) {
        return false;
    }
    out.column_len.resize(width);
    for (uint32_t item = 0;
         item < width; ++item) {
        out.column_len[item] =
            take(
                NormalizedAlgAirCodecTokenKind::U32,
                NormalizedAlgAirCodecOwnerFamily::Deep,
                Fp3::FromFp(gf::FromU64(
                    batch.column_len[item])));
        if (out.column_len[item] == nullptr) {
            return false;
        }
    }
    out.lambda =
        take(
            NormalizedAlgAirCodecTokenKind::Fp3,
            NormalizedAlgAirCodecOwnerFamily::Deep,
            batch.lambda);
    out.z1 =
        take(
            NormalizedAlgAirCodecTokenKind::Fp3,
            NormalizedAlgAirCodecOwnerFamily::Deep,
            batch.z1);
    out.z2 =
        take(
            NormalizedAlgAirCodecTokenKind::Fp3,
            NormalizedAlgAirCodecOwnerFamily::Deep,
            batch.z2);
    if (out.lambda == nullptr ||
        out.z1 == nullptr ||
        out.z2 == nullptr ||
        !skip(1)) {
        return false;
    }
    out.eval_z1.resize(width);
    for (uint32_t item = 0;
         item < width; ++item) {
        out.eval_z1[item] =
            take(
                NormalizedAlgAirCodecTokenKind::Fp3,
                NormalizedAlgAirCodecOwnerFamily::Deep,
                batch.evals_z1[item]);
        if (out.eval_z1[item] == nullptr) {
            return false;
        }
    }
    if (!skip(1)) return false;
    out.eval_z2.resize(width);
    for (uint32_t item = 0;
         item < width; ++item) {
        out.eval_z2[item] =
            take(
                NormalizedAlgAirCodecTokenKind::Fp3,
                NormalizedAlgAirCodecOwnerFamily::Deep,
                batch.evals_z2[item]);
        if (out.eval_z2[item] == nullptr) {
            return false;
        }
    }
    out.w1 =
        take(
            NormalizedAlgAirCodecTokenKind::Fp3,
            NormalizedAlgAirCodecOwnerFamily::Deep,
            batch.w1);
    out.w2 =
        take(
            NormalizedAlgAirCodecTokenKind::Fp3,
            NormalizedAlgAirCodecOwnerFamily::Deep,
            batch.w2);
    if (out.w1 == nullptr ||
        out.w2 == nullptr ||
        !skip(1)) {
        return false;
    }
    for (const auto& layer :
         batch.fold_layers) {
        (void)layer;
        if (!skip(8 + 1)) return false;
    }
    if (!skip(6 + 1) ||
        !skip(
            6 * uint64_t{
                    batch.fold_challenges.size()} +
            1)) {
        return false;
    }

    out.query_index.resize(queries);
    out.row_value.resize(queries);
    out.opened_deep.resize(queries);
    for (uint32_t query = 0;
         query < queries; ++query) {
        const auto& opened =
            batch.queries[query];
        out.query_index[query] =
            take(
                NormalizedAlgAirCodecTokenKind::U32,
                NormalizedAlgAirCodecOwnerFamily::
                    HashOpening,
                Fp3::FromFp(
                    gf::FromU64(opened.index)));
        if (out.query_index[query] == nullptr ||
            !skip(1)) {
            return false;
        }
        out.row_value[query].resize(width);
        if (opened.row.values.size() != width) {
            return false;
        }
        for (uint32_t item = 0;
             item < width; ++item) {
            out.row_value[query][item] =
                take(
                    NormalizedAlgAirCodecTokenKind::Fp3,
                    NormalizedAlgAirCodecOwnerFamily::
                        HashOpening,
                    opened.row.values[item]);
            if (out.row_value[query][item] ==
                    nullptr) {
                return false;
            }
        }
        if (!skip(1) ||
            !skip(
                8 * uint64_t{
                        opened.row.siblings.size()}) ||
            !skip(1) ||
            opened.steps.empty()) {
            return false;
        }
        for (uint32_t layer = 0;
             layer < opened.steps.size(); ++layer) {
            const auto& step =
                opened.steps[layer];
            const auto* even_index =
                take(
                    NormalizedAlgAirCodecTokenKind::U32,
                    NormalizedAlgAirCodecOwnerFamily::Fold,
                    Fp3::FromFp(
                        gf::FromU64(
                            step.even_index)));
            const auto* odd_index =
                take(
                    NormalizedAlgAirCodecTokenKind::U32,
                    NormalizedAlgAirCodecOwnerFamily::Fold,
                    Fp3::FromFp(
                        gf::FromU64(
                            step.odd_index)));
            const auto* even =
                take(
                    NormalizedAlgAirCodecTokenKind::Fp3,
                    NormalizedAlgAirCodecOwnerFamily::Fold,
                    step.even);
            const auto* odd =
                take(
                    NormalizedAlgAirCodecTokenKind::Fp3,
                    NormalizedAlgAirCodecOwnerFamily::Fold,
                    step.odd);
            if (even_index == nullptr ||
                odd_index == nullptr ||
                even == nullptr ||
                odd == nullptr) {
                return false;
            }
            if (layer == 0) {
                const uint32_t half =
                    batch.fold_layers[0].n_leaves /
                    2;
                out.opened_deep[query] =
                    opened.index < half
                    ? even
                    : odd;
            }
            if (!skip(1) ||
                !skip(
                    8 * uint64_t{
                            step.even_siblings.size()}) ||
                !skip(1) ||
                !skip(
                    8 * uint64_t{
                            step.odd_siblings.size()})) {
                return false;
            }
        }
        if (out.opened_deep[query] == nullptr) {
            return false;
        }
    }
    return word == map.codec_words;
}

bool NormalizedDeepDecoderTokenIsLiteralV1(
    const FoldBusComposition& composition,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirCodecSemanticTokenV1& token)
{
    constexpr uint32_t TRANSCRIPT_CODEC_BEGIN = 5;
    const uint64_t position =
        uint64_t{TRANSCRIPT_CODEC_BEGIN} +
        token.word_index;
    const uint32_t row =
        static_cast<uint32_t>(
            position /
                NormalizedAlgAirCodecCtlLayout::kPorts);
    const uint32_t port =
        static_cast<uint32_t>(
            position %
                NormalizedAlgAirCodecCtlLayout::kPorts);
    return row < composition.combined.n_rows &&
        gf::Eq(
            composition.columns[
                codec_ctl.layout.Value(false, port)]
                [row],
            token.value) &&
        gf::Eq(
            composition.columns[
                codec_ctl.layout.Address(false, port)]
                [row],
            Fp3::FromFp(
                gf::FromU64(token.address))) &&
        gf::Eq(
            composition.columns[
                codec_ctl.layout.Active(false, port)]
                [row],
            Fp3::One());
}

uint256 NormalizedDeepSparseBusCommitV1(
    const char* label,
    const std::vector<NormalizedDeepEventV1>& producer,
    const std::vector<NormalizedDeepEventV1>& consumer)
{
    HashWriter writer;
    writer <<
        "BTX_RC_STAGE3_NORMALIZED_DEEP64_SPARSE_LOGUP_V1";
    writer << std::string(label);
    writer << static_cast<uint64_t>(
        producer.size());
    writer << static_cast<uint64_t>(
        consumer.size());
    const auto write =
        [&](uint8_t side,
            const NormalizedDeepEventV1& event) {
            writer << side;
            writer << event.address;
            writer << gf::Canonical(event.value.c0);
            writer << gf::Canonical(event.value.c1);
            writer << gf::Canonical(event.value.c2);
            writer << event.multiplicity;
        };
    for (const auto& event : producer) {
        write(0, event);
    }
    for (const auto& event : consumer) {
        write(1, event);
    }
    return writer.GetHash();
}

NormalizedDeepSparseLogUpAuditV1
BuildNormalizedDeepSparseLogUpAuditV1(
    const char* label,
    const std::vector<NormalizedDeepEventV1>& producer,
    const std::vector<NormalizedDeepEventV1>& consumer)
{
    NormalizedDeepSparseLogUpAuditV1 out;
    out.producer_records = producer.size();
    out.consumer_records = consumer.size();
    for (const auto& event : producer) {
        if (event.address == 0 ||
            event.multiplicity >
                std::numeric_limits<uint64_t>::max() -
                    out.producer_multiplicity) {
            return out;
        }
        out.producer_multiplicity +=
            event.multiplicity;
    }
    for (const auto& event : consumer) {
        if (event.address == 0 ||
            event.multiplicity >
                std::numeric_limits<uint64_t>::max() -
                    out.consumer_multiplicity) {
            return out;
        }
        out.consumer_multiplicity +=
            event.multiplicity;
    }
    out.prechallenge_commitment =
        NormalizedDeepSparseBusCommitV1(
            label, producer, consumer);
    if (out.prechallenge_commitment.IsNull()) {
        return out;
    }
    const std::vector<uint256> no_roots;
    const auto challenge =
        [&](const char* suffix) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    out.prechallenge_commitment,
                    suffix, no_roots,
                    {
                        static_cast<uint32_t>(
                            out.producer_records),
                        static_cast<uint32_t>(
                            out.producer_records >> 32),
                        static_cast<uint32_t>(
                            out.consumer_records),
                        static_cast<uint32_t>(
                            out.consumer_records >> 32),
                        static_cast<uint32_t>(
                            out.producer_multiplicity),
                        static_cast<uint32_t>(
                            out.producer_multiplicity >>
                            32),
                        static_cast<uint32_t>(
                            out.consumer_multiplicity),
                        static_cast<uint32_t>(
                            out.consumer_multiplicity >>
                            32),
                    });
            return gf::FromChallengeBytes3(
                digest.data());
        };
    const std::string base(label);
    out.challenges = {
        challenge(
            (base + ".gamma1").c_str()),
        challenge(
            (base + ".gamma2").c_str()),
        challenge(
            (base + ".alpha1").c_str()),
        challenge(
            (base + ".alpha2").c_str()),
    };
    out.commit_then_challenge = true;
    out.denominator_nonzero = true;
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        const Fp3 gamma =
            lane == 0
            ? out.challenges.gamma1
            : out.challenges.gamma2;
        const Fp3 alpha =
            lane == 0
            ? out.challenges.alpha1
            : out.challenges.alpha2;
        Fp3 terminal = Fp3::Zero();
        for (const bool is_consumer :
             std::array<bool, 2>{false, true}) {
            const auto& events =
                is_consumer ? consumer : producer;
            const Fp3 sign =
                is_consumer
                ? Fp3::FromFp(gf::Neg(1))
                : Fp3::One();
            for (const auto& event : events) {
                const Fp3 denominator =
                    gf::Sub(
                        alpha,
                        gf::Add(
                            Fp3::FromFp(
                                gf::FromU64(
                                    event.address)),
                            gf::Mul(
                                gamma,
                                event.value)));
                if (gf::IsZero(denominator)) {
                    out.denominator_nonzero = false;
                    return out;
                }
                terminal =
                    gf::Add(
                        terminal,
                        gf::Mul(
                            sign,
                            gf::Mul(
                                Fp3::FromFp(
                                    gf::FromU64(
                                        event
                                            .multiplicity)),
                                gf::Inv(
                                    denominator))));
            }
        }
        if (lane == 0) {
            out.terminal1 = terminal;
        } else {
            out.terminal2 = terminal;
        }
    }
    out.terminal_zero =
        gf::IsZero(out.terminal1) &&
        gf::IsZero(out.terminal2);
    out.valid =
        out.commit_then_challenge &&
        out.denominator_nonzero &&
        out.terminal_zero &&
        out.producer_records != 0 &&
        out.consumer_records != 0 &&
        out.producer_multiplicity ==
            out.consumer_multiplicity;
    return out;
}

bool EqNormalizedDeepPortV1(
    const NormalizedDeep64PortWitnessV1& lhs,
    const NormalizedDeep64PortWitnessV1& rhs)
{
    if (lhs.query != rhs.query ||
        lhs.port != rhs.port ||
        lhs.item != rhs.item ||
        lhs.query_index != rhs.query_index ||
        lhs.column_len != rhs.column_len ||
        lhs.shift != rhs.shift ||
        lhs.active != rhs.active ||
        lhs.output != rhs.output ||
        lhs.source_address !=
            rhs.source_address) {
        return false;
    }
    return
        gf::Eq(lhs.x, rhs.x) &&
        gf::Eq(lhs.row_value, rhs.row_value) &&
        gf::Eq(lhs.eval_z1, rhs.eval_z1) &&
        gf::Eq(lhs.eval_z2, rhs.eval_z2) &&
        gf::Eq(
            lhs.lambda_power,
            rhs.lambda_power) &&
        gf::Eq(lhs.x_shift, rhs.x_shift) &&
        gf::Eq(lhs.z1_shift, rhs.z1_shift) &&
        gf::Eq(lhs.z2_shift, rhs.z2_shift) &&
        gf::Eq(lhs.v1_running, rhs.v1_running) &&
        gf::Eq(lhs.v2_running, rhs.v2_running) &&
        gf::Eq(lhs.ux_running, rhs.ux_running) &&
        gf::Eq(lhs.invd1, rhs.invd1) &&
        gf::Eq(lhs.invd2, rhs.invd2) &&
        gf::Eq(lhs.deep_value, rhs.deep_value) &&
        gf::Eq(
            lhs.opened_deep_value,
            rhs.opened_deep_value);
}

bool EqNormalizedDeepSparseLogUpV1(
    const NormalizedDeepSparseLogUpAuditV1& lhs,
    const NormalizedDeepSparseLogUpAuditV1& rhs)
{
    return
        lhs.prechallenge_commitment ==
            rhs.prechallenge_commitment &&
        EqChallenges(lhs.challenges, rhs.challenges) &&
        lhs.producer_records ==
            rhs.producer_records &&
        lhs.consumer_records ==
            rhs.consumer_records &&
        lhs.producer_multiplicity ==
            rhs.producer_multiplicity &&
        lhs.consumer_multiplicity ==
            rhs.consumer_multiplicity &&
        gf::Eq(lhs.terminal1, rhs.terminal1) &&
        gf::Eq(lhs.terminal2, rhs.terminal2) &&
        lhs.commit_then_challenge ==
            rhs.commit_then_challenge &&
        lhs.denominator_nonzero ==
            rhs.denominator_nonzero &&
        lhs.terminal_zero ==
            rhs.terminal_zero &&
        lhs.valid == rhs.valid;
}

} // namespace

NormalizedDeep64IntegrationV1
BuildNormalizedDeep64IntegrationV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports)
{
    NormalizedDeep64IntegrationV1 out;
    const auto& batch = proof.batch;
    out.batch_width =
        static_cast<uint32_t>(
            batch.column_len.size());
    out.queries =
        static_cast<uint32_t>(
            batch.queries.size());
    out.physical_port_records =
        uint64_t{out.queries} *
        kNormalizedDeepDerivationPorts;
    out.active_port_records =
        uint64_t{out.queries} *
        out.batch_width;
    if (!composition.valid ||
        !decoder.valid ||
        !codec_ctl.valid ||
        !remote_exports.valid ||
        out.batch_width == 0 ||
        out.batch_width >
            kNormalizedDeepDerivationPorts ||
        out.queries == 0 ||
        batch.fold_layers.empty() ||
        remote_exports.deep_tokens_remaining !=
            3 * out.batch_width + 5 ||
        !remote_exports.literal_same_row_aliases ||
        !remote_exports.
            every_direct_opening_query_path_root_fold_owned ||
        !remote_exports.
            dual_rational_identity_terminal_zero ||
        !remote_exports.denominator_nonzero) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_integration_shape";
        return out;
    }

    NormalizedDeepCanonicalSourcesV1 sources;
    if (!BuildNormalizedDeepCanonicalSourcesV1(
            proof, decoder.map, sources)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_canonical_sources";
        return out;
    }
    std::vector<
        const NormalizedAlgAirCodecSemanticTokenV1*>
        deep_tokens{
            sources.lambda, sources.z1,
            sources.z2, sources.w1, sources.w2};
    deep_tokens.insert(
        deep_tokens.end(),
        sources.column_len.begin(),
        sources.column_len.end());
    deep_tokens.insert(
        deep_tokens.end(),
        sources.eval_z1.begin(),
        sources.eval_z1.end());
    deep_tokens.insert(
        deep_tokens.end(),
        sources.eval_z2.begin(),
        sources.eval_z2.end());
    for (const auto* token : deep_tokens) {
        if (token == nullptr ||
            !NormalizedDeepDecoderTokenIsLiteralV1(
                composition, codec_ctl, *token)) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_deep64_decoder_literal";
            return out;
        }
    }
    out.canonical_deep_tokens =
        static_cast<uint32_t>(
            deep_tokens.size());

    std::vector<NormalizedRemoteExportRef> remote_refs;
    uint32_t deep_remaining = 0;
    uint32_t scheduler_remaining = 0;
    uint32_t fs_remaining = 0;
    if (!BuildNormalizedRemoteExportRefs(
            composition, proof, decoder.map,
            remote_refs, deep_remaining,
            scheduler_remaining, fs_remaining) ||
        deep_remaining != out.canonical_deep_tokens ||
        remote_refs.size() !=
            remote_exports.remote_events) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_remote_map";
        return out;
    }
    out.literal_remote_events =
        static_cast<uint32_t>(
            remote_refs.size());
    std::vector<const NormalizedRemoteExportRef*>
        remote_at_address(
            decoder.map.semantic_tokens.size() + 1,
            nullptr);
    for (const auto& ref : remote_refs) {
        if (ref.address >=
                remote_at_address.size() ||
            remote_at_address[ref.address] !=
                nullptr ||
            !gf::Eq(
                NormalizedRemoteSourceValue(
                    composition, ref),
                ref.value)) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_deep64_remote_literal";
            return out;
        }
        remote_at_address[ref.address] = &ref;
    }
    const auto remote_literal =
        [&](const NormalizedAlgAirCodecSemanticTokenV1*
                token) {
            return token != nullptr &&
                token->address <
                    remote_at_address.size() &&
                remote_at_address[token->address] !=
                    nullptr &&
                gf::Eq(
                    remote_at_address[token->address]->
                        value,
                    token->value);
        };
    for (uint32_t query = 0;
         query < out.queries; ++query) {
        if (!remote_literal(
                sources.query_index[query]) ||
            !remote_literal(
                sources.opened_deep[query])) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_deep64_query_fold_literal";
            return out;
        }
        for (uint32_t item = 0;
             item < out.batch_width; ++item) {
            if (!remote_literal(
                    sources.row_value[query][item])) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "normalized_deep64_row_literal";
                return out;
            }
        }
    }

    std::array<
        std::vector<NormalizedDeepEventV1>, 3>
        producer;
    std::array<
        std::vector<NormalizedDeepEventV1>, 3>
        consumer;
    const uint64_t sites =
        out.active_port_records;
    const auto input_producer =
        [&](const NormalizedAlgAirCodecSemanticTokenV1*
                token,
            uint64_t multiplicity) {
            producer[0].push_back({
                token->address,
                token->value,
                multiplicity,
            });
        };
    input_producer(sources.lambda, sites);
    input_producer(sources.z1, sites);
    input_producer(sources.z2, sites);
    input_producer(sources.w1, out.queries);
    input_producer(sources.w2, out.queries);
    for (uint32_t item = 0;
         item < out.batch_width; ++item) {
        input_producer(
            sources.column_len[item],
            out.queries);
        input_producer(
            sources.eval_z1[item],
            out.queries);
        input_producer(
            sources.eval_z2[item],
            out.queries);
    }
    for (uint32_t query = 0;
         query < out.queries; ++query) {
        input_producer(
            sources.query_index[query],
            out.batch_width);
        input_producer(
            sources.opened_deep[query], 1);
        for (uint32_t item = 0;
             item < out.batch_width; ++item) {
            input_producer(
                sources.row_value[query][item],
                1);
        }
    }

    out.port_witness.reserve(
        static_cast<size_t>(
            out.physical_port_records));
    out.shared_power_tables_checked = true;
    for (uint32_t query = 0;
         query < out.queries; ++query) {
        const auto& opened =
            batch.queries[query];
        const uint32_t n_lde =
            batch.fold_layers[0].n_leaves;
        const uint32_t log_lde =
            Log2Exact(n_lde);
        if (log_lde == 0 || log_lde > 32) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_deep64_domain";
            return out;
        }
        const gf::Fp omega =
            PowFp(
                kOmega2_32,
                uint64_t{1} <<
                    (32 - log_lde));
        Fp3 x_from_bits = Fp3::One();
        Fp3 omega_bit =
            Fp3::FromFp(omega);
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            if (((opened.index >> bit) & 1U) !=
                    0) {
                x_from_bits =
                    gf::Mul(
                        x_from_bits,
                        omega_bit);
            }
            omega_bit =
                gf::Mul(
                    omega_bit,
                    omega_bit);
        }
        const Fp3 x =
            DomainPoint(n_lde, opened.index);
        if (!gf::Eq(x_from_bits, x) ||
            gf::IsZero(
                gf::Sub(x, batch.z1)) ||
            gf::IsZero(
                gf::Sub(x, batch.z2))) {
            out.shared_power_tables_checked =
                false;
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_deep64_shared_tables";
            return out;
        }
        const Fp3 invd1 =
            gf::Inv(gf::Sub(x, batch.z1));
        const Fp3 invd2 =
            gf::Inv(gf::Sub(x, batch.z2));
        producer[1].push_back({
            uint64_t{query} + 1,
            x, out.batch_width,
        });
        Fp3 lambda_power = Fp3::One();
        Fp3 v1 = Fp3::Zero();
        Fp3 v2 = Fp3::Zero();
        Fp3 ux = Fp3::Zero();
        for (uint32_t port = 0;
             port <
                 kNormalizedDeepDerivationPorts;
             ++port) {
            NormalizedDeep64PortWitnessV1 record;
            record.query = query;
            record.port = port;
            record.item = port;
            record.query_index = opened.index;
            record.active =
                port < out.batch_width;
            if (!record.active) {
                out.port_witness.push_back(record);
                continue;
            }
            record.output =
                port + 1 == out.batch_width;
            record.column_len =
                batch.column_len[port];
            if (record.column_len == 0 ||
                record.column_len >
                    batch.n_coeffs) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "normalized_deep64_column_len";
                return out;
            }
            record.shift =
                batch.n_coeffs -
                record.column_len;
            record.x = x;
            record.row_value =
                opened.row.values[port];
            record.eval_z1 =
                batch.evals_z1[port];
            record.eval_z2 =
                batch.evals_z2[port];
            record.lambda_power =
                lambda_power;
            record.x_shift =
                PowFp3(x, record.shift);
            record.z1_shift =
                PowFp3(
                    batch.z1, record.shift);
            record.z2_shift =
                PowFp3(
                    batch.z2, record.shift);
            v1 = gf::Add(
                v1,
                gf::Mul(
                    gf::Mul(
                        lambda_power,
                        record.z1_shift),
                    record.eval_z1));
            v2 = gf::Add(
                v2,
                gf::Mul(
                    gf::Mul(
                        lambda_power,
                        record.z2_shift),
                    record.eval_z2));
            ux = gf::Add(
                ux,
                gf::Mul(
                    gf::Mul(
                        lambda_power,
                        record.x_shift),
                    record.row_value));
            record.v1_running = v1;
            record.v2_running = v2;
            record.ux_running = ux;
            record.invd1 = invd1;
            record.invd2 = invd2;
            record.deep_value =
                record.output
                ? gf::Add(
                      gf::Mul(
                          batch.w1,
                          gf::Mul(
                              gf::Sub(ux, v1),
                              invd1)),
                      gf::Mul(
                          batch.w2,
                          gf::Mul(
                              gf::Sub(ux, v2),
                              invd2)))
                : Fp3::Zero();
            record.opened_deep_value =
                record.output
                ? sources.opened_deep[query]->
                      value
                : Fp3::Zero();
            if (record.output &&
                !gf::Eq(
                    record.deep_value,
                    record.opened_deep_value)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "normalized_deep64_opened_value";
                return out;
            }
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        Lambda)] =
                sources.lambda->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        Z1)] =
                sources.z1->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        Z2)] =
                sources.z2->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        ColumnLen)] =
                sources.column_len[port]->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        EvalZ1)] =
                sources.eval_z1[port]->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        EvalZ2)] =
                sources.eval_z2[port]->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        W1)] =
                sources.w1->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        W2)] =
                sources.w2->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        QueryIndex)] =
                sources.query_index[query]->address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        RowValue)] =
                sources.row_value[query][port]->
                    address;
            record.source_address[
                static_cast<uint32_t>(
                    NormalizedDeepSourceLaneV1::
                        OpenedDeep)] =
                sources.opened_deep[query]->
                    address;

            for (const auto& event :
                 std::array<NormalizedDeepEventV1, 8>{
                     NormalizedDeepEventV1{
                         sources.lambda->address,
                         batch.lambda, 1},
                     NormalizedDeepEventV1{
                         sources.z1->address,
                         batch.z1, 1},
                     NormalizedDeepEventV1{
                         sources.z2->address,
                         batch.z2, 1},
                     NormalizedDeepEventV1{
                         sources.column_len[port]->
                             address,
                         Fp3::FromFp(gf::FromU64(
                             record.column_len)), 1},
                     NormalizedDeepEventV1{
                         sources.eval_z1[port]->
                             address,
                         record.eval_z1, 1},
                     NormalizedDeepEventV1{
                         sources.eval_z2[port]->
                             address,
                         record.eval_z2, 1},
                     NormalizedDeepEventV1{
                         sources.query_index[query]->
                             address,
                         Fp3::FromFp(gf::FromU64(
                             opened.index)), 1},
                     NormalizedDeepEventV1{
                         sources.row_value[query][port]->
                             address,
                         record.row_value, 1}}) {
                consumer[0].push_back(event);
            }
            consumer[1].push_back({
                uint64_t{query} + 1, x, 1});
            const uint64_t site =
                uint64_t{query} *
                    out.batch_width +
                port;
            producer[2].push_back({
                site + 1, ux, 1});
            consumer[2].push_back({
                site + 1, ux, 1});
            if (record.output) {
                consumer[0].push_back({
                    sources.w1->address,
                    batch.w1, 1});
                consumer[0].push_back({
                    sources.w2->address,
                    batch.w2, 1});
                consumer[0].push_back({
                    sources.opened_deep[query]->
                        address,
                    record.opened_deep_value, 1});
                const uint64_t base =
                    sites +
                    5 * uint64_t{query} + 1;
                for (uint32_t field = 0;
                     field < 5; ++field) {
                    const Fp3 value =
                        field == 0
                        ? v1
                        : field == 1
                        ? v2
                        : field == 2
                        ? invd1
                        : field == 3
                        ? invd2
                        : record.deep_value;
                    producer[2].push_back({
                        base + field, value, 1});
                    consumer[2].push_back({
                        base + field, value, 1});
                }
            }
            out.port_witness.push_back(record);
            lambda_power =
                gf::Mul(
                    lambda_power,
                    batch.lambda);
        }
    }
    if (out.port_witness.size() !=
            out.physical_port_records) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_physical_ports";
        return out;
    }
    out.logup[0] =
        BuildNormalizedDeepSparseLogUpAuditV1(
            "input", producer[0],
            consumer[0]);
    out.logup[1] =
        BuildNormalizedDeepSparseLogUpAuditV1(
            "read", producer[1],
            consumer[1]);
    out.logup[2] =
        BuildNormalizedDeepSparseLogUpAuditV1(
            "output", producer[2],
            consumer[2]);

    out.canonical_decoder_input_table_bound =
        out.canonical_deep_tokens ==
            3 * out.batch_width + 5;
    out.current_opening_values_literal_bound = true;
    out.query_indices_literal_bound = true;
    out.selected_fold_openings_literal_bound = true;
    out.root_path_fold_remote_bus_preserved =
        out.literal_remote_events != 0 &&
        remote_exports.
            every_direct_opening_query_path_root_fold_owned;
    out.all_64_ports_structurally_constrained =
        out.physical_port_records ==
            uint64_t{out.queries} *
                kNormalizedDeepDerivationPorts &&
        out.active_port_records ==
            uint64_t{out.queries} *
                out.batch_width;
    out.all_three_logup_terminals_zero =
        out.logup[0].valid &&
        out.logup[1].valid &&
        out.logup[2].valid;
    out.local_endpoint_executable =
        out.canonical_decoder_input_table_bound &&
        out.current_opening_values_literal_bound &&
        out.query_indices_literal_bound &&
        out.selected_fold_openings_literal_bound &&
        out.root_path_fold_remote_bus_preserved &&
        out.shared_power_tables_checked &&
        out.all_64_ports_structurally_constrained &&
        out.all_three_logup_terminals_zero;
    out.executable =
        out.local_endpoint_executable;
    out.recursive_endpoints_consumed = 0;
    out.recursive_roles_consumed = 0;
    out.recursively_consumed = false;
    out.residuals = {
        "sha256d_fiat_shamir_replay_not_yet_recursive",
        "unified_ctl_child_terminal_not_yet_recursive",
    };
    out.valid =
        out.version == 1 &&
        out.ports ==
            kNormalizedDeepDerivationPorts &&
        out.local_endpoint_executable &&
        out.executable &&
        out.recursive_endpoints_consumed == 0 &&
        out.recursive_roles_consumed == 0 &&
        !out.recursively_consumed &&
        out.residuals.size() == 2;
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_deep64_local_endpoint_executable;"
          "all_ports_and_three_logup_terminals_closed;"
          "sha_fs_and_recursive_ctl_open"
        : "stage3:recursive_fixedpoint:"
          "normalized_deep64_integration_invalid";
    return out;
}

bool ValidateNormalizedDeep64IntegrationV1(
    const FoldBusComposition& composition,
    const AlgAirProof& proof,
    const NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const NormalizedAlgAirRemoteExportAttachmentV1& remote_exports,
    const NormalizedDeep64IntegrationV1& attachment,
    std::string* why)
{
    const auto fail =
        [&](const char* reason) {
            if (why != nullptr) *why = reason;
            return false;
        };
    if (!attachment.valid ||
        !attachment.local_endpoint_executable ||
        !attachment.executable ||
        attachment.recursive_endpoints_consumed != 0 ||
        attachment.recursive_roles_consumed != 0 ||
        attachment.recursively_consumed ||
        attachment.ports !=
            kNormalizedDeepDerivationPorts) {
        return fail(
            "normalized_deep64_integration_flags");
    }
    const auto expected =
        BuildNormalizedDeep64IntegrationV1(
            composition, proof, decoder,
            codec_ctl, remote_exports);
    if (!expected.valid ||
        expected.batch_width !=
            attachment.batch_width ||
        expected.queries != attachment.queries ||
        expected.physical_port_records !=
            attachment.physical_port_records ||
        expected.active_port_records !=
            attachment.active_port_records ||
        expected.canonical_deep_tokens !=
            attachment.canonical_deep_tokens ||
        expected.literal_remote_events !=
            attachment.literal_remote_events ||
        expected.port_witness.size() !=
            attachment.port_witness.size()) {
        return fail(
            "normalized_deep64_integration_shape");
    }
    for (uint32_t index = 0;
         index < expected.port_witness.size();
         ++index) {
        if (!EqNormalizedDeepPortV1(
                expected.port_witness[index],
                attachment.port_witness[index])) {
            return fail(
                "normalized_deep64_integration_port");
        }
    }
    for (uint32_t family = 0;
         family < 3; ++family) {
        if (!EqNormalizedDeepSparseLogUpV1(
                expected.logup[family],
                attachment.logup[family])) {
            return fail(
                "normalized_deep64_integration_logup");
        }
    }
    if (expected.canonical_decoder_input_table_bound !=
            attachment.
                canonical_decoder_input_table_bound ||
        expected.current_opening_values_literal_bound !=
            attachment.
                current_opening_values_literal_bound ||
        expected.query_indices_literal_bound !=
            attachment.query_indices_literal_bound ||
        expected.selected_fold_openings_literal_bound !=
            attachment.
                selected_fold_openings_literal_bound ||
        expected.root_path_fold_remote_bus_preserved !=
            attachment.
                root_path_fold_remote_bus_preserved ||
        expected.shared_power_tables_checked !=
            attachment.shared_power_tables_checked ||
        expected.all_64_ports_structurally_constrained !=
            attachment.
                all_64_ports_structurally_constrained ||
        expected.all_three_logup_terminals_zero !=
            attachment.
                all_three_logup_terminals_zero) {
        return fail(
            "normalized_deep64_integration_closure");
    }
    return true;
}

uint256
ComputeNormalizedCoupledBankCtlTupleExportAdapterCommitmentV1(
    const NormalizedCoupledBankCtlTupleExportAdapterV1& adapter)
{
    constexpr uint32_t NAMESPACE =
        0x43425047U; // "CBPG"
    if (adapter.version != 1 ||
        adapter.role !=
            RCStage3RelationRole::CoupledBank ||
        adapter.endpoint !=
            RCStage3RelationEndpoint::CoupledBankPages ||
        adapter.namespace_id != NAMESPACE ||
        adapter.first_address != 1 ||
        adapter.producer_source_column !=
            kRCStage3CoupledBankOutput ||
        adapter.logical_rows == 0 ||
        adapter.trace_rows < adapter.logical_rows ||
        (adapter.trace_rows &
         (adapter.trace_rows - 1)) != 0 ||
        adapter.required_event_count !=
            2ULL * adapter.logical_rows ||
        adapter.required_send_count !=
            adapter.logical_rows ||
        adapter.required_receive_count !=
            adapter.logical_rows ||
        adapter.required_event_count >
            kRCStage3CtlMaxEvents ||
        adapter.source_pin_commitment.IsNull() ||
        adapter.row_pin_commitment.IsNull() ||
        adapter.producer_trace_commitment.IsNull() ||
        adapter.producer_proof_commitment.IsNull() ||
        !adapter.canonical_tuple_manifest ||
        !adapter.producer_relation_proof_verified ||
        !adapter.producer_output_column_identified ||
        adapter.producer_cells_exported ||
        adapter.consumer_proof_bound ||
        adapter.consumer_cells_exported ||
        adapter.shared_post_commit_challenges ||
        adapter.cross_proof_logup_identity ||
        adapter.executable ||
        adapter.semantic_closure ||
        adapter.residuals !=
            std::vector<std::string>{
                "producer_output_cells_not_projected_from_alg_row_commitment",
                "consumer_table_proof_tuple_export_absent",
                "shared_post_commit_ctl_challenges_and_logup_identity_absent",
            }) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_COUPLED_BANK_CTL_"
        "TUPLE_EXPORT_ADAPTER_V1";
    hash << adapter.version;
    hash << static_cast<uint16_t>(
        adapter.role);
    hash << static_cast<uint16_t>(
        adapter.endpoint);
    hash << adapter.namespace_id;
    hash << adapter.stage;
    hash << adapter.first_address;
    hash << adapter.producer_source_column;
    hash << adapter.logical_rows;
    hash << adapter.trace_rows;
    hash << adapter.required_event_count;
    hash << adapter.required_send_count;
    hash << adapter.required_receive_count;
    hash << adapter.source_pin_commitment;
    hash << adapter.row_pin_commitment;
    hash << adapter.producer_trace_commitment;
    hash << adapter.producer_proof_commitment;
    return hash.GetHash();
}

NormalizedCoupledBankCtlTupleExportAdapterV1
BuildNormalizedCoupledBankCtlTupleExportAdapterV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed)
{
    constexpr uint32_t NAMESPACE =
        0x43425047U; // "CBPG"
    NormalizedCoupledBankCtlTupleExportAdapterV1 out;
    out.namespace_id = NAMESPACE;
    out.stage = source_pin.page_index;
    out.first_address = 1;
    out.producer_source_column =
        kRCStage3CoupledBankOutput;
    out.logical_rows = source_pin.logical_rows;
    out.trace_rows = source_pin.n_rows;
    out.required_event_count =
        2ULL * source_pin.logical_rows;
    out.required_send_count =
        source_pin.logical_rows;
    out.required_receive_count =
        source_pin.logical_rows;
    out.source_pin_commitment =
        source_pin.pin_commitment;
    out.row_pin_commitment =
        row_pin.pin_commitment;
    out.producer_trace_commitment =
        proof.trace_commit;
    out.producer_proof_commitment =
        ComputeNormalizedAlgAirProofCommitment(
            proof);
    std::string proof_why;
    if (source_pin.pin_commitment.IsNull() ||
        source_pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(
                source_pin) ||
        row_pin.pin_commitment.IsNull() ||
        row_pin.pin_commitment !=
            ComputeNormalizedCoupledBankRowPinCommitment(
                row_pin) ||
        row_pin.source_pin_commitment !=
            source_pin.pin_commitment ||
        row_pin.trace_row_commitment !=
            proof.trace_commit ||
        source_pin.logical_rows == 0 ||
        source_pin.logical_rows >
            source_pin.n_rows ||
        2ULL * source_pin.logical_rows >
            kRCStage3CtlMaxEvents ||
        out.producer_proof_commitment.IsNull() ||
        !VerifyNormalizedCoupledBankProof(
            source_pin, row_pin, proof,
            fs_seed, &proof_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_ctl_tuple_adapter_producer:" +
            proof_why;
        return out;
    }
    out.canonical_tuple_manifest = true;
    out.producer_relation_proof_verified = true;
    out.producer_output_column_identified = true;

    // A row commitment binds the ordered full row, but does not expose a
    // commitment to OUTPUT alone.  Treating the source pin's legacy SHA
    // column root or a prover-supplied value vector as that projection would
    // recreate the shared-commitment hybrid gap.  The consumer/table proof is
    // likewise not an input to this API, so every semantic-closure flag stays
    // false.
    out.producer_cells_exported = false;
    out.consumer_proof_bound = false;
    out.consumer_cells_exported = false;
    out.shared_post_commit_challenges = false;
    out.cross_proof_logup_identity = false;
    out.executable = false;
    out.semantic_closure = false;
    out.residuals = {
        "producer_output_cells_not_projected_from_alg_row_commitment",
        "consumer_table_proof_tuple_export_absent",
        "shared_post_commit_ctl_challenges_and_logup_identity_absent",
    };
    out.adapter_commitment =
        ComputeNormalizedCoupledBankCtlTupleExportAdapterCommitmentV1(
            out);
    out.valid = !out.adapter_commitment.IsNull();
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_bank_ctl_tuple_manifest_bound;"
          "semantic_adapter_fail_closed"
        : "stage3:recursive_fixedpoint:"
          "normalized_bank_ctl_tuple_adapter_invalid";
    return out;
}

bool ValidateNormalizedCoupledBankCtlTupleExportAdapterV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankRowPin& row_pin,
    const AlgAirProof& proof,
    const uint256& fs_seed,
    const NormalizedCoupledBankCtlTupleExportAdapterV1& adapter,
    std::string* why)
{
    if (!adapter.valid ||
        adapter.executable ||
        adapter.semantic_closure ||
        adapter.producer_cells_exported ||
        adapter.consumer_proof_bound ||
        adapter.consumer_cells_exported ||
        adapter.shared_post_commit_challenges ||
        adapter.cross_proof_logup_identity) {
        return Fail(
            why,
            "normalized_bank_ctl_tuple_adapter_flags");
    }
    const auto expected =
        BuildNormalizedCoupledBankCtlTupleExportAdapterV1(
            source_pin, row_pin, proof, fs_seed);
    if (!expected.valid ||
        !(expected == adapter)) {
        return Fail(
            why,
            "normalized_bank_ctl_tuple_adapter_binding");
    }
    return true;
}

bool BuildNormalizedCoupledBankCtlRootScheduleV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    RCStage3CtlSchedule& schedule,
    std::vector<Fp3>& values,
    std::string* why)
{
    schedule.events.clear();
    values.clear();
    if (source_pin.version !=
            kRCStage3CoupledBankProductVersion ||
        source_pin.pin_commitment.IsNull() ||
        source_pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(
                source_pin) ||
        source_pin.r0_row_group_root.IsNull()) {
        return Fail(
            why,
            "normalized_deep64_ctl_source_pin");
    }
    constexpr uint32_t NAMESPACE =
        0x43424b52U; // "CBKR"
    schedule.events.reserve(2 * 8);
    values.reserve(schedule.events.capacity());
    for (uint32_t limb = 0;
         limb < 8; ++limb) {
        const Fp3 value =
            Fp3::FromFp(
                gf::FromU64(
                    Uint256Limb32(
                        source_pin.r0_row_group_root,
                        limb)));
        const uint32_t address = 1 + limb;
        schedule.events.push_back({
            NAMESPACE,
            source_pin.page_index,
            address,
            1,
        });
        values.push_back(value);
        schedule.events.push_back({
            NAMESPACE,
            source_pin.page_index,
            address,
            -1,
        });
        values.push_back(value);
    }
    if (!ValidateRCStage3CtlSchedule(
            schedule, why) ||
        schedule.events.size() != values.size() ||
        schedule.events.size() != 2 * 8) {
        schedule.events.clear();
        values.clear();
        return false;
    }
    return true;
}

namespace {

void AppendDeepCtlU32V1(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    for (uint32_t byte = 0;
         byte < 4; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

void AppendDeepCtlFp3V1(
    std::vector<unsigned char>& out,
    const Fp3& value)
{
    for (gf::Fp coordinate :
         std::array<gf::Fp, 3>{
             value.c0, value.c1, value.c2}) {
        for (uint32_t byte = 0;
             byte < 8; ++byte) {
            out.push_back(
                static_cast<unsigned char>(
                    gf::Canonical(coordinate) >>
                    (8 * byte)));
        }
    }
}

void AppendDeepCtlHashV1(
    std::vector<unsigned char>& out,
    const uint256& value)
{
    out.insert(
        out.end(),
        value.begin(), value.end());
}

bool BuildNormalizedDeepCtlProofCodecV1(
    const RCStage3CtlChildPin& child,
    const RCStage3CtlRelationExportPin& relation_export,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<unsigned char> child_bytes;
    std::vector<unsigned char> export_bytes;
    std::vector<unsigned char> batch_bytes;
    if (!SerializeRCStage3CtlChildPin(
            child, child_bytes) ||
        !SerializeRCStage3CtlRelationExportPin(
            relation_export, export_bytes) ||
        !ValidateRCStage3CtlSchedule(
            schedule, nullptr) ||
        SerializeFri3BatchProof(
            proof.batch, batch_bytes) == 0 ||
        batch_bytes.size() >
            kRCFriMaxProofBytesHard ||
        proof.next_openings.size() >
            UINT32_MAX) {
        return false;
    }
    const std::string domain =
        "BTX_RC_STAGE3_NORMALIZED_DEEP64_CTL_PROOF_CODEC_V1";
    out.insert(
        out.end(),
        domain.begin(), domain.end());
    AppendDeepCtlU32V1(
        out,
        static_cast<uint32_t>(
            child_bytes.size()));
    out.insert(
        out.end(),
        child_bytes.begin(), child_bytes.end());
    AppendDeepCtlU32V1(
        out,
        static_cast<uint32_t>(
            export_bytes.size()));
    out.insert(
        out.end(),
        export_bytes.begin(), export_bytes.end());
    AppendDeepCtlU32V1(
        out,
        static_cast<uint32_t>(
            schedule.events.size()));
    for (const auto& event :
         schedule.events) {
        AppendDeepCtlU32V1(
            out, event.namespace_id);
        AppendDeepCtlU32V1(
            out, event.stage);
        AppendDeepCtlU32V1(
            out, event.address);
        out.push_back(
            static_cast<unsigned char>(
                event.multiplicity));
    }
    if (batch_bytes.size() > UINT32_MAX) {
        return false;
    }
    AppendDeepCtlU32V1(
        out,
        static_cast<uint32_t>(
            batch_bytes.size()));
    out.insert(
        out.end(),
        batch_bytes.begin(), batch_bytes.end());
    AppendDeepCtlHashV1(
        out, proof.trace_commit);
    AppendDeepCtlU32V1(
        out,
        static_cast<uint32_t>(
            proof.next_openings.size()));
    for (const auto& paths :
         proof.next_openings) {
        if (paths.size() > UINT32_MAX) {
            return false;
        }
        AppendDeepCtlU32V1(
            out,
            static_cast<uint32_t>(
                paths.size()));
        for (const auto& path : paths) {
            if (path.siblings.size() >
                    UINT32_MAX) {
                return false;
            }
            AppendDeepCtlU32V1(
                out, path.index);
            AppendDeepCtlFp3V1(
                out, path.leaf);
            AppendDeepCtlU32V1(
                out,
                static_cast<uint32_t>(
                    path.siblings.size()));
            for (const auto& sibling :
                 path.siblings) {
                AppendDeepCtlHashV1(
                    out, sibling);
            }
        }
    }
    return !out.empty() &&
        out.size() <= kRCFriMaxProofBytesHard;
}

bool BuildNormalizedDeepCtlProofFieldsV1(
    const std::vector<unsigned char>& bytes,
    std::vector<Fp3>& fields,
    uint256& commitment)
{
    fields.clear();
    commitment.SetNull();
    if (bytes.empty() ||
        bytes.size() > UINT32_MAX) {
        return false;
    }
    std::vector<gf::Fp> base_fields;
    base_fields.reserve(
        1 + CeilDiv(bytes.size(), 4));
    base_fields.push_back(
        gf::FromU64(bytes.size()));
    for (size_t offset = 0;
         offset < bytes.size();
         offset += 4) {
        uint32_t word = 0;
        for (uint32_t byte = 0;
             byte < 4 &&
             offset + byte < bytes.size();
             ++byte) {
            word |=
                uint32_t{bytes[offset + byte]}
                << (8 * byte);
        }
        base_fields.push_back(
            gf::FromU64(word));
    }
    fields.reserve(base_fields.size());
    for (gf::Fp value : base_fields) {
        fields.push_back(
            Fp3::FromFp(value));
    }
    commitment =
        aq::AirFriBackendAlg<Fp3>::PackDigest(
            ah::SpongeHashFp(base_fields));
    return !commitment.IsNull();
}

bool EqNormalizedDeepCtlAttachmentV1(
    const NormalizedDeep64CtlTerminalAttachmentV1& lhs,
    const NormalizedDeep64CtlTerminalAttachmentV1& rhs)
{
    if (lhs.version != rhs.version ||
        !(lhs.relation_export ==
          rhs.relation_export) ||
        lhs.child_index != rhs.child_index ||
        lhs.event_count != rhs.event_count ||
        lhs.send_count != rhs.send_count ||
        lhs.receive_count != rhs.receive_count ||
        lhs.proof_codec_bytes !=
            rhs.proof_codec_bytes ||
        lhs.proof_field_count !=
            rhs.proof_field_count ||
        lhs.proof_transport_commitment !=
            rhs.proof_transport_commitment ||
        lhs.terminal_bus_commitment !=
            rhs.terminal_bus_commitment ||
        lhs.proof_fields.size() !=
            rhs.proof_fields.size()) {
        return false;
    }
    for (uint32_t index = 0;
         index < lhs.proof_fields.size();
         ++index) {
        const Fp3& left =
            lhs.proof_fields[index];
        const Fp3& right =
            rhs.proof_fields[index];
        if (left.c0 >= gf::kP ||
            left.c1 >= gf::kP ||
            left.c2 >= gf::kP ||
            right.c0 >= gf::kP ||
            right.c1 >= gf::kP ||
            right.c2 >= gf::kP ||
            left.c0 != right.c0 ||
            left.c1 != right.c1 ||
            left.c2 != right.c2) {
            return false;
        }
    }
    return
        lhs.canonical_relation_root_tuples ==
            rhs.canonical_relation_root_tuples &&
        lhs.relation_value_column_bound ==
            rhs.relation_value_column_bound &&
        lhs.prechallenge_commitments_bound ==
            rhs.prechallenge_commitments_bound &&
        lhs.challenges_after_commitments ==
            rhs.challenges_after_commitments &&
        lhs.denominator_nonzero_constraints_verified ==
            rhs.denominator_nonzero_constraints_verified &&
        lhs.multiplicity_accumulators_verified ==
            rhs.multiplicity_accumulators_verified &&
        lhs.selected_child_terminal_zero ==
            rhs.selected_child_terminal_zero &&
        lhs.public_pin_terminal_equality_verified ==
            rhs.public_pin_terminal_equality_verified &&
        lhs.all_participant_child_proofs_verified ==
            rhs.all_participant_child_proofs_verified &&
        lhs.global_terminal_equality_verified ==
            rhs.global_terminal_equality_verified &&
        lhs.proof_codec_canonical ==
            rhs.proof_codec_canonical &&
        lhs.proof_field_transport_bound ==
            rhs.proof_field_transport_bound &&
        lhs.terminal_semantic_lanes_linked ==
            rhs.terminal_semantic_lanes_linked &&
        lhs.semantic_slot_and_sponge_binding_verified ==
            rhs.semantic_slot_and_sponge_binding_verified &&
        lhs.child_proof_verified_natively ==
            rhs.child_proof_verified_natively &&
        lhs.root_inventory_transport_only ==
            rhs.root_inventory_transport_only &&
        lhs.actual_producer_relation_tuples_bound ==
            rhs.actual_producer_relation_tuples_bound &&
        lhs.actual_consumer_proof_tuples_bound ==
            rhs.actual_consumer_proof_tuples_bound &&
        lhs.cross_proof_logup_identity_verified ==
            rhs.cross_proof_logup_identity_verified &&
        lhs.ctl_semantic_closure ==
            rhs.ctl_semantic_closure &&
        lhs.complete_sha_fiat_shamir_replay_in_parent ==
            rhs.complete_sha_fiat_shamir_replay_in_parent &&
        lhs.endpoint_promoted ==
            rhs.endpoint_promoted &&
        lhs.authority == rhs.authority &&
        lhs.recursive_endpoints_consumed ==
            rhs.recursive_endpoints_consumed &&
        lhs.recursive_roles_consumed ==
            rhs.recursive_roles_consumed &&
        lhs.recursively_consumed ==
            rhs.recursively_consumed &&
        lhs.residuals == rhs.residuals &&
        lhs.valid == rhs.valid;
}

} // namespace

namespace {

constexpr uint32_t kNormalizedBankSemanticCtlNamespaceV1 =
    0x43323831U; // "C281"
constexpr uint32_t kNormalizedBankSemanticCtlBusV1 =
    0x43324231U; // "C2B1"

bool BuildNormalizedBankSemanticSchedulesV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    RCStage3CtlSchedule& producer,
    RCStage3CtlSchedule& consumer)
{
    producer.events.clear();
    consumer.events.clear();
    if (source_pin.logical_rows == 0 ||
        source_pin.logical_rows >
            source_pin.n_rows ||
        source_pin.n_rows < 2 ||
        (source_pin.n_rows &
         (source_pin.n_rows - 1)) != 0 ||
        source_pin.n_rows !=
            NextPow2(source_pin.logical_rows)) {
        return false;
    }
    producer.events.reserve(
        source_pin.logical_rows);
    consumer.events.reserve(
        source_pin.logical_rows);
    for (uint32_t row = 0;
         row < source_pin.logical_rows;
         ++row) {
        const RCStage3CtlEvent send{
            kNormalizedBankSemanticCtlNamespaceV1,
            source_pin.page_index,
            1 + row,
            1,
        };
        RCStage3CtlEvent receive = send;
        receive.multiplicity = -1;
        producer.events.push_back(send);
        consumer.events.push_back(receive);
    }
    return ValidateRCStage3CtlSchedule(
               producer, nullptr) &&
        ValidateRCStage3CtlSchedule(
            consumer, nullptr);
}

RCStage3CtlParticipantSpec
NormalizedBankSemanticParticipantV1(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count =
        schedule.events.size();
    for (const auto& event :
         schedule.events) {
        out.send_count +=
            event.multiplicity == 1 ? 1 : 0;
        out.receive_count +=
            event.multiplicity == -1 ? 1 : 0;
    }
    out.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    return out;
}

uint256 NormalizedBankSemanticTranscriptSeedV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const uint256& fs_seed)
{
    if (source_pin.pin_commitment.IsNull() ||
        fs_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "PROJECTION_BRIDGE_TRANSCRIPT_V1";
    hash << source_pin.pin_commitment;
    hash << fs_seed;
    return hash.GetHash();
}

std::vector<uint32_t>
NormalizedBankSemanticProducerBaseColumnsV1()
{
    std::vector<uint32_t> out;
    out.reserve(
        kRCStage3CoupledBankDequantColumns +
        5);
    for (uint32_t column = 0;
         column <
             kRCStage3CoupledBankDequantColumns;
         ++column) {
        out.push_back(column);
    }
    const uint32_t ctl_base =
        kRCStage3CoupledBankDequantColumns;
    for (uint32_t column =
             stage3_ctl_col::NAMESPACE;
         column <=
             stage3_ctl_col::MULTIPLICITY;
         ++column) {
        out.push_back(ctl_base + column);
    }
    return out;
}

uint256 CommitNormalizedBankSemanticProducerProofV1(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes) == 0) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "PRODUCER_SPLIT_RAP_V1";
    hash << bytes;
    return hash.GetHash();
}

uint256 NormalizedBankSemanticProducerSeedV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const uint256& fs_seed,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    const uint256& projection_root)
{
    if (fs_seed.IsNull() ||
        fs_seed !=
            ComputeRCStage3CoupledBankDequantSeed(
                source_pin) ||
        source_pin.pin_commitment.IsNull() ||
        projection_root.IsNull() ||
        pins.size() != 2 ||
        manifest.participants.size() != 2) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "PRODUCER_SEED_V1";
    hash << fs_seed;
    hash << source_pin.pin_commitment;
    hash << manifest.bus_id;
    hash << manifest.transcript_seed;
    for (const auto& participant :
         manifest.participants) {
        hash << static_cast<uint16_t>(
            participant.role);
        hash << participant.event_count;
        hash << participant.send_count;
        hash << participant.receive_count;
        hash << participant.schedule_commitment;
    }
    for (const auto& pin : pins) {
        hash << static_cast<uint16_t>(
            pin.role);
        hash << pin.schedule_commitment;
        hash << pin.trace_commitment;
        hash << pin.challenge_commitment;
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c0);
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c1);
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c2);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c0);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c1);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c2);
    }
    hash << projection_root;
    return hash.GetHash();
}

uint256 CommitNormalizedBankSemanticProofV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankCtlProjectionBridgeProofV1& proof)
{
    if (proof.version != 1 ||
        source_pin.pin_commitment.IsNull() ||
        proof.pins.size() != 2 ||
        proof.manifest.participants.size() != 2 ||
        proof.output_projection_root.IsNull() ||
        proof.producer_proof_commitment.IsNull() ||
        proof.mirror_proof_commitment.IsNull()) {
        return {};
    }
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    const uint256 producer_schedule =
        CommitRCStage3CtlSchedule(
            proof.producer_schedule);
    const uint256 mirror_schedule =
        CommitRCStage3CtlSchedule(
            proof.mirror_schedule);
    const uint256 export_commitment =
        CommitRCStage3CtlRelationExportPin(
            proof.mirror_export);
    if (composition.IsNull() ||
        producer_schedule.IsNull() ||
        mirror_schedule.IsNull() ||
        export_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "PROJECTION_BRIDGE_PROOF_V1";
    hash << proof.version;
    hash << source_pin.pin_commitment;
    hash << proof.manifest.bus_id;
    hash << proof.manifest.transcript_seed;
    hash << composition;
    hash << producer_schedule;
    hash << mirror_schedule;
    hash << export_commitment;
    hash << proof.output_projection_root;
    hash << proof.producer_proof_commitment;
    hash << proof.mirror_proof_commitment;
    return hash.GetHash();
}

uint256 NormalizedBankSemanticTerminalCommitmentV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankCtlProjectionBridgeProofV1& proof)
{
    if (proof.proof_commitment.IsNull() ||
        proof.output_projection_root.IsNull()) {
        return {};
    }
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (composition.IsNull()) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "PROJECTION_BRIDGE_TERMINAL_V1";
    hash << source_pin.statement_commitment;
    hash << source_pin.pin_commitment;
    hash << proof.output_projection_root;
    hash << proof.proof_commitment;
    hash << composition;
    return hash.GetHash();
}

bool CanonicalNormalizedBankSemanticManifestV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const uint256& fs_seed,
    const NormalizedCoupledBankCtlProjectionBridgeProofV1& proof)
{
    RCStage3CtlSchedule producer;
    RCStage3CtlSchedule consumer;
    if (!BuildNormalizedBankSemanticSchedulesV1(
            source_pin, producer,
            consumer) ||
        proof.producer_schedule != producer ||
        proof.mirror_schedule != consumer ||
        proof.manifest.bus_id !=
            kNormalizedBankSemanticCtlBusV1 ||
        proof.manifest.transcript_seed !=
            NormalizedBankSemanticTranscriptSeedV1(
                source_pin, fs_seed) ||
        proof.manifest.participants.size() != 2) {
        return false;
    }
    const std::array<
        RCStage3CtlParticipantSpec, 2>
        expected{
            NormalizedBankSemanticParticipantV1(
                RCStage3RelationRole::
                    CoupledBank,
                producer),
            NormalizedBankSemanticParticipantV1(
                RCStage3RelationRole::
                    CompositionLink,
                consumer),
        };
    return
        proof.manifest.participants[0] ==
            expected[0] &&
        proof.manifest.participants[1] ==
            expected[1];
}

} // namespace

bool ProveNormalizedCoupledBankCtlProjectionBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<std::vector<Fp3>>&
        relation_columns,
    const uint256& fs_seed,
    NormalizedCoupledBankCtlProjectionBridgeProofV1& out,
    std::string* why)
{
    out = {};
    const uint256 source_commitment =
        ComputeRCStage3CoupledBankDequantPinCommitment(
            source_pin);
    if (fs_seed.IsNull() ||
        fs_seed !=
            ComputeRCStage3CoupledBankDequantSeed(
                source_pin) ||
        source_commitment.IsNull() ||
        source_pin.pin_commitment !=
            source_commitment ||
        relation_columns.size() !=
            kRCStage3CoupledBankDequantColumns) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_shape");
    }
    for (const auto& column :
         relation_columns) {
        if (column.size() !=
                source_pin.n_rows) {
            return Fail(
                why,
                "normalized_bank_semantic_prove_rows");
        }
    }
    if (!BuildNormalizedBankSemanticSchedulesV1(
            source_pin,
            out.producer_schedule,
            out.mirror_schedule)) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_schedule");
    }
    out.manifest.bus_id =
        kNormalizedBankSemanticCtlBusV1;
    out.manifest.transcript_seed =
        NormalizedBankSemanticTranscriptSeedV1(
            source_pin, fs_seed);
    out.manifest.participants = {
        NormalizedBankSemanticParticipantV1(
            RCStage3RelationRole::CoupledBank,
            out.producer_schedule),
        NormalizedBankSemanticParticipantV1(
            RCStage3RelationRole::CompositionLink,
            out.mirror_schedule),
    };
    if (out.manifest.transcript_seed.IsNull()) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_manifest");
    }

    std::vector<Fp3> values(
        relation_columns[
            kRCStage3CoupledBankOutput]
            .begin(),
        relation_columns[
            kRCStage3CoupledBankOutput]
            .begin() +
            source_pin.logical_rows);

    // Commit the producer R0 group with a harmless placeholder challenge.
    // Only relation columns and CTL N/S/A/V/M enter this retained group; all
    // challenge-dependent inverse/running columns are excluded.
    const RCStage3CtlChallenges placeholder{
        Fp3::FromFp(gf::FromU64(2)),
        Fp3::FromFp(gf::FromU64(3)),
        Fp3::FromFp(gf::FromU64(5)),
        Fp3::FromFp(gf::FromU64(7)),
    };
    RCStage3CtlWitness placeholder_ctl;
    placeholder_ctl.ok = true;
    placeholder_ctl.columns.assign(
        stage3_ctl_col::NUM_COLUMNS,
        std::vector<Fp3>(
            source_pin.n_rows,
            Fp3::Zero()));
    for (uint32_t row = 0;
         row < source_pin.logical_rows;
         ++row) {
        const auto& event =
            out.producer_schedule.events[row];
        placeholder_ctl.columns[
            stage3_ctl_col::NAMESPACE][row] =
            Fp3::FromFp(
                gf::FromU64(
                    event.namespace_id));
        placeholder_ctl.columns[
            stage3_ctl_col::STAGE][row] =
            Fp3::FromFp(
                gf::FromU64(event.stage));
        placeholder_ctl.columns[
            stage3_ctl_col::ADDRESS][row] =
            Fp3::FromFp(
                gf::FromU64(event.address));
        placeholder_ctl.columns[
            stage3_ctl_col::VALUE][row] =
            values[row];
        placeholder_ctl.columns[
            stage3_ctl_col::MULTIPLICITY][row] =
            Fp3::One();
    }
    aq::AirConstraintSystem<Fp3>
        relation_cs;
    if (!BuildNormalizedCoupledBankConstraintSystem(
            source_pin, relation_cs, why)) {
        return false;
    }
    aq::AirConstraintSystem<Fp3>
        placeholder_combined;
    RCStage3RelationCtlDirectAliasLayout
        placeholder_layout;
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            relation_cs,
            {out.producer_schedule,
             placeholder,
             placeholder_ctl.terminal},
            kRCStage3CoupledBankOutput,
            placeholder_combined,
            &placeholder_layout, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>>
        placeholder_columns;
    if (!BuildRCStage3RelationCtlDirectAliasWitness(
            placeholder_layout,
            relation_columns,
            placeholder_ctl,
            placeholder_columns,
            why)) {
        return false;
    }
    const auto base_indices =
        NormalizedBankSemanticProducerBaseColumnsV1();
    const auto r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            placeholder_combined,
            placeholder_columns,
            base_indices);
    if (!r0_session.valid ||
        r0_session.base_row_commitment.IsNull()) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_r0:" +
                r0_session.note);
    }

    out.pins.resize(2);
    for (size_t index = 0;
         index < out.pins.size();
         ++index) {
        const auto& participant =
            out.manifest.participants[index];
        auto& pin = out.pins[index];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count =
            participant.event_count;
        pin.send_count =
            participant.send_count;
        pin.receive_count =
            participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
    }
    out.pins[0].trace_commitment =
        r0_session.base_row_commitment;
    out.pins[1].trace_commitment =
        ComputeRCStage3CtlPrechallengeTraceCommitment(
            out.mirror_schedule, values);
    if (out.pins[1].trace_commitment.IsNull()) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_consumer_r0");
    }

    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            out.manifest, out.pins,
            challenges, why)) {
        return false;
    }
    const auto producer_witness =
        BuildRCStage3CtlWitness(
            out.producer_schedule,
            values, challenges);
    const auto consumer_witness =
        BuildRCStage3CtlWitness(
            out.mirror_schedule,
            values, challenges);
    if (!producer_witness.ok ||
        !consumer_witness.ok) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_witness");
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (auto& pin : out.pins) {
        pin.challenge_commitment =
            challenge_commitment;
    }
    out.pins[0].terminal =
        producer_witness.terminal;
    out.pins[1].terminal =
        consumer_witness.terminal;

    aq::AirConstraintSystem<Fp3>
        producer_cs;
    RCStage3RelationCtlDirectAliasLayout
        producer_layout;
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            relation_cs,
            {out.producer_schedule,
             challenges,
             producer_witness.terminal},
            kRCStage3CoupledBankOutput,
            producer_cs,
            &producer_layout, why)) {
        return false;
    }
    std::vector<std::vector<Fp3>>
        producer_columns;
    if (!BuildRCStage3RelationCtlDirectAliasWitness(
            producer_layout,
            relation_columns,
            producer_witness,
            producer_columns, why)) {
        return false;
    }

    const auto consumer_cs =
        BuildRCStage3CtlConstraintSystem({
            out.mirror_schedule,
            challenges,
            consumer_witness.terminal});
    const uint32_t consumer_n_coeffs =
        FriNextPow2(std::max(
            consumer_cs.n_rows,
            consumer_cs.QuotientLen()));
    out.output_projection_root =
        aq::AirCommittedValuesRoot<Fp3>(
            consumer_witness.columns[
                stage3_ctl_col::VALUE],
            consumer_n_coeffs);
    const uint256 producer_seed =
        NormalizedBankSemanticProducerSeedV1(
            source_pin, fs_seed,
            out.manifest, out.pins,
            out.output_projection_root);
    const auto producer_proved =
        aq::AirQuotientProveRowsSplitRap(
            producer_cs, producer_columns,
            base_indices, producer_seed, {},
            &r0_session);
    if (!producer_proved.ok ||
        !producer_proved.division_exact) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_producer:" +
                producer_proved.note);
    }
    out.producer_proof =
        producer_proved.proof;
    out.producer_proof_commitment =
        CommitNormalizedBankSemanticProducerProofV1(
            out.producer_proof);
    out.pins[0].auxiliary_commitment =
        out.producer_proof_commitment;
    if (out.producer_proof_commitment.IsNull()) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_producer_codec");
    }

    const uint256 consumer_seed =
        ComputeRCStage3CtlAirSeed(
            out.manifest, out.pins[1]);
    const auto consumer_proved =
        aq::AirQuotientProve<Fp3>(
            consumer_cs,
            consumer_witness.columns,
            consumer_seed, {});
    if (!consumer_proved.ok ||
        !consumer_proved.division_exact) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_consumer:" +
                consumer_proved.note);
    }
    out.mirror_proof =
        consumer_proved.proof;
    out.pins[1].auxiliary_commitment =
        ComputeRCStage3CtlAuxiliaryCommitment(
            out.mirror_proof);

    out.mirror_export.role =
        RCStage3RelationRole::CompositionLink;
    out.mirror_export.bus_id =
        out.manifest.bus_id;
    out.mirror_export.event_count =
        out.mirror_schedule.events.size();
    out.mirror_export.relation_commitment =
        source_pin.pin_commitment;
    out.mirror_export.schedule_commitment =
        CommitRCStage3CtlSchedule(
            out.mirror_schedule);
    out.mirror_export.n_rows =
        out.mirror_proof.batch.column_len[
            stage3_ctl_col::VALUE];
    out.mirror_export.n_coeffs =
        out.mirror_proof.batch.n_coeffs;
    for (uint32_t column =
             stage3_ctl_col::NAMESPACE;
         column <=
             stage3_ctl_col::MULTIPLICITY;
         ++column) {
        out.mirror_export.
            prechallenge_column_roots[column] =
            out.mirror_proof.batch
                .columns[column].root;
    }
    if (out.mirror_export.
            prechallenge_column_roots[
                stage3_ctl_col::VALUE] !=
            out.output_projection_root) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_projection_root");
    }
    std::vector<unsigned char> consumer_codec;
    if (!BuildNormalizedDeepCtlProofCodecV1(
            out.pins[1],
            out.mirror_export,
            out.mirror_schedule,
            out.mirror_proof,
            consumer_codec)) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_consumer_codec");
    }
    HashWriter consumer_hash;
    consumer_hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "MIRROR_PROJECTION_PROOF_V1";
    consumer_hash << consumer_codec;
    out.mirror_proof_commitment =
        consumer_hash.GetHash();
    out.proof_commitment =
        CommitNormalizedBankSemanticProofV1(
            source_pin, out);
    out.terminal_bus_commitment =
        NormalizedBankSemanticTerminalCommitmentV1(
            source_pin, out);
    if (out.pins[1].auxiliary_commitment.IsNull() ||
        out.mirror_proof_commitment.IsNull() ||
        out.proof_commitment.IsNull() ||
        out.terminal_bus_commitment.IsNull()) {
        return Fail(
            why,
            "normalized_bank_semantic_prove_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "normalized_bank_projection_bridge_proved_native";
    }
    return true;
}

NormalizedCoupledBankCtlProjectionBridgeAuditV1
VerifyNormalizedCoupledBankCtlProjectionBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedCoupledBankCtlProjectionBridgeProofV1& proof,
    const uint256& fs_seed,
    const FoldBusComposition& composition,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge)
{
    NormalizedCoupledBankCtlProjectionBridgeAuditV1 out;
    out.logical_rows =
        source_pin.logical_rows;
    out.output_projection_root =
        proof.output_projection_root;
    out.proof_commitment =
        proof.proof_commitment;
    const auto fail =
        [&](const std::string& reason) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_bank_projection_bridge:" +
                reason;
            return out;
        };
    if (proof.version != 1 ||
        fs_seed.IsNull() ||
        fs_seed !=
            ComputeRCStage3CoupledBankDequantSeed(
                source_pin) ||
        source_pin.pin_commitment.IsNull() ||
        source_pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(
                source_pin) ||
        proof.pins.size() != 2 ||
        !CanonicalNormalizedBankSemanticManifestV1(
            source_pin, fs_seed, proof)) {
        return fail("shape_or_manifest");
    }
    out.producer_events =
        proof.producer_schedule.events.size();
    out.mirror_events =
        proof.mirror_schedule.events.size();
    out.exact_tuple_schedule =
        out.producer_events ==
            source_pin.logical_rows &&
        out.mirror_events ==
            source_pin.logical_rows;

    RCStage3CtlChallenges challenges;
    std::string verify_why;
    if (!DeriveRCStage3CtlChallenges(
            proof.manifest, proof.pins,
            challenges, &verify_why)) {
        return fail(
            "challenges:" + verify_why);
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    if (proof.pins[0].challenge_commitment !=
            challenge_commitment ||
        proof.pins[1].challenge_commitment !=
            challenge_commitment) {
        return fail("challenge_commitment");
    }
    out.shared_post_commit_challenges = true;

    aq::AirConstraintSystem<Fp3>
        relation_cs;
    if (!BuildNormalizedCoupledBankConstraintSystem(
            source_pin, relation_cs,
            &verify_why)) {
        return fail(
            "relation_cs:" + verify_why);
    }
    aq::AirConstraintSystem<Fp3>
        producer_cs;
    RCStage3RelationCtlDirectAliasLayout
        producer_layout;
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            relation_cs,
            {proof.producer_schedule,
             challenges,
             proof.pins[0].terminal},
            kRCStage3CoupledBankOutput,
            producer_cs,
            &producer_layout,
            &verify_why)) {
        return fail(
            "producer_cs:" + verify_why);
    }
    const auto base_indices =
        NormalizedBankSemanticProducerBaseColumnsV1();
    if (proof.producer_proof.
            base_column_indices !=
            base_indices ||
        proof.producer_proof.batch.groups.size() !=
            3 ||
        Fri3AlgDigestToUint256(
            proof.producer_proof.batch
                .groups[0].row_commit.root) !=
            proof.pins[0].trace_commitment) {
        return fail("producer_r0_binding");
    }
    const uint256 producer_seed =
        NormalizedBankSemanticProducerSeedV1(
            source_pin, fs_seed,
            proof.manifest, proof.pins,
            proof.output_projection_root);
    if (!aq::AirQuotientVerifyRowsSplitRap(
            producer_cs,
            proof.producer_proof,
            base_indices,
            producer_seed,
            &verify_why)) {
        return fail(
            "producer_proof:" + verify_why);
    }
    out.producer_relation_output_same_trace =
        producer_layout.same_trace &&
        producer_layout.direct_alias &&
        producer_layout.source_column ==
            kRCStage3CoupledBankOutput &&
        producer_layout.ctl_value_column ==
            static_cast<uint32_t>(
                kRCStage3CoupledBankDequantColumns) +
                stage3_ctl_col::VALUE;
    out.producer_split_rap_verified = true;

    if (proof.mirror_proof.batch.columns.size() !=
            stage3_ctl_col::NUM_COLUMNS + 1 ||
        proof.mirror_proof.batch.column_len.size() !=
            stage3_ctl_col::NUM_COLUMNS + 1 ||
        proof.mirror_proof.batch.columns[
            stage3_ctl_col::VALUE].root !=
            proof.output_projection_root ||
        !VerifyRCStage3CtlRelationExportBinding(
            proof.mirror_export,
            proof.pins[1],
            proof.mirror_schedule,
            proof.mirror_proof,
            source_pin.pin_commitment,
            &verify_why)) {
        return fail(
            "consumer_projection:" +
            verify_why);
    }
    out.mirror_projection_root_verified =
        true;
    if (!VerifyRCStage3CtlChildAirProof(
            proof.manifest, proof.pins, 1,
            proof.mirror_schedule,
            proof.mirror_proof,
            &verify_why)) {
        return fail(
            "consumer_proof:" + verify_why);
    }
    out.mirror_ctl_child_verified = true;
    if (!VerifyRCStage3CtlPublicPinComposition(
            proof.manifest, proof.pins,
            &verify_why)) {
        return fail(
            "terminal:" + verify_why);
    }
    out.dual_logup_terminal_equality = true;
    out.projection_self_consistency_verified =
        out.exact_tuple_schedule &&
        out.producer_relation_output_same_trace &&
        out.producer_split_rap_verified &&
        out.mirror_projection_root_verified &&
        out.mirror_ctl_child_verified &&
        out.shared_post_commit_challenges &&
        out.dual_logup_terminal_equality;
    out.registered_consumer_relation_bound =
        false;
    out.producer_registered_roots_bound =
        false;
    out.signed_output_to_u8_mapping_verified =
        false;
    out.all_pages_aggregated = false;
    out.projection_child_soundness_at_least_100_bits =
        false;
    out.native_cross_proof_semantic_closure =
        false;
    out.production_semantic_closure = false;

    const uint256 expected_producer_commitment =
        CommitNormalizedBankSemanticProducerProofV1(
            proof.producer_proof);
    std::vector<unsigned char> consumer_codec;
    if (!BuildNormalizedDeepCtlProofCodecV1(
            proof.pins[1],
            proof.mirror_export,
            proof.mirror_schedule,
            proof.mirror_proof,
            consumer_codec)) {
        return fail("consumer_codec");
    }
    HashWriter consumer_hash;
    consumer_hash <<
        "BTX_RC_STAGE3_NORMALIZED_BANK_CTL_"
        "MIRROR_PROJECTION_PROOF_V1";
    consumer_hash << consumer_codec;
    const uint256 expected_consumer_commitment =
        consumer_hash.GetHash();
    const uint256 expected_proof_commitment =
        CommitNormalizedBankSemanticProofV1(
            source_pin, proof);
    if (proof.producer_proof_commitment !=
            expected_producer_commitment ||
        proof.pins[0].auxiliary_commitment !=
            expected_producer_commitment ||
        proof.mirror_proof_commitment !=
            expected_consumer_commitment ||
        proof.proof_commitment !=
            expected_proof_commitment) {
        return fail("proof_codec_commitment");
    }

    out.terminal_bus_commitment =
        NormalizedBankSemanticTerminalCommitmentV1(
            source_pin, proof);
    constraint_bytecode::ProgramTable
        program_table;
    if (out.terminal_bus_commitment.IsNull() ||
        proof.terminal_bus_commitment !=
            out.terminal_bus_commitment ||
        !BuildRCStage3CoupledBankDequantProgramTable(
            source_pin, program_table,
            &verify_why) ||
        slot.role !=
            RCStage3RelationRole::CoupledBank ||
        slot.statement_commitment !=
            source_pin.statement_commitment ||
        slot.program_table_commitment !=
            constraint_bytecode::CommitProgramTable(
                program_table) ||
        slot.child_trace_row_root !=
            proof.pins[0].trace_commitment ||
        slot.child_proof_commitment !=
            proof.proof_commitment ||
        slot.terminal_bus_commitment !=
            out.terminal_bus_commitment ||
        slot.normalized_semantic_root !=
            ComputeNormalizedSemanticRootV1(slot) ||
        slot.slot_commitment !=
            ComputeNormalizedRoleChildSlotCommitment(
                slot)) {
        return fail("semantic_slot");
    }
    out.proof_and_projection_bound_in_semantic_slot =
        true;
    if (!ValidateNormalizedSemanticRootSpongeV1(
            composition, slot,
            semantic_sponge,
            &verify_why)) {
        return fail(
            "semantic_lanes:" + verify_why);
    }
    out.semantic_root_lanes_verified = true;

    out.complete_sha_fiat_shamir_replay_in_parent =
        false;
    out.all_child_verifiers_execute_in_parent =
        false;
    out.endpoint_promoted = false;
    out.authority = false;
    out.recursive_endpoints_consumed = 0;
    out.recursive_roles_consumed = 0;
    out.residuals = {
        "registered_endpoint29_or_table_consumer_relation_absent",
        "producer_split_rap_r0_not_bound_to_registered_source_column_roots",
        "signed_output_to_twos_complement_u8_relation_absent",
        "all_page_count_order_concatenation_and_omission_proof_absent",
        "projection_child_q128_fri_soundness_below_100_bits",
        "producer_split_rap_verifier_not_executed_in_parent_air",
        "projection_ctl_verifier_not_executed_in_parent_air",
    };
    out.valid =
        out.projection_self_consistency_verified &&
        !out.registered_consumer_relation_bound &&
        !out.producer_registered_roots_bound &&
        !out.signed_output_to_u8_mapping_verified &&
        !out.all_pages_aggregated &&
        !out.
            projection_child_soundness_at_least_100_bits &&
        !out.native_cross_proof_semantic_closure &&
        !out.production_semantic_closure &&
        out.proof_and_projection_bound_in_semantic_slot &&
        out.semantic_root_lanes_verified &&
        !out.complete_sha_fiat_shamir_replay_in_parent &&
        !out.all_child_verifiers_execute_in_parent &&
        !out.endpoint_promoted &&
        !out.authority &&
        out.recursive_endpoints_consumed == 0 &&
        out.recursive_roles_consumed == 0 &&
        out.residuals.size() == 7;
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_bank_endpoint28_output_projection_"
          "self_consistency_only;production_semantic_no_go"
        : "stage3:recursive_fixedpoint:"
          "normalized_bank_projection_bridge_invalid";
    return out;
}

NormalizedDeep64CtlTerminalAttachmentV1
BuildNormalizedDeep64CtlTerminalV1(
    const FoldBusComposition& composition,
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof)
{
    using namespace stage3_ctl_col;
    NormalizedDeep64CtlTerminalAttachmentV1 out;
    out.child_index =
        static_cast<uint32_t>(child_index);
    const auto& role_order =
        RCStage3UnifiedRoleOrder();
    const auto role_it = std::find(
        role_order.begin(), role_order.end(),
        RCStage3RelationRole::CoupledBank);
    const size_t canonical_child_index =
        role_it == role_order.end()
        ? role_order.size()
        : static_cast<size_t>(
              std::distance(
                  role_order.begin(), role_it));
    std::string ctl_why;
    constraint_bytecode::ProgramTable program_table;
    if (!composition.valid ||
        !semantic_sponge.valid ||
        role_it == role_order.end() ||
        child_index != canonical_child_index ||
        child_index >= pins.size() ||
        child_index >= manifest.participants.size() ||
        pins.size() != role_order.size() ||
        manifest.participants.size() !=
            role_order.size() ||
        pins.size() !=
            manifest.participants.size() ||
        pins[child_index].role !=
            RCStage3RelationRole::CoupledBank ||
        manifest.participants[child_index].role !=
            RCStage3RelationRole::CoupledBank ||
        source_pin.pin_commitment.IsNull() ||
        slot.role !=
            RCStage3RelationRole::CoupledBank ||
        slot.ordinal != canonical_child_index ||
        slot.statement_commitment !=
            source_pin.statement_commitment ||
        slot.slot_commitment.IsNull() ||
        slot.slot_commitment !=
            ComputeNormalizedRoleChildSlotCommitment(
                slot) ||
        slot.normalized_semantic_root !=
            ComputeNormalizedSemanticRootV1(slot) ||
        !BuildRCStage3CoupledBankDequantProgramTable(
            source_pin, program_table, &ctl_why) ||
        slot.program_table_commitment !=
            constraint_bytecode::CommitProgramTable(
                program_table) ||
        !ValidateNormalizedSemanticRootSpongeV1(
            composition, slot,
            semantic_sponge, &ctl_why) ||
        proof.batch.columns.size() !=
            NUM_COLUMNS + 1 ||
        proof.batch.column_len.size() !=
            NUM_COLUMNS + 1) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_shape";
        return out;
    }
    for (size_t index = 0;
         index < role_order.size();
         ++index) {
        if (manifest.participants[index].role !=
                role_order[index] ||
            pins[index].role !=
                role_order[index]) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "normalized_deep64_ctl_role_order";
            return out;
        }
    }
    out.semantic_slot_and_sponge_binding_verified =
        true;
    RCStage3CtlSchedule expected_schedule;
    std::vector<Fp3> expected_values;
    if (!BuildNormalizedCoupledBankCtlRootScheduleV1(
            source_pin, expected_schedule,
            expected_values, nullptr) ||
        schedule != expected_schedule) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_schedule";
        return out;
    }
    out.event_count =
        schedule.events.size();
    for (const auto& event : schedule.events) {
        out.send_count +=
            event.multiplicity == 1 ? 1 : 0;
        out.receive_count +=
            event.multiplicity == -1 ? 1 : 0;
    }
    if (out.event_count !=
            pins[child_index].event_count ||
        out.send_count !=
            pins[child_index].send_count ||
        out.receive_count !=
            pins[child_index].receive_count ||
        out.send_count != out.receive_count) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_counts";
        return out;
    }

    out.relation_export.role =
        pins[child_index].role;
    out.relation_export.bus_id =
        pins[child_index].bus_id;
    out.relation_export.event_count =
        out.event_count;
    out.relation_export.relation_commitment =
        source_pin.pin_commitment;
    out.relation_export.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    out.relation_export.n_rows =
        proof.batch.column_len[NAMESPACE];
    out.relation_export.n_coeffs =
        proof.batch.n_coeffs;
    for (uint32_t column = NAMESPACE;
         column <= MULTIPLICITY; ++column) {
        out.relation_export.
            prechallenge_column_roots[column] =
            proof.batch.columns[column].root;
    }
    if (!VerifyRCStage3CtlRelationExportBinding(
            out.relation_export,
            pins[child_index], schedule, proof,
            source_pin.pin_commitment,
            &ctl_why) ||
        ComputeRCStage3CtlPrechallengeTraceCommitment(
            schedule, expected_values) !=
            pins[child_index].trace_commitment) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_relation:" +
            ctl_why;
        return out;
    }
    out.canonical_relation_root_tuples = true;
    out.relation_value_column_bound = true;
    out.prechallenge_commitments_bound = true;

    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            manifest, pins, challenges,
            &ctl_why) ||
        pins[child_index].
                challenge_commitment !=
            CommitRCStage3CtlChallenges(
                challenges)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_challenge:" +
            ctl_why;
        return out;
    }
    out.challenges_after_commitments = true;
    if (!VerifyRCStage3CtlChildAirProof(
            manifest, pins, child_index,
            schedule, proof, &ctl_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_child:" +
            ctl_why;
        return out;
    }
    out.child_proof_verified_natively = true;
    out.denominator_nonzero_constraints_verified =
        true;
    out.multiplicity_accumulators_verified =
        true;
    out.selected_child_terminal_zero =
        gf::IsZero(
            pins[child_index].
                terminal.alpha1_sum) &&
        gf::IsZero(
            pins[child_index].
                terminal.alpha2_sum);
    if (!out.selected_child_terminal_zero ||
        !VerifyRCStage3CtlPublicPinComposition(
            manifest, pins, &ctl_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_terminal:" +
            ctl_why;
        return out;
    }
    out.public_pin_terminal_equality_verified =
        true;
    out.all_participant_child_proofs_verified =
        false;
    out.global_terminal_equality_verified = false;

    std::vector<unsigned char> codec;
    if (!BuildNormalizedDeepCtlProofCodecV1(
            pins[child_index],
            out.relation_export,
            schedule, proof, codec) ||
        !BuildNormalizedDeepCtlProofFieldsV1(
            codec, out.proof_fields,
            out.proof_transport_commitment)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_codec";
        return out;
    }
    out.proof_codec_bytes =
        static_cast<uint32_t>(codec.size());
    out.proof_field_count =
        static_cast<uint32_t>(
            out.proof_fields.size());
    std::vector<unsigned char> canonical_codec;
    out.proof_codec_canonical =
        BuildNormalizedDeepCtlProofCodecV1(
            pins[child_index],
            out.relation_export,
            schedule, proof,
            canonical_codec) &&
        canonical_codec == codec;
    out.proof_field_transport_bound =
        out.proof_codec_canonical &&
        out.proof_field_count ==
            1 + CeilDiv(
                    out.proof_codec_bytes, 4);

    out.terminal_bus_commitment =
        ComputeNormalizedTerminalBusCommitment(
            manifest, pins, child_index,
            schedule);
    if (out.terminal_bus_commitment.IsNull() ||
        out.terminal_bus_commitment !=
            slot.terminal_bus_commitment) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_terminal_commitment";
        return out;
    }
    out.terminal_semantic_lanes_linked = true;
    for (uint32_t limb = 0;
         limb < 8; ++limb) {
        const Fp3 expected =
            Fp3::FromFp(
                gf::FromU64(
                    Uint256Limb32(
                        out.terminal_bus_commitment,
                        limb)));
        const uint32_t column =
            semantic_sponge.layout.Input(
                40 + limb);
        if (column >= composition.columns.size() ||
            composition.columns[column].size() !=
                composition.combined.n_rows) {
            out.terminal_semantic_lanes_linked =
                false;
            break;
        }
        for (uint32_t row = 0;
             row <
                 composition.combined.n_rows;
             ++row) {
            if (!gf::Eq(
                    composition.columns[column][row],
                    expected)) {
                out.terminal_semantic_lanes_linked =
                    false;
                break;
            }
        }
        if (!out.terminal_semantic_lanes_linked) {
            break;
        }
    }
    if (!out.terminal_semantic_lanes_linked) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "normalized_deep64_ctl_semantic_lanes";
        return out;
    }

    // This child proves a canonical transport of the relation proof's root
    // inventory into the CTL codec.  Since every root limb is paired with
    // itself at the same address, the zero terminal is tautological and does
    // not establish the endpoint-28 producer/consumer tuple equality.
    out.root_inventory_transport_only = true;
    out.actual_producer_relation_tuples_bound = false;
    out.actual_consumer_proof_tuples_bound = false;
    out.cross_proof_logup_identity_verified = false;
    out.ctl_semantic_closure = false;
    out.complete_sha_fiat_shamir_replay_in_parent =
        false;
    out.endpoint_promoted = false;
    out.authority = false;
    out.recursive_endpoints_consumed = 0;
    out.recursive_roles_consumed = 0;
    out.recursively_consumed = false;
    out.residuals = {
        "root_limb_send_receive_pairs_self_cancel",
        "actual_relation_output_tuple_export_not_bound",
        "corresponding_consumer_table_tuple_export_not_bound",
        "cross_proof_logup_identity_not_established",
        "other_13_ctl_child_air_proofs_not_supplied",
        "ctl_proof_fields_not_equality_wired_into_parent_air",
        "sha256d_ctl_fiat_shamir_replay_not_in_parent_air",
        "ctl_air_proof_native_not_recursively_consumed",
    };
    out.valid =
        out.canonical_relation_root_tuples &&
        out.relation_value_column_bound &&
        out.prechallenge_commitments_bound &&
        out.challenges_after_commitments &&
        out.denominator_nonzero_constraints_verified &&
        out.multiplicity_accumulators_verified &&
        out.selected_child_terminal_zero &&
        out.public_pin_terminal_equality_verified &&
        !out.all_participant_child_proofs_verified &&
        !out.global_terminal_equality_verified &&
        out.proof_codec_canonical &&
        out.proof_field_transport_bound &&
        out.terminal_semantic_lanes_linked &&
        out.semantic_slot_and_sponge_binding_verified &&
        out.child_proof_verified_natively &&
        out.root_inventory_transport_only &&
        !out.actual_producer_relation_tuples_bound &&
        !out.actual_consumer_proof_tuples_bound &&
        !out.cross_proof_logup_identity_verified &&
        !out.ctl_semantic_closure &&
        !out.complete_sha_fiat_shamir_replay_in_parent &&
        !out.endpoint_promoted &&
        !out.authority &&
        out.recursive_endpoints_consumed == 0 &&
        out.recursive_roles_consumed == 0 &&
        !out.recursively_consumed &&
        out.residuals.size() == 8;
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "normalized_deep64_ctl_root_inventory_transport_only;"
          "producer_consumer_tuple_equality_and_sha_fs_recursive_"
          "authority_open"
        : "stage3:recursive_fixedpoint:"
          "normalized_deep64_ctl_terminal_invalid";
    return out;
}

bool ValidateNormalizedDeep64CtlTerminalV1(
    const FoldBusComposition& composition,
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedRoleChildSlot& slot,
    const NormalizedSemanticRootSpongeAttachmentV1&
        semantic_sponge,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    const NormalizedDeep64CtlTerminalAttachmentV1&
        attachment,
    std::string* why)
{
    const auto fail =
        [&](const char* reason) {
            if (why != nullptr) *why = reason;
            return false;
        };
    if (!attachment.valid ||
        attachment.authority ||
        attachment.endpoint_promoted ||
        attachment.
            complete_sha_fiat_shamir_replay_in_parent ||
        !attachment.root_inventory_transport_only ||
        attachment.actual_producer_relation_tuples_bound ||
        attachment.actual_consumer_proof_tuples_bound ||
        attachment.cross_proof_logup_identity_verified ||
        attachment.ctl_semantic_closure ||
        !attachment.
            semantic_slot_and_sponge_binding_verified ||
        !attachment.
            public_pin_terminal_equality_verified ||
        attachment.
            all_participant_child_proofs_verified ||
        attachment.global_terminal_equality_verified ||
        attachment.recursive_endpoints_consumed != 0 ||
        attachment.recursive_roles_consumed != 0 ||
        attachment.recursively_consumed) {
        return fail(
            "normalized_deep64_ctl_flags");
    }
    const auto expected =
        BuildNormalizedDeep64CtlTerminalV1(
            composition, source_pin, slot,
            semantic_sponge, manifest, pins,
            child_index, schedule, proof);
    if (!expected.valid ||
        !EqNormalizedDeepCtlAttachmentV1(
            expected, attachment)) {
        return fail(
            "normalized_deep64_ctl_binding");
    }
    return true;
}


namespace {

std::vector<Fp3> SliceParentRowForCtl(
    const std::vector<Fp3>& row,
    uint32_t column_offset,
    uint32_t columns)
{
    if (column_offset > row.size() ||
        columns > row.size() - column_offset) {
        return {};
    }
    return std::vector<Fp3>(
        row.begin() + column_offset,
        row.begin() + column_offset + columns);
}

void AppendRelocatedCtlConstraints(
    const aq::AirConstraintSystem<Fp3>& source,
    uint32_t column_offset,
    aq::AirConstraintSystem<Fp3>& destination)
{
    for (const auto& constraint : source.constraints) {
        aq::AirConstraint<Fp3> shifted;
        shifted.name = constraint.name;
        shifted.kind = constraint.kind;
        shifted.alg_degree = constraint.alg_degree;
        shifted.eval =
            [eval = constraint.eval,
             column_offset,
             columns = source.n_columns](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                return eval(
                    SliceParentRowForCtl(
                        current, column_offset, columns),
                    SliceParentRowForCtl(
                        next, column_offset, columns));
            };
        destination.constraints.push_back(std::move(shifted));
    }
    for (const auto& [column, values] : source.preprocessed) {
        destination.preprocessed.emplace_back(
            column_offset + column, values);
    }
    for (const auto& [column, root] :
         source.preprocessed_roots) {
        destination.preprocessed_roots.emplace_back(
            column_offset + column, root);
    }
    destination.preprocessed_pin_ood =
        destination.preprocessed_pin_ood ||
        source.preprocessed_pin_ood;
}

} // namespace

NormalizedSemanticAlgHashParentAudit
PromoteNormalizedSemanticTerminalFromDeep64CtlV1(
    const NormalizedSemanticAlgHashParentAudit& base,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl,
    const NormalizedRoleChildSlot& slot)
{
    NormalizedSemanticAlgHashParentAudit out = base;
    const bool closable =
        deep64_ctl.valid &&
        deep64_ctl.terminal_semantic_lanes_linked &&
        deep64_ctl.proof_field_transport_bound &&
        deep64_ctl.child_proof_verified_natively &&
        deep64_ctl.public_pin_terminal_equality_verified &&
        !deep64_ctl.terminal_bus_commitment.IsNull() &&
        deep64_ctl.terminal_bus_commitment ==
            slot.terminal_bus_commitment &&
        !out.terminal_bus_commitment_mapped;
    if (!closable) {
        return out;
    }

    out.terminal_bus_commitment_mapped = true;
    out.proof_authenticated_lanes = 0;
    out.missing_proof_bus_lanes = 0;
    out.verifier_constant_lanes = 0;
    for (auto& field : out.fields) {
        if (field.field == "terminal_bus_commitment_u32") {
            field.source =
                NormalizedAlgHashInputSource::ProofAuthenticated;
            field.all_lanes_bound = true;
            field.detail =
                "Deep64CtlTerminal natively verifies CoupledBank CTL child, "
                "binds proof-field transport, and links eight u32 semantic "
                "sponge terminal lanes to terminal_bus_commitment";
        }
        if (field.source ==
            NormalizedAlgHashInputSource::VerifierConstant) {
            out.verifier_constant_lanes += field.input_lanes;
        } else if (
            field.source ==
                NormalizedAlgHashInputSource::ProofAuthenticated &&
            field.all_lanes_bound) {
            out.proof_authenticated_lanes += field.input_lanes;
        } else {
            out.missing_proof_bus_lanes += field.input_lanes;
        }
    }
    out.in_parent_derivation_complete =
        out.canonical_alg_hash_available &&
        out.slot_binding_valid &&
        out.child_trace_root_mapped &&
        out.child_proof_commitment_mapped &&
        out.terminal_bus_commitment_mapped &&
        out.missing_proof_bus_lanes == 0;
    out.blocker =
        out.in_parent_derivation_complete
            ? "stage3:recursive_fixedpoint:"
              "normalized_semantic_alg_hash_parent_complete;"
              "terminal_bus_closed_via_deep64_ctl;"
              "ctl_child_verifier_equations_not_in_parent_air"
            : "stage3:recursive_fixedpoint:"
              "normalized_semantic_alg_hash_blocked:"
              "terminal_bus_closed_via_deep64_ctl_but_"
              "other_semantic_inputs_still_missing";
    return out;
}
NormalizedDeep64CtlChildParentAirAttachmentV1
AttachNormalizedDeep64CtlChildVerifierInParentAirV1(
    FoldBusComposition& composition,
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof)
{
    using namespace stage3_ctl_col;
    NormalizedDeep64CtlChildParentAirAttachmentV1 out;
    out.parent_rows = composition.combined.n_rows;
    out.layout.ctl_column_base =
        composition.combined.n_columns;
    if (!composition.valid ||
        !deep64_ctl.valid ||
        !deep64_ctl.child_proof_verified_natively ||
        !deep64_ctl.proof_field_transport_bound ||
        !deep64_ctl.terminal_semantic_lanes_linked ||
        out.parent_rows < 2 ||
        child_index >= pins.size() ||
        child_index != deep64_ctl.child_index) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_shape";
        return out;
    }

    RCStage3CtlSchedule expected_schedule;
    std::vector<Fp3> expected_values;
    if (!BuildNormalizedCoupledBankCtlRootScheduleV1(
            source_pin, expected_schedule,
            expected_values, nullptr) ||
        schedule != expected_schedule ||
        expected_values.size() !=
            schedule.events.size()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_schedule";
        return out;
    }

    std::string ctl_why;
    if (!VerifyRCStage3CtlChildAirProof(
            manifest, pins, child_index, schedule,
            proof, &ctl_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_native:" +
            ctl_why;
        return out;
    }

    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            manifest, pins, challenges, &ctl_why)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_challenges:" +
            ctl_why;
        return out;
    }

    const RCStage3CtlAirSpec spec{
        schedule, challenges, pins[child_index].terminal};
    aq::AirConstraintSystem<Fp3> ctl_cs =
        BuildRCStage3CtlConstraintSystem(spec);
    const RCStage3CtlWitness witness =
        BuildRCStage3CtlWitness(
            schedule, expected_values, challenges);
    out.ctl_rows = ctl_cs.n_rows;
    if (ctl_cs.n_columns != NUM_COLUMNS ||
        ctl_cs.n_rows < 2 ||
        ctl_cs.n_rows > out.parent_rows ||
        !witness.ok ||
        witness.columns.size() != NUM_COLUMNS ||
        witness.columns[0].size() != out.ctl_rows ||
        ctl_cs.constraints.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_witness";
        return out;
    }

    // Prechallenge binding: schedule+values commitment matches the pin
    // (same predicate VerifyRCStage3CtlChildAirProof already checked against
    // the native proof). Per-column AirCommittedValuesRoot is not required —
    // the hosted witness is rebuilt from that schedule and checked by the
    // relocated CTL equations below.
    out.prechallenge_roots_bound =
        !pins[child_index].trace_commitment.IsNull() &&
        ComputeRCStage3CtlPrechallengeTraceCommitment(
            schedule, expected_values) ==
            pins[child_index].trace_commitment;
    if (!out.prechallenge_roots_bound) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_prechallenge_trace";
        return out;
    }
    if (!gf::IsZero(witness.terminal.alpha1_sum) ||
        !gf::IsZero(witness.terminal.alpha2_sum)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_terminal_nonzero";
        return out;
    }
    if (!gf::Eq(
            witness.terminal.alpha1_sum,
            pins[child_index].terminal.alpha1_sum) ||
        !gf::Eq(
            witness.terminal.alpha2_sum,
            pins[child_index].terminal.alpha2_sum)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_terminal_mismatch";
        return out;
    }
    out.terminal_zero_in_parent = true;

    // Pad CTL witness/preprocessed to parent height (M=0 tail keeps
    // LastRow terminal identity under FoldBus n_rows).
    std::vector<std::vector<Fp3>> padded = witness.columns;
    for (auto& column : padded) {
        column.resize(out.parent_rows, Fp3::Zero());
    }
    for (uint32_t row = out.ctl_rows;
         row < out.parent_rows; ++row) {
        padded[RUNNING1][row] =
            witness.terminal.alpha1_sum;
        padded[RUNNING2][row] =
            witness.terminal.alpha2_sum;
    }
    for (auto& [column, values] : ctl_cs.preprocessed) {
        values.resize(out.parent_rows, Fp3::Zero());
        if (column >= padded.size()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "ctl_child_parent_air_preprocessed";
            return out;
        }
        // Keep public schedule columns identical to the hosted witness.
        values = padded[column];
    }
    ctl_cs.n_rows = out.parent_rows;

    out.proof_field_count =
        deep64_ctl.proof_field_count;
    out.proof_transport_commitment =
        deep64_ctl.proof_transport_commitment;
    // Pack codec limbs into a fixed-rate row bus. One parent-height
    // column per limb OOMs: a ~1.2 MiB CTL FRI codec is ~318k limbs →
    // ~62 GiB at parent_rows=8192 (measured 2026-07-28).
    constexpr uint32_t kProofFieldLanes =
        kNormalizedDeep64CtlProofFieldBusRate;
    out.layout.proof_field_base =
        out.layout.ctl_column_base + NUM_COLUMNS;
    out.layout.proof_field_count =
        out.proof_field_count;
    out.layout.proof_field_lanes = kProofFieldLanes;
    out.layout.proof_field_rows =
        static_cast<uint32_t>(
            (uint64_t{out.proof_field_count} +
             kProofFieldLanes - 1) /
            kProofFieldLanes);
    out.layout.proof_field_active =
        out.layout.proof_field_base + kProofFieldLanes;
    out.proof_field_rows = out.layout.proof_field_rows;
    if (out.proof_field_count == 0 ||
        deep64_ctl.proof_fields.size() !=
            out.proof_field_count ||
        out.proof_transport_commitment.IsNull() ||
        out.layout.proof_field_rows == 0 ||
        out.layout.proof_field_rows > out.parent_rows) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_proof_fields";
        return out;
    }
    {
        // Belt-and-suspenders: refuse unsurvivable residency even if a
        // future layout change reintroduces width∝field_count.
        const uint64_t packed_bytes =
            uint64_t{kProofFieldLanes + 1} *
            out.parent_rows * sizeof(Fp3);
        constexpr uint64_t kCtlParentAirFieldBudget =
            uint64_t{256} << 20; // 256 MiB
        if (packed_bytes > kCtlParentAirFieldBudget) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "ctl_child_parent_air_proof_field_residency";
            return out;
        }
    }

    out.added_columns =
        out.layout.End() - out.layout.ctl_column_base;
    out.constraint_base = static_cast<uint32_t>(
        composition.combined.constraints.size());

    composition.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    composition.combined.n_columns = out.layout.End();
    composition.combined.preprocessed_pin_ood = true;

    for (uint32_t column = 0;
         column < NUM_COLUMNS; ++column) {
        composition.columns[
            out.layout.CtlColumn(column)] =
            padded[column];
    }
    for (uint32_t index = 0;
         index < out.proof_field_count; ++index) {
        const uint32_t row =
            index / kProofFieldLanes;
        const uint32_t lane =
            index % kProofFieldLanes;
        const uint32_t column =
            out.layout.ProofFieldLane(lane);
        composition.columns[column][row] =
            deep64_ctl.proof_fields[index];
    }
    for (uint32_t lane = 0;
         lane < kProofFieldLanes; ++lane) {
        const uint32_t column =
            out.layout.ProofFieldLane(lane);
        composition.combined.preprocessed.emplace_back(
            column, composition.columns[column]);
    }
    for (uint32_t row = 0;
         row < out.layout.proof_field_rows; ++row) {
        composition.columns[
            out.layout.proof_field_active][row] =
            Fp3::One();
    }
    composition.combined.preprocessed.emplace_back(
        out.layout.proof_field_active,
        composition.columns[
            out.layout.proof_field_active]);

    AppendRelocatedCtlConstraints(
        ctl_cs, out.layout.ctl_column_base,
        composition.combined);
    // Active selector is boolean on packed field rows (1) and idle
    // tail (0); field cells are preprocessed pins, so no extra
    // equality chip beyond the transport commitment check below.
    {
        aq::AirConstraint<Fp3> boolean;
        boolean.name =
            "stage3.fixedpoint.ctl_child_parent_air."
            "proof_field_active_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        const uint32_t selector =
            out.layout.proof_field_active;
        boolean.eval =
            [selector](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[selector],
                    gf::Sub(
                        row[selector],
                        Fp3::One()));
            };
        composition.combined.constraints.push_back(
            std::move(boolean));
    }
    // Equality-wire: recomputed transport commitment from pinned fields.
    {
        std::vector<gf::Fp> base_fields;
        base_fields.reserve(out.proof_field_count);
        for (const Fp3& field : deep64_ctl.proof_fields) {
            if (field.c1 != 0 || field.c2 != 0 ||
                field.c0 >= gf::kP) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "ctl_child_parent_air_field_limb";
                return out;
            }
            base_fields.push_back(field.c0);
        }
        const uint256 recomputed =
            aq::AirFriBackendAlg<Fp3>::PackDigest(
                ah::SpongeHashFp(base_fields));
        if (recomputed.IsNull() ||
            recomputed !=
                out.proof_transport_commitment) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "ctl_child_parent_air_transport";
            return out;
        }
        out.proof_fields_equality_wired = true;
    }

    out.added_constraints = static_cast<uint32_t>(
        composition.combined.constraints.size() -
        out.constraint_base);
    out.ctl_equations_hosted =
        out.added_constraints > 0;

    // Validate CTL equations on the padded CTL-width witness (not a full
    // FoldBus H-scan — relocated evals allocate per call).
    out.violations =
        CountHashOpeningViolations(ctl_cs, padded);
    if (out.violations != 0) {
        composition.valid = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_violations";
        return out;
    }

    // Diff-test: tamper hosted VALUE on an active event row.
    {
        const gf::Fp3 saved = padded[VALUE][0];
        padded[VALUE][0] = gf::Add(saved, Fp3::One());
        const uint32_t forged =
            CountHashOpeningViolations(ctl_cs, padded);
        padded[VALUE][0] = saved;
        // Keep the live parent column consistent with the restored witness.
        composition.columns[out.layout.CtlColumn(VALUE)][0] =
            saved;
        out.forgery_rejected = forged > 0;
    }
    if (!out.forgery_rejected) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "ctl_child_parent_air_forgery_not_rejected";
        return out;
    }

    out.complete_sha_fiat_shamir_replay_in_parent =
        false;
    out.recursively_consumed = false;
    out.valid =
        out.ctl_equations_hosted &&
        out.prechallenge_roots_bound &&
        out.proof_fields_equality_wired &&
        out.terminal_zero_in_parent &&
        out.forgery_rejected &&
        out.violations == 0 &&
        !out.complete_sha_fiat_shamir_replay_in_parent &&
        !out.recursively_consumed;
    composition.valid =
        composition.valid && out.valid;
    out.note =
        out.valid
            ? "stage3:recursive_fixedpoint:"
              "ctl_child_verifier_equations_hosted_in_"
              "parent_air;"
              "proof_fields_equality_wired;"
              "sha_fs_replay_and_recursive_consumption_open;"
              "complete_fp=false"
            : "stage3:recursive_fixedpoint:"
              "ctl_child_parent_air_invalid";
    return out;
}
bool ValidateNormalizedDeep64CtlChildVerifierInParentAirV1(
    const FoldBusComposition& composition,
    const RCStage3CoupledBankDequantPin& source_pin,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl,
    const RCStage3CtlManifest& manifest,
    const std::vector<RCStage3CtlChildPin>& pins,
    size_t child_index,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlAirProof& proof,
    const NormalizedDeep64CtlChildParentAirAttachmentV1&
        attachment,
    std::string* why)
{
    const auto fail =
        [&](const char* reason) {
            if (why != nullptr) {
                *why = reason;
            }
            return false;
        };
    if (!attachment.valid ||
        attachment.complete_sha_fiat_shamir_replay_in_parent ||
        attachment.recursively_consumed ||
        !attachment.ctl_equations_hosted ||
        !attachment.proof_fields_equality_wired ||
        !attachment.forgery_rejected ||
        attachment.violations != 0) {
        return fail("ctl_child_parent_air_flags");
    }
    // Re-attach on a copy is too expensive; check structural binding
    // against the live composition and Deep64 attachment instead.
    if (attachment.parent_rows !=
            composition.combined.n_rows ||
        attachment.layout.End() !=
            composition.combined.n_columns ||
        attachment.proof_field_count !=
            deep64_ctl.proof_field_count ||
        attachment.proof_transport_commitment !=
            deep64_ctl.proof_transport_commitment ||
        attachment.layout.proof_field_lanes !=
            kNormalizedDeep64CtlProofFieldBusRate ||
        attachment.layout.proof_field_rows == 0 ||
        attachment.layout.proof_field_rows >
            attachment.parent_rows ||
        attachment.proof_field_rows !=
            attachment.layout.proof_field_rows ||
        attachment.layout.ctl_column_base +
                stage3_ctl_col::NUM_COLUMNS +
                attachment.layout.proof_field_lanes + 1 !=
            attachment.layout.End()) {
        return fail("ctl_child_parent_air_layout");
    }
    for (uint32_t index = 0;
         index < attachment.proof_field_count;
         ++index) {
        const uint32_t row =
            index / attachment.layout.proof_field_lanes;
        const uint32_t lane =
            index % attachment.layout.proof_field_lanes;
        const uint32_t column =
            attachment.layout.ProofFieldLane(lane);
        if (column >= composition.columns.size() ||
            composition.columns[column].size() !=
                attachment.parent_rows ||
            row >= attachment.parent_rows ||
            !gf::Eq(
                composition.columns[column][row],
                deep64_ctl.proof_fields[index])) {
            return fail(
                "ctl_child_parent_air_proof_field_pin");
        }
    }
    // Touch schedule/native binding so callers cannot swap proofs.
    std::string ctl_why;
    if (!VerifyRCStage3CtlChildAirProof(
            manifest, pins, child_index, schedule,
            proof, &ctl_why)) {
        return fail("ctl_child_parent_air_native_binding");
    }
    RCStage3CtlSchedule expected_schedule;
    std::vector<Fp3> expected_values;
    if (!BuildNormalizedCoupledBankCtlRootScheduleV1(
            source_pin, expected_schedule,
            expected_values, nullptr) ||
        schedule != expected_schedule) {
        return fail("ctl_child_parent_air_schedule_binding");
    }
    (void)deep64_ctl;
    return true;
}
NormalizedRecursiveChildCapabilityAuditV1
AssessNormalizedRecursiveChildCapabilityWithProofBusAndDeepCtlV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl)
{
    NormalizedRecursiveChildCapabilityAuditV1 out =
        AssessNormalizedRecursiveChildCapabilityWithProofBusV1(
            composition, interpreter, row_pin, execution,
            proof_bus);
    if (!out.valid || !out.child_proof_commitment_mapped) {
        out.valid = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_with_proof_bus_and_deep_ctl_"
            "commitment_not_promoted";
        return out;
    }

    const NormalizedSemanticAlgHashParentAudit base_root =
        AssessNormalizedSemanticAlgHashParentClosure(
            composition, interpreter, row_pin, execution);
    const NormalizedSemanticAlgHashParentAudit committed =
        PromoteNormalizedSemanticProofCommitmentFromFieldBusV1(
            base_root, proof_bus, execution.slot);
    const NormalizedSemanticAlgHashParentAudit root =
        PromoteNormalizedSemanticTerminalFromDeep64CtlV1(
            committed, deep64_ctl, execution.slot);
    if (!root.terminal_bus_commitment_mapped) {
        out.valid = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_with_proof_bus_and_deep_ctl_"
            "terminal_not_promoted";
        return out;
    }

    out.terminal_bus_commitment_mapped = true;
    // Still native-only: Deep64 verifies the CTL child off-parent.
    out.ctl_child_verified_in_parent_air = false;
    out.normalized_root_available_input_lanes =
        root.verifier_constant_lanes +
        root.proof_authenticated_lanes;
    out.normalized_root_missing_input_lanes =
        root.missing_proof_bus_lanes;
    out.normalized_semantic_root_derived_in_parent =
        root.in_parent_derivation_complete;

    for (auto& gap : out.gaps) {
        if (gap.code ==
            NormalizedRecursiveVerifierGapCode::
                CtlChildVerifierAndTerminalBus) {
            gap.mapped_lanes = 8;
            gap.present_in_parent_air =
                out.ctl_child_verified_in_parent_air &&
                out.terminal_bus_commitment_mapped;
            gap.detail =
                "Deep64CtlTerminal binds eight terminal_bus_commitment "
                "u32 lanes into the parent semantic sponge after native "
                "CTL child verify + codec transport; "
                "ctl_child_verified_in_parent_air remains false until "
                "CTL verifier equations execute inside this parent AIR";
        } else if (
            gap.code ==
            NormalizedRecursiveVerifierGapCode::
                NormalizedSemanticRootAlgHash) {
            gap.mapped_lanes =
                out.normalized_root_available_input_lanes;
            gap.present_in_parent_air =
                out.normalized_semantic_root_derived_in_parent;
            gap.detail =
                out.normalized_semantic_root_derived_in_parent
                    ? "all 48 semantic-root input lanes are bound "
                      "(ProofFieldBus commitment + Deep64 CTL terminal); "
                      "910 permutation columns already execute in the "
                      "parent sponge attachment"
                    : "semantic-root inputs still incomplete after "
                      "terminal promote";
        }
    }

    std::string failed;
    const auto fail_pred = [&](bool ok, const char* tag) {
        if (!ok) {
            failed.push_back(';');
            failed += tag;
        }
        return ok;
    };
    out.valid =
        fail_pred(out.candidate_role_endpoint_count == 3,
                  "role_endpoint_count") &&
        fail_pred(out.child_relation_columns == 6,
                  "child_relation_columns") &&
        fail_pred(out.child_relation_constraints == 5,
                  "child_relation_constraints") &&
        fail_pred(out.parent_rows >= 2, "parent_rows") &&
        fail_pred(out.parent_columns > 0, "parent_columns") &&
        fail_pred(out.parent_constraints > 0, "parent_constraints") &&
        fail_pred(out.native_child_host_verified,
                  "native_child_host_verified") &&
        fail_pred(out.authenticated_opening_air,
                  "authenticated_opening_air") &&
        fail_pred(out.fold_deep_air, "fold_deep_air") &&
        fail_pred(out.relation_bytecode_air,
                  "relation_bytecode_air") &&
        fail_pred(out.child_trace_root_mapped,
                  "child_trace_root_mapped") &&
        fail_pred(out.normalized_root_required_input_lanes == 48,
                  "root_required_lanes") &&
        fail_pred(out.normalized_root_available_input_lanes == 48,
                  "root_available_lanes") &&
        fail_pred(out.normalized_root_missing_input_lanes == 0,
                  "root_missing_lanes") &&
        fail_pred(
            out.normalized_root_additional_permutation_columns == 910,
            "root_perm_columns") &&
        fail_pred(out.split_rap_native_verifier_executable,
                  "split_rap_native") &&
        fail_pred(out.gaps.size() == 7, "gaps_size") &&
        fail_pred(out.child_proof_payload_bound_in_air,
                  "payload_bound_required") &&
        fail_pred(out.child_fiat_shamir_replayed_in_air,
                  "fs_replay_required") &&
        fail_pred(out.child_proof_commitment_mapped,
                  "proof_commit_required") &&
        fail_pred(!out.ctl_child_verified_in_parent_air,
                  "ctl_verified_unexpected") &&
        fail_pred(out.terminal_bus_commitment_mapped,
                  "terminal_bus_required") &&
        fail_pred(out.normalized_semantic_root_derived_in_parent,
                  "semantic_root_required") &&
        fail_pred(out.split_rap_multirow_parent_adapter,
                  "split_rap_adapter_required") &&
        fail_pred(!out.endpoint_terminal_equality,
                  "endpoint_terminal_unexpected") &&
        fail_pred(!kCompleteRecursiveFixedPointExecutable,
                  "complete_fp_unexpected") &&
        fail_pred(!kRecursiveFixedPointConsensusAuthority,
                  "fp_authority_unexpected") &&
        fail_pred(!va::kVerifierAirConsensusAuthority,
                  "va_authority_unexpected") &&
        fail_pred(!va::kVerifierFiatShamirAirExecutable,
                  "va_fs_chip_unexpected");
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "capability_audit_ok;"
          "proof_commitment_bus_closed_via_proof_field_bus;"
          "terminal_bus_closed_via_deep64_ctl;"
          "semantic_root_input_lanes_complete;"
          "ctl_child_verifier_in_parent_air_open;"
          "ledger_g4_fiat_shamir_replay_closed;"
          "split_rap_multirow_adapter_closed;"
          "proof_payload_bus_closed;"
          "complete_fp=false;"
        : ("stage3:recursive_fixedpoint:"
           "capability_with_proof_bus_and_deep_ctl_not_canonical" +
           failed);
    if (out.valid) {
        // Living counters — never hard-code 0/52 while CellAudit could lie.
        out.note +=
            "recursive_counters_" +
            std::to_string(out.recursively_consumed_endpoints) +
            "_of_52_and_" +
            std::to_string(out.recursively_consumed_roles) +
            "_of_14";
    }
    return out;
}
bool ValidateNormalizedRecursiveChildCapabilityWithProofBusAndDeepCtlV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl,
    const NormalizedRecursiveChildCapabilityAuditV1& audit,
    std::string* why)
{
    const NormalizedRecursiveChildCapabilityAuditV1 expected =
        AssessNormalizedRecursiveChildCapabilityWithProofBusAndDeepCtlV1(
            composition, interpreter, row_pin, execution,
            proof_bus, deep64_ctl);
    if (!expected.valid || !(expected == audit)) {
        if (why != nullptr) {
            *why =
                "normalized_recursive_child_capability_"
                "with_proof_bus_and_deep_ctl_mismatch";
        }
        return false;
    }
    return true;
}
NormalizedRecursiveChildCapabilityAuditV1
AssessNormalizedRecursiveChildCapabilityWithProofBusDeepCtlParentAirV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl,
    const NormalizedDeep64CtlChildParentAirAttachmentV1&
        ctl_parent_air)
{
    NormalizedRecursiveChildCapabilityAuditV1 out =
        AssessNormalizedRecursiveChildCapabilityWithProofBusAndDeepCtlV1(
            composition, interpreter, row_pin, execution,
            proof_bus, deep64_ctl);
    if (!out.valid ||
        !out.terminal_bus_commitment_mapped ||
        !out.normalized_semantic_root_derived_in_parent) {
        out.valid = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_with_ctl_parent_air_"
            "deep_ctl_not_ready";
        return out;
    }
    if (!ctl_parent_air.valid ||
        !ctl_parent_air.ctl_equations_hosted ||
        !ctl_parent_air.proof_fields_equality_wired ||
        !ctl_parent_air.forgery_rejected ||
        ctl_parent_air.violations != 0 ||
        ctl_parent_air.parent_rows !=
            composition.combined.n_rows ||
        ctl_parent_air.layout.End() !=
            composition.combined.n_columns) {
        out.valid = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_with_ctl_parent_air_attach_invalid";
        return out;
    }

    out.ctl_child_verified_in_parent_air = true;
    out.parent_columns =
        composition.combined.n_columns;
    out.parent_constraints = static_cast<uint32_t>(
        composition.combined.constraints.size());

    for (auto& gap : out.gaps) {
        if (gap.code ==
            NormalizedRecursiveVerifierGapCode::
                CtlChildVerifierAndTerminalBus) {
            gap.mapped_lanes = 8;
            gap.present_in_parent_air =
                out.ctl_child_verified_in_parent_air &&
                out.terminal_bus_commitment_mapped;
            gap.detail =
                "Deep64CtlTerminal binds eight terminal lanes; "
                "AttachNormalizedDeep64CtlChildVerifierInParentAirV1 "
                "hosts CTL AirQuotient equations in the FoldBus "
                "parent, equality-wires proof-field transport, and "
                "rejects VALUE forgery; SHA CTL FS replay and "
                "recursive consumption remain open";
        }
    }

    std::string failed;
    const auto fail_pred = [&](bool ok, const char* tag) {
        if (!ok) {
            failed.push_back(';');
            failed += tag;
        }
        return ok;
    };
    out.valid =
        fail_pred(out.candidate_role_endpoint_count == 3,
                  "role_endpoint_count") &&
        fail_pred(out.child_relation_columns == 6,
                  "child_relation_columns") &&
        fail_pred(out.child_relation_constraints == 5,
                  "child_relation_constraints") &&
        fail_pred(out.parent_rows >= 2, "parent_rows") &&
        fail_pred(out.parent_columns > 0, "parent_columns") &&
        fail_pred(out.parent_constraints > 0,
                  "parent_constraints") &&
        fail_pred(out.native_child_host_verified,
                  "native_child_host_verified") &&
        fail_pred(out.authenticated_opening_air,
                  "authenticated_opening_air") &&
        fail_pred(out.fold_deep_air, "fold_deep_air") &&
        fail_pred(out.relation_bytecode_air,
                  "relation_bytecode_air") &&
        fail_pred(out.child_trace_root_mapped,
                  "child_trace_root_mapped") &&
        fail_pred(out.normalized_root_required_input_lanes == 48,
                  "root_required_lanes") &&
        fail_pred(out.normalized_root_available_input_lanes == 48,
                  "root_available_lanes") &&
        fail_pred(out.normalized_root_missing_input_lanes == 0,
                  "root_missing_lanes") &&
        fail_pred(
            out.normalized_root_additional_permutation_columns == 910,
            "root_perm_columns") &&
        fail_pred(out.split_rap_native_verifier_executable,
                  "split_rap_native") &&
        fail_pred(out.gaps.size() == 7, "gaps_size") &&
        fail_pred(out.child_proof_payload_bound_in_air,
                  "payload_bound_required") &&
        fail_pred(out.child_fiat_shamir_replayed_in_air,
                  "fs_replay_required") &&
        fail_pred(out.child_proof_commitment_mapped,
                  "proof_commit_required") &&
        fail_pred(out.ctl_child_verified_in_parent_air,
                  "ctl_verified_required") &&
        fail_pred(out.terminal_bus_commitment_mapped,
                  "terminal_bus_required") &&
        fail_pred(out.normalized_semantic_root_derived_in_parent,
                  "semantic_root_required") &&
        fail_pred(out.split_rap_multirow_parent_adapter,
                  "split_rap_adapter_required") &&
        fail_pred(!out.endpoint_terminal_equality,
                  "endpoint_terminal_unexpected") &&
        fail_pred(!kCompleteRecursiveFixedPointExecutable,
                  "complete_fp_unexpected") &&
        fail_pred(!kRecursiveFixedPointConsensusAuthority,
                  "fp_authority_unexpected") &&
        fail_pred(!va::kVerifierAirConsensusAuthority,
                  "va_authority_unexpected") &&
        fail_pred(!va::kVerifierFiatShamirAirExecutable,
                  "va_fs_chip_unexpected");
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "capability_audit_ok;"
          "proof_commitment_bus_closed_via_proof_field_bus;"
          "terminal_bus_closed_via_deep64_ctl;"
          "semantic_root_input_lanes_complete;"
          "ctl_child_verifier_in_parent_air_closed;"
          "ledger_g4_fiat_shamir_replay_closed;"
          "split_rap_multirow_adapter_closed;"
          "proof_payload_bus_closed;"
          "complete_fp=false;"
        : ("stage3:recursive_fixedpoint:"
           "capability_with_ctl_parent_air_not_canonical" +
           failed);
    if (out.valid) {
        out.note +=
            "recursive_counters_" +
            std::to_string(out.recursively_consumed_endpoints) +
            "_of_52_and_" +
            std::to_string(out.recursively_consumed_roles) +
            "_of_14";
    }
    return out;
}
bool ValidateNormalizedRecursiveChildCapabilityWithProofBusDeepCtlParentAirV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedDeep64CtlTerminalAttachmentV1& deep64_ctl,
    const NormalizedDeep64CtlChildParentAirAttachmentV1&
        ctl_parent_air,
    const NormalizedRecursiveChildCapabilityAuditV1& audit,
    std::string* why)
{
    const NormalizedRecursiveChildCapabilityAuditV1 expected =
        AssessNormalizedRecursiveChildCapabilityWithProofBusDeepCtlParentAirV1(
            composition, interpreter, row_pin, execution,
            proof_bus, deep64_ctl, ctl_parent_air);
    if (!expected.valid || !(expected == audit)) {
        if (why != nullptr) {
            *why =
                "normalized_recursive_child_capability_"
                "with_ctl_parent_air_mismatch";
        }
        return false;
    }
    return true;
}

NormalizedRecursiveChildCapabilityAuditV1
AssessNormalizedRecursiveChildCapabilityV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution)
{
    NormalizedRecursiveChildCapabilityAuditV1 out;
    out.candidate_role_endpoint_count =
        static_cast<uint16_t>(
            RequiredRCStage3RelationEndpoints(
                out.candidate_role).size());
    out.candidate_endpoint_count = 1;
    out.child_relation_columns =
        kRCStage3CoupledBankDequantColumns;
    out.child_relation_constraints =
        static_cast<uint32_t>(
            interpreter.program_table.programs.size());
    out.parent_rows =
        composition.combined.n_rows;
    out.parent_columns =
        composition.combined.n_columns;
    out.parent_constraints =
        static_cast<uint32_t>(
            composition.combined.constraints.size());

    const NormalizedSemanticAlgHashParentAudit root =
        AssessNormalizedSemanticAlgHashParentClosure(
            composition, interpreter, row_pin, execution);
    out.normalized_root_required_input_lanes =
        root.required_input_lanes;
    out.normalized_root_available_input_lanes =
        root.verifier_constant_lanes +
        root.proof_authenticated_lanes;
    out.normalized_root_missing_input_lanes =
        root.missing_proof_bus_lanes;
    out.normalized_root_additional_permutation_columns =
        root.additional_permutation_columns;

    out.native_child_host_verified =
        execution.valid &&
        execution.normalized_child_proof_verified;
    out.authenticated_opening_air =
        composition.valid &&
        composition.hash.valid &&
        composition.hash.proof_derived &&
        composition.hash.native_child_accepted &&
        composition.hash.program.current_row_opening &&
        composition.hash.program.next_row_opening &&
        composition.hash.program.trace_root_opening &&
        composition.hash.program.every_fold_opening &&
        composition.direct_hash_alias;
    out.fold_deep_air =
        composition.fold_equations &&
        composition.fold_chain_and_final_equations &&
        composition.initial_deep_identity &&
        composition.deep_per_point_transition_join &&
        composition.dual_logup_terminal;
    // result_zero_constrained stays false by design: the interpreter enforces
    // child equations through the quotient-opening identity bus, not a separate
    // per-result zero chip (see episode_digest_bytecode_uses_authenticated_
    // vertical_memory, which asserts !result_zero_constrained). Requiring that
    // flag here made the capability audit permanently unsatisfiable.
    out.relation_bytecode_air =
        interpreter.valid &&
        interpreter.canonical_program &&
        interpreter.authenticated_row_memory_bus &&
        interpreter.dual_logup_terminal &&
        interpreter.quotient_opening_equality &&
        interpreter.same_trace_relation_cell_logup_export;
    out.child_trace_root_mapped =
        root.child_trace_root_mapped;

    // Host replay and proof commitments are useful witness-construction
    // checks; the ChildProofPayloadBus additionally places every batch codec
    // word and supplemental opening field in authenticated AIR columns
    // (va::BuildVerifierProofRowsPayloadBusV1 / kVerifierProofRowsBoundInAir).
    out.child_proof_payload_bound_in_air =
        va::kVerifierProofRowsBoundInAir;
    // g4 child Fiat-Shamir replay is owned by recursive_parent_air. The
    // ledger's fiat_shamir_replay_complete is COMPUTED from
    // AssessChildFsReplayClosureV1().closed — consume that same predicate
    // here (do NOT use va::kVerifierFiatShamirAirExecutable, still false;
    // do NOT re-own parent_air / air_quotient).
    out.child_fiat_shamir_replayed_in_air =
        recursive_parent_air::AssessChildFsReplayClosureV1()
            .closed;
    out.child_proof_commitment_mapped =
        root.child_proof_commitment_mapped;
    out.ctl_child_verified_in_parent_air = false;
    out.terminal_bus_commitment_mapped =
        root.terminal_bus_commitment_mapped;
    out.normalized_semantic_root_derived_in_parent =
        root.in_parent_derivation_complete;

    // Native signed-range Split-RAP canary plus the MultiRow-V2 local verifier
    // AIR parent adapter (CoupledBankEqualityChildVerifier /
    // NormalizedUniversalParentCandidate consume MultiRow-V2 proofs).
    // RecursiveAuthority stays false (semantic Poseidon I/O + SHA AIR open).
    out.split_rap_native_verifier_executable =
        kRCStage3EpisodeSignedRangeSplitRapCanaryExecutable;
    out.split_rap_multirow_parent_adapter =
        va::kMultiRowV2SplitRapVerifierAirLocalExecutable;
    out.endpoint_terminal_equality =
        interpreter.role_semantic_root_terminal_equality;

    out.gaps = {
        {
            NormalizedRecursiveVerifierGapCode::
                ChildProofPayloadBus,
            "ordered_all_child_proof_field_bus",
            0, 0, 0, out.child_proof_payload_bound_in_air,
            out.child_proof_payload_bound_in_air
                ? "va::BuildVerifierProofRowsPayloadBusV1 enumerates "
                  "batch codec words and every supplemental next-opening "
                  "index/value/sibling into AlgHash sponge columns; "
                  "forgery rejected; kVerifierProofRowsBoundInAir"
                : "no parent columns enumerate and authenticate every batch "
                  "field, opening, sibling, index and supplemental next row",
        },
        {
            NormalizedRecursiveVerifierGapCode::
                FiatShamirReplayAir,
            "complete_child_fiat_shamir_replay",
            0, 0, 0, out.child_fiat_shamir_replayed_in_air,
            out.child_fiat_shamir_replayed_in_air
                ? "ledger g4 AssessChildFsReplayClosureV1().closed; "
                  "va::kVerifierFiatShamirAirExecutable remains false"
                : "host replay exists; SHA/XOF rejection sampling and all "
                  "challenge-to-proof equalities are absent from the parent "
                  "AIR; ledger fiat_shamir_replay_complete is still open",
        },
        {
            NormalizedRecursiveVerifierGapCode::
                ChildProofCommitmentBus,
            "child_proof_commitment_u32_bus",
            8, 0, 0, out.child_proof_commitment_mapped,
            "zero of eight collision-free u32 digest lanes have a "
            "proof-authenticated parent source",
        },
        {
            NormalizedRecursiveVerifierGapCode::
                CtlChildVerifierAndTerminalBus,
            "normalized_ctl_child_verifier_and_terminal_bus",
            8, 0, 0, out.ctl_child_verified_in_parent_air &&
                         out.terminal_bus_commitment_mapped,
            "the CTL child is host-verified; zero of eight terminal "
            "commitment lanes are produced by a verifier inside this parent",
        },
        {
            NormalizedRecursiveVerifierGapCode::
                NormalizedSemanticRootAlgHash,
            "normalized_semantic_root_alg_hash_sponge",
            root.required_input_lanes,
            out.normalized_root_available_input_lanes,
            root.additional_permutation_columns,
            out.normalized_semantic_root_derived_in_parent,
            "the canonical seven-block sponge needs 910 permutation "
            "columns; 32 of 48 inputs are available and 16 proof buses "
            "remain missing",
        },
        {
            NormalizedRecursiveVerifierGapCode::
                SplitRapMultiRowVerifier,
            "split_rap_multirow_v2_recursive_adapter",
            0, 0, 0, out.split_rap_multirow_parent_adapter,
            out.split_rap_multirow_parent_adapter
                ? "MultiRow-V2 Split-RAP local verifier AIR executes "
                  "(kMultiRowV2SplitRapVerifierAirLocalExecutable); "
                  "CoupledBankEqualityChildVerifier + "
                  "NormalizedUniversalParentCandidate consume the three-"
                  "group proof; RecursiveAuthority / hash chips remain open"
                : "EpisodeGemmSignedRange uses three ordered current-row "
                  "groups, two supplemental next-row groups and Q192; "
                  "MultiRow-V2 local verifier AIR adapter still open",
        },
        {
            NormalizedRecursiveVerifierGapCode::
                EndpointTerminalEquality,
            "coupled_bank_pages_endpoint_terminal_equality",
            8, 0, 0, out.endpoint_terminal_equality,
            "the externally pinned normalized role root is not equality-"
            "constrained to endpoint 28's proof-owned terminal",
        },
    };

    // These are authority counters, not coverage estimates. They stay zero
    // while any required recursive verifier component is absent.
    out.recursively_consumed_endpoints = 0;
    out.recursively_consumed_roles = 0;
    out.recursive_consumption_complete = false;
    std::string failed;
    const auto fail_pred = [&](bool ok, const char* tag) {
        if (!ok) {
            failed.push_back(';');
            failed += tag;
        }
        return ok;
    };
    out.valid =
        fail_pred(out.candidate_role_endpoint_count == 3,
                  "role_endpoint_count") &&
        fail_pred(out.child_relation_columns == 6,
                  "child_relation_columns") &&
        fail_pred(out.child_relation_constraints == 5,
                  "child_relation_constraints") &&
        fail_pred(out.parent_rows >= 2, "parent_rows") &&
        fail_pred(out.parent_columns > 0, "parent_columns") &&
        fail_pred(out.parent_constraints > 0, "parent_constraints") &&
        fail_pred(out.native_child_host_verified,
                  "native_child_host_verified") &&
        fail_pred(out.authenticated_opening_air,
                  "authenticated_opening_air") &&
        fail_pred(out.fold_deep_air, "fold_deep_air") &&
        fail_pred(out.relation_bytecode_air,
                  "relation_bytecode_air") &&
        fail_pred(out.child_trace_root_mapped,
                  "child_trace_root_mapped") &&
        fail_pred(out.normalized_root_required_input_lanes == 48,
                  "root_required_lanes") &&
        fail_pred(out.normalized_root_available_input_lanes == 32,
                  "root_available_lanes") &&
        fail_pred(out.normalized_root_missing_input_lanes == 16,
                  "root_missing_lanes") &&
        fail_pred(
            out.normalized_root_additional_permutation_columns == 910,
            "root_perm_columns") &&
        fail_pred(out.split_rap_native_verifier_executable,
                  "split_rap_native") &&
        fail_pred(out.gaps.size() == 7, "gaps_size") &&
        fail_pred(out.child_proof_payload_bound_in_air,
                  "payload_bound_required") &&
        fail_pred(out.child_fiat_shamir_replayed_in_air,
                  "fs_replay_required") &&
        fail_pred(!out.child_proof_commitment_mapped,
                  "proof_commit_unexpected") &&
        fail_pred(!out.ctl_child_verified_in_parent_air,
                  "ctl_verified_unexpected") &&
        fail_pred(!out.terminal_bus_commitment_mapped,
                  "terminal_bus_unexpected") &&
        fail_pred(!out.normalized_semantic_root_derived_in_parent,
                  "semantic_root_unexpected") &&
        fail_pred(out.split_rap_multirow_parent_adapter,
                  "split_rap_adapter_required") &&
        fail_pred(!out.endpoint_terminal_equality,
                  "endpoint_terminal_unexpected") &&
        fail_pred(!kCompleteRecursiveFixedPointExecutable,
                  "complete_fp_unexpected") &&
        fail_pred(!kRecursiveFixedPointConsensusAuthority,
                  "fp_authority_unexpected") &&
        fail_pred(!va::kVerifierAirConsensusAuthority,
                  "va_authority_unexpected") &&
        fail_pred(!va::kVerifierFiatShamirAirExecutable,
                  "va_fs_chip_unexpected");
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "capability_audit_ok;"
          "coupled_bank_pages_is_smallest_current_parent_candidate;"
          "algebraic_child_equations_execute;"
          "ledger_g4_fiat_shamir_replay_closed;"
          "proof_payload_bus_closed;"
          "ctl_terminal_and_semantic_root_chips_open;"
          "split_rap_multirow_adapter_closed;"
        : ("stage3:recursive_fixedpoint:"
           "capability_audit_input_not_canonical" +
           failed);
    if (out.valid) {
        out.note +=
            "recursive_counters_" +
            std::to_string(out.recursively_consumed_endpoints) +
            "_of_52_and_" +
            std::to_string(out.recursively_consumed_roles) +
            "_of_14";
    }
    return out;
}

bool ValidateNormalizedRecursiveChildCapabilityV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedRecursiveChildCapabilityAuditV1& audit,
    std::string* why)
{
    const NormalizedRecursiveChildCapabilityAuditV1 expected =
        AssessNormalizedRecursiveChildCapabilityV1(
            composition, interpreter, row_pin, execution);
    if (!expected.valid ||
        audit.version !=
            kNormalizedRecursiveChildCapabilityAuditVersion ||
        !audit.valid) {
        return Fail(
            why,
            "normalized_recursive_capability_shape");
    }
    if (audit != expected) {
        return Fail(
            why,
            "normalized_recursive_capability_substitution");
    }
    if (audit.recursively_consumed_endpoints != 0 ||
        audit.recursively_consumed_roles != 0 ||
        audit.recursive_consumption_complete) {
        return Fail(
            why,
            "normalized_recursive_capability_counter_promotion");
    }
    return true;
}

NormalizedRecursiveChildCapabilityAuditV1
AssessNormalizedRecursiveChildCapabilityWithProofBusV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedTerminalBusCommitmentBusAttachmentV1* terminal_bus)
{
    NormalizedRecursiveChildCapabilityAuditV1 out =
        AssessNormalizedRecursiveChildCapabilityV1(
            composition, interpreter, row_pin, execution);
    const NormalizedSemanticAlgHashParentAudit base_root =
        AssessNormalizedSemanticAlgHashParentClosure(
            composition, interpreter, row_pin, execution);
    NormalizedSemanticAlgHashParentAudit root =
        PromoteNormalizedSemanticProofCommitmentFromFieldBusV1(
            base_root, proof_bus, execution.slot);
    if (!root.child_proof_commitment_mapped) {
        out.valid = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_with_proof_bus_commitment_not_promoted";
        return out;
    }
    const bool close_terminal =
        terminal_bus != nullptr && terminal_bus->valid;
    if (close_terminal) {
        root = PromoteNormalizedSemanticTerminalBusFromCommitmentBusV1(
            root, *terminal_bus, execution.slot);
        if (!root.terminal_bus_commitment_mapped) {
            out.valid = false;
            out.note =
                "stage3:recursive_fixedpoint:"
                "capability_with_terminal_bus_not_promoted";
            return out;
        }
    }

    out.child_proof_commitment_mapped = true;
    out.terminal_bus_commitment_mapped =
        root.terminal_bus_commitment_mapped;
    out.normalized_root_available_input_lanes =
        root.verifier_constant_lanes +
        root.proof_authenticated_lanes;
    out.normalized_root_missing_input_lanes =
        root.missing_proof_bus_lanes;
    out.normalized_semantic_root_derived_in_parent =
        root.in_parent_derivation_complete;

    for (auto& gap : out.gaps) {
        if (gap.code ==
            NormalizedRecursiveVerifierGapCode::
                ChildProofCommitmentBus) {
            gap.mapped_lanes = 8;
            gap.present_in_parent_air = true;
            gap.detail =
                "ProofFieldBus derives child proof commitment from the "
                "ordered transcript and links eight u32 semantic lanes; "
                "proof field cells remain verifier pins until decoder/"
                "remote equality maps close";
        }
        if (close_terminal &&
            gap.code ==
                NormalizedRecursiveVerifierGapCode::
                    CtlChildVerifierAndTerminalBus) {
            gap.mapped_lanes = 8;
            gap.present_in_parent_air =
                out.ctl_child_verified_in_parent_air &&
                out.terminal_bus_commitment_mapped;
            gap.detail =
                "TerminalBusCommitmentBus closed eight terminal "
                "commitment lanes; CTL child verifier remains host-only "
                "(ctl_child_verified_in_parent_air=false)";
        }
        if (close_terminal &&
            gap.code ==
                NormalizedRecursiveVerifierGapCode::
                    NormalizedSemanticRootAlgHash) {
            gap.mapped_lanes = 48;
            gap.present_in_parent_air =
                out.normalized_semantic_root_derived_in_parent;
            gap.detail =
                "all 48 semantic-root input lanes bound after "
                "ProofFieldBus + TerminalBusCommitmentBus promotes";
        }
    }

    const uint32_t expect_available = close_terminal ? 48U : 40U;
    const uint32_t expect_missing = close_terminal ? 0U : 8U;

    std::string failed;
    const auto fail_pred = [&](bool ok, const char* tag) {
        if (!ok) {
            failed.push_back(';');
            failed += tag;
        }
        return ok;
    };
    out.valid =
        fail_pred(out.candidate_role_endpoint_count == 3,
                  "role_endpoint_count") &&
        fail_pred(out.child_relation_columns == 6,
                  "child_relation_columns") &&
        fail_pred(out.child_relation_constraints == 5,
                  "child_relation_constraints") &&
        fail_pred(out.parent_rows >= 2, "parent_rows") &&
        fail_pred(out.parent_columns > 0, "parent_columns") &&
        fail_pred(out.parent_constraints > 0, "parent_constraints") &&
        fail_pred(out.native_child_host_verified,
                  "native_child_host_verified") &&
        fail_pred(out.authenticated_opening_air,
                  "authenticated_opening_air") &&
        fail_pred(out.fold_deep_air, "fold_deep_air") &&
        fail_pred(out.relation_bytecode_air,
                  "relation_bytecode_air") &&
        fail_pred(out.child_trace_root_mapped,
                  "child_trace_root_mapped") &&
        fail_pred(out.normalized_root_required_input_lanes == 48,
                  "root_required_lanes") &&
        fail_pred(out.normalized_root_available_input_lanes ==
                      expect_available,
                  "root_available_lanes") &&
        fail_pred(out.normalized_root_missing_input_lanes ==
                      expect_missing,
                  "root_missing_lanes") &&
        fail_pred(
            out.normalized_root_additional_permutation_columns == 910,
            "root_perm_columns") &&
        fail_pred(out.split_rap_native_verifier_executable,
                  "split_rap_native") &&
        fail_pred(out.gaps.size() == 7, "gaps_size") &&
        fail_pred(out.child_proof_payload_bound_in_air,
                  "payload_bound_required") &&
        fail_pred(out.child_fiat_shamir_replayed_in_air,
                  "fs_replay_required") &&
        fail_pred(out.child_proof_commitment_mapped,
                  "proof_commit_required") &&
        fail_pred(!out.ctl_child_verified_in_parent_air,
                  "ctl_verified_unexpected") &&
        fail_pred(out.terminal_bus_commitment_mapped == close_terminal,
                  "terminal_bus_state") &&
        fail_pred(out.normalized_semantic_root_derived_in_parent ==
                      close_terminal,
                  "semantic_root_state") &&
        fail_pred(out.split_rap_multirow_parent_adapter,
                  "split_rap_adapter_required") &&
        fail_pred(!out.endpoint_terminal_equality,
                  "endpoint_terminal_unexpected") &&
        fail_pred(!kCompleteRecursiveFixedPointExecutable,
                  "complete_fp_unexpected") &&
        fail_pred(!kRecursiveFixedPointConsensusAuthority,
                  "fp_authority_unexpected") &&
        fail_pred(!va::kVerifierAirConsensusAuthority,
                  "va_authority_unexpected") &&
        fail_pred(!va::kVerifierFiatShamirAirExecutable,
                  "va_fs_chip_unexpected");
    if (out.valid) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_audit_ok;"
            "proof_commitment_bus_closed_via_proof_field_bus;";
        if (close_terminal) {
            out.note +=
                "terminal_bus_closed_via_commitment_bus;"
                "semantic_root_derived_in_parent;"
                "ctl_child_verifier_still_host_only;"
                "proof_payload_bus_closed;"
                "endpoint_open;";
        } else {
            out.note +=
                "ledger_g4_fiat_shamir_replay_closed;"
                "proof_payload_bus_closed;"
                "ctl_terminal_and_semantic_root_chips_open;";
        }
        out.note +=
            "split_rap_multirow_adapter_closed;"
            "complete_fp=false;"
            "recursive_counters_" +
            std::to_string(out.recursively_consumed_endpoints) +
            "_of_52_and_" +
            std::to_string(out.recursively_consumed_roles) +
            "_of_14";
    } else {
        out.note =
            "stage3:recursive_fixedpoint:"
            "capability_with_proof_bus_not_canonical" +
            failed;
    }
    return out;
}

bool ValidateNormalizedRecursiveChildCapabilityWithProofBusV1(
    const FoldBusComposition& composition,
    const BytecodeInterpreterAttachment& interpreter,
    const NormalizedCoupledBankRowPin& row_pin,
    const NormalizedCoupledBankTerminalExecution& execution,
    const NormalizedAlgAirProofFieldBusAttachmentV1& proof_bus,
    const NormalizedRecursiveChildCapabilityAuditV1& audit,
    std::string* why,
    const NormalizedTerminalBusCommitmentBusAttachmentV1* terminal_bus)
{
    const NormalizedRecursiveChildCapabilityAuditV1 expected =
        AssessNormalizedRecursiveChildCapabilityWithProofBusV1(
            composition, interpreter, row_pin, execution,
            proof_bus, terminal_bus);
    if (!expected.valid || !(expected == audit)) {
        if (why != nullptr) {
            *why =
                "normalized_recursive_child_capability_"
                "with_proof_bus_mismatch";
        }
        return false;
    }
    return true;
}


NormalizedParentProofPreflight
AssessNormalizedParentProofPreflight(
    const aq::AirConstraintSystem<Fp3>& parent_cs)
{
    NormalizedParentProofPreflight out;
    out.trace_rows = parent_cs.n_rows;
    out.trace_columns = parent_cs.n_columns;
    out.constraints = static_cast<uint32_t>(
        parent_cs.constraints.size());
    for (const auto& constraint : parent_cs.constraints) {
        out.max_alg_degree = std::max(
            out.max_alg_degree, constraint.alg_degree);
    }
    if (out.trace_rows < 2 ||
        (out.trace_rows & (out.trace_rows - 1)) != 0 ||
        out.trace_columns == 0 ||
        out.constraints == 0) {
        out.note =
            "stage3:recursive_fixedpoint:parent_preflight_shape";
        return out;
    }
    out.max_composed_degree =
        parent_cs.MaxComposedDegreeBound();
    out.quotient_len = parent_cs.QuotientLen();
    out.degree_supported =
        out.max_composed_degree + 1 <=
        (uint64_t{1} << kRCFriMaxLdeLog2);
    if (!out.degree_supported) {
        out.note =
            "stage3:recursive_fixedpoint:parent_preflight_degree";
        return out;
    }
    out.composition_rows = std::max(
        out.trace_rows,
        FriNextPow2(static_cast<uint32_t>(
            out.max_composed_degree + 1)));
    out.n_coeffs = FriNextPow2(std::max(
        out.trace_rows, out.quotient_len));
    const uint64_t n_lde =
        uint64_t{out.n_coeffs} * kRCFriBlowup;
    if (n_lde <= std::numeric_limits<uint32_t>::max()) {
        out.n_lde = static_cast<uint32_t>(n_lde);
    }
    out.lde_supported =
        n_lde <= (uint64_t{1} << kRCFriMaxLdeLog2);
    out.backend_columns_supported =
        uint64_t{out.trace_columns} + 1 <=
        kRCFri3AlgBatchMaxColumns;
    out.queries = kRCFri3AlgNumQueries;

    constexpr uint64_t FP3_BYTES =
        3 * sizeof(uint64_t);
    const uint64_t opened_columns =
        uint64_t{out.trace_columns} + 1;
    auto multiply =
        [](uint64_t lhs, uint64_t rhs,
           uint64_t& result) {
            if (lhs != 0 &&
                rhs >
                    std::numeric_limits<uint64_t>::max() /
                        lhs) {
                return false;
            }
            result = lhs * rhs;
            return true;
        };
    uint64_t raw_cells = 0;
    uint64_t query_cells = 0;
    uint64_t batch_lde_cells = 0;
    if (!multiply(
            out.trace_columns, out.trace_rows,
            raw_cells) ||
        !multiply(
            out.queries, opened_columns,
            query_cells) ||
        !multiply(
            opened_columns, n_lde,
            batch_lde_cells) ||
        !multiply(raw_cells, FP3_BYTES,
                  out.raw_trace_bytes) ||
        !multiply(
            query_cells, FP3_BYTES,
            out.minimum_batch_row_value_bytes) ||
        !multiply(
            batch_lde_cells, FP3_BYTES,
            out.current_batch_lde_bytes)) {
        out.note =
            "stage3:recursive_fixedpoint:parent_preflight_overflow";
        return out;
    }
    // The supplemental next-row opening repeats the same W+1 canonical
    // values. The trace-binding path reuses current-row values and carries no
    // additional Fp3 value vector.
    out.minimum_next_row_value_bytes =
        out.minimum_batch_row_value_bytes;
    if (out.minimum_batch_row_value_bytes >
        std::numeric_limits<uint64_t>::max() -
            out.minimum_next_row_value_bytes) {
        out.note =
            "stage3:recursive_fixedpoint:parent_preflight_overflow";
        return out;
    }
    out.minimum_total_row_value_bytes =
        out.minimum_batch_row_value_bytes +
        out.minimum_next_row_value_bytes;
    out.codec_bytes_per_lane =
        kRCFriMaxProofBytesHard;
    out.batch_codec_lower_bound_supported =
        out.minimum_batch_row_value_bytes <=
        out.codec_bytes_per_lane;

    // The new AirQuotientProveRows/Fri3AlgBatchCommitStreamingShared path
    // emits byte-identical bounded proofs and does not return the W×N_LDE
    // matrix. AuditAirQuotientSpillFp3 separately proves quotient tile
    // equivalence, but is still audit-only and itself keeps dense comparison
    // vectors. Joining those two pieces behind an external coefficient source
    // and quotient sink is the remaining production prover seam.
    out.spill_audit_available = true;
    out.spill_audit_materializes_dense_lde = true;
    out.two_pass_row_commit_executable = true;
    out.bounded_row_streaming_byte_identical = true;
    out.external_store_quotient_prover = false;
    out.streamed_row_commit_callback = false;
    out.safe_to_execute_current_prover = false;
    out.missing_streaming_callback =
        "AirQuotientProveRowsExternal(column_source, quotient_tile_sink): "
        "join the existing quotient spill callback to the executable "
        "two-pass row commit without materializing coeffs/shifted/ldeM";
    out.valid = true;
    out.note =
        out.lde_supported &&
        out.backend_columns_supported &&
        out.batch_codec_lower_bound_supported
            ? "stage3:recursive_fixedpoint:parent_shape_fits_but_"
              "streaming_proof_emitter_missing"
            : "stage3:recursive_fixedpoint:parent_backend_cap";
    return out;
}

std::vector<CompleteFixedPointScenario>
AssessCompleteFixedPointScenarios(
    const nr::NarrowChildShape& leaf)
{
    std::vector<CompleteFixedPointScenario> out;
    const std::array<nr::PoseidonLaneStrategy, 3> strategies{
        nr::PoseidonLaneStrategy::DirectX7,
        nr::PoseidonLaneStrategy::DecomposedX2X4,
        nr::PoseidonLaneStrategy::DecomposedX2X4X6};
    const std::array<uint32_t, 3> physical_lanes{
        1, 2, 4};
    for (const auto strategy : strategies) {
        for (const uint32_t lanes : physical_lanes) {
            CompleteFixedPointScenario scenario;
            scenario.poseidon_strategy = strategy;
            scenario.physical_lanes = lanes;
            scenario.child_packing =
                lanes == 1
                    ? nr::ChildPacking::VerticalRows
                    : nr::ChildPacking::ParallelLanes;
            scenario.charges_current_next_trace = true;
            scenario.executable_hash_opening_air =
                kHashOpeningAirExecutable;
            scenario.executable_scalar_air = true;
            scenario.executable_memory_bus = false;
            scenario.leaf =
                BuildLevel(leaf, strategy, lanes);
            const nr::NarrowChildShape shape1 =
                NextShape(leaf, scenario.leaf);
            scenario.level1 =
                BuildLevel(shape1, strategy, lanes);
            const nr::NarrowChildShape shape2 =
                NextShape(shape1, scenario.level1);
            scenario.level2 =
                BuildLevel(shape2, strategy, lanes);
            scenario.width_fixed_point =
                scenario.leaf.valid &&
                scenario.level1.valid &&
                scenario.level2.valid &&
                scenario.level1.parent_width ==
                    scenario.leaf.parent_width &&
                scenario.level2.parent_width ==
                    scenario.leaf.parent_width;
            scenario.trace_fixed_point =
                scenario.level1.valid &&
                scenario.level2.valid &&
                scenario.level2.trace_rows <=
                    scenario.level1.trace_rows;
            scenario.backend_shape_supported =
                scenario.leaf.valid &&
                scenario.level1.valid &&
                scenario.level2.valid &&
                scenario.leaf.columns_supported &&
                scenario.leaf.lde_supported &&
                scenario.level1.columns_supported &&
                scenario.level1.lde_supported &&
                scenario.level2.columns_supported &&
                scenario.level2.lde_supported;
            scenario.selected_v1_topology =
                strategy ==
                    nr::PoseidonLaneStrategy::
                        DecomposedX2X4X6 &&
                lanes == 4 &&
                scenario.backend_shape_supported &&
                scenario.width_fixed_point &&
                scenario.trace_fixed_point;
            scenario.complete_recursive_parent =
                scenario.selected_v1_topology &&
                scenario.executable_hash_opening_air &&
                scenario.executable_scalar_air &&
                scenario.executable_memory_bus;
            scenario.note =
                scenario.selected_v1_topology
                    ? "stage3:recursive_fixedpoint:selected_binary_"
                      "four_lane_quadratic_memory_bus_open;"
                      "p2_fs_ledger_closed;"
                      "proof_commitment_bus_promotable_via_field_bus"
                    : scenario.backend_shape_supported
                    ? "stage3:recursive_fixedpoint:shape_supported_"
                      "not_selected"
                    : "stage3:recursive_fixedpoint:backend_cap";
            out.push_back(std::move(scenario));
        }
    }
    return out;
}

CompleteFixedPointScenario SelectCompleteFixedPointV1(
    const nr::NarrowChildShape& leaf)
{
    for (auto& scenario :
         AssessCompleteFixedPointScenarios(leaf)) {
        if (scenario.selected_v1_topology) {
            return scenario;
        }
    }
    CompleteFixedPointScenario out;
    out.note =
        "stage3:recursive_fixedpoint:no_complete_shape";
    return out;
}

namespace {

/**
 * Emit ONE child's schedule at the end of `out.rows`, tagging every emitted row
 * with `child_index`. Byte-identical to the original single-child body; the tag
 * is 0 for every existing caller, so no schedule changes.
 */
bool AppendChildHashOpeningProgram(
    HashOpeningProgram& out,
    const ar::ChildPublicInputs& pi,
    uint32_t child_index,
    std::string& note)
{
    if (!pi.ok || pi.child_w == 0 ||
        pi.child_n_rows < 2 ||
        pi.child_n_lde == 0 ||
        pi.merkle_depth != Log2Exact(pi.child_n_lde) ||
        pi.n_folds != Log2Exact(pi.child_n_coeffs) ||
        pi.query_index.empty() ||
        pi.fold_roots.size() != pi.n_folds) {
        note =
            "stage3:recursive_fixedpoint:hash_program_shape";
        return false;
    }
    const size_t begin = out.rows.size();
    const uint32_t next_step =
        pi.child_n_lde / pi.child_n_rows;
    for (uint32_t query = 0;
         query < pi.query_index.size(); ++query) {
        const uint32_t index = pi.query_index[query];
        if (index >= pi.child_n_lde) {
            note =
                "stage3:recursive_fixedpoint:hash_query_index";
            return false;
        }
        AppendSpongeProgram(
            out, pi.child_w + 1, index,
            pi.merkle_depth, pi.row_commit_root,
            true, false, query);
        const uint32_t next_index =
            (index + next_step) % pi.child_n_lde;
        AppendSpongeProgram(
            out, pi.child_w + 1, next_index,
            pi.merkle_depth, pi.row_commit_root,
            false, true, query);
        AppendSpongeProgram(
            out, pi.child_w, index,
            pi.merkle_depth, pi.rt_root,
            false, false, query);
        uint32_t reduced = index;
        for (uint32_t layer = 0;
             layer < pi.n_folds; ++layer) {
            const uint32_t n_leaves =
                pi.child_n_lde >> layer;
            const uint32_t half = n_leaves / 2;
            const uint32_t even_index = reduced % half;
            const uint32_t odd_index =
                even_index + half;
            const uint32_t depth =
                pi.merkle_depth - layer;
            AppendSingleValueProgram(
                out, even_index, depth,
                pi.fold_roots[layer], query, layer, 1);
            AppendSingleValueProgram(
                out, odd_index, depth,
                pi.fold_roots[layer], query, layer, 2);
            reduced = even_index;
        }
    }
    for (size_t row = begin; row < out.rows.size(); ++row) {
        out.rows[row].child = child_index;
    }
    return true;
}

} // namespace

HashOpeningProgram BuildHashOpeningProgram(
    const std::vector<ar::ChildPublicInputs>& children)
{
    HashOpeningProgram out;
    if (children.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:hash_program_shape";
        return out;
    }
    out.public_inputs = children.front();
    out.children = children;
    std::string note;
    for (uint32_t child = 0;
         child < children.size(); ++child) {
        out.child_row_offsets.push_back(
            static_cast<uint32_t>(out.rows.size()));
        if (!AppendChildHashOpeningProgram(
                out, children[child], child, note)) {
            out.note = note;
            return out;
        }
    }
    out.active_rows =
        static_cast<uint32_t>(out.rows.size());
    out.trace_rows = NextPow2(out.active_rows);
    if (out.trace_rows == 0) {
        out.note =
            "stage3:recursive_fixedpoint:hash_trace_overflow";
        return out;
    }
    while (out.rows.size() < out.trace_rows) {
        out.rows.emplace_back();
    }
    out.current_row_opening = true;
    out.next_row_opening = true;
    out.trace_root_opening = true;
    out.every_fold_opening = true;
    out.valid = true;
    out.note =
        "stage3:recursive_fixedpoint:hash_program_complete";
    return out;
}

HashOpeningProgram BuildHashOpeningProgram(
    const ar::ChildPublicInputs& pi)
{
    return BuildHashOpeningProgram(
        std::vector<ar::ChildPublicInputs>{pi});
}

bool BuildHashOpeningConstraintSystem(
    const HashOpeningProgram& program,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why,
    uint32_t column_base)
{
    if (!program.valid ||
        program.rows.size() != program.trace_rows ||
        !program.current_row_opening ||
        !program.next_row_opening ||
        !program.trace_root_opening ||
        !program.every_fold_opening) {
        return Fail(why, "hash_program_invalid");
    }
    const HashOpeningProgram canonical =
        BuildHashOpeningProgram(
            program.children.empty()
                ? std::vector<ar::ChildPublicInputs>{
                      program.public_inputs}
                : program.children);
    if (!canonical.valid ||
        canonical.active_rows != program.active_rows ||
        canonical.trace_rows != program.trace_rows ||
        canonical.rows.size() != program.rows.size() ||
        !std::equal(
            canonical.rows.begin(), canonical.rows.end(),
            program.rows.begin(), ProgramRowsEqual)) {
        return Fail(why, "hash_program_noncanonical");
    }
    const HashOpeningLayout layout =
        HashOpeningLayoutAt(column_base);
    out = {};
    out.n_rows = program.trace_rows;
    out.n_columns = layout.End();
    out.preprocessed_pin_ood = true;

    // Fully quadratic x^7 on every row. Padding rows execute a harmless
    // permutation too, avoiding selector degree on the expensive chip.
    for (uint32_t s = 0; s < ar::kPermSboxCells; ++s) {
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.fixedpoint.poseidon.x2";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, s](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 x =
                        ar::PermSboxInput(
                            layout.perm, cur, s);
                    return gf::Sub(
                        cur[layout.x2_base + s],
                        gf::Mul(x, x));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.fixedpoint.poseidon.x4";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, s](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 x2 =
                        cur[layout.x2_base + s];
                    return gf::Sub(
                        cur[layout.x4_base + s],
                        gf::Mul(x2, x2));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.fixedpoint.poseidon.x6";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, s](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[layout.x6_base + s],
                        gf::Mul(
                            cur[layout.x4_base + s],
                            cur[layout.x2_base + s]));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.fixedpoint.poseidon.output";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, s](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 x =
                        ar::PermSboxInput(
                            layout.perm, cur, s);
                    return gf::Sub(
                        cur[layout.perm.SboxCol(s)],
                        gf::Mul(
                            cur[layout.x6_base + s], x));
                };
            out.constraints.push_back(std::move(c));
        }
    }

    const uint32_t first =
        layout.KindSelector(HashRowKind::SpongeFirst);
    const uint32_t single =
        layout.KindSelector(
            HashRowKind::SingleValueLeaf);
    const uint32_t merkle =
        layout.KindSelector(HashRowKind::MerkleCompress);

    // First sponge block: state starts at zero and rate is the absorbed word.
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.sponge.first.rate", 1,
            first,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[layout.perm.InputCol(lane)],
                    cur[layout.absorbed_pin_base + lane]);
            }));
    }
    for (uint32_t lane = ah::kAlgHashRate;
         lane < ah::kAlgHashT; ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.sponge.first.capacity",
            1, first,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[layout.perm.InputCol(lane)];
            }));
    }

    // Exact index/padding pins. Unmasked absorbed words are the proof's opened
    // row values and intentionally remain witness data.
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        aq::AirConstraint<Fp3> c;
        c.name =
            "stage3.fixedpoint.sponge.absorbed_pin";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 2;
        c.eval =
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[layout.absorbed_mask_base + lane],
                    gf::Sub(
                        cur[layout.absorbed_pin_base + lane],
                        cur[layout.absorbed_expected_base +
                            lane]));
            };
        out.constraints.push_back(std::move(c));
    }

    // Single-value leaf: [v.c0,v.c1,v.c2,index,Le,0..].
    out.constraints.push_back(Gate(
        "stage3.fixedpoint.leaf.index", 1, single,
        [layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Sub(
                cur[layout.perm.InputCol(3)],
                cur[layout.index_col]);
        }));
    out.constraints.push_back(Gate(
        "stage3.fixedpoint.leaf.domain", 1, single,
        [layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Sub(
                cur[layout.perm.InputCol(4)],
                Fp3::FromFp(
                    ah::GetAlgHashConstants().leaf_domain));
        }));
    for (uint32_t lane = 5; lane < ah::kAlgHashT;
         ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.leaf.zero", 1, single,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[layout.perm.InputCol(lane)];
            }));
    }

    // Every compression has the fixed node capacity.
    out.constraints.push_back(Gate(
        "stage3.fixedpoint.merkle.domain", 1, merkle,
        [layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Sub(
                cur[layout.perm.InputCol(8)],
                Fp3::FromFp(
                    ah::GetAlgHashConstants().node_domain));
        }));
    for (uint32_t lane = 9; lane < ah::kAlgHashT;
         ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.merkle.zero", 1, merkle,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[layout.perm.InputCol(lane)];
            }));
    }

    // Sponge carry and Merkle routing use true transition identities.
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.sponge.carry.rate", 1,
            layout.link_sponge_col,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[layout.perm.InputCol(lane)],
                    gf::Add(
                        ar::PermOutputLane(
                            layout.perm, cur, lane),
                        next[layout.absorbed_pin_base + lane]));
            },
            aq::AirKind::kTransition));
    }
    for (uint32_t lane = ah::kAlgHashRate;
         lane < ah::kAlgHashT; ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.sponge.carry.capacity",
            1, layout.link_sponge_col,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[layout.perm.InputCol(lane)],
                    ar::PermOutputLane(
                        layout.perm, cur, lane));
            },
            aq::AirKind::kTransition));
    }
    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        {
            aq::AirConstraint<Fp3> selected;
            selected.name =
                "stage3.fixedpoint.merkle.route_selected";
            selected.kind = aq::AirKind::kTransition;
            selected.alg_degree = 2;
            selected.eval =
                [layout, lane](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    const Fp3 direction =
                        next[layout.direction_col];
                    const Fp3 left =
                        next[layout.perm.InputCol(lane)];
                    const Fp3 right =
                        next[layout.perm.InputCol(
                            ah::kAlgHashDigestLen + lane)];
                    return gf::Sub(
                        cur[layout.route_selected_base + lane],
                        gf::Add(
                            left,
                            gf::Mul(
                                direction,
                                gf::Sub(right, left))));
                };
            out.constraints.push_back(std::move(selected));
        }
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.merkle.route", 1,
            layout.link_merkle_col,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 acc =
                    ar::PermOutputLane(
                        layout.perm, cur, lane);
                return gf::Sub(
                    cur[layout.route_selected_base + lane],
                    acc);
            },
            aq::AirKind::kTransition));
    }

    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        out.constraints.push_back(Gate(
            "stage3.fixedpoint.merkle.root", 1,
            layout.terminal_col,
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    ar::PermOutputLane(
                        layout.perm, cur, lane),
                    cur[layout.expected_root_base + lane]);
            }));
    }

    // Program columns.
    for (uint32_t kind = 0;
         kind < kHashRowKindCount; ++kind) {
        std::vector<Fp3> values(
            program.trace_rows, Fp3::Zero());
        for (uint32_t row = 0;
             row < program.trace_rows; ++row) {
            values[row] = Fp3::FromFp(gf::FromU64(
                static_cast<uint32_t>(
                    program.rows[row].kind) == kind));
        }
        AddPreprocessed(
            out, layout.kind_selector_base + kind,
            std::move(values));
    }
    auto bool_column =
        [&](uint32_t col,
            const std::function<bool(
                const HashOpeningProgramRow&)>& get) {
            std::vector<Fp3> values(
                program.trace_rows, Fp3::Zero());
            for (uint32_t row = 0;
                 row < program.trace_rows; ++row) {
                values[row] = Fp3::FromFp(
                    gf::FromU64(get(program.rows[row])));
            }
            AddPreprocessed(out, col, std::move(values));
        };
    bool_column(layout.link_sponge_col,
                [](const auto& row) {
                    return row.link_to_sponge;
                });
    bool_column(layout.link_merkle_col,
                [](const auto& row) {
                    return row.link_to_merkle;
                });
    bool_column(layout.terminal_col,
                [](const auto& row) {
                    return row.terminal;
                });
    bool_column(layout.direction_col,
                [](const auto& row) {
                    return row.direction;
                });
    {
        std::vector<Fp3> values(
            program.trace_rows, Fp3::Zero());
        for (uint32_t row = 0;
             row < program.trace_rows; ++row) {
            values[row] = Fp3::FromFp(
                gf::FromU64(program.rows[row].index));
        }
        AddPreprocessed(
            out, layout.index_col, std::move(values));
    }
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        std::vector<Fp3> mask(
            program.trace_rows, Fp3::Zero());
        std::vector<Fp3> expected(
            program.trace_rows, Fp3::Zero());
        for (uint32_t row = 0;
             row < program.trace_rows; ++row) {
            mask[row] = Fp3::FromFp(gf::FromU64(
                program.rows[row].
                    absorbed_is_pinned[lane]));
            expected[row] =
                program.rows[row].absorbed_pin[lane];
        }
        AddPreprocessed(
            out, layout.absorbed_mask_base + lane,
            std::move(mask));
        AddPreprocessed(
            out, layout.absorbed_expected_base + lane,
            std::move(expected));
    }
    for (uint32_t lane = 0;
         lane < ah::kAlgHashDigestLen; ++lane) {
        std::vector<Fp3> roots(
            program.trace_rows, Fp3::Zero());
        for (uint32_t row = 0;
             row < program.trace_rows; ++row) {
            roots[row] = Fp3::FromFp(gf::Canonical(
                program.rows[row].expected_root[lane]));
        }
        AddPreprocessed(
            out, layout.expected_root_base + lane,
            std::move(roots));
    }
    return true;
}

namespace {

HashOpeningWitness BuildAcceptedHashOpeningWitnessMulti(
    const std::vector<ar::ChildPublicInputs>& public_inputs,
    const std::vector<AlgAirProof>& proofs,
    uint32_t column_base = 0)
{
    HashOpeningWitness out;
    out.column_base = column_base;
    out.native_child_accepted = true;
    if (public_inputs.empty() ||
        public_inputs.size() != proofs.size()) {
        out.note =
            "stage3:recursive_fixedpoint:multi_child_arity";
        return out;
    }
    out.program = BuildHashOpeningProgram(public_inputs);
    if (!out.program.valid) {
        out.note = out.program.note;
        return out;
    }
    aq::AirConstraintSystem<Fp3> cs;
    std::string why;
    if (!BuildHashOpeningConstraintSystem(
            out.program, cs, &why, column_base)) {
        out.note = why;
        return out;
    }
    const HashOpeningLayout layout =
        HashOpeningLayoutAt(column_base);
    out.columns.assign(
        cs.n_columns,
        std::vector<Fp3>(
            cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        out.columns[column] = values;
    }

    uint32_t cursor = 0;
    for (uint32_t index = 0;
         index < public_inputs.size(); ++index) {
    const ar::ChildPublicInputs& child_pi =
        public_inputs[index];
    const AlgAirProof& child = proofs[index];
    if (child.batch.queries.size() !=
            child_pi.query_index.size()) {
        out.note =
            "stage3:recursive_fixedpoint:proof_query_count";
        return out;
    }
    for (uint32_t query = 0;
         query < child.batch.queries.size(); ++query) {
        const auto& q = child.batch.queries[query];
        if (child.next_openings.size() <= query ||
            child.next_openings[query].size() != 2 ||
            q.steps.size() != child_pi.n_folds) {
            out.note =
                "stage3:recursive_fixedpoint:proof_opening_shape";
            return out;
        }
        if (!AppendSpongeWitness(
                layout, q.row.values, q.index,
                q.row.siblings, out.columns, cursor,
                cs.n_rows)) {
            out.note =
                "stage3:recursive_fixedpoint:current_witness";
            return out;
        }
        const auto& next = child.next_openings[query][0];
        if (!AppendSpongeWitness(
                layout, next.values, next.index,
                next.siblings, out.columns, cursor,
                cs.n_rows)) {
            out.note =
                "stage3:recursive_fixedpoint:next_witness";
            return out;
        }
        const auto& trace = child.next_openings[query][1];
        if (q.row.values.size() < child_pi.child_w) {
            out.note =
                "stage3:recursive_fixedpoint:trace_row_width";
            return out;
        }
        const std::vector<Fp3> trace_values(
            q.row.values.begin(),
            q.row.values.begin() + child_pi.child_w);
        if (!AppendSpongeWitness(
                layout, trace_values, trace.index,
                trace.siblings, out.columns, cursor,
                cs.n_rows)) {
            out.note =
                "stage3:recursive_fixedpoint:trace_witness";
            return out;
        }
        for (uint32_t layer = 0;
             layer < child_pi.n_folds; ++layer) {
            const auto& step = q.steps[layer];
            if (!AppendSingleValueWitness(
                    layout, step.even, step.even_index,
                    step.even_siblings, out.columns,
                    cursor, cs.n_rows) ||
                !AppendSingleValueWitness(
                    layout, step.odd, step.odd_index,
                    step.odd_siblings, out.columns,
                    cursor, cs.n_rows)) {
                out.note =
                    "stage3:recursive_fixedpoint:fold_witness";
                return out;
            }
        }
    }
    }
    if (cursor != out.program.active_rows) {
        out.note =
            "stage3:recursive_fixedpoint:witness_schedule_mismatch";
        return out;
    }
    const ah::State zero{};
    while (cursor < cs.n_rows) {
        WritePermutation(
            layout, zero, out.columns, cursor);
        ++cursor;
    }
    for (uint32_t row = 0; row + 1 < cs.n_rows; ++row) {
        const Fp3 direction =
            out.columns[layout.direction_col][row + 1];
        for (uint32_t lane = 0;
             lane < ah::kAlgHashDigestLen; ++lane) {
            const Fp3 left =
                out.columns[
                    layout.perm.InputCol(lane)][row + 1];
            const Fp3 right =
                out.columns[
                    layout.perm.InputCol(
                        ah::kAlgHashDigestLen + lane)]
                    [row + 1];
            out.columns[
                layout.route_selected_base + lane][row] =
                gf::Add(
                    left,
                    gf::Mul(
                        direction, gf::Sub(right, left)));
        }
    }
    out.violations =
        CountHashOpeningViolations(
            cs, out.columns);
    out.proof_derived = true;
    out.valid = out.violations == 0;
    out.note =
        out.valid
            ? "stage3:recursive_fixedpoint:proof_derived_"
              "hash_openings_ok"
            : "stage3:recursive_fixedpoint:hash_opening_"
              "violation";
    return out;
}

HashOpeningWitness BuildAcceptedHashOpeningWitness(
    const ar::ChildPublicInputs& public_inputs,
    const AlgAirProof& child,
    uint32_t column_base = 0)
{
    return BuildAcceptedHashOpeningWitnessMulti(
        std::vector<ar::ChildPublicInputs>{public_inputs},
        std::vector<AlgAirProof>{child}, column_base);
}

AlgAirProof DualLaneView(
    const ar::DualAlgAirProof& child,
    uint32_t lane)
{
    AlgAirProof view;
    if (lane >= kRCFri3AlgDualNumLanes) return view;
    view.batch = child.batch.repeated.lane[lane];
    view.trace_commit = child.trace_commit;
    const size_t begin =
        static_cast<size_t>(lane) *
        kRCFri3AlgDualQueriesPerLane;
    const size_t end =
        begin + kRCFri3AlgDualQueriesPerLane;
    if (end <= child.next_openings.size()) {
        view.next_openings.insert(
            view.next_openings.end(),
            child.next_openings.begin() + begin,
            child.next_openings.begin() + end);
    }
    return view;
}

} // namespace

HashOpeningWitness BuildHashOpeningWitness(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const AlgAirProof& child,
    const uint256& child_fs_seed)
{
    std::string native_why;
    if (!aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            child_cs, child, child_fs_seed,
            &native_why)) {
        HashOpeningWitness out;
        out.note =
            "stage3:recursive_fixedpoint:native_child:" +
            native_why;
        return out;
    }
    const ar::ChildPublicInputs pi =
        ar::ExtractChildPublicInputs(
            child_cs, child, child_fs_seed);
    return BuildAcceptedHashOpeningWitness(pi, child);
}

HashOpeningWitness BuildHashOpeningWitnessMulti(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<AlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds)
{
    HashOpeningWitness out;
    if (children.empty() ||
        child_css.size() != children.size() ||
        child_fs_seeds.size() != children.size()) {
        out.note =
            "stage3:recursive_fixedpoint:multi_child_arity";
        return out;
    }
    std::vector<ar::ChildPublicInputs> pis;
    pis.reserve(children.size());
    for (size_t index = 0; index < children.size(); ++index) {
        std::string native_why;
        // FAIL CLOSED: the real, unmodified native verifier decides, per child,
        // under that child's own constraint system and seed.
        if (!aq::AirQuotientVerify<
                Fp3, aq::AirFriBackendAlg<Fp3>>(
                child_css[index], children[index],
                child_fs_seeds[index], &native_why)) {
            out.note =
                "stage3:recursive_fixedpoint:native_child[" +
                std::to_string(index) + "]:" + native_why;
            return out;
        }
        pis.push_back(
            ar::ExtractChildPublicInputs(
                child_css[index], children[index],
                child_fs_seeds[index]));
    }
    return BuildAcceptedHashOpeningWitnessMulti(pis, children);
}

HashOpeningWitness BuildDualV5HashOpeningWitness(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane)
{
    HashOpeningWitness out;
    if (lane >= kRCFri3AlgDualNumLanes) {
        out.note =
            "stage3:recursive_fixedpoint:dual_lane_range";
        return out;
    }
    std::string native_why;
    if (!aq::AirQuotientVerify<Fp3, ar::DualAlgB3>(
            child_cs, child, child_fs_seed,
            &native_why)) {
        out.note =
            "stage3:recursive_fixedpoint:dual_native_child:" +
            native_why;
        return out;
    }
    const Fri3AlgDualTranscriptWitness transcript =
        BuildFri3AlgDualTranscriptWitness(
            child.batch.repeated, child_fs_seed);
    if (!transcript.valid ||
        !transcript.common_statement_bound ||
        !transcript.ordered_lanes_bound) {
        out.note =
            "stage3:recursive_fixedpoint:dual_transcript:" +
            transcript.note;
        return out;
    }
    AlgAirProof view = DualLaneView(child, lane);
    if (view.next_openings.size() !=
            kRCFri3AlgDualQueriesPerLane) {
        out.note =
            "stage3:recursive_fixedpoint:dual_lane_openings";
        return out;
    }
    ar::ChildPublicInputs pi =
        ar::ExtractChildPublicInputs(
            child_cs, view, child_fs_seed);
    const auto& coefficients =
        transcript.lane[lane].batch_coefficients;
    if (coefficients.size() != pi.child_w + 1) {
        out.note =
            "stage3:recursive_fixedpoint:dual_lane_coefficients";
        return out;
    }
    pi.fri_batch_coefficients = coefficients;
    pi.independent_fri_batching = true;
    out = BuildAcceptedHashOpeningWitness(pi, view);
    if (out.valid) {
        out.note =
            "stage3:recursive_fixedpoint:dual_v5_proof_derived_"
            "hash_openings_ok";
    }
    return out;
}

HashOpeningWitness BuildDualV5HashOpeningWitnessAtBase(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t column_base)
{
    HashOpeningWitness out;
    if (lane >= kRCFri3AlgDualNumLanes) {
        out.note = "stage3:recursive_fixedpoint:dual_lane_range";
        return out;
    }
    std::string native_why;
    if (!aq::AirQuotientVerify<Fp3, ar::DualAlgB3>(
            child_cs, child, child_fs_seed, &native_why)) {
        out.note =
            "stage3:recursive_fixedpoint:dual_native_child:" +
            native_why;
        return out;
    }
    const Fri3AlgDualTranscriptWitness transcript =
        BuildFri3AlgDualTranscriptWitness(
            child.batch.repeated, child_fs_seed);
    if (!transcript.valid ||
        !transcript.common_statement_bound ||
        !transcript.ordered_lanes_bound) {
        out.note =
            "stage3:recursive_fixedpoint:dual_transcript:" +
            transcript.note;
        return out;
    }
    AlgAirProof view = DualLaneView(child, lane);
    if (view.next_openings.size() !=
            kRCFri3AlgDualQueriesPerLane) {
        out.note =
            "stage3:recursive_fixedpoint:dual_lane_openings";
        return out;
    }
    ar::ChildPublicInputs pi =
        ar::ExtractChildPublicInputs(
            child_cs, view, child_fs_seed);
    const auto& coefficients =
        transcript.lane[lane].batch_coefficients;
    if (coefficients.size() != pi.child_w + 1) {
        out.note =
            "stage3:recursive_fixedpoint:dual_lane_coefficients";
        return out;
    }
    pi.fri_batch_coefficients = coefficients;
    pi.independent_fri_batching = true;
    out = BuildAcceptedHashOpeningWitness(
        pi, view, column_base);
    if (out.valid) {
        out.note =
            "stage3:recursive_fixedpoint:dual_v5_proof_derived_"
            "hash_openings_at_base_ok";
    }
    return out;
}

uint32_t CountHashOpeningViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_row,
    std::string* first_constraint)
{
    return ar::CountWitnessViolationsOnH(
        cs, columns, first_row, first_constraint);
}

namespace {

FoldBusComposition BuildAcceptedFoldBusCompositionMulti(
    HashOpeningWitness hash,
    const std::vector<AlgAirProof>& proofs)
{
    FoldBusComposition out;
    out.hash = std::move(hash);
    if (!out.hash.valid) {
        out.note = out.hash.note;
        return out;
    }
    if (proofs.empty() ||
        out.hash.program.children.size() != proofs.size()) {
        out.note =
            "stage3:recursive_fixedpoint:multi_child_arity";
        return out;
    }
    aq::AirConstraintSystem<Fp3> hash_cs;
    std::string why;
    if (!BuildHashOpeningConstraintSystem(
            out.hash.program, hash_cs, &why,
            out.hash.column_base)) {
        out.note = why;
        return out;
    }
    const HashOpeningLayout hash_layout =
        HashOpeningLayoutAt(out.hash.column_base);
    out.bus = FoldBusLayout(hash_cs.n_columns);
    out.chain = FoldChainBusLayout(out.bus.End());
    out.deep = DeepInitialLayout(out.chain.End());
    out.combined = hash_cs;
    out.combined.n_columns = out.deep.End();
    out.columns.assign(
        out.combined.n_columns,
        std::vector<Fp3>(
            out.combined.n_rows, Fp3::Zero()));
    for (uint32_t column = 0;
         column < hash_cs.n_columns; ++column) {
        out.columns[column] = out.hash.columns[column];
    }

    const std::vector<ar::ChildPublicInputs>& pis =
        out.hash.program.children;
    const uint32_t arity =
        static_cast<uint32_t>(pis.size());

    // GLOBAL, DISJOINT bus address space. Child c's fold tuples occupy
    // [fold_base[c], fold_base[c+1]) and its chain tuples
    // [chain_base[c], chain_base[c+1]); no two children can alias one
    // another's addresses, so the multiset identities close once over the
    // whole node rather than per child.
    std::vector<uint64_t> fold_base(arity, 0);
    std::vector<uint64_t> chain_base(arity, 0);
    {
        uint64_t cursor = 1;
        for (uint32_t c = 0; c < arity; ++c) {
            fold_base[c] = cursor;
            cursor += 2 * uint64_t{pis[c].query_index.size()} *
                      pis[c].n_folds;
        }
        for (uint32_t c = 0; c < arity; ++c) {
            chain_base[c] = cursor;
            if (pis[c].n_folds == 0) {
                out.note =
                    "stage3:recursive_fixedpoint:deep_public_shape";
                return out;
            }
            cursor += uint64_t{pis[c].query_index.size()} *
                      (pis[c].n_folds - 1);
        }
    }
    auto address_of =
        [&](uint32_t child, uint32_t query, uint32_t layer,
            uint32_t side) {
            return fold_base[child] +
                2 * (uint64_t{query} * pis[child].n_folds +
                     layer) +
                side;
        };
    auto chain_address_of =
        [&](uint32_t child, uint32_t query,
            uint32_t prior_layer) {
            return chain_base[child] +
                uint64_t{query} * (pis[child].n_folds - 1) +
                prior_layer;
        };
    auto selected_fold_side =
        [&](uint32_t child, uint32_t query, uint32_t layer) {
            uint32_t reduced =
                pis[child].query_index[query];
            for (uint32_t prior = 0;
                 prior < layer; ++prior) {
                const uint32_t n_leaves =
                    pis[child].child_n_lde >> prior;
                reduced %= n_leaves / 2;
            }
            const uint32_t n_leaves =
                pis[child].child_n_lde >> layer;
            return static_cast<uint8_t>(
                reduced < n_leaves / 2 ? 1 : 2);
        };
    const Fp3 minus_one =
        Fp3::FromFp(gf::Neg(gf::FromU64(1)));
    const Fp3 u{0, 1, 0};
    const Fp3 u2{0, 0, 1};
    std::vector<std::vector<std::vector<Fp3>>> ux_weights(arity);
    std::vector<std::vector<Fp3>> deep_invd1(arity);
    std::vector<std::vector<Fp3>> deep_invd2(arity);
    std::vector<std::vector<Fp3>> deep_v1(arity);
    std::vector<std::vector<Fp3>> deep_v2(arity);
    uint64_t expected_chain_pairs = 0;
    uint64_t expected_final_rows = 0;
    uint64_t expected_deep_rows = 0;
    for (uint32_t c = 0; c < arity; ++c) {
    const ar::ChildPublicInputs& pi = pis[c];
    const uint32_t batch_width = pi.child_w + 1;
    if (pi.column_len.size() != batch_width ||
        pi.evals_z1.size() != batch_width ||
        pi.evals_z2.size() != batch_width ||
        pi.fold_challenges.size() != pi.n_folds) {
        out.note =
            "stage3:recursive_fixedpoint:deep_public_shape";
        return out;
    }
    expected_chain_pairs +=
        uint64_t{pi.query_index.size()} * (pi.n_folds - 1);
    expected_final_rows += pi.query_index.size();
    expected_deep_rows += pi.query_index.size();
    std::vector<Fp3> batch_coefficients(batch_width);
    if (!pi.fri_batch_coefficients.empty()) {
        if (pi.fri_batch_coefficients.size() != batch_width) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "deep_batch_coefficient_shape";
            return out;
        }
        batch_coefficients = pi.fri_batch_coefficients;
    } else {
        Fp3 power = Fp3::One();
        for (uint32_t item = 0;
             item < batch_width; ++item) {
            batch_coefficients[item] = power;
            power = gf::Mul(power, pi.fri_lambda);
        }
    }
    ux_weights[c].assign(
        pi.query_index.size(),
        std::vector<Fp3>(batch_width));
    deep_invd1[c].assign(pi.query_index.size(), Fp3::Zero());
    deep_invd2[c].assign(pi.query_index.size(), Fp3::Zero());
    deep_v1[c].assign(pi.query_index.size(), Fp3::Zero());
    deep_v2[c].assign(pi.query_index.size(), Fp3::Zero());
    for (uint32_t query = 0;
         query < pi.query_index.size(); ++query) {
        const Fp3 x =
            DomainPoint(pi.child_n_lde,
                        pi.query_index[query]);
        const Fp3 d1 = gf::Sub(x, pi.z1);
        const Fp3 d2 = gf::Sub(x, pi.z2);
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "deep_challenge_on_domain";
            return out;
        }
        // w already multiplied in; see DeepInitialLayout::w1_invd1.
        deep_invd1[c][query] = gf::Mul(pi.w1, gf::Inv(d1));
        deep_invd2[c][query] = gf::Mul(pi.w2, gf::Inv(d2));
        for (uint32_t item = 0;
             item < batch_width; ++item) {
            if (pi.column_len[item] >
                pi.child_n_coeffs) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "deep_column_length";
                return out;
            }
            const uint32_t shift =
                pi.child_n_coeffs - pi.column_len[item];
            ux_weights[c][query][item] =
                gf::Mul(
                    batch_coefficients[item],
                    PowFp3(x, shift));
            const Fp3 z1_weight =
                gf::Mul(
                    batch_coefficients[item],
                    PowFp3(pi.z1, shift));
            const Fp3 z2_weight =
                gf::Mul(
                    batch_coefficients[item],
                    PowFp3(pi.z2, shift));
            deep_v1[c][query] = gf::Add(
                deep_v1[c][query],
                gf::Mul(z1_weight, pi.evals_z1[item]));
            deep_v2[c][query] = gf::Add(
                deep_v2[c][query],
                gf::Mul(z2_weight, pi.evals_z2[item]));
        }
    }
    }
    // Per-row public pin of each child's terminal FRI value.
    for (uint32_t row = 0; row < out.combined.n_rows; ++row) {
        const uint32_t child =
            row < out.hash.program.rows.size()
                ? std::min(out.hash.program.rows[row].child,
                           arity - 1)
                : 0;
        out.columns[out.deep.child_final_value][row] =
            pis[child].final_value;
    }
    auto leaf_value =
        [&](uint32_t row) {
            return gf::Add(
                out.columns[
                    hash_layout.perm.InputCol(0)][row],
                gf::Add(
                    gf::Mul(
                        u,
                        out.columns[
                            hash_layout.perm.InputCol(1)][row]),
                    gf::Mul(
                        u2,
                        out.columns[
                            hash_layout.perm.InputCol(2)][row])));
        };

    uint32_t initial_deep_rows = 0;
    for (uint32_t row = 0;
         row < out.hash.program.active_rows; ++row) {
        const auto& meta =
            out.hash.program.rows[row];
        if (meta.child >= arity) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "deep_child_metadata";
            return out;
        }
        const uint32_t c = meta.child;
        const ar::ChildPublicInputs& pi = pis[c];
        const AlgAirProof& child = proofs[c];
        const uint32_t batch_width = pi.child_w + 1;
        if (meta.query >= pi.query_index.size()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "deep_query_metadata";
            return out;
        }
        if (meta.current_row_sponge) {
            for (uint32_t lane = 0;
                 lane < ah::kAlgHashRate; ++lane) {
                const uint32_t position =
                    meta.current_word_offset + lane;
                if (position >= 3 * batch_width) {
                    continue;
                }
                const uint32_t item = position / 3;
                const uint32_t coordinate = position % 3;
                Fp3 coefficient =
                    ux_weights[c][meta.query][item];
                if (coordinate == 1) {
                    coefficient =
                        gf::Mul(coefficient, u);
                } else if (coordinate == 2) {
                    coefficient =
                        gf::Mul(coefficient, u2);
                }
                out.columns[
                    out.deep.Coefficient(lane)][row] =
                    coefficient;
            }
        }
        if (meta.kind ==
                HashRowKind::SingleValueLeaf &&
            meta.fold_layer == 0 &&
            meta.fold_side ==
                selected_fold_side(c, meta.query, 0)) {
            out.columns[
                out.deep.identity_selector][row] =
                Fp3::One();
            out.columns[out.deep.w1_invd1][row] =
                deep_invd1[c][meta.query];
            out.columns[out.deep.w2_invd2][row] =
                deep_invd2[c][meta.query];
            out.columns[out.deep.v1][row] =
                deep_v1[c][meta.query];
            out.columns[out.deep.v2][row] =
                deep_v2[c][meta.query];
            ++initial_deep_rows;
        }
        if (meta.fold_terminal &&
            meta.fold_side == 2 &&
            meta.fold_layer + 1 == pi.n_folds) {
            out.columns[out.deep.reset_next][row] =
                Fp3::One();
        }
        if (meta.kind ==
                HashRowKind::SingleValueLeaf &&
            meta.fold_side != 0) {
            const uint32_t port = 0;
            out.columns[out.bus.Value(port)][row] =
                leaf_value(row);
            out.columns[out.bus.Address(port)][row] =
                Fp3::FromFp(gf::FromU64(address_of(
                    c, meta.query, meta.fold_layer,
                    meta.fold_side - 1)));
            out.columns[
                out.bus.Multiplicity(port)][row] =
                Fp3::One();
            out.columns[out.bus.Send(port)][row] =
                Fp3::One();
            if (meta.fold_layer > 0 &&
                meta.fold_side ==
                    selected_fold_side(
                        c, meta.query,
                        meta.fold_layer)) {
                out.columns[out.chain.value][row] =
                    leaf_value(row);
                out.columns[out.chain.address][row] =
                    Fp3::FromFp(gf::FromU64(
                        chain_address_of(
                            c, meta.query,
                            meta.fold_layer - 1)));
                out.columns[
                    out.chain.multiplicity][row] =
                    minus_one;
                out.columns[out.chain.receive][row] =
                    Fp3::One();
            }
        }
        if (meta.fold_terminal &&
            meta.fold_side == 2) {
            if (meta.query >= child.batch.queries.size() ||
                meta.fold_layer >=
                    child.batch.queries[meta.query].
                        steps.size()) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "fold_bus_metadata";
                return out;
            }
            const auto& step =
                child.batch.queries[meta.query].
                    steps[meta.fold_layer];
            out.columns[out.bus.consumer_even][row] =
                step.even;
            out.columns[out.bus.consumer_odd][row] =
                step.odd;
            for (uint32_t port = 0;
                 port < FoldBusLayout::kPorts; ++port) {
                out.columns[out.bus.Value(port)][row] =
                    port == 0 ? step.even : step.odd;
                out.columns[out.bus.Address(port)][row] =
                    Fp3::FromFp(gf::FromU64(address_of(
                        c, meta.query, meta.fold_layer,
                        port)));
                out.columns[
                    out.bus.Multiplicity(port)][row] =
                    minus_one;
                out.columns[
                    port == 0
                        ? out.bus.ReceiveEven(port)
                        : out.bus.ReceiveOdd(port)][row] =
                    Fp3::One();
            }
            const uint32_t n_leaves =
                pi.child_n_lde >> meta.fold_layer;
            const Fp3 x =
                DomainPoint(
                    n_leaves, step.even_index);
            const Fp3 beta =
                pi.fold_challenges[meta.fold_layer];
            const Fp3 inv2 =
                gf::Inv(Fp3::FromFp(gf::FromU64(2)));
            const Fp3 even_part =
                gf::Mul(
                    gf::Add(step.even, step.odd), inv2);
            const Fp3 odd_part =
                gf::Mul(
                    gf::Sub(step.even, step.odd),
                    gf::Mul(inv2, gf::Inv(x)));
            out.columns[out.bus.x][row] = x;
            out.columns[out.bus.beta][row] = beta;
            out.columns[out.bus.folded][row] =
                gf::Add(
                    even_part,
                    gf::Mul(beta, odd_part));
            if (meta.fold_layer + 1 < pi.n_folds) {
                out.columns[out.chain.value][row] =
                    out.columns[out.bus.folded][row];
                out.columns[out.chain.address][row] =
                    Fp3::FromFp(gf::FromU64(
                        chain_address_of(
                            c, meta.query,
                            meta.fold_layer)));
                out.columns[
                    out.chain.multiplicity][row] =
                    Fp3::One();
                out.columns[out.chain.send][row] =
                    Fp3::One();
                ++out.fold_chain_pairs;
            } else {
                out.columns[
                    out.chain.final_selector][row] =
                    Fp3::One();
                ++out.fold_final_rows;
            }
            ++out.fold_pairs;
        }
    }
    Fp3 deep_running = Fp3::Zero();
    for (uint32_t row = 0;
         row < out.combined.n_rows; ++row) {
        out.columns[out.deep.running][row] =
            deep_running;
        Fp3 contribution = Fp3::Zero();
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            contribution = gf::Add(
                contribution,
                gf::Mul(
                    out.columns[
                        out.deep.Coefficient(lane)][row],
                    out.columns[
                        hash_layout.absorbed_pin_base +
                        lane][row]));
        }
        if (!gf::IsZero(
                out.columns[out.deep.reset_next][row])) {
            deep_running = Fp3::Zero();
        } else {
            deep_running =
                gf::Add(deep_running, contribution);
        }
    }

    // Epoch 1: commit every bus tuple/value and scalar operand before
    // deriving rational-identity challenges.
    const std::array<uint32_t, 23> base_columns{
        out.bus.Value(0), out.bus.Address(0),
        out.bus.Multiplicity(0), out.bus.Send(0),
        out.bus.ReceiveEven(0), out.bus.ReceiveOdd(0),
        out.bus.Value(1), out.bus.Address(1),
        out.bus.Multiplicity(1), out.bus.Send(1),
        out.bus.ReceiveEven(1), out.bus.ReceiveOdd(1),
        out.bus.consumer_even, out.bus.consumer_odd,
        out.bus.x, out.bus.beta,
        out.chain.value, out.chain.address,
        out.chain.multiplicity, out.chain.send,
        out.chain.receive, out.bus.folded,
        out.chain.final_selector};
    std::vector<uint256> roots;
    roots.reserve(base_columns.size());
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_FIXEDPOINT_FOLD_BUS_PRECOMMIT_V1";
    precommit << out.combined.n_rows;
    precommit << out.fold_pairs;
    for (const uint32_t column : base_columns) {
        const uint256 root =
            aq::AirCommittedValuesRoot<Fp3>(
                out.columns[column],
                out.combined.n_rows);
        if (root.IsNull()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "fold_bus_precommit";
            return out;
        }
        roots.push_back(root);
        precommit << root;
    }
    out.prechallenge_commitment =
        precommit.GetHash();
    auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    out.prechallenge_commitment, label,
                    roots,
                    {out.combined.n_rows,
                     out.fold_pairs});
            return gf::FromChallengeBytes3(digest.data());
        };
    out.challenges.gamma1 =
        challenge("fold_bus_gamma1");
    out.challenges.gamma2 =
        challenge("fold_bus_gamma2");
    out.challenges.alpha1 =
        challenge("fold_bus_alpha1");
    out.challenges.alpha2 =
        challenge("fold_bus_alpha2");
    out.commit_then_challenge = true;

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    Fp3 chain_running1 = Fp3::Zero();
    Fp3 chain_running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < out.combined.n_rows; ++row) {
        out.columns[out.bus.running1][row] = running1;
        out.columns[out.bus.running2][row] = running2;
        for (uint32_t port = 0;
             port < FoldBusLayout::kPorts; ++port) {
            const Fp3 multiplicity =
                out.columns[
                    out.bus.Multiplicity(port)][row];
            if (gf::IsZero(multiplicity)) continue;
            const Fp3 value =
                out.columns[out.bus.Value(port)][row];
            const Fp3 address =
                out.columns[out.bus.Address(port)][row];
            const Fp3 key1 =
                gf::Add(
                    address,
                    gf::Mul(out.challenges.gamma1,
                            value));
            const Fp3 key2 =
                gf::Add(
                    address,
                    gf::Mul(out.challenges.gamma2,
                            value));
            const Fp3 denominator1 =
                gf::Sub(out.challenges.alpha1, key1);
            const Fp3 denominator2 =
                gf::Sub(out.challenges.alpha2, key2);
            if (gf::IsZero(denominator1) ||
                gf::IsZero(denominator2)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "fold_bus_challenge_pole";
                return out;
            }
            const Fp3 inverse1 = gf::Inv(denominator1);
            const Fp3 inverse2 = gf::Inv(denominator2);
            out.columns[
                out.bus.Inverse1(port)][row] =
                inverse1;
            out.columns[
                out.bus.Inverse2(port)][row] =
                inverse2;
            running1 = gf::Add(
                running1,
                gf::Mul(multiplicity, inverse1));
            running2 = gf::Add(
                running2,
                gf::Mul(multiplicity, inverse2));
        }
        out.columns[out.chain.running1][row] =
            chain_running1;
        out.columns[out.chain.running2][row] =
            chain_running2;
        const Fp3 chain_multiplicity =
            out.columns[out.chain.multiplicity][row];
        if (!gf::IsZero(chain_multiplicity)) {
            const Fp3 value =
                out.columns[out.chain.value][row];
            const Fp3 address =
                out.columns[out.chain.address][row];
            const Fp3 key1 = gf::Add(
                address,
                gf::Mul(out.challenges.gamma1, value));
            const Fp3 key2 = gf::Add(
                address,
                gf::Mul(out.challenges.gamma2, value));
            const Fp3 denominator1 =
                gf::Sub(out.challenges.alpha1, key1);
            const Fp3 denominator2 =
                gf::Sub(out.challenges.alpha2, key2);
            if (gf::IsZero(denominator1) ||
                gf::IsZero(denominator2)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "fold_chain_challenge_pole";
                return out;
            }
            const Fp3 inverse1 = gf::Inv(denominator1);
            const Fp3 inverse2 = gf::Inv(denominator2);
            out.columns[out.chain.inverse1][row] =
                inverse1;
            out.columns[out.chain.inverse2][row] =
                inverse2;
            chain_running1 = gf::Add(
                chain_running1,
                gf::Mul(chain_multiplicity, inverse1));
            chain_running2 = gf::Add(
                chain_running2,
                gf::Mul(chain_multiplicity, inverse2));
        }
    }

    // Immutable event schedule and public fold constants.
    const std::array<uint32_t, 12> preprocessed_columns{
        out.bus.Address(0), out.bus.Multiplicity(0),
        out.bus.Send(0), out.bus.ReceiveEven(0),
        out.bus.ReceiveOdd(0), out.bus.Address(1),
        out.bus.Multiplicity(1), out.bus.Send(1),
        out.bus.ReceiveEven(1), out.bus.ReceiveOdd(1),
        out.bus.x, out.bus.beta};
    for (const uint32_t column : preprocessed_columns) {
        out.combined.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    const std::array<uint32_t, 5>
        chain_preprocessed_columns{
            out.chain.address,
            out.chain.multiplicity,
            out.chain.send,
            out.chain.receive,
            out.chain.final_selector};
    for (const uint32_t column :
         chain_preprocessed_columns) {
        out.combined.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.combined.preprocessed.emplace_back(
        out.deep.reset_next,
        out.columns[out.deep.reset_next]);
    out.combined.preprocessed.emplace_back(
        out.deep.identity_selector,
        out.columns[out.deep.identity_selector]);
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        out.combined.preprocessed.emplace_back(
            out.deep.Coefficient(lane),
            out.columns[out.deep.Coefficient(lane)]);
    }
    const std::array<uint32_t, 5>
        deep_preprocessed_columns{
            out.deep.w1_invd1,
            out.deep.w2_invd2,
            out.deep.v1,
            out.deep.v2,
            out.deep.child_final_value};
    for (const uint32_t column :
         deep_preprocessed_columns) {
        out.combined.preprocessed.emplace_back(
            column, out.columns[column]);
    }

    auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            out.combined.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t port = 0;
         port < FoldBusLayout::kPorts; ++port) {
        add(
            "stage3.fixedpoint.fold_bus.inverse1",
            aq::AirKind::kEverywhere, 2,
            [bus = out.bus,
             challenges = out.challenges,
             port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 active =
                    gf::Add(
                        cur[bus.Send(port)],
                        gf::Add(
                            cur[bus.ReceiveEven(port)],
                            cur[bus.ReceiveOdd(port)]));
                const Fp3 key =
                    gf::Add(
                        cur[bus.Address(port)],
                        gf::Mul(
                            challenges.gamma1,
                            cur[bus.Value(port)]));
                return gf::Sub(
                    active,
                    gf::Mul(
                        cur[bus.Inverse1(port)],
                        gf::Sub(
                            challenges.alpha1, key)));
            });
        add(
            "stage3.fixedpoint.fold_bus.inverse2",
            aq::AirKind::kEverywhere, 2,
            [bus = out.bus,
             challenges = out.challenges,
             port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 active =
                    gf::Add(
                        cur[bus.Send(port)],
                        gf::Add(
                            cur[bus.ReceiveEven(port)],
                            cur[bus.ReceiveOdd(port)]));
                const Fp3 key =
                    gf::Add(
                        cur[bus.Address(port)],
                        gf::Mul(
                            challenges.gamma2,
                            cur[bus.Value(port)]));
                return gf::Sub(
                    active,
                    gf::Mul(
                        cur[bus.Inverse2(port)],
                        gf::Sub(
                            challenges.alpha2, key)));
            });
        add(
            "stage3.fixedpoint.fold_bus.send_alias",
            aq::AirKind::kEverywhere, 2,
            [bus = out.bus, hash_layout, port, u, u2](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 leaf =
                    gf::Add(
                        cur[
                            hash_layout.perm.InputCol(0)],
                        gf::Add(
                            gf::Mul(
                                u,
                                cur[hash_layout.perm.
                                        InputCol(1)]),
                            gf::Mul(
                                u2,
                                cur[hash_layout.perm.
                                        InputCol(2)])));
                return gf::Mul(
                    cur[bus.Send(port)],
                    gf::Sub(cur[bus.Value(port)],
                            leaf));
            });
        add(
            "stage3.fixedpoint.fold_bus.receive_even_alias",
            aq::AirKind::kEverywhere, 2,
            [bus = out.bus, port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[bus.ReceiveEven(port)],
                    gf::Sub(
                        cur[bus.Value(port)],
                        cur[bus.consumer_even]));
            });
        add(
            "stage3.fixedpoint.fold_bus.receive_odd_alias",
            aq::AirKind::kEverywhere, 2,
            [bus = out.bus, port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[bus.ReceiveOdd(port)],
                    gf::Sub(
                        cur[bus.Value(port)],
                        cur[bus.consumer_odd]));
            });
    }
    add(
        "stage3.fixedpoint.fold_bus.running1",
        aq::AirKind::kTransition, 2,
        [bus = out.bus](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            Fp3 contribution = Fp3::Zero();
            for (uint32_t port = 0;
                 port < FoldBusLayout::kPorts; ++port) {
                contribution = gf::Add(
                    contribution,
                    gf::Mul(
                        cur[bus.Multiplicity(port)],
                        cur[bus.Inverse1(port)]));
            }
            return gf::Sub(
                next[bus.running1],
                gf::Add(cur[bus.running1],
                        contribution));
        });
    add(
        "stage3.fixedpoint.fold_bus.running2",
        aq::AirKind::kTransition, 2,
        [bus = out.bus](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            Fp3 contribution = Fp3::Zero();
            for (uint32_t port = 0;
                 port < FoldBusLayout::kPorts; ++port) {
                contribution = gf::Add(
                    contribution,
                    gf::Mul(
                        cur[bus.Multiplicity(port)],
                        cur[bus.Inverse2(port)]));
            }
            return gf::Sub(
                next[bus.running2],
                gf::Add(cur[bus.running2],
                        contribution));
        });
    add(
        "stage3.fixedpoint.fold_bus.first1",
        aq::AirKind::kFirstRow, 1,
        [bus = out.bus](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[bus.running1];
        });
    add(
        "stage3.fixedpoint.fold_bus.first2",
        aq::AirKind::kFirstRow, 1,
        [bus = out.bus](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[bus.running2];
        });
    auto terminal =
        [bus = out.bus](bool lane1) {
            return [bus, lane1](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
                Fp3 sum =
                    cur[lane1 ? bus.running1
                              : bus.running2];
                for (uint32_t port = 0;
                     port < FoldBusLayout::kPorts;
                     ++port) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            cur[bus.Multiplicity(port)],
                            cur[lane1
                                    ? bus.Inverse1(port)
                                    : bus.Inverse2(port)]));
                }
                return sum;
            };
        };
    add(
        "stage3.fixedpoint.fold_bus.last1",
        aq::AirKind::kLastRow, 2, terminal(true));
    add(
        "stage3.fixedpoint.fold_bus.last2",
        aq::AirKind::kLastRow, 2, terminal(false));
    add(
        "stage3.fixedpoint.fold_chain.inverse1",
        aq::AirKind::kEverywhere, 2,
        [chain = out.chain,
         challenges = out.challenges](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            const Fp3 active =
                gf::Add(
                    cur[chain.send],
                    cur[chain.receive]);
            const Fp3 key =
                gf::Add(
                    cur[chain.address],
                    gf::Mul(
                        challenges.gamma1,
                        cur[chain.value]));
            return gf::Sub(
                active,
                gf::Mul(
                    cur[chain.inverse1],
                    gf::Sub(challenges.alpha1, key)));
        });
    add(
        "stage3.fixedpoint.fold_chain.inverse2",
        aq::AirKind::kEverywhere, 2,
        [chain = out.chain,
         challenges = out.challenges](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            const Fp3 active =
                gf::Add(
                    cur[chain.send],
                    cur[chain.receive]);
            const Fp3 key =
                gf::Add(
                    cur[chain.address],
                    gf::Mul(
                        challenges.gamma2,
                        cur[chain.value]));
            return gf::Sub(
                active,
                gf::Mul(
                    cur[chain.inverse2],
                    gf::Sub(challenges.alpha2, key)));
        });
    add(
        "stage3.fixedpoint.fold_chain.send_alias",
        aq::AirKind::kEverywhere, 2,
        [chain = out.chain, bus = out.bus](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[chain.send],
                gf::Sub(
                    cur[chain.value],
                    cur[bus.folded]));
        });
    add(
        "stage3.fixedpoint.fold_chain.receive_alias",
        aq::AirKind::kEverywhere, 2,
        [chain = out.chain, hash_layout, u, u2](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            const Fp3 leaf =
                gf::Add(
                    cur[
                        hash_layout.perm.InputCol(0)],
                    gf::Add(
                        gf::Mul(
                            u,
                            cur[hash_layout.perm.
                                    InputCol(1)]),
                        gf::Mul(
                            u2,
                            cur[hash_layout.perm.
                                    InputCol(2)])));
            return gf::Mul(
                cur[chain.receive],
                gf::Sub(cur[chain.value], leaf));
        });
    add(
        "stage3.fixedpoint.fold_chain.running1",
        aq::AirKind::kTransition, 2,
        [chain = out.chain](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            return gf::Sub(
                next[chain.running1],
                gf::Add(
                    cur[chain.running1],
                    gf::Mul(
                        cur[chain.multiplicity],
                        cur[chain.inverse1])));
        });
    add(
        "stage3.fixedpoint.fold_chain.running2",
        aq::AirKind::kTransition, 2,
        [chain = out.chain](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            return gf::Sub(
                next[chain.running2],
                gf::Add(
                    cur[chain.running2],
                    gf::Mul(
                        cur[chain.multiplicity],
                        cur[chain.inverse2])));
        });
    add(
        "stage3.fixedpoint.fold_chain.first1",
        aq::AirKind::kFirstRow, 1,
        [chain = out.chain](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[chain.running1];
        });
    add(
        "stage3.fixedpoint.fold_chain.first2",
        aq::AirKind::kFirstRow, 1,
        [chain = out.chain](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[chain.running2];
        });
    auto chain_terminal =
        [chain = out.chain](bool lane1) {
            return [chain, lane1](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
                return gf::Add(
                    cur[lane1
                            ? chain.running1
                            : chain.running2],
                    gf::Mul(
                        cur[chain.multiplicity],
                        cur[lane1
                                ? chain.inverse1
                                : chain.inverse2]));
            };
        };
    add(
        "stage3.fixedpoint.fold_chain.last1",
        aq::AirKind::kLastRow, 2,
        chain_terminal(true));
    add(
        "stage3.fixedpoint.fold_chain.last2",
        aq::AirKind::kLastRow, 2,
        chain_terminal(false));
    add(
        "stage3.fixedpoint.fold_chain.final",
        aq::AirKind::kEverywhere, 2,
        [chain = out.chain, bus = out.bus,
         deep = out.deep](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[chain.final_selector],
                gf::Sub(
                    cur[bus.folded],
                    cur[deep.child_final_value]));
        });
    add(
        "stage3.fixedpoint.fold_bus.equation",
        aq::AirKind::kEverywhere, 2,
        [bus = out.bus](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            const Fp3 lhs =
                gf::Mul(
                    gf::Mul(Fp3::FromFp(
                                gf::FromU64(2)),
                            cur[bus.x]),
                    cur[bus.folded]);
            const Fp3 rhs =
                gf::Add(
                    gf::Mul(
                        cur[bus.x],
                        gf::Add(
                            cur[bus.consumer_even],
                            cur[bus.consumer_odd])),
                    gf::Mul(
                        cur[bus.beta],
                        gf::Sub(
                            cur[bus.consumer_even],
                            cur[bus.consumer_odd])));
            return gf::Sub(lhs, rhs);
        });
    add(
        "stage3.fixedpoint.deep.initial_running",
        aq::AirKind::kTransition, 3,
        [deep = out.deep, hash_layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            Fp3 contribution = Fp3::Zero();
            for (uint32_t lane = 0;
                 lane < ah::kAlgHashRate; ++lane) {
                contribution = gf::Add(
                    contribution,
                    gf::Mul(
                        cur[deep.Coefficient(lane)],
                        cur[
                            hash_layout.absorbed_pin_base +
                            lane]));
            }
            const Fp3 accumulated =
                gf::Add(cur[deep.running], contribution);
            return gf::Sub(
                next[deep.running],
                gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[deep.reset_next]),
                    accumulated));
        });
    add(
        "stage3.fixedpoint.deep.initial_first",
        aq::AirKind::kFirstRow, 1,
        [deep = out.deep](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[deep.running];
        });
    add(
        "stage3.fixedpoint.deep.initial_identity",
        aq::AirKind::kEverywhere, 3,
        [deep = out.deep, hash_layout, u, u2](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            const Fp3 leaf =
                gf::Add(
                    cur[hash_layout.perm.InputCol(0)],
                    gf::Add(
                        gf::Mul(
                            u,
                            cur[
                                hash_layout.perm.InputCol(
                                    1)]),
                        gf::Mul(
                            u2,
                            cur[
                                hash_layout.perm.InputCol(
                                    2)])));
            const Fp3 expected =
                gf::Add(
                    gf::Mul(
                        gf::Sub(
                            cur[deep.running],
                            cur[deep.v1]),
                        cur[deep.w1_invd1]),
                    gf::Mul(
                        gf::Sub(
                            cur[deep.running],
                            cur[deep.v2]),
                        cur[deep.w2_invd2]));
            return gf::Mul(
                cur[deep.identity_selector],
                gf::Sub(leaf, expected));
        });

    out.violations =
        CountHashOpeningViolations(
            out.combined, out.columns);
    out.direct_hash_alias = true;
    out.dual_logup_terminal =
        gf::IsZero(running1) &&
        gf::IsZero(running2) &&
        gf::IsZero(chain_running1) &&
        gf::IsZero(chain_running2);
    out.fold_equations = true;
    // Totals over EVERY packed child; a missing child's rows cannot be hidden
    // behind another child's count.
    out.fold_chain_and_final_equations =
        out.fold_chain_pairs == expected_chain_pairs &&
        out.fold_final_rows == expected_final_rows;
    out.initial_deep_identity =
        initial_deep_rows == expected_deep_rows;
    out.deep_per_point_transition_join = false;
    out.valid =
        out.fold_pairs > 0 &&
        out.violations == 0 &&
        out.direct_hash_alias &&
        out.commit_then_challenge &&
        out.dual_logup_terminal &&
        out.fold_equations &&
        out.fold_chain_and_final_equations &&
        out.initial_deep_identity;
    out.note =
        out.valid
            ? "stage3:recursive_fixedpoint:fold_hash_"
              "scalar_dual_logup_chain_final_ok_"
              "initial_deep_ok_perpoint_open"
            : "stage3:recursive_fixedpoint:fold_bus_"
              "violation";
    return out;
}

} // namespace

FoldBusComposition BuildFoldBusComposition(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const AlgAirProof& child,
    const uint256& child_fs_seed)
{
    return BuildAcceptedFoldBusCompositionMulti(
        BuildHashOpeningWitness(
            child_cs, child, child_fs_seed),
        std::vector<AlgAirProof>{child});
}

FoldBusComposition BuildFoldBusCompositionMulti(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<AlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds)
{
    return BuildAcceptedFoldBusCompositionMulti(
        BuildHashOpeningWitnessMulti(
            child_css, children, child_fs_seeds),
        children);
}

FoldBusComposition BuildDualV5FoldBusComposition(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane)
{
    if (lane >= kRCFri3AlgDualNumLanes) {
        FoldBusComposition out;
        out.note =
            "stage3:recursive_fixedpoint:dual_fold_lane_range";
        return out;
    }
    AlgAirProof view = DualLaneView(child, lane);
    return BuildAcceptedFoldBusCompositionMulti(
        BuildDualV5HashOpeningWitness(
            child_cs, child, child_fs_seed, lane),
        std::vector<AlgAirProof>{view});
}

FoldBusComposition BuildDualV5FoldBusCompositionAtBase(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const ar::DualAlgAirProof& child,
    const uint256& child_fs_seed,
    uint32_t lane,
    uint32_t column_base)
{
    if (lane >= kRCFri3AlgDualNumLanes) {
        FoldBusComposition out;
        out.note =
            "stage3:recursive_fixedpoint:dual_fold_lane_range";
        return out;
    }
    AlgAirProof view = DualLaneView(child, lane);
    return BuildAcceptedFoldBusCompositionMulti(
        BuildDualV5HashOpeningWitnessAtBase(
            child_cs, child, child_fs_seed,
            lane, column_base),
        std::vector<AlgAirProof>{view});
}

uint64_t CountProgramTableInstructions(
    const constraint_bytecode::ProgramTable& table)
{
    uint64_t instructions = 0;
    for (const auto& program : table.programs) {
        instructions += program.instructions.size();
    }
    return instructions;
}

uint32_t CountFoldBusReservedSpongeRows(
    const FoldBusComposition& composition)
{
    if (!composition.valid || !composition.hash.valid ||
        composition.hash.program.rows.size() <
            composition.hash.program.active_rows) {
        return 0;
    }
    uint32_t reserved = 0;
    for (uint32_t row = 0;
         row < composition.hash.program.active_rows;
         ++row) {
        const auto& meta =
            composition.hash.program.rows[row];
        if (meta.current_row_sponge ||
            meta.next_row_sponge) {
            ++reserved;
        }
    }
    return reserved;
}

NarrowBytecodePerPointJoinBudgetV1
AssessNarrowBytecodePerPointJoinBudgetV1(
    const FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table)
{
    NarrowBytecodePerPointJoinBudgetV1 out;
    out.p2_fs_replay_closed =
        recursive_parent_air::AssessChildFsReplayClosureV1()
            .closed;
    if (!composition.valid ||
        !constraint_bytecode::ValidateProgramTable(
            table, nullptr)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_bytecode_join_budget_base_invalid";
        return out;
    }
    const auto& pi =
        composition.hash.program.public_inputs;
    out.fold_bus_columns = composition.combined.n_columns;
    out.fold_bus_rows = composition.combined.n_rows;
    out.reserved_sponge_rows =
        CountFoldBusReservedSpongeRows(composition);
    out.free_rows =
        out.fold_bus_rows > out.reserved_sponge_rows
            ? out.fold_bus_rows - out.reserved_sponge_rows
            : 0;
    out.bytecode_added_columns =
        BytecodeBusLayout(out.fold_bus_columns).End() -
        out.fold_bus_columns;
    out.projected_columns =
        out.fold_bus_columns + out.bytecode_added_columns;
    // Narrow family stays well under 1024 columns (575-col
    // multi-child measurement + ~65 bytecode ports).
    out.projected_columns_narrow =
        out.fold_bus_columns < 1024U &&
        out.projected_columns < 1024U;
    out.queries =
        static_cast<uint32_t>(pi.query_index.size());
    out.instructions = CountProgramTableInstructions(table);
    out.rows_needed =
        uint64_t{out.queries} * (out.instructions + 1U);
    out.rows_fit_without_pad =
        out.rows_needed <= out.free_rows;
    const uint64_t deficit =
        out.rows_fit_without_pad
            ? 0
            : (out.rows_needed - out.free_rows);
    const uint64_t min_rows =
        uint64_t{out.fold_bus_rows} + deficit;
    // Use the same quotient-degree-derived FRI shape as the executable
    // narrow backend.  `trace_rows * blowup` is only exact for a degree-2
    // Everywhere relation; this parent has the measured degree-3 V_CS.
    const nr::NarrowNodeFriShape fri_shape =
        nr::AssessNarrowNodeFriShape(
            min_rows, out.projected_columns);
    out.projected_trace_rows = fri_shape.trace_rows;
    out.projected_max_algebraic_degree =
        fri_shape.max_algebraic_degree;
    out.projected_quotient_len = fri_shape.quotient_len;
    out.projected_coefficient_rows = fri_shape.n_coeffs;
    out.projected_lde = fri_shape.n_lde;
    out.exact_quotient_degree_accounting =
        fri_shape.trace_rows != 0 &&
        fri_shape.max_algebraic_degree != 0 &&
        fri_shape.quotient_len != 0 &&
        fri_shape.n_coeffs != 0 &&
        fri_shape.n_lde != 0;
    if (!out.exact_quotient_degree_accounting) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_bytecode_join_budget_domain_overflow";
        return out;
    }
    out.projected_lde_supported =
        fri_shape.fits_lde_cap;
    out.capacity_closed =
        !out.rows_fit_without_pad &&
        !out.projected_lde_supported;

    out.single_node_fri_representable = fri_shape.representable;

    // Hierarchical attach: reuse blk planner so one 575-col node is not
    // required to absorb the full LDE-over-cap pad.
    const NarrowBytecodeHierarchicalAttachPlanV1 hier =
        PlanNarrowBytecodeHierarchicalAttachV1(
            table, out.queries);
    out.hierarchical_attach_planned =
        hier.valid || hier.hierarchical_fits ||
        hier.single_node_fits;
    out.hierarchical_attach_fits =
        hier.hierarchical_fits || hier.single_node_fits;
    out.hierarchical_depth = hier.depth;
    out.hierarchical_node_count = hier.node_count;
    out.hierarchical_single_level_rows = hier.total_leaf_rows;

    out.valid =
        out.projected_columns_narrow &&
        out.queries > 0 &&
        out.instructions > 0 &&
        out.rows_needed > 0 &&
        out.exact_quotient_degree_accounting;
    out.note =
        out.valid
            ? (std::string(
                   "stage3:recursive_fixedpoint:"
                   "narrow_bytecode_join_budget") +
               ";fold_cols=" +
               std::to_string(out.fold_bus_columns) +
               ";fold_rows=" +
               std::to_string(out.fold_bus_rows) +
               ";free=" + std::to_string(out.free_rows) +
               ";bytecode_cols=" +
               std::to_string(out.bytecode_added_columns) +
               ";projected_cols=" +
               std::to_string(out.projected_columns) +
               ";queries=" + std::to_string(out.queries) +
               ";instructions=" +
               std::to_string(out.instructions) +
               ";needed=" +
               std::to_string(out.rows_needed) +
               ";projected_rows=" +
               std::to_string(out.projected_trace_rows) +
               ";max_degree=" +
               std::to_string(
                   out.projected_max_algebraic_degree) +
               ";quotient_len=" +
               std::to_string(out.projected_quotient_len) +
               ";coefficient_rows=" +
               std::to_string(
                   out.projected_coefficient_rows) +
               ";projected_lde=" +
               std::to_string(out.projected_lde) +
               (out.rows_fit_without_pad
                    ? ";fits_free"
                    : ";needs_pad") +
               (out.projected_lde_supported
                    ? ";lde_ok"
                    : ";lde_over_cap") +
               (out.single_node_fri_representable
                    ? ";fri_ok"
                    : ";fri_over_cap") +
               (out.p2_fs_replay_closed
                    ? ";p2_fs_closed"
                    : ";p2_fs_open") +
               (out.capacity_closed
                    ? ";capacity_closed"
                    : ";join_representable_if_padded") +
               ";hier_fits=" +
               (out.hierarchical_attach_fits ? "1" : "0") +
               ";hier_depth=" +
               std::to_string(out.hierarchical_depth) +
               ";hier_nodes=" +
               std::to_string(out.hierarchical_node_count) +
               ";hier_leaf_rows=" +
               std::to_string(
                   out.hierarchical_single_level_rows) +
               ";complete_fp=false")
            : "stage3:recursive_fixedpoint:"
              "narrow_bytecode_join_budget_invalid";
    return out;
}

std::vector<nr::NarrowHierarchyLeaf>
BuildNarrowBytecodeHierarchyLeaves(
    const constraint_bytecode::ProgramTable& table,
    uint32_t queries)
{
    std::vector<nr::NarrowHierarchyLeaf> leaves;
    if (queries == 0) return leaves;
    leaves.reserve(table.programs.size());
    for (uint32_t i = 0; i < table.programs.size(); ++i) {
        nr::NarrowHierarchyLeaf leaf;
        leaf.role_index = i;
        leaf.name = "bytecode:program:" + std::to_string(i);
        const uint64_t insn = static_cast<uint64_t>(
            table.programs[i].instructions.size());
        // Conservative per-program attach cost (matches shard attach).
        leaf.active_rows = uint64_t{queries} * (insn + 1U);
        leaf.child_w = table.current_width;
        leaves.push_back(std::move(leaf));
    }
    return leaves;
}

NarrowBytecodeHierarchicalAttachPlanV1
PlanNarrowBytecodeHierarchicalAttachV1(
    const constraint_bytecode::ProgramTable& table,
    uint32_t queries,
    const nr::NarrowHierarchyPlanConfig& config)
{
    NarrowBytecodeHierarchicalAttachPlanV1 out;
    out.queries = queries;
    out.program_count =
        static_cast<uint32_t>(table.programs.size());
    out.instructions = CountProgramTableInstructions(table);
    if (queries == 0 || table.programs.empty() ||
        !constraint_bytecode::ValidateProgramTable(
            table, nullptr)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_hier_attach_input_invalid";
        return out;
    }
    const auto leaves =
        BuildNarrowBytecodeHierarchyLeaves(table, queries);
    if (leaves.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_hier_attach_empty_leaves";
        return out;
    }
    for (const auto& leaf : leaves) {
        out.total_leaf_rows += leaf.active_rows;
    }
    // Bytecode programs are tiny vs episode-role children. Disable the
    // soft arity-4 preference so first-fit packs by LDE row budget; the
    // episode six-role planner keeps preferred_max_children=4 separately.
    nr::NarrowHierarchyPlanConfig attach_config = config;
    if (attach_config.preferred_max_children == 4) {
        attach_config.preferred_max_children = 0;
    }
    out.single_node_shape = nr::AssessNarrowNodeFriShape(
        out.total_leaf_rows,
        attach_config.vcs_columns,
        attach_config.max_algebraic_degree,
        attach_config.lde_log2_cap,
        attach_config.column_cap);
    out.single_node_fits = out.single_node_shape.representable;

    out.hierarchy = nr::PlanHierarchicalNarrowAggregation(
        leaves, attach_config);
    out.hierarchical_fits = out.hierarchy.hierarchical_fits;
    out.all_programs_covered =
        out.hierarchy.all_leaves_covered;
    out.node_count = out.hierarchy.node_count;
    out.depth = out.hierarchy.depth;
    // Accept single-level or multi-level closure under budgets.
    out.valid = out.hierarchical_fits &&
                out.all_programs_covered &&
                out.hierarchy.node_count > 0;
    out.note =
        out.valid
            ? (std::string(
                   "stage3:recursive_fixedpoint:"
                   "bytecode_hier_attach") +
               ";programs=" +
               std::to_string(out.program_count) +
               ";queries=" + std::to_string(out.queries) +
               ";instructions=" +
               std::to_string(out.instructions) +
               ";leaf_rows=" +
               std::to_string(out.total_leaf_rows) +
               ";single_fits=" +
               (out.single_node_fits ? "1" : "0") +
               ";hier_fits=" +
               (out.hierarchical_fits ? "1" : "0") +
               ";depth=" + std::to_string(out.depth) +
               ";nodes=" + std::to_string(out.node_count) +
               ";single_lde=" +
               std::to_string(out.single_node_shape.n_lde) +
               ";complete_fp=false")
            : (std::string(
                   "stage3:recursive_fixedpoint:"
                   "bytecode_hier_attach_failed:") +
               out.hierarchy.note);
    return out;
}

bool SliceProgramTableByLeafIndices(
    const constraint_bytecode::ProgramTable& table,
    const std::vector<uint32_t>& leaf_indices,
    constraint_bytecode::ProgramTable& out,
    std::string* why)
{
    out = constraint_bytecode::ProgramTable{};
    out.version = table.version;
    out.role = table.role;
    out.current_width = table.current_width;
    out.next_width = table.next_width;
    out.challenge_width = table.challenge_width;
    out.programs.reserve(leaf_indices.size());
    for (uint32_t idx : leaf_indices) {
        if (idx >= table.programs.size()) {
            return Fail(why, "bytecode_hier_shard_leaf_oob");
        }
        out.programs.push_back(table.programs[idx]);
        // ValidateProgramTable requires constraint_ordinal == table index.
        out.programs.back().constraint_ordinal =
            static_cast<uint32_t>(out.programs.size() - 1);
    }
    if (!constraint_bytecode::ValidateProgramTable(out, why)) {
        return false;
    }
    return true;
}

bool PrepareFoldBusForBytecodeShard(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& full_table,
    const std::vector<uint32_t>& leaf_indices,
    const constraint_bytecode::ProgramTable& shard_table,
    FoldBusComposition& out,
    std::string* why)
{
    if (!base.valid || leaf_indices.empty() ||
        leaf_indices.size() != shard_table.programs.size()) {
        return Fail(why, "bytecode_hier_shard_prepare_input");
    }
    out = base;
    auto& pi = out.hash.program.public_inputs;
    if (pi.child_constraints.size() != full_table.programs.size()) {
        return Fail(why, "bytecode_hier_shard_full_table_mismatch");
    }
    std::vector<aq::AirConstraint<Fp3>> sliced;
    sliced.reserve(leaf_indices.size());
    for (size_t i = 0; i < leaf_indices.size(); ++i) {
        const uint32_t idx = leaf_indices[i];
        if (idx >= pi.child_constraints.size() ||
            idx >= full_table.programs.size()) {
            return Fail(why, "bytecode_hier_shard_constraint_oob");
        }
        if (full_table.programs[idx].kind !=
                pi.child_constraints[idx].kind ||
            full_table.programs[idx].declared_degree !=
                pi.child_constraints[idx].alg_degree ||
            shard_table.programs[i].kind !=
                full_table.programs[idx].kind ||
            shard_table.programs[i].declared_degree !=
                full_table.programs[idx].declared_degree) {
            return Fail(why, "bytecode_hier_shard_metadata");
        }
        sliced.push_back(pi.child_constraints[idx]);
    }
    pi.child_constraints = std::move(sliced);
    if (!out.hash.program.children.empty()) {
        out.hash.program.children.front().child_constraints =
            pi.child_constraints;
    }
    const uint32_t queries =
        static_cast<uint32_t>(pi.query_index.size());
    const uint64_t rows_needed =
        uint64_t{queries} *
        (CountProgramTableInstructions(shard_table) + 1U);
    // Extending n_rows after fold-bus challenge derivation rebinds
    // committed column roots. Only accept shards that fit free rows.
    const uint32_t reserved =
        CountFoldBusReservedSpongeRows(out);
    const uint32_t free =
        out.combined.n_rows > reserved
            ? out.combined.n_rows - reserved
            : 0;
    if (rows_needed > free) {
        return Fail(
            why,
            "bytecode_hier_shard_needs_pad;needed=" +
                std::to_string(rows_needed) +
                ";free=" + std::to_string(free) +
                ";pad_after_challenge_forbidden");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "bytecode_hier_shard_fits_free;needed=" +
            std::to_string(rows_needed) +
            ";free=" + std::to_string(free);
    }
    return true;
}

namespace {

std::vector<std::vector<uint32_t>>
PackBytecodeShardsUnderFreeRows(
    const constraint_bytecode::ProgramTable& table,
    uint32_t queries,
    uint64_t free_rows)
{
    std::vector<std::vector<uint32_t>> bins;
    if (queries == 0 || free_rows == 0 || table.programs.empty()) {
        return bins;
    }
    std::vector<uint32_t> order(table.programs.size());
    for (uint32_t i = 0; i < order.size(); ++i) order[i] = i;
    std::stable_sort(
        order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
            const auto sa = table.programs[a].instructions.size();
            const auto sb = table.programs[b].instructions.size();
            if (sa != sb) return sa > sb;
            return a < b;
        });
    struct Bin {
        std::vector<uint32_t> leaves;
        uint64_t instructions{0};
    };
    std::vector<Bin> packed;
    for (uint32_t leaf : order) {
        const uint64_t insn = static_cast<uint64_t>(
            table.programs[leaf].instructions.size());
        if (uint64_t{queries} * (insn + 1U) > free_rows) {
            return {};
        }
        bool placed = false;
        for (Bin& bin : packed) {
            const uint64_t candidate = bin.instructions + insn;
            if (uint64_t{queries} * (candidate + 1U) <= free_rows) {
                bin.leaves.push_back(leaf);
                bin.instructions = candidate;
                placed = true;
                break;
            }
        }
        if (!placed) {
            packed.push_back(Bin{{leaf}, insn});
        }
    }
    bins.reserve(packed.size());
    for (auto& bin : packed) {
        std::sort(bin.leaves.begin(), bin.leaves.end());
        bins.push_back(std::move(bin.leaves));
    }
    return bins;
}

bool RejectBytecodeShardForgery(
    const FoldBusComposition& honest)
{
    if (!honest.valid || honest.columns.empty() ||
        honest.combined.n_rows == 0 ||
        honest.combined.n_columns == 0) {
        return false;
    }
    const uint32_t bytecode_width = BytecodeBusLayout(0).End();
    if (honest.combined.n_columns < bytecode_width) {
        return false;
    }
    const BytecodeBusLayout bus(
        honest.combined.n_columns - bytecode_width);
    uint32_t target_row = 0;
    bool found = false;
    for (uint32_t row = 0; row < honest.combined.n_rows; ++row) {
        if (!gf::IsZero(honest.columns[bus.Active(0)][row]) ||
            !gf::IsZero(
                honest.columns[bus.result_selector][row])) {
            target_row = row;
            found = true;
            break;
        }
    }
    if (!found) target_row = 0;
    // Exactly one witness cell changes. An AIR constraint can observe it only
    // as `current` on target_row or as `next` on the preceding row (including
    // the wrap used by first/last-row constraints). Rebuilding a full witness
    // copy and scanning every row here used O(N*C*W) work and duplicated the
    // multi-gigabyte L1 witness before the real proof. Evaluate precisely the
    // two affected row pairs instead.
    const uint32_t n_rows = honest.combined.n_rows;
    const uint32_t n_columns = honest.combined.n_columns;
    const uint32_t value_column = bus.Value(0);
    const std::array<uint32_t, 2> affected_rows{
        target_row, (target_row + n_rows - 1) % n_rows};
    std::vector<Fp3> current(n_columns);
    std::vector<Fp3> next(n_columns);
    for (size_t affected = 0; affected < affected_rows.size(); ++affected) {
        const uint32_t row = affected_rows[affected];
        if (affected != 0 && row == affected_rows[0]) continue;
        const uint32_t next_row = (row + 1) % n_rows;
        for (uint32_t column = 0; column < n_columns; ++column) {
            current[column] = honest.columns[column][row];
            next[column] = honest.columns[column][next_row];
        }
        if (row == target_row) {
            current[value_column] =
                gf::Add(current[value_column], Fp3::One());
        }
        if (next_row == target_row) {
            next[value_column] =
                gf::Add(next[value_column], Fp3::One());
        }
        for (const auto& constraint : honest.combined.constraints) {
            bool applies = true;
            if (constraint.kind == aq::AirKind::kTransition) {
                applies = row + 1 < n_rows;
            } else if (constraint.kind == aq::AirKind::kFirstRow) {
                applies = row == 0;
            } else if (constraint.kind == aq::AirKind::kLastRow) {
                applies = row + 1 == n_rows;
            }
            if (applies &&
                !gf::IsZero(constraint.eval(current, next))) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

namespace {

bool FailJoin(std::string* why, const char* code)
{
    if (why != nullptr) *why = code;
    return false;
}

} // namespace

bool ExtractAuthenticatedParentQuotientOpenings(
    const FoldBusComposition& base,
    uint32_t current_width,
    std::vector<Fp3>& out_per_query,
    std::string* why)
{
    out_per_query.clear();
    if (!base.valid || base.columns.empty() ||
        base.hash.program.rows.empty() ||
        current_width == 0) {
        return FailJoin(
            why,
            "stage3:recursive_fixedpoint:"
            "bytecode_parent_q_input");
    }
    const uint32_t queries = static_cast<uint32_t>(
        base.hash.program.public_inputs.query_index.size());
    if (queries == 0) {
        return FailJoin(
            why,
            "stage3:recursive_fixedpoint:"
            "bytecode_parent_q_no_queries");
    }
    const HashOpeningLayout hash_layout =
        HashOpeningLayoutAt(base.hash.column_base);
    if (base.combined.n_columns <=
        hash_layout.absorbed_pin_base + ah::kAlgHashRate) {
        return FailJoin(
            why,
            "stage3:recursive_fixedpoint:"
            "bytecode_parent_q_layout");
    }
    const Fp3 u{0, 1, 0};
    const Fp3 u2{0, 0, 1};
    std::vector<std::array<Fp3, 3>> coords(queries);
    std::vector<std::array<bool, 3>> seen(queries);
    for (uint32_t row = 0;
         row < base.hash.program.active_rows &&
         row < base.hash.program.rows.size();
         ++row) {
        const auto& meta = base.hash.program.rows[row];
        if (!meta.current_row_sponge) continue;
        for (uint32_t lane = 0; lane < ah::kAlgHashRate;
             ++lane) {
            const uint32_t position =
                meta.current_word_offset + lane;
            // Quotient occupies items [current_width] limbs 0..2.
            const uint32_t width_items = current_width + 1U;
            if (position >= 3U * width_items) continue;
            const uint32_t item = position / 3U;
            const uint32_t coordinate = position % 3U;
            if (item != current_width) continue;
            if (meta.query >= queries || coordinate >= 3U) {
                return FailJoin(
                    why,
                    "stage3:recursive_fixedpoint:"
                    "bytecode_parent_q_oob");
            }
            coords[meta.query][coordinate] =
                base.columns[hash_layout.absorbed_pin_base +
                             lane][row];
            seen[meta.query][coordinate] = true;
        }
    }
    out_per_query.assign(queries, Fp3::Zero());
    for (uint32_t q = 0; q < queries; ++q) {
        if (!seen[q][0] || !seen[q][1] || !seen[q][2]) {
            return FailJoin(
                why,
                "stage3:recursive_fixedpoint:"
                "bytecode_parent_q_missing");
        }
        out_per_query[q] = gf::Add(
            coords[q][0],
            gf::Add(
                gf::Mul(u, coords[q][1]),
                gf::Mul(u2, coords[q][2])));
    }
    return true;
}

bool ExtractShardLocalQuotientOpenings(
    const FoldBusComposition& shard_bus,
    std::vector<Fp3>& out_per_query,
    std::string* why)
{
    out_per_query.clear();
    if (!shard_bus.valid || shard_bus.columns.empty()) {
        return FailJoin(
            why,
            "stage3:recursive_fixedpoint:"
            "bytecode_local_q_input");
    }
    const uint32_t bytecode_width = BytecodeBusLayout(0).End();
    if (shard_bus.combined.n_columns < bytecode_width) {
        return FailJoin(
            why,
            "stage3:recursive_fixedpoint:"
            "bytecode_local_q_no_bus");
    }
    const BytecodeBusLayout bus(
        shard_bus.combined.n_columns - bytecode_width);
    // InterpreterRowKind::Quotient == 8 (see attach impl).
    constexpr uint32_t kQuotientKind = 8;
    const uint32_t queries = static_cast<uint32_t>(
        shard_bus.hash.program.public_inputs.query_index
            .size());
    out_per_query.reserve(queries);
    for (uint32_t row = 0; row < shard_bus.combined.n_rows;
         ++row) {
        if (gf::IsZero(
                shard_bus.columns[bus.RowKind(kQuotientKind)]
                                 [row])) {
            continue;
        }
        out_per_query.push_back(
            shard_bus.columns[bus.Value(3)][row]);
    }
    if (queries == 0 || out_per_query.size() != queries) {
        return FailJoin(
            why,
            "stage3:recursive_fixedpoint:"
            "bytecode_local_q_count");
    }
    return true;
}

NarrowBytecodeShardQuotientJoinAirMirrorV1
AirMirrorNarrowBytecodeShardLocalQuotientsV1(
    const std::vector<Fp3>& bound_q_per_query,
    const std::vector<std::vector<Fp3>>& shard_local_q,
    bool absolute_parent_bound)
{
    NarrowBytecodeShardQuotientJoinAirMirrorV1 out;
    out.absolute_parent_bound = absolute_parent_bound;
    out.shard_count =
        static_cast<uint32_t>(shard_local_q.size());
    if (bound_q_per_query.empty() ||
        shard_local_q.size() < 2) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_air_input";
        return out;
    }
    const uint32_t queries =
        static_cast<uint32_t>(bound_q_per_query.size());
    out.queries = queries;
    for (const auto& shard : shard_local_q) {
        if (shard.size() != queries) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_q_join_air_query_mismatch";
            return out;
        }
    }
    // Residual identity check before proving.
    for (uint32_t q = 0; q < queries; ++q) {
        Fp3 sum = Fp3::Zero();
        for (const auto& shard : shard_local_q) {
            sum = gf::Add(sum, shard[q]);
        }
        if (!gf::IsZero(gf::Sub(sum, bound_q_per_query[q]))) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_q_join_air_bound_mismatch";
            return out;
        }
    }

    const uint32_t n_rows = NextPow2(queries);
    const uint32_t n_columns =
        1U + static_cast<uint32_t>(shard_local_q.size());
    if (n_rows < 2 || n_columns < 3) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_air_shape";
        return out;
    }
    out.n_rows = n_rows;
    out.n_columns = n_columns;

    aq::AirConstraintSystem<Fp3> cs;
    cs.n_rows = n_rows;
    cs.n_columns = n_columns;
    const uint32_t shard_count = out.shard_count;
    cs.constraints.push_back(
        {"bytecode_q_join_sum_eq_bound",
         aq::AirKind::kEverywhere,
         /*alg_degree=*/1,
         [shard_count](
             const std::vector<Fp3>& cur,
             const std::vector<Fp3>&) {
             Fp3 sum = Fp3::Zero();
             for (uint32_t s = 0; s < shard_count; ++s) {
                 sum = gf::Add(sum, cur[1U + s]);
             }
             return gf::Sub(sum, cur[0]);
         }});

    std::vector<std::vector<Fp3>> columns(
        n_columns, std::vector<Fp3>(n_rows, Fp3::Zero()));
    for (uint32_t q = 0; q < queries; ++q) {
        columns[0][q] = bound_q_per_query[q];
        for (uint32_t s = 0; s < shard_count; ++s) {
            columns[1U + s][q] = shard_local_q[s][q];
        }
    }
    // Padding rows: bound = 0 and shards = 0 keep the residual zero.
    cs.preprocessed_pin_ood = true;
    for (uint32_t column = 0; column < n_columns; ++column) {
        cs.preprocessed.emplace_back(column, columns[column]);
    }
    out.operands_preprocessed =
        cs.preprocessed.size() == n_columns;

    HashWriter seed_hash;
    seed_hash <<
        "BTX_RC_STAGE3_BYTECODE_Q_JOIN_AIR_MIRROR_V1";
    seed_hash << queries;
    seed_hash << shard_count;
    seed_hash << n_rows;
    seed_hash << static_cast<uint8_t>(
        absolute_parent_bound ? 1 : 0);
    for (uint32_t q = 0; q < queries; ++q) {
        seed_hash << gf::Canonical(bound_q_per_query[q].c0);
        seed_hash << gf::Canonical(bound_q_per_query[q].c1);
        seed_hash << gf::Canonical(bound_q_per_query[q].c2);
        for (uint32_t s = 0; s < shard_count; ++s) {
            seed_hash << gf::Canonical(shard_local_q[s][q].c0);
            seed_hash << gf::Canonical(shard_local_q[s][q].c1);
            seed_hash << gf::Canonical(shard_local_q[s][q].c2);
        }
    }
    const uint256 seed = seed_hash.GetHash();

    const auto proved =
        aq::AirQuotientProve<Fp3>(cs, columns, seed);
    out.proved = proved.ok && proved.division_exact;
    if (!out.proved) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_air_prove:" +
            proved.note;
        return out;
    }

    std::string verify_why;
    const auto t0 = std::chrono::steady_clock::now();
    out.verified = aq::AirQuotientVerify<Fp3>(
        cs, proved.proof, seed, &verify_why);
    const auto t1 = std::chrono::steady_clock::now();
    out.verify_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t1 - t0)
            .count());
    if (!out.verified) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_air_verify:" +
            verify_why;
        return out;
    }

    // Forgery 1: mutate shard-0 at query 0; honest residual must break.
    auto forged = columns;
    forged[1][0] = gf::Add(forged[1][0], Fp3::One());
    const auto forged_proved =
        aq::AirQuotientProve<Fp3>(cs, forged, seed);
    const bool forged_ok =
        forged_proved.ok && forged_proved.division_exact;
    bool forged_verified = false;
    if (forged_ok) {
        std::string forged_why;
        forged_verified = aq::AirQuotientVerify<Fp3>(
            cs, forged_proved.proof, seed, &forged_why);
    }
    out.forgery_rejected = !forged_ok || !forged_verified;
    // Forgery 2: preserve the sum with +delta/-delta.  This defeats the
    // residual by itself and is rejected only because every operand is a
    // verifier-owned preprocessed column in the ORIGINAL constraint system.
    auto compensated = columns;
    compensated[1][0] =
        gf::Add(compensated[1][0], Fp3::One());
    compensated[2][0] =
        gf::Sub(compensated[2][0], Fp3::One());
    const auto compensated_proved =
        aq::AirQuotientProve<Fp3>(
            cs, compensated, seed);
    bool compensated_verified = false;
    if (compensated_proved.ok &&
        compensated_proved.division_exact) {
        std::string compensated_why;
        compensated_verified =
            aq::AirQuotientVerify<Fp3>(
                cs, compensated_proved.proof,
                seed, &compensated_why);
    }
    out.compensated_forgery_rejected =
        !compensated_proved.ok ||
        !compensated_proved.division_exact ||
        !compensated_verified;
    out.valid =
        out.proved && out.verified &&
        out.operands_preprocessed &&
        out.forgery_rejected &&
        out.compensated_forgery_rejected;
    out.note =
        std::string(
            "stage3:recursive_fixedpoint:bytecode_q_join_air") +
        ";shards=" + std::to_string(out.shard_count) +
        ";queries=" + std::to_string(out.queries) +
        ";rows=" + std::to_string(out.n_rows) +
        ";cols=" + std::to_string(out.n_columns) +
        ";abs=" + (out.absolute_parent_bound ? "1" : "0") +
        ";proved=" + (out.proved ? "1" : "0") +
        ";verified=" + (out.verified ? "1" : "0") +
        ";preprocessed=" +
        (out.operands_preprocessed ? "1" : "0") +
        ";forgery=" + (out.forgery_rejected ? "1" : "0") +
        ";compensated_forgery=" +
        (out.compensated_forgery_rejected ? "1" : "0") +
        ";verify_us=" + std::to_string(out.verify_micros) +
        ";complete_fp=false";
    return out;
}

NarrowBytecodeShardCompositionAirProveV1
AirProveNarrowBytecodeShardCompositionV1(
    const FoldBusComposition& attached_shard)
{
    NarrowBytecodeShardCompositionAirProveV1 out;
    out.streaming = true;
    if (!attached_shard.valid ||
        attached_shard.columns.empty() ||
        attached_shard.combined.n_rows < 2 ||
        attached_shard.combined.n_columns < 3 ||
        attached_shard.columns.size() !=
            attached_shard.combined.n_columns) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_prove_input";
        return out;
    }
    for (const auto& column : attached_shard.columns) {
        if (column.size() != attached_shard.combined.n_rows) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_shard_air_prove_column_len";
            return out;
        }
    }
    out.attached = true;
    out.n_rows = attached_shard.combined.n_rows;
    out.n_columns = attached_shard.combined.n_columns;
    out.n_constraints = static_cast<uint32_t>(
        attached_shard.combined.constraints.size());

    HashWriter seed_hash;
    seed_hash <<
        "BTX_RC_STAGE3_BYTECODE_SHARD_COMPOSITION_AIR_V1";
    seed_hash << out.n_rows;
    seed_hash << out.n_columns;
    seed_hash << out.n_constraints;
    seed_hash << attached_shard.prechallenge_commitment;
    const uint256 seed = seed_hash.GetHash();

    const auto t0 = std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRows(
        attached_shard.combined, attached_shard.columns, seed,
        {});
    const auto t1 = std::chrono::steady_clock::now();
    out.prove_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t1 - t0)
            .count());
    out.proved = proved.ok && proved.division_exact;
    if (!out.proved) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_prove:" +
            proved.note;
        return out;
    }

    std::string verify_why;
    const auto t2 = std::chrono::steady_clock::now();
    out.verified = aq::AirQuotientVerifyRows(
        attached_shard.combined, proved.proof, seed,
        &verify_why);
    const auto t3 = std::chrono::steady_clock::now();
    out.verify_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t3 - t2)
            .count());
    if (!out.verified) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_verify:" +
            verify_why;
        return out;
    }

    // Retain the exact L1 artifact needed by the next recursive level.
    // A boolean "proved" label is not a child proof: canonical bytes are
    // decoded and re-entered into the unmodified verifier before this result
    // can be consumed by an L2 parent.
    out.constraint_system = attached_shard.combined;
    out.fs_seed = seed;
    // AirQuotientProveRows uses the streaming-row backend.  Its wire proof
    // has the same canonical fields as AlgAirProof, but the C++ template
    // specializations are intentionally distinct types.  Copy the wire
    // fields explicitly, as the L2 path below already does, so the retained
    // artifact is verifier/backend independent.
    out.proof.batch = proved.proof.batch;
    out.proof.trace_commit = proved.proof.trace_commit;
    out.proof.next_openings = proved.proof.next_openings;
    std::string codec_why;
    if (!SerializeAirQuotientProofAlg(
            out.proof, out.proof_bytes, &codec_why) ||
        out.proof_bytes.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_codec:" + codec_why;
        return out;
    }
    const auto decoded =
        DeserializeAirQuotientProofAlg(
            out.proof_bytes, &codec_why);
    std::vector<unsigned char> canonical;
    if (!decoded.has_value() ||
        !SerializeAirQuotientProofAlg(
            *decoded, canonical, &codec_why) ||
        canonical != out.proof_bytes) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_roundtrip:" + codec_why;
        return out;
    }
    out.canonical_whole_proof_codec = true;
    out.proof_commitment =
        ComputeNormalizedAlgAirProofCommitment(*decoded);
    out.proof_retained =
        !out.proof_commitment.IsNull();
    std::string retained_why;
    out.retained_proof_reverified =
        out.proof_retained &&
        aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            out.constraint_system, *decoded, out.fs_seed,
            &retained_why);
    if (!out.retained_proof_reverified) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_retained_verify:" +
            retained_why;
        return out;
    }

    // Two independent negative checks, without constructing a second
    // production-sized proof:
    //   (1) the exact affected-row evaluator exhibits that a live bytecode
    //       witness mutation violates the AIR; and
    //   (2) the real FRI/AIR verifier rejects a mutated opening in the proof
    //       it just accepted.  The latter is the proof-level rejection gate.
    const bool witness_mutation_violates =
        RejectBytecodeShardForgery(attached_shard);
    bool proof_tamper_rejected = false;
    if (!proved.proof.batch.queries.empty() &&
        !proved.proof.batch.queries[0].steps.empty()) {
        auto tampered = proved.proof;
        tampered.batch.queries[0].steps[0].even =
            gf::Add(
                tampered.batch.queries[0].steps[0].even,
                Fp3::One());
        std::string forged_why;
        proof_tamper_rejected =
            !aq::AirQuotientVerifyRows(
                attached_shard.combined, tampered, seed,
                &forged_why);
    }
    // The fold-bus-only canary has no bytecode lane to mutate; the production
    // shard does.  In both cases the security gate is the proof-level verifier
    // rejection.  The affected-row result remains separately reported as
    // relation-specific negative evidence.
    out.forgery_rejected = proof_tamper_rejected;
    out.valid =
        out.attached && out.proved && out.verified &&
        out.forgery_rejected && out.proof_retained &&
        out.canonical_whole_proof_codec &&
        out.retained_proof_reverified;
    out.note =
        std::string(
            "stage3:recursive_fixedpoint:bytecode_shard_air") +
        ";rows=" + std::to_string(out.n_rows) +
        ";cols=" + std::to_string(out.n_columns) +
        ";cons=" + std::to_string(out.n_constraints) +
        ";programs=" + std::to_string(out.program_count) +
        ";shard=" + std::to_string(out.shard_index) +
        ";proved=" + (out.proved ? "1" : "0") +
        ";verified=" + (out.verified ? "1" : "0") +
        ";forgery=" + (out.forgery_rejected ? "1" : "0") +
        ";proof_tamper=" +
        (proof_tamper_rejected ? "1" : "0") +
        ";retained=1;roundtrip=1;reverified=1" +
        ";witness_mutation=" +
        (witness_mutation_violates ? "1" : "0") +
        ";stream=" + (out.streaming ? "1" : "0") +
        ";prove_us=" + std::to_string(out.prove_micros) +
        ";verify_us=" + std::to_string(out.verify_micros) +
        ";complete_fp=false";
    return out;
}

NarrowBytecodeShardCompositionAirProveV1
ExecuteNarrowBytecodeOneFreeRowShardCompositionAirProveV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    uint32_t shard_index)
{
    NarrowBytecodeShardCompositionAirProveV1 out;
    if (!base.valid ||
        !constraint_bytecode::ValidateProgramTable(
            table, nullptr)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_exec_input";
        return out;
    }
    const uint32_t queries = static_cast<uint32_t>(
        base.hash.program.public_inputs.query_index.size());
    const uint32_t reserved =
        CountFoldBusReservedSpongeRows(base);
    const uint64_t free_rows =
        base.combined.n_rows > reserved
            ? uint64_t{base.combined.n_rows - reserved}
            : 0;
    const auto shard_groups =
        PackBytecodeShardsUnderFreeRows(table, queries, free_rows);
    if (shard_groups.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_exec_no_free_row_shards;free=" +
            std::to_string(free_rows);
        return out;
    }
    if (shard_index != UINT32_MAX &&
        shard_index >= shard_groups.size()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_exec_shard_index";
        return out;
    }

    // UINT32_MAX (default): smallest free-row shard by program count.
    // In-range index selects that pack bin explicitly.
    uint32_t pick = 0;
    for (uint32_t i = 1; i < shard_groups.size(); ++i) {
        if (shard_groups[i].size() < shard_groups[pick].size()) {
            pick = i;
        }
    }
    if (shard_index != UINT32_MAX) {
        pick = shard_index;
    }
    out.shard_index = pick;
    out.program_count =
        static_cast<uint32_t>(shard_groups[pick].size());

    constraint_bytecode::ProgramTable shard;
    std::string why;
    if (!SliceProgramTableByLeafIndices(
            table, shard_groups[pick], shard, &why)) {
        out.note = why;
        return out;
    }
    FoldBusComposition shard_bus;
    if (!PrepareFoldBusForBytecodeShard(
            base, table, shard_groups[pick], shard, shard_bus,
            &why)) {
        out.note = why;
        return out;
    }
    const BytecodeInterpreterAttachment att =
        AttachConstraintBytecodeInterpreterShard(
            shard_bus, shard, shard_groups[pick]);
    if (!att.valid) {
        out.note = att.note;
        return out;
    }
    if (!RejectBytecodeShardForgery(shard_bus)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_air_exec_host_forgery";
        return out;
    }

    out = AirProveNarrowBytecodeShardCompositionV1(shard_bus);
    out.shard_index = pick;
    out.program_count =
        static_cast<uint32_t>(shard_groups[pick].size());
    if (out.valid) {
        out.note =
            out.note + ";free_shards=" +
            std::to_string(shard_groups.size()) +
            ";free_rows=" + std::to_string(free_rows);
    }
    return out;
}

NarrowMultiChildL2FriConsumeV1
ExecuteNarrowMultiChildL2FriConsumeV1(
    const std::vector<aq::AirConstraintSystem<Fp3>>& child_css,
    const std::vector<AlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    bool prove,
    const uint256& parent_context_binding)
{
    NarrowMultiChildL2FriConsumeV1 out;
    out.arity = static_cast<uint32_t>(children.size());
    out.parent_context_binding = parent_context_binding;
    if (child_css.size() != children.size() ||
        child_fs_seeds.size() != children.size() ||
        children.size() < 2) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume_arity";
        return out;
    }

    // Cryptographic join: BuildFoldBusCompositionMulti packs ≥2 L1 proofs
    // into one narrow V_CS (zero column expansion). Distinct from host Σ
    // local_q / AIR-mirror of openings.
    const FoldBusComposition node =
        BuildFoldBusCompositionMulti(
            child_css, children, child_fs_seeds);
    out.fold_bus_built = node.valid;
    if (!node.valid) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume_fold_bus:" +
            node.note;
        return out;
    }
    out.n_rows = node.combined.n_rows;
    out.n_columns = node.combined.n_columns;
    out.n_constraints = static_cast<uint32_t>(
        node.combined.constraints.size());
    for (const auto& constraint : node.combined.constraints) {
        switch (constraint.kind) {
        case aq::AirKind::kEverywhere:
            ++out.everywhere_constraints;
            break;
        case aq::AirKind::kTransition:
            ++out.transition_constraints;
            break;
        case aq::AirKind::kFirstRow:
            ++out.first_row_constraints;
            break;
        case aq::AirKind::kLastRow:
            ++out.last_row_constraints;
            break;
        }
    }
    out.active_rows =
        node.hash.valid
            ? uint64_t{node.hash.program.active_rows}
            : uint64_t{node.combined.n_rows};

    out.fri_shape = nr::AssessNarrowNodeFriShape(out.active_rows);
    out.n_lde = out.fri_shape.n_lde;
    out.fri_shape_representable = out.fri_shape.representable;
    if (!out.fri_shape_representable) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume_shape:" +
            out.fri_shape.note;
        return out;
    }

    // Forgery: mutate one live limb of child[1]; native fold-bus must refuse
    // before any L2 witness is built.
    {
        auto forged_children = children;
        bool mutated = false;
        if (!forged_children[1].batch.queries.empty() &&
            !forged_children[1].batch.queries[0].row.values
                 .empty()) {
            forged_children[1].batch.queries[0].row.values[0] =
                gf::Add(
                    forged_children[1]
                        .batch.queries[0]
                        .row.values[0],
                    Fp3::One());
            mutated = true;
        }
        if (!mutated) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "multi_child_l2_fri_consume_forgery_no_limb";
            return out;
        }
        const FoldBusComposition forged_node =
            BuildFoldBusCompositionMulti(
                child_css, forged_children, child_fs_seeds);
        out.forgery_rejected = !forged_node.valid;
        if (!out.forgery_rejected) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "multi_child_l2_fri_consume_forgery_accepted";
            return out;
        }
    }

    if (!prove) {
        out.valid =
            out.fold_bus_built && out.fri_shape_representable &&
            out.forgery_rejected;
        out.note =
            std::string(
                "stage3:recursive_fixedpoint:"
                "multi_child_l2_fri_consume") +
            ";arity=" + std::to_string(out.arity) +
            ";rows=" + std::to_string(out.n_rows) +
            ";cols=" + std::to_string(out.n_columns) +
            ";active=" + std::to_string(out.active_rows) +
            ";n_lde=" + std::to_string(out.n_lde) +
            ";shape=1;fold=1;forgery=1;prove=0" +
            ";complete_fp=false";
        return out;
    }

    const uint256 parent_seed =
        ComputeNarrowMultiChildParentFsSeedV1(
            node, child_fs_seeds, parent_context_binding);
    if (parent_seed.IsNull()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume_seed";
        return out;
    }
    out.parent_fs_seed = parent_seed;

    const auto t0 = std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRows(
        node.combined, node.columns, parent_seed, {});
    const auto t1 = std::chrono::steady_clock::now();
    out.prove_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t1 - t0)
            .count());
    out.proved = proved.ok && proved.division_exact;
    if (!out.proved) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume_prove:" +
            proved.note;
        return out;
    }

    std::string verify_why;
    const auto t2 = std::chrono::steady_clock::now();
    // Query checks are independent.  OpenMP builds use their native parallel
    // loop; portable builds use the backend's deterministic thread fallback.
    // Both paths preserve the exact ordered proof statement and bytes.
    constexpr uint32_t kRootVerifyThreads = 16;
    out.verified = aq::AirQuotientVerify<
        Fp3, aq::AirFriBackendAlgStreamingRows>(
        node.combined, proved.proof, parent_seed,
        &verify_why, kRootVerifyThreads);
    const auto t3 = std::chrono::steady_clock::now();
    out.verify_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t3 - t2)
            .count());
    if (!out.verified) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume_verify:" +
            verify_why;
        return out;
    }
    if (std::getenv(
            "BTX_STAGE3_G2_VERIFY_PHASE_TIMING") != nullptr) {
        std::string batch_why;
        const auto batch_t0 =
            std::chrono::steady_clock::now();
        out.standalone_batch_verify_ok =
            aq::AirFriBackendAlgStreamingRows::
                BatchVerify(
                    proved.proof.batch, parent_seed,
                    &batch_why);
        const auto batch_t1 =
            std::chrono::steady_clock::now();
        out.standalone_batch_verify_micros =
            static_cast<uint64_t>(
                std::chrono::duration_cast<
                    std::chrono::microseconds>(
                    batch_t1 - batch_t0).count());
        if (!out.standalone_batch_verify_ok) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "standalone_batch_verify:" +
                batch_why;
            return out;
        }
    }

    out.parent_proof.batch = proved.proof.batch;
    out.parent_proof.trace_commit =
        proved.proof.trace_commit;
    out.parent_proof.next_openings =
        proved.proof.next_openings;
    std::string codec_why;
    if (!SerializeAirQuotientProofAlg(
            out.parent_proof, out.parent_proof_bytes,
            &codec_why) ||
        out.parent_proof_bytes.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_parent_codec:" + codec_why;
        return out;
    }
    const auto decoded =
        DeserializeAirQuotientProofAlg(
            out.parent_proof_bytes, &codec_why);
    std::vector<unsigned char> reencoded;
    out.canonical_whole_proof_codec =
        decoded.has_value() &&
        SerializeAirQuotientProofAlg(
            *decoded, reencoded, &codec_why) &&
        reencoded == out.parent_proof_bytes &&
        aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            node.combined, *decoded, parent_seed,
            &codec_why);
    if (!out.canonical_whole_proof_codec) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_parent_codec_roundtrip:" +
            codec_why;
        return out;
    }
    HashWriter proof_hash;
    proof_hash <<
        "BTX_RC_STAGE3_MULTI_CHILD_L2_PARENT_PROOF_V1";
    proof_hash <<
        static_cast<uint64_t>(
            out.parent_proof_bytes.size());
    proof_hash << out.parent_proof_bytes;
    out.parent_proof_commitment = proof_hash.GetHash();
    out.parent_proof_retained =
        !out.parent_proof_commitment.IsNull();
    out.parent_constraint_system = node.combined;
    std::string reentry_why;
    out.parent_reentry_verified =
        aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            out.parent_constraint_system,
            out.parent_proof,
            out.parent_fs_seed,
            &reentry_why);
    if (!out.parent_reentry_verified) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_parent_reentry:" +
            reentry_why;
        return out;
    }
    HashWriter statement_hash;
    statement_hash <<
        "BTX_RC_STAGE3_MULTI_CHILD_L2_PARENT_STATEMENT_V1";
    statement_hash << out.arity;
    statement_hash << out.n_rows;
    statement_hash << out.n_columns;
    statement_hash << out.n_constraints;
    statement_hash << out.active_rows;
    statement_hash << out.n_lde;
    statement_hash << node.prechallenge_commitment;
    if (!parent_context_binding.IsNull()) {
        statement_hash <<
            "BTX_RC_STAGE3_MULTI_CHILD_L2_BOUND_CONTEXT_V1";
        statement_hash << parent_context_binding;
    }
    statement_hash << out.parent_fs_seed;
    for (const auto& child_seed : child_fs_seeds) {
        statement_hash << child_seed;
    }
    statement_hash << out.parent_proof_commitment;
    out.parent_statement_commitment =
        statement_hash.GetHash();
    if (out.parent_statement_commitment.IsNull()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_parent_statement";
        return out;
    }

    // Proof-level tamper of the retained parent itself. This is distinct
    // from the earlier child-forgery check.
    auto tampered_parent = out.parent_proof;
    bool tampered = false;
    if (!tampered_parent.batch.queries.empty() &&
        !tampered_parent.batch.queries[0]
             .row.values.empty()) {
        tampered_parent.batch.queries[0]
            .row.values[0] =
            gf::Add(
                tampered_parent.batch.queries[0]
                    .row.values[0],
                Fp3::One());
        tampered = true;
    }
    if (!tampered) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_parent_tamper_no_limb";
        return out;
    }
    std::string tamper_why;
    out.parent_proof_tamper_rejected =
        !aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            node.combined, tampered_parent,
            parent_seed, &tamper_why);
    if (!out.parent_proof_tamper_rejected) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_parent_tamper_accepted";
        return out;
    }

    // Family-root WIRE serialize — NOT an Extract/Builder engine receipt.
    // g2's serialize conjunct gates on this path's SerializeFri3AlgBatchProof
    // size against kRCFriMaxProofBytesHard (~16 MiB).
    {
        std::vector<unsigned char> batch;
        const size_t batch_bytes =
            SerializeFri3AlgBatchProof(proved.proof.batch, batch);
        out.serialize_batch_bytes = static_cast<uint64_t>(batch_bytes);
        out.serialize_root_bytes =
            static_cast<uint64_t>(
                out.parent_proof_bytes.size());
    }
    constexpr uint64_t kRelayBudgetUs = 900ULL * 1000ULL;
    out.verify_within_relay_budget =
        out.verify_micros != 0 &&
        out.verify_micros <= kRelayBudgetUs;
    out.serialize_within_fri_budget =
        out.serialize_root_bytes != 0 &&
        out.serialize_root_bytes <=
            static_cast<uint64_t>(kRCFriMaxProofBytesHard);

    out.cryptographically_valid =
        out.fold_bus_built && out.fri_shape_representable &&
        out.proved && out.verified && out.forgery_rejected &&
        out.parent_proof_tamper_rejected &&
        out.parent_proof_retained &&
        out.canonical_whole_proof_codec &&
        out.parent_reentry_verified &&
        !out.parent_statement_commitment.IsNull();
    out.valid =
        out.cryptographically_valid &&
        out.verify_within_relay_budget &&
        out.serialize_within_fri_budget;
    out.note =
        std::string(
            "stage3:recursive_fixedpoint:"
            "multi_child_l2_fri_consume") +
        ";arity=" + std::to_string(out.arity) +
        ";rows=" + std::to_string(out.n_rows) +
        ";cols=" + std::to_string(out.n_columns) +
        ";cons=" + std::to_string(out.n_constraints) +
        ";active=" + std::to_string(out.active_rows) +
        ";n_lde=" + std::to_string(out.n_lde) +
        ";shape=1;fold=1;proved=1;verified=1;forgery=1" +
        ";parent_tamper=1;proof_retained=1;codec=1;reentry=1" +
        ";prove_us=" + std::to_string(out.prove_micros) +
        ";verify_us=" + std::to_string(out.verify_micros) +
        ";batch_bytes=" +
        std::to_string(out.serialize_batch_bytes) +
        ";root_bytes=" +
        std::to_string(out.serialize_root_bytes) +
        (out.verify_within_relay_budget
             ? ";verify_within_budget"
             : ";verify_OVER_BUDGET") +
        (out.serialize_within_fri_budget
             ? ";serialize_within_fri"
             : ";serialize_OVER_FRI") +
        ";complete_fp=false";
    return out;
}

NarrowBytecodeRealL1L2ConsumeV1
ExecuteNarrowBytecodeRealL1L2ConsumeV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    const std::vector<uint32_t>& shard_indices,
    bool prove_l2,
    const uint256& parent_context_binding)
{
    NarrowBytecodeRealL1L2ConsumeV1 out;
    out.shard_indices = shard_indices;
    out.l1_count =
        static_cast<uint32_t>(shard_indices.size());
    if (!base.valid ||
        !constraint_bytecode::ValidateProgramTable(
            table, nullptr) ||
        shard_indices.size() < 2) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_real_l1_l2_input";
        return out;
    }

    // Reusing a shard in two child slots would make the hierarchy look
    // complete while omitting a distinct portion of the program table.
    // Reject duplicates before performing any expensive proving work.
    std::vector<uint32_t> sorted_indices = shard_indices;
    std::sort(sorted_indices.begin(), sorted_indices.end());
    if (std::adjacent_find(
            sorted_indices.begin(), sorted_indices.end()) !=
        sorted_indices.end()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_real_l1_l2_duplicate_shard";
        return out;
    }

    out.l1_proofs.reserve(shard_indices.size());
    std::vector<aq::AirConstraintSystem<Fp3>> child_css;
    std::vector<AlgAirProof> child_proofs;
    std::vector<uint256> child_seeds;
    child_css.reserve(shard_indices.size());
    child_proofs.reserve(shard_indices.size());
    child_seeds.reserve(shard_indices.size());
    for (const uint32_t shard_index : shard_indices) {
        NarrowBytecodeShardCompositionAirProveV1 l1 =
            ExecuteNarrowBytecodeOneFreeRowShardCompositionAirProveV1(
                base, table, shard_index);
        if (!l1.valid || !l1.proof_retained ||
            !l1.canonical_whole_proof_codec ||
            !l1.retained_proof_reverified ||
            l1.fs_seed.IsNull() ||
            l1.proof_commitment.IsNull() ||
            l1.proof_bytes.empty()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_real_l1_l2_l1:" + l1.note;
            return out;
        }
        child_css.push_back(l1.constraint_system);
        child_proofs.push_back(l1.proof);
        child_seeds.push_back(l1.fs_seed);
        out.l1_proofs.push_back(std::move(l1));
    }
    out.every_l1_proof_retained =
        out.l1_proofs.size() == shard_indices.size();
    out.every_l1_proof_reverified =
        std::all_of(
            out.l1_proofs.begin(), out.l1_proofs.end(),
            [](const auto& l1) {
                return l1.retained_proof_reverified;
            });
    // This path has no BooleanChildProof or synthetic "accepted" witness:
    // the vectors passed below came only from retained, canonical proofs
    // produced by the bytecode-shard composition prover above.
    out.no_boolean_standins =
        out.every_l1_proof_retained &&
        out.every_l1_proof_reverified;

    out.l2 = ExecuteNarrowMultiChildL2FriConsumeV1(
        child_css, child_proofs, child_seeds, prove_l2,
        parent_context_binding);
    out.l2_consumed_exact_l1_proofs =
        out.no_boolean_standins &&
        out.l2.fold_bus_built &&
        (!prove_l2 || out.l2.cryptographically_valid);
    // A shape-only invocation is useful for sizing, but it is never a
    // completed recursive proof construction.
    out.valid =
        prove_l2 &&
        out.every_l1_proof_retained &&
        out.every_l1_proof_reverified &&
        out.no_boolean_standins &&
        out.l2_consumed_exact_l1_proofs &&
        out.l2.cryptographically_valid;
    out.note =
        std::string(
            "stage3:recursive_fixedpoint:"
            "bytecode_real_l1_l2") +
        ";l1=" + std::to_string(out.l1_count) +
        ";retained=" +
        (out.every_l1_proof_retained ? "1" : "0") +
        ";reverified=" +
        (out.every_l1_proof_reverified ? "1" : "0") +
        ";standins=0" +
        ";l2_exact=" +
        (out.l2_consumed_exact_l1_proofs ? "1" : "0") +
        ";l2_crypto=" +
        (out.l2.cryptographically_valid ? "1" : "0") +
        ";prove_l2=" + (prove_l2 ? "1" : "0") +
        ";universal_root_only_open=1";
    return out;
}

uint256 ComputeNarrowMultiChildParentFsSeedV1(
    const FoldBusComposition& node,
    const std::vector<uint256>& child_fs_seeds,
    const uint256& parent_context_binding)
{
    if (!node.valid || child_fs_seeds.size() < 2 ||
        node.combined.n_rows < 2 ||
        node.combined.n_columns == 0 ||
        node.combined.constraints.empty() ||
        node.prechallenge_commitment.IsNull()) {
        return {};
    }
    for (const uint256& seed : child_fs_seeds) {
        if (seed.IsNull()) return {};
    }
    HashWriter seed_hash;
    seed_hash << "BTX_RC_STAGE3_MULTI_CHILD_L2_FRI_CONSUME_V1";
    seed_hash << static_cast<uint32_t>(child_fs_seeds.size());
    seed_hash << node.combined.n_rows;
    seed_hash << node.combined.n_columns;
    seed_hash <<
        static_cast<uint32_t>(node.combined.constraints.size());
    seed_hash << node.prechallenge_commitment;
    if (!parent_context_binding.IsNull()) {
        seed_hash <<
            "BTX_RC_STAGE3_MULTI_CHILD_L2_BOUND_CONTEXT_V1";
        seed_hash << parent_context_binding;
    }
    for (const auto& seed : child_fs_seeds) {
        seed_hash << seed;
    }
    return seed_hash.GetHash();
}

namespace {

uint256 CommitNarrowProofBytesV1(
    const std::vector<unsigned char>& proof_bytes)
{
    if (proof_bytes.empty()) return {};
    HashWriter proof_hash;
    proof_hash <<
        "BTX_RC_STAGE3_MULTI_CHILD_L2_PARENT_PROOF_V1";
    proof_hash <<
        static_cast<uint64_t>(proof_bytes.size());
    proof_hash << proof_bytes;
    return proof_hash.GetHash();
}

uint256 DeriveRetainedParentContextV1(
    const std::vector<NarrowRecursiveProofReceiptV1>& children,
    const uint256& parent_node_binding)
{
    if (children.size() < 2 || parent_node_binding.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_NARROW_RETAINED_PARENT_CONTEXT_V1";
    hash << parent_node_binding;
    hash << static_cast<uint32_t>(children.size());
    for (uint32_t slot = 0; slot < children.size(); ++slot) {
        if (children[slot].receipt_commitment.IsNull() ||
            children[slot].program_binding.IsNull()) {
            return {};
        }
        hash << slot;
        hash << children[slot].node_binding;
        hash << children[slot].program_binding;
        hash << children[slot].receipt_commitment;
    }
    return hash.GetHash();
}

} // namespace

uint256 ComputeNarrowRetainedParentContextV1(
    const std::vector<NarrowRecursiveProofReceiptV1>& children,
    const uint256& parent_node_binding,
    const uint256& parent_program_binding)
{
    if (parent_program_binding.IsNull()) return {};
    const uint256 child_context =
        DeriveRetainedParentContextV1(
            children, parent_node_binding);
    if (child_context.IsNull()) return {};
    HashWriter program_hash;
    program_hash <<
        "BTX_RC_STAGE3_NARROW_RETAINED_PARENT_PROGRAM_V1";
    program_hash << child_context;
    program_hash << parent_program_binding;
    return program_hash.GetHash();
}

uint256 CommitNarrowRecursiveProofReceiptV1(
    const NarrowRecursiveProofReceiptV1& receipt)
{
    if (receipt.version !=
            kNarrowRecursiveProofReceiptVersionV1 ||
        receipt.node_binding.IsNull() ||
        receipt.program_binding.IsNull() ||
        receipt.proof_context_binding.IsNull() ||
        receipt.n_rows < 2 || receipt.n_columns == 0 ||
        receipt.n_constraints == 0 || receipt.active_rows == 0 ||
        receipt.n_lde == 0 ||
        receipt.constraint_system_commitment.IsNull() ||
        receipt.fs_seed.IsNull() ||
        receipt.proof_commitment.IsNull() ||
        receipt.statement_commitment.IsNull() ||
        receipt.proof_bytes.empty()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_NARROW_RECURSIVE_PROOF_RECEIPT_V1";
    hash << receipt.version;
    hash << receipt.node_binding;
    hash << receipt.program_binding;
    hash << receipt.proof_context_binding;
    hash << receipt.n_rows;
    hash << receipt.n_columns;
    hash << receipt.n_constraints;
    hash << receipt.active_rows;
    hash << receipt.n_lde;
    hash << receipt.constraint_system_commitment;
    hash << receipt.fs_seed;
    hash << receipt.proof_commitment;
    hash << receipt.statement_commitment;
    hash << static_cast<uint64_t>(receipt.proof_bytes.size());
    return hash.GetHash();
}

NarrowRecursiveProofReceiptV1
RetainNarrowRecursiveProofReceiptV1(
    const NarrowMultiChildL2FriConsumeV1& consumed,
    const uint256& node_binding,
    const uint256& program_binding)
{
    NarrowRecursiveProofReceiptV1 out;
    out.node_binding = node_binding;
    out.program_binding = program_binding;
    out.proof_context_binding =
        consumed.parent_context_binding;
    out.n_rows = consumed.n_rows;
    out.n_columns = consumed.n_columns;
    out.n_constraints = consumed.n_constraints;
    out.active_rows = consumed.active_rows;
    out.n_lde = consumed.n_lde;
    out.constraint_system_commitment =
        rh::ComputeHierarchyConstraintSystemCommitmentV1(
            consumed.parent_constraint_system);
    out.fs_seed = consumed.parent_fs_seed;
    out.proof_commitment = consumed.parent_proof_commitment;
    out.statement_commitment =
        consumed.parent_statement_commitment;
    out.constraint_system = consumed.parent_constraint_system;
    out.proof = consumed.parent_proof;
    out.proof_bytes = consumed.parent_proof_bytes;
    out.verify_within_relay_budget =
        consumed.verify_within_relay_budget;
    out.serialize_within_fri_budget =
        consumed.serialize_within_fri_budget;
    if (!consumed.cryptographically_valid ||
        !consumed.proved ||
        !consumed.verified ||
        !consumed.parent_proof_retained ||
        !consumed.canonical_whole_proof_codec ||
        !consumed.parent_reentry_verified ||
        node_binding.IsNull() ||
        program_binding.IsNull() ||
        consumed.parent_context_binding.IsNull()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_receipt_source_not_admissible";
        return out;
    }
    out.receipt_commitment =
        CommitNarrowRecursiveProofReceiptV1(out);
    std::string why;
    out.valid =
        !out.receipt_commitment.IsNull() &&
        ValidateNarrowRecursiveProofReceiptV1(
            out, consumed.parent_constraint_system,
            node_binding, program_binding, &why);
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "narrow_recursive_receipt_valid"
        : "stage3:recursive_fixedpoint:"
          "narrow_recursive_receipt_invalid:" + why;
    return out;
}

bool ValidateNarrowRecursiveProofReceiptV1(
    const NarrowRecursiveProofReceiptV1& receipt,
    const aq::AirConstraintSystem<Fp3>& expected_constraint_system,
    const uint256& expected_node_binding,
    const uint256& expected_program_binding,
    std::string* why)
{
    if (receipt.version !=
            kNarrowRecursiveProofReceiptVersionV1) {
        return Fail(why, "narrow_receipt_version");
    }
    if (expected_node_binding.IsNull() ||
        receipt.node_binding != expected_node_binding) {
        return Fail(why, "narrow_receipt_node_binding");
    }
    if (expected_program_binding.IsNull() ||
        receipt.program_binding != expected_program_binding) {
        return Fail(why, "narrow_receipt_program_binding");
    }
    if (receipt.proof_context_binding.IsNull() ||
        receipt.fs_seed.IsNull() ||
        receipt.proof_commitment.IsNull() ||
        receipt.statement_commitment.IsNull() ||
        receipt.receipt_commitment.IsNull() ||
        receipt.proof_bytes.empty()) {
        return Fail(why, "narrow_receipt_null_binding");
    }
    if (receipt.constraint_system.n_rows != receipt.n_rows ||
        receipt.constraint_system.n_columns != receipt.n_columns ||
        receipt.constraint_system.constraints.size() !=
            receipt.n_constraints ||
        receipt.active_rows == 0 || receipt.n_lde == 0) {
        return Fail(why, "narrow_receipt_shape");
    }
    const uint256 expected_cs_commitment =
        rh::ComputeHierarchyConstraintSystemCommitmentV1(
            expected_constraint_system);
    if (expected_cs_commitment.IsNull() ||
        receipt.constraint_system_commitment !=
            expected_cs_commitment ||
        expected_constraint_system.n_rows != receipt.n_rows ||
        expected_constraint_system.n_columns !=
            receipt.n_columns ||
        expected_constraint_system.constraints.size() !=
            receipt.n_constraints) {
        return Fail(
            why, "narrow_receipt_constraint_system");
    }
    const nr::NarrowNodeFriShape shape =
        nr::AssessNarrowNodeFriShape(receipt.active_rows);
    if (!shape.representable || shape.n_lde != receipt.n_lde) {
        return Fail(why, "narrow_receipt_fri_shape");
    }
    std::string codec_why;
    std::vector<unsigned char> canonical;
    if (!SerializeAirQuotientProofAlg(
            receipt.proof, canonical, &codec_why) ||
        canonical != receipt.proof_bytes) {
        return Fail(
            why, "narrow_receipt_noncanonical_proof:" +
                     codec_why);
    }
    if (CommitNarrowProofBytesV1(canonical) !=
        receipt.proof_commitment) {
        return Fail(why, "narrow_receipt_proof_commitment");
    }
    if (!aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendAlg<Fp3>>(
            expected_constraint_system, receipt.proof,
            receipt.fs_seed, &codec_why)) {
        return Fail(
            why, "narrow_receipt_proof_verify:" +
                     codec_why);
    }
    if (CommitNarrowRecursiveProofReceiptV1(receipt) !=
        receipt.receipt_commitment) {
        return Fail(why, "narrow_receipt_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "narrow_recursive_receipt_verified";
    }
    return true;
}

bool ValidateNarrowRecursiveProofReceiptV2(
    const NarrowRecursiveProofReceiptV1& receipt,
    const aq::AirConstraintSystem<Fp3>& expected_constraint_system,
    const NarrowRecursiveProofExpectedBindingV2& expected_binding,
    std::string* why)
{
    if (expected_binding.version !=
            kNarrowRecursiveProofReceiptVersionV1 ||
        expected_binding.node_binding.IsNull() ||
        expected_binding.program_binding.IsNull() ||
        expected_binding.proof_context_binding.IsNull() ||
        expected_binding.statement_commitment.IsNull() ||
        expected_binding.fs_seed.IsNull() ||
        expected_binding.active_rows == 0 ||
        expected_binding.n_lde == 0) {
        return Fail(why, "narrow_receipt_v2_expected_binding");
    }
    if (receipt.proof_context_binding !=
            expected_binding.proof_context_binding) {
        return Fail(why, "narrow_receipt_v2_proof_context");
    }
    if (receipt.statement_commitment !=
            expected_binding.statement_commitment) {
        return Fail(why, "narrow_receipt_v2_statement");
    }
    if (receipt.fs_seed != expected_binding.fs_seed) {
        return Fail(why, "narrow_receipt_v2_fs_seed");
    }
    if (receipt.active_rows != expected_binding.active_rows ||
        receipt.n_lde != expected_binding.n_lde) {
        return Fail(why, "narrow_receipt_v2_proof_domain");
    }
    return ValidateNarrowRecursiveProofReceiptV1(
        receipt, expected_constraint_system,
        expected_binding.node_binding,
        expected_binding.program_binding, why);
}

NarrowRetainedReceiptParentV1
ExecuteNarrowRetainedReceiptParentV1(
    const std::vector<NarrowRecursiveProofReceiptV1>& children,
    const std::vector<aq::AirConstraintSystem<Fp3>>&
        expected_child_constraint_systems,
    const std::vector<uint256>& expected_child_node_bindings,
    const std::vector<uint256>& expected_child_program_bindings,
    const uint256& parent_node_binding,
    const uint256& parent_program_binding,
    bool prove)
{
    NarrowRetainedReceiptParentV1 out;
    out.arity = static_cast<uint32_t>(children.size());
    out.parent_node_binding = parent_node_binding;
    out.parent_program_binding = parent_program_binding;
    if (children.size() < 2 ||
        expected_child_constraint_systems.size() !=
            children.size() ||
        expected_child_node_bindings.size() !=
            children.size() ||
        expected_child_program_bindings.size() !=
            children.size() ||
        parent_node_binding.IsNull() ||
        parent_program_binding.IsNull()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_retained_parent_input";
        return out;
    }

    std::vector<aq::AirConstraintSystem<Fp3>> child_css;
    std::vector<AlgAirProof> child_proofs;
    std::vector<uint256> child_seeds;
    child_css.reserve(children.size());
    child_proofs.reserve(children.size());
    child_seeds.reserve(children.size());
    for (uint32_t i = 0; i < children.size(); ++i) {
        std::string why;
        if (!ValidateNarrowRecursiveProofReceiptV1(
                children[i], expected_child_constraint_systems[i],
                expected_child_node_bindings[i],
                expected_child_program_bindings[i], &why)) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "narrow_retained_child_invalid:" +
                std::to_string(i) + ":" + why;
            return out;
        }
        for (uint32_t j = 0; j < i; ++j) {
            if (children[i].node_binding ==
                    children[j].node_binding ||
                children[i].receipt_commitment ==
                    children[j].receipt_commitment ||
                children[i].proof_commitment ==
                    children[j].proof_commitment) {
                out.duplicate_child_rejected = true;
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "narrow_retained_duplicate_child";
                return out;
            }
        }
        child_css.push_back(
            expected_child_constraint_systems[i]);
        child_proofs.push_back(children[i].proof);
        child_seeds.push_back(children[i].fs_seed);
    }
    out.all_children_validated = true;
    out.parent_context_binding =
        ComputeNarrowRetainedParentContextV1(
            children, parent_node_binding,
            parent_program_binding);
    if (out.parent_context_binding.IsNull()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_retained_parent_context";
        return out;
    }
    out.ordered_child_context_bound = true;
    out.consumed =
        ExecuteNarrowMultiChildL2FriConsumeV1(
            child_css, child_proofs, child_seeds, prove,
            out.parent_context_binding);
    if (!out.consumed.cryptographically_valid) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_retained_parent_consume:" +
            out.consumed.note;
        return out;
    }
    out.child_tamper_rejected =
        out.consumed.forgery_rejected &&
        out.consumed.parent_proof_tamper_rejected;
    out.receipt =
        RetainNarrowRecursiveProofReceiptV1(
            out.consumed, parent_node_binding,
            parent_program_binding);
    out.cryptographically_valid =
        out.all_children_validated &&
        out.ordered_child_context_bound &&
        out.child_tamper_rejected &&
        out.receipt.valid;
    out.production_budget_met =
        out.consumed.verify_within_relay_budget &&
        out.consumed.serialize_within_fri_budget;
    out.valid =
        out.cryptographically_valid &&
        out.production_budget_met;
    out.note =
        std::string(
            "stage3:recursive_fixedpoint:"
            "narrow_retained_parent") +
        ";arity=" + std::to_string(out.arity) +
        ";children_valid=1;ordered_context=1;"
        "child_forgery=1;parent_tamper=1" +
        ";verify_us=" +
        std::to_string(out.consumed.verify_micros) +
        ";standalone_batch_verify_us=" +
        std::to_string(
            out.consumed.standalone_batch_verify_micros) +
        ";root_bytes=" +
        std::to_string(out.consumed.serialize_root_bytes) +
        (out.production_budget_met
             ? ";production_budget=1"
             : ";production_budget=0") +
        ";complete_fp=false";
    return out;
}

NarrowRetainedReceiptParentV1
ExecuteNarrowRetainedReceiptParentV2(
    const std::vector<NarrowRecursiveProofReceiptV1>& children,
    const std::vector<aq::AirConstraintSystem<Fp3>>&
        expected_child_constraint_systems,
    const std::vector<NarrowRecursiveProofExpectedBindingV2>&
        expected_child_bindings,
    const uint256& parent_node_binding,
    const uint256& parent_program_binding,
    bool prove)
{
    NarrowRetainedReceiptParentV1 out;
    out.arity = static_cast<uint32_t>(children.size());
    out.parent_node_binding = parent_node_binding;
    out.parent_program_binding = parent_program_binding;
    if (children.size() < 2 ||
        expected_child_constraint_systems.size() !=
            children.size() ||
        expected_child_bindings.size() != children.size()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "narrow_retained_parent_v2_input";
        return out;
    }

    std::vector<uint256> expected_node_bindings;
    std::vector<uint256> expected_program_bindings;
    expected_node_bindings.reserve(children.size());
    expected_program_bindings.reserve(children.size());
    for (uint32_t i = 0; i < children.size(); ++i) {
        std::string why;
        if (!ValidateNarrowRecursiveProofReceiptV2(
                children[i],
                expected_child_constraint_systems[i],
                expected_child_bindings[i], &why)) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "narrow_retained_child_v2_invalid:" +
                std::to_string(i) + ":" + why;
            return out;
        }
        expected_node_bindings.push_back(
            expected_child_bindings[i].node_binding);
        expected_program_bindings.push_back(
            expected_child_bindings[i].program_binding);
    }
    return ExecuteNarrowRetainedReceiptParentV1(
        children, expected_child_constraint_systems,
        expected_node_bindings, expected_program_bindings,
        parent_node_binding, parent_program_binding, prove);
}

NarrowBytecodeShardQuotientJoinV1
JoinNarrowBytecodeShardLocalQuotientsV1(
    const std::vector<Fp3>& parent_q_per_query,
    const std::vector<std::vector<Fp3>>& shard_local_q,
    uint32_t programs_covered,
    uint32_t programs_total)
{
    NarrowBytecodeShardQuotientJoinV1 out;
    out.programs_covered = programs_covered;
    out.programs_total = programs_total;
    out.shard_count =
        static_cast<uint32_t>(shard_local_q.size());
    out.covers_full_table =
        programs_total > 0 &&
        programs_covered == programs_total;
    out.parent_extracted = !parent_q_per_query.empty();
    if (shard_local_q.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_no_shards";
        return out;
    }
    const uint32_t queries =
        static_cast<uint32_t>(shard_local_q.front().size());
    out.queries = queries;
    if (queries == 0) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_no_queries";
        return out;
    }
    for (const auto& shard : shard_local_q) {
        if (shard.size() != queries) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_q_join_query_mismatch";
            return out;
        }
    }
    out.shards_extracted = true;
    out.sum_local_q_per_query.assign(queries, Fp3::Zero());
    for (const auto& shard : shard_local_q) {
        for (uint32_t q = 0; q < queries; ++q) {
            out.sum_local_q_per_query[q] = gf::Add(
                out.sum_local_q_per_query[q], shard[q]);
        }
    }
    // Relative partition closed: recomputing the sum is the identity of
    // the extracted openings; forgery below proves each shard is load-bearing.
    out.partition_closed = true;

    if (out.parent_extracted) {
        if (parent_q_per_query.size() != queries) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_q_join_parent_query_mismatch";
            out.partition_closed = false;
            return out;
        }
        out.parent_q_per_query = parent_q_per_query;
        out.sum_equals_parent = true;
        for (uint32_t q = 0; q < queries; ++q) {
            if (!gf::IsZero(gf::Sub(
                    out.sum_local_q_per_query[q],
                    parent_q_per_query[q]))) {
                out.sum_equals_parent = false;
                break;
            }
        }
    } else {
        out.sum_equals_parent = false;
    }

    // Forgery: drop any single shard → remaining sum ≠ full sum (hence ≠ parent
    // when absolute binding holds). Requires ≥2 shards with a nonzero delta.
    out.forgery_rejected = shard_local_q.size() >= 2;
    if (out.forgery_rejected) {
        for (size_t drop = 0; drop < shard_local_q.size();
             ++drop) {
            std::vector<Fp3> partial(queries, Fp3::Zero());
            for (size_t s = 0; s < shard_local_q.size();
                 ++s) {
                if (s == drop) continue;
                for (uint32_t q = 0; q < queries; ++q) {
                    partial[q] = gf::Add(
                        partial[q], shard_local_q[s][q]);
                }
            }
            bool differs = false;
            for (uint32_t q = 0; q < queries; ++q) {
                if (!gf::IsZero(gf::Sub(
                        partial[q],
                        out.sum_local_q_per_query[q]))) {
                    differs = true;
                    break;
                }
            }
            if (!differs) {
                out.forgery_rejected = false;
                break;
            }
            if (out.parent_extracted && out.sum_equals_parent) {
                bool differs_parent = false;
                for (uint32_t q = 0; q < queries; ++q) {
                    if (!gf::IsZero(gf::Sub(
                            partial[q],
                            parent_q_per_query[q]))) {
                        differs_parent = true;
                        break;
                    }
                }
                if (!differs_parent) {
                    out.forgery_rejected = false;
                    break;
                }
            }
        }
    }

    out.valid =
        out.shards_extracted && out.partition_closed &&
        out.forgery_rejected &&
        (!out.covers_full_table ||
         (out.parent_extracted && out.sum_equals_parent));
    // Absolute parent binding is required for full-table cover; relative-only
    // subsets are still reported valid when partition+forgery close.
    if (!out.covers_full_table) {
        out.valid =
            out.shards_extracted && out.partition_closed &&
            out.forgery_rejected;
    }

    if (out.valid) {
        const std::vector<Fp3>& bound =
            out.sum_equals_parent ? out.parent_q_per_query
                                  : out.sum_local_q_per_query;
        out.air_mirror =
            AirMirrorNarrowBytecodeShardLocalQuotientsV1(
                bound, shard_local_q, out.sum_equals_parent);
        out.air_mirrored = out.air_mirror.valid;
        // Host join stays valid even if AIR mirror fails; mirror is additive.
    }

    out.note =
        std::string(
            "stage3:recursive_fixedpoint:bytecode_q_join") +
        ";shards=" + std::to_string(out.shard_count) +
        ";queries=" + std::to_string(out.queries) +
        ";covered=" + std::to_string(out.programs_covered) +
        "/" + std::to_string(out.programs_total) +
        ";full=" + (out.covers_full_table ? "1" : "0") +
        ";parent=" + (out.parent_extracted ? "1" : "0") +
        ";sum_eq=" + (out.sum_equals_parent ? "1" : "0") +
        ";part=" + (out.partition_closed ? "1" : "0") +
        ";forgery=" + (out.forgery_rejected ? "1" : "0") +
        ";mirror=" + (out.air_mirrored ? "1" : "0") +
        ";complete_fp=false";
    if (out.air_mirrored) {
        out.note +=
            ";air_verify_us=" +
            std::to_string(out.air_mirror.verify_micros);
    } else if (!out.air_mirror.note.empty()) {
        out.note += ";" + out.air_mirror.note;
    }
    return out;
}

NarrowBytecodeShardQuotientJoinV1
ExecuteNarrowBytecodeShardQuotientJoinV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    const std::vector<std::vector<uint32_t>>& shard_leaf_groups)
{
    NarrowBytecodeShardQuotientJoinV1 out;
    if (!base.valid ||
        !constraint_bytecode::ValidateProgramTable(
            table, nullptr) ||
        shard_leaf_groups.size() < 2) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_q_join_exec_input";
        return out;
    }
    std::vector<Fp3> parent_q;
    std::string why;
    const bool parent_ok =
        ExtractAuthenticatedParentQuotientOpenings(
            base, table.current_width, parent_q, &why);
    std::vector<std::vector<Fp3>> shard_qs;
    shard_qs.reserve(shard_leaf_groups.size());
    uint32_t covered = 0;
    std::vector<bool> seen(table.programs.size(), false);
    for (const auto& leaves : shard_leaf_groups) {
        if (leaves.empty()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_q_join_exec_empty_shard";
            return out;
        }
        for (uint32_t leaf : leaves) {
            if (leaf >= table.programs.size() || seen[leaf]) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "bytecode_q_join_exec_leaf";
                return out;
            }
            seen[leaf] = true;
            ++covered;
        }
        constraint_bytecode::ProgramTable shard;
        if (!SliceProgramTableByLeafIndices(
                table, leaves, shard, &why)) {
            out.note = why;
            return out;
        }
        FoldBusComposition shard_bus;
        if (!PrepareFoldBusForBytecodeShard(
                base, table, leaves, shard, shard_bus,
                &why)) {
            out.note = why;
            return out;
        }
        const BytecodeInterpreterAttachment att =
            AttachConstraintBytecodeInterpreterShard(
                shard_bus, shard, leaves);
        if (!att.valid) {
            out.note = att.note;
            return out;
        }
        std::vector<Fp3> local_q;
        if (!ExtractShardLocalQuotientOpenings(
                shard_bus, local_q, &why)) {
            out.note = why;
            return out;
        }
        shard_qs.push_back(std::move(local_q));
    }
    if (!parent_ok) {
        // Relative join still proceeds; absolute parent binding stays false.
        parent_q.clear();
    }
    return JoinNarrowBytecodeShardLocalQuotientsV1(
        parent_q, shard_qs, covered,
        static_cast<uint32_t>(table.programs.size()));
}

namespace {

namespace gf = gkr_field;

/** Tiny W=1 boolean child used only as a hierarchical L2-wire stand-in
 *  until real free-row L1 AirProofs are available. */
bool BuildBooleanStandInChildrenForHierL2Wire(
    uint32_t arity,
    unsigned char seed_tag,
    std::vector<aq::AirConstraintSystem<Fp3>>& out_css,
    std::vector<AlgAirProof>& out_proofs,
    std::vector<uint256>& out_seeds)
{
    out_css.clear();
    out_proofs.clear();
    out_seeds.clear();
    if (arity < 2) return false;
    out_css.reserve(arity);
    out_proofs.reserve(arity);
    out_seeds.reserve(arity);
    for (uint32_t i = 0; i < arity; ++i) {
        aq::AirConstraintSystem<Fp3> cs;
        cs.n_rows = 2;
        cs.n_columns = 1;
        aq::AirConstraint<Fp3> boolean;
        boolean.name = "stage3.fixedpoint.hier_l2_wire.boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval =
            [](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[0], gf::Sub(cur[0], Fp3::One()));
            };
        cs.constraints.push_back(std::move(boolean));

        HashWriter seed_hash;
        seed_hash << "BTX_RC_HIER_L2_WIRE_STANDIN_V1";
        seed_hash << seed_tag;
        seed_hash << i;
        seed_hash << arity;
        const uint256 seed = seed_hash.GetHash();

        std::vector<std::vector<Fp3>> columns(
            1, std::vector<Fp3>(2, Fp3::Zero()));
        columns[0][1] = Fp3::One();
        const auto proved =
            aq::AirQuotientProve<Fp3, aq::AirFriBackendAlg<Fp3>>(
                cs, columns, seed, {});
        if (!proved.ok || !proved.division_exact) {
            return false;
        }
        out_css.push_back(std::move(cs));
        out_proofs.push_back(proved.proof);
        out_seeds.push_back(seed);
    }
    return out_css.size() == arity &&
           out_proofs.size() == arity &&
           out_seeds.size() == arity;
}

} // namespace

NarrowBytecodeHierarchicalAttachExecutionV1
ExecuteNarrowBytecodeHierarchicalAttachV1(
    const FoldBusComposition& base,
    const constraint_bytecode::ProgramTable& table,
    bool attach_l1,
    bool wire_l2_fri_consume,
    bool l2_prove)
{
    NarrowBytecodeHierarchicalAttachExecutionV1 out;
    out.p2_fs_replay_closed =
        recursive_parent_air::AssessChildFsReplayClosureV1()
            .closed;
    out.complete_verifier_mirror = false;
    // When wiring, start true and clear on any arity≥2 compose failure.
    // When not wiring, stays false (wire not claimed).
    out.all_composed_l2_wired = wire_l2_fri_consume;
    if (!base.valid ||
        !constraint_bytecode::ValidateProgramTable(
            table, nullptr)) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_hier_exec_input_invalid";
        return out;
    }
    const uint32_t queries = static_cast<uint32_t>(
        base.hash.program.public_inputs.query_index.size());
    out.plan =
        PlanNarrowBytecodeHierarchicalAttachV1(table, queries);
    out.plan_valid = out.plan.valid;
    out.depth = out.plan.depth;
    out.node_count = out.plan.node_count;
    if (!out.plan_valid) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_hier_exec_plan_invalid:" +
            out.plan.note;
        return out;
    }

    // Stand-in boolean children for the hierarchical L2/L3 wire path.
    // Real free-row L1 AirProof children remain a separate AggregationReady
    // blocker (await measured chip-A proofs). Built once up to max arity.
    std::vector<aq::AirConstraintSystem<Fp3>> wire_css;
    std::vector<AlgAirProof> wire_proofs;
    std::vector<uint256> wire_seeds;
    if (wire_l2_fri_consume) {
        uint32_t max_arity = 2;
        for (const auto& node : out.plan.hierarchy.nodes) {
            if (node.level >= 2) {
                max_arity = std::max(
                    max_arity,
                    static_cast<uint32_t>(
                        node.child_node_indices.size()));
            }
        }
        if (!BuildBooleanStandInChildrenForHierL2Wire(
                max_arity, /*seed_tag=*/0xC2U, wire_css,
                wire_proofs, wire_seeds)) {
            out.all_composed_l2_wired = false;
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_hier_l2_wire_standin_build";
            return out;
        }
    }

    out.all_nodes_representable = true;
    out.all_composed_scheduled = true;
    for (const auto& node : out.plan.hierarchy.nodes) {
        NarrowBytecodeHierarchicalAttachNodeResultV1 nr;
        nr.level = node.level;
        nr.node_index = node.node_index;
        nr.label = node.label;
        nr.active_rows = node.active_rows;
        nr.trace_rows = node.shape.trace_rows;
        nr.n_lde = node.shape.n_lde;
        nr.shape_representable = node.shape.representable;
        nr.program_count =
            static_cast<uint32_t>(node.child_leaf_indices.size());
        nr.child_node_count =
            static_cast<uint32_t>(node.child_node_indices.size());
        if (!nr.shape_representable) {
            out.all_nodes_representable = false;
            nr.note = "shape_not_representable";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        if (node.level == 1) {
            nr.note = "fri_l1_scheduled;attach_via_free_row_shards";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        ++out.composed_count;
        if (node.child_node_indices.empty()) {
            out.all_composed_scheduled = false;
            if (wire_l2_fri_consume) {
                out.all_composed_l2_wired = false;
            }
            nr.note = "composed_missing_children";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        bool children_ok = true;
        for (uint32_t child : node.child_node_indices) {
            if (child >= node.node_index ||
                child >= out.plan.hierarchy.nodes.size()) {
                children_ok = false;
                break;
            }
            const auto& child_node =
                out.plan.hierarchy.nodes[child];
            if (child_node.level >= node.level ||
                !child_node.shape.representable) {
                children_ok = false;
                break;
            }
        }
        if (!children_ok) {
            out.all_composed_scheduled = false;
            if (wire_l2_fri_consume) {
                out.all_composed_l2_wired = false;
            }
            nr.note = "composed_child_link_invalid";
            out.nodes.push_back(std::move(nr));
            continue;
        }

        if (!wire_l2_fri_consume) {
            nr.note =
                "composed_scheduled;crypto_join_pending;"
                "l2_fri_consume_executable";
            out.nodes.push_back(std::move(nr));
            continue;
        }

        // Hierarchical L2/L3 wire: invoke multi-child FRI consume.
        if (nr.child_node_count < 2U) {
            ++out.composed_l2_arity_lt2;
            // Unary composed edges are schedule-ok but cannot exercise
            // the arity≥2 multi-child consume API.
            nr.note =
                "composed_scheduled;crypto_join_arity_lt2;"
                "l2_fri_consume_skipped";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        if (wire_css.size() < nr.child_node_count) {
            out.all_composed_l2_wired = false;
            nr.note =
                "composed_scheduled;crypto_join_wire_standin_short";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        std::vector<aq::AirConstraintSystem<Fp3>> child_css(
            wire_css.begin(),
            wire_css.begin() + nr.child_node_count);
        std::vector<AlgAirProof> children(
            wire_proofs.begin(),
            wire_proofs.begin() + nr.child_node_count);
        std::vector<uint256> child_seeds(
            wire_seeds.begin(),
            wire_seeds.begin() + nr.child_node_count);
        const NarrowMultiChildL2FriConsumeV1 consumed =
            ExecuteNarrowMultiChildL2FriConsumeV1(
                child_css, children, child_seeds, l2_prove);
        nr.l2_fri_consume_invoked = true;
        nr.l2_fri_consume_valid = consumed.valid;
        nr.l2_fri_consume_arity = consumed.arity;
        nr.forgery_rejected = consumed.forgery_rejected;
        if (consumed.valid) {
            ++out.composed_l2_wired;
            nr.note =
                std::string("composed_scheduled;crypto_join_wired;") +
                consumed.note;
        } else {
            out.all_composed_l2_wired = false;
            nr.note =
                std::string(
                    "composed_scheduled;crypto_join_wire_failed;") +
                consumed.note;
        }
        out.nodes.push_back(std::move(nr));
    }

    if (wire_l2_fri_consume) {
        // Arity-lt2 composed nodes do not block the wire (no multi-child
        // API to invoke); require every arity≥2 composed node wired.
        const uint32_t need =
            out.composed_count > out.composed_l2_arity_lt2
                ? out.composed_count - out.composed_l2_arity_lt2
                : 0;
        out.all_composed_l2_wired =
            out.all_composed_l2_wired &&
            out.composed_l2_wired == need && need > 0;
    }

    const uint32_t reserved =
        CountFoldBusReservedSpongeRows(base);
    const uint64_t free_rows =
        base.combined.n_rows > reserved
            ? uint64_t{base.combined.n_rows - reserved}
            : 0;
    const auto shard_groups =
        PackBytecodeShardsUnderFreeRows(table, queries, free_rows);
    out.l1_count = static_cast<uint32_t>(shard_groups.size());
    out.all_l1_attached = attach_l1 && !shard_groups.empty();
    out.all_l1_forgeries_rejected =
        attach_l1 && !shard_groups.empty();
    if (shard_groups.empty()) {
        out.all_l1_attached = false;
        out.all_l1_forgeries_rejected = false;
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_hier_exec_no_free_row_shards;free=" +
            std::to_string(free_rows);
        out.valid = false;
        return out;
    }

    std::vector<std::vector<Fp3>> shard_local_qs;
    uint32_t programs_covered = 0;
    if (attach_l1) {
        shard_local_qs.reserve(shard_groups.size());
    }

    for (uint32_t si = 0; si < shard_groups.size(); ++si) {
        NarrowBytecodeHierarchicalAttachNodeResultV1 nr;
        nr.level = 1;
        nr.node_index = static_cast<uint32_t>(out.nodes.size());
        nr.label = "freeL1-" + std::to_string(si);
        nr.program_count =
            static_cast<uint32_t>(shard_groups[si].size());
        constraint_bytecode::ProgramTable shard;
        std::string why;
        if (!SliceProgramTableByLeafIndices(
                table, shard_groups[si], shard, &why)) {
            out.all_l1_attached = false;
            out.all_l1_forgeries_rejected = false;
            nr.note = why;
            out.nodes.push_back(std::move(nr));
            continue;
        }
        nr.instructions = CountProgramTableInstructions(shard);
        nr.rows_needed =
            uint64_t{queries} * (nr.instructions + 1U);
        nr.active_rows = nr.rows_needed;
        const nr::NarrowNodeFriShape shape =
            nr::AssessNarrowNodeFriShape(nr.rows_needed);
        nr.trace_rows = shape.trace_rows;
        nr.n_lde = shape.n_lde;
        nr.shape_representable = shape.representable;
        nr.pad_ok = nr.rows_needed <= free_rows;
        if (!nr.pad_ok || !nr.shape_representable) {
            out.all_l1_attached = false;
            out.all_l1_forgeries_rejected = false;
            nr.note = "free_row_shard_capacity";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        if (!attach_l1) {
            nr.note = "free_row_shard_capacity_ok;attach_deferred";
            out.nodes.push_back(std::move(nr));
            continue;
        }
        FoldBusComposition shard_bus;
        if (!PrepareFoldBusForBytecodeShard(
                base, table, shard_groups[si], shard,
                shard_bus, &why)) {
            out.all_l1_attached = false;
            out.all_l1_forgeries_rejected = false;
            nr.note = why;
            out.nodes.push_back(std::move(nr));
            continue;
        }
        const BytecodeInterpreterAttachment att =
            AttachConstraintBytecodeInterpreterShard(
                shard_bus, shard, shard_groups[si]);
        nr.attached = att.valid;
        nr.dual_logup_terminal = att.dual_logup_terminal;
        nr.quotient_opening_equality =
            att.quotient_opening_equality;
        nr.violations = att.violations;
        if (att.valid) {
            nr.note = att.note;
            ++out.l1_attached;
            programs_covered += nr.program_count;
            nr.forgery_rejected =
                RejectBytecodeShardForgery(shard_bus);
            if (!nr.forgery_rejected) {
                out.all_l1_forgeries_rejected = false;
            }
            std::vector<Fp3> local_q;
            if (ExtractShardLocalQuotientOpenings(
                    shard_bus, local_q, &why)) {
                shard_local_qs.push_back(std::move(local_q));
            } else {
                out.all_l1_attached = false;
                nr.note = nr.note + ";" + why;
            }
        } else {
            out.all_l1_attached = false;
            out.all_l1_forgeries_rejected = false;
            nr.note =
                att.note +
                ";violations=" +
                std::to_string(att.violations) +
                ";logup=" +
                (att.dual_logup_terminal ? "1" : "0") +
                ";quot=" +
                (att.quotient_opening_equality ? "1" : "0");
        }
        out.nodes.push_back(std::move(nr));
    }

    if (attach_l1) {
        out.all_l1_attached =
            out.all_l1_attached && out.l1_count > 0 &&
            out.l1_attached == out.l1_count;
        out.all_l1_forgeries_rejected =
            out.all_l1_forgeries_rejected && out.all_l1_attached;
        if (out.all_l1_attached &&
            shard_local_qs.size() == out.l1_count) {
            std::vector<Fp3> parent_q;
            std::string why;
            if (!ExtractAuthenticatedParentQuotientOpenings(
                    base, table.current_width, parent_q,
                    &why)) {
                parent_q.clear();
            }
            out.quotient_join =
                JoinNarrowBytecodeShardLocalQuotientsV1(
                    parent_q, shard_local_qs, programs_covered,
                    static_cast<uint32_t>(table.programs.size()));
        }
    } else {
        out.all_l1_attached = false;
        out.all_l1_forgeries_rejected = false;
    }

    out.valid =
        out.plan_valid && out.all_nodes_representable &&
        out.all_composed_scheduled && out.composed_count > 0 &&
        out.l1_count > 0 &&
        (!wire_l2_fri_consume || out.all_composed_l2_wired) &&
        (attach_l1 ? out.all_l1_attached &&
                         out.all_l1_forgeries_rejected
                   : true);
    // Absolute AIR-mirrored join earns runtime complete_verifier_mirror.
    // CompleteFP / AggregationReady constexprs stay false (SHA-FS +
    // real free-row L1 AirProof children for hier L2 consume still open).
    out.complete_verifier_mirror =
        attach_l1 && out.valid && out.p2_fs_replay_closed &&
        out.quotient_join.valid &&
        out.quotient_join.sum_equals_parent &&
        out.quotient_join.air_mirrored &&
        out.quotient_join.air_mirror.forgery_rejected;
    std::string first_fail;
    for (const auto& node : out.nodes) {
        if (node.label.rfind("freeL1-", 0) == 0 && attach_l1 &&
            (!node.attached || !node.forgery_rejected ||
             !node.pad_ok)) {
            first_fail = ";" + node.label + ":" + node.note;
            break;
        }
    }
    out.note =
        std::string(
            "stage3:recursive_fixedpoint:bytecode_hier_exec") +
        ";plan_valid=" + (out.plan_valid ? "1" : "0") +
        ";free_shards=" + std::to_string(out.l1_count) +
        ";l1_attached=" + std::to_string(out.l1_attached) +
        ";fri_composed=" +
        std::to_string(out.composed_count) +
        ";fri_depth=" + std::to_string(out.depth) +
        ";fri_nodes=" + std::to_string(out.node_count) +
        ";free_rows=" + std::to_string(free_rows) +
        ";attach=" + (attach_l1 ? "1" : "0") +
        ";all_l1=" + (out.all_l1_attached ? "1" : "0") +
        ";forgery=" +
        (out.all_l1_forgeries_rejected ? "1" : "0") +
        ";composed_ok=" +
        (out.all_composed_scheduled ? "1" : "0") +
        ";l2_wire=" + (wire_l2_fri_consume ? "1" : "0") +
        ";l2_wired=" + std::to_string(out.composed_l2_wired) +
        ";l2_all=" + (out.all_composed_l2_wired ? "1" : "0") +
        ";l2_prove=" + (l2_prove ? "1" : "0") +
        ";p2_fs=" + (out.p2_fs_replay_closed ? "1" : "0") +
        ";q_join=" +
        (out.quotient_join.valid ? "1" : "0") +
        ";q_sum_eq=" +
        (out.quotient_join.sum_equals_parent ? "1" : "0") +
        ";mirror=" +
        (out.complete_verifier_mirror ? "1" : "0") +
        ";complete_fp=false" + first_fail;
    return out;
}


namespace {

std::string HierarchicalAttachWhySuffix(
    const constraint_bytecode::ProgramTable* table,
    uint32_t queries)
{
    if (table == nullptr || queries == 0) return {};
    const NarrowBytecodeHierarchicalAttachPlanV1 hier =
        PlanNarrowBytecodeHierarchicalAttachV1(*table, queries);
    return ";hier_fits=" +
           std::string(
               hier.hierarchical_fits || hier.single_node_fits
                   ? "1"
                   : "0") +
           ";hier_depth=" + std::to_string(hier.depth) +
           ";hier_nodes=" + std::to_string(hier.node_count) +
           ";hier_leaf_rows=" +
           std::to_string(hier.total_leaf_rows);
}

} // namespace

bool PadFoldBusFreeRowsForBytecode(
    FoldBusComposition& composition,
    uint64_t rows_needed,
    std::string* why)
{
    return PadFoldBusFreeRowsForBytecode(
        composition, rows_needed, nullptr, why);
}

bool PadFoldBusFreeRowsForBytecode(
    FoldBusComposition& composition,
    uint64_t rows_needed,
    const constraint_bytecode::ProgramTable* table,
    std::string* why)
{
    if (!composition.valid || rows_needed == 0) {
        return Fail(why, "bytecode_pad_input");
    }
    const uint32_t reserved =
        CountFoldBusReservedSpongeRows(composition);
    const uint32_t n_rows = composition.combined.n_rows;
    const uint32_t free =
        n_rows > reserved ? n_rows - reserved : 0;
    if (rows_needed <= free) {
        if (why != nullptr) {
            *why =
                "stage3:recursive_fixedpoint:"
                "bytecode_pad_already_fits";
        }
        return true;
    }
    const uint64_t deficit = rows_needed - free;
    const uint64_t min_rows = uint64_t{n_rows} + deficit;
    const uint32_t projected = NextPow2(min_rows);
    const uint32_t queries = static_cast<uint32_t>(
        composition.hash.program.public_inputs.query_index
            .size());
    if (projected == 0 ||
        uint64_t{projected} * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return Fail(
            why,
            "bytecode_pad_lde_over_cap;needed=" +
                std::to_string(rows_needed) +
                ";free=" + std::to_string(free) +
                ";min_rows=" +
                std::to_string(min_rows) +
                HierarchicalAttachWhySuffix(table, queries));
    }
    // Degree-aware FRI shape (arity-2 / degree-3 LDE bound).
    const nr::NarrowNodeFriShape fri =
        nr::AssessNarrowNodeFriShape(min_rows);
    if (!fri.representable) {
        return Fail(
            why,
            "bytecode_pad_fri_over_cap;needed=" +
                std::to_string(rows_needed) +
                ";free=" + std::to_string(free) +
                ";min_rows=" +
                std::to_string(min_rows) +
                ";n_lde=" + std::to_string(fri.n_lde) +
                HierarchicalAttachWhySuffix(table, queries));
    }
    composition.combined.n_rows = projected;
    for (auto& column : composition.columns) {
        column.resize(projected, Fp3::Zero());
    }
    for (auto& [col, values] :
         composition.combined.preprocessed) {
        (void)col;
        values.resize(projected, Fp3::Zero());
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "bytecode_pad_ok;rows=" +
            std::to_string(projected);
    }
    return true;
}

namespace {

uint256 CommitBytecodeChallengeTranscriptV1(
    const BytecodeChallengeTranscriptV1& transcript)
{
    if (transcript.version != 1 ||
        transcript.public_fs_seed.IsNull() ||
        transcript.program_commitment.IsNull() ||
        transcript.r0_commitment.IsNull() ||
        transcript.challenge_width == 0 ||
        transcript.challenge_preimage_lanes.size() !=
            transcript.challenge_width ||
        transcript.challenge_digest.size() !=
            transcript.challenge_width ||
        transcript.challenges.size() !=
            transcript.challenge_width) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_BYTECODE_CHALLENGE_TRANSCRIPT_V1";
    hash << transcript.version;
    hash << transcript.child_proof_version;
    hash << transcript.public_fs_seed;
    hash << transcript.program_commitment;
    hash << transcript.r0_commitment;
    hash << transcript.trace_rows;
    hash << transcript.current_width;
    hash << transcript.next_width;
    hash << transcript.challenge_width;
    hash << static_cast<uint32_t>(
        transcript.base_column_indices.size());
    for (const uint32_t column :
         transcript.base_column_indices) {
        hash << column;
    }
    for (uint32_t challenge = 0;
         challenge < transcript.challenge_width;
         ++challenge) {
        const auto& lanes =
            transcript.challenge_preimage_lanes[
                challenge];
        hash << challenge;
        hash << static_cast<uint32_t>(lanes.size());
        for (const gkr_field::Fp lane : lanes) {
            hash << gkr_field::Canonical(lane);
        }
        hash << transcript.challenge_digest[challenge];
        const Fp3 value =
            transcript.challenges[challenge];
        hash << gkr_field::Canonical(value.c0);
        hash << gkr_field::Canonical(value.c1);
        hash << gkr_field::Canonical(value.c2);
    }
    return hash.GetHash();
}

std::vector<uint32_t> BytecodeChallengeExtraV1(
    const constraint_bytecode::ProgramTable& table,
    uint32_t trace_rows,
    const std::vector<uint32_t>& base_column_indices,
    uint32_t challenge)
{
    std::vector<uint32_t> extra;
    extra.reserve(9 + base_column_indices.size());
    extra.push_back(1);
    extra.push_back(
        static_cast<uint32_t>(table.role));
    extra.push_back(trace_rows);
    extra.push_back(table.current_width);
    extra.push_back(table.next_width);
    extra.push_back(table.challenge_width);
    extra.push_back(
        static_cast<uint32_t>(
            base_column_indices.size()));
    extra.insert(
        extra.end(),
        base_column_indices.begin(),
        base_column_indices.end());
    extra.push_back(challenge);
    return extra;
}

bool SameFp3Vector(
    const std::vector<Fp3>& lhs,
    const std::vector<Fp3>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!gkr_field::Eq(lhs[i], rhs[i])) {
            return false;
        }
    }
    return true;
}

bool SameFpLaneVectors(
    const std::vector<std::vector<gkr_field::Fp>>& lhs,
    const std::vector<std::vector<gkr_field::Fp>>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (lhs[i].size() != rhs[i].size()) return false;
        for (size_t j = 0; j < lhs[i].size(); ++j) {
            if (gkr_field::Canonical(lhs[i][j]) !=
                gkr_field::Canonical(rhs[i][j])) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

bool DeriveBytecodeChallengeVectorV1(
    const constraint_bytecode::ProgramTable& table,
    uint32_t trace_rows,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const uint256& r0_commitment,
    std::vector<Fp3>& challenges,
    std::string* why)
{
    challenges.clear();
    std::string table_why;
    if (!constraint_bytecode::ValidateProgramTable(
            table, &table_why) ||
        table.challenge_width == 0 ||
        trace_rows < 2 ||
        (trace_rows & (trace_rows - 1U)) != 0 ||
        public_fs_seed.IsNull() ||
        r0_commitment.IsNull() ||
        base_column_indices.empty()) {
        return Fail(
            why,
            "bytecode_challenge_epoch_shape:" +
                table_why);
    }
    uint32_t previous = 0;
    for (size_t i = 0;
         i < base_column_indices.size(); ++i) {
        const uint32_t column =
            base_column_indices[i];
        if (column >= table.current_width ||
            (i != 0 && column <= previous)) {
            return Fail(
                why,
                "bytecode_challenge_epoch_base_schedule");
        }
        previous = column;
    }
    const uint256 program_commitment =
        constraint_bytecode::CommitProgramTable(
            table);
    if (program_commitment.IsNull()) {
        return Fail(
            why,
            "bytecode_challenge_epoch_program");
    }
    challenges.reserve(table.challenge_width);
    for (uint32_t challenge = 0;
         challenge < table.challenge_width;
         ++challenge) {
        const auto extra =
            BytecodeChallengeExtraV1(
                table, trace_rows,
                base_column_indices,
                challenge);
        const uint256 digest =
            aq::AirChallengeDigestP2(
                public_fs_seed,
                "bytecode_program_challenge_v1",
                {r0_commitment,
                 program_commitment},
                extra);
        if (digest.IsNull()) {
            challenges.clear();
            return Fail(
                why,
                "bytecode_challenge_epoch_digest");
        }
        challenges.push_back(
            gkr_field::FromChallengeBytes3(
                digest.data()));
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "bytecode_challenge_epoch_derived";
    }
    return true;
}

bool BuildBytecodeChallengeTranscriptV1(
    const constraint_bytecode::ProgramTable& table,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const std::vector<uint32_t>&
        expected_base_column_indices,
    const uint256& public_fs_seed,
    BytecodeChallengeTranscriptV1& out,
    std::string* why)
{
    out = {};
    std::string table_why;
    if (!constraint_bytecode::ValidateProgramTable(
            table, &table_why) ||
        table.challenge_width == 0 ||
        child_proof.version !=
            aq::kAirQuotientSplitRapRowsSafeProofVersionV2 ||
        child_proof.trace_rows < 2 ||
        child_proof.base_column_indices !=
            expected_base_column_indices ||
        child_proof.batch.groups.size() != 3 ||
        public_fs_seed.IsNull()) {
        return Fail(
            why,
            "bytecode_challenge_transcript_shape:" +
                table_why);
    }
    out.child_proof_version =
        child_proof.version;
    out.public_fs_seed = public_fs_seed;
    out.program_commitment =
        constraint_bytecode::CommitProgramTable(
            table);
    out.r0_commitment =
        Fri3AlgDigestToUint256(
            child_proof.batch.groups[0]
                .row_commit.root);
    out.trace_rows = child_proof.trace_rows;
    out.current_width = table.current_width;
    out.next_width = table.next_width;
    out.challenge_width = table.challenge_width;
    out.base_column_indices =
        expected_base_column_indices;
    if (out.program_commitment.IsNull() ||
        out.r0_commitment.IsNull() ||
        !DeriveBytecodeChallengeVectorV1(
            table, out.trace_rows,
            out.base_column_indices,
            public_fs_seed,
            out.r0_commitment,
            out.challenges, why)) {
        out = {};
        return false;
    }
    out.challenge_preimage_lanes.reserve(
        out.challenge_width);
    out.challenge_digest.reserve(
        out.challenge_width);
    for (uint32_t challenge = 0;
         challenge < out.challenge_width;
         ++challenge) {
        const auto extra =
            BytecodeChallengeExtraV1(
                table, out.trace_rows,
                out.base_column_indices,
                challenge);
        auto lanes =
            aq::AirChallengeP2Lanes(
                public_fs_seed,
                "bytecode_program_challenge_v1",
                {out.r0_commitment,
                 out.program_commitment},
                extra);
        const uint256 digest =
            aq::AirChallengeDigestP2(
                public_fs_seed,
                "bytecode_program_challenge_v1",
                {out.r0_commitment,
                 out.program_commitment},
                extra);
        if (lanes.empty() ||
            digest.IsNull() ||
            !gkr_field::Eq(
                out.challenges[challenge],
                gkr_field::FromChallengeBytes3(
                    digest.data()))) {
            out = {};
            return Fail(
                why,
                "bytecode_challenge_transcript_replay");
        }
        out.challenge_preimage_lanes.push_back(
            std::move(lanes));
        out.challenge_digest.push_back(
            digest);
    }
    aq::AirConstraintSystem<Fp3> child_cs;
    if (!constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, out.trace_rows,
                out.challenges, child_cs,
                why) ||
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            child_cs, child_proof,
            expected_base_column_indices,
            public_fs_seed, why)) {
        out = {};
        return false;
    }
    out.safe_split_rap_statement_verified = true;
    out.exact_p2_replay = true;
    out.transcript_commitment =
        CommitBytecodeChallengeTranscriptV1(
            out);
    out.valid =
        !out.transcript_commitment.IsNull();
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "bytecode_challenge_transcript_verified"
        : "stage3:recursive_fixedpoint:"
          "bytecode_challenge_transcript_commitment";
    if (!out.valid) {
        return Fail(
            why,
            "bytecode_challenge_transcript_commitment");
    }
    if (why != nullptr) *why = out.note;
    return true;
}

bool ValidateBytecodeChallengeTranscriptV1(
    const constraint_bytecode::ProgramTable& table,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const std::vector<uint32_t>&
        expected_base_column_indices,
    const uint256& public_fs_seed,
    const BytecodeChallengeTranscriptV1& transcript,
    std::string* why)
{
    BytecodeChallengeTranscriptV1 expected;
    std::string local_why;
    if (!BuildBytecodeChallengeTranscriptV1(
            table, child_proof,
            expected_base_column_indices,
            public_fs_seed,
            expected, &local_why) ||
        !transcript.valid ||
        transcript.version != expected.version ||
        transcript.child_proof_version !=
            expected.child_proof_version ||
        transcript.public_fs_seed !=
            expected.public_fs_seed ||
        transcript.program_commitment !=
            expected.program_commitment ||
        transcript.r0_commitment !=
            expected.r0_commitment ||
        transcript.trace_rows !=
            expected.trace_rows ||
        transcript.current_width !=
            expected.current_width ||
        transcript.next_width !=
            expected.next_width ||
        transcript.challenge_width !=
            expected.challenge_width ||
        transcript.base_column_indices !=
            expected.base_column_indices ||
        transcript.challenge_digest !=
            expected.challenge_digest ||
        !SameFp3Vector(
            transcript.challenges,
            expected.challenges) ||
        !SameFpLaneVectors(
            transcript.challenge_preimage_lanes,
            expected.challenge_preimage_lanes) ||
        transcript.transcript_commitment !=
            expected.transcript_commitment ||
        CommitBytecodeChallengeTranscriptV1(
            transcript) !=
            expected.transcript_commitment) {
        return Fail(
            why,
            "bytecode_challenge_transcript_mismatch:" +
                local_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "bytecode_challenge_transcript_valid";
    }
    return true;
}

BytecodeChallengeReplayParentV1
BuildBytecodeChallengeReplayParentV1(
    const constraint_bytecode::ProgramTable& table,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const std::vector<uint32_t>&
        expected_base_column_indices,
    const uint256& public_fs_seed,
    const BytecodeChallengeTranscriptV1& transcript)
{
    namespace pa = stage3_poseidon_air;
    BytecodeChallengeReplayParentV1 out;
    out.transcript = transcript;
    std::string why;
    if (!ValidateBytecodeChallengeTranscriptV1(
            table, child_proof,
            expected_base_column_indices,
            public_fs_seed, transcript, &why)) {
        out.note = why;
        return out;
    }
    out.transcript_authenticated = true;

    struct Load {
        uint32_t challenge{0};
    };
    std::vector<Load> loads;
    for (const auto& program : table.programs) {
        for (const auto& instruction :
             program.instructions) {
            if (instruction.opcode ==
                constraint_bytecode::Opcode::
                    Challenge) {
                loads.push_back(
                    {instruction.lhs});
            }
        }
    }
    out.challenge_loads =
        static_cast<uint32_t>(loads.size());
    if (loads.empty()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_challenge_parent_no_loads";
        return out;
    }

    uint64_t permutation_rows = 0;
    for (const auto& lanes :
         transcript.challenge_preimage_lanes) {
        const uint32_t permutations =
            aq::AirChallengeP2Permutations(
                lanes.size());
        if (permutations == 0 ||
            permutation_rows >
                std::numeric_limits<uint32_t>::max() -
                    permutations) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_challenge_parent_permutations";
            return out;
        }
        permutation_rows += permutations;
    }
    out.poseidon_permutations =
        static_cast<uint32_t>(
            permutation_rows);
    const uint64_t active_rows =
        permutation_rows + loads.size();
    const uint32_t rows =
        NextPow2(std::max<uint64_t>(
            16, active_rows));
    if (rows == 0 ||
        uint64_t{rows} * kRCFriBlowup <
            kRCFri3AlgNumQueries) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_challenge_parent_rows";
        return out;
    }

    out.cs.n_rows = rows;
    const pa::Layout poseidon =
        pa::CanonicalLayout(0);
    out.poseidon_base = 0;
    out.absorbed_lane_base =
        poseidon.End();
    out.active_column =
        out.absorbed_lane_base +
        ah::kAlgHashRate;
    out.start_column =
        out.active_column + 1;
    const uint32_t continuation_column =
        out.start_column + 1;
    const uint32_t last_selector_base =
        continuation_column + 1;
    const uint32_t load_selector_base =
        last_selector_base +
        table.challenge_width;
    out.interpreter_result_column =
        load_selector_base +
        table.challenge_width;
    out.challenge_column_base =
        out.interpreter_result_column + 1;
    out.cs.n_columns =
        out.challenge_column_base +
        table.challenge_width;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            rows, Fp3::Zero()));
    out.cs.constraints =
        pa::BuildFixedConstraints(
            poseidon);

    uint32_t row = 0;
    for (uint32_t challenge = 0;
         challenge < table.challenge_width;
         ++challenge) {
        std::vector<gkr_field::Fp> padded =
            transcript
                .challenge_preimage_lanes[
                    challenge];
        padded.push_back(1);
        while (padded.size() %
                   ah::kAlgHashRate !=
               0) {
            padded.push_back(0);
        }
        const uint32_t blocks =
            static_cast<uint32_t>(
                padded.size() /
                ah::kAlgHashRate);
        ah::State state{};
        for (uint32_t block = 0;
             block < blocks; ++block, ++row) {
            for (uint32_t lane = 0;
                 lane < ah::kAlgHashRate;
                 ++lane) {
                const gkr_field::Fp value =
                    padded[
                        block *
                            ah::kAlgHashRate +
                        lane];
                out.columns[
                    out.absorbed_lane_base +
                    lane][row] =
                    Fp3::FromFp(value);
                state[lane] =
                    gkr_field::Add(
                        state[lane], value);
            }
            const pa::Witness witness =
                pa::BuildWitness(
                    poseidon, state);
            for (uint32_t column =
                     poseidon.perm.base;
                 column < poseidon.End();
                 ++column) {
                out.columns[column][row] =
                    witness.row[column];
            }
            out.columns[
                out.active_column][row] =
                Fp3::One();
            if (block == 0) {
                out.columns[
                    out.start_column][row] =
                    Fp3::One();
            } else {
                out.columns[
                    continuation_column][row] =
                    Fp3::One();
            }
            if (block + 1 == blocks) {
                out.columns[
                    last_selector_base +
                    challenge][row] =
                    Fp3::One();
            }
            state = witness.output;
        }
    }
    const pa::Witness zero =
        pa::BuildWitness(
            poseidon, ah::State{});
    for (const auto& load : loads) {
        // The fixed Poseidon chip is present on every trace row. Challenge
        // load rows are not sponge rows, so materialize the canonical
        // zero-input witness rather than leaving the fixed cells at zero.
        for (uint32_t column =
                 poseidon.perm.base;
             column < poseidon.End();
             ++column) {
            out.columns[column][row] =
                zero.row[column];
        }
        out.columns[
            load_selector_base +
            load.challenge][row] =
            Fp3::One();
        out.columns[
            out.interpreter_result_column][row] =
            transcript.challenges[
                load.challenge];
        ++row;
    }
    for (; row < rows; ++row) {
        for (uint32_t column =
                 poseidon.perm.base;
             column < poseidon.End();
             ++column) {
            out.columns[column][row] =
                zero.row[column];
        }
    }
    for (uint32_t challenge = 0;
         challenge < table.challenge_width;
         ++challenge) {
        out.columns[
            out.challenge_column_base +
            challenge]
            .assign(
                rows,
                transcript.challenges[
                    challenge]);
    }

    out.cs.preprocessed_pin_ood = true;
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        out.cs.preprocessed.emplace_back(
            out.absorbed_lane_base + lane,
            out.columns[
                out.absorbed_lane_base +
                lane]);
    }
    for (const uint32_t column : {
             out.active_column,
             out.start_column,
             continuation_column}) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    for (uint32_t challenge = 0;
         challenge < table.challenge_width;
         ++challenge) {
        out.cs.preprocessed.emplace_back(
            last_selector_base + challenge,
            out.columns[
                last_selector_base +
                challenge]);
        out.cs.preprocessed.emplace_back(
            load_selector_base + challenge,
            out.columns[
                load_selector_base +
                challenge]);
    }

    auto add =
        [&out](
            const char* name,
            aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)>
                eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            out.cs.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t lane = 0;
         lane < ah::kAlgHashT; ++lane) {
        const uint32_t input =
            poseidon.perm.InputCol(lane);
        add(
            "stage3.bytecode_challenge.start_absorb",
            aq::AirKind::kEverywhere, 2,
            [start = out.start_column,
             input,
             source =
                 lane < ah::kAlgHashRate
                 ? out.absorbed_lane_base +
                       lane
                 : UINT32_MAX](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 expected =
                    source == UINT32_MAX
                    ? Fp3::Zero()
                    : cur[source];
                return gkr_field::Mul(
                    cur[start],
                    gkr_field::Sub(
                        cur[input],
                        expected));
            });
        add(
            "stage3.bytecode_challenge.sponge_carry",
            aq::AirKind::kTransition, 2,
            [poseidon, continuation_column,
             input, lane,
             source =
                 lane < ah::kAlgHashRate
                 ? out.absorbed_lane_base +
                       lane
                 : UINT32_MAX](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                Fp3 expected =
                    ar::PermOutputLane(
                        poseidon.perm,
                        cur, lane);
                if (source != UINT32_MAX) {
                    expected =
                        gkr_field::Add(
                            expected,
                            next[source]);
                }
                return gkr_field::Mul(
                    next[
                        continuation_column],
                    gkr_field::Sub(
                        next[input],
                        expected));
            });
    }
    const Fp3 u{0, 1, 0};
    const Fp3 u2{0, 0, 1};
    for (uint32_t challenge = 0;
         challenge < table.challenge_width;
         ++challenge) {
        add(
            "stage3.bytecode_challenge.output",
            aq::AirKind::kEverywhere, 2,
            [poseidon,
             selector =
                 last_selector_base +
                 challenge,
             value =
                 out.challenge_column_base +
                 challenge,
             u, u2](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 reconstructed =
                    gkr_field::Add(
                        ar::PermOutputLane(
                            poseidon.perm,
                            cur, 0),
                        gkr_field::Add(
                            gkr_field::Mul(
                                u,
                                ar::PermOutputLane(
                                    poseidon.perm,
                                    cur, 1)),
                            gkr_field::Mul(
                                u2,
                                ar::PermOutputLane(
                                    poseidon.perm,
                                    cur, 2))));
                return gkr_field::Mul(
                    cur[selector],
                    gkr_field::Sub(
                        cur[value],
                        reconstructed));
            });
        add(
            "stage3.bytecode_challenge.constant_column",
            aq::AirKind::kTransition, 1,
            [value =
                 out.challenge_column_base +
                 challenge](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gkr_field::Sub(
                    next[value],
                    cur[value]);
            });
        add(
            "stage3.bytecode_challenge.interpreter_load",
            aq::AirKind::kEverywhere, 2,
            [selector =
                 load_selector_base +
                 challenge,
             result =
                 out.interpreter_result_column,
             value =
                 out.challenge_column_base +
                 challenge](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gkr_field::Mul(
                    cur[selector],
                    gkr_field::Sub(
                        cur[result],
                        cur[value]));
            });
    }
    uint32_t first_bad_row = 0;
    std::string first_bad_name;
    out.violations =
        ar::CountWitnessViolationsOnH(
            out.cs, out.columns,
            &first_bad_row, &first_bad_name);
    out.p2_replay_constrained =
        out.violations == 0 &&
        out.poseidon_permutations > 0;
    out.every_challenge_lane_mapped =
        out.violations == 0 &&
        transcript.challenges.size() ==
            table.challenge_width;
    out.interpreter_challenge_rows_equal =
        out.violations == 0 &&
        out.challenge_loads ==
            loads.size();
    out.full_child_verifier_recursively_consumed =
        false;
    out.valid =
        out.transcript_authenticated &&
        out.p2_replay_constrained &&
        out.every_challenge_lane_mapped &&
        out.interpreter_challenge_rows_equal;
    out.note =
        out.valid
        ? "stage3:recursive_fixedpoint:"
          "bytecode_challenge_replay_parent_valid;"
          "full_child_verifier_recursion_open"
        : "stage3:recursive_fixedpoint:"
          "bytecode_challenge_replay_parent_violation;"
          "first_row=" +
              std::to_string(first_bad_row) +
          ";first_constraint=" +
              first_bad_name;
    return out;
}

bool VerifyBytecodeChallengeReplayParentV1(
    const constraint_bytecode::ProgramTable& table,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const std::vector<uint32_t>&
        expected_base_column_indices,
    const uint256& public_fs_seed,
    const BytecodeChallengeTranscriptV1& transcript,
    const aq::AirQuotientRowsProof& parent_proof,
    std::string* why)
{
    const auto expected =
        BuildBytecodeChallengeReplayParentV1(
            table, child_proof,
            expected_base_column_indices,
            public_fs_seed, transcript);
    if (!expected.valid) {
        return Fail(
            why,
            "bytecode_challenge_parent_rebuild:" +
                expected.note);
    }
    if (!aq::AirQuotientVerifyRows(
            expected.cs, parent_proof,
            transcript.transcript_commitment,
            why)) {
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:recursive_fixedpoint:"
            "bytecode_challenge_parent_proof_verified";
    }
    return true;
}

namespace {

BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreterImpl(
    FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table,
    const std::vector<uint32_t>* shard_global_ordinals)
{
    BytecodeInterpreterAttachment out;
    out.program_table = table;
    if (!table.programs.empty()) {
        out.program = table.programs.front();
    }
    out.layout =
        BytecodeBusLayout(composition.combined.n_columns);
    std::string why;
    if (!composition.valid ||
        !constraint_bytecode::ValidateProgramTable(
            table, &why)) {
        out.note = why.empty()
            ? "stage3:recursive_fixedpoint:"
              "bytecode_base_invalid"
            : why;
        return out;
    }
    // Challenge loads require verifier-owned post-commitment value columns.
    // This attachment currently owns only current/next proof rows. Reject the
    // newer opcode explicitly instead of silently treating it as Constant.
    if (table.challenge_width != 0) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_challenge_columns_not_attached";
        return out;
    }
    const bool shard_mode =
        shard_global_ordinals != nullptr;
    if (shard_mode &&
        shard_global_ordinals->size() !=
            table.programs.size()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_shard_ordinal_size";
        return out;
    }
    const auto& pi =
        composition.hash.program.public_inputs;
    if (table.current_width != pi.child_w ||
        table.next_width != pi.child_w ||
        table.programs.size() !=
            pi.child_constraints.size()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_child_constraint_table";
        return out;
    }
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        if (table.programs[ordinal].kind !=
                pi.child_constraints[ordinal].kind ||
            table.programs[ordinal].declared_degree !=
                pi.child_constraints[ordinal].alg_degree) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_child_constraint_metadata";
            return out;
        }
    }
    out.program_commitment =
        constraint_bytecode::CommitProgramTable(table);
    if (out.program_commitment.IsNull()) {
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_program_commitment";
        return out;
    }
    out.canonical_program = true;

    const uint32_t old_columns =
        composition.combined.n_columns;
    composition.combined.n_columns = out.layout.End();
    composition.columns.resize(
        composition.combined.n_columns,
        std::vector<Fp3>(
            composition.combined.n_rows,
            Fp3::Zero()));
    const HashOpeningLayout hash_layout =
        HashOpeningLayoutAt(
            composition.hash.column_base);
    const uint32_t queries =
        static_cast<uint32_t>(pi.query_index.size());
    std::vector<uint32_t> current_reads(
        table.current_width, 0);
    std::vector<uint32_t> next_reads(
        table.next_width, 0);
    std::vector<uint32_t> program_offsets;
    program_offsets.reserve(table.programs.size());
    uint32_t instructions = 0;
    for (const auto& program : table.programs) {
        program_offsets.push_back(instructions);
        if (program.instructions.size() >
            std::numeric_limits<uint32_t>::max() -
                instructions) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_instruction_overflow";
            return out;
        }
        instructions += static_cast<uint32_t>(
            program.instructions.size());
    }
    std::vector<uint32_t> register_reads(
        instructions, 0);
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        const auto& program = table.programs[ordinal];
        const uint32_t offset = program_offsets[ordinal];
        for (const auto& instruction :
             program.instructions) {
            switch (instruction.opcode) {
            case constraint_bytecode::Opcode::Current:
                ++current_reads[instruction.lhs];
                break;
            case constraint_bytecode::Opcode::Next:
                ++next_reads[instruction.lhs];
                break;
            case constraint_bytecode::Opcode::Add:
            case constraint_bytecode::Opcode::Sub:
            case constraint_bytecode::Opcode::Mul:
                ++register_reads[
                    offset + instruction.lhs];
                ++register_reads[
                    offset + instruction.rhs];
                break;
            case constraint_bytecode::Opcode::Constant:
            case constraint_bytecode::Opcode::Challenge:
                break;
            }
        }
    }

    enum class InterpreterRowKind : uint32_t {
        SourceCurrent = 0,
        SourceNext = 1,
        Current = 2,
        Next = 3,
        Constant = 4,
        Add = 5,
        Sub = 6,
        Mul = 7,
        Quotient = 8,
    };
    auto row_kind =
        [](constraint_bytecode::Opcode opcode) {
            switch (opcode) {
            case constraint_bytecode::Opcode::Current:
                return InterpreterRowKind::Current;
            case constraint_bytecode::Opcode::Next:
                return InterpreterRowKind::Next;
            case constraint_bytecode::Opcode::Constant:
                return InterpreterRowKind::Constant;
            case constraint_bytecode::Opcode::Add:
                return InterpreterRowKind::Add;
            case constraint_bytecode::Opcode::Sub:
                return InterpreterRowKind::Sub;
            case constraint_bytecode::Opcode::Mul:
                return InterpreterRowKind::Mul;
            case constraint_bytecode::Opcode::Challenge:
                return InterpreterRowKind::Constant;
            }
            return InterpreterRowKind::Constant;
        };
    auto set_event =
        [&](uint32_t row, uint32_t port,
            const Fp3& value, uint64_t address,
            int64_t multiplicity) {
            if (port >= BytecodeBusLayout::kPorts ||
                address >= gf::kP ||
                multiplicity == 0) {
                return false;
            }
            composition.columns[
                out.layout.Value(port)][row] = value;
            composition.columns[
                out.layout.Address(port)][row] =
                Fp3::FromFp(gf::FromU64(address));
            composition.columns[
                out.layout.Multiplicity(port)][row] =
                multiplicity > 0
                ? Fp3::FromFp(gf::FromU64(
                      static_cast<uint64_t>(
                          multiplicity)))
                : Fp3::FromFp(gf::Neg(gf::FromU64(
                      static_cast<uint64_t>(
                          -multiplicity))));
            composition.columns[
                out.layout.Active(port)][row] =
                Fp3::One();
            return true;
        };
    const uint64_t query_address_stride =
        uint64_t{3} *
            (table.current_width + 1 +
             table.next_width) +
        instructions;
    auto source_address =
        [&](uint32_t query, bool next,
            uint32_t item, uint32_t coordinate) {
            const uint64_t query_base =
                uint64_t{1} +
                uint64_t{query} *
                    query_address_stride;
            const uint64_t next_offset =
                next
                ? uint64_t{3} *
                      (table.current_width + 1)
                : 0;
            return query_base + next_offset +
                uint64_t{3} * item + coordinate;
        };
    auto register_address =
        [&](uint32_t query, uint32_t reg) {
            return uint64_t{1} +
                uint64_t{query} *
                    query_address_stride +
                uint64_t{3} *
                    (table.current_width + 1 +
                     table.next_width) +
                reg;
        };

    std::vector<bool> reserved(
        composition.combined.n_rows, false);
    std::vector<std::vector<Fp3>> current_values(
        queries,
        std::vector<Fp3>(
            table.current_width, Fp3::Zero()));
    std::vector<std::vector<Fp3>> next_values(
        queries,
        std::vector<Fp3>(
            table.next_width, Fp3::Zero()));
    std::vector<std::vector<std::array<Fp3, 3>>>
        current_coordinates(
            queries,
            std::vector<std::array<Fp3, 3>>(
                table.current_width + 1));
    std::vector<std::vector<std::array<Fp3, 3>>>
        next_coordinates(
            queries,
            std::vector<std::array<Fp3, 3>>(
                table.next_width));
    std::vector<std::vector<std::array<bool, 3>>>
        current_seen(
            queries,
            std::vector<std::array<bool, 3>>(
                table.current_width + 1));
    std::vector<std::vector<std::array<bool, 3>>>
        next_seen(
            queries,
            std::vector<std::array<bool, 3>>(
                table.next_width));

    for (uint32_t row = 0;
         row < composition.hash.program.active_rows;
         ++row) {
        const auto& meta =
            composition.hash.program.rows[row];
        if (!meta.current_row_sponge &&
            !meta.next_row_sponge) {
            continue;
        }
        reserved[row] = true;
        const bool is_next = meta.next_row_sponge;
        const uint32_t width =
            is_next
            ? table.next_width
            : table.current_width + 1;
        bool row_active = false;
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            const uint32_t position =
                meta.current_word_offset + lane;
            if (position >= 3 * width) continue;
            const uint32_t item = position / 3;
            const uint32_t coordinate = position % 3;
            const Fp3 raw =
                composition.columns[
                    hash_layout.absorbed_pin_base +
                    lane][row];
            // Shard L1 synthesizes a local quotient; do not emit memory-bus
            // events for the full-child AIR q opening (item == current_width).
            const uint32_t reads =
                is_next
                ? next_reads[item]
                : (item == table.current_width
                       ? (shard_mode ? 0U : 1U)
                       : current_reads[item]);
            if (is_next) {
                next_coordinates[meta.query][item]
                    [coordinate] = raw;
                next_seen[meta.query][item]
                    [coordinate] = true;
            } else {
                current_coordinates[meta.query][item]
                    [coordinate] = raw;
                current_seen[meta.query][item]
                    [coordinate] = true;
            }
            if (reads == 0) continue;
            if (!set_event(
                    row, lane, raw,
                    source_address(
                        meta.query, is_next,
                        item, coordinate),
                    reads)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "bytecode_source_event";
                return out;
            }
            ++out.authenticated_source_coordinates;
            row_active = true;
        }
        if (row_active) {
            const uint32_t kind =
                static_cast<uint32_t>(
                    is_next
                    ? InterpreterRowKind::SourceNext
                    : InterpreterRowKind::SourceCurrent);
            composition.columns[
                out.layout.RowKind(kind)][row] =
                Fp3::One();
        }
    }
    const Fp3 u{0, 1, 0};
    const Fp3 u2{0, 0, 1};
    for (uint32_t query = 0;
         query < queries; ++query) {
        for (uint32_t item = 0;
             item < table.current_width; ++item) {
            if (!current_seen[query][item][0] ||
                !current_seen[query][item][1] ||
                !current_seen[query][item][2]) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "bytecode_current_source_missing";
                return out;
            }
            current_values[query][item] =
                gf::Add(
                    current_coordinates[query][item][0],
                    gf::Add(
                        gf::Mul(
                            u,
                            current_coordinates[query][item]
                                               [1]),
                        gf::Mul(
                            u2,
                            current_coordinates[query][item]
                                               [2])));
        }
        for (uint32_t item = 0;
             item < table.next_width; ++item) {
            if (!next_seen[query][item][0] ||
                !next_seen[query][item][1] ||
                !next_seen[query][item][2]) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "bytecode_next_source_missing";
                return out;
            }
            next_values[query][item] =
                gf::Add(
                    next_coordinates[query][item][0],
                    gf::Add(
                        gf::Mul(
                            u,
                            next_coordinates[query][item][1]),
                        gf::Mul(
                            u2,
                            next_coordinates[query][item]
                                            [2])));
        }
    }
    std::vector<uint32_t> free_rows;
    free_rows.reserve(composition.combined.n_rows);
    for (uint32_t row = 0;
         row < composition.combined.n_rows; ++row) {
        if (!reserved[row]) free_rows.push_back(row);
    }
    const uint64_t rows_needed =
        uint64_t{queries} * (instructions + 1);
    if (rows_needed > free_rows.size()) {
        // Single-node vertical attach cannot absorb the pad. Annotate
        // whether PlanHierarchicalNarrowAggregation closes the same
        // ProgramTable under LDE/column caps (shape only — not an attach).
        const NarrowBytecodeHierarchicalAttachPlanV1 hier =
            PlanNarrowBytecodeHierarchicalAttachV1(
                table, queries);
        out.note =
            "stage3:recursive_fixedpoint:"
            "bytecode_vertical_rows"
            ";needed=" +
            std::to_string(rows_needed) +
            ";free=" +
            std::to_string(free_rows.size()) +
            ";queries=" + std::to_string(queries) +
            ";instructions=" +
            std::to_string(instructions) +
            ";hier_fits=" +
            (hier.hierarchical_fits || hier.single_node_fits
                 ? "1"
                 : "0") +
            ";hier_depth=" + std::to_string(hier.depth) +
            ";hier_nodes=" +
            std::to_string(hier.node_count);
        return out;
    }
    if (!shard_mode) {
        for (uint32_t query = 0;
             query < queries; ++query) {
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                if (!current_seen[query][table.current_width]
                                 [coordinate]) {
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "bytecode_quotient_source_missing";
                    return out;
                }
            }
        }
    }
    std::vector<Fp3> rho_powers(
        table.programs.size(), Fp3::One());
    if (shard_mode) {
        // Weight each shard program by the full-table ordinal so a later
        // L2/L3 join can line up with the parent AIR linearization.
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size(); ++ordinal) {
            const uint32_t global =
                (*shard_global_ordinals)[ordinal];
            Fp3 weight = Fp3::One();
            for (uint32_t i = 0; i < global; ++i) {
                weight = gf::Mul(weight, pi.air_lambda);
            }
            rho_powers[ordinal] = weight;
        }
    } else {
        for (uint32_t ordinal = 1;
             ordinal < table.programs.size(); ++ordinal) {
            rho_powers[ordinal] =
                gf::Mul(
                    rho_powers[ordinal - 1],
                    pi.air_lambda);
        }
    }
    const Fp3 h_last =
        DomainPoint(pi.child_n_rows,
                    pi.child_n_rows - 1);
    const Fp3 coset_shift =
        Fp3::FromFp(aq::kAirCosetShift);
    auto selector_at =
        [&](aq::AirKind kind, const Fp3& y,
            const Fp3& zh) {
            switch (kind) {
            case aq::AirKind::kEverywhere:
                return Fp3::One();
            case aq::AirKind::kTransition:
                return gf::Sub(y, h_last);
            case aq::AirKind::kFirstRow:
                return gf::Mul(
                    zh,
                    gf::Inv(gf::Sub(
                        y, Fp3::One())));
            case aq::AirKind::kLastRow:
                return gf::Mul(
                    zh,
                    gf::Inv(gf::Sub(y, h_last)));
            }
            return Fp3::Zero();
        };
    uint32_t free_cursor = 0;
    for (uint32_t query = 0;
         query < queries; ++query) {
        const Fp3 x =
            DomainPoint(
                pi.child_n_lde,
                pi.query_index[query]);
        const Fp3 y = gf::Mul(coset_shift, x);
        const Fp3 zh =
            gf::Sub(
                PowFp3(y, pi.child_n_rows),
                Fp3::One());
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size();
             ++ordinal) {
            const auto& program =
                table.programs[ordinal];
            const uint32_t register_offset =
                program_offsets[ordinal];
            std::vector<Fp3> registers;
            registers.reserve(
                program.instructions.size());
            for (uint32_t index = 0;
                 index < program.instructions.size();
                 ++index) {
                const auto& instruction =
                    program.instructions[index];
                const uint32_t global_index =
                    register_offset + index;
                const uint32_t row =
                    free_rows[free_cursor++];
                const auto kind = row_kind(
                    instruction.opcode);
                composition.columns[
                    out.layout.RowKind(
                        static_cast<uint32_t>(kind))][row] =
                    Fp3::One();
                Fp3 value = Fp3::Zero();
                uint32_t output_port = 0;
                switch (instruction.opcode) {
                case constraint_bytecode::Opcode::Current:
                case constraint_bytecode::Opcode::Next: {
                    const bool is_next =
                        instruction.opcode ==
                        constraint_bytecode::Opcode::Next;
                    const auto& coordinates =
                        is_next
                        ? next_coordinates[query]
                        : current_coordinates[query];
                    for (uint32_t coordinate = 0;
                         coordinate < 3; ++coordinate) {
                        if (!set_event(
                                row, coordinate,
                                coordinates[instruction.lhs]
                                           [coordinate],
                                source_address(
                                    query, is_next,
                                    instruction.lhs,
                                    coordinate),
                                -1)) {
                            out.note =
                                "stage3:recursive_fixedpoint:"
                                "bytecode_load_event";
                            return out;
                        }
                    }
                    value = is_next
                        ? next_values[query][instruction.lhs]
                        : current_values[query]
                                        [instruction.lhs];
                    output_port = 3;
                    break;
                }
                case constraint_bytecode::Opcode::Challenge:
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "bytecode_challenge_columns_not_attached";
                    return out;
                case constraint_bytecode::Opcode::Constant:
                    value = instruction.constant;
                    composition.columns[
                        out.layout.constant][row] = value;
                    output_port = 0;
                    break;
                case constraint_bytecode::Opcode::Add:
                case constraint_bytecode::Opcode::Sub:
                case constraint_bytecode::Opcode::Mul:
                    if (!set_event(
                            row, 0,
                            registers[instruction.lhs],
                            register_address(
                                query,
                                register_offset +
                                    instruction.lhs),
                            -1) ||
                        !set_event(
                            row, 1,
                            registers[instruction.rhs],
                            register_address(
                                query,
                                register_offset +
                                    instruction.rhs),
                            -1)) {
                        out.note =
                            "stage3:recursive_fixedpoint:"
                            "bytecode_operand_event";
                        return out;
                    }
                    if (instruction.opcode ==
                        constraint_bytecode::Opcode::Add) {
                        value = gf::Add(
                            registers[instruction.lhs],
                            registers[instruction.rhs]);
                    } else if (
                        instruction.opcode ==
                        constraint_bytecode::Opcode::Sub) {
                        value = gf::Sub(
                            registers[instruction.lhs],
                            registers[instruction.rhs]);
                    } else {
                        value = gf::Mul(
                            registers[instruction.lhs],
                            registers[instruction.rhs]);
                    }
                    output_port = 2;
                    break;
                }
                registers.push_back(value);
                const bool result =
                    index + 1 ==
                    program.instructions.size();
                if (result) {
                    composition.columns[
                        out.layout.Value(output_port)][row] =
                        value;
                    composition.columns[
                        out.layout.Value(7)][row] =
                        value;
                    composition.columns[
                        out.layout.result_selector][row] =
                        Fp3::One();
                    composition.columns[
                        out.layout.constraint_weight][row] =
                        gf::Mul(
                            rho_powers[ordinal],
                            selector_at(
                                program.kind, y, zh));
                    ++out.constraint_result_rows;
                } else if (!set_event(
                               row, output_port, value,
                               register_address(
                                   query, global_index),
                               register_reads[
                                   global_index])) {
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "bytecode_output_event";
                    return out;
                }
                ++out.instruction_rows;
            }
        }
        const uint32_t quotient_row =
            free_rows[free_cursor++];
        composition.columns[
            out.layout.RowKind(
                static_cast<uint32_t>(
                    InterpreterRowKind::Quotient))]
                               [quotient_row] =
            Fp3::One();
        if (!shard_mode) {
            Fp3 quotient_value = Fp3::Zero();
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                const Fp3 raw =
                    current_coordinates[query]
                                       [table.current_width]
                                       [coordinate];
                if (!set_event(
                        quotient_row, coordinate, raw,
                        source_address(
                            query, false,
                            table.current_width,
                            coordinate),
                        -1)) {
                    out.note =
                        "stage3:recursive_fixedpoint:"
                        "bytecode_quotient_event";
                    return out;
                }
                quotient_value =
                    coordinate == 0
                    ? raw
                    : gf::Add(
                          quotient_value,
                          gf::Mul(
                              coordinate == 1 ? u : u2,
                              raw));
            }
            composition.columns[
                out.layout.Value(3)][quotient_row] =
                quotient_value;
        }
        // Shard mode: Value(0..3) filled after accumulator as local q.
        composition.columns[
            out.layout.zh][quotient_row] = zh;
        composition.columns[
            out.layout.reset_next][quotient_row] =
            Fp3::One();
        ++out.quotient_rows;
    }
    auto result_value_at =
        [&](uint32_t row) {
            return composition.columns[
                out.layout.Value(7)][row];
        };
    Fp3 constraint_accumulator = Fp3::Zero();
    for (uint32_t row = 0;
         row < composition.combined.n_rows; ++row) {
        composition.columns[
            out.layout.constraint_accumulator][row] =
            constraint_accumulator;
        if (!gf::IsZero(composition.columns[
                out.layout.result_selector][row])) {
            constraint_accumulator = gf::Add(
                constraint_accumulator,
                gf::Mul(
                    composition.columns[
                        out.layout.constraint_weight][row],
                    result_value_at(row)));
        }
        if (!gf::IsZero(composition.columns[
                out.layout.reset_next][row])) {
            constraint_accumulator = Fp3::Zero();
        }
    }
    if (shard_mode) {
        // L1 shard: parent AIR q opening is for the FULL constraint vector.
        // Synthesize local q = accumulator/zh and Fp3 limbs on Value(0..2)
        // so load + quotient_identity close; parent-q binding is later join.
        const uint32_t quotient_kind =
            static_cast<uint32_t>(InterpreterRowKind::Quotient);
        for (uint32_t row = 0;
             row < composition.combined.n_rows; ++row) {
            if (gf::IsZero(composition.columns[
                    out.layout.RowKind(quotient_kind)][row])) {
                continue;
            }
            const Fp3 zh_v =
                composition.columns[out.layout.zh][row];
            if (gf::IsZero(zh_v)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "bytecode_shard_zh_zero";
                return out;
            }
            const Fp3 local_q = gf::Mul(
                composition.columns[
                    out.layout.constraint_accumulator][row],
                gf::Inv(zh_v));
            // load constraint: Value(3) == Value(0)+u*Value(1)+u2*Value(2)
            composition.columns[out.layout.Value(0)][row] =
                Fp3::FromFp(local_q.c0);
            composition.columns[out.layout.Value(1)][row] =
                Fp3::FromFp(local_q.c1);
            composition.columns[out.layout.Value(2)][row] =
                Fp3::FromFp(local_q.c2);
            composition.columns[out.layout.Value(3)][row] =
                local_q;
        }
    }

    std::vector<uint256> value_roots;
    value_roots.reserve(BytecodeBusLayout::kPorts);
    HashWriter precommit;
    precommit <<
        "BTX_RC_STAGE3_BYTECODE_MEMORY_PRECOMMIT_V1";
    precommit << out.program_commitment;
    precommit << composition.prechallenge_commitment;
    precommit << composition.combined.n_rows;
    precommit << queries;
    for (uint32_t port = 0;
         port < BytecodeBusLayout::kPorts; ++port) {
        const uint256 root =
            aq::AirCommittedValuesRoot<Fp3>(
                composition.columns[
                    out.layout.Value(port)],
                composition.combined.n_rows);
        if (root.IsNull()) {
            out.note =
                "stage3:recursive_fixedpoint:"
                "bytecode_value_precommit";
            return out;
        }
        value_roots.push_back(root);
        precommit << root;
    }
    out.prechallenge_commitment = precommit.GetHash();
    auto challenge =
        [&](const char* label) {
            const uint256 digest =
                aq::AirChallengeDigest(
                    out.prechallenge_commitment,
                    label, value_roots,
                    {composition.combined.n_rows,
                     queries, instructions});
            return gf::FromChallengeBytes3(
                digest.data());
        };
    out.challenges.gamma1 =
        challenge("bytecode_memory_gamma1");
    out.challenges.gamma2 =
        challenge("bytecode_memory_gamma2");
    out.challenges.alpha1 =
        challenge("bytecode_memory_alpha1");
    out.challenges.alpha2 =
        challenge("bytecode_memory_alpha2");

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < composition.combined.n_rows; ++row) {
        composition.columns[
            out.layout.running1][row] = running1;
        composition.columns[
            out.layout.running2][row] = running2;
        for (uint32_t port = 0;
             port < BytecodeBusLayout::kPorts; ++port) {
            const Fp3 multiplicity =
                composition.columns[
                    out.layout.Multiplicity(port)][row];
            if (gf::IsZero(multiplicity)) continue;
            const Fp3 value =
                composition.columns[
                    out.layout.Value(port)][row];
            const Fp3 address =
                composition.columns[
                    out.layout.Address(port)][row];
            const Fp3 key1 =
                gf::Add(
                    address,
                    gf::Mul(
                        out.challenges.gamma1, value));
            const Fp3 key2 =
                gf::Add(
                    address,
                    gf::Mul(
                        out.challenges.gamma2, value));
            const Fp3 d1 =
                gf::Sub(out.challenges.alpha1, key1);
            const Fp3 d2 =
                gf::Sub(out.challenges.alpha2, key2);
            if (gf::IsZero(d1) || gf::IsZero(d2)) {
                out.note =
                    "stage3:recursive_fixedpoint:"
                    "bytecode_memory_pole";
                return out;
            }
            const Fp3 inv1 = gf::Inv(d1);
            const Fp3 inv2 = gf::Inv(d2);
            composition.columns[
                out.layout.Inverse1(port)][row] = inv1;
            composition.columns[
                out.layout.Inverse2(port)][row] = inv2;
            running1 = gf::Add(
                running1,
                gf::Mul(multiplicity, inv1));
            running2 = gf::Add(
                running2,
                gf::Mul(multiplicity, inv2));
        }
    }

    for (uint32_t port = 0;
         port < BytecodeBusLayout::kPorts; ++port) {
        for (const uint32_t column : {
                 out.layout.Address(port),
                 out.layout.Multiplicity(port),
                 out.layout.Active(port)}) {
            composition.combined.preprocessed.emplace_back(
                column, composition.columns[column]);
        }
    }
    for (uint32_t kind = 0;
         kind < BytecodeBusLayout::kRowKinds; ++kind) {
        const uint32_t column =
            out.layout.RowKind(kind);
        composition.combined.preprocessed.emplace_back(
            column, composition.columns[column]);
    }
    composition.combined.preprocessed.emplace_back(
        out.layout.constant,
        composition.columns[out.layout.constant]);
    composition.combined.preprocessed.emplace_back(
        out.layout.result_selector,
        composition.columns[out.layout.result_selector]);
    for (const uint32_t column : {
             out.layout.reset_next,
             out.layout.constraint_weight,
             out.layout.zh}) {
        composition.combined.preprocessed.emplace_back(
            column, composition.columns[column]);
    }

    auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)> eval) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree = degree;
            constraint.eval = std::move(eval);
            composition.combined.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t port = 0;
         port < BytecodeBusLayout::kPorts; ++port) {
        add(
            "stage3.fixedpoint.bytecode.memory.inverse1",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout,
             challenges = out.challenges,
             port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 key =
                    gf::Add(
                        cur[layout.Address(port)],
                        gf::Mul(
                            challenges.gamma1,
                            cur[layout.Value(port)]));
                return gf::Sub(
                    cur[layout.Active(port)],
                    gf::Mul(
                        cur[layout.Inverse1(port)],
                        gf::Sub(
                            challenges.alpha1, key)));
            });
        add(
            "stage3.fixedpoint.bytecode.memory.inverse2",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout,
             challenges = out.challenges,
             port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 key =
                    gf::Add(
                        cur[layout.Address(port)],
                        gf::Mul(
                            challenges.gamma2,
                            cur[layout.Value(port)]));
                return gf::Sub(
                    cur[layout.Active(port)],
                    gf::Mul(
                        cur[layout.Inverse2(port)],
                        gf::Sub(
                            challenges.alpha2, key)));
            });
        for (uint32_t kind : {
                 static_cast<uint32_t>(
                     InterpreterRowKind::SourceCurrent),
                 static_cast<uint32_t>(
                     InterpreterRowKind::SourceNext)}) {
            add(
                "stage3.fixedpoint.bytecode.source_alias",
                aq::AirKind::kEverywhere, 3,
                [layout = out.layout, hash_layout,
                 port, kind](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[layout.RowKind(kind)],
                        gf::Mul(
                            cur[layout.Active(port)],
                            gf::Sub(
                                cur[layout.Value(port)],
                                cur[
                                    hash_layout.
                                        absorbed_pin_base +
                                    port])));
                });
        }
    }
    auto running_constraint =
        [layout = out.layout](bool first) {
            return [layout, first](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>& next) {
                Fp3 contribution = Fp3::Zero();
                for (uint32_t port = 0;
                     port < BytecodeBusLayout::kPorts;
                     ++port) {
                    contribution = gf::Add(
                        contribution,
                        gf::Mul(
                            cur[layout.Multiplicity(port)],
                            cur[first
                                    ? layout.Inverse1(port)
                                    : layout.Inverse2(port)]));
                }
                return gf::Sub(
                    next[first
                            ? layout.running1
                            : layout.running2],
                    gf::Add(
                        cur[first
                                ? layout.running1
                                : layout.running2],
                        contribution));
            };
        };
    add(
        "stage3.fixedpoint.bytecode.memory.running1",
        aq::AirKind::kTransition, 2,
        running_constraint(true));
    add(
        "stage3.fixedpoint.bytecode.memory.running2",
        aq::AirKind::kTransition, 2,
        running_constraint(false));
    add(
        "stage3.fixedpoint.bytecode.memory.first1",
        aq::AirKind::kFirstRow, 1,
        [layout = out.layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[layout.running1];
        });
    add(
        "stage3.fixedpoint.bytecode.memory.first2",
        aq::AirKind::kFirstRow, 1,
        [layout = out.layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[layout.running2];
        });
    auto terminal =
        [layout = out.layout](bool first) {
            return [layout, first](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
                Fp3 value =
                    cur[first
                            ? layout.running1
                            : layout.running2];
                for (uint32_t port = 0;
                     port < BytecodeBusLayout::kPorts;
                     ++port) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            cur[layout.Multiplicity(port)],
                            cur[first
                                    ? layout.Inverse1(port)
                                    : layout.Inverse2(port)]));
                }
                return value;
            };
        };
    add(
        "stage3.fixedpoint.bytecode.memory.last1",
        aq::AirKind::kLastRow, 2, terminal(true));
    add(
        "stage3.fixedpoint.bytecode.memory.last2",
        aq::AirKind::kLastRow, 2, terminal(false));
    const uint32_t current_kind =
        static_cast<uint32_t>(
            InterpreterRowKind::Current);
    const uint32_t next_kind =
        static_cast<uint32_t>(
            InterpreterRowKind::Next);
    const uint32_t quotient_kind =
        static_cast<uint32_t>(
            InterpreterRowKind::Quotient);
    for (uint32_t kind : {
             current_kind, next_kind, quotient_kind}) {
        add(
            "stage3.fixedpoint.bytecode.load",
            aq::AirKind::kEverywhere, 2,
            [layout = out.layout, kind, u, u2](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 assembled =
                    gf::Add(
                        cur[layout.Value(0)],
                        gf::Add(
                            gf::Mul(
                                u,
                                cur[layout.Value(1)]),
                            gf::Mul(
                                u2,
                                cur[layout.Value(2)])));
                return gf::Mul(
                    cur[layout.RowKind(kind)],
                    gf::Sub(
                        cur[layout.Value(3)],
                        assembled));
            });
    }
    const uint32_t constant_kind =
        static_cast<uint32_t>(
            InterpreterRowKind::Constant);
    add(
        "stage3.fixedpoint.bytecode.constant",
        aq::AirKind::kEverywhere, 2,
        [layout = out.layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.RowKind(constant_kind)],
                gf::Sub(
                    cur[layout.Value(0)],
                    cur[layout.constant]));
        });
    for (const auto [kind, opcode] :
         std::array<std::pair<uint32_t,
                              constraint_bytecode::Opcode>,
                    3>{
             std::pair{
                 static_cast<uint32_t>(
                     InterpreterRowKind::Add),
                 constraint_bytecode::Opcode::Add},
             std::pair{
                 static_cast<uint32_t>(
                     InterpreterRowKind::Sub),
                 constraint_bytecode::Opcode::Sub},
             std::pair{
                 static_cast<uint32_t>(
                     InterpreterRowKind::Mul),
                 constraint_bytecode::Opcode::Mul}}) {
        add(
            "stage3.fixedpoint.bytecode.binary",
            aq::AirKind::kEverywhere,
            opcode == constraint_bytecode::Opcode::Mul
                ? 3
                : 2,
            [layout = out.layout, kind, opcode](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                Fp3 expected = Fp3::Zero();
                if (opcode ==
                    constraint_bytecode::Opcode::Add) {
                    expected = gf::Add(
                        cur[layout.Value(0)],
                        cur[layout.Value(1)]);
                } else if (
                    opcode ==
                    constraint_bytecode::Opcode::Sub) {
                    expected = gf::Sub(
                        cur[layout.Value(0)],
                        cur[layout.Value(1)]);
                } else {
                    expected = gf::Mul(
                        cur[layout.Value(0)],
                        cur[layout.Value(1)]);
                }
                return gf::Mul(
                    cur[layout.RowKind(kind)],
                    gf::Sub(
                        cur[layout.Value(2)],
                        expected));
            });
    }
    auto selected_result =
        [layout = out.layout](
            const std::vector<Fp3>& cur) {
            return cur[layout.Value(7)];
        };
    for (const auto [kind, port] :
         std::array<std::pair<uint32_t, uint32_t>, 6>{
             std::pair{current_kind, 3U},
             std::pair{next_kind, 3U},
             std::pair{constant_kind, 0U},
             std::pair{
                 static_cast<uint32_t>(
                     InterpreterRowKind::Add),
                 2U},
             std::pair{
                 static_cast<uint32_t>(
                     InterpreterRowKind::Sub),
                 2U},
             std::pair{
                 static_cast<uint32_t>(
                     InterpreterRowKind::Mul),
                 2U}}) {
        add(
            "stage3.fixedpoint.bytecode.result_alias",
            aq::AirKind::kEverywhere, 3,
            [layout = out.layout, kind, port](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[layout.result_selector],
                    gf::Mul(
                        cur[layout.RowKind(kind)],
                        gf::Sub(
                            cur[layout.Value(7)],
                            cur[layout.Value(port)])));
            });
    }
    add(
        "stage3.fixedpoint.bytecode.constraint_accumulator",
        aq::AirKind::kTransition, 4,
        [layout = out.layout, selected_result](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            const Fp3 contribution =
                gf::Mul(
                    cur[layout.result_selector],
                    gf::Mul(
                        cur[layout.constraint_weight],
                        selected_result(cur)));
            return gf::Sub(
                next[layout.constraint_accumulator],
                gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[layout.reset_next]),
                    gf::Add(
                        cur[layout.constraint_accumulator],
                        contribution)));
        });
    add(
        "stage3.fixedpoint.bytecode.constraint_accumulator_first",
        aq::AirKind::kFirstRow, 1,
        [layout = out.layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[layout.constraint_accumulator];
        });
    add(
        "stage3.fixedpoint.bytecode.quotient_identity",
        aq::AirKind::kEverywhere, 3,
        [layout = out.layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.RowKind(quotient_kind)],
                gf::Sub(
                    cur[layout.constraint_accumulator],
                    gf::Mul(
                        cur[layout.Value(3)],
                        cur[layout.zh])));
        });

    out.dual_logup_terminal =
        gf::IsZero(running1) &&
        gf::IsZero(running2);
    out.authenticated_row_memory_bus =
        out.authenticated_source_coordinates > 0;
    out.result_zero_constrained = false;
    out.quotient_opening_equality =
        out.constraint_result_rows ==
            queries * table.programs.size() &&
        out.quotient_rows == queries;
    out.same_trace_relation_cell_logup_export =
        out.authenticated_row_memory_bus &&
        out.dual_logup_terminal;
    out.role_semantic_root_terminal_equality = false;
    out.violations =
        CountHashOpeningViolations(
            composition.combined,
            composition.columns);
    out.valid =
        out.canonical_program &&
        out.authenticated_row_memory_bus &&
        out.dual_logup_terminal &&
        out.quotient_opening_equality &&
        out.violations == 0;
    out.note =
        out.valid
        ? (shard_mode
               ? "stage3:recursive_fixedpoint:"
                 "bytecode_shard_selector_local_quotient_ok"
               : "stage3:recursive_fixedpoint:"
                 "bytecode_table_selector_quotient_ok")
        : "stage3:recursive_fixedpoint:"
          "bytecode_interpreter_violation";
    composition.violations = out.violations;
    composition.valid =
        composition.valid && out.valid;
    composition.deep_per_point_transition_join =
        composition.valid &&
        out.quotient_opening_equality;
    if (!composition.valid) {
        composition.note = out.note;
    }
    (void)old_columns;
    return out;
}

} // namespace

BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreter(
    FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table)
{
    return AttachConstraintBytecodeInterpreterImpl(
        composition, table, nullptr);
}

BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreterShard(
    FoldBusComposition& composition,
    const constraint_bytecode::ProgramTable& table,
    const std::vector<uint32_t>& shard_global_ordinals)
{
    return AttachConstraintBytecodeInterpreterImpl(
        composition, table, &shard_global_ordinals);
}

BytecodeInterpreterAttachment
AttachConstraintBytecodeInterpreter(
    FoldBusComposition& composition,
    const constraint_bytecode::Program& program)
{
    constraint_bytecode::ProgramTable table;
    table.role = program.role;
    table.current_width = program.current_width;
    table.next_width = program.next_width;
    table.programs.push_back(program);
    return AttachConstraintBytecodeInterpreter(
        composition, table);
}

CompleteRecursiveFixedPointResidualInventoryV1
AssessCompleteRecursiveFixedPointResidualInventoryV1()
{
    namespace va = stage3_verifier_air;
    CompleteRecursiveFixedPointResidualInventoryV1 out;
    // Attach APIs measured closed on the DeepCtlParentAir capability path
    // (ProofFieldBus + Deep64 CTL terminal + CTL child verifier in parent).
    out.proof_field_bus_attachable = true;
    out.deep64_ctl_terminal_attachable = true;
    out.ctl_child_verifier_in_parent_air_attachable = true;
    out.ledger_g4_child_fs_replay_closed =
        recursive_parent_air::AssessChildFsReplayClosureV1()
            .closed;
    // Inventoried CompleteFP residual families are closed via living
    // constexprs (payload bus / Split-RAP local / endpoint equality).
    // kCompleteRecursiveFixedPointExecutable stays fail-closed separately.
    out.child_proof_payload_bus_open =
        !va::kVerifierProofRowsBoundInAir;
    out.split_rap_multirow_parent_adapter_open =
        !va::kMultiRowV2SplitRapVerifierAirLocalExecutable;
    // EndpointTerminalEquality closed by
    // kNormalizedEndpointTerminalEqualityExecutable /
    // AttachNormalizedEndpointTerminalEqualityV1.
    out.endpoint_terminal_equality_open =
        !kNormalizedEndpointTerminalEqualityExecutable;
    out.verifier_fiat_shamir_air_chip_open =
        !va::kVerifierFiatShamirAirExecutable;
    out.complete_fp_open = !kCompleteRecursiveFixedPointExecutable;
    // Relation-closure RecursiveChildrenExecutable stays false while
    // CompleteFP is open (CellAudit would invent recursive consumption).
    out.recursive_children_gate_blocked = out.complete_fp_open;
    out.open_residual_families = 0;
    out.open_residual_families +=
        out.child_proof_payload_bus_open ? 1 : 0;
    out.open_residual_families +=
        out.split_rap_multirow_parent_adapter_open ? 1 : 0;
    out.open_residual_families +=
        out.endpoint_terminal_equality_open ? 1 : 0;
    out.valid =
        out.proof_field_bus_attachable &&
        out.deep64_ctl_terminal_attachable &&
        out.ctl_child_verifier_in_parent_air_attachable &&
        out.ledger_g4_child_fs_replay_closed &&
        !out.child_proof_payload_bus_open &&
        !out.split_rap_multirow_parent_adapter_open &&
        !out.endpoint_terminal_equality_open &&
        out.verifier_fiat_shamir_air_chip_open &&
        out.complete_fp_open &&
        out.recursive_children_gate_blocked &&
        out.open_residual_families == 0 &&
        kNormalizedEndpointTerminalEqualityExecutable &&
        !kCompleteRecursiveFixedPointExecutable &&
        !kRecursiveFixedPointConsensusAuthority;
    out.note = out.valid
        ? "stage3:recursive_fixedpoint:"
          "complete_fp_residual_families_closed;"
          "payload_bus_closed;"
          "split_rap_multirow_closed;"
          "endpoint_terminal_equality_closed;"
          "complete_fp_executable_still_false;"
          "verifier_fs_requires_active_config_authority_eligible;"
          "recursive_children_blocked_until_living_parent_consume;"
          "authority=false"
        : "stage3:recursive_fixedpoint:"
          "complete_fp_residual_inventory_incoherent";
    return out;
}

} // namespace matmul::v4::rc::recursive_fixedpoint
