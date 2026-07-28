// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_deep_vm.h>

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_deep_vm {
namespace {

using gf::Fp;
using gf::Fp3;

constexpr Fp kOmega2_32 = 0x185629dcda58878cULL;

Fp PowFp(Fp base, uint64_t exponent)
{
    Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = gf::Mul(out, base);
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp3 PowFp3(Fp3 base, uint64_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = gf::Mul(out, base);
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp OmegaForSize(uint32_t size)
{
    const uint32_t log = std::countr_zero(size);
    return PowFp(kOmega2_32, uint64_t{1} << (32 - log));
}

uint32_t NextPowerOfTwo(uint64_t value)
{
    if (value <= 2) return 2;
    if (value > kMaxOperationRowsV1) return 0;
    return static_cast<uint32_t>(
        std::bit_ceil(static_cast<uint32_t>(value)));
}

bool DigestEq(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    return a == b;
}

abi::SourceKeyV1 Key(
    abi::FieldKindV1 kind,
    uint32_t a = 0,
    uint32_t b = 0,
    uint32_t c = 0,
    uint32_t d = 0,
    uint8_t limb = 0)
{
    return {kind, a, b, c, d, limb};
}

struct AddressBook {
    explicit AddressBook(const abi::DecodedV1& decoded)
    {
        for (const auto& source : decoded.sources) {
            cells.emplace(source.key, &source);
        }
    }

    [[nodiscard]] std::optional<ScalarOriginV1> Field3(
        const abi::SourceKeyV1& base,
        const Fp3& expected) const
    {
        ScalarOriginV1 out;
        out.key = base;
        out.value = expected;
        const std::array<Fp, 3> coordinates{
            gf::Canonical(expected.c0),
            gf::Canonical(expected.c1),
            gf::Canonical(expected.c2)};
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            for (uint8_t limb = 0; limb < 2; ++limb) {
                auto key = base;
                key.d = coordinate;
                key.limb = limb;
                const auto it = cells.find(key);
                if (it == cells.end()) return std::nullopt;
                const uint32_t want = limb == 0
                    ? static_cast<uint32_t>(coordinates[coordinate])
                    : static_cast<uint32_t>(
                          coordinates[coordinate] >> 32);
                if (it->second->value != want) return std::nullopt;
                out.source_addresses[2 * coordinate + limb] =
                    it->second->address;
            }
        }
        out.literal_proof_source = true;
        return out;
    }

    [[nodiscard]] std::optional<uint32_t> U32(
        const abi::SourceKeyV1& key,
        uint32_t expected) const
    {
        const auto it = cells.find(key);
        if (it == cells.end() ||
            it->second->value != expected) {
            return std::nullopt;
        }
        return it->second->address;
    }

    std::map<abi::SourceKeyV1, const abi::SourceCellV1*> cells;
};

struct Row {
    RowKindV1 kind{RowKindV1::Padding};
    uint32_t query{0};
    uint32_t item{0};
    uint32_t source_address{0};
    Fp3 current{};
    Fp3 eval1{};
    Fp3 eval2{};
    Fp3 coefficient{};
    Fp3 x_power{};
    Fp3 z1_power{};
    Fp3 z2_power{};
    Fp3 u_before{};
    Fp3 u_after{};
    Fp3 v1_before{};
    Fp3 v1_after{};
    Fp3 v2_before{};
    Fp3 v2_after{};
    bool deep_start{false};
    bool deep_chain{false};
    Fp3 x{};
    Fp3 z1{};
    Fp3 z2{};
    Fp3 inv1{};
    Fp3 inv2{};
    Fp3 w1{};
    Fp3 w2{};
    Fp3 expected_deep{};
    Fp3 first_fold{};
    cb::Opcode opcode{cb::Opcode::Constant};
    Fp3 lhs{};
    Fp3 rhs{};
    Fp3 result{};
    bool program_end{false};
    bool vm_start{false};
    bool vm_chain{false};
    bool vm_to_quotient{false};
    Fp3 air_lambda{};
    Fp3 lambda_power{};
    Fp3 selector{};
    Fp3 composition_before{};
    Fp3 composition_after{};
    Fp3 y{};
    Fp3 zh{};
    Fp3 quotient{};
    Fp3 quotient_tape_value{};
    bool quotient_tape_deep_consumer{false};
};

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back({name, kind, degree, std::move(eval)});
}

bool Applies(aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition: return row + 1 < rows;
    case aq::AirKind::kFirstRow: return row == 0;
    case aq::AirKind::kLastRow: return row + 1 == rows;
    }
    return false;
}

Fp3 Selector(
    aq::AirKind kind,
    uint32_t rows,
    const Fp3& y)
{
    const Fp omega_rows = OmegaForSize(rows);
    const Fp3 first = Fp3::One();
    const Fp3 last =
        Fp3::FromFp(PowFp(omega_rows, rows - 1));
    const Fp3 zh = gf::Sub(PowFp3(y, rows), Fp3::One());
    const auto zh_over = [&](const Fp3& at) {
        const Fp3 denominator = gf::Sub(y, at);
        return gf::IsZero(denominator)
            ? gf::Mul(
                  Fp3::FromFp(rows),
                  PowFp3(at, rows - 1))
            : gf::Mul(zh, gf::Inv(denominator));
    };
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return Fp3::One();
    case aq::AirKind::kTransition:
        return gf::Sub(y, last);
    case aq::AirKind::kFirstRow:
        return zh_over(first);
    case aq::AirKind::kLastRow:
        return zh_over(last);
    }
    return Fp3::Zero();
}

bool ProgramResult(
    const cb::Program& program,
    const std::vector<Fp3>& current,
    const std::vector<Fp3>& next,
    std::vector<Fp3>& registers,
    std::string* why)
{
    registers.clear();
    registers.reserve(program.instructions.size());
    for (const auto& instruction : program.instructions) {
        Fp3 value = Fp3::Zero();
        switch (instruction.opcode) {
        case cb::Opcode::Current:
            if (instruction.lhs >= current.size()) {
                if (why) *why = "current_load";
                return false;
            }
            value = current[instruction.lhs];
            break;
        case cb::Opcode::Next:
            if (instruction.lhs >= next.size()) {
                if (why) *why = "next_load";
                return false;
            }
            value = next[instruction.lhs];
            break;
        case cb::Opcode::Constant:
            value = instruction.constant;
            break;
        case cb::Opcode::Add:
        case cb::Opcode::Sub:
        case cb::Opcode::Mul:
            if (instruction.lhs >= registers.size() ||
                instruction.rhs >= registers.size()) {
                if (why) *why = "register_load";
                return false;
            }
            if (instruction.opcode == cb::Opcode::Add) {
                value = gf::Add(
                    registers[instruction.lhs],
                    registers[instruction.rhs]);
            } else if (instruction.opcode == cb::Opcode::Sub) {
                value = gf::Sub(
                    registers[instruction.lhs],
                    registers[instruction.rhs]);
            } else {
                value = gf::Mul(
                    registers[instruction.lhs],
                    registers[instruction.rhs]);
            }
            break;
        case cb::Opcode::Challenge:
            if (why) *why = "challenge_program_requires_join";
            return false;
        }
        registers.push_back(value);
    }
    return !registers.empty();
}

std::optional<abi::DecodedV1> DecodeProof(
    const backend::ProofV1& proof,
    std::string* why)
{
    std::vector<uint32_t> words;
    if (!abi::EncodeCanonicalV1(
            proof.envelope, words, nullptr, why)) {
        return std::nullopt;
    }
    return abi::DecodeCanonicalV1(words, why);
}

void Set(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t column,
    uint32_t row,
    const Fp3& value)
{
    columns[column][row] = value;
}

void SetU32(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t column,
    uint32_t row,
    uint32_t value)
{
    Set(columns, column, row, Fp3::FromFp(value));
}

bool RootMatches(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            product.cs, columns, product.preprocessed_columns);
    return session.valid &&
        session.base_row_commitment ==
            product.preprocessed_row_group_root;
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    uint32_t column = 0;
#define BTX_V11_DEEP_VM_COL(name) out.name = column++
    BTX_V11_DEEP_VM_COL(active);
    BTX_V11_DEEP_VM_COL(deep_term);
    BTX_V11_DEEP_VM_COL(deep_finalize);
    BTX_V11_DEEP_VM_COL(vm_instruction);
    BTX_V11_DEEP_VM_COL(quotient_identity);
    BTX_V11_DEEP_VM_COL(query);
    BTX_V11_DEEP_VM_COL(item);
    BTX_V11_DEEP_VM_COL(source_address);
    BTX_V11_DEEP_VM_COL(current_value);
    BTX_V11_DEEP_VM_COL(eval_z1);
    BTX_V11_DEEP_VM_COL(eval_z2);
    BTX_V11_DEEP_VM_COL(coefficient);
    BTX_V11_DEEP_VM_COL(x_power);
    BTX_V11_DEEP_VM_COL(z1_power);
    BTX_V11_DEEP_VM_COL(z2_power);
    BTX_V11_DEEP_VM_COL(u_before);
    BTX_V11_DEEP_VM_COL(u_after);
    BTX_V11_DEEP_VM_COL(v1_before);
    BTX_V11_DEEP_VM_COL(v1_after);
    BTX_V11_DEEP_VM_COL(v2_before);
    BTX_V11_DEEP_VM_COL(v2_after);
    BTX_V11_DEEP_VM_COL(u_weight);
    BTX_V11_DEEP_VM_COL(u_contribution);
    BTX_V11_DEEP_VM_COL(v1_weight);
    BTX_V11_DEEP_VM_COL(v1_contribution);
    BTX_V11_DEEP_VM_COL(v2_weight);
    BTX_V11_DEEP_VM_COL(v2_contribution);
    BTX_V11_DEEP_VM_COL(deep_start);
    BTX_V11_DEEP_VM_COL(deep_chain);
    BTX_V11_DEEP_VM_COL(x);
    BTX_V11_DEEP_VM_COL(z1);
    BTX_V11_DEEP_VM_COL(z2);
    BTX_V11_DEEP_VM_COL(inv_x_minus_z1);
    BTX_V11_DEEP_VM_COL(inv_x_minus_z2);
    BTX_V11_DEEP_VM_COL(w1);
    BTX_V11_DEEP_VM_COL(w2);
    BTX_V11_DEEP_VM_COL(expected_deep);
    BTX_V11_DEEP_VM_COL(first_fold_value);
    BTX_V11_DEEP_VM_COL(inv_product1);
    BTX_V11_DEEP_VM_COL(inv_product2);
    BTX_V11_DEEP_VM_COL(deep_diff_inv1);
    BTX_V11_DEEP_VM_COL(deep_rhs_term1);
    BTX_V11_DEEP_VM_COL(deep_diff_inv2);
    BTX_V11_DEEP_VM_COL(deep_rhs_term2);
    BTX_V11_DEEP_VM_COL(deep_rhs);
    BTX_V11_DEEP_VM_COL(op_current);
    BTX_V11_DEEP_VM_COL(op_next);
    BTX_V11_DEEP_VM_COL(op_constant);
    BTX_V11_DEEP_VM_COL(op_add);
    BTX_V11_DEEP_VM_COL(op_sub);
    BTX_V11_DEEP_VM_COL(op_mul);
    BTX_V11_DEEP_VM_COL(operand_lhs);
    BTX_V11_DEEP_VM_COL(operand_rhs);
    BTX_V11_DEEP_VM_COL(instruction_result);
    BTX_V11_DEEP_VM_COL(mul_product);
    BTX_V11_DEEP_VM_COL(program_end);
    BTX_V11_DEEP_VM_COL(vm_start);
    BTX_V11_DEEP_VM_COL(vm_chain);
    BTX_V11_DEEP_VM_COL(vm_to_quotient);
    BTX_V11_DEEP_VM_COL(air_lambda);
    BTX_V11_DEEP_VM_COL(lambda_power);
    BTX_V11_DEEP_VM_COL(selector);
    BTX_V11_DEEP_VM_COL(selected_result);
    BTX_V11_DEEP_VM_COL(lambda_selected);
    BTX_V11_DEEP_VM_COL(program_contribution);
    BTX_V11_DEEP_VM_COL(lambda_delta);
    BTX_V11_DEEP_VM_COL(lambda_after);
    BTX_V11_DEEP_VM_COL(composition_before);
    BTX_V11_DEEP_VM_COL(composition_after);
    BTX_V11_DEEP_VM_COL(y);
    BTX_V11_DEEP_VM_COL(zh);
    BTX_V11_DEEP_VM_COL(quotient_value);
    BTX_V11_DEEP_VM_COL(quotient_product);
    BTX_V11_DEEP_VM_COL(quotient_tape_value);
    BTX_V11_DEEP_VM_COL(quotient_tape_deep_consumer);
    for (auto& limb : out.quotient_tape_limb) {
        limb = column++;
    }
    for (auto& limb_bits : out.quotient_tape_bit) {
        for (auto& bit : limb_bits) {
            bit = column++;
        }
    }
    for (auto& flag : out.quotient_high_is_max) {
        flag = column++;
    }
    for (auto& inverse :
         out.quotient_high_delta_inverse) {
        inverse = column++;
    }
    BTX_V11_DEEP_VM_COL(quotient_tape_accept);
#undef BTX_V11_DEEP_VM_COL
    out.n_columns = column;
    return out;
}

ProductV1 BuildProductV1(
    const backend::ProofV1& proof,
    const tp::ReceiptV1& transcript,
    const cb::ProgramTable& table,
    const alg_hash::Digest& expected_program_root,
    uint32_t first_query,
    uint32_t query_count)
{
    ProductV1 out;
    out.layout = CanonicalLayoutV1();
    out.first_query = first_query;
    out.query_count = query_count;
    out.program_root = cb::CommitProgramTableAlgHash(table);
    const auto fail = [&](const std::string& reason) {
        out.note = "stage3:v11_deep_vm:" + reason;
        out.valid = false;
        return out;
    };

    std::string why;
    auto decoded = DecodeProof(proof, &why);
    if (!decoded.has_value()) return fail("decode:" + why);
    out.canonical_abi =
        decoded->canonical && decoded->complete &&
        decoded->addresses_unique &&
        decoded->semantic_keys_unique;
    if (!out.canonical_abi) return fail("canonical_abi");

    tp::ReceiptV1 backend_receipt;
    out.backend_proof_verified =
        backend::VerifyV1(proof, &backend_receipt, &why);
    if (!out.backend_proof_verified) {
        return fail("backend:" + why);
    }
    // VerifyV1 already replays the exact statement and returns its receipt.
    // Equality below prevents a caller from supplying a different valid
    // transcript for another statement.
    const auto receipt_equal =
        backend_receipt.shape_commit == transcript.shape_commit &&
        gf::Eq(backend_receipt.air_lambda, transcript.air_lambda) &&
        backend_receipt.fri_seed == transcript.fri_seed &&
        backend_receipt.ood_eval_commit == transcript.ood_eval_commit &&
        backend_receipt.batch_seed == transcript.batch_seed &&
        backend_receipt.query_seed == transcript.query_seed &&
        gf::Eq(backend_receipt.z1, transcript.z1) &&
        gf::Eq(backend_receipt.z2, transcript.z2) &&
        gf::Eq(backend_receipt.w1, transcript.w1) &&
        gf::Eq(backend_receipt.w2, transcript.w2) &&
        backend_receipt.z1_selected == transcript.z1_selected &&
        backend_receipt.z2_selected == transcript.z2_selected &&
        backend_receipt.batching_coefficients.size() ==
            transcript.batching_coefficients.size() &&
        backend_receipt.fold_challenges.size() ==
            transcript.fold_challenges.size();
    if (!receipt_equal) return fail("transcript_receipt_mismatch");
    for (uint32_t q = 0; q < abi::kQueryCountV11; ++q) {
        const auto& a = backend_receipt.queries[q];
        const auto& b = transcript.queries[q];
        if (a.selected_ordinal != b.selected_ordinal ||
            a.index != b.index ||
            a.candidate_digest != b.candidate_digest) {
            return fail("query_receipt_mismatch");
        }
    }
    for (uint32_t i = 0;
         i < backend_receipt.batching_coefficients.size(); ++i) {
        if (!gf::Eq(
                backend_receipt.batching_coefficients[i],
                transcript.batching_coefficients[i])) {
            return fail("batch_coefficient_mismatch");
        }
    }
    for (uint32_t i = 0;
         i < backend_receipt.fold_challenges.size(); ++i) {
        if (!gf::Eq(
                backend_receipt.fold_challenges[i],
                transcript.fold_challenges[i])) {
            return fail("fold_challenge_mismatch");
        }
    }
    out.transcript_receipt_verified = true;

    if (!cb::ValidateProgramTable(table, &why) ||
        table.current_width != decoded->envelope.trace_columns ||
        table.next_width != decoded->envelope.trace_columns ||
        table.challenge_width != 0 ||
        !DigestEq(out.program_root, expected_program_root)) {
        return fail("program_table_or_root:" + why);
    }
    out.exact_program_root_checked = true;

    const auto& split = decoded->envelope.split;
    const auto& batch = split.batch;
    if (first_query > batch.queries.size() ||
        query_count == 0 ||
        query_count > batch.queries.size() - first_query ||
        batch.queries.size() != abi::kQueryCountV11 ||
        split.next_trace_group_rows.size() != batch.queries.size() ||
        batch.groups.size() != 3 ||
        batch.column_len.size() !=
            decoded->envelope.trace_columns + 1 ||
        transcript.batching_coefficients.size() !=
            batch.column_len.size()) {
        return fail("query_or_batch_shape");
    }

    out.parent_consumer_refs =
        mf::BuildParentConsumerCellRefsV1(*decoded);
    if (out.parent_consumer_refs.empty()) {
        return fail("parent_consumer_refs");
    }
    AddressBook addresses(*decoded);
    std::vector<uint8_t> is_base(
        decoded->envelope.trace_columns, 0);
    for (uint32_t column : split.base_column_indices) {
        if (column >= is_base.size() || is_base[column]) {
            return fail("base_columns");
        }
        is_base[column] = 1;
    }
    std::vector<uint32_t> dependent;
    for (uint32_t column = 0; column < is_base.size(); ++column) {
        if (!is_base[column]) dependent.push_back(column);
    }
    if (batch.groups[0].column_count !=
            split.base_column_indices.size() ||
        batch.groups[1].column_count != dependent.size() ||
        batch.groups[2].column_count != 1) {
        return fail("group_width");
    }

    const auto add_origin = [&](const abi::SourceKeyV1& key,
                                const Fp3& value,
                                std::vector<ScalarOriginV1>& origins)
        -> std::optional<ScalarOriginV1> {
        auto origin = addresses.Field3(key, value);
        if (origin.has_value()) origins.push_back(*origin);
        return origin;
    };
    if (!add_origin(
            Key(abi::FieldKindV1::AirConstraintLambda),
            split.air_constraint_lambda,
            out.scalar_origins) ||
        !add_origin(
            Key(abi::FieldKindV1::Z1), batch.z1,
            out.scalar_origins) ||
        !add_origin(
            Key(abi::FieldKindV1::Z2), batch.z2,
            out.scalar_origins) ||
        !add_origin(
            Key(abi::FieldKindV1::DeepWeight1), batch.w1,
            out.scalar_origins) ||
        !add_origin(
            Key(abi::FieldKindV1::DeepWeight2), batch.w2,
            out.scalar_origins)) {
        return fail("global_scalar_source");
    }
    for (uint32_t column = 0; column < batch.column_len.size(); ++column) {
        if (!add_origin(
                Key(abi::FieldKindV1::EvalZ1, column),
                batch.evals_z1[column], out.scalar_origins) ||
            !add_origin(
                Key(abi::FieldKindV1::EvalZ2, column),
                batch.evals_z2[column], out.scalar_origins)) {
            return fail("ood_eval_source");
        }
    }

    const uint32_t n_lde = batch.n_coeffs * batch.blowup;
    if (n_lde == 0 ||
        (n_lde & (n_lde - 1)) != 0 ||
        split.trace_rows == 0 ||
        n_lde % split.trace_rows != 0) {
        return fail("lde_domain");
    }
    const Fp omega_lde = OmegaForSize(n_lde);
    const Fp3 coset =
        Fp3::FromFp(aq::kAirCosetShift);
    std::vector<Row> rows;
    uint32_t duplicate_queries = 0;
    std::set<uint32_t> seen_queries;

    for (uint32_t q = first_query;
         q < first_query + query_count; ++q) {
        const size_t query_first_row =
            rows.size();
        const auto& query = batch.queries[q];
        if (!seen_queries.insert(query.index).second) {
            ++duplicate_queries;
        }
        const auto query_address =
            addresses.U32(
                Key(abi::FieldKindV1::QueryIndex, q),
                query.index);
        if (!query_address.has_value() ||
            query.index != transcript.queries[q].index) {
            return fail("query_index_source");
        }

        std::vector<Fp3> current(
            decoded->envelope.trace_columns, Fp3::Zero());
        std::vector<Fp3> next(
            decoded->envelope.trace_columns, Fp3::Zero());
        for (uint32_t i = 0;
             i < split.base_column_indices.size(); ++i) {
            const uint32_t column = split.base_column_indices[i];
            current[column] = query.group_rows[0].values[i];
            next[column] =
                split.next_trace_group_rows[q][0].values[i];
            if (!add_origin(
                    Key(abi::FieldKindV1::QueryRowValue, q, 0, i),
                    current[column], out.scalar_origins) ||
                !add_origin(
                    Key(abi::FieldKindV1::NextRowValue, q, 0, i),
                    next[column], out.scalar_origins)) {
                return fail("base_trace_source");
            }
        }
        for (uint32_t i = 0; i < dependent.size(); ++i) {
            const uint32_t column = dependent[i];
            current[column] = query.group_rows[1].values[i];
            next[column] =
                split.next_trace_group_rows[q][1].values[i];
            if (!add_origin(
                    Key(abi::FieldKindV1::QueryRowValue, q, 1, i),
                    current[column], out.scalar_origins) ||
                !add_origin(
                    Key(abi::FieldKindV1::NextRowValue, q, 1, i),
                    next[column], out.scalar_origins)) {
                return fail("dependent_trace_source");
            }
        }
        const Fp3 quotient =
            query.group_rows[2].values[0];
        const auto quotient_origin = add_origin(
            Key(abi::FieldKindV1::QueryRowValue, q, 2, 0),
            quotient, out.scalar_origins);
        if (!quotient_origin) return fail("quotient_source");
        for (uint32_t limb = 1;
             limb < kFp3TapeLimbsV1;
             ++limb) {
            if (quotient_origin->source_addresses[limb] !=
                quotient_origin->source_addresses[0] + limb) {
                return fail("quotient_tape_offsets");
            }
        }

        std::vector<Fp3> entire_row;
        entire_row.reserve(batch.column_len.size());
        entire_row.insert(
            entire_row.end(),
            query.group_rows[0].values.begin(),
            query.group_rows[0].values.end());
        entire_row.insert(
            entire_row.end(),
            query.group_rows[1].values.begin(),
            query.group_rows[1].values.end());
        entire_row.push_back(quotient);
        if (entire_row.size() != batch.column_len.size()) {
            return fail("entire_row");
        }

        // The FRI batch evaluates the already coset-shifted coefficient
        // vectors on the ordinary n_lde subgroup, so DEEP uses x=omega^i.
        // The AIR quotient identity evaluates the underlying trace at
        // y=g*omega^i and therefore applies the coset shift separately.
        const Fp3 x = Fp3::FromFp(
            PowFp(omega_lde, query.index));
        Fp3 u = Fp3::Zero();
        Fp3 v1 = Fp3::Zero();
        Fp3 v2 = Fp3::Zero();
        for (uint32_t column = 0;
             column < entire_row.size(); ++column) {
            const uint32_t shift =
                batch.n_coeffs - batch.column_len[column];
            Row row;
            row.kind = RowKindV1::DeepTerm;
            row.query = q;
            row.item = column;
            row.current = entire_row[column];
            row.eval1 = batch.evals_z1[column];
            row.eval2 = batch.evals_z2[column];
            row.coefficient =
                transcript.batching_coefficients[column];
            row.x_power = PowFp3(x, shift);
            row.z1_power = PowFp3(batch.z1, shift);
            row.z2_power = PowFp3(batch.z2, shift);
            row.u_before = u;
            row.v1_before = v1;
            row.v2_before = v2;
            u = gf::Add(
                u,
                gf::Mul(
                    row.coefficient,
                    gf::Mul(row.x_power, row.current)));
            v1 = gf::Add(
                v1,
                gf::Mul(
                    row.coefficient,
                    gf::Mul(row.z1_power, row.eval1)));
            v2 = gf::Add(
                v2,
                gf::Mul(
                    row.coefficient,
                    gf::Mul(row.z2_power, row.eval2)));
            row.u_after = u;
            row.v1_after = v1;
            row.v2_after = v2;
            row.deep_start = column == 0;
            row.deep_chain = true;
            if (column + 1 == entire_row.size()) {
                row.source_address =
                    quotient_origin->source_addresses[0];
            } else {
                const uint32_t group =
                    column < batch.groups[0].column_count ? 0 : 1;
                const uint32_t item = group == 0
                    ? column
                    : column - batch.groups[0].column_count;
                const auto origin = addresses.Field3(
                    Key(
                        abi::FieldKindV1::QueryRowValue,
                        q, group, item),
                    entire_row[column]);
                if (!origin) return fail("deep_current_source");
                row.source_address =
                    origin->source_addresses[0];
            }
            rows.push_back(row);
            ++out.deep_term_rows;

            ScalarOriginV1 derived;
            derived.value = row.coefficient;
            derived.transcript_derived_root_pin = true;
            out.scalar_origins.push_back(derived);
        }

        if (query.steps.empty()) return fail("first_fold_missing");
        const uint32_t half =
            batch.fold_layers[0].n_leaves / 2;
        const bool odd = query.index >= half;
        const Fp3 first_fold = odd
            ? query.steps[0].odd
            : query.steps[0].even;
        const auto first_origin = add_origin(
            Key(
                odd ? abi::FieldKindV1::QueryStepOdd
                    : abi::FieldKindV1::QueryStepEven,
                q, 0),
            first_fold, out.scalar_origins);
        if (!first_origin) return fail("first_fold_source");
        const Fp3 denominator1 = gf::Sub(x, batch.z1);
        const Fp3 denominator2 = gf::Sub(x, batch.z2);
        if (gf::IsZero(denominator1) ||
            gf::IsZero(denominator2)) {
            return fail("deep_denominator_zero");
        }
        const Fp3 expected_deep = gf::Add(
            gf::Mul(
                batch.w1,
                gf::Mul(
                    gf::Sub(u, v1),
                    gf::Inv(denominator1))),
            gf::Mul(
                batch.w2,
                gf::Mul(
                    gf::Sub(u, v2),
                    gf::Inv(denominator2))));
        Row final;
        final.kind = RowKindV1::DeepFinalize;
        final.query = q;
        final.source_address =
            first_origin->source_addresses[0];
        final.u_before = u;
        final.v1_before = v1;
        final.v2_before = v2;
        final.x = x;
        final.z1 = batch.z1;
        final.z2 = batch.z2;
        final.inv1 = gf::Inv(denominator1);
        final.inv2 = gf::Inv(denominator2);
        final.w1 = batch.w1;
        final.w2 = batch.w2;
        final.expected_deep = expected_deep;
        final.first_fold = first_fold;
        rows.push_back(final);

        const Fp3 y = gf::Mul(coset, x);
        const Fp3 zh =
            gf::Sub(PowFp3(y, split.trace_rows), Fp3::One());
        Fp3 composition = Fp3::Zero();
        Fp3 lambda_power = Fp3::One();
        bool first_vm = true;
        for (uint32_t p = 0; p < table.programs.size(); ++p) {
            const auto& program = table.programs[p];
            std::vector<Fp3> registers;
            if (!ProgramResult(
                    program, current, next,
                    registers, &why)) {
                return fail("program:" + why);
            }
            const Fp3 selector =
                Selector(program.kind, split.trace_rows, y);
            for (uint32_t instruction_index = 0;
                 instruction_index < program.instructions.size();
                 ++instruction_index) {
                const auto& instruction =
                    program.instructions[instruction_index];
                Row vm;
                vm.kind = RowKindV1::VmInstruction;
                vm.query = q;
                vm.item = instruction_index;
                vm.opcode = instruction.opcode;
                vm.result = registers[instruction_index];
                vm.program_end =
                    instruction_index + 1 ==
                    program.instructions.size();
                vm.vm_start = first_vm;
                vm.air_lambda = split.air_constraint_lambda;
                vm.lambda_power = lambda_power;
                vm.selector = selector;
                vm.composition_before = composition;
                if (instruction.opcode == cb::Opcode::Current) {
                    vm.lhs = current[instruction.lhs];
                    const uint32_t column = instruction.lhs;
                    const auto base_it = std::find(
                        split.base_column_indices.begin(),
                        split.base_column_indices.end(), column);
                    uint32_t group = 0;
                    uint32_t item = 0;
                    if (base_it !=
                        split.base_column_indices.end()) {
                        item = static_cast<uint32_t>(
                            base_it -
                            split.base_column_indices.begin());
                    } else {
                        group = 1;
                        const auto dep_it = std::find(
                            dependent.begin(),
                            dependent.end(), column);
                        if (dep_it == dependent.end()) {
                            return fail("current_column_map");
                        }
                        item = static_cast<uint32_t>(
                            dep_it - dependent.begin());
                    }
                    const auto origin = addresses.Field3(
                        Key(
                            abi::FieldKindV1::QueryRowValue,
                            q, group, item),
                        vm.lhs);
                    if (!origin) return fail("vm_current_source");
                    vm.source_address =
                        origin->source_addresses[0];
                } else if (instruction.opcode == cb::Opcode::Next) {
                    vm.lhs = next[instruction.lhs];
                    const uint32_t column = instruction.lhs;
                    const auto base_it = std::find(
                        split.base_column_indices.begin(),
                        split.base_column_indices.end(), column);
                    uint32_t group = 0;
                    uint32_t item = 0;
                    if (base_it !=
                        split.base_column_indices.end()) {
                        item = static_cast<uint32_t>(
                            base_it -
                            split.base_column_indices.begin());
                    } else {
                        group = 1;
                        const auto dep_it = std::find(
                            dependent.begin(),
                            dependent.end(), column);
                        if (dep_it == dependent.end()) {
                            return fail("next_column_map");
                        }
                        item = static_cast<uint32_t>(
                            dep_it - dependent.begin());
                    }
                    const auto origin = addresses.Field3(
                        Key(
                            abi::FieldKindV1::NextRowValue,
                            q, group, item),
                        vm.lhs);
                    if (!origin) return fail("vm_next_source");
                    vm.source_address =
                        origin->source_addresses[0];
                } else if (
                    instruction.opcode ==
                    cb::Opcode::Constant) {
                    vm.lhs = instruction.constant;
                } else {
                    vm.lhs = registers[instruction.lhs];
                    vm.rhs = registers[instruction.rhs];
                }
                vm.composition_after = composition;
                if (vm.program_end) {
                    composition = gf::Add(
                        composition,
                        gf::Mul(
                            lambda_power,
                            gf::Mul(selector, vm.result)));
                    vm.composition_after = composition;
                    lambda_power = gf::Mul(
                        lambda_power,
                        split.air_constraint_lambda);
                }
                vm.vm_chain =
                    !(p + 1 == table.programs.size() &&
                      vm.program_end);
                vm.vm_to_quotient =
                    p + 1 == table.programs.size() &&
                    vm.program_end;
                rows.push_back(vm);
                ++out.vm_instruction_rows;
                first_vm = false;
            }
        }

        Row quotient_row;
        quotient_row.kind =
            RowKindV1::QuotientIdentity;
        quotient_row.query = q;
        quotient_row.source_address =
            quotient_origin->source_addresses[0];
        quotient_row.composition_before = composition;
        quotient_row.y = y;
        quotient_row.zh = zh;
        quotient_row.quotient = quotient;
        rows.push_back(quotient_row);
        ++out.quotient_rows;
        for (size_t row = query_first_row;
             row < rows.size();
            ++row) {
            rows[row].quotient_tape_value =
                quotient;
            rows[row].quotient_tape_deep_consumer =
                rows[row].kind ==
                    RowKindV1::DeepTerm &&
                rows[row].source_address ==
                    quotient_origin->source_addresses[0];
        }
        if (!gf::Eq(
                composition, gf::Mul(zh, quotient))) {
            return fail("native_quotient_identity");
        }
    }

    out.real_rows = static_cast<uint32_t>(rows.size());
    out.trace_rows = NextPowerOfTwo(rows.size());
    if (out.trace_rows == 0) return fail("operation_rows");
    rows.resize(out.trace_rows);
    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns = out.layout.n_columns;
    out.columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(out.trace_rows, Fp3::Zero()));

    const auto& l = out.layout;
    for (uint32_t row = 0; row < out.real_rows; ++row) {
        const auto& r = rows[row];
        Set(out.columns, l.active, row, Fp3::One());
        SetU32(out.columns, l.query, row, r.query);
        SetU32(out.columns, l.item, row, r.item);
        SetU32(
            out.columns, l.source_address, row,
            r.source_address);
        Set(
            out.columns, l.deep_term, row,
            r.kind == RowKindV1::DeepTerm
                ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.deep_finalize, row,
            r.kind == RowKindV1::DeepFinalize
                ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.vm_instruction, row,
            r.kind == RowKindV1::VmInstruction
                ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.quotient_identity, row,
            r.kind == RowKindV1::QuotientIdentity
                ? Fp3::One() : Fp3::Zero());
#define BTX_SET(field, member) \
        Set(out.columns, l.field, row, r.member)
        BTX_SET(current_value, current);
        BTX_SET(eval_z1, eval1);
        BTX_SET(eval_z2, eval2);
        BTX_SET(coefficient, coefficient);
        BTX_SET(x_power, x_power);
        BTX_SET(z1_power, z1_power);
        BTX_SET(z2_power, z2_power);
        BTX_SET(u_before, u_before);
        BTX_SET(u_after, u_after);
        BTX_SET(v1_before, v1_before);
        BTX_SET(v1_after, v1_after);
        BTX_SET(v2_before, v2_before);
        BTX_SET(v2_after, v2_after);
        Set(
            out.columns, l.u_weight, row,
            gf::Mul(r.coefficient, r.x_power));
        Set(
            out.columns, l.u_contribution, row,
            gf::Mul(
                out.columns[l.u_weight][row],
                r.current));
        Set(
            out.columns, l.v1_weight, row,
            gf::Mul(r.coefficient, r.z1_power));
        Set(
            out.columns, l.v1_contribution, row,
            gf::Mul(
                out.columns[l.v1_weight][row],
                r.eval1));
        Set(
            out.columns, l.v2_weight, row,
            gf::Mul(r.coefficient, r.z2_power));
        Set(
            out.columns, l.v2_contribution, row,
            gf::Mul(
                out.columns[l.v2_weight][row],
                r.eval2));
        BTX_SET(x, x);
        BTX_SET(z1, z1);
        BTX_SET(z2, z2);
        BTX_SET(inv_x_minus_z1, inv1);
        BTX_SET(inv_x_minus_z2, inv2);
        BTX_SET(w1, w1);
        BTX_SET(w2, w2);
        BTX_SET(expected_deep, expected_deep);
        BTX_SET(first_fold_value, first_fold);
        Set(
            out.columns, l.inv_product1, row,
            gf::Mul(
                gf::Sub(r.x, r.z1), r.inv1));
        Set(
            out.columns, l.inv_product2, row,
            gf::Mul(
                gf::Sub(r.x, r.z2), r.inv2));
        Set(
            out.columns, l.deep_diff_inv1, row,
            gf::Mul(
                gf::Sub(r.u_before, r.v1_before),
                r.inv1));
        Set(
            out.columns, l.deep_rhs_term1, row,
            gf::Mul(
                r.w1,
                out.columns[
                    l.deep_diff_inv1][row]));
        Set(
            out.columns, l.deep_diff_inv2, row,
            gf::Mul(
                gf::Sub(r.u_before, r.v2_before),
                r.inv2));
        Set(
            out.columns, l.deep_rhs_term2, row,
            gf::Mul(
                r.w2,
                out.columns[
                    l.deep_diff_inv2][row]));
        Set(
            out.columns, l.deep_rhs, row,
            gf::Add(
                out.columns[
                    l.deep_rhs_term1][row],
                out.columns[
                    l.deep_rhs_term2][row]));
        BTX_SET(operand_lhs, lhs);
        BTX_SET(operand_rhs, rhs);
        BTX_SET(instruction_result, result);
        Set(
            out.columns, l.mul_product, row,
            gf::Mul(r.lhs, r.rhs));
        BTX_SET(air_lambda, air_lambda);
        BTX_SET(lambda_power, lambda_power);
        BTX_SET(selector, selector);
        Set(
            out.columns, l.selected_result, row,
            gf::Mul(r.selector, r.result));
        Set(
            out.columns, l.lambda_selected, row,
            gf::Mul(
                r.lambda_power,
                out.columns[
                    l.selected_result][row]));
        Set(
            out.columns, l.program_contribution,
            row,
            gf::Mul(
                r.program_end
                    ? Fp3::One()
                    : Fp3::Zero(),
                out.columns[
                    l.lambda_selected][row]));
        Set(
            out.columns, l.lambda_delta, row,
            gf::Mul(
                r.program_end
                    ? Fp3::One()
                    : Fp3::Zero(),
                gf::Sub(
                    r.air_lambda,
                    Fp3::One())));
        Set(
            out.columns, l.lambda_after, row,
            gf::Mul(
                r.lambda_power,
                gf::Add(
                    Fp3::One(),
                    out.columns[
                        l.lambda_delta][row])));
        BTX_SET(composition_before, composition_before);
        BTX_SET(composition_after, composition_after);
        BTX_SET(y, y);
        BTX_SET(zh, zh);
        BTX_SET(quotient_value, quotient);
        Set(
            out.columns, l.quotient_product, row,
            gf::Mul(r.zh, r.quotient));
        Set(
            out.columns, l.quotient_tape_value,
            row, r.quotient_tape_value);
        Set(
            out.columns,
            l.quotient_tape_deep_consumer, row,
            r.quotient_tape_deep_consumer
                ? Fp3::One() : Fp3::Zero());
        const std::array<uint64_t, kFp3CoordinatesV1>
            quotient_coordinates{{
                gf::Canonical(
                    r.quotient_tape_value.c0),
                gf::Canonical(
                    r.quotient_tape_value.c1),
                gf::Canonical(
                    r.quotient_tape_value.c2),
            }};
        for (uint32_t coordinate = 0;
             coordinate < kFp3CoordinatesV1;
             ++coordinate) {
            const uint32_t low =
                static_cast<uint32_t>(
                    quotient_coordinates[coordinate]);
            const uint32_t high =
                static_cast<uint32_t>(
                    quotient_coordinates[coordinate] >> 32);
            const std::array<uint32_t, 2> limbs{{low, high}};
            for (uint32_t half = 0; half < 2; ++half) {
                const uint32_t limb =
                    2 * coordinate + half;
                SetU32(
                    out.columns,
                    l.quotient_tape_limb[limb],
                    row, limbs[half]);
                for (uint32_t bit = 0;
                     bit < kU32TapeBitsV1;
                     ++bit) {
                    SetU32(
                        out.columns,
                        l.quotient_tape_bit[limb][bit],
                        row,
                        (limbs[half] >> bit) & 1U);
                }
            }
            const bool high_is_max =
                high == std::numeric_limits<uint32_t>::max();
            SetU32(
                out.columns,
                l.quotient_high_is_max[coordinate],
                row, high_is_max ? 1U : 0U);
            if (!high_is_max) {
                const Fp3 high_delta = gf::Sub(
                    Fp3::FromFp(high),
                    Fp3::FromFp(
                        std::numeric_limits<uint32_t>::max()));
                Set(
                    out.columns,
                    l.quotient_high_delta_inverse[coordinate],
                    row, gf::Inv(high_delta));
            }
        }
        Set(
            out.columns, l.quotient_tape_accept, row,
            r.kind == RowKindV1::QuotientIdentity
                ? Fp3::One() : Fp3::Zero());
#undef BTX_SET
        Set(
            out.columns, l.deep_start, row,
            r.deep_start ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.deep_chain, row,
            r.deep_chain ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.program_end, row,
            r.program_end ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.vm_start, row,
            r.vm_start ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.vm_chain, row,
            r.vm_chain ? Fp3::One() : Fp3::Zero());
        Set(
            out.columns, l.vm_to_quotient, row,
            r.vm_to_quotient ? Fp3::One() : Fp3::Zero());
        const std::array<std::pair<cb::Opcode, uint32_t>, 6> ops{{
            {cb::Opcode::Current, l.op_current},
            {cb::Opcode::Next, l.op_next},
            {cb::Opcode::Constant, l.op_constant},
            {cb::Opcode::Add, l.op_add},
            {cb::Opcode::Sub, l.op_sub},
            {cb::Opcode::Mul, l.op_mul},
        }};
        for (const auto& [opcode, column] : ops) {
            Set(
                out.columns, column, row,
                r.kind == RowKindV1::VmInstruction &&
                        r.opcode == opcode
                    ? Fp3::One() : Fp3::Zero());
        }
    }
    const Fp3 zero_high_delta = gf::Sub(
        Fp3::Zero(),
        Fp3::FromFp(
            std::numeric_limits<uint32_t>::max()));
    const Fp3 zero_high_delta_inverse =
        gf::Inv(zero_high_delta);
    for (uint32_t row = out.real_rows;
         row < out.trace_rows;
         ++row) {
        for (uint32_t coordinate = 0;
             coordinate < kFp3CoordinatesV1;
             ++coordinate) {
            Set(
                out.columns,
                l.quotient_high_delta_inverse[
                    coordinate],
                row, zero_high_delta_inverse);
        }
    }

    const auto binary = [&](uint32_t column) {
        AddConstraint(
            out.cs, "stage3.v11.deep_vm.boolean",
            aq::AirKind::kEverywhere, 2,
            [column](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[column],
                    gf::Sub(cur[column], Fp3::One()));
            });
    };
    const std::array<uint32_t, 18> boolean_columns{{
        l.active, l.deep_term, l.deep_finalize,
        l.vm_instruction, l.quotient_identity,
        l.deep_start, l.deep_chain,
        l.op_current, l.op_next, l.op_constant,
        l.op_add, l.op_sub, l.op_mul,
        l.program_end, l.vm_start, l.vm_chain,
        l.vm_to_quotient,
        l.quotient_tape_deep_consumer,
    }};
    for (uint32_t column : boolean_columns) binary(column);
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.row_one_hot",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.active],
                gf::Add(
                    gf::Add(
                        cur[l.deep_term],
                        cur[l.deep_finalize]),
                    gf::Add(
                        cur[l.vm_instruction],
                        cur[l.quotient_identity])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.u_weight",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.u_weight],
                gf::Mul(
                    cur[l.coefficient],
                    cur[l.x_power]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.u_contribution",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.u_contribution],
                gf::Mul(
                    cur[l.u_weight],
                    cur[l.current_value]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.u_term",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_term],
                gf::Sub(
                    cur[l.u_after],
                    gf::Add(
                        cur[l.u_before],
                        cur[l.u_contribution])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.v1_weight",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.v1_weight],
                gf::Mul(
                    cur[l.coefficient],
                    cur[l.z1_power]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.v1_contribution",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.v1_contribution],
                gf::Mul(
                    cur[l.v1_weight],
                    cur[l.eval_z1]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.v1_term",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_term],
                gf::Sub(
                    cur[l.v1_after],
                    gf::Add(
                        cur[l.v1_before],
                        cur[l.v1_contribution])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.v2_weight",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.v2_weight],
                gf::Mul(
                    cur[l.coefficient],
                    cur[l.z2_power]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.v2_contribution",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.v2_contribution],
                gf::Mul(
                    cur[l.v2_weight],
                    cur[l.eval_z2]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.v2_term",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_term],
                gf::Sub(
                    cur[l.v2_after],
                    gf::Add(
                        cur[l.v2_before],
                        cur[l.v2_contribution])));
        });
    for (uint32_t accumulator :
         {l.u_before, l.v1_before, l.v2_before}) {
        AddConstraint(
            out.cs, "stage3.v11.deep_vm.deep_zero",
            aq::AirKind::kEverywhere, 2,
            [l, accumulator](const auto& cur, const auto&) {
                return gf::Mul(
                    cur[l.deep_start],
                    cur[accumulator]);
            });
    }
    for (const auto [after, before] :
         {std::pair{l.u_after, l.u_before},
          std::pair{l.v1_after, l.v1_before},
          std::pair{l.v2_after, l.v2_before}}) {
        AddConstraint(
            out.cs, "stage3.v11.deep_vm.deep_chain",
            aq::AirKind::kTransition, 2,
            [l, after, before](const auto& cur, const auto& next) {
                return gf::Mul(
                    cur[l.deep_chain],
                    gf::Sub(next[before], cur[after]));
            });
    }
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.inverse_product_z1",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.inv_product1],
                gf::Mul(
                    gf::Sub(cur[l.x], cur[l.z1]),
                    cur[l.inv_x_minus_z1]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.inverse_z1",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_finalize],
                gf::Sub(
                    cur[l.inv_product1],
                    Fp3::One()));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.inverse_product_z2",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.inv_product2],
                gf::Mul(
                    gf::Sub(cur[l.x], cur[l.z2]),
                    cur[l.inv_x_minus_z2]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.inverse_z2",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_finalize],
                gf::Sub(
                    cur[l.inv_product2],
                    Fp3::One()));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.deep_diff_inv1",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.deep_diff_inv1],
                gf::Mul(
                    gf::Sub(
                        cur[l.u_before],
                        cur[l.v1_before]),
                    cur[l.inv_x_minus_z1]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.deep_rhs_term1",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.deep_rhs_term1],
                gf::Mul(
                    cur[l.w1],
                    cur[l.deep_diff_inv1]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.deep_diff_inv2",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.deep_diff_inv2],
                gf::Mul(
                    gf::Sub(
                        cur[l.u_before],
                        cur[l.v2_before]),
                    cur[l.inv_x_minus_z2]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.deep_rhs_term2",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.deep_rhs_term2],
                gf::Mul(
                    cur[l.w2],
                    cur[l.deep_diff_inv2]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.deep_rhs_sum",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.deep_rhs],
                gf::Add(
                    cur[l.deep_rhs_term1],
                    cur[l.deep_rhs_term2]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.deep_formula",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_finalize],
                gf::Sub(
                    cur[l.expected_deep],
                    cur[l.deep_rhs]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.first_fold",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.deep_finalize],
                gf::Sub(
                    cur[l.first_fold_value],
                    cur[l.expected_deep]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.op_one_hot",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t column :
                 {l.op_current, l.op_next, l.op_constant,
                  l.op_add, l.op_sub, l.op_mul}) {
                sum = gf::Add(sum, cur[column]);
            }
            return gf::Sub(sum, cur[l.vm_instruction]);
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.load",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            const Fp3 load = gf::Add(
                gf::Add(
                    cur[l.op_current], cur[l.op_next]),
                cur[l.op_constant]);
            return gf::Mul(
                load,
                gf::Sub(
                    cur[l.instruction_result],
                    cur[l.operand_lhs]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.add",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.op_add],
                gf::Sub(
                    cur[l.instruction_result],
                    gf::Add(
                        cur[l.operand_lhs],
                        cur[l.operand_rhs])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.sub",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.op_sub],
                gf::Sub(
                    cur[l.instruction_result],
                    gf::Sub(
                        cur[l.operand_lhs],
                        cur[l.operand_rhs])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.mul_product",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.mul_product],
                gf::Mul(
                    cur[l.operand_lhs],
                    cur[l.operand_rhs]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.mul",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.op_mul],
                gf::Sub(
                    cur[l.instruction_result],
                    cur[l.mul_product]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.vm_start_composition",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.vm_start],
                cur[l.composition_before]);
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.vm_start_power",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.vm_start],
                gf::Sub(
                    cur[l.lambda_power], Fp3::One()));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.selected_result",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.selected_result],
                gf::Mul(
                    cur[l.selector],
                    cur[l.instruction_result]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.lambda_selected",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.lambda_selected],
                gf::Mul(
                    cur[l.lambda_power],
                    cur[l.selected_result]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.program_contribution",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.program_contribution],
                gf::Mul(
                    cur[l.program_end],
                    cur[l.lambda_selected]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.composition_step",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.vm_instruction],
                gf::Sub(
                    cur[l.composition_after],
                    gf::Add(
                        cur[l.composition_before],
                        cur[l.program_contribution])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.composition_chain",
        aq::AirKind::kTransition, 2,
        [l](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.vm_chain],
                gf::Sub(
                    next[l.composition_before],
                    cur[l.composition_after]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.lambda_delta",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.lambda_delta],
                gf::Mul(
                    cur[l.program_end],
                    gf::Sub(
                        cur[l.air_lambda],
                        Fp3::One())));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.lambda_after",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.lambda_after],
                gf::Mul(
                    cur[l.lambda_power],
                    gf::Add(
                        Fp3::One(),
                        cur[l.lambda_delta])));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.lambda_chain",
        aq::AirKind::kTransition, 2,
        [l](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.vm_chain],
                gf::Sub(
                    next[l.lambda_power],
                    cur[l.lambda_after]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.vm_to_quotient",
        aq::AirKind::kTransition, 2,
        [l](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.vm_to_quotient],
                gf::Sub(
                    next[l.composition_before],
                    cur[l.composition_after]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.quotient_product",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.quotient_product],
                gf::Mul(
                    cur[l.zh],
                    cur[l.quotient_value]));
        });
    AddConstraint(
        out.cs, "stage3.v11.deep_vm.quotient_identity",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.quotient_identity],
                gf::Sub(
                    cur[l.composition_before],
                    cur[l.quotient_product]));
        });
    for (uint32_t limb = 0;
         limb < kFp3TapeLimbsV1;
         ++limb) {
        for (uint32_t bit = 0;
             bit < kU32TapeBitsV1;
             ++bit) {
            const uint32_t bit_column =
                l.quotient_tape_bit[limb][bit];
            AddConstraint(
                out.cs,
                "stage3.v11.deep_vm."
                "quotient_tape_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [bit_column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[bit_column],
                        gf::Sub(
                            cur[bit_column],
                            Fp3::One()));
                });
        }
        AddConstraint(
            out.cs,
            "stage3.v11.deep_vm."
            "quotient_tape_limb_reconstruct",
            aq::AirKind::kEverywhere, 1,
            [l, limb](
                const auto& cur,
                const auto&) {
                Fp3 reconstructed =
                    Fp3::Zero();
                for (uint32_t bit = 0;
                     bit < kU32TapeBitsV1;
                     ++bit) {
                    reconstructed = gf::Add(
                        reconstructed,
                        gf::Mul(
                            cur[
                                l.quotient_tape_bit[
                                    limb][bit]],
                            Fp3::FromFp(
                                uint64_t{1} << bit)));
                }
                return gf::Sub(
                    cur[
                        l.quotient_tape_limb[limb]],
                    reconstructed);
            });
        AddConstraint(
            out.cs,
            "stage3.v11.deep_vm."
            "quotient_tape_limb_chain",
            aq::AirKind::kTransition, 2,
            [l, limb](
                const auto& cur,
                const auto& next) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[l.quotient_identity]),
                    gf::Sub(
                        next[
                            l.quotient_tape_limb[limb]],
                        cur[
                            l.quotient_tape_limb[limb]]));
            });
    }
    for (uint32_t coordinate = 0;
         coordinate < kFp3CoordinatesV1;
         ++coordinate) {
        const uint32_t high_is_max =
            l.quotient_high_is_max[coordinate];
        const uint32_t high_inverse =
            l.quotient_high_delta_inverse[coordinate];
        const uint32_t low =
            l.quotient_tape_limb[2 * coordinate];
        const uint32_t high =
            l.quotient_tape_limb[
                2 * coordinate + 1];
        AddConstraint(
            out.cs,
            "stage3.v11.deep_vm."
            "quotient_tape_high_is_max_boolean",
            aq::AirKind::kEverywhere, 2,
            [high_is_max](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[high_is_max],
                    gf::Sub(
                        cur[high_is_max],
                        Fp3::One()));
            });
        AddConstraint(
            out.cs,
            "stage3.v11.deep_vm."
            "quotient_tape_high_max_zero_test",
            aq::AirKind::kEverywhere, 2,
            [high, high_is_max](
                const auto& cur,
                const auto&) {
                const Fp3 delta = gf::Sub(
                    cur[high],
                    Fp3::FromFp(
                        std::numeric_limits<
                            uint32_t>::max()));
                return gf::Mul(
                    delta, cur[high_is_max]);
            });
        AddConstraint(
            out.cs,
            "stage3.v11.deep_vm."
            "quotient_tape_high_nonmax_inverse",
            aq::AirKind::kEverywhere, 2,
            [high, high_is_max, high_inverse](
                const auto& cur,
                const auto&) {
                const Fp3 delta = gf::Sub(
                    cur[high],
                    Fp3::FromFp(
                        std::numeric_limits<
                            uint32_t>::max()));
                return gf::Sub(
                    gf::Mul(
                        delta, cur[high_inverse]),
                    gf::Sub(
                        Fp3::One(),
                        cur[high_is_max]));
            });
        AddConstraint(
            out.cs,
            "stage3.v11.deep_vm."
            "quotient_tape_goldilocks_canonical",
            aq::AirKind::kEverywhere, 2,
            [low, high_is_max](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[high_is_max],
                    cur[low]);
            });
    }
    AddConstraint(
        out.cs,
        "stage3.v11.deep_vm."
        "quotient_tape_fp3_reconstruct",
        aq::AirKind::kEverywhere, 1,
        [l](
            const auto& cur,
            const auto&) {
            constexpr uint64_t two32 =
                uint64_t{1} << 32;
            const std::array<Fp3, 3> basis{{
                Fp3{1, 0, 0},
                Fp3{0, 1, 0},
                Fp3{0, 0, 1},
            }};
            Fp3 reconstructed = Fp3::Zero();
            for (uint32_t coordinate = 0;
                 coordinate < kFp3CoordinatesV1;
                 ++coordinate) {
                const Fp3 coordinate_value =
                    gf::Add(
                        cur[
                            l.quotient_tape_limb[
                                2 * coordinate]],
                        gf::Mul(
                            cur[
                                l.quotient_tape_limb[
                                    2 * coordinate + 1]],
                            Fp3::FromFp(two32)));
                reconstructed = gf::Add(
                    reconstructed,
                    gf::Mul(
                        coordinate_value,
                        basis[coordinate]));
            }
            return gf::Sub(
                cur[l.quotient_tape_value],
                reconstructed);
        });
    AddConstraint(
        out.cs,
        "stage3.v11.deep_vm."
        "quotient_tape_deep_value_join",
        aq::AirKind::kEverywhere, 2,
        [l](
            const auto& cur,
            const auto&) {
            return gf::Mul(
                cur[l.quotient_tape_deep_consumer],
                gf::Sub(
                    cur[l.current_value],
                    cur[l.quotient_tape_value]));
        });
    AddConstraint(
        out.cs,
        "stage3.v11.deep_vm."
        "quotient_tape_final_value_join",
        aq::AirKind::kEverywhere, 2,
        [l](
            const auto& cur,
            const auto&) {
            return gf::Mul(
                cur[l.quotient_identity],
                gf::Sub(
                    cur[l.quotient_value],
                    cur[l.quotient_tape_value]));
        });
    AddConstraint(
        out.cs,
        "stage3.v11.deep_vm."
        "quotient_tape_acceptance",
        aq::AirKind::kEverywhere, 1,
        [l](
            const auto& cur,
            const auto&) {
            return gf::Sub(
                cur[l.quotient_tape_accept],
                cur[l.quotient_identity]);
        });

    out.preprocessed_columns = {
        l.active, l.deep_term, l.deep_finalize,
        l.vm_instruction, l.quotient_identity,
        l.query, l.item, l.source_address,
        l.current_value, l.eval_z1, l.eval_z2,
        l.coefficient, l.x_power, l.z1_power,
        l.z2_power, l.deep_start, l.deep_chain,
        l.x, l.z1, l.z2, l.w1, l.w2,
        l.first_fold_value,
        l.op_current, l.op_next, l.op_constant,
        l.op_add, l.op_sub, l.op_mul,
        l.operand_lhs, l.operand_rhs,
        l.program_end, l.vm_start, l.vm_chain,
        l.vm_to_quotient, l.air_lambda, l.selector,
        l.y, l.zh,
        l.quotient_tape_deep_consumer,
    };
    std::sort(
        out.preprocessed_columns.begin(),
        out.preprocessed_columns.end());
    out.preprocessed_columns.erase(
        std::unique(
            out.preprocessed_columns.begin(),
            out.preprocessed_columns.end()),
        out.preprocessed_columns.end());
    for (uint32_t column : out.preprocessed_columns) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        return fail("preprocessed_root:" + session.note);
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.preprocessed_columns,
        .root = out.preprocessed_row_group_root,
    });

    out.constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
        out.max_constraint_degree = std::max(
            out.max_constraint_degree,
            constraint.alg_degree);
    }
    out.violations =
        RecountViolationsV1(out, out.columns);
    out.literal_current_next_refs = true;
    out.duplicate_queries_preserved = true;
    (void)duplicate_queries;
    out.deep_rlc_air_constrained = true;
    out.denominator_inverse_air_constrained = true;
    out.first_fold_equality_air_constrained = true;
    out.quotient_identity_air_constrained = true;
    out.canonical_bytecode_vm_air_constrained = true;
    out.lambda_accumulation_air_constrained = true;
    out.ordered_preprocessed_root_pinned =
        RootMatches(out, out.columns);
    const auto is_preprocessed =
        [&out](uint32_t column) {
            return std::find(
                       out.preprocessed_columns.begin(),
                       out.preprocessed_columns.end(),
                       column) !=
                out.preprocessed_columns.end();
        };
    out.quotient_tape_cells_ordinary =
        !is_preprocessed(l.quotient_value) &&
        !is_preprocessed(l.quotient_tape_value) &&
        !is_preprocessed(l.quotient_tape_accept);
    for (uint32_t limb = 0;
         limb < kFp3TapeLimbsV1;
         ++limb) {
        out.quotient_tape_cells_ordinary =
            out.quotient_tape_cells_ordinary &&
            !is_preprocessed(
                l.quotient_tape_limb[limb]);
        for (uint32_t bit = 0;
             bit < kU32TapeBitsV1;
             ++bit) {
            out.quotient_tape_cells_ordinary =
                out.quotient_tape_cells_ordinary &&
                !is_preprocessed(
                    l.quotient_tape_bit[limb][bit]);
        }
    }
    out.quotient_tape_u32_canonical = true;
    out.quotient_tape_value_reconstructed = true;
    out.quotient_tape_fixed_offsets_r0_bound =
        is_preprocessed(l.source_address) &&
        is_preprocessed(
            l.quotient_tape_deep_consumer) &&
        out.ordered_preprocessed_root_pinned;
    out.quotient_tape_all_consumers_joined =
        true;
    out.quotient_tape_acceptance_constrained = true;
    out.same_parent_decoder_aliases = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.canonical_abi &&
        out.transcript_receipt_verified &&
        out.backend_proof_verified &&
        out.literal_current_next_refs &&
        out.duplicate_queries_preserved &&
        out.deep_rlc_air_constrained &&
        out.denominator_inverse_air_constrained &&
        out.first_fold_equality_air_constrained &&
        out.quotient_identity_air_constrained &&
        out.canonical_bytecode_vm_air_constrained &&
        out.lambda_accumulation_air_constrained &&
        out.exact_program_root_checked &&
        out.ordered_preprocessed_root_pinned &&
        out.quotient_tape_cells_ordinary &&
        out.quotient_tape_u32_canonical &&
        out.quotient_tape_value_reconstructed &&
        out.quotient_tape_fixed_offsets_r0_bound &&
        out.quotient_tape_all_consumers_joined &&
        out.quotient_tape_acceptance_constrained &&
        !out.same_parent_decoder_aliases &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_deep_vm:bounded_air_complete;"
          "quotient_tape_value_bus_complete;"
          "same_parent_decoder_alias_pending"
        : "stage3:v11_deep_vm:invalid:violations=" +
            std::to_string(out.violations) +
            ":root=" +
            std::to_string(
                out.ordered_preprocessed_root_pinned);
    if (!out.valid && out.violations != 0) {
        std::vector<Fp3> current(out.cs.n_columns);
        std::vector<Fp3> next(out.cs.n_columns);
        for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
            const uint32_t next_row = (row + 1) % out.cs.n_rows;
            for (uint32_t column = 0;
                 column < out.cs.n_columns; ++column) {
                current[column] = out.columns[column][row];
                next[column] = out.columns[column][next_row];
            }
            for (const auto& constraint : out.cs.constraints) {
                if (Applies(
                        constraint.kind, row, out.cs.n_rows) &&
                    !gf::IsZero(
                        constraint.eval(current, next))) {
                    out.note +=
                        std::string{":first="} +
                        constraint.name + "@" +
                        std::to_string(row);
                    return out;
                }
            }
        }
    }
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != product.cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != product.cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    uint64_t violations = 0;
    std::vector<Fp3> current(product.cs.n_columns);
    std::vector<Fp3> next(product.cs.n_columns);
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1) % product.cs.n_rows;
        for (uint32_t column = 0;
             column < product.cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : product.cs.constraints) {
            if (Applies(
                    constraint.kind, row,
                    product.cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    if (!RootMatches(product, columns)) ++violations;
    return violations;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_deep_vm
