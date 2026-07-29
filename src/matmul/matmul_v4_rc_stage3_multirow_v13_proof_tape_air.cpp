// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air {
namespace {

using gf::Fp3;

constexpr uint32_t kPrefixAddressBase = UINT32_C(0xf0000000);
constexpr uint32_t kHeaderAddressBase = UINT32_C(0xf1000000);
constexpr uint64_t kSemanticPackLimbShift = UINT64_C(1) << 32;
constexpr uint64_t kSemanticPackOwnershipShift = UINT64_C(1) << 40;

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    if (!PowerOfTwo(value)) return 0;
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

uint32_t NextPow2(uint64_t value)
{
    if (value < 2) return 2;
    uint64_t out = 1;
    while (out < value) {
        out <<= 1;
        if (out > std::numeric_limits<uint32_t>::max()) return 0;
    }
    return static_cast<uint32_t>(out);
}

bool CanonicalDigest(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) { return value < gf::kP; });
}

bool NullDigest(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) { return value == 0; });
}

std::array<uint32_t, 8> Uint256Words(const uint256& value)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4 * word;
        out[word] =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 3]) << 24);
    }
    return out;
}

bool ValidShape(const PublicShapeV1& shape)
{
    uint32_t padded = 1;
    const uint32_t maximum =
        std::max(shape.trace_rows, shape.quotient_len);
    while (padded < maximum &&
           padded <= (UINT32_MAX >> 1)) {
        padded <<= 1;
    }
    if (!PowerOfTwo(shape.trace_rows) ||
        !PowerOfTwo(shape.n_coeffs) ||
        shape.trace_rows > shape.n_coeffs ||
        shape.quotient_len == 0 ||
        shape.quotient_len > shape.n_coeffs ||
        shape.trace_columns < 2 ||
        shape.trace_columns + 1 >
            kRCFri3AlgBatchMaxColumns ||
        shape.base_column_indices.empty() ||
        shape.base_column_indices.size() >=
            shape.trace_columns ||
        padded != shape.n_coeffs ||
        uint64_t{shape.n_coeffs} * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        return false;
    }
    uint32_t prior = 0;
    for (uint32_t index = 0;
         index < shape.base_column_indices.size();
         ++index) {
        const uint32_t column =
            shape.base_column_indices[index];
        if (column >= shape.trace_columns ||
            (index != 0 && column <= prior)) {
            return false;
        }
        prior = column;
    }
    return true;
}

bool ValidBinding(const PublicBindingV1& binding)
{
    return !binding.program_root.IsNull() &&
        !binding.statement_root.IsNull() &&
        !binding.public_fs_seed.IsNull() &&
        !binding.proof_wire_root.IsNull() &&
        CanonicalDigest(binding.tape_root) &&
        !NullDigest(binding.tape_root);
}

Fri3AlgRowOpening DummyRow(
    uint32_t values, uint32_t depth)
{
    Fri3AlgRowOpening out;
    out.values.resize(values, Fp3::Zero());
    out.siblings.resize(depth, {});
    return out;
}

abi::EnvelopeV1 DummyEnvelope(const PublicShapeV1& shape)
{
    abi::EnvelopeV1 out;
    out.trace_columns = shape.trace_columns;
    out.quotient_len = shape.quotient_len;
    out.split.version =
        aq::kAirQuotientSplitRapRowsSafeProofVersionV2;
    out.split.trace_rows = shape.trace_rows;
    out.split.base_column_indices =
        shape.base_column_indices;
    auto& batch = out.split.batch;
    batch.version =
        kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13;
    batch.blowup = kRCFriBlowup;
    batch.n_coeffs = shape.n_coeffs;
    const uint32_t n_lde =
        shape.n_coeffs * kRCFriBlowup;
    const uint32_t main =
        static_cast<uint32_t>(
            shape.base_column_indices.size());
    const uint32_t auxiliary =
        shape.trace_columns - main;
    batch.groups.resize(3);
    batch.groups[0].role =
        Fri3AlgMultiRowGroupRole::MainTrace;
    batch.groups[0].first_column = 0;
    batch.groups[0].column_count = main;
    batch.groups[0].row_commit.n_leaves = n_lde;
    batch.groups[1].role =
        Fri3AlgMultiRowGroupRole::AuxiliaryTrace;
    batch.groups[1].first_column = main;
    batch.groups[1].column_count = auxiliary;
    batch.groups[1].row_commit.n_leaves = n_lde;
    batch.groups[2].role =
        Fri3AlgMultiRowGroupRole::Quotient;
    batch.groups[2].first_column = shape.trace_columns;
    batch.groups[2].column_count = 1;
    batch.groups[2].row_commit.n_leaves = n_lde;
    batch.column_len.assign(
        shape.trace_columns, shape.trace_rows);
    batch.column_len.push_back(shape.quotient_len);
    batch.evals_z1.resize(
        shape.trace_columns + 1, Fp3::Zero());
    batch.evals_z2.resize(
        shape.trace_columns + 1, Fp3::Zero());
    const uint32_t folds = Log2Exact(shape.n_coeffs);
    const uint32_t row_depth = Log2Exact(n_lde);
    batch.fold_layers.resize(folds + 1);
    for (uint32_t fold = 0; fold <= folds; ++fold) {
        batch.fold_layers[fold].n_leaves =
            n_lde >> fold;
    }
    batch.fold_challenges.resize(folds, Fp3::Zero());
    batch.queries.resize(abi::kQueryCountV11);
    out.split.next_trace_group_rows.resize(
        abi::kQueryCountV11);
    for (uint32_t query = 0;
         query < abi::kQueryCountV11; ++query) {
        auto& q = batch.queries[query];
        q.index = 0;
        q.group_rows = {
            DummyRow(main, row_depth),
            DummyRow(auxiliary, row_depth),
            DummyRow(1, row_depth),
        };
        q.steps.resize(folds);
        uint32_t index = q.index;
        for (uint32_t fold = 0; fold < folds; ++fold) {
            const uint32_t half =
                (n_lde >> fold) / 2;
            auto& step = q.steps[fold];
            step.even_index = index % half;
            step.odd_index =
                step.even_index + half;
            step.even_siblings.resize(
                row_depth - fold);
            step.odd_siblings.resize(
                row_depth - fold);
            index %= half;
        }
        out.split.next_trace_group_rows[query] = {
            DummyRow(main, row_depth),
            DummyRow(auxiliary, row_depth),
        };
    }
    return out;
}

bool IsFieldKind(abi::FieldKindV1 kind)
{
    using K = abi::FieldKindV1;
    switch (kind) {
    case K::AirConstraintLambda:
    case K::GroupRoot:
    case K::Lambda:
    case K::Z1:
    case K::Z2:
    case K::EvalZ1:
    case K::EvalZ2:
    case K::DeepWeight1:
    case K::DeepWeight2:
    case K::FoldRoot:
    case K::FinalValue:
    case K::FoldChallenge:
    case K::QueryCandidateDigest:
    case K::QueryRowValue:
    case K::QueryRowSibling:
    case K::QueryStepEven:
    case K::QueryStepOdd:
    case K::QueryStepEvenSibling:
    case K::QueryStepOddSibling:
    case K::NextRowValue:
    case K::NextRowSibling:
        return true;
    default:
        return false;
    }
}

bool FixedStructuralKind(abi::FieldKindV1 kind)
{
    using K = abi::FieldKindV1;
    switch (kind) {
    case K::PublicFsSeed:
    case K::SplitVersion:
    case K::TraceRows:
    case K::TraceColumns:
    case K::QuotientLen:
    case K::BaseColumnCount:
    case K::BaseColumnIndex:
    case K::BatchVersion:
    case K::Blowup:
    case K::NCoeffs:
    case K::GroupCount:
    case K::GroupRole:
    case K::GroupFirstColumn:
    case K::GroupColumnCount:
    case K::GroupLeaves:
    case K::ColumnCount:
    case K::ColumnLen:
    case K::EvalZ1Count:
    case K::EvalZ2Count:
    case K::FoldLayerCount:
    case K::FoldLeaves:
    case K::FoldChallengeCount:
    case K::QueryCount:
    case K::QueryGroupCount:
    case K::QueryRowValueCount:
    case K::QueryRowSiblingCount:
    case K::QueryStepCount:
    case K::QueryStepEvenSiblingCount:
    case K::QueryStepOddSiblingCount:
    case K::NextQueryCount:
    case K::NextGroupCount:
    case K::NextRowValueCount:
    case K::NextRowSiblingCount:
        return true;
    default:
        return false;
    }
}

uint64_t SemanticPacked(const RecordScheduleV1& record)
{
    return uint64_t{record.key.d} +
        kSemanticPackLimbShift * record.key.limb +
        kSemanticPackOwnershipShift *
            static_cast<uint8_t>(record.ownership);
}

bool AddPreprocessed(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    if (column >= cs.n_columns ||
        values.size() != cs.n_rows) {
        return false;
    }
    cs.preprocessed.emplace_back(
        column, std::move(values));
    return true;
}

struct MaterializedRecords {
    std::vector<uint32_t> address;
    std::vector<uint32_t> value;
    bool valid{false};
};

MaterializedRecords MaterializeRecords(
    const ScheduleV1& schedule,
    const std::vector<uint32_t>& words)
{
    MaterializedRecords out;
    if (!schedule.valid ||
        words.size() !=
            abi::kFieldAbiHeaderWordsV1 +
            size_t{schedule.source_records} * 2) {
        return out;
    }
    const size_t total =
        size_t{schedule.trace_rows} *
        kRecordsPerRowV1;
    out.address.assign(total, 0);
    out.value.assign(total, 0);
    for (uint32_t record = 0;
         record < schedule.active_records; ++record) {
        const auto& expected = schedule.records[record];
        out.address[record] = expected.expected_address;
        if (record < kPublicPrefixRecordsV1) {
            out.value[record] =
                expected.expected_value;
        } else if (
            record <
                kPublicPrefixRecordsV1 +
                    kHeaderRecordsV1) {
            const uint32_t header =
                record - kPublicPrefixRecordsV1;
            out.value[record] = words[header];
        } else {
            const uint32_t source =
                record - kPublicPrefixRecordsV1 -
                kHeaderRecordsV1;
            const size_t offset =
                abi::kFieldAbiHeaderWordsV1 +
                size_t{source} * 2;
            out.address[record] = words[offset];
            out.value[record] = words[offset + 1];
        }
    }
    out.valid = true;
    return out;
}

bool SameSourceSchedule(
    const std::vector<abi::SourceCellV1>& left,
    const std::vector<abi::SourceCellV1>& right)
{
    if (left.size() != right.size()) return false;
    for (size_t index = 0; index < left.size(); ++index) {
        if (left[index].address != right[index].address ||
            left[index].key != right[index].key ||
            left[index].ownership != right[index].ownership) {
            return false;
        }
    }
    return true;
}

bool HasConstraint(
    const aq::AirConstraintSystem<Fp3>& cs,
    const char* name)
{
    return std::any_of(
        cs.constraints.begin(), cs.constraints.end(),
        [name](const auto& constraint) {
            return constraint.name == name;
        });
}

bool NoPreprocessedProofValues(
    const aq::AirConstraintSystem<Fp3>& cs,
    const LayoutV1& layout)
{
    for (const auto& [column, values] : cs.preprocessed) {
        (void)values;
        if (column < layout.poseidon.End() ||
            column == layout.dependent_zero) {
            return false;
        }
        for (uint32_t slot = 0;
             slot < kRecordsPerRowV1; ++slot) {
            if (column == layout.Address(slot) ||
                column == layout.Value(slot) ||
                column == layout.HighIsMax(slot) ||
                column ==
                    layout.HighDeltaInverse(slot)) {
                return false;
            }
            for (uint32_t bit = 0; bit < 32; ++bit) {
                if (column == layout.Bit(slot, bit)) {
                    return false;
                }
            }
        }
    }
    return true;
}

uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_bad_row,
    std::string* first_bad_constraint)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows < 2) {
        return UINT32_MAX;
    }
    uint32_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            if (columns[column].size() != cs.n_rows) {
                return UINT32_MAX;
            }
            current[column] = columns[column][row];
            next[column] =
                columns[column][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            bool evaluate = false;
            switch (constraint.kind) {
            case aq::AirKind::kEverywhere:
                evaluate = true;
                break;
            case aq::AirKind::kTransition:
                evaluate = row + 1 < cs.n_rows;
                break;
            case aq::AirKind::kFirstRow:
                evaluate = row == 0;
                break;
            case aq::AirKind::kLastRow:
                evaluate = row + 1 == cs.n_rows;
                break;
            }
            if (evaluate &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                if (violations == 0) {
                    if (first_bad_row) {
                        *first_bad_row = row;
                    }
                    if (first_bad_constraint) {
                        *first_bad_constraint =
                            constraint.name;
                    }
                }
                ++violations;
            }
        }
    }
    return violations;
}

uint256 BindingHash(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_MULTIROW_V13_PROOF_TAPE_AIR_V1";
    hash << shape.trace_rows;
    hash << shape.trace_columns;
    hash << shape.quotient_len;
    hash << shape.n_coeffs;
    hash <<
        static_cast<uint32_t>(
            shape.base_column_indices.size());
    for (uint32_t column :
         shape.base_column_indices) {
        hash << column;
    }
    hash << binding.program_root;
    hash << binding.statement_root;
    hash << binding.public_fs_seed;
    hash << binding.proof_wire_root;
    for (gf::Fp lane : binding.tape_root) {
        hash << static_cast<uint64_t>(lane);
    }
    return hash.GetHash();
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.poseidon = p2air::CanonicalLayout(0);
    uint32_t cursor = out.poseidon.End();
    out.address_base = cursor;
    cursor += kRecordsPerRowV1;
    out.value_base = cursor;
    cursor += kRecordsPerRowV1;
    out.bit_base = cursor;
    cursor += 32 * kRecordsPerRowV1;
    out.high_is_max_base = cursor;
    cursor += kRecordsPerRowV1;
    out.high_delta_inverse_base = cursor;
    cursor += kRecordsPerRowV1;
    out.active_base = cursor;
    cursor += kRecordsPerRowV1;
    out.source_base = cursor;
    cursor += kRecordsPerRowV1;
    out.fixed_value_base = cursor;
    cursor += kRecordsPerRowV1;
    out.expected_address_base = cursor;
    cursor += kRecordsPerRowV1;
    out.expected_value_base = cursor;
    cursor += kRecordsPerRowV1;
    out.fp_low_base = cursor;
    cursor += kRecordsPerRowV1;
    out.successor_base = cursor;
    cursor += kRecordsPerRowV1;
    out.record_class_base = cursor;
    cursor += kRecordsPerRowV1;
    out.semantic_kind_base = cursor;
    cursor += kRecordsPerRowV1;
    out.semantic_a_base = cursor;
    cursor += kRecordsPerRowV1;
    out.semantic_b_base = cursor;
    cursor += kRecordsPerRowV1;
    out.semantic_c_base = cursor;
    cursor += kRecordsPerRowV1;
    out.semantic_packed_base = cursor;
    cursor += kRecordsPerRowV1;
    out.expected_tape_root_base = cursor;
    cursor += alg_hash::kAlgHashDigestLen;
    out.dependent_zero = cursor;
    return out;
}

ScheduleV1 BuildScheduleV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding)
{
    ScheduleV1 out;
    out.shape = shape;
    const auto fail = [&](const char* why) {
        out.note =
            std::string{
                "stage3:multirow_v13_proof_tape:"} +
            why;
        return out;
    };
    if (!ValidShape(shape) ||
        binding.program_root.IsNull() ||
        binding.statement_root.IsNull() ||
        binding.public_fs_seed.IsNull() ||
        binding.proof_wire_root.IsNull()) {
        return fail("public_shape_or_binding");
    }

    const abi::EnvelopeV1 dummy =
        DummyEnvelope(shape);
    std::vector<uint32_t> dummy_words;
    std::string why;
    if (!abi::EncodeCanonicalSafeV13(
            dummy, dummy_words,
            &out.semantic_sources, &why)) {
        return fail("semantic_schedule");
    }
    out.source_records =
        static_cast<uint32_t>(
            out.semantic_sources.size());
    out.active_records =
        kPublicPrefixRecordsV1 +
        kHeaderRecordsV1 +
        out.source_records;
    out.active_rows =
        (out.active_records +
         kRecordsPerRowV1 - 1) /
        kRecordsPerRowV1;
    out.trace_rows = NextPow2(out.active_rows);
    if (out.trace_rows == 0) {
        return fail("trace_rows");
    }
    out.records.resize(
        size_t{out.trace_rows} *
        kRecordsPerRowV1);

    const std::array<uint256, kPublicRootCountV1> roots{
        binding.program_root,
        binding.statement_root,
        binding.public_fs_seed,
        binding.proof_wire_root,
    };
    uint32_t cursor = 0;
    for (uint32_t root = 0;
         root < roots.size(); ++root) {
        const auto words = Uint256Words(roots[root]);
        for (uint32_t limb = 0;
             limb < words.size(); ++limb) {
            auto& record = out.records[cursor++];
            record.record_class =
                static_cast<RecordClassV1>(
                    static_cast<uint8_t>(
                        RecordClassV1::
                            PublicProgramRoot) +
                    root);
            record.expected_address =
                kPrefixAddressBase +
                root * kPublicRootLimbsV1 + limb;
            record.fixed_value = true;
            record.expected_value = words[limb];
        }
    }

    const std::array<uint32_t, kHeaderRecordsV1>
        header{
            abi::kFieldAbiMagicV1,
            abi::kFieldAbiVersionV1,
            abi::kMultiRowProtocolVersionV13,
            static_cast<uint32_t>(
                abi::kMultiRowProtocolDomainV13),
            static_cast<uint32_t>(
                abi::kMultiRowProtocolDomainV13 >> 32),
            out.source_records,
        };
    for (uint32_t index = 0;
         index < header.size(); ++index) {
        auto& record = out.records[cursor++];
        record.record_class =
            RecordClassV1::AbiHeader;
        record.expected_address =
            kHeaderAddressBase + index;
        record.fixed_value = true;
        record.expected_value = header[index];
    }

    const auto seed_words =
        Uint256Words(binding.public_fs_seed);
    for (uint32_t source_index = 0;
         source_index < out.semantic_sources.size();
         ++source_index) {
        const auto& source =
            out.semantic_sources[source_index];
        auto& record = out.records[cursor++];
        record.record_class =
            RecordClassV1::AbiSource;
        record.expected_address = source.address;
        record.source_record = true;
        record.key = source.key;
        record.ownership = source.ownership;
        record.fp_low_limb =
            IsFieldKind(source.key.kind) &&
            source.key.limb == 0;
        record.fixed_value =
            FixedStructuralKind(source.key.kind);
        record.expected_value = source.value;
        if (source.key.kind ==
                abi::FieldKindV1::PublicFsSeed &&
            source.key.a < seed_words.size()) {
            record.fixed_value = true;
            record.expected_value =
                seed_words[source.key.a];
        }
    }
    while (cursor < out.records.size()) {
        auto& record = out.records[cursor++];
        record.record_class =
            RecordClassV1::Padding;
        record.fixed_value = true;
        record.expected_address = 0;
        record.expected_value = 0;
    }

    out.exact_safe_v13_header = true;
    out.semantic_schedule_regenerated = true;
    out.stable_addresses = true;
    for (uint32_t index = 0;
         index < out.semantic_sources.size();
         ++index) {
        const auto& source =
            out.semantic_sources[index];
        const auto& record =
            out.records[
                kPublicPrefixRecordsV1 +
                kHeaderRecordsV1 + index];
        if (source.address != index ||
            record.expected_address != index ||
            record.key != source.key) {
            out.stable_addresses = false;
            break;
        }
        if (record.fp_low_limb) {
            if (index + 1 >=
                    out.semantic_sources.size() ||
                out.semantic_sources[index + 1].key.kind !=
                    source.key.kind ||
                out.semantic_sources[index + 1].key.a !=
                    source.key.a ||
                out.semantic_sources[index + 1].key.b !=
                    source.key.b ||
                out.semantic_sources[index + 1].key.c !=
                    source.key.c ||
                out.semantic_sources[index + 1].key.d !=
                    source.key.d ||
                out.semantic_sources[index + 1].key.limb !=
                    1) {
                out.stable_addresses = false;
                break;
            }
        }
    }
    out.valid =
        out.exact_safe_v13_header &&
        out.semantic_schedule_regenerated &&
        out.stable_addresses;
    out.note = out.valid
        ? "stage3:multirow_v13_proof_tape:"
          "verifier_owned_schedule"
        : "stage3:multirow_v13_proof_tape:"
          "schedule_invalid";
    return out;
}

bool BuildConstraintSystemV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    aq::AirConstraintSystem<Fp3>& out,
    LayoutV1* layout_out,
    ScheduleV1* schedule_out,
    std::string* why)
{
    out = {};
    const LayoutV1 layout =
        CanonicalLayoutV1();
    const ScheduleV1 schedule =
        BuildScheduleV1(shape, binding);
    const auto fail = [&](const char* detail) {
        if (why) {
            *why =
                std::string{
                    "stage3:multirow_v13_proof_tape:"} +
                detail;
        }
        return false;
    };
    if (!schedule.valid ||
        !ValidBinding(binding)) {
        return fail("cs_input");
    }
    out.n_rows = schedule.trace_rows;
    out.n_columns = layout.End();
    out.preprocessed_pin_ood = true;

    auto constraints =
        p2air::BuildFixedConstraints(
            layout.poseidon);
    out.constraints.insert(
        out.constraints.end(),
        std::make_move_iterator(
            constraints.begin()),
        std::make_move_iterator(
            constraints.end()));

    for (uint32_t slot = 0;
         slot < kRecordsPerRowV1; ++slot) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.u32_bit";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, slot, bit](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 value =
                        cur[layout.Bit(slot, bit)];
                    return gf::Mul(
                        value,
                        gf::Sub(value, Fp3::One()));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.u32_recompose";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 1;
            c.eval =
                [layout, slot](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    Fp3 value = Fp3::Zero();
                    uint64_t weight = 1;
                    for (uint32_t bit = 0;
                         bit < 32; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                U(weight),
                                cur[layout.Bit(
                                    slot, bit)]));
                        weight <<= 1;
                    }
                    return gf::Sub(
                        cur[layout.Value(slot)],
                        value);
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.address_exact";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 1;
            c.eval =
                [layout, slot](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[layout.Address(slot)],
                        cur[layout.ExpectedAddress(
                            slot)]);
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.fixed_value";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, slot](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[layout.FixedValue(slot)],
                        gf::Sub(
                            cur[layout.Value(slot)],
                            cur[layout.ExpectedValue(
                                slot)]));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.fp_eq_bool";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, slot](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 eq =
                        cur[layout.HighIsMax(slot)];
                    return gf::Mul(
                        eq, gf::Sub(eq, Fp3::One()));
                };
            out.constraints.push_back(std::move(c));
        }
        auto high_value =
            [layout, slot](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return slot + 1 <
                        kRecordsPerRowV1
                    ? cur[layout.Value(slot + 1)]
                    : next[layout.Value(0)];
            };
        const aq::AirKind pair_kind =
            slot + 1 < kRecordsPerRowV1
            ? aq::AirKind::kEverywhere
            : aq::AirKind::kTransition;
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.fp_eq_sound";
            c.kind = pair_kind;
            c.alg_degree = 3;
            c.eval =
                [layout, slot, high_value](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    const Fp3 selector =
                        cur[layout.FpLow(slot)];
                    const Fp3 eq =
                        cur[layout.HighIsMax(slot)];
                    const Fp3 delta =
                        gf::Sub(
                            U(UINT32_MAX),
                            high_value(cur, next));
                    return gf::Mul(
                        selector,
                        gf::Mul(eq, delta));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.fp_delta_inverse";
            c.kind = pair_kind;
            c.alg_degree = 3;
            c.eval =
                [layout, slot, high_value](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    const Fp3 selector =
                        cur[layout.FpLow(slot)];
                    const Fp3 eq =
                        cur[layout.HighIsMax(slot)];
                    const Fp3 delta =
                        gf::Sub(
                            U(UINT32_MAX),
                            high_value(cur, next));
                    return gf::Mul(
                        selector,
                        gf::Sub(
                            gf::Mul(
                                delta,
                                cur[layout.
                                    HighDeltaInverse(
                                        slot)]),
                            gf::Sub(Fp3::One(), eq)));
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.fp_low_if_high_max";
            c.kind = pair_kind;
            c.alg_degree = 3;
            c.eval =
                [layout, slot](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[layout.FpLow(slot)],
                        gf::Mul(
                            cur[layout.HighIsMax(slot)],
                            cur[layout.Value(slot)]));
                };
            out.constraints.push_back(std::move(c));
        }
        for (bool inverse : {false, true}) {
            aq::AirConstraint<Fp3> c;
            c.name = inverse
                ? "stage3.v13_tape.fp_unused_inverse_zero"
                : "stage3.v13_tape.fp_unused_eq_zero";
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval =
                [layout, slot, inverse](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.FpLow(slot)]),
                        cur[inverse
                                ? layout.
                                    HighDeltaInverse(slot)
                                : layout.HighIsMax(
                                    slot)]);
                };
            out.constraints.push_back(std::move(c));
        }
        {
            aq::AirConstraint<Fp3> c;
            c.name =
                "stage3.v13_tape.address_successor";
            c.kind =
                slot + 1 < kRecordsPerRowV1
                ? aq::AirKind::kEverywhere
                : aq::AirKind::kTransition;
            c.alg_degree = 2;
            c.eval =
                [layout, slot](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    const Fp3 following =
                        slot + 1 <
                                kRecordsPerRowV1
                        ? cur[layout.Address(slot + 1)]
                        : next[layout.Address(0)];
                    return gf::Mul(
                        cur[layout.Successor(slot)],
                        gf::Sub(
                            gf::Sub(
                                following,
                                cur[layout.Address(slot)]),
                            Fp3::One()));
                };
            out.constraints.push_back(std::move(c));
        }
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate; ++lane) {
        aq::AirConstraint<Fp3> first;
        first.name =
            "stage3.v13_tape.sponge_first";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        first.eval =
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const uint32_t slot = lane / 2;
                const uint32_t column =
                    (lane & 1U) == 0
                    ? layout.Address(slot)
                    : layout.Value(slot);
                return gf::Sub(
                    cur[
                        layout.poseidon.perm.
                            InputCol(lane)],
                    cur[column]);
            };
        out.constraints.push_back(std::move(first));

        aq::AirConstraint<Fp3> transition;
        transition.name =
            "stage3.v13_tape.sponge_rate_carry";
        transition.kind = aq::AirKind::kTransition;
        transition.alg_degree = 1;
        transition.eval =
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                const uint32_t slot = lane / 2;
                const uint32_t column =
                    (lane & 1U) == 0
                    ? layout.Address(slot)
                    : layout.Value(slot);
                return gf::Sub(
                    next[
                        layout.poseidon.perm.
                            InputCol(lane)],
                    gf::Add(
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm,
                            cur, lane),
                        next[column]));
            };
        out.constraints.push_back(
            std::move(transition));
    }
    for (uint32_t lane = alg_hash::kAlgHashRate;
         lane < alg_hash::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> first;
        first.name =
            "stage3.v13_tape.sponge_first_capacity";
        first.kind = aq::AirKind::kFirstRow;
        first.alg_degree = 1;
        first.eval =
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[
                    layout.poseidon.perm.InputCol(lane)];
            };
        out.constraints.push_back(std::move(first));

        aq::AirConstraint<Fp3> transition;
        transition.name =
            "stage3.v13_tape.sponge_capacity_carry";
        transition.kind = aq::AirKind::kTransition;
        transition.alg_degree = 1;
        transition.eval =
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[
                        layout.poseidon.perm.
                            InputCol(lane)],
                    air_recurse::PermOutputLane(
                        layout.poseidon.perm,
                        cur, lane));
            };
        out.constraints.push_back(
            std::move(transition));
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen; ++lane) {
        aq::AirConstraint<Fp3> terminal;
        terminal.name =
            "stage3.v13_tape.terminal_root";
        terminal.kind = aq::AirKind::kLastRow;
        terminal.alg_degree = 1;
        terminal.eval =
            [layout, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    air_recurse::PermOutputLane(
                        layout.poseidon.perm,
                        cur, lane),
                    cur[layout.ExpectedTapeRoot(
                        lane)]);
            };
        out.constraints.push_back(
            std::move(terminal));
    }
    {
        aq::AirConstraint<Fp3> zero;
        zero.name =
            "stage3.v13_tape.rdep_zero";
        zero.kind = aq::AirKind::kEverywhere;
        zero.alg_degree = 1;
        zero.eval =
            [layout](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[layout.dependent_zero];
            };
        out.constraints.push_back(std::move(zero));
    }

    for (uint32_t slot = 0;
         slot < kRecordsPerRowV1; ++slot) {
        auto values_for =
            [&](auto getter) {
                std::vector<Fp3> values(
                    out.n_rows, Fp3::Zero());
                for (uint32_t row = 0;
                     row < out.n_rows; ++row) {
                    values[row] =
                        getter(schedule.records[
                            row * kRecordsPerRowV1 +
                            slot]);
                }
                return values;
            };
        if (!AddPreprocessed(
                out, layout.Active(slot),
                values_for([](const auto& r) {
                    return U(
                        r.record_class !=
                        RecordClassV1::Padding);
                })) ||
            !AddPreprocessed(
                out, layout.Source(slot),
                values_for([](const auto& r) {
                    return U(r.source_record);
                })) ||
            !AddPreprocessed(
                out, layout.FixedValue(slot),
                values_for([](const auto& r) {
                    return U(r.fixed_value);
                })) ||
            !AddPreprocessed(
                out, layout.ExpectedAddress(slot),
                values_for([](const auto& r) {
                    return U(r.expected_address);
                })) ||
            !AddPreprocessed(
                out, layout.ExpectedValue(slot),
                values_for([](const auto& r) {
                    return U(r.expected_value);
                })) ||
            !AddPreprocessed(
                out, layout.FpLow(slot),
                values_for([](const auto& r) {
                    return U(r.fp_low_limb);
                })) ||
            !AddPreprocessed(
                out, layout.Successor(slot),
                values_for(
                    [&](const auto& r) {
                        if (!r.source_record) {
                            return Fp3::Zero();
                        }
                        const uint32_t record =
                            static_cast<uint32_t>(
                                &r -
                                schedule.records.data());
                        return U(
                            record + 1 <
                                schedule.records.size() &&
                            schedule.records[
                                record + 1].
                                source_record);
                    })) ||
            !AddPreprocessed(
                out, layout.RecordClass(slot),
                values_for([](const auto& r) {
                    return U(
                        static_cast<uint8_t>(
                            r.record_class));
                })) ||
            !AddPreprocessed(
                out, layout.SemanticKind(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? static_cast<uint16_t>(
                              r.key.kind)
                        : 0);
                })) ||
            !AddPreprocessed(
                out, layout.SemanticA(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record ? r.key.a : 0);
                })) ||
            !AddPreprocessed(
                out, layout.SemanticB(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record ? r.key.b : 0);
                })) ||
            !AddPreprocessed(
                out, layout.SemanticC(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record ? r.key.c : 0);
                })) ||
            !AddPreprocessed(
                out, layout.SemanticPacked(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? SemanticPacked(r)
                        : 0);
                }))) {
            return fail("preprocessed");
        }
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashDigestLen; ++lane) {
        if (!AddPreprocessed(
                out, layout.ExpectedTapeRoot(lane),
                std::vector<Fp3>(
                    out.n_rows,
                    Fp3::FromFp(
                        binding.tape_root[lane])))) {
            return fail("preprocessed_tape_root");
        }
    }

    if (layout_out) *layout_out = layout;
    if (schedule_out) *schedule_out = schedule;
    if (why) {
        *why =
            "stage3:multirow_v13_proof_tape:"
            "fixed_constraint_system";
    }
    return true;
}

alg_hash::Digest ComputeTapeRootV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words,
    std::string* why)
{
    PublicBindingV1 schedule_binding = binding;
    // The schedule does not consume tape_root; permit callers to compute it
    // before filling that field.
    if (NullDigest(schedule_binding.tape_root)) {
        schedule_binding.tape_root = {
            gf::FromU64(1), 0, 0, 0};
    }
    const ScheduleV1 schedule =
        BuildScheduleV1(shape, schedule_binding);
    const auto records =
        MaterializeRecords(
            schedule, canonical_words);
    if (!records.valid) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "root_records";
        }
        return {};
    }
    for (uint32_t source = 0;
         source < schedule.source_records; ++source) {
        const uint32_t record =
            kPublicPrefixRecordsV1 +
            kHeaderRecordsV1 + source;
        if (records.address[record] != source) {
            if (why) {
                *why =
                    "stage3:multirow_v13_proof_tape:"
                    "root_address_order";
            }
            return {};
        }
    }
    alg_hash::State state{};
    for (uint32_t row = 0;
         row < schedule.trace_rows; ++row) {
        for (uint32_t slot = 0;
             slot < kRecordsPerRowV1; ++slot) {
            const uint32_t record =
                row * kRecordsPerRowV1 + slot;
            state[2 * slot] =
                gf::Add(
                    state[2 * slot],
                    gf::FromU64(
                        records.address[record]));
            state[2 * slot + 1] =
                gf::Add(
                    state[2 * slot + 1],
                    gf::FromU64(
                        records.value[record]));
        }
        alg_hash::Permute(state);
    }
    alg_hash::Digest out{};
    std::copy_n(
        state.begin(), out.size(), out.begin());
    if (why) {
        *why =
            "stage3:multirow_v13_proof_tape:"
            "root_computed";
    }
    return out;
}

uint256 DeriveProofFsSeedV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding)
{
    if (!ValidShape(shape) ||
        !ValidBinding(binding)) {
        return {};
    }
    return BindingHash(shape, binding);
}

ProductV1 BuildProductV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words)
{
    ProductV1 out;
    out.binding = binding;
    const auto fail = [&](const std::string& detail) {
        out.note =
            "stage3:multirow_v13_proof_tape:" +
            detail;
        return out;
    };
    std::string why;
    const auto decoded =
        abi::DecodeCanonicalSafeV13(
            canonical_words, &why);
    if (!decoded.has_value() ||
        !decoded->canonical ||
        !decoded->complete) {
        return fail("host_witness_decode:" + why);
    }
    if (!BuildConstraintSystemV1(
            shape, binding, out.cs,
            &out.layout, &out.schedule, &why)) {
        return fail("cs:" + why);
    }
    if (!SameSourceSchedule(
            decoded->sources,
            out.schedule.semantic_sources) ||
        decoded->envelope.split.trace_rows !=
            shape.trace_rows ||
        decoded->envelope.trace_columns !=
            shape.trace_columns ||
        decoded->envelope.quotient_len !=
            shape.quotient_len ||
        decoded->envelope.split.batch.n_coeffs !=
            shape.n_coeffs ||
        decoded->envelope.split.base_column_indices !=
            shape.base_column_indices) {
        return fail("decoded_shape_or_schedule");
    }
    const alg_hash::Digest root =
        ComputeTapeRootV1(
            shape, binding,
            canonical_words, &why);
    if (root != binding.tape_root) {
        return fail("tape_root");
    }
    const auto records =
        MaterializeRecords(
            out.schedule, canonical_words);
    if (!records.valid) {
        return fail("record_materialization");
    }

    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        out.columns[column] = values;
    }
    alg_hash::State state{};
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        alg_hash::State input = state;
        for (uint32_t slot = 0;
             slot < kRecordsPerRowV1; ++slot) {
            const uint32_t record =
                row * kRecordsPerRowV1 + slot;
            const uint32_t address =
                records.address[record];
            const uint32_t value =
                records.value[record];
            out.columns[
                out.layout.Address(slot)][row] =
                U(address);
            out.columns[
                out.layout.Value(slot)][row] =
                U(value);
            for (uint32_t bit = 0;
                 bit < 32; ++bit) {
                out.columns[
                    out.layout.Bit(slot, bit)][row] =
                    U((value >> bit) & 1U);
            }
            input[2 * slot] =
                gf::Add(
                    input[2 * slot],
                    gf::FromU64(address));
            input[2 * slot + 1] =
                gf::Add(
                    input[2 * slot + 1],
                    gf::FromU64(value));
        }
        const auto p2 =
            p2air::BuildWitness(
                out.layout.poseidon, input);
        if (p2.row.size() !=
                out.layout.poseidon.End()) {
            return fail("poseidon_witness");
        }
        for (uint32_t column = 0;
             column < p2.row.size(); ++column) {
            out.columns[column][row] =
                p2.row[column];
        }
        state = p2.output;
    }
    for (uint32_t record = 0;
         record < out.schedule.records.size();
         ++record) {
        const auto& scheduled =
            out.schedule.records[record];
        if (!scheduled.fp_low_limb) continue;
        const uint32_t high = records.value[record + 1];
        const uint32_t row =
            record / kRecordsPerRowV1;
        const uint32_t slot =
            record % kRecordsPerRowV1;
        const bool high_is_max =
            high == UINT32_MAX;
        out.columns[
            out.layout.HighIsMax(slot)][row] =
            U(high_is_max);
        if (!high_is_max) {
            const Fp3 delta =
                gf::Sub(
                    U(UINT32_MAX), U(high));
            out.columns[
                out.layout.HighDeltaInverse(
                    slot)][row] =
                gf::Inv(delta);
        }
    }
    for (uint32_t index = 0;
         index < out.schedule.semantic_sources.size();
         ++index) {
        const auto& source =
            out.schedule.semantic_sources[index];
        const uint32_t record =
            kPublicPrefixRecordsV1 +
            kHeaderRecordsV1 + index;
        const uint32_t row =
            record / kRecordsPerRowV1;
        const uint32_t slot =
            record % kRecordsPerRowV1;
        out.source_cells.push_back({
            source.key, source.ownership,
            source.address, row, slot,
            out.layout.Address(slot),
            out.layout.Value(slot),
        });
    }

    out.violations =
        CountViolations(
            out.cs, out.columns,
            &out.first_bad_row,
            &out.first_bad_constraint);
    out.r0_base_column_indices.reserve(
        out.layout.dependent_zero);
    for (uint32_t column = 0;
         column < out.layout.dependent_zero;
         ++column) {
        out.r0_base_column_indices.push_back(column);
    }
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    out.fixed_verifier_owned_schedule =
        out.schedule.valid;
    out.no_preprocessed_proof_values =
        NoPreprocessedProofValues(
            out.cs, out.layout);
    out.canonical_u32_decomposition_air =
        HasConstraint(
            out.cs, "stage3.v13_tape.u32_bit") &&
        HasConstraint(
            out.cs, "stage3.v13_tape.u32_recompose");
    out.canonical_fp_pairs_air =
        HasConstraint(
            out.cs, "stage3.v13_tape.fp_eq_sound") &&
        HasConstraint(
            out.cs,
            "stage3.v13_tape.fp_delta_inverse") &&
        HasConstraint(
            out.cs,
            "stage3.v13_tape.fp_low_if_high_max");
    out.monotone_no_omission_addresses_air =
        HasConstraint(
            out.cs,
            "stage3.v13_tape.address_exact") &&
        HasConstraint(
            out.cs,
            "stage3.v13_tape.address_successor");
    out.fixed_protocol_header_air =
        out.schedule.exact_safe_v13_header &&
        HasConstraint(
            out.cs, "stage3.v13_tape.fixed_value");
    out.public_bindings_in_r0 =
        out.r0_session.valid;
    out.stable_source_exports =
        out.source_cells.size() ==
            out.schedule.semantic_sources.size();
    out.proof_wire_codec_correspondence = false;
    out.public_root_preimage_correspondence = false;
    out.complete_v13_consumption = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.r0_session.valid &&
        !out.r0_session.base_row_commitment.IsNull() &&
        out.fixed_verifier_owned_schedule &&
        out.no_preprocessed_proof_values &&
        out.canonical_u32_decomposition_air &&
        out.canonical_fp_pairs_air &&
        out.monotone_no_omission_addresses_air &&
        out.fixed_protocol_header_air &&
        out.public_bindings_in_r0 &&
        out.stable_source_exports &&
        !out.complete_v13_consumption &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:multirow_v13_proof_tape:"
          "r0_source_tape_bound;"
          "wire_codec_and_root_preimage_joins_open;"
          "phase_consumption_open"
        : "stage3:multirow_v13_proof_tape:"
          "product_invalid:" +
          out.first_bad_constraint;
    return out;
}

bool ProveV1(
    const ProductV1& product,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.complete_v13_consumption ||
        product.recursive_authority_ready ||
        !product.r0_session.valid) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "prove_product";
        }
        return false;
    }
    const uint256 seed =
        DeriveProofFsSeedV1(
            product.schedule.shape,
            product.binding);
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs, product.columns,
            product.r0_base_column_indices,
            seed, {}, &product.r0_session);
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.r0_session.base_row_commitment) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "prove:" + proved.note;
        }
        return false;
    }
    out.r0_row_root =
        product.r0_session.base_row_commitment;
    out.tape_root = product.binding.tape_root;
    out.proof = proved.proof;
    std::string verify_why;
    const bool self_verified =
        aq::AirQuotientVerifyRowsSplitRapSafeV2(
            product.cs, out.proof,
            product.r0_base_column_indices,
            seed, &verify_why);
    out.complete_v13_consumption = false;
    out.recursive_authority_ready = false;
    out.note = self_verified
        ? "stage3:multirow_v13_proof_tape:"
          "proof_verified;phase_consumption_open"
        : "stage3:multirow_v13_proof_tape:"
          "proof_verify:" + verify_why;
    if (why) *why = out.note;
    return self_verified;
}

bool VerifyV1(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const ProofV1& proof,
    std::string* why)
{
    if (proof.version !=
            kProofTapeAirVersionV1 ||
        proof.r0_row_root.IsNull() ||
        proof.tape_root != binding.tape_root ||
        proof.complete_v13_consumption ||
        proof.recursive_authority_ready) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "proof_envelope";
        }
        return false;
    }
    aq::AirConstraintSystem<Fp3> cs;
    LayoutV1 layout;
    ScheduleV1 schedule;
    if (!BuildConstraintSystemV1(
            shape, binding, cs,
            &layout, &schedule, why)) {
        return false;
    }
    std::vector<uint32_t> base;
    base.reserve(layout.dependent_zero);
    for (uint32_t column = 0;
         column < layout.dependent_zero;
         ++column) {
        base.push_back(column);
    }
    if (proof.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.proof.batch.groups[0]
                .row_commit.root) !=
            proof.r0_row_root) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "r0_envelope";
        }
        return false;
    }
    return aq::AirQuotientVerifyRowsSplitRapSafeV2(
        cs, proof.proof, base,
        DeriveProofFsSeedV1(shape, binding),
        why);
}

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air
