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

namespace {

uint256 ComputeSourceInventoryRootV2(
    const PublicShapeV1& shape,
    const std::vector<RecordScheduleV1>& records,
    uint32_t source_records,
    uint32_t trace_rows)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SAFE_V13_PACKED_TAPE_INVENTORY_V2";
    hash << kProofTapeAirVersionV2;
    hash << kRecordsPerRowV2;
    hash << kPoseidonInstancesPerRowV2;
    hash << shape.trace_rows;
    hash << shape.trace_columns;
    hash << shape.quotient_len;
    hash << shape.n_coeffs;
    hash << shape.base_column_indices;
    hash << source_records;
    hash << static_cast<uint32_t>(records.size());
    hash << trace_rows;
    for (uint32_t ordinal = 0;
         ordinal < records.size(); ++ordinal) {
        const auto& record = records[ordinal];
        hash << ordinal;
        hash << ordinal / kRecordsPerRowV2;
        hash << ordinal % kRecordsPerRowV2;
        hash << static_cast<uint8_t>(
            record.record_class);
        hash << record.expected_address;
        hash << record.fixed_value;
        hash << record.expected_value;
        hash << record.source_record;
        hash << record.fp_low_limb;
        hash << static_cast<uint16_t>(
            record.key.kind);
        hash << record.key.a;
        hash << record.key.b;
        hash << record.key.c;
        hash << record.key.d;
        hash << record.key.limb;
        hash << static_cast<uint8_t>(
            record.ownership);
    }
    return hash.GetHash();
}

} // namespace

ScheduleV2 BuildScheduleV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding)
{
    ScheduleV2 out;
    out.shape = shape;
    const ScheduleV1 legacy =
        BuildScheduleV1(shape, binding);
    if (!legacy.valid ||
        legacy.active_records == 0 ||
        legacy.active_records >
            legacy.records.size()) {
        out.note =
            "stage3:multirow_v13_proof_tape:"
            "packed_schedule_source";
        return out;
    }
    out.source_records = legacy.source_records;
    out.active_records = legacy.active_records;
    out.trace_rows = NextPow2(
        (uint64_t{out.active_records} +
         kRecordsPerRowV2 - 1) /
        kRecordsPerRowV2);
    if (out.trace_rows < 2) out.trace_rows = 2;
    const uint64_t total =
        uint64_t{out.trace_rows} *
        kRecordsPerRowV2;
    if (out.trace_rows == 0 ||
        total > UINT32_MAX ||
        total < out.active_records) {
        out.note =
            "stage3:multirow_v13_proof_tape:"
            "packed_schedule_rows";
        return out;
    }
    out.padding_records =
        static_cast<uint32_t>(total) -
        out.active_records;
    out.active_schedule.assign(
        legacy.records.begin(),
        legacy.records.begin() +
            out.active_records);
    out.records = legacy.records;
    out.semantic_sources =
        legacy.semantic_sources;
    out.exact_v1_record_order =
        out.active_schedule.size() ==
            legacy.active_records &&
        std::equal(
            out.active_schedule.begin(),
            out.active_schedule.end(),
            legacy.records.begin(),
            [](const auto& a, const auto& b) {
                return a.record_class ==
                        b.record_class &&
                    a.expected_address ==
                        b.expected_address &&
                    a.fixed_value == b.fixed_value &&
                    a.expected_value ==
                        b.expected_value &&
                    a.source_record ==
                        b.source_record &&
                    a.fp_low_limb ==
                        b.fp_low_limb &&
                    a.key == b.key &&
                    a.ownership == b.ownership;
            });
    out.immutable_row_slot_mapping = true;
    for (uint32_t ordinal = 0;
         ordinal < out.active_schedule.size();
         ++ordinal) {
        const uint32_t row =
            ordinal / kRecordsPerRowV2;
        const uint32_t slot =
            ordinal % kRecordsPerRowV2;
        if (row >= out.trace_rows ||
            slot >= kRecordsPerRowV2) {
            out.immutable_row_slot_mapping = false;
            break;
        }
    }
    std::set<std::pair<uint32_t, abi::SourceKeyV1>>
        source_keys;
    uint32_t seen_source = 0;
    out.exact_source_multiplicity = true;
    for (const auto& record : out.active_schedule) {
        if (!record.source_record) continue;
        ++seen_source;
        if (!source_keys.insert(
                {record.expected_address,
                 record.key}).second) {
            out.exact_source_multiplicity = false;
        }
    }
    out.exact_source_multiplicity =
        out.exact_source_multiplicity &&
        seen_source == out.source_records &&
        source_keys.size() == out.source_records;
    // Padding is not accepted from a proof/caller.  It is the unique implicit
    // all-zero suffix determined by active_records and trace_rows.
    out.canonical_padding = true;
    out.source_inventory_root =
        ComputeSourceInventoryRootV2(
            shape, out.active_schedule,
            out.source_records, out.trace_rows);
    out.valid =
        out.exact_v1_record_order &&
        out.immutable_row_slot_mapping &&
        out.exact_source_multiplicity &&
        out.canonical_padding &&
        !out.source_inventory_root.IsNull();
    out.note = out.valid
        ? "stage3:multirow_v13_proof_tape:"
          "packed_v2_schedule"
        : "stage3:multirow_v13_proof_tape:"
          "packed_v2_schedule_invalid";
    return out;
}

LayoutV2 CanonicalLayoutV2()
{
    LayoutV2 out;
    uint32_t cursor = 0;
    for (uint32_t block = 0;
         block < kPoseidonInstancesPerRowV2;
         ++block) {
        out.poseidon[block] =
            p2air::CanonicalLayout(cursor);
        cursor = out.poseidon[block].End();
    }
    out.address_base = cursor;
    cursor += kRecordsPerRowV2;
    out.value_base = cursor;
    cursor += kRecordsPerRowV2;
    out.bit_base = cursor;
    cursor += 32 * kRecordsPerRowV2;
    out.high_is_max_base = cursor;
    cursor += kRecordsPerRowV2;
    out.high_delta_inverse_base = cursor;
    cursor += kRecordsPerRowV2;
    out.active_base = cursor;
    cursor += kRecordsPerRowV2;
    out.source_base = cursor;
    cursor += kRecordsPerRowV2;
    out.fixed_value_base = cursor;
    cursor += kRecordsPerRowV2;
    out.expected_address_base = cursor;
    cursor += kRecordsPerRowV2;
    out.expected_value_base = cursor;
    cursor += kRecordsPerRowV2;
    out.fp_low_base = cursor;
    cursor += kRecordsPerRowV2;
    out.successor_base = cursor;
    cursor += kRecordsPerRowV2;
    out.record_class_base = cursor;
    cursor += kRecordsPerRowV2;
    out.semantic_kind_base = cursor;
    cursor += kRecordsPerRowV2;
    out.semantic_a_base = cursor;
    cursor += kRecordsPerRowV2;
    out.semantic_b_base = cursor;
    cursor += kRecordsPerRowV2;
    out.semantic_c_base = cursor;
    cursor += kRecordsPerRowV2;
    out.semantic_packed_base = cursor;
    cursor += kRecordsPerRowV2;
    out.expected_tape_root_base = cursor;
    cursor += alg_hash::kAlgHashDigestLen;
    out.dependent_zero = cursor;
    return out;
}

std::optional<SourceAddressCellV1> ResolveSourceAddressV2(
    const ScheduleV2& schedule,
    const LayoutV2& layout,
    uint32_t address)
{
    if (!schedule.valid ||
        address >= schedule.semantic_sources.size()) {
        return std::nullopt;
    }
    const auto& source =
        schedule.semantic_sources[address];
    if (source.address != address) {
        return std::nullopt;
    }
    const uint32_t ordinal =
        kPublicPrefixRecordsV1 +
        kHeaderRecordsV1 + address;
    if (ordinal >= schedule.active_records) {
        return std::nullopt;
    }
    const uint32_t row =
        ordinal / kRecordsPerRowV2;
    const uint32_t slot =
        ordinal % kRecordsPerRowV2;
    return SourceAddressCellV1{
        .key = source.key,
        .ownership = source.ownership,
        .address = source.address,
        .row = row,
        .slot = slot,
        .address_column = layout.Address(slot),
        .value_column = layout.Value(slot),
    };
}

std::optional<SourceAddressCellV1> ResolveSourceKeyV2(
    const ScheduleV2& schedule,
    const LayoutV2& layout,
    const abi::SourceKeyV1& key)
{
    if (!schedule.valid) return std::nullopt;
    const auto it = std::find_if(
        schedule.semantic_sources.begin(),
        schedule.semantic_sources.end(),
        [&](const auto& source) {
            return source.key == key;
        });
    if (it == schedule.semantic_sources.end()) {
        return std::nullopt;
    }
    return ResolveSourceAddressV2(
        schedule, layout, it->address);
}

alg_hash::Digest ComputeTapeRootV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words,
    std::string* why)
{
    const ScheduleV1 legacy =
        BuildScheduleV1(shape, binding);
    const ScheduleV2 packed =
        BuildScheduleV2(shape, binding);
    const auto records =
        MaterializeRecords(
            legacy, canonical_words);
    const uint64_t packed_total =
        uint64_t{packed.trace_rows} *
        kRecordsPerRowV2;
    if (!legacy.valid || !packed.valid ||
        !records.valid ||
        records.address.size() != packed_total ||
        records.value.size() != packed_total) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "packed_root_records";
        }
        return {};
    }
    alg_hash::State state{};
    for (uint32_t row = 0;
         row < packed.trace_rows; ++row) {
        for (uint32_t block = 0;
             block <
                kPoseidonInstancesPerRowV2;
             ++block) {
            for (uint32_t local = 0;
                 local <
                    kRecordsPerPoseidonV2;
                 ++local) {
                const uint32_t slot =
                    block *
                        kRecordsPerPoseidonV2 +
                    local;
                const uint32_t record =
                    row * kRecordsPerRowV2 +
                    slot;
                state[2 * local] = gf::Add(
                    state[2 * local],
                    gf::FromU64(
                        records.address[record]));
                state[2 * local + 1] = gf::Add(
                    state[2 * local + 1],
                    gf::FromU64(
                        records.value[record]));
            }
            alg_hash::Permute(state);
        }
    }
    alg_hash::Digest out{};
    std::copy_n(
        state.begin(), out.size(), out.begin());
    if (why) {
        *why =
            "stage3:multirow_v13_proof_tape:"
            "packed_root_computed";
    }
    return out;
}

bool VerifyPackedWordsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words,
    std::string* why)
{
    const auto decoded =
        abi::DecodeCanonicalSafeV13(
            canonical_words, why);
    const ScheduleV2 packed =
        BuildScheduleV2(shape, binding);
    if (!decoded.has_value() ||
        !decoded->canonical ||
        !decoded->complete ||
        !decoded->addresses_unique ||
        !decoded->semantic_keys_unique ||
        !packed.valid ||
        !SameSourceSchedule(
            decoded->sources,
            packed.semantic_sources) ||
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
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "packed_decode_or_schedule";
        }
        return false;
    }
    const alg_hash::Digest packed_root =
        ComputeTapeRootV2(
            shape, binding,
            canonical_words, why);
    const alg_hash::Digest legacy_root =
        ComputeTapeRootV1(
            shape, binding,
            canonical_words, why);
    if (packed_root != binding.tape_root ||
        packed_root != legacy_root) {
        if (why) {
            *why =
                "stage3:multirow_v13_proof_tape:"
                "packed_root_or_parity";
        }
        return false;
    }
    if (why) {
        *why =
            "stage3:multirow_v13_proof_tape:"
            "packed_v2_verified";
    }
    return true;
}

uint256 DeriveProofFsSeedV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const uint256& source_inventory_root)
{
    if (!ValidShape(shape) ||
        !ValidBinding(binding) ||
        source_inventory_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SAFE_V13_PACKED_TAPE_FS_V2";
    hash << kProofTapeAirVersionV2;
    hash << BindingHash(shape, binding);
    hash << source_inventory_root;
    hash << kRecordsPerRowV2;
    hash << kPoseidonInstancesPerRowV2;
    return hash.GetHash();
}

namespace {

bool SameShardPlan(
    const ShardPlanV2& a,
    const ShardPlanV2& b)
{
    return a.shard_index == b.shard_index &&
        a.shard_count == b.shard_count &&
        a.row_begin == b.row_begin &&
        a.trace_rows == b.trace_rows &&
        a.record_begin == b.record_begin &&
        a.record_count == b.record_count &&
        a.active_records == b.active_records &&
        a.total_trace_rows == b.total_trace_rows &&
        a.total_records == b.total_records &&
        a.total_active_records ==
            b.total_active_records &&
        a.contains_first_row ==
            b.contains_first_row &&
        a.contains_final_row ==
            b.contains_final_row &&
        a.contains_canonical_padding ==
            b.contains_canonical_padding &&
        a.valid == b.valid;
}

bool StateEq(
    const alg_hash::State& a,
    const alg_hash::State& b)
{
    for (uint32_t lane = 0;
         lane < a.size(); ++lane) {
        if (a[lane] != b[lane]) return false;
    }
    return true;
}

uint256 DeriveShardFsSeed(
    const ShardStatementV2& statement,
    const uint256& join_context_root)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SAFE_V13_STREAMING_TAPE_SHARD_FS_V2";
    hash << kProofTapeShardVersionV2;
    hash << BindingHash(
        statement.child_shape,
        statement.binding);
    hash << statement.plan.shard_index;
    hash << statement.plan.shard_count;
    hash << statement.plan.row_begin;
    hash << statement.plan.trace_rows;
    hash << statement.plan.record_begin;
    hash << statement.plan.record_count;
    hash << statement.plan.active_records;
    hash << statement.plan.total_trace_rows;
    hash << statement.plan.total_active_records;
    for (gf::Fp lane : statement.start_state) {
        hash << static_cast<uint64_t>(lane);
    }
    for (gf::Fp lane : statement.end_state) {
        hash << static_cast<uint64_t>(lane);
    }
    hash << statement.first_record_value;
    hash << statement.next_record_value;
    hash << statement.source_inventory_root;
    hash << join_context_root;
    return hash.GetHash();
}

} // namespace

std::vector<ShardPlanV2> BuildShardPlansForMaxRowsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    uint32_t max_rows)
{
    std::vector<ShardPlanV2> out;
    const ScheduleV1 global =
        BuildScheduleV1(shape, binding);
    if (!global.valid ||
        max_rows < 2 ||
        (max_rows & (max_rows - 1)) != 0 ||
        max_rows > kProofTapeShardMaxRowsV2 ||
        global.trace_rows % std::min(
            global.trace_rows, max_rows) != 0) {
        return out;
    }
    const uint32_t shard_rows =
        std::min(global.trace_rows, max_rows);
    const uint32_t shard_count =
        global.trace_rows / shard_rows;
    if (shard_count == 0 ||
        shard_count > 4 ||
        (shard_count & (shard_count - 1)) != 0) {
        return {};
    }
    out.reserve(shard_count);
    const uint32_t records_per_shard =
        shard_rows *
        kProofTapeShardRecordsPerRowV2;
    const uint32_t total_records =
        global.trace_rows *
        kProofTapeShardRecordsPerRowV2;
    for (uint32_t index = 0;
         index < shard_count; ++index) {
        ShardPlanV2 plan;
        plan.shard_index = index;
        plan.shard_count = shard_count;
        plan.row_begin = index * shard_rows;
        plan.trace_rows = shard_rows;
        plan.record_begin =
            index * records_per_shard;
        plan.record_count = records_per_shard;
        plan.total_trace_rows =
            global.trace_rows;
        plan.total_records = total_records;
        plan.total_active_records =
            global.active_records;
        const uint32_t active_end =
            std::min(
                global.active_records,
                plan.record_begin +
                    plan.record_count);
        plan.active_records =
            active_end > plan.record_begin
            ? active_end - plan.record_begin
            : 0;
        plan.contains_first_row =
            index == 0;
        plan.contains_final_row =
            index + 1 == shard_count;
        plan.contains_canonical_padding =
            plan.active_records <
                plan.record_count;
        plan.valid =
            plan.record_begin ==
                plan.shard_index *
                    plan.record_count &&
            plan.record_begin +
                plan.record_count <=
                    total_records;
        out.push_back(plan);
    }
    return out;
}

std::vector<ShardPlanV2> BuildShardPlansV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding)
{
    return BuildShardPlansForMaxRowsV2(
        shape, binding,
        kProofTapeShardMaxRowsV2);
}

ShardJoinContextV2 BuildShardJoinContextV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint256>& tape_r0_roots,
    const std::vector<uint256>& consumer_r0_roots)
{
    ShardJoinContextV2 out;
    out.tape_r0_roots = tape_r0_roots;
    out.consumer_r0_roots =
        consumer_r0_roots;
    const auto plans =
        BuildShardPlansV2(shape, binding);
    if (plans.empty() ||
        tape_r0_roots.size() != plans.size() ||
        consumer_r0_roots.empty() ||
        std::any_of(
            tape_r0_roots.begin(),
            tape_r0_roots.end(),
            [](const uint256& root) {
                return root.IsNull();
            }) ||
        std::any_of(
            consumer_r0_roots.begin(),
            consumer_r0_roots.end(),
            [](const uint256& root) {
                return root.IsNull();
            })) {
        return out;
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SAFE_V13_STREAMING_TAPE_JOIN_CONTEXT_V2";
    hash << kProofTapeShardVersionV2;
    hash << BindingHash(shape, binding);
    hash <<
        ComputeShardSourceInventoryRootV2(
            shape, binding);
    hash << static_cast<uint32_t>(
        tape_r0_roots.size());
    for (const auto& root :
         tape_r0_roots) {
        hash << root;
    }
    hash << static_cast<uint32_t>(
        consumer_r0_roots.size());
    for (const auto& root :
         consumer_r0_roots) {
        hash << root;
    }
    out.root = hash.GetHash();
    out.valid = !out.root.IsNull();
    return out;
}

uint256 ComputeShardSourceInventoryRootV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding)
{
    const ScheduleV1 global =
        BuildScheduleV1(shape, binding);
    if (!global.valid) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SAFE_V13_STREAMING_TAPE_SOURCE_INVENTORY_V2";
    hash << kProofTapeShardVersionV2;
    hash << shape.trace_rows;
    hash << shape.trace_columns;
    hash << shape.quotient_len;
    hash << shape.n_coeffs;
    hash << static_cast<uint32_t>(
        shape.base_column_indices.size());
    for (uint32_t column :
         shape.base_column_indices) {
        hash << column;
    }
    hash << global.source_records;
    hash << global.active_records;
    hash << global.trace_rows;
    for (uint32_t ordinal = 0;
         ordinal < global.active_records;
         ++ordinal) {
        const auto& record =
            global.records[ordinal];
        hash << ordinal;
        hash << static_cast<uint8_t>(
            record.record_class);
        hash << record.expected_address;
        hash << record.fixed_value;
        hash << record.expected_value;
        hash << record.source_record;
        hash << record.fp_low_limb;
        hash << static_cast<uint16_t>(
            record.key.kind);
        hash << record.key.a;
        hash << record.key.b;
        hash << record.key.c;
        hash << record.key.d;
        hash << record.key.limb;
        hash << static_cast<uint8_t>(
            record.ownership);
    }
    return hash.GetHash();
}

Fp3 ShardAddressTagV2(
    uint32_t shard_index,
    uint32_t address)
{
    if (shard_index >= 4) {
        return Fp3::Zero();
    }
    return U(
        (uint64_t{shard_index} << 32) |
        uint64_t{address});
}

ShardLayoutV2 CanonicalShardLayoutV2()
{
    ShardLayoutV2 out;
    out.tape = CanonicalLayoutV1();
    uint32_t cursor = out.tape.End();
    out.expected_start_state_base = cursor;
    cursor += alg_hash::kAlgHashT;
    out.expected_end_state_base = cursor;
    cursor += alg_hash::kAlgHashT;
    out.expected_first_value = cursor++;
    out.expected_next_value = cursor++;
    out.dependent_base = cursor;
    out.source_inverse_base = cursor;
    cursor += 2 *
        kProofTapeShardRecordsPerRowV2;
    out.running_base = cursor;
    cursor += 2;
    out.expected_terminal_base = cursor;
    return out;
}

ShardBoundaryStatesV2 ComputeShardBoundaryStatesV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<uint32_t>& canonical_words)
{
    ShardBoundaryStatesV2 out;
    const ScheduleV1 global =
        BuildScheduleV1(shape, binding);
    const auto plans =
        BuildShardPlansV2(shape, binding);
    const auto records =
        MaterializeRecords(
            global, canonical_words);
    if (!global.valid || plans.empty() ||
        !records.valid) {
        out.note =
            "stage3:proof_tape_shard:"
            "boundary_inputs";
        return out;
    }
    out.states.assign(
        plans.size() + 1,
        alg_hash::State{});
    out.first_record_values.resize(
        plans.size(), 0);
    out.next_record_values.resize(
        plans.size(), 0);
    for (uint32_t index = 0;
         index < plans.size(); ++index) {
        out.first_record_values[index] =
            records.value[
                plans[index].record_begin];
        if (index + 1 < plans.size()) {
            out.next_record_values[index] =
                records.value[
                    plans[index].record_begin +
                    plans[index].record_count];
        }
    }
    alg_hash::State state{};
    uint32_t next_boundary = 1;
    for (uint32_t row = 0;
         row < global.trace_rows; ++row) {
        for (uint32_t slot = 0;
             slot <
                kProofTapeShardRecordsPerRowV2;
             ++slot) {
            const uint32_t record =
                row *
                    kProofTapeShardRecordsPerRowV2 +
                slot;
            state[2 * slot] = gf::Add(
                state[2 * slot],
                gf::FromU64(
                    records.address[record]));
            state[2 * slot + 1] = gf::Add(
                state[2 * slot + 1],
                gf::FromU64(
                    records.value[record]));
        }
        alg_hash::Permute(state);
        if (next_boundary < out.states.size() &&
            row + 1 ==
                plans[next_boundary - 1].
                    row_begin +
                plans[next_boundary - 1].
                    trace_rows) {
            out.states[next_boundary++] =
                state;
        }
    }
    std::copy_n(
        state.begin(),
        out.final_root.size(),
        out.final_root.begin());
    const alg_hash::Digest legacy =
        ComputeTapeRootV1(
            shape, binding,
            canonical_words);
    out.exact_v1_tape_root =
        out.final_root == legacy &&
        out.final_root == binding.tape_root;
    out.valid =
        next_boundary == out.states.size() &&
        out.exact_v1_tape_root;
    out.note = out.valid
        ? "stage3:proof_tape_shard:"
          "exact_boundary_states"
        : "stage3:proof_tape_shard:"
          "boundary_state_mismatch";
    return out;
}

bool BuildShardConstraintSystemV2(
    const ShardStatementV2& statement,
    aq::AirConstraintSystem<Fp3>& out,
    ShardLayoutV2* layout_out,
    std::vector<RecordScheduleV1>* records_out,
    std::string* why)
{
    out = {};
    const auto fail = [&](const char* detail) {
        if (why) {
            *why =
                std::string{
                    "stage3:proof_tape_shard:"} +
                detail;
        }
        return false;
    };
    const auto plans =
        BuildShardPlansV2(
            statement.child_shape,
            statement.binding);
    const ScheduleV1 global =
        BuildScheduleV1(
            statement.child_shape,
            statement.binding);
    const uint256 inventory =
        ComputeShardSourceInventoryRootV2(
            statement.child_shape,
            statement.binding);
    if (!global.valid ||
        statement.plan.shard_index >=
            plans.size() ||
        !SameShardPlan(
            statement.plan,
            plans[statement.plan.shard_index]) ||
        statement.source_inventory_root.IsNull() ||
        statement.source_inventory_root !=
            inventory ||
        statement.plan.record_begin +
            statement.plan.record_count >
                global.records.size() ||
        statement.plan.trace_rows < 2) {
        return fail("statement_or_schedule");
    }
    std::vector<RecordScheduleV1> records(
        global.records.begin() +
            statement.plan.record_begin,
        global.records.begin() +
            statement.plan.record_begin +
            statement.plan.record_count);
    if (records.size() !=
            size_t{statement.plan.trace_rows} *
                kProofTapeShardRecordsPerRowV2 ||
        (statement.plan.contains_final_row &&
         statement.next_record_value != 0)) {
        return fail("record_slice_or_fp_boundary");
    }

    const ShardLayoutV2 layout =
        CanonicalShardLayoutV2();
    out.n_rows = statement.plan.trace_rows;
    out.n_columns = layout.dependent_base;
    out.preprocessed_pin_ood = true;

    auto fixed =
        p2air::BuildFixedConstraints(
            layout.tape.poseidon);
    out.constraints.insert(
        out.constraints.end(),
        std::make_move_iterator(fixed.begin()),
        std::make_move_iterator(fixed.end()));

    const auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree, auto eval) {
            aq::AirConstraint<Fp3> c;
            c.name = name;
            c.kind = kind;
            c.alg_degree = degree;
            c.eval = std::move(eval);
            out.constraints.push_back(std::move(c));
        };

    for (uint32_t slot = 0;
         slot <
            kProofTapeShardRecordsPerRowV2;
         ++slot) {
        for (uint32_t bit = 0;
             bit < 32; ++bit) {
            add(
                "stage3.v13_tape_shard.u32_bit",
                aq::AirKind::kEverywhere, 2,
                [layout, slot, bit](
                    const auto& cur,
                    const auto&) {
                    const Fp3 v =
                        cur[layout.tape.Bit(
                            slot, bit)];
                    return gf::Mul(
                        v,
                        gf::Sub(v, Fp3::One()));
                });
        }
        add(
            "stage3.v13_tape_shard.u32_recompose",
            aq::AirKind::kEverywhere, 1,
            [layout, slot](
                const auto& cur,
                const auto&) {
                Fp3 sum = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    sum = gf::Add(
                        sum,
                        gf::Mul(
                            U(weight),
                            cur[layout.tape.Bit(
                                slot, bit)]));
                    weight <<= 1;
                }
                return gf::Sub(
                    cur[layout.tape.Value(slot)],
                    sum);
            });
        add(
            "stage3.v13_tape_shard.address_exact",
            aq::AirKind::kEverywhere, 1,
            [layout, slot](
                const auto& cur,
                const auto&) {
                return gf::Sub(
                    cur[layout.tape.Address(slot)],
                    cur[layout.tape.
                        ExpectedAddress(slot)]);
            });
        add(
            "stage3.v13_tape_shard.fixed_value",
            aq::AirKind::kEverywhere, 2,
            [layout, slot](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.tape.
                        FixedValue(slot)],
                    gf::Sub(
                        cur[layout.tape.Value(slot)],
                        cur[layout.tape.
                            ExpectedValue(slot)]));
            });
        add(
            "stage3.v13_tape_shard.fp_eq_bool",
            aq::AirKind::kEverywhere, 2,
            [layout, slot](
                const auto& cur,
                const auto&) {
                const Fp3 eq =
                    cur[layout.tape.
                        HighIsMax(slot)];
                return gf::Mul(
                    eq,
                    gf::Sub(eq, Fp3::One()));
            });
        const aq::AirKind pair_kind =
            slot + 1 <
                    kProofTapeShardRecordsPerRowV2
            ? aq::AirKind::kEverywhere
            : aq::AirKind::kTransition;
        const auto high =
            [layout, slot](
                const auto& cur,
                const auto& next) {
                return slot + 1 <
                        kProofTapeShardRecordsPerRowV2
                    ? cur[layout.tape.
                        Value(slot + 1)]
                    : next[layout.tape.Value(0)];
            };
        add(
            "stage3.v13_tape_shard.fp_eq_sound",
            pair_kind, 3,
            [layout, slot, high](
                const auto& cur,
                const auto& next) {
                return gf::Mul(
                    cur[layout.tape.FpLow(slot)],
                    gf::Mul(
                        cur[layout.tape.
                            HighIsMax(slot)],
                        gf::Sub(
                            U(UINT32_MAX),
                            high(cur, next))));
            });
        add(
            "stage3.v13_tape_shard.fp_delta_inverse",
            pair_kind, 3,
            [layout, slot, high](
                const auto& cur,
                const auto& next) {
                const Fp3 eq =
                    cur[layout.tape.
                        HighIsMax(slot)];
                const Fp3 delta =
                    gf::Sub(
                        U(UINT32_MAX),
                        high(cur, next));
                return gf::Mul(
                    cur[layout.tape.FpLow(slot)],
                    gf::Sub(
                        gf::Mul(
                            delta,
                            cur[layout.tape.
                                HighDeltaInverse(
                                    slot)]),
                        gf::Sub(
                            Fp3::One(), eq)));
            });
        add(
            "stage3.v13_tape_shard.fp_low_if_high_max",
            pair_kind, 3,
            [layout, slot](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.tape.FpLow(slot)],
                    gf::Mul(
                        cur[layout.tape.
                            HighIsMax(slot)],
                        cur[layout.tape.
                            Value(slot)]));
            });
        for (bool inverse : {false, true}) {
            add(
                inverse
                    ? "stage3.v13_tape_shard.fp_unused_inverse_zero"
                    : "stage3.v13_tape_shard.fp_unused_eq_zero",
                aq::AirKind::kEverywhere, 2,
                [layout, slot, inverse](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.tape.
                                FpLow(slot)]),
                        cur[inverse
                            ? layout.tape.
                                HighDeltaInverse(slot)
                            : layout.tape.
                                HighIsMax(slot)]);
                });
        }
        add(
            "stage3.v13_tape_shard.address_successor",
            pair_kind, 2,
            [layout, slot](
                const auto& cur,
                const auto& next) {
                const Fp3 following =
                    slot + 1 <
                            kProofTapeShardRecordsPerRowV2
                    ? cur[layout.tape.
                        Address(slot + 1)]
                    : next[layout.tape.Address(0)];
                return gf::Mul(
                    cur[layout.tape.
                        Successor(slot)],
                    gf::Sub(
                        gf::Sub(
                            following,
                            cur[layout.tape.
                                Address(slot)]),
                        Fp3::One()));
            });
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT; ++lane) {
        add(
            "stage3.v13_tape_shard.sponge_first",
            aq::AirKind::kFirstRow, 1,
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 expected =
                    cur[layout.
                        ExpectedStartState(lane)];
                if (lane <
                        alg_hash::kAlgHashRate) {
                    const uint32_t slot =
                        lane / 2;
                    const uint32_t column =
                        (lane & 1U) == 0
                        ? layout.tape.Address(slot)
                        : layout.tape.Value(slot);
                    expected = gf::Add(
                        expected, cur[column]);
                }
                return gf::Sub(
                    cur[layout.tape.poseidon.
                        perm.InputCol(lane)],
                    expected);
            });
        add(
            "stage3.v13_tape_shard.sponge_carry",
            aq::AirKind::kTransition, 1,
            [layout, lane](
                const auto& cur,
                const auto& next) {
                Fp3 expected =
                    air_recurse::PermOutputLane(
                        layout.tape.poseidon.perm,
                        cur, lane);
                if (lane <
                        alg_hash::kAlgHashRate) {
                    const uint32_t slot =
                        lane / 2;
                    const uint32_t column =
                        (lane & 1U) == 0
                        ? layout.tape.Address(slot)
                        : layout.tape.Value(slot);
                    expected = gf::Add(
                        expected, next[column]);
                }
                return gf::Sub(
                    next[layout.tape.poseidon.
                        perm.InputCol(lane)],
                    expected);
            });
        add(
            "stage3.v13_tape_shard.terminal_state",
            aq::AirKind::kLastRow, 1,
            [layout, lane](
                const auto& cur,
                const auto&) {
                return gf::Sub(
                    air_recurse::PermOutputLane(
                        layout.tape.poseidon.perm,
                        cur, lane),
                    cur[layout.
                        ExpectedEndState(lane)]);
            });
    }
    add(
        "stage3.v13_tape_shard.first_record_value",
        aq::AirKind::kFirstRow, 1,
        [layout](
            const auto& cur,
            const auto&) {
            return gf::Sub(
                cur[layout.tape.Value(0)],
                cur[layout.expected_first_value]);
        });
    if (records.back().fp_low_limb) {
        constexpr uint32_t slot =
            kProofTapeShardRecordsPerRowV2 - 1;
        add(
            "stage3.v13_tape_shard.boundary_fp_eq_sound",
            aq::AirKind::kLastRow, 2,
            [layout](
                const auto& cur,
                const auto&) {
                const Fp3 delta =
                    gf::Sub(
                        U(UINT32_MAX),
                        cur[layout.expected_next_value]);
                return gf::Mul(
                    cur[layout.tape.HighIsMax(slot)],
                    delta);
            });
        add(
            "stage3.v13_tape_shard.boundary_fp_delta_inverse",
            aq::AirKind::kLastRow, 2,
            [layout](
                const auto& cur,
                const auto&) {
                const Fp3 eq =
                    cur[layout.tape.HighIsMax(slot)];
                const Fp3 delta =
                    gf::Sub(
                        U(UINT32_MAX),
                        cur[layout.expected_next_value]);
                return gf::Sub(
                    gf::Mul(
                        delta,
                        cur[layout.tape.
                            HighDeltaInverse(slot)]),
                    gf::Sub(Fp3::One(), eq));
            });
        add(
            "stage3.v13_tape_shard.boundary_fp_low_if_high_max",
            aq::AirKind::kLastRow, 2,
            [layout](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.tape.HighIsMax(slot)],
                    cur[layout.tape.Value(slot)]);
            });
    }
    add(
        "stage3.v13_tape_shard.legacy_rdep_zero",
        aq::AirKind::kEverywhere, 1,
        [layout](const auto& cur,
                 const auto&) {
            return cur[
                layout.tape.dependent_zero];
        });

    for (uint32_t slot = 0;
         slot <
            kProofTapeShardRecordsPerRowV2;
         ++slot) {
        const auto values_for =
            [&](auto getter) {
                std::vector<Fp3> values(
                    out.n_rows, Fp3::Zero());
                for (uint32_t row = 0;
                     row < out.n_rows; ++row) {
                    values[row] =
                        getter(records[
                            row *
                                kProofTapeShardRecordsPerRowV2 +
                            slot]);
                }
                return values;
            };
        if (!AddPreprocessed(
                out, layout.tape.Active(slot),
                values_for([](const auto& r) {
                    return U(
                        r.record_class !=
                        RecordClassV1::Padding);
                })) ||
            !AddPreprocessed(
                out, layout.tape.Source(slot),
                values_for([](const auto& r) {
                    return U(r.source_record);
                })) ||
            !AddPreprocessed(
                out, layout.tape.FixedValue(slot),
                values_for([](const auto& r) {
                    return U(r.fixed_value);
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.ExpectedAddress(slot),
                values_for([](const auto& r) {
                    return U(r.expected_address);
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.ExpectedValue(slot),
                values_for([](const auto& r) {
                    return U(r.expected_value);
                })) ||
            !AddPreprocessed(
                out, layout.tape.FpLow(slot),
                values_for([](const auto& r) {
                    return U(r.fp_low_limb);
                })) ||
            !AddPreprocessed(
                out, layout.tape.Successor(slot),
                values_for(
                    [&](const auto& r) {
                        if (!r.source_record) {
                            return Fp3::Zero();
                        }
                        const uint32_t local =
                            static_cast<uint32_t>(
                                &r - records.data());
                        const uint32_t global_record =
                            statement.plan.record_begin +
                            local;
                        return U(
                            global_record + 1 <
                                global.records.size() &&
                            global.records[
                                global_record + 1].
                                source_record);
                    })) ||
            !AddPreprocessed(
                out,
                layout.tape.RecordClass(slot),
                values_for([](const auto& r) {
                    return U(
                        static_cast<uint8_t>(
                            r.record_class));
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.SemanticKind(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? static_cast<uint16_t>(
                            r.key.kind)
                        : 0);
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.SemanticA(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? r.key.a : 0);
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.SemanticB(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? r.key.b : 0);
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.SemanticC(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? r.key.c : 0);
                })) ||
            !AddPreprocessed(
                out,
                layout.tape.SemanticPacked(slot),
                values_for([](const auto& r) {
                    return U(
                        r.source_record
                        ? SemanticPacked(r)
                        : 0);
                }))) {
            return fail("preprocessed_schedule");
        }
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT; ++lane) {
        if (!AddPreprocessed(
                out,
                layout.ExpectedStartState(lane),
                std::vector<Fp3>(
                    out.n_rows,
                    Fp3::FromFp(
                        statement.start_state[
                            lane]))) ||
            !AddPreprocessed(
                out,
                layout.ExpectedEndState(lane),
                std::vector<Fp3>(
                    out.n_rows,
                    Fp3::FromFp(
                        statement.end_state[
                            lane])))) {
            return fail("preprocessed_state");
        }
    }
    if (!AddPreprocessed(
            out, layout.expected_first_value,
            std::vector<Fp3>(
                out.n_rows,
                U(statement.first_record_value))) ||
        !AddPreprocessed(
            out, layout.expected_next_value,
            std::vector<Fp3>(
                out.n_rows,
                U(statement.next_record_value)))) {
        return fail("preprocessed_boundary_value");
    }
    uint32_t max_everywhere = 0;
    uint32_t max_transition = 0;
    uint32_t max_boundary = 0;
    for (const auto& constraint :
         out.constraints) {
        if (constraint.kind ==
                aq::AirKind::kEverywhere) {
            max_everywhere =
                std::max(
                    max_everywhere,
                    constraint.alg_degree);
        } else if (
            constraint.kind ==
                aq::AirKind::kTransition) {
            max_transition =
                std::max(
                    max_transition,
                    constraint.alg_degree);
        } else {
            max_boundary =
                std::max(
                    max_boundary,
                    constraint.alg_degree);
        }
    }
    if (max_everywhere > 3 ||
        max_transition > 3 ||
        max_boundary > 2 ||
        out.QuotientLen() >
            2 * out.n_rows) {
        return fail("recursive_degree_budget");
    }
    if (layout_out) *layout_out = layout;
    if (records_out) {
        *records_out = std::move(records);
    }
    if (why) {
        *why =
            "stage3:proof_tape_shard:"
            "fixed_constraint_system";
    }
    return true;
}

ShardProductV2 BuildShardProductV2(
    const ShardStatementV2& statement,
    const std::vector<uint32_t>& canonical_words)
{
    ShardProductV2 out;
    out.statement = statement;
    const auto fail =
        [&](const std::string& detail) {
            out.note =
                "stage3:proof_tape_shard:" +
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
        return fail("canonical_decode:" + why);
    }
    const ScheduleV1 global =
        BuildScheduleV1(
            statement.child_shape,
            statement.binding);
    const auto materialized =
        MaterializeRecords(
            global, canonical_words);
    std::vector<RecordScheduleV1> records;
    if (!global.valid ||
        !materialized.valid ||
        !SameSourceSchedule(
            decoded->sources,
            global.semantic_sources) ||
        !BuildShardConstraintSystemV2(
            statement, out.cs,
            &out.layout, &records, &why)) {
        return fail("schedule_or_cs:" + why);
    }
    const ShardBoundaryStatesV2 boundaries =
        ComputeShardBoundaryStatesV2(
            statement.child_shape,
            statement.binding,
            canonical_words);
    if (!boundaries.valid ||
        statement.plan.shard_index + 1 >=
            boundaries.states.size() ||
        !StateEq(
            statement.start_state,
            boundaries.states[
                statement.plan.shard_index]) ||
        !StateEq(
            statement.end_state,
            boundaries.states[
                statement.plan.shard_index + 1]) ||
        statement.plan.shard_index >=
            boundaries.first_record_values.size() ||
        statement.first_record_value !=
            boundaries.first_record_values[
                statement.plan.shard_index] ||
        statement.next_record_value !=
            boundaries.next_record_values[
                statement.plan.shard_index]) {
        return fail("state_boundary");
    }

    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        out.columns[column] = values;
    }
    alg_hash::State state =
        statement.start_state;
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        alg_hash::State input = state;
        for (uint32_t slot = 0;
             slot <
                kProofTapeShardRecordsPerRowV2;
             ++slot) {
            const uint32_t local_record =
                row *
                    kProofTapeShardRecordsPerRowV2 +
                slot;
            const uint32_t global_record =
                statement.plan.record_begin +
                local_record;
            const uint32_t address =
                materialized.address[
                    global_record];
            const uint32_t value =
                materialized.value[
                    global_record];
            out.columns[
                out.layout.tape.
                    Address(slot)][row] =
                U(address);
            out.columns[
                out.layout.tape.
                    Value(slot)][row] =
                U(value);
            for (uint32_t bit = 0;
                 bit < 32; ++bit) {
                out.columns[
                    out.layout.tape.
                        Bit(slot, bit)][row] =
                    U((value >> bit) & 1U);
            }
            input[2 * slot] = gf::Add(
                input[2 * slot],
                gf::FromU64(address));
            input[2 * slot + 1] = gf::Add(
                input[2 * slot + 1],
                gf::FromU64(value));
        }
        const auto p2 =
            p2air::BuildWitness(
                out.layout.tape.poseidon,
                input);
        if (p2.row.size() !=
                out.layout.tape.poseidon.End()) {
            return fail("poseidon_witness");
        }
        for (uint32_t column = 0;
             column < p2.row.size();
             ++column) {
            out.columns[column][row] =
                p2.row[column];
        }
        state = p2.output;
    }
    if (!StateEq(state, statement.end_state)) {
        return fail("terminal_state");
    }
    for (uint32_t local_record = 0;
         local_record < records.size();
         ++local_record) {
        if (!records[local_record].
                fp_low_limb) {
            continue;
        }
        const uint32_t global_record =
            statement.plan.record_begin +
            local_record;
        const uint32_t high =
            local_record + 1 < records.size()
            ? materialized.value[
                global_record + 1]
            : statement.next_record_value;
        const uint32_t row =
            local_record /
            kProofTapeShardRecordsPerRowV2;
        const uint32_t slot =
            local_record %
            kProofTapeShardRecordsPerRowV2;
        const bool high_is_max =
            high == UINT32_MAX;
        out.columns[
            out.layout.tape.
                HighIsMax(slot)][row] =
            U(high_is_max);
        if (!high_is_max) {
            out.columns[
                out.layout.tape.
                    HighDeltaInverse(slot)][row] =
                gf::Inv(
                    gf::Sub(
                        U(UINT32_MAX),
                        U(high)));
        }
    }
    for (uint32_t source_index = 0;
         source_index <
            global.semantic_sources.size();
         ++source_index) {
        const uint32_t global_record =
            kPublicPrefixRecordsV1 +
            kHeaderRecordsV1 +
            source_index;
        if (global_record <
                statement.plan.record_begin ||
            global_record >=
                statement.plan.record_begin +
                    statement.plan.record_count) {
            continue;
        }
        const uint32_t local =
            global_record -
            statement.plan.record_begin;
        const uint32_t row =
            local /
            kProofTapeShardRecordsPerRowV2;
        const uint32_t slot =
            local %
            kProofTapeShardRecordsPerRowV2;
        const auto& source =
            global.semantic_sources[
                source_index];
        out.source_cells.push_back({
            source.key,
            source.ownership,
            source.address,
            row,
            slot,
            out.layout.tape.Address(slot),
            out.layout.tape.Value(slot),
        });
    }
    out.violations =
        CountViolations(
            out.cs, out.columns,
            &out.first_bad_row,
            &out.first_bad_constraint);
    out.r0_base_column_indices.reserve(
        out.layout.dependent_base);
    for (uint32_t column = 0;
         column < out.layout.dependent_base;
         ++column) {
        out.r0_base_column_indices.push_back(
            column);
    }
    out.r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.r0_base_column_indices);
    out.exact_schedule_slice =
        records.size() ==
            statement.plan.record_count;
    out.exact_state_boundary = true;
    out.stable_source_exports =
        out.source_cells.size() ==
            statement.plan.active_records -
                std::min(
                    statement.plan.active_records,
                    kPublicPrefixRecordsV1 +
                        kHeaderRecordsV1);
    // The exact equality above is only true for shard zero.  For subsequent
    // shards, every active record is a semantic source record.
    if (statement.plan.shard_index != 0) {
        out.stable_source_exports =
            out.source_cells.size() ==
                statement.plan.active_records;
    }
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.r0_session.valid &&
        !out.r0_session.
            base_row_commitment.IsNull() &&
        out.exact_schedule_slice &&
        out.exact_state_boundary &&
        out.stable_source_exports &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:proof_tape_shard:"
          "executable_bounded_shard"
        : "stage3:proof_tape_shard:"
          "product_invalid:" +
          out.first_bad_constraint;
    return out;
}

bool DeriveShardSourceChallengesV2(
    const ShardStatementV2& statement,
    const uint256& r0_row_root,
    const ShardJoinContextV2& join_context,
    ShardSourceChallengesV2& out)
{
    out = {};
    if (r0_row_root.IsNull() ||
        !join_context.valid ||
        join_context.root.IsNull() ||
        statement.plan.shard_index >=
            join_context.tape_r0_roots.size() ||
        join_context.tape_r0_roots[
            statement.plan.shard_index] !=
            r0_row_root) {
        return false;
    }
    const uint256 seed =
        join_context.root;
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        const uint256 gamma_digest =
            aq::AirChallengeDigest(
                seed,
                "stage3.v13_tape_shard.source_gamma",
                {statement.source_inventory_root,
                 join_context.root},
                {lane});
        const uint256 alpha_digest =
            aq::AirChallengeDigest(
                seed,
                "stage3.v13_tape_shard.source_alpha",
                {statement.source_inventory_root,
                 join_context.root},
                {lane});
        out.gamma[lane] =
            gf::FromChallengeBytes3(
                gamma_digest.data());
        out.alpha[lane] =
            gf::FromChallengeBytes3(
                alpha_digest.data());
    }
    return !gf::IsZero(out.gamma[0]) &&
        !gf::IsZero(out.gamma[1]) &&
        !gf::Eq(
            out.gamma[0], out.gamma[1]) &&
        !gf::Eq(
            out.alpha[0], out.alpha[1]);
}

namespace {

bool MaterializeShardSourceTerminal(
    const ShardLayoutV2& layout,
    const ShardSourceChallengesV2& challenges,
    uint32_t shard_index,
    std::vector<std::vector<Fp3>>& columns,
    std::array<Fp3, 2>& terminal)
{
    if (columns.size() !=
            layout.dependent_base ||
        columns.empty()) {
        return false;
    }
    const uint32_t n_rows =
        static_cast<uint32_t>(
            columns[0].size());
    columns.resize(
        layout.End(),
        std::vector<Fp3>(
            n_rows, Fp3::Zero()));
    terminal = {};
    for (uint32_t row = 0;
         row < n_rows; ++row) {
        for (uint32_t lane = 0;
             lane < 2; ++lane) {
            Fp3 row_sum = Fp3::Zero();
            for (uint32_t slot = 0;
                 slot <
                    kProofTapeShardRecordsPerRowV2;
                 ++slot) {
                const bool active =
                    !gf::IsZero(
                        columns[
                            layout.tape.
                                Source(slot)][row]);
                if (!active) continue;
                const Fp3 denominator =
                    gf::Add(
                        columns[
                            layout.tape.
                                Value(slot)][row],
                        gf::Add(
                            gf::Mul(
                                challenges.alpha[lane],
                                gf::Add(
                                    columns[
                                        layout.tape.
                                            Address(slot)][row],
                                    ShardAddressTagV2(
                                        shard_index,
                                        0))),
                            challenges.gamma[lane]));
                if (gf::IsZero(denominator)) {
                    return false;
                }
                const Fp3 inverse =
                    gf::Inv(denominator);
                columns[
                    layout.SourceInverse(
                        lane, slot)][row] =
                    inverse;
                row_sum =
                    gf::Add(row_sum, inverse);
            }
            terminal[lane] =
                gf::Add(
                    terminal[lane], row_sum);
            columns[
                layout.Running(lane)][row] =
                terminal[lane];
        }
    }
    return true;
}

bool AppendShardSourceTerminal(
    const ShardLayoutV2& layout,
    const ShardSourceChallengesV2& challenges,
    uint32_t shard_index,
    const std::array<Fp3, 2>& terminal,
    aq::AirConstraintSystem<Fp3>& cs)
{
    if (cs.n_columns !=
            layout.dependent_base ||
        cs.n_rows < 2) {
        return false;
    }
    cs.n_columns = layout.End();
    const auto add =
        [&](const char* name, aq::AirKind kind,
            uint32_t degree, auto eval) {
            aq::AirConstraint<Fp3> c;
            c.name = name;
            c.kind = kind;
            c.alg_degree = degree;
            c.eval = std::move(eval);
            cs.constraints.push_back(std::move(c));
        };
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        for (uint32_t slot = 0;
             slot <
                kProofTapeShardRecordsPerRowV2;
             ++slot) {
            add(
                "stage3.v13_tape_shard.source_inverse",
                aq::AirKind::kEverywhere, 2,
                [layout, challenges, shard_index,
                 lane, slot](
                    const auto& cur,
                    const auto&) {
                    const Fp3 active =
                        cur[layout.tape.Source(slot)];
                    const Fp3 denominator =
                        gf::Add(
                            cur[layout.tape.
                                Value(slot)],
                            gf::Add(
                                gf::Mul(
                                    challenges.alpha[lane],
                                    gf::Add(
                                        cur[layout.tape.
                                            Address(slot)],
                                        ShardAddressTagV2(
                                            shard_index,
                                            0))),
                                challenges.gamma[lane]));
                    return gf::Mul(
                        active,
                        gf::Sub(
                            gf::Mul(
                                denominator,
                                cur[layout.
                                    SourceInverse(
                                        lane, slot)]),
                            Fp3::One()));
                });
            add(
                "stage3.v13_tape_shard.inactive_inverse_zero",
                aq::AirKind::kEverywhere, 2,
                [layout, lane, slot](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.tape.
                                Source(slot)]),
                        cur[layout.SourceInverse(
                            lane, slot)]);
                });
        }
        const auto row_sum =
            [layout, lane](
                const auto& row) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t slot = 0;
                     slot <
                        kProofTapeShardRecordsPerRowV2;
                     ++slot) {
                    sum = gf::Add(
                        sum,
                        row[layout.SourceInverse(
                            lane, slot)]);
                }
                return sum;
            };
        add(
            "stage3.v13_tape_shard.source_running_first",
            aq::AirKind::kFirstRow, 1,
            [layout, lane, row_sum](
                const auto& cur,
                const auto&) {
                return gf::Sub(
                    cur[layout.Running(lane)],
                    row_sum(cur));
            });
        add(
            "stage3.v13_tape_shard.source_running_transition",
            aq::AirKind::kTransition, 1,
            [layout, lane, row_sum](
                const auto& cur,
                const auto& next) {
                return gf::Sub(
                    next[layout.Running(lane)],
                    gf::Add(
                        cur[layout.Running(lane)],
                        row_sum(next)));
            });
        add(
            "stage3.v13_tape_shard.source_terminal",
            aq::AirKind::kLastRow, 1,
            [layout, lane](
                const auto& cur,
                const auto&) {
                return gf::Sub(
                    cur[layout.Running(lane)],
                    cur[layout.
                        ExpectedTerminal(lane)]);
            });
        if (!AddPreprocessed(
                cs,
                layout.ExpectedTerminal(lane),
                std::vector<Fp3>(
                    cs.n_rows,
                    terminal[lane]))) {
            return false;
        }
    }
    return true;
}

} // namespace

bool ProveShardV2(
    const ShardProductV2& product,
    const ShardJoinContextV2& join_context,
    ShardProofV2& out,
    std::string* why)
{
    out = {};
    const ShardJoinContextV2 expected_context =
        BuildShardJoinContextV2(
            product.statement.child_shape,
            product.statement.binding,
            join_context.tape_r0_roots,
            join_context.consumer_r0_roots);
    if (!product.valid ||
        product.recursive_authority_ready ||
        !product.r0_session.valid ||
        !join_context.valid ||
        !expected_context.valid ||
        expected_context.root !=
            join_context.root ||
        product.statement.plan.shard_index >=
            join_context.tape_r0_roots.size() ||
        join_context.tape_r0_roots[
            product.statement.plan.shard_index] !=
            product.r0_session.
                base_row_commitment) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "prove_product";
        }
        return false;
    }
    const uint256 seed =
        DeriveShardFsSeed(
            product.statement,
            join_context.root);
    ShardSourceChallengesV2 challenges;
    if (!DeriveShardSourceChallengesV2(
            product.statement,
            product.r0_session.
                base_row_commitment,
            join_context,
            challenges)) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "source_challenges";
        }
        return false;
    }
    auto final_cs = product.cs;
    auto final_columns = product.columns;
    std::array<Fp3, 2> source_terminal{};
    uint32_t terminal_bad_row = UINT32_MAX;
    std::string terminal_bad_constraint;
    const bool terminal_materialized =
        MaterializeShardSourceTerminal(
            product.layout, challenges,
            product.statement.plan.shard_index,
            final_columns, source_terminal);
    const bool terminal_appended =
        terminal_materialized &&
        AppendShardSourceTerminal(
            product.layout, challenges,
            product.statement.plan.shard_index,
            source_terminal, final_cs);
    if (terminal_appended) {
        for (uint32_t lane = 0;
             lane < 2; ++lane) {
            std::fill(
                final_columns[
                    product.layout.
                        ExpectedTerminal(lane)].
                    begin(),
                final_columns[
                    product.layout.
                        ExpectedTerminal(lane)].
                    end(),
                source_terminal[lane]);
        }
    }
    const uint32_t terminal_violations =
        terminal_appended
        ? CountViolations(
            final_cs, final_columns,
            &terminal_bad_row,
            &terminal_bad_constraint)
        : UINT32_MAX;
    if (!terminal_materialized ||
        !terminal_appended ||
        terminal_violations != 0) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "source_terminal_witness:" +
                terminal_bad_constraint +
                ":row=" +
                std::to_string(
                    terminal_bad_row);
        }
        return false;
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            final_cs,
            final_columns,
            product.r0_base_column_indices,
            seed, {},
            &product.r0_session);
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0].
                row_commit.root) !=
            product.r0_session.
                base_row_commitment) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "prove:" + proved.note;
        }
        return false;
    }
    out.version =
        kProofTapeShardVersionV2;
    out.shard_index =
        product.statement.plan.shard_index;
    out.r0_row_root =
        product.r0_session.
            base_row_commitment;
    out.join_context_root =
        join_context.root;
    out.source_terminal =
        source_terminal;
    out.proof = proved.proof;
    const bool verified =
        VerifyShardV2(
            product.statement,
            join_context, out, why);
    return verified;
}

bool VerifyShardV2(
    const ShardStatementV2& statement,
    const ShardJoinContextV2& join_context,
    const ShardProofV2& proof,
    std::string* why)
{
    const ShardJoinContextV2 expected_context =
        BuildShardJoinContextV2(
            statement.child_shape,
            statement.binding,
            join_context.tape_r0_roots,
            join_context.consumer_r0_roots);
    if (proof.version !=
            kProofTapeShardVersionV2 ||
        proof.shard_index !=
            statement.plan.shard_index ||
        proof.r0_row_root.IsNull() ||
        !join_context.valid ||
        !expected_context.valid ||
        expected_context.root !=
            join_context.root ||
        proof.join_context_root !=
            join_context.root ||
        statement.plan.shard_index >=
            join_context.tape_r0_roots.size() ||
        join_context.tape_r0_roots[
            statement.plan.shard_index] !=
            proof.r0_row_root) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "proof_envelope";
        }
        return false;
    }
    aq::AirConstraintSystem<Fp3> cs;
    ShardLayoutV2 layout;
    if (!BuildShardConstraintSystemV2(
            statement, cs, &layout,
            nullptr, why)) {
        return false;
    }
    ShardSourceChallengesV2 challenges;
    if (!DeriveShardSourceChallengesV2(
            statement,
            proof.r0_row_root,
            join_context,
            challenges) ||
        !AppendShardSourceTerminal(
            layout, challenges,
            statement.plan.shard_index,
            proof.source_terminal, cs)) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "source_terminal_cs";
        }
        return false;
    }
    std::vector<uint32_t> base;
    base.reserve(layout.dependent_base);
    for (uint32_t column = 0;
         column < layout.dependent_base;
         ++column) {
        base.push_back(column);
    }
    if (proof.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.proof.batch.groups[0].
                row_commit.root) !=
            proof.r0_row_root) {
        if (why) {
            *why =
                "stage3:proof_tape_shard:"
                "r0_envelope";
        }
        return false;
    }
    return
        aq::AirQuotientVerifyRowsSplitRapSafeV2(
            cs, proof.proof, base,
            DeriveShardFsSeed(
                statement,
                join_context.root),
            why);
}

bool VerifyShardCoverageChainForMaxRowsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const std::vector<ShardReceiptV2>& receipts,
    uint32_t max_rows,
    std::string* why)
{
    const auto fail =
        [&](const char* detail) {
            if (why) {
                *why =
                    std::string{
                        "stage3:proof_tape_shard:"} +
                    detail;
            }
            return false;
        };
    const auto plans =
        BuildShardPlansForMaxRowsV2(
            shape, binding, max_rows);
    const uint256 inventory =
        ComputeShardSourceInventoryRootV2(
            shape, binding);
    if (plans.empty() ||
        receipts.size() != plans.size() ||
        inventory.IsNull()) {
        return fail("receipt_count");
    }
    alg_hash::State zero{};
    if (!StateEq(
            receipts.front().start_state,
            zero)) {
        return fail("initial_state");
    }
    for (uint32_t index = 0;
         index < receipts.size(); ++index) {
        const auto& receipt =
            receipts[index];
        if (!SameShardPlan(
                receipt.plan, plans[index]) ||
            receipt.source_inventory_root !=
                inventory) {
            return fail(
                "receipt_plan_or_proof");
        }
        if (index != 0 &&
            !StateEq(
                receipts[index - 1].
                    end_state,
                receipt.start_state)) {
            return fail(
                "state_chain");
        }
        if (index + 1 < receipts.size() &&
            receipt.next_record_value !=
                receipts[index + 1].
                    first_record_value) {
            return fail(
                "record_value_chain");
        }
    }
    if (receipts.back().next_record_value != 0) {
        return fail("terminal_record_value");
    }
    alg_hash::Digest final_root{};
    std::copy_n(
        receipts.back().
            end_state.begin(),
        final_root.size(),
        final_root.begin());
    if (final_root != binding.tape_root) {
        return fail("terminal_root");
    }
    if (why) {
        *why =
            "stage3:proof_tape_shard:"
            "receipt_chain_verified";
    }
    return true;
}

bool VerifyShardReceiptChainForMaxRowsV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const ShardJoinContextV2& join_context,
    const std::vector<ShardReceiptV2>& receipts,
    uint32_t max_rows,
    std::string* why)
{
    if (!VerifyShardCoverageChainForMaxRowsV2(
            shape, binding, receipts,
            max_rows, why)) {
        return false;
    }
    for (const auto& receipt : receipts) {
        const ShardStatementV2 statement{
            .child_shape = shape,
            .binding = binding,
            .plan = receipt.plan,
            .start_state =
                receipt.start_state,
            .end_state =
                receipt.end_state,
            .first_record_value =
                receipt.first_record_value,
            .next_record_value =
                receipt.next_record_value,
            .source_inventory_root =
                receipt.source_inventory_root,
        };
        if (!VerifyShardV2(
                statement, join_context,
                receipt.proof,
                why)) {
            return false;
        }
    }
    return true;
}

bool VerifyShardReceiptChainV2(
    const PublicShapeV1& shape,
    const PublicBindingV1& binding,
    const ShardJoinContextV2& join_context,
    const std::vector<ShardReceiptV2>& receipts,
    std::string* why)
{
    return VerifyShardReceiptChainForMaxRowsV2(
        shape, binding, join_context, receipts,
        kProofTapeShardMaxRowsV2, why);
}

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air
