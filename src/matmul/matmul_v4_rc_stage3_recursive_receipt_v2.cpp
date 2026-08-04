// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_receipt_v2.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>

namespace matmul::v4::rc::recursive_receipt_v2 {
namespace {

constexpr uint32_t kQuotientRowKindV2 = 8;
constexpr uint32_t kMaxQueriesV2 = 4096;
constexpr std::array<const char*, kSourceOpeningLanesV2>
    kSourceOpeningConstraintNamesV2{
        "stage3.recursive_receipt_v2.source_opening_lane_0",
        "stage3.recursive_receipt_v2.source_opening_lane_1",
        "stage3.recursive_receipt_v2.source_opening_lane_2",
        "stage3.recursive_receipt_v2.source_opening_lane_3",
        "stage3.recursive_receipt_v2.source_opening_lane_4",
        "stage3.recursive_receipt_v2.source_opening_lane_5",
        "stage3.recursive_receipt_v2.source_opening_lane_6",
        "stage3.recursive_receipt_v2.source_opening_lane_7",
    };

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_receipt_v2:" + detail;
    }
    return false;
}

bool CanonicalFp3(const gf::Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool CanonicalFp3Vector(const std::vector<gf::Fp3>& values)
{
    return std::all_of(
        values.begin(), values.end(),
        [](const gf::Fp3& value) {
            return CanonicalFp3(value);
        });
}

bool SameFp3Vector(
    const std::vector<gf::Fp3>& lhs,
    const std::vector<gf::Fp3>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!gf::Eq(lhs[i], rhs[i])) return false;
    }
    return true;
}

void WriteU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteHash(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_bytes(bytes)
    {
    }

    bool U16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
            static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8;
        m_pos += 2;
        return true;
    }

    bool U32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (uint32_t i = 0; i < 4; ++i) {
            out |= static_cast<uint32_t>(
                       m_bytes[m_pos + i])
                << (8U * i);
        }
        m_pos += 4;
        return true;
    }

    bool U64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            out |= static_cast<uint64_t>(
                       m_bytes[m_pos + i])
                << (8U * i);
        }
        m_pos += 8;
        return true;
    }

    bool Hash(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos),
            out.size(), out.begin());
        m_pos += out.size();
        return true;
    }

    bool Bytes(uint32_t count, std::vector<unsigned char>& out)
    {
        if (Remaining() < count) return false;
        out.assign(
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos),
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos + count));
        m_pos += count;
        return true;
    }

    [[nodiscard]] size_t Remaining() const
    {
        return m_bytes.size() - m_pos;
    }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

std::array<uint32_t, kIdentityLimbsV2> HashLimbs(
    const uint256& value)
{
    std::array<uint32_t, kIdentityLimbsV2> out{};
    for (uint32_t limb = 0; limb < kIdentityLimbsV2; ++limb) {
        out[limb] =
            static_cast<uint32_t>(value.begin()[4U * limb]) |
            (static_cast<uint32_t>(
                 value.begin()[4U * limb + 1])
             << 8) |
            (static_cast<uint32_t>(
                 value.begin()[4U * limb + 2])
             << 16) |
            (static_cast<uint32_t>(
                 value.begin()[4U * limb + 3])
             << 24);
    }
    return out;
}

const std::vector<gf::Fp3>* FindPreprocessed(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    uint32_t column)
{
    const auto it = std::find_if(
        cs.preprocessed.begin(), cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
    return it == cs.preprocessed.end() ? nullptr : &it->second;
}

bool HasConstraint(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::string& name)
{
    return std::any_of(
        cs.constraints.begin(), cs.constraints.end(),
        [&name](const auto& constraint) {
            return constraint.name == name;
        });
}

bool IdentityColumnEquals(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    uint32_t base,
    const uint256& identity,
    const std::vector<uint32_t>& quotient_rows)
{
    const auto limbs = HashLimbs(identity);
    for (uint32_t limb = 0; limb < kIdentityLimbsV2; ++limb) {
        const auto* column = FindPreprocessed(cs, base + limb);
        if (column == nullptr || column->size() != cs.n_rows) {
            return false;
        }
        std::vector<bool> active(cs.n_rows, false);
        for (const uint32_t row : quotient_rows) {
            if (row >= cs.n_rows ||
                !gf::Eq(
                    (*column)[row],
                    gf::Fp3::FromFp(
                        gf::FromU64(limbs[limb])))) {
                return false;
            }
            active[row] = true;
        }
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            if (!CanonicalFp3((*column)[row])) {
                return false;
            }
            if (!active[row] &&
                !gf::IsZero((*column)[row])) {
                return false;
            }
        }
    }
    return true;
}

bool CollectSourceOpeningExports(
    const fp::FoldBusComposition& composition,
    uint32_t current_width,
    std::vector<SourceOpeningExportV2>& exports,
    std::vector<std::array<gf::Fp, 3>>& coordinates,
    std::vector<gf::Fp3>& q_values,
    std::string* why)
{
    exports.clear();
    coordinates.clear();
    q_values.clear();
    if (!composition.valid || current_width == 0 ||
        composition.columns.size() !=
            composition.combined.n_columns ||
        composition.hash.program.public_inputs.query_index.empty()) {
        return Fail(why, "source_opening_input");
    }
    const uint32_t queries = static_cast<uint32_t>(
        composition.hash.program.public_inputs.query_index.size());
    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            composition.hash.column_base);
    if (hash_layout.absorbed_pin_base +
            kSourceOpeningLanesV2 >
        composition.combined.n_columns) {
        return Fail(why, "source_opening_layout");
    }
    coordinates.assign(queries, {});
    std::vector<std::array<bool, 3>> seen(queries);
    for (uint32_t row = 0;
         row < composition.hash.program.active_rows;
         ++row) {
        if (row >= composition.hash.program.rows.size() ||
            row >= composition.combined.n_rows) {
            return Fail(why, "source_opening_row");
        }
        const auto& meta =
            composition.hash.program.rows[row];
        if (!meta.current_row_sponge) continue;
        for (uint32_t lane = 0;
             lane < kSourceOpeningLanesV2; ++lane) {
            const uint32_t position =
                meta.current_word_offset + lane;
            const uint32_t width_items =
                current_width + 1U;
            if (position >= 3U * width_items) continue;
            const uint32_t item = position / 3U;
            const uint32_t coordinate = position % 3U;
            if (item != current_width) continue;
            if (meta.query >= queries ||
                coordinate >= 3 ||
                seen[meta.query][coordinate]) {
                return Fail(why, "source_opening_schedule");
            }
            const gf::Fp3 value =
                composition.columns[
                    hash_layout.absorbed_pin_base +
                    lane][row];
            if (!CanonicalFp3(value) ||
                value.c1 != 0 || value.c2 != 0) {
                return Fail(why, "source_opening_noncanonical");
            }
            seen[meta.query][coordinate] = true;
            coordinates[meta.query][coordinate] =
                value.c0;
            exports.push_back(SourceOpeningExportV2{
                meta.query, row, lane, coordinate,
                value.c0});
        }
    }
    if (exports.size() !=
        static_cast<size_t>(queries) * 3U) {
        return Fail(why, "source_opening_count");
    }
    q_values.assign(queries, gf::Fp3::Zero());
    for (uint32_t query = 0; query < queries; ++query) {
        if (!seen[query][0] || !seen[query][1] ||
            !seen[query][2]) {
            return Fail(why, "source_opening_missing");
        }
        q_values[query] = gf::Fp3{
            coordinates[query][0],
            coordinates[query][1],
            coordinates[query][2]};
    }
    std::sort(
        exports.begin(), exports.end(),
        [](const auto& lhs, const auto& rhs) {
            if (lhs.query != rhs.query) {
                return lhs.query < rhs.query;
            }
            return lhs.coordinate < rhs.coordinate;
        });
    return true;
}

std::vector<uint32_t> QuotientRows(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const rr::ShardTerminalBindingV1& local)
{
    std::vector<uint32_t> out;
    const uint32_t bytecode_width =
        fp::BytecodeBusLayout(0).End();
    if (local.original_columns < bytecode_width) {
        return out;
    }
    const fp::BytecodeBusLayout bus(
        local.original_columns - bytecode_width);
    const auto* rows =
        FindPreprocessed(
            cs, bus.RowKind(kQuotientRowKindV2));
    if (rows == nullptr || rows->size() != cs.n_rows) {
        return out;
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        if (!gf::IsZero((*rows)[row])) {
            out.push_back(row);
        }
    }
    return out;
}

bool BindingMatchesConstraintSystem(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const ShardSourceTerminalBindingV2& binding,
    std::string* why)
{
    if (!binding.valid ||
        binding.version != kShardReceiptVersionV2 ||
        !binding.local.valid ||
        binding.local.version != rr::kShardReceiptVersionV1 ||
        binding.local.queries == 0 ||
        binding.local.queries > kMaxQueriesV2 ||
        binding.local.layout.End() != binding.layout.base ||
        binding.layout.End() != cs.n_columns ||
        binding.source_current_width == 0 ||
        binding.source_proof_commitment.IsNull() ||
        binding.source_fs_seed.IsNull() ||
        binding.source_prechallenge_commitment.IsNull() ||
        binding.source_parent_q_per_query.size() !=
            binding.local.queries ||
        binding.source_parent_q_coordinates.size() !=
            binding.local.queries ||
        binding.source_opening_exports.size() !=
            static_cast<size_t>(binding.local.queries) * 3U ||
        !CanonicalFp3Vector(binding.local.local_q_per_query) ||
        !CanonicalFp3Vector(
            binding.source_parent_q_per_query)) {
        return Fail(why, "binding_shape");
    }
    for (uint32_t query = 0;
         query < binding.local.queries; ++query) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            if (binding.source_parent_q_coordinates
                    [query][coordinate] >= gf::kP) {
                return Fail(why, "binding_coordinate_noncanonical");
            }
        }
        const gf::Fp3 reconstructed{
            binding.source_parent_q_coordinates[query][0],
            binding.source_parent_q_coordinates[query][1],
            binding.source_parent_q_coordinates[query][2]};
        if (!gf::Eq(
                reconstructed,
                binding.source_parent_q_per_query[query])) {
            return Fail(why, "binding_source_q");
        }
    }
    const std::vector<uint32_t> quotient_rows =
        QuotientRows(cs, binding.local);
    if (quotient_rows.size() != binding.local.queries) {
        return Fail(why, "binding_quotient_rows");
    }
    const auto* local_expected =
        FindPreprocessed(
            cs, binding.local.layout.expected_local_q);
    const auto* query_index =
        FindPreprocessed(
            cs, binding.local.layout.query_index);
    const auto* source_q =
        FindPreprocessed(
            cs, binding.layout.source_parent_q);
    if (local_expected == nullptr || query_index == nullptr ||
        source_q == nullptr ||
        local_expected->size() != cs.n_rows ||
        query_index->size() != cs.n_rows ||
        source_q->size() != cs.n_rows) {
        return Fail(why, "binding_terminal_columns");
    }
    for (uint32_t query = 0;
         query < binding.local.queries; ++query) {
        const uint32_t row = quotient_rows[query];
        if (!gf::Eq(
                (*local_expected)[row],
                binding.local.local_q_per_query[query]) ||
            !gf::Eq(
                (*query_index)[row],
                gf::Fp3::FromFp(gf::FromU64(
                    binding.local.query_indices[query]))) ||
            !gf::Eq(
                (*source_q)[row],
                binding.source_parent_q_per_query[query])) {
            return Fail(why, "binding_terminal_values");
        }
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            const auto* column = FindPreprocessed(
                cs,
                binding.layout.SourceCoordinate(coordinate));
            if (column == nullptr ||
                column->size() != cs.n_rows ||
                !CanonicalFp3((*column)[row]) ||
                !gf::Eq(
                    (*column)[row],
                    gf::Fp3::FromFp(
                        binding.source_parent_q_coordinates
                            [query][coordinate]))) {
                return Fail(why, "binding_coordinate_columns");
            }
        }
    }
    std::vector<bool> quotient_active(cs.n_rows, false);
    for (const uint32_t row : quotient_rows) {
        quotient_active[row] = true;
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        if (!CanonicalFp3((*local_expected)[row]) ||
            !CanonicalFp3((*query_index)[row]) ||
            !CanonicalFp3((*source_q)[row])) {
            return Fail(why, "binding_terminal_noncanonical");
        }
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            const auto* column = FindPreprocessed(
                cs,
                binding.layout.SourceCoordinate(coordinate));
            if (column == nullptr ||
                !CanonicalFp3((*column)[row]) ||
                (!quotient_active[row] &&
                 !gf::IsZero((*column)[row]))) {
                return Fail(
                    why, "binding_coordinate_padding");
            }
        }
        if (!quotient_active[row] &&
            (!gf::IsZero((*local_expected)[row]) ||
             !gf::IsZero((*query_index)[row]) ||
             !gf::IsZero((*source_q)[row]))) {
            return Fail(why, "binding_terminal_padding");
        }
    }
    if (!IdentityColumnEquals(
            cs, binding.layout.source_proof_identity_base,
            binding.source_proof_commitment, quotient_rows) ||
        !IdentityColumnEquals(
            cs, binding.layout.source_fs_seed_identity_base,
            binding.source_fs_seed, quotient_rows) ||
        !IdentityColumnEquals(
            cs,
            binding.layout.source_prechallenge_identity_base,
            binding.source_prechallenge_commitment,
            quotient_rows) ||
        !IdentityColumnEquals(
            cs, binding.layout.shard_program_identity_base,
            binding.local.program_commitment,
            quotient_rows) ||
        !IdentityColumnEquals(
            cs,
            binding.layout.shard_prechallenge_identity_base,
            binding.local.bytecode_prechallenge_commitment,
            quotient_rows)) {
        return Fail(why, "binding_identity_columns");
    }
    const auto* shard_index =
        FindPreprocessed(cs, binding.layout.shard_index);
    const auto* program_count =
        FindPreprocessed(cs, binding.layout.program_count);
    if (shard_index == nullptr || program_count == nullptr ||
        shard_index->size() != cs.n_rows ||
        program_count->size() != cs.n_rows) {
        return Fail(why, "binding_shard_columns");
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        if (!CanonicalFp3((*shard_index)[row]) ||
            !CanonicalFp3((*program_count)[row])) {
            return Fail(why, "binding_shard_noncanonical");
        }
    }
    for (const uint32_t row : quotient_rows) {
        if (!gf::Eq(
                (*shard_index)[row],
                gf::Fp3::FromFp(gf::FromU64(
                    binding.local.shard_index))) ||
            !gf::Eq(
                (*program_count)[row],
                gf::Fp3::FromFp(gf::FromU64(
                    binding.local.program_count)))) {
            return Fail(why, "binding_shard_values");
        }
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        if (!quotient_active[row] &&
            (!gf::IsZero((*source_q)[row]) ||
             !gf::IsZero((*shard_index)[row]) ||
             !gf::IsZero((*program_count)[row]))) {
            return Fail(why, "binding_terminal_padding");
        }
    }

    std::vector<std::array<bool, kSourceOpeningLanesV2>>
        opening_active(cs.n_rows);
    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            binding.source_hash_column_base);
    for (const auto& export_cell :
         binding.source_opening_exports) {
        if (export_cell.query >= binding.local.queries ||
            export_cell.row >= cs.n_rows ||
            export_cell.lane >= kSourceOpeningLanesV2 ||
            export_cell.coordinate >= 3 ||
            export_cell.value >= gf::kP ||
            export_cell.value !=
                binding.source_parent_q_coordinates
                    [export_cell.query]
                    [export_cell.coordinate] ||
            opening_active[export_cell.row][export_cell.lane]) {
            return Fail(why, "binding_opening_export_shape");
        }
        const auto* values = FindPreprocessed(
            cs,
            binding.layout.SourceOpeningValue(
                export_cell.lane));
        const auto* masks = FindPreprocessed(
            cs,
            binding.layout.SourceOpeningMask(
                export_cell.lane));
        if (values == nullptr || masks == nullptr ||
            values->size() != cs.n_rows ||
            masks->size() != cs.n_rows ||
            !CanonicalFp3((*values)[export_cell.row]) ||
            !CanonicalFp3((*masks)[export_cell.row]) ||
            !gf::Eq(
                (*values)[export_cell.row],
                gf::Fp3::FromFp(export_cell.value)) ||
            !gf::Eq(
                (*masks)[export_cell.row],
                gf::Fp3::One())) {
            return Fail(why, "binding_opening_export_values");
        }
        opening_active[export_cell.row][export_cell.lane] =
            true;
        if (hash_layout.absorbed_pin_base +
                export_cell.lane >=
            cs.n_columns) {
            return Fail(why, "binding_hash_layout");
        }
    }
    for (uint32_t lane = 0;
         lane < kSourceOpeningLanesV2; ++lane) {
        const auto* values = FindPreprocessed(
            cs, binding.layout.SourceOpeningValue(lane));
        const auto* masks = FindPreprocessed(
            cs, binding.layout.SourceOpeningMask(lane));
        if (values == nullptr || masks == nullptr) {
            return Fail(why, "binding_opening_columns");
        }
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            if (!CanonicalFp3((*values)[row]) ||
                !CanonicalFp3((*masks)[row])) {
                return Fail(
                    why, "binding_opening_noncanonical");
            }
            if (!opening_active[row][lane] &&
                (!gf::IsZero((*values)[row]) ||
                 !gf::IsZero((*masks)[row]))) {
                return Fail(why, "binding_opening_padding");
            }
        }
        if (!HasConstraint(
                cs,
                kSourceOpeningConstraintNamesV2[lane])) {
            return Fail(why, "binding_opening_constraint");
        }
    }
    if (!HasConstraint(
            cs,
            "stage3.fixedpoint.bytecode."
            "shard_receipt_local_q") ||
        !HasConstraint(
            cs,
            "stage3.recursive_receipt_v2."
            "source_parent_q_reconstruct")) {
        return Fail(why, "binding_terminal_constraint");
    }
    return true;
}

fp::AlgAirProof ToCanonicalAlgProof(
    aq::AirQuotientRowsProof proof)
{
    fp::AlgAirProof out;
    out.batch = std::move(proof.batch);
    out.next_openings = std::move(proof.next_openings);
    out.trace_commit = proof.trace_commit;
    return out;
}

bool NativeSourceMatchesBinding(
    const aq::AirConstraintSystem<gf::Fp3>& source_child_cs,
    const fp::AlgAirProof& source_child_proof,
    const uint256& source_child_fs_seed,
    const ShardSourceTerminalBindingV2& binding,
    std::string* why)
{
    std::string native_why;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            source_child_cs, source_child_proof,
            source_child_fs_seed, &native_why)) {
        return Fail(
            why, "source_native_verify:" + native_why);
    }
    const uint256 proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(
            source_child_proof);
    if (proof_commitment.IsNull() ||
        proof_commitment !=
            binding.source_proof_commitment ||
        source_child_fs_seed != binding.source_fs_seed) {
        return Fail(why, "source_identity");
    }
    const fp::FoldBusComposition rebuilt =
        fp::BuildFoldBusComposition(
            source_child_cs, source_child_proof,
            source_child_fs_seed);
    if (!rebuilt.valid ||
        rebuilt.prechallenge_commitment !=
            binding.source_prechallenge_commitment) {
        return Fail(why, "source_prechallenge");
    }
    std::vector<SourceOpeningExportV2> exports;
    std::vector<std::array<gf::Fp, 3>> coordinates;
    std::vector<gf::Fp3> q_values;
    if (!CollectSourceOpeningExports(
            rebuilt, binding.source_current_width,
            exports, coordinates, q_values, why) ||
        coordinates !=
            binding.source_parent_q_coordinates ||
        !SameFp3Vector(
            q_values,
            binding.source_parent_q_per_query)) {
        return Fail(why, "source_reconstruction");
    }
    return true;
}

bool ReceiptShapeCanonical(const ShardReceiptV2& receipt)
{
    return
        receipt.version == kShardReceiptVersionV2 &&
        receipt.queries != 0 &&
        receipt.queries <= kMaxQueriesV2 &&
        receipt.query_indices.size() == receipt.queries &&
        receipt.local_q_per_query.size() == receipt.queries &&
        receipt.source_parent_q_per_query.size() ==
            receipt.queries &&
        CanonicalFp3Vector(receipt.local_q_per_query) &&
        CanonicalFp3Vector(
            receipt.source_parent_q_per_query) &&
        receipt.program_count != 0 &&
        receipt.n_rows != 0 &&
        receipt.n_columns != 0 &&
        receipt.n_constraints != 0 &&
        receipt.source_current_width != 0 &&
        !receipt.program_commitment.IsNull() &&
        !receipt.bytecode_prechallenge_commitment.IsNull() &&
        !receipt.source_proof_commitment.IsNull() &&
        !receipt.source_fs_seed.IsNull() &&
        !receipt.source_prechallenge_commitment.IsNull() &&
        !receipt.statement_commitment.IsNull() &&
        !receipt.receipt_fs_seed.IsNull() &&
        !receipt.proof_commitment.IsNull() &&
        !receipt.proof_bytes.empty();
}

} // namespace

ShardSourceTerminalBindingV2 BindShardSourceTerminalsV2(
    fp::FoldBusComposition& attached_shard,
    const fp::BytecodeInterpreterAttachment& interpreter,
    uint32_t shard_index,
    const aq::AirConstraintSystem<gf::Fp3>& source_child_cs,
    const fp::AlgAirProof& source_child_proof,
    const uint256& source_child_fs_seed,
    uint32_t source_current_width)
{
    ShardSourceTerminalBindingV2 out;
    out.source_current_width = source_current_width;
    out.source_hash_column_base =
        attached_shard.hash.column_base;
    if (!attached_shard.valid ||
        source_current_width == 0 ||
        source_child_fs_seed.IsNull()) {
        out.note =
            "stage3:recursive_receipt_v2:bind_input";
        return out;
    }
    std::string why;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            source_child_cs, source_child_proof,
            source_child_fs_seed, &why)) {
        out.note =
            "stage3:recursive_receipt_v2:"
            "source_native_verify:" + why;
        return out;
    }
    out.source_child_native_verified = true;
    out.source_proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(
            source_child_proof);
    out.source_fs_seed = source_child_fs_seed;
    if (out.source_proof_commitment.IsNull()) {
        out.note =
            "stage3:recursive_receipt_v2:"
            "source_proof_commitment";
        return out;
    }
    const fp::FoldBusComposition rebuilt =
        fp::BuildFoldBusComposition(
            source_child_cs, source_child_proof,
            source_child_fs_seed);
    if (!rebuilt.valid ||
        attached_shard.prechallenge_commitment !=
            rebuilt.prechallenge_commitment) {
        out.note =
            "stage3:recursive_receipt_v2:"
            "source_fold_bus_identity";
        return out;
    }
    out.source_prechallenge_commitment =
        rebuilt.prechallenge_commitment;

    std::vector<SourceOpeningExportV2> rebuilt_exports;
    std::vector<std::array<gf::Fp, 3>>
        rebuilt_coordinates;
    std::vector<gf::Fp3> rebuilt_q;
    if (!CollectSourceOpeningExports(
            attached_shard, source_current_width,
            out.source_opening_exports,
            out.source_parent_q_coordinates,
            out.source_parent_q_per_query, &why) ||
        !CollectSourceOpeningExports(
            rebuilt, source_current_width,
            rebuilt_exports, rebuilt_coordinates,
            rebuilt_q, &why) ||
        out.source_opening_exports != rebuilt_exports ||
        out.source_parent_q_coordinates !=
            rebuilt_coordinates ||
        !SameFp3Vector(
            out.source_parent_q_per_query,
            rebuilt_q)) {
        out.note = why.empty()
            ? "stage3:recursive_receipt_v2:"
              "source_opening_mismatch"
            : why;
        return out;
    }

    out.local = rr::BindShardLocalQuotientTerminalsV1(
        attached_shard, interpreter, shard_index);
    if (!out.local.valid ||
        out.local.queries !=
            out.source_parent_q_per_query.size()) {
        out.note =
            "stage3:recursive_receipt_v2:"
            "local_v1_binding:" + out.local.note;
        return out;
    }
    out.local_q_v1_constrained = true;
    out.layout =
        ShardSourceTerminalLayoutV2(
            attached_shard.combined.n_columns);
    const uint32_t rows = attached_shard.combined.n_rows;
    attached_shard.combined.n_columns = out.layout.End();
    attached_shard.columns.resize(
        out.layout.End(),
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));

    for (const auto& export_cell :
         out.source_opening_exports) {
        attached_shard.columns[
            out.layout.SourceOpeningValue(
                export_cell.lane)][export_cell.row] =
            gf::Fp3::FromFp(export_cell.value);
        attached_shard.columns[
            out.layout.SourceOpeningMask(
                export_cell.lane)][export_cell.row] =
            gf::Fp3::One();
    }
    const std::vector<uint32_t> quotient_rows =
        QuotientRows(attached_shard.combined, out.local);
    if (quotient_rows.size() != out.local.queries) {
        out.note =
            "stage3:recursive_receipt_v2:"
            "quotient_rows";
        return out;
    }
    const auto source_proof_limbs =
        HashLimbs(out.source_proof_commitment);
    const auto source_seed_limbs =
        HashLimbs(out.source_fs_seed);
    const auto source_prechallenge_limbs =
        HashLimbs(out.source_prechallenge_commitment);
    const auto program_limbs =
        HashLimbs(out.local.program_commitment);
    const auto shard_prechallenge_limbs =
        HashLimbs(
            out.local.bytecode_prechallenge_commitment);
    for (uint32_t query = 0;
         query < out.local.queries; ++query) {
        const uint32_t row = quotient_rows[query];
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            attached_shard.columns[
                out.layout.SourceCoordinate(coordinate)][row] =
                gf::Fp3::FromFp(
                    out.source_parent_q_coordinates
                        [query][coordinate]);
        }
        attached_shard.columns[
            out.layout.source_parent_q][row] =
            out.source_parent_q_per_query[query];
        for (uint32_t limb = 0;
             limb < kIdentityLimbsV2; ++limb) {
            attached_shard.columns[
                out.layout.source_proof_identity_base +
                limb][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    source_proof_limbs[limb]));
            attached_shard.columns[
                out.layout.source_fs_seed_identity_base +
                limb][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    source_seed_limbs[limb]));
            attached_shard.columns[
                out.layout
                    .source_prechallenge_identity_base +
                limb][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    source_prechallenge_limbs[limb]));
            attached_shard.columns[
                out.layout.shard_program_identity_base +
                limb][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    program_limbs[limb]));
            attached_shard.columns[
                out.layout
                    .shard_prechallenge_identity_base +
                limb][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    shard_prechallenge_limbs[limb]));
        }
        attached_shard.columns[out.layout.shard_index][row] =
            gf::Fp3::FromFp(gf::FromU64(
                out.local.shard_index));
        attached_shard.columns[out.layout.program_count][row] =
            gf::Fp3::FromFp(gf::FromU64(
                out.local.program_count));
    }

    // Every V2 column is a verifier-owned public/preprocessed column.
    for (uint32_t column = out.layout.base;
         column < out.layout.End(); ++column) {
        attached_shard.combined.preprocessed.emplace_back(
            column, attached_shard.columns[column]);
    }
    attached_shard.combined.preprocessed_pin_ood = true;
    out.identities_u32_preprocessed = true;

    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            out.source_hash_column_base);
    for (uint32_t lane = 0;
         lane < kSourceOpeningLanesV2; ++lane) {
        aq::AirConstraint<gf::Fp3> alias;
        alias.name =
            kSourceOpeningConstraintNamesV2[lane];
        alias.kind = aq::AirKind::kEverywhere;
        alias.alg_degree = 2;
        alias.eval =
            [layout = out.layout, hash_layout, lane](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[layout.SourceOpeningMask(lane)],
                    gf::Sub(
                        cur[
                            hash_layout.absorbed_pin_base +
                            lane],
                        cur[
                            layout.SourceOpeningValue(
                                lane)]));
            };
        attached_shard.combined.constraints.push_back(
            std::move(alias));
    }
    out.source_opening_direct_aliases = true;

    const uint32_t bytecode_width =
        fp::BytecodeBusLayout(0).End();
    const fp::BytecodeBusLayout bytecode(
        out.local.original_columns - bytecode_width);
    aq::AirConstraint<gf::Fp3> reconstruct;
    reconstruct.name =
        "stage3.recursive_receipt_v2."
        "source_parent_q_reconstruct";
    reconstruct.kind = aq::AirKind::kEverywhere;
    reconstruct.alg_degree = 2;
    reconstruct.eval =
        [layout = out.layout, bytecode](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            const gf::Fp3 u{0, 1, 0};
            const gf::Fp3 u2{0, 0, 1};
            const gf::Fp3 reconstructed =
                gf::Add(
                    cur[layout.SourceCoordinate(0)],
                    gf::Add(
                        gf::Mul(
                            u,
                            cur[
                                layout.SourceCoordinate(
                                    1)]),
                        gf::Mul(
                            u2,
                            cur[
                                layout.SourceCoordinate(
                                    2)])));
            return gf::Mul(
                cur[
                    bytecode.RowKind(
                        kQuotientRowKindV2)],
                gf::Sub(
                    cur[layout.source_parent_q],
                    reconstructed));
        };
    attached_shard.combined.constraints.push_back(
        std::move(reconstruct));
    out.source_q_reconstruction_constrained = true;

    out.valid = true;
    out.statement_commitment =
        ComputeShardSourceStatementCommitmentV2(
            out, attached_shard.combined.n_rows,
            attached_shard.combined.n_columns,
            static_cast<uint32_t>(
                attached_shard.combined.constraints.size()));
    if (out.statement_commitment.IsNull() ||
        !BindingMatchesConstraintSystem(
            attached_shard.combined, out, &why)) {
        out.valid = false;
        out.note = why.empty()
            ? "stage3:recursive_receipt_v2:statement"
            : why;
        return out;
    }
    out.note =
        "stage3:recursive_receipt_v2:"
        "source_and_local_terminals_bound";
    return out;
}

uint256 ComputeShardSourceStatementCommitmentV2(
    const ShardSourceTerminalBindingV2& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints)
{
    if (binding.version != kShardReceiptVersionV2 ||
        !binding.local.valid ||
        binding.local.queries == 0 ||
        binding.local.queries > kMaxQueriesV2 ||
        binding.local.query_indices.size() !=
            binding.local.queries ||
        binding.local.local_q_per_query.size() !=
            binding.local.queries ||
        binding.source_parent_q_per_query.size() !=
            binding.local.queries ||
        binding.source_parent_q_coordinates.size() !=
            binding.local.queries ||
        binding.source_opening_exports.size() !=
            static_cast<size_t>(binding.local.queries) * 3U ||
        !CanonicalFp3Vector(binding.local.local_q_per_query) ||
        !CanonicalFp3Vector(
            binding.source_parent_q_per_query) ||
        binding.source_proof_commitment.IsNull() ||
        binding.source_fs_seed.IsNull() ||
        binding.source_prechallenge_commitment.IsNull() ||
        binding.local.program_commitment.IsNull() ||
        binding.local.bytecode_prechallenge_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SHARD_SOURCE_STATEMENT_V2";
    hash << binding.version;
    hash << binding.source_current_width;
    hash << binding.source_hash_column_base;
    hash << binding.local.shard_index;
    hash << binding.local.program_count;
    hash << binding.local.queries;
    hash << binding.local.original_columns;
    hash << binding.layout.base;
    hash << binding.layout.End();
    hash << n_rows;
    hash << n_columns;
    hash << n_constraints;
    hash << binding.source_proof_commitment;
    hash << binding.source_fs_seed;
    hash << binding.source_prechallenge_commitment;
    hash << binding.local.program_commitment;
    hash << binding.local.bytecode_prechallenge_commitment;
    for (uint32_t query = 0;
         query < binding.local.queries; ++query) {
        hash << binding.local.query_indices[query];
        const gf::Fp3 local =
            binding.local.local_q_per_query[query];
        const gf::Fp3 source =
            binding.source_parent_q_per_query[query];
        const std::array<gf::Fp, 3> source_coordinates{
            source.c0, source.c1, source.c2};
        hash << local.c0 << local.c1 << local.c2;
        hash << source.c0 << source.c1 << source.c2;
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            const gf::Fp value =
                binding.source_parent_q_coordinates
                    [query][coordinate];
            if (value >= gf::kP ||
                value != source_coordinates[coordinate]) {
                return {};
            }
            hash << value;
        }
    }
    for (const auto& export_cell :
         binding.source_opening_exports) {
        if (export_cell.query >= binding.local.queries ||
            export_cell.row >= n_rows ||
            export_cell.lane >= kSourceOpeningLanesV2 ||
            export_cell.coordinate >= 3 ||
            export_cell.value >= gf::kP) {
            return {};
        }
        hash << export_cell.query;
        hash << export_cell.row;
        hash << export_cell.lane;
        hash << export_cell.coordinate;
        hash << export_cell.value;
    }
    return hash.GetHash();
}

uint256 ComputeShardReceiptFsSeedV2(
    const ShardSourceTerminalBindingV2& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints)
{
    const uint256 statement =
        ComputeShardSourceStatementCommitmentV2(
            binding, n_rows, n_columns, n_constraints);
    if (statement.IsNull()) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SHARD_RECEIPT_FS_V2";
    hash << statement;
    hash << binding.source_proof_commitment;
    hash << binding.source_fs_seed;
    hash << binding.source_prechallenge_commitment;
    hash << binding.local.program_commitment;
    hash << binding.local.bytecode_prechallenge_commitment;
    hash << n_rows << n_columns << n_constraints;
    return hash.GetHash();
}

uint256 ComputeShardReceiptRootV2(
    const ShardReceiptV2& receipt)
{
    if (!ReceiptShapeCanonical(receipt)) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SHARD_RECEIPT_ROOT_V2";
    hash << receipt.version;
    hash << receipt.shard_index;
    hash << receipt.program_count;
    hash << receipt.queries;
    hash << receipt.n_rows;
    hash << receipt.n_columns;
    hash << receipt.n_constraints;
    hash << receipt.source_current_width;
    hash << receipt.program_commitment;
    hash << receipt.bytecode_prechallenge_commitment;
    hash << receipt.source_proof_commitment;
    hash << receipt.source_fs_seed;
    hash << receipt.source_prechallenge_commitment;
    hash << receipt.statement_commitment;
    hash << receipt.receipt_fs_seed;
    hash << receipt.proof_commitment;
    for (uint32_t query = 0;
         query < receipt.queries; ++query) {
        hash << receipt.query_indices[query];
        const gf::Fp3 local =
            receipt.local_q_per_query[query];
        const gf::Fp3 source =
            receipt.source_parent_q_per_query[query];
        hash << local.c0 << local.c1 << local.c2;
        hash << source.c0 << source.c1 << source.c2;
    }
    return hash.GetHash();
}

ShardReceiptProveResultV2 ProveShardReceiptV2(
    const fp::FoldBusComposition& attached_shard,
    const ShardSourceTerminalBindingV2& binding)
{
    ShardReceiptProveResultV2 out;
    std::string why;
    if (!attached_shard.valid ||
        !BindingMatchesConstraintSystem(
            attached_shard.combined, binding, &why) ||
        binding.statement_commitment !=
            ComputeShardSourceStatementCommitmentV2(
                binding,
                attached_shard.combined.n_rows,
                attached_shard.combined.n_columns,
                static_cast<uint32_t>(
                    attached_shard.combined.constraints.size()))) {
        out.note = why.empty()
            ? "stage3:recursive_receipt_v2:prove_binding"
            : why;
        return out;
    }
    out.binding_valid = true;
    const uint256 receipt_seed =
        ComputeShardReceiptFsSeedV2(
            binding,
            attached_shard.combined.n_rows,
            attached_shard.combined.n_columns,
            static_cast<uint32_t>(
                attached_shard.combined.constraints.size()));
    if (receipt_seed.IsNull()) {
        out.note =
            "stage3:recursive_receipt_v2:prove_seed";
        return out;
    }
    const auto prove_start =
        std::chrono::steady_clock::now();
    auto proved = aq::AirQuotientProveRows(
        attached_shard.combined,
        attached_shard.columns,
        receipt_seed, {});
    out.prove_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            prove_start).count());
    out.proved = proved.ok && proved.division_exact;
    if (!out.proved) {
        out.note =
            "stage3:recursive_receipt_v2:prove:" +
            proved.note;
        return out;
    }
    const auto verify_start =
        std::chrono::steady_clock::now();
    out.verified = aq::AirQuotientVerifyRows(
        attached_shard.combined, proved.proof,
        receipt_seed, &why);
    out.verify_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            verify_start).count());
    if (!out.verified) {
        out.note =
            "stage3:recursive_receipt_v2:verify:" + why;
        return out;
    }

    const fp::AlgAirProof proof =
        ToCanonicalAlgProof(std::move(proved.proof));
    ShardReceiptV2 receipt;
    receipt.shard_index = binding.local.shard_index;
    receipt.program_count = binding.local.program_count;
    receipt.queries = binding.local.queries;
    receipt.n_rows = attached_shard.combined.n_rows;
    receipt.n_columns = attached_shard.combined.n_columns;
    receipt.n_constraints = static_cast<uint32_t>(
        attached_shard.combined.constraints.size());
    receipt.source_current_width =
        binding.source_current_width;
    receipt.program_commitment =
        binding.local.program_commitment;
    receipt.bytecode_prechallenge_commitment =
        binding.local.bytecode_prechallenge_commitment;
    receipt.source_proof_commitment =
        binding.source_proof_commitment;
    receipt.source_fs_seed = binding.source_fs_seed;
    receipt.source_prechallenge_commitment =
        binding.source_prechallenge_commitment;
    receipt.statement_commitment =
        binding.statement_commitment;
    receipt.receipt_fs_seed = receipt_seed;
    receipt.proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(proof);
    receipt.query_indices = binding.local.query_indices;
    receipt.local_q_per_query =
        binding.local.local_q_per_query;
    receipt.source_parent_q_per_query =
        binding.source_parent_q_per_query;
    if (receipt.proof_commitment.IsNull() ||
        !SerializeAirQuotientProofAlg(
            proof, receipt.proof_bytes, &why)) {
        out.note =
            "stage3:recursive_receipt_v2:proof_codec:" +
            why;
        return out;
    }
    receipt.receipt_root =
        ComputeShardReceiptRootV2(receipt);
    if (receipt.receipt_root.IsNull()) {
        out.note =
            "stage3:recursive_receipt_v2:receipt_root";
        return out;
    }
    out.receipt = std::move(receipt);

    std::vector<unsigned char> encoded;
    out.wire_fits =
        SerializeShardReceiptV2(
            out.receipt, encoded, &why) &&
        encoded.size() <= kRCStage3MaxProofBytes;
    out.encoded_bytes = encoded.size();
    if (!out.wire_fits) {
        out.note =
            "stage3:recursive_receipt_v2:wire:" + why;
        return out;
    }
    const auto decoded =
        DeserializeShardReceiptV2(encoded, &why);
    out.canonical_codec_round_trip =
        decoded.has_value() &&
        decoded->receipt_root ==
            out.receipt.receipt_root &&
        decoded->proof_bytes == out.receipt.proof_bytes;
    if (!out.canonical_codec_round_trip) {
        out.note =
            "stage3:recursive_receipt_v2:round_trip:" +
            why;
        return out;
    }

    ShardReceiptV2 proof_tamper = out.receipt;
    proof_tamper.proof_bytes[
        proof_tamper.proof_bytes.size() / 2] ^= 1;
    out.proof_tamper_rejected =
        !DeserializeAirQuotientProofAlg(
            proof_tamper.proof_bytes, nullptr)
             .has_value();
    if (!out.proof_tamper_rejected) {
        const auto tampered_proof =
            DeserializeAirQuotientProofAlg(
                proof_tamper.proof_bytes, nullptr);
        out.proof_tamper_rejected =
            !tampered_proof.has_value() ||
            !aq::AirQuotientVerify<
                gf::Fp3,
                aq::AirFriBackendAlg<gf::Fp3>>(
                attached_shard.combined,
                *tampered_proof,
                out.receipt.receipt_fs_seed,
                nullptr);
    }

    auto forged_columns = attached_shard.columns;
    const SourceOpeningExportV2& target =
        binding.source_opening_exports.front();
    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            binding.source_hash_column_base);
    forged_columns[
        hash_layout.absorbed_pin_base +
        target.lane][target.row] =
        gf::Add(
            forged_columns[
                hash_layout.absorbed_pin_base +
                target.lane][target.row],
            gf::Fp3::One());
    const auto forged =
        aq::AirQuotientProveRows(
            attached_shard.combined,
            forged_columns, receipt_seed, {});
    out.source_opening_forgery_rejected =
        !forged.ok || !forged.division_exact ||
        !aq::AirQuotientVerifyRows(
            attached_shard.combined,
            forged.proof, receipt_seed, nullptr);

    out.recursively_consumed_by_parent = false;
    out.valid =
        out.binding_valid && out.proved &&
        out.verified &&
        out.canonical_codec_round_trip &&
        out.proof_tamper_rejected &&
        out.source_opening_forgery_rejected &&
        out.wire_fits &&
        !out.recursively_consumed_by_parent;
    out.note =
        "stage3:recursive_receipt_v2:l1_receipt"
        ";rows=" + std::to_string(out.receipt.n_rows) +
        ";cols=" + std::to_string(out.receipt.n_columns) +
        ";constraints=" +
        std::to_string(out.receipt.n_constraints) +
        ";queries=" +
        std::to_string(out.receipt.queries) +
        ";bytes=" + std::to_string(out.encoded_bytes) +
        ";prove_us=" + std::to_string(out.prove_micros) +
        ";verify_us=" + std::to_string(out.verify_micros) +
        ";source_opening_forgery=1"
        ";proof_tamper=1"
        ";recursive_consumption=0";
    return out;
}

bool VerifyShardReceiptV2(
    const aq::AirConstraintSystem<gf::Fp3>& source_child_cs,
    const fp::AlgAirProof& source_child_proof,
    const uint256& source_child_fs_seed,
    const aq::AirConstraintSystem<gf::Fp3>& shard_cs,
    const ShardSourceTerminalBindingV2& expected_binding,
    const ShardReceiptV2& receipt,
    std::string* why)
{
    if (!BindingMatchesConstraintSystem(
            shard_cs, expected_binding, why) ||
        !NativeSourceMatchesBinding(
            source_child_cs, source_child_proof,
            source_child_fs_seed, expected_binding, why)) {
        return false;
    }
    if (!ReceiptShapeCanonical(receipt) ||
        receipt.shard_index !=
            expected_binding.local.shard_index ||
        receipt.program_count !=
            expected_binding.local.program_count ||
        receipt.queries != expected_binding.local.queries ||
        receipt.n_rows != shard_cs.n_rows ||
        receipt.n_columns != shard_cs.n_columns ||
        receipt.n_constraints !=
            shard_cs.constraints.size() ||
        receipt.source_current_width !=
            expected_binding.source_current_width ||
        receipt.program_commitment !=
            expected_binding.local.program_commitment ||
        receipt.bytecode_prechallenge_commitment !=
            expected_binding.local
                .bytecode_prechallenge_commitment ||
        receipt.source_proof_commitment !=
            expected_binding.source_proof_commitment ||
        receipt.source_fs_seed !=
            expected_binding.source_fs_seed ||
        receipt.source_prechallenge_commitment !=
            expected_binding.source_prechallenge_commitment ||
        receipt.query_indices !=
            expected_binding.local.query_indices ||
        !SameFp3Vector(
            receipt.local_q_per_query,
            expected_binding.local.local_q_per_query) ||
        !SameFp3Vector(
            receipt.source_parent_q_per_query,
            expected_binding.source_parent_q_per_query)) {
        return Fail(why, "receipt_statement_fields");
    }
    const uint256 statement =
        ComputeShardSourceStatementCommitmentV2(
            expected_binding, receipt.n_rows,
            receipt.n_columns, receipt.n_constraints);
    const uint256 fs_seed =
        ComputeShardReceiptFsSeedV2(
            expected_binding, receipt.n_rows,
            receipt.n_columns, receipt.n_constraints);
    if (statement.IsNull() || fs_seed.IsNull() ||
        receipt.statement_commitment != statement ||
        receipt.receipt_fs_seed != fs_seed ||
        receipt.receipt_root !=
            ComputeShardReceiptRootV2(receipt)) {
        return Fail(why, "receipt_statement_seed_root");
    }
    std::string codec_why;
    const auto proof =
        DeserializeAirQuotientProofAlg(
            receipt.proof_bytes, &codec_why);
    if (!proof.has_value() ||
        receipt.proof_commitment !=
            fp::ComputeNormalizedAlgAirProofCommitment(
                *proof)) {
        return Fail(
            why, "receipt_proof_codec:" + codec_why);
    }
    std::vector<unsigned char> encoded;
    if (!SerializeShardReceiptV2(
            receipt, encoded, &codec_why) ||
        encoded.size() > kRCStage3MaxProofBytes) {
        return Fail(
            why, "receipt_wire:" + codec_why);
    }
    std::string verify_why;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            shard_cs, *proof, receipt.receipt_fs_seed,
            &verify_why)) {
        return Fail(
            why, "receipt_child_verify:" + verify_why);
    }
    return true;
}

bool SerializeShardReceiptV2(
    const ShardReceiptV2& receipt,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ReceiptShapeCanonical(receipt) ||
        receipt.receipt_root !=
            ComputeShardReceiptRootV2(receipt) ||
        receipt.proof_bytes.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "serialize_shape");
    }
    WriteU32(out, kShardReceiptMagicV2);
    WriteU16(out, receipt.version);
    WriteU32(out, receipt.shard_index);
    WriteU32(out, receipt.program_count);
    WriteU32(out, receipt.queries);
    WriteU32(out, receipt.n_rows);
    WriteU32(out, receipt.n_columns);
    WriteU32(out, receipt.n_constraints);
    WriteU32(out, receipt.source_current_width);
    WriteHash(out, receipt.program_commitment);
    WriteHash(out, receipt.bytecode_prechallenge_commitment);
    WriteHash(out, receipt.source_proof_commitment);
    WriteHash(out, receipt.source_fs_seed);
    WriteHash(out, receipt.source_prechallenge_commitment);
    WriteHash(out, receipt.statement_commitment);
    WriteHash(out, receipt.receipt_fs_seed);
    WriteHash(out, receipt.proof_commitment);
    WriteHash(out, receipt.receipt_root);
    for (uint32_t query = 0;
         query < receipt.queries; ++query) {
        WriteU32(out, receipt.query_indices[query]);
        const gf::Fp3 local =
            receipt.local_q_per_query[query];
        const gf::Fp3 source =
            receipt.source_parent_q_per_query[query];
        WriteU64(out, local.c0);
        WriteU64(out, local.c1);
        WriteU64(out, local.c2);
        WriteU64(out, source.c0);
        WriteU64(out, source.c1);
        WriteU64(out, source.c2);
    }
    WriteU32(
        out,
        static_cast<uint32_t>(receipt.proof_bytes.size()));
    out.insert(
        out.end(), receipt.proof_bytes.begin(),
        receipt.proof_bytes.end());
    if (out.size() > kRCStage3MaxProofBytes) {
        out.clear();
        return Fail(why, "serialize_wire");
    }
    return true;
}

std::optional<ShardReceiptV2>
DeserializeShardReceiptV2(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    if (bytes.empty() ||
        bytes.size() > kRCStage3MaxProofBytes) {
        Fail(why, "deserialize_size");
        return std::nullopt;
    }
    Reader reader(bytes);
    uint32_t magic = 0;
    ShardReceiptV2 out;
    if (!reader.U32(magic) ||
        !reader.U16(out.version) ||
        magic != kShardReceiptMagicV2 ||
        out.version != kShardReceiptVersionV2 ||
        !reader.U32(out.shard_index) ||
        !reader.U32(out.program_count) ||
        !reader.U32(out.queries) ||
        !reader.U32(out.n_rows) ||
        !reader.U32(out.n_columns) ||
        !reader.U32(out.n_constraints) ||
        !reader.U32(out.source_current_width) ||
        !reader.Hash(out.program_commitment) ||
        !reader.Hash(
            out.bytecode_prechallenge_commitment) ||
        !reader.Hash(out.source_proof_commitment) ||
        !reader.Hash(out.source_fs_seed) ||
        !reader.Hash(
            out.source_prechallenge_commitment) ||
        !reader.Hash(out.statement_commitment) ||
        !reader.Hash(out.receipt_fs_seed) ||
        !reader.Hash(out.proof_commitment) ||
        !reader.Hash(out.receipt_root) ||
        out.queries == 0 || out.queries > kMaxQueriesV2) {
        Fail(why, "deserialize_header");
        return std::nullopt;
    }
    out.query_indices.resize(out.queries);
    out.local_q_per_query.resize(out.queries);
    out.source_parent_q_per_query.resize(out.queries);
    for (uint32_t query = 0;
         query < out.queries; ++query) {
        gf::Fp3 local;
        gf::Fp3 source;
        if (!reader.U32(out.query_indices[query]) ||
            !reader.U64(local.c0) ||
            !reader.U64(local.c1) ||
            !reader.U64(local.c2) ||
            !reader.U64(source.c0) ||
            !reader.U64(source.c1) ||
            !reader.U64(source.c2) ||
            !CanonicalFp3(local) ||
            !CanonicalFp3(source)) {
            Fail(why, "deserialize_query");
            return std::nullopt;
        }
        out.local_q_per_query[query] = local;
        out.source_parent_q_per_query[query] = source;
    }
    uint32_t proof_bytes = 0;
    if (!reader.U32(proof_bytes) ||
        !reader.Bytes(proof_bytes, out.proof_bytes) ||
        reader.Remaining() != 0 ||
        !ReceiptShapeCanonical(out) ||
        out.receipt_root !=
            ComputeShardReceiptRootV2(out)) {
        Fail(why, "deserialize_body");
        return std::nullopt;
    }
    std::vector<unsigned char> reencoded;
    if (!SerializeShardReceiptV2(
            out, reencoded, why) ||
        reencoded != bytes) {
        Fail(why, "deserialize_noncanonical");
        return std::nullopt;
    }
    return out;
}

} // namespace matmul::v4::rc::recursive_receipt_v2
