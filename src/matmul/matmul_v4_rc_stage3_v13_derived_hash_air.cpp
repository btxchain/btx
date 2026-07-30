// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v13_derived_hash_air.h>

#include <algorithm>
#include <limits>
#include <map>

namespace matmul::v4::rc::stage3_v13_derived_hash_air {
namespace {

using gf::Fp3;

constexpr gf::Fp kU32Max = UINT64_C(0xffffffff);
constexpr gf::Fp kTwo32 = UINT64_C(1) << 32;

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:v13_derived_hash_air:" + detail;
    }
    return false;
}

uint32_t NextPow2(uint64_t value)
{
    if (value < 2) return 2;
    uint64_t out = 1;
    while (out < value) {
        out <<= 1;
        if (out > std::numeric_limits<uint32_t>::max()) {
            return 0;
        }
    }
    return static_cast<uint32_t>(out);
}

bool CanonicalDigest(const Fri3AlgDigest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp value) { return value < gf::kP; });
}

enum class DescriptorKind : uint8_t {
    Fixed = 1,
    U32 = 2,
    Fp = 3,
};

struct Descriptor {
    DescriptorKind kind{DescriptorKind::Fixed};
    gf::Fp fixed{0};
    abi::SourceKeyV1 low_key{};
    abi::SourceKeyV1 high_key{};
    uint32_t low_address{UINT32_MAX};
    uint32_t high_address{UINT32_MAX};
    bool selected{false};
};

struct Plan {
    std::vector<std::array<Descriptor, kRateV1>> rows;
    uint32_t shape_blocks{0};
    uint32_t ood_blocks{0};
    uint32_t trace_rows{0};
    std::vector<SourceExportV1> exports;
    bool valid{false};
};

abi::SourceKeyV1 Limb(
    abi::FieldKindV1 kind, uint32_t item,
    uint32_t coordinate, uint8_t limb)
{
    return {kind, item, 0, 0, coordinate, limb};
}

Descriptor Fixed(gf::Fp value)
{
    Descriptor out;
    out.kind = DescriptorKind::Fixed;
    out.fixed = value;
    return out;
}

bool BuildPlan(
    const tape::PublicShapeV1& shape,
    const LayoutV1& layout,
    Plan& out,
    std::string* why)
{
    out = {};
    tape::PublicBindingV1 dummy;
    dummy.program_root = uint256::ONE;
    dummy.statement_root = uint256::ONE;
    dummy.public_fs_seed = uint256::ONE;
    dummy.proof_wire_root = uint256::ONE;
    const auto tape_schedule =
        tape::BuildScheduleV1(shape, dummy);
    if (!tape_schedule.valid) {
        return Fail(why, "proof_tape_shape");
    }
    std::map<abi::SourceKeyV1, uint32_t> addresses;
    for (const auto& source :
         tape_schedule.semantic_sources) {
        addresses.emplace(source.key, source.address);
    }
    const auto source_u32 =
        [&](abi::FieldKindV1 kind, uint32_t item,
            Descriptor& descriptor) {
            const abi::SourceKeyV1 key{
                kind, item, 0, 0, 0, 0};
            const auto found = addresses.find(key);
            if (found == addresses.end()) return false;
            descriptor = {};
            descriptor.kind = DescriptorKind::U32;
            descriptor.low_key = key;
            descriptor.low_address = found->second;
            return true;
        };
    const auto source_fp =
        [&](abi::FieldKindV1 kind, uint32_t item,
            uint32_t coordinate, bool selected,
            Descriptor& descriptor) {
            const auto low =
                Limb(kind, item, coordinate, 0);
            const auto high =
                Limb(kind, item, coordinate, 1);
            const auto low_it = addresses.find(low);
            const auto high_it = addresses.find(high);
            if (low_it == addresses.end() ||
                high_it == addresses.end()) {
                return false;
            }
            descriptor = {};
            descriptor.kind = DescriptorKind::Fp;
            descriptor.low_key = low;
            descriptor.high_key = high;
            descriptor.low_address = low_it->second;
            descriptor.high_address = high_it->second;
            descriptor.selected = selected;
            return true;
        };
    std::vector<Descriptor> shape_payload;
    shape_payload.push_back(Fixed(gf::FromU64(
        static_cast<uint32_t>(
            kRCFri3AlgShapeCommitDomain))));
    shape_payload.push_back(Fixed(gf::FromU64(
        static_cast<uint32_t>(
            kRCFri3AlgShapeCommitDomain >> 32))));
    Descriptor descriptor;
    if (!source_u32(
            abi::FieldKindV1::ColumnCount,
            0, descriptor)) {
        return Fail(why, "shape_column_count");
    }
    shape_payload.push_back(descriptor);
    if (!source_u32(
            abi::FieldKindV1::NCoeffs,
            0, descriptor)) {
        return Fail(why, "shape_n_coeffs");
    }
    shape_payload.push_back(descriptor);
    for (uint32_t column = 0;
         column < shape.trace_columns + 1; ++column) {
        if (!source_u32(
                abi::FieldKindV1::ColumnLen,
                column, descriptor)) {
            return Fail(why, "shape_column_len");
        }
        shape_payload.push_back(descriptor);
    }

    std::vector<Descriptor> ood_payload;
    ood_payload.push_back(Fixed(gf::FromU64(
        static_cast<uint32_t>(
            kRCFri3AlgOodEvalCommitDomain))));
    ood_payload.push_back(Fixed(gf::FromU64(
        static_cast<uint32_t>(
            kRCFri3AlgOodEvalCommitDomain >> 32))));
    if (!source_u32(
            abi::FieldKindV1::EvalZ1Count,
            0, descriptor)) {
        return Fail(why, "ood_eval_z1_count");
    }
    ood_payload.push_back(descriptor);
    if (!source_u32(
            abi::FieldKindV1::EvalZ2Count,
            0, descriptor)) {
        return Fail(why, "ood_eval_z2_count");
    }
    ood_payload.push_back(descriptor);
    for (const auto kind :
         {abi::FieldKindV1::Z1,
          abi::FieldKindV1::Z2}) {
        for (uint32_t coordinate = 0;
             coordinate < 3; ++coordinate) {
            if (!source_fp(
                    kind, 0, coordinate,
                    true, descriptor)) {
                return Fail(why, "ood_selected_z");
            }
            ood_payload.push_back(descriptor);
        }
    }
    for (const auto kind :
         {abi::FieldKindV1::EvalZ1,
          abi::FieldKindV1::EvalZ2}) {
        for (uint32_t column = 0;
             column < shape.trace_columns + 1;
             ++column) {
            for (uint32_t coordinate = 0;
                 coordinate < 3; ++coordinate) {
                if (!source_fp(
                        kind, column, coordinate,
                        false, descriptor)) {
                    return Fail(why, "ood_evaluation");
                }
                ood_payload.push_back(descriptor);
            }
        }
    }
    const auto append_session =
        [&](std::vector<Descriptor> payload,
            uint32_t& blocks) {
            payload.push_back(Fixed(gf::FromU64(1)));
            while (payload.size() % kRateV1 != 0) {
                payload.push_back(Fixed(gf::FromU64(0)));
            }
            blocks =
                static_cast<uint32_t>(
                    payload.size() / kRateV1);
            for (uint32_t block = 0;
                 block < blocks; ++block) {
                std::array<Descriptor, kRateV1> row{};
                for (uint32_t lane = 0;
                     lane < kRateV1; ++lane) {
                    row[lane] =
                        payload[kRateV1 * block + lane];
                }
                out.rows.push_back(std::move(row));
            }
        };
    append_session(
        std::move(shape_payload), out.shape_blocks);
    append_session(
        std::move(ood_payload), out.ood_blocks);
    out.trace_rows = NextPow2(out.rows.size() + 1);
    if (out.shape_blocks == 0 ||
        out.ood_blocks == 0 ||
        out.trace_rows == 0) {
        return Fail(why, "block_schedule");
    }
    out.rows.resize(out.trace_rows);
    for (uint32_t row = 0;
         row < out.shape_blocks + out.ood_blocks;
         ++row) {
        for (uint32_t lane = 0; lane < kRateV1; ++lane) {
            const auto& item = out.rows[row][lane];
            if (item.kind == DescriptorKind::Fixed) continue;
            SourceExportV1 low;
            low.key = item.low_key;
            low.high_key = item.high_key;
            low.source_address = item.low_address;
            low.high_source_address = item.high_address;
            low.row = row;
            low.lane = lane;
            low.low_column = layout.Low(lane);
            low.high_column = layout.High(lane);
            low.value_column = layout.Message(lane);
            low.u32_source =
                item.kind == DescriptorKind::U32;
            low.has_high_source =
                item.kind == DescriptorKind::Fp;
            low.selected_point_source = item.selected;
            out.exports.push_back(std::move(low));
        }
    }
    out.valid = true;
    return true;
}

void AddPreprocessed(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column, std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(
        column, std::move(values));
}

std::vector<Fp3> Selector(
    uint32_t rows,
    const std::function<bool(uint32_t)>& predicate)
{
    std::vector<Fp3> out(rows, Fp3::Zero());
    for (uint32_t row = 0; row < rows; ++row) {
        if (predicate(row)) out[row] = Fp3::One();
    }
    return out;
}

std::optional<abi::DecodedV1> DecodeForShape(
    const tape::PublicShapeV1& shape,
    const std::vector<uint32_t>& words,
    std::string* why)
{
    auto decoded =
        abi::DecodeCanonicalSafeV13(words, why);
    if (!decoded.has_value() ||
        !decoded->canonical ||
        !decoded->complete ||
        decoded->envelope.trace_columns !=
            shape.trace_columns ||
        decoded->envelope.quotient_len !=
            shape.quotient_len ||
        decoded->envelope.split.trace_rows !=
            shape.trace_rows ||
        decoded->envelope.split.base_column_indices !=
            shape.base_column_indices ||
        decoded->envelope.split.batch.n_coeffs !=
            shape.n_coeffs ||
        decoded->envelope.split.batch.column_len.size() !=
            shape.trace_columns + 1) {
        return std::nullopt;
    }
    return decoded;
}

gf::Fp3 SelectedCoordinate(
    const SelectedPointsV1& selected,
    abi::FieldKindV1 kind)
{
    return kind == abi::FieldKindV1::Z1
        ? selected.z1
        : selected.z2;
}

gf::Fp Coordinate(const gf::Fp3& value, uint32_t coordinate)
{
    if (coordinate == 0) return value.c0;
    if (coordinate == 1) return value.c1;
    return value.c2;
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.poseidon = pa::CanonicalLayout(0);
    uint32_t cursor = out.poseidon.End();
    out.message_base = cursor;
    cursor += kRateV1;
    out.state_base = cursor;
    cursor += alg_hash::kAlgHashT;
    out.active = cursor++;
    out.first = cursor++;
    out.terminal = cursor++;
    out.shape = cursor++;
    out.ood = cursor++;
    out.source_active_base = cursor;
    cursor += kRateV1;
    out.fp_source_base = cursor;
    cursor += kRateV1;
    out.selected_source_base = cursor;
    cursor += kRateV1;
    out.fixed_active_base = cursor;
    cursor += kRateV1;
    out.fixed_value_base = cursor;
    cursor += kRateV1;
    out.low_base = cursor;
    cursor += kRateV1;
    out.high_base = cursor;
    cursor += kRateV1;
    out.bit_base = cursor;
    cursor += 64 * kRateV1;
    out.high_is_max_base = cursor;
    cursor += kRateV1;
    out.high_delta_inverse_base = cursor;
    cursor += kRateV1;
    out.selected_value_base = cursor;
    cursor += kRateV1;
    out.digest_byte_base = cursor;
    cursor += 8 * kDigestLanesV1;
    out.digest_bit_base = cursor;
    cursor += 8 * 8 * kDigestLanesV1;
    out.digest_high_is_max_base = cursor;
    cursor += kDigestLanesV1;
    out.digest_high_delta_inverse_base = cursor;
    return out;
}

uint32_t LayoutV1::Message(uint32_t lane) const
{
    return message_base + lane;
}
uint32_t LayoutV1::State(uint32_t lane) const
{
    return state_base + lane;
}
uint32_t LayoutV1::SourceActive(uint32_t lane) const
{
    return source_active_base + lane;
}
uint32_t LayoutV1::FpSource(uint32_t lane) const
{
    return fp_source_base + lane;
}
uint32_t LayoutV1::SelectedSource(uint32_t lane) const
{
    return selected_source_base + lane;
}
uint32_t LayoutV1::FixedActive(uint32_t lane) const
{
    return fixed_active_base + lane;
}
uint32_t LayoutV1::FixedValue(uint32_t lane) const
{
    return fixed_value_base + lane;
}
uint32_t LayoutV1::Low(uint32_t lane) const
{
    return low_base + lane;
}
uint32_t LayoutV1::High(uint32_t lane) const
{
    return high_base + lane;
}
uint32_t LayoutV1::Bit(
    uint32_t lane, uint32_t bit) const
{
    return bit_base + 64 * lane + bit;
}
uint32_t LayoutV1::HighIsMax(uint32_t lane) const
{
    return high_is_max_base + lane;
}
uint32_t LayoutV1::HighDeltaInverse(uint32_t lane) const
{
    return high_delta_inverse_base + lane;
}
uint32_t LayoutV1::SelectedValue(uint32_t lane) const
{
    return selected_value_base + lane;
}
uint32_t LayoutV1::DigestByte(
    uint32_t lane, uint32_t byte) const
{
    return digest_byte_base + 8 * lane + byte;
}
uint32_t LayoutV1::DigestBit(
    uint32_t lane, uint32_t byte,
    uint32_t bit) const
{
    return digest_bit_base +
        64 * lane + 8 * byte + bit;
}
uint32_t LayoutV1::DigestHighIsMax(uint32_t lane) const
{
    return digest_high_is_max_base + lane;
}
uint32_t LayoutV1::DigestHighDeltaInverse(
    uint32_t lane) const
{
    return digest_high_delta_inverse_base + lane;
}
uint32_t LayoutV1::End() const
{
    return digest_high_delta_inverse_base +
        kDigestLanesV1;
}

bool BuildScheduleV1(
    const tape::PublicShapeV1& shape,
    ScheduleV1& out,
    std::string* why)
{
    out = {};
    out.shape = shape;
    const LayoutV1 layout = CanonicalLayoutV1();
    Plan plan;
    if (!BuildPlan(shape, layout, plan, why)) return false;
    out.active_rows =
        plan.shape_blocks + plan.ood_blocks;
    out.trace_rows = plan.trace_rows;
    out.shape_terminal_row = plan.shape_blocks - 1;
    out.ood_terminal_row =
        plan.shape_blocks + plan.ood_blocks - 1;
    out.source_exports = std::move(plan.exports);
    for (uint32_t family = 0; family < 2; ++family) {
        auto& digest = out.digest_exports[family];
        digest.family = family == 0
            ? PayloadFamilyV1::ShapeCommit
            : PayloadFamilyV1::OodEvaluationCommit;
        digest.terminal_row = family == 0
            ? out.shape_terminal_row
            : out.ood_terminal_row;
        digest.permutation_base =
            layout.poseidon.perm.base;
        digest.value_is_virtual_poseidon2_output = true;
        for (uint32_t lane = 0;
             lane < kDigestLanesV1; ++lane) {
            for (uint32_t byte = 0; byte < 8; ++byte) {
                digest.byte_column[lane][byte] =
                    layout.DigestByte(lane, byte);
            }
        }
    }
    out.exact_native_domains = true;
    out.exact_native_lane_order = true;
    out.exact_10star_padding = true;
    out.proof_tape_addresses_resolved =
        !out.source_exports.empty() &&
        std::all_of(
            out.source_exports.begin(),
            out.source_exports.end(),
            [](const SourceExportV1& source) {
                return
                    source.source_address != UINT32_MAX &&
                    (!source.has_high_source ||
                     source.high_source_address !=
                         UINT32_MAX);
            });
    out.valid =
        out.active_rows > 0 &&
        out.trace_rows >= out.active_rows &&
        out.exact_native_domains &&
        out.exact_native_lane_order &&
        out.exact_10star_padding &&
        out.proof_tape_addresses_resolved;
    out.note = out.valid
        ? "exact verifier-owned V13 derived-hash schedule"
        : "invalid V13 derived-hash schedule";
    if (!out.valid) return Fail(why, "schedule");
    return true;
}

bool BuildConstraintSystemV1(
    const tape::PublicShapeV1& shape,
    const BindingV1& binding,
    aq::AirConstraintSystem<Fp3>& out,
    LayoutV1* layout_out,
    ScheduleV1* schedule_out,
    std::string* why)
{
    out = {};
    if (!CanonicalDigest(binding.shape_commit) ||
        !CanonicalDigest(
            binding.ood_evaluation_commit)) {
        return Fail(why, "binding");
    }
    const LayoutV1 layout = CanonicalLayoutV1();
    Plan plan;
    if (!BuildPlan(shape, layout, plan, why)) return false;
    ScheduleV1 schedule;
    if (!BuildScheduleV1(shape, schedule, why)) return false;
    out.n_rows = plan.trace_rows;
    out.n_columns = layout.End();
    const uint32_t active_rows =
        plan.shape_blocks + plan.ood_blocks;
    AddPreprocessed(out, layout.active, Selector(
        out.n_rows,
        [=](uint32_t row) {
            return row < active_rows;
        }));
    AddPreprocessed(out, layout.first, Selector(
        out.n_rows,
        [=](uint32_t row) {
            return row == 0 ||
                row == plan.shape_blocks;
        }));
    AddPreprocessed(out, layout.terminal, Selector(
        out.n_rows,
        [=](uint32_t row) {
            return row + 1 == plan.shape_blocks ||
                row + 1 == active_rows;
        }));
    AddPreprocessed(out, layout.shape, Selector(
        out.n_rows,
        [=](uint32_t row) {
            return row < plan.shape_blocks;
        }));
    AddPreprocessed(out, layout.ood, Selector(
        out.n_rows,
        [=](uint32_t row) {
            return row >= plan.shape_blocks &&
                row < active_rows;
        }));
    for (uint32_t lane = 0; lane < kRateV1; ++lane) {
        AddPreprocessed(out, layout.SourceActive(lane), Selector(
            out.n_rows,
            [&](uint32_t row) {
                return row < active_rows &&
                    plan.rows[row][lane].kind !=
                        DescriptorKind::Fixed;
            }));
        AddPreprocessed(out, layout.FpSource(lane), Selector(
            out.n_rows,
            [&](uint32_t row) {
                return row < active_rows &&
                    plan.rows[row][lane].kind ==
                        DescriptorKind::Fp;
            }));
        AddPreprocessed(out, layout.SelectedSource(lane), Selector(
            out.n_rows,
            [&](uint32_t row) {
                return row < active_rows &&
                    plan.rows[row][lane].selected;
            }));
        AddPreprocessed(out, layout.FixedActive(lane), Selector(
            out.n_rows,
            [&](uint32_t row) {
                return row < active_rows &&
                    plan.rows[row][lane].kind ==
                        DescriptorKind::Fixed;
            }));
        std::vector<Fp3> fixed(out.n_rows, Fp3::Zero());
        for (uint32_t row = 0; row < active_rows; ++row) {
            if (plan.rows[row][lane].kind ==
                    DescriptorKind::Fixed) {
                fixed[row] =
                    Fp3::FromFp(
                        plan.rows[row][lane].fixed);
            }
        }
        AddPreprocessed(
            out, layout.FixedValue(lane),
            std::move(fixed));
    }
    out.preprocessed_pin_ood = true;

    auto poseidon =
        pa::BuildFixedConstraints(layout.poseidon);
    out.constraints.insert(
        out.constraints.end(),
        std::make_move_iterator(poseidon.begin()),
        std::make_move_iterator(poseidon.end()));
    for (uint32_t lane = 0; lane < kRateV1; ++lane) {
        for (uint32_t bit = 0; bit < 64; ++bit) {
            aq::AirConstraint<Fp3> boolean;
            boolean.name =
                "stage3.v13_hash.source_bit_boolean";
            boolean.kind = aq::AirKind::kEverywhere;
            boolean.alg_degree = 2;
            const uint32_t column =
                layout.Bit(lane, bit);
            boolean.eval =
                [column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[column],
                        gf::Sub(
                            cur[column], Fp3::One()));
                };
            out.constraints.push_back(std::move(boolean));
            aq::AirConstraint<Fp3> inactive_zero;
            inactive_zero.name =
                "stage3.v13_hash.inactive_source_bit_zero";
            inactive_zero.kind =
                aq::AirKind::kEverywhere;
            inactive_zero.alg_degree = 2;
            inactive_zero.eval =
                [layout, lane, column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.SourceActive(lane)]),
                        cur[column]);
                };
            out.constraints.push_back(
                std::move(inactive_zero));
        }
        for (uint32_t half = 0; half < 2; ++half) {
            aq::AirConstraint<Fp3> reconstruct;
            reconstruct.name =
                "stage3.v13_hash.source_u32_reconstruct";
            reconstruct.kind = aq::AirKind::kEverywhere;
            reconstruct.alg_degree = 2;
            reconstruct.eval =
                [layout, lane, half](
                    const auto& cur,
                    const auto&) {
                    Fp3 value = Fp3::Zero();
                    for (uint32_t bit = 0;
                         bit < 32; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                U(uint64_t{1} << bit),
                                cur[layout.Bit(
                                    lane,
                                    32 * half + bit)]));
                    }
                    return gf::Mul(
                        cur[layout.SourceActive(lane)],
                        gf::Sub(
                            cur[half == 0
                                    ? layout.Low(lane)
                                    : layout.High(lane)],
                            value));
                };
            out.constraints.push_back(
                std::move(reconstruct));
        }
        {
            aq::AirConstraint<Fp3> u32;
            u32.name =
                "stage3.v13_hash.u32_high_zero";
            u32.kind = aq::AirKind::kEverywhere;
            u32.alg_degree = 2;
            u32.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            cur[layout.SourceActive(lane)],
                            cur[layout.FpSource(lane)]),
                        cur[layout.High(lane)]);
                };
            out.constraints.push_back(std::move(u32));
        }
        {
            aq::AirConstraint<Fp3> message;
            message.name =
                "stage3.v13_hash.message_source";
            message.kind = aq::AirKind::kEverywhere;
            message.alg_degree = 2;
            message.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    const Fp3 reconstructed =
                        gf::Add(
                            cur[layout.Low(lane)],
                            gf::Mul(
                                U(kTwo32),
                                cur[layout.High(lane)]));
                    return gf::Add(
                        gf::Mul(
                            cur[layout.SourceActive(lane)],
                            gf::Sub(
                                cur[layout.Message(lane)],
                                reconstructed)),
                        gf::Mul(
                            cur[layout.FixedActive(lane)],
                            gf::Sub(
                                cur[layout.Message(lane)],
                                cur[layout.FixedValue(lane)])));
                };
            out.constraints.push_back(std::move(message));
        }
        {
            aq::AirConstraint<Fp3> selected;
            selected.name =
                "stage3.v13_hash.selected_z_equals_tape";
            selected.kind = aq::AirKind::kEverywhere;
            selected.alg_degree = 2;
            selected.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[layout.SelectedSource(lane)],
                        gf::Sub(
                            cur[layout.SelectedValue(lane)],
                            cur[layout.Message(lane)]));
                };
            out.constraints.push_back(std::move(selected));
        }
        for (const auto [column, allowed] :
             std::array<std::pair<uint32_t, uint32_t>, 5>{{
                 {layout.Low(lane),
                  layout.SourceActive(lane)},
                 {layout.High(lane),
                  layout.SourceActive(lane)},
                 {layout.HighIsMax(lane),
                  layout.FpSource(lane)},
                 {layout.HighDeltaInverse(lane),
                  layout.FpSource(lane)},
                 {layout.SelectedValue(lane),
                  layout.SelectedSource(lane)},
             }}) {
            aq::AirConstraint<Fp3> zero;
            zero.name =
                "stage3.v13_hash.inactive_source_zero";
            zero.kind = aq::AirKind::kEverywhere;
            zero.alg_degree = 2;
            zero.eval =
                [column, allowed](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(), cur[allowed]),
                        cur[column]);
                };
            out.constraints.push_back(std::move(zero));
        }
        {
            aq::AirConstraint<Fp3> eq;
            eq.name =
                "stage3.v13_hash.fp_high_eq";
            eq.kind = aq::AirKind::kEverywhere;
            eq.alg_degree = 3;
            eq.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    const Fp3 delta =
                        gf::Sub(
                            U(kU32Max),
                            cur[layout.High(lane)]);
                    return gf::Mul(
                        cur[layout.FpSource(lane)],
                        gf::Mul(
                            cur[layout.HighIsMax(lane)],
                            delta));
                };
            out.constraints.push_back(std::move(eq));
        }
        {
            aq::AirConstraint<Fp3> inverse;
            inverse.name =
                "stage3.v13_hash.fp_high_inverse";
            inverse.kind = aq::AirKind::kEverywhere;
            inverse.alg_degree = 3;
            inverse.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    const Fp3 delta =
                        gf::Sub(
                            U(kU32Max),
                            cur[layout.High(lane)]);
                    return gf::Mul(
                        cur[layout.FpSource(lane)],
                        gf::Sub(
                            gf::Mul(
                                delta,
                                cur[layout.
                                    HighDeltaInverse(lane)]),
                            gf::Sub(
                                Fp3::One(),
                                cur[layout.
                                    HighIsMax(lane)])));
                };
            out.constraints.push_back(std::move(inverse));
        }
        {
            aq::AirConstraint<Fp3> low;
            low.name =
                "stage3.v13_hash.fp_low_if_high_max";
            low.kind = aq::AirKind::kEverywhere;
            low.alg_degree = 3;
            low.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[layout.FpSource(lane)],
                        gf::Mul(
                            cur[layout.HighIsMax(lane)],
                            cur[layout.Low(lane)]));
                };
            out.constraints.push_back(std::move(low));
        }
        {
            aq::AirConstraint<Fp3> inactive;
            inactive.name =
                "stage3.v13_hash.inactive_message_zero";
            inactive.kind = aq::AirKind::kEverywhere;
            inactive.alg_degree = 2;
            inactive.eval =
                [layout, lane](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.active]),
                        cur[layout.Message(lane)]);
                };
            out.constraints.push_back(std::move(inactive));
        }
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> reset_state;
        reset_state.name =
            "stage3.v13_hash.session_state_zero";
        reset_state.kind = aq::AirKind::kEverywhere;
        reset_state.alg_degree = 2;
        reset_state.eval =
            [layout, lane](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.first],
                    cur[layout.State(lane)]);
            };
        out.constraints.push_back(
            std::move(reset_state));
        aq::AirConstraint<Fp3> input;
        input.name =
            "stage3.v13_hash.sponge_input";
        input.kind = aq::AirKind::kEverywhere;
        input.alg_degree = 2;
        input.eval =
            [layout, lane](
                const auto& cur,
                const auto&) {
                const Fp3 message =
                    lane < kRateV1
                    ? cur[layout.Message(lane)]
                    : Fp3::Zero();
                const Fp3 continued =
                    gf::Add(
                        cur[layout.State(lane)],
                        message);
                const Fp3 reset = message;
                const Fp3 expected =
                    gf::Add(
                        gf::Mul(cur[layout.first], reset),
                        gf::Mul(
                            gf::Sub(
                                cur[layout.active],
                                cur[layout.first]),
                            continued));
                return gf::Sub(
                    cur[layout.poseidon.perm.
                        InputCol(lane)],
                    expected);
            };
        out.constraints.push_back(std::move(input));

        aq::AirConstraint<Fp3> state;
        state.name =
            "stage3.v13_hash.sponge_state";
        state.kind = aq::AirKind::kTransition;
        state.alg_degree = 3;
        state.eval =
            [layout, lane](
                const auto& cur,
                const auto& next) {
                const Fp3 carried =
                    gf::Add(
                        gf::Mul(
                            cur[layout.active],
                            air_recurse::PermOutputLane(
                                layout.poseidon.perm,
                                cur, lane)),
                        gf::Mul(
                            gf::Sub(
                                Fp3::One(),
                                cur[layout.active]),
                            cur[layout.State(lane)]));
                const Fp3 expected =
                    gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            next[layout.first]),
                        carried);
                return gf::Sub(
                    next[layout.State(lane)],
                    expected);
            };
        out.constraints.push_back(std::move(state));
    }
    for (uint32_t lane = 0;
         lane < kDigestLanesV1; ++lane) {
        for (uint32_t byte = 0; byte < 8; ++byte) {
            for (uint32_t bit = 0; bit < 8; ++bit) {
                aq::AirConstraint<Fp3> boolean;
                boolean.name =
                    "stage3.v13_hash.digest_bit_boolean";
                boolean.kind = aq::AirKind::kEverywhere;
                boolean.alg_degree = 2;
                const uint32_t column =
                    layout.DigestBit(lane, byte, bit);
                boolean.eval =
                    [column](
                        const auto& cur,
                        const auto&) {
                        return gf::Mul(
                            cur[column],
                            gf::Sub(
                                cur[column],
                                Fp3::One()));
                        };
                out.constraints.push_back(
                    std::move(boolean));
                aq::AirConstraint<Fp3> inactive_zero;
                inactive_zero.name =
                    "stage3.v13_hash."
                    "inactive_digest_bit_zero";
                inactive_zero.kind =
                    aq::AirKind::kEverywhere;
                inactive_zero.alg_degree = 2;
                inactive_zero.eval =
                    [layout, column](
                        const auto& cur,
                        const auto&) {
                        return gf::Mul(
                            gf::Sub(
                                Fp3::One(),
                                cur[layout.terminal]),
                            cur[column]);
                    };
                out.constraints.push_back(
                    std::move(inactive_zero));
            }
            aq::AirConstraint<Fp3> reconstruct;
            reconstruct.name =
                "stage3.v13_hash.digest_byte";
            reconstruct.kind = aq::AirKind::kEverywhere;
            reconstruct.alg_degree = 2;
            reconstruct.eval =
                [layout, lane, byte](
                    const auto& cur,
                    const auto&) {
                    Fp3 value = Fp3::Zero();
                    for (uint32_t bit = 0;
                         bit < 8; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                U(uint32_t{1} << bit),
                                cur[layout.DigestBit(
                                    lane, byte, bit)]));
                    }
                    return gf::Mul(
                        cur[layout.terminal],
                        gf::Sub(
                            cur[layout.DigestByte(
                                lane, byte)],
                            value));
                };
            out.constraints.push_back(
                std::move(reconstruct));
            aq::AirConstraint<Fp3> inactive_byte;
            inactive_byte.name =
                "stage3.v13_hash."
                "inactive_digest_byte_zero";
            inactive_byte.kind =
                aq::AirKind::kEverywhere;
            inactive_byte.alg_degree = 2;
            const uint32_t byte_column =
                layout.DigestByte(lane, byte);
            inactive_byte.eval =
                [layout, byte_column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.terminal]),
                        cur[byte_column]);
                };
            out.constraints.push_back(
                std::move(inactive_byte));
        }
        aq::AirConstraint<Fp3> output_permutation;
        output_permutation.name =
            "stage3.v13_hash.digest_equals_permutation";
        output_permutation.kind = aq::AirKind::kEverywhere;
        output_permutation.alg_degree = 2;
        output_permutation.eval =
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 encoded = Fp3::Zero();
                for (uint32_t byte = 0;
                     byte < 8; ++byte) {
                    encoded = gf::Add(
                        encoded,
                        gf::Mul(
                            U(uint64_t{1} << (8 * byte)),
                            cur[layout.DigestByte(
                                lane, byte)]));
                }
                return gf::Mul(
                    cur[layout.terminal],
                    gf::Sub(
                        encoded,
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm,
                            cur, lane)));
            };
        out.constraints.push_back(
            std::move(output_permutation));
        aq::AirConstraint<Fp3> output_binding;
        output_binding.name =
            "stage3.v13_hash.digest_equals_binding";
        output_binding.kind = aq::AirKind::kEverywhere;
        output_binding.alg_degree = 2;
        output_binding.eval =
            [layout, lane, binding](
                const auto& cur,
                const auto&) {
                Fp3 encoded = Fp3::Zero();
                for (uint32_t byte = 0;
                     byte < 8; ++byte) {
                    encoded = gf::Add(
                        encoded,
                        gf::Mul(
                            U(uint64_t{1} << (8 * byte)),
                            cur[layout.DigestByte(
                                lane, byte)]));
                }
                const Fp3 expected =
                    gf::Add(
                        gf::Mul(
                            cur[layout.shape],
                            Fp3::FromFp(
                                binding.shape_commit[lane])),
                        gf::Mul(
                            cur[layout.ood],
                            Fp3::FromFp(
                                binding.
                                    ood_evaluation_commit[
                                        lane])));
                return gf::Mul(
                    cur[layout.terminal],
                    gf::Sub(encoded, expected));
            };
        out.constraints.push_back(
            std::move(output_binding));
        aq::AirConstraint<Fp3> high_eq;
        high_eq.name =
            "stage3.v13_hash.digest_high_eq";
        high_eq.kind = aq::AirKind::kEverywhere;
        high_eq.alg_degree = 3;
        high_eq.eval =
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 high_word = Fp3::Zero();
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    const Fp3 coeff =
                        U(uint64_t{1} << (8 * byte));
                    high_word = gf::Add(
                        high_word,
                        gf::Mul(
                            coeff,
                            cur[layout.DigestByte(
                                lane, 4 + byte)]));
                }
                const Fp3 delta =
                    gf::Sub(U(kU32Max), high_word);
                const Fp3 eq =
                    cur[layout.DigestHighIsMax(lane)];
                return gf::Mul(
                    cur[layout.terminal],
                    gf::Mul(eq, delta));
            };
        out.constraints.push_back(std::move(high_eq));
        aq::AirConstraint<Fp3> high_inverse;
        high_inverse.name =
            "stage3.v13_hash.digest_high_inverse";
        high_inverse.kind = aq::AirKind::kEverywhere;
        high_inverse.alg_degree = 3;
        high_inverse.eval =
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 high_word = Fp3::Zero();
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    high_word = gf::Add(
                        high_word,
                        gf::Mul(
                            U(uint64_t{1} << (8 * byte)),
                            cur[layout.DigestByte(
                                lane, 4 + byte)]));
                }
                const Fp3 delta =
                    gf::Sub(U(kU32Max), high_word);
                const Fp3 eq =
                    cur[layout.DigestHighIsMax(lane)];
                return gf::Mul(
                    cur[layout.terminal],
                    gf::Sub(
                        gf::Mul(
                            delta,
                            cur[layout.
                                DigestHighDeltaInverse(lane)]),
                        gf::Sub(Fp3::One(), eq)));
            };
        out.constraints.push_back(
            std::move(high_inverse));
        aq::AirConstraint<Fp3> high_low;
        high_low.name =
            "stage3.v13_hash.digest_low_if_high_max";
        high_low.kind = aq::AirKind::kEverywhere;
        high_low.alg_degree = 3;
        high_low.eval =
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 low_word = Fp3::Zero();
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    low_word = gf::Add(
                        low_word,
                        gf::Mul(
                            U(uint64_t{1} << (8 * byte)),
                            cur[layout.DigestByte(
                                lane, byte)]));
                }
                return gf::Mul(
                    cur[layout.terminal],
                    gf::Mul(
                        cur[layout.DigestHighIsMax(lane)],
                        low_word));
            };
        out.constraints.push_back(std::move(high_low));
        for (const uint32_t column :
             {layout.DigestHighIsMax(lane),
              layout.DigestHighDeltaInverse(lane)}) {
            aq::AirConstraint<Fp3> inactive_aux;
            inactive_aux.name =
                "stage3.v13_hash."
                "inactive_digest_aux_zero";
            inactive_aux.kind =
                aq::AirKind::kEverywhere;
            inactive_aux.alg_degree = 2;
            inactive_aux.eval =
                [layout, column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[layout.terminal]),
                        cur[column]);
                };
            out.constraints.push_back(
                std::move(inactive_aux));
        }
    }
    if (layout_out != nullptr) *layout_out = layout;
    if (schedule_out != nullptr) {
        *schedule_out = std::move(schedule);
    }
    if (why != nullptr) {
        *why =
            "stage3:v13_derived_hash_air:constraint_system";
    }
    return true;
}

ProductV1 BuildProductV1(
    const tape::PublicShapeV1& shape,
    const std::vector<uint32_t>& words,
    const SelectedPointsV1& selected_points)
{
    ProductV1 out;
    out.selected_points = selected_points;
    std::string why;
    const auto decoded =
        DecodeForShape(shape, words, &why);
    if (!decoded.has_value()) {
        out.note =
            "stage3:v13_derived_hash_air:decode:" + why;
        return out;
    }
    out.layout = CanonicalLayoutV1();
    Plan plan;
    if (!BuildPlan(
            shape, out.layout, plan, &why)) {
        out.note = why;
        return out;
    }
    std::map<abi::SourceKeyV1, uint32_t> values;
    for (const auto& source : decoded->sources) {
        values.emplace(source.key, source.value);
    }

    // Build the public output witness from the same explicit message
    // schedule and decomposed Poseidon2 primitive used by the AIR.  Do not
    // call the native ShapeCommit/OodEvaluationCommit helpers here: native
    // parity is a test oracle, never a verifier-side trust dependency.
    alg_hash::State derived_state{};
    for (uint32_t row = 0;
         row < plan.shape_blocks + plan.ood_blocks;
         ++row) {
        if (row == 0 || row == plan.shape_blocks) {
            derived_state = {};
        }
        alg_hash::State input = derived_state;
        for (uint32_t lane = 0;
             lane < kRateV1; ++lane) {
            const auto& item = plan.rows[row][lane];
            gf::Fp value = item.fixed;
            if (item.kind != DescriptorKind::Fixed) {
                const auto low_it =
                    values.find(item.low_key);
                if (low_it == values.end()) {
                    out.note =
                        "stage3:v13_derived_hash_air:"
                        "derived_missing_low_source";
                    return out;
                }
                uint32_t high = 0;
                if (item.kind == DescriptorKind::Fp) {
                    const auto high_it =
                        values.find(item.high_key);
                    if (high_it == values.end()) {
                        out.note =
                            "stage3:v13_derived_hash_air:"
                            "derived_missing_high_source";
                        return out;
                    }
                    high = high_it->second;
                }
                const uint64_t raw =
                    uint64_t{low_it->second} |
                    (uint64_t{high} << 32);
                if (raw >= gf::kP) {
                    out.note =
                        "stage3:v13_derived_hash_air:"
                        "derived_noncanonical_source";
                    return out;
                }
                value = gf::FromU64(raw);
            }
            input[lane] = gf::Add(input[lane], value);
        }
        derived_state =
            pa::BuildWitness(
                out.layout.poseidon, input).output;
        Fri3AlgDigest* terminal = nullptr;
        if (row + 1 == plan.shape_blocks) {
            terminal = &out.binding.shape_commit;
        } else if (
            row + 1 ==
                plan.shape_blocks + plan.ood_blocks) {
            terminal =
                &out.binding.ood_evaluation_commit;
        }
        if (terminal != nullptr) {
            for (uint32_t lane = 0;
                 lane < kDigestLanesV1; ++lane) {
                (*terminal)[lane] = derived_state[lane];
            }
        }
    }
    if (!BuildConstraintSystemV1(
            shape, out.binding, out.cs,
            &out.layout, &out.schedule, &why)) {
        out.note = why;
        return out;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        if (column >= out.columns.size() ||
            values.size() != out.cs.n_rows) {
            out.note =
                "stage3:v13_derived_hash_air:"
                "preprocessed_shape";
            return out;
        }
        out.columns[column] = values;
    }
    alg_hash::State state{};
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        const bool active =
            row < out.schedule.active_rows;
        const bool first =
            row == 0 ||
            row == plan.shape_blocks;
        if (first) state = {};
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashT; ++lane) {
            out.columns[out.layout.State(lane)][row] =
                Fp3::FromFp(state[lane]);
        }
        if (active) {
            for (uint32_t lane = 0;
                 lane < kRateV1; ++lane) {
                const auto& item = plan.rows[row][lane];
                gf::Fp value = item.fixed;
                uint32_t low = 0;
                uint32_t high = 0;
                if (item.kind != DescriptorKind::Fixed) {
                    const auto low_it =
                        values.find(item.low_key);
                    if (low_it == values.end()) {
                        out.note =
                            "stage3:v13_derived_hash_air:"
                            "missing_low_source";
                        return out;
                    }
                    low = low_it->second;
                    if (item.kind == DescriptorKind::Fp) {
                        const auto high_it =
                            values.find(item.high_key);
                        if (high_it == values.end()) {
                            out.note =
                                "stage3:v13_derived_hash_air:"
                                "missing_high_source";
                            return out;
                        }
                        high = high_it->second;
                    }
                    const uint64_t raw =
                        uint64_t{low} |
                        (uint64_t{high} << 32);
                    if (raw >= gf::kP) {
                        out.note =
                            "stage3:v13_derived_hash_air:"
                            "noncanonical_source";
                        return out;
                    }
                    value = gf::FromU64(raw);
                    out.columns[
                        out.layout.Low(lane)][row] =
                        U(low);
                    out.columns[
                        out.layout.High(lane)][row] =
                        U(high);
                    for (uint32_t bit = 0;
                         bit < 64; ++bit) {
                        out.columns[
                            out.layout.Bit(
                                lane, bit)][row] =
                            U((raw >> bit) & 1U);
                    }
                    if (item.kind == DescriptorKind::Fp) {
                        const bool is_max =
                            high == UINT32_MAX;
                        out.columns[
                            out.layout.HighIsMax(
                                lane)][row] =
                            is_max
                            ? Fp3::One()
                            : Fp3::Zero();
                        if (!is_max) {
                            out.columns[
                                out.layout.
                                    HighDeltaInverse(
                                        lane)][row] =
                                Fp3::FromFp(
                                    gf::Inv(
                                        kU32Max - high));
                        }
                    }
                    if (item.selected) {
                        const auto selected =
                            SelectedCoordinate(
                                selected_points,
                                item.low_key.kind);
                        out.columns[
                            out.layout.SelectedValue(
                                lane)][row] =
                            Fp3::FromFp(
                                Coordinate(
                                    selected,
                                    item.low_key.d));
                    }
                }
                out.columns[
                    out.layout.Message(lane)][row] =
                    Fp3::FromFp(value);
            }
        }
        alg_hash::State input{};
        if (active && !first) input = state;
        if (active) {
            for (uint32_t lane = 0;
                 lane < kRateV1; ++lane) {
                input[lane] = gf::Add(
                    input[lane],
                    out.columns[
                        out.layout.Message(lane)][row].c0);
            }
        }
        const pa::Witness witness =
            pa::BuildWitness(out.layout.poseidon, input);
        for (uint32_t column =
                 out.layout.poseidon.perm.base;
             column < out.layout.poseidon.End();
             ++column) {
            out.columns[column][row] =
                witness.row[column];
        }
        if (active) state = witness.output;
    }
    const std::array<std::pair<uint32_t, Fri3AlgDigest>, 2>
        terminals{{
            {out.schedule.shape_terminal_row,
             out.binding.shape_commit},
            {out.schedule.ood_terminal_row,
             out.binding.ood_evaluation_commit},
        }};
    for (const auto& [row, digest] : terminals) {
        for (uint32_t lane = 0;
             lane < kDigestLanesV1; ++lane) {
            const uint64_t raw =
                gf::Canonical(digest[lane]);
            for (uint32_t byte = 0;
                 byte < 8; ++byte) {
                const uint8_t value =
                    static_cast<uint8_t>(
                        raw >> (8 * byte));
                out.columns[
                    out.layout.DigestByte(
                        lane, byte)][row] = U(value);
                for (uint32_t bit = 0;
                     bit < 8; ++bit) {
                    out.columns[
                        out.layout.DigestBit(
                            lane, byte, bit)][row] =
                        U((value >> bit) & 1U);
                }
            }
            const uint32_t high =
                static_cast<uint32_t>(raw >> 32);
            const bool is_max =
                high == UINT32_MAX;
            out.columns[
                out.layout.DigestHighIsMax(
                    lane)][row] =
                is_max ? Fp3::One() : Fp3::Zero();
            if (!is_max) {
                out.columns[
                    out.layout.
                        DigestHighDeltaInverse(
                            lane)][row] =
                    Fp3::FromFp(
                        gf::Inv(kU32Max - high));
            }
        }
    }
    out.violations =
        CountViolationsV1(out.cs, out.columns);
    out.canonical_safe_v13_tape_decoded = true;
    out.source_values_ordinary_columns = true;
    out.no_preprocessed_proof_values = true;
    out.canonical_two_u32_goldilocks_air = true;
    out.selected_points_equal_tape_z_air = true;
    out.exact_poseidon2_relations = true;
    out.proof_tape_same_parent_equality_executed = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.canonical_safe_v13_tape_decoded &&
        out.source_values_ordinary_columns &&
        out.no_preprocessed_proof_values &&
        out.canonical_two_u32_goldilocks_air &&
        out.selected_points_equal_tape_z_air &&
        out.exact_poseidon2_relations &&
        !out.proof_tape_same_parent_equality_executed &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "exact V13 ShapeCommit/OodEvaluationCommit AIR"
        : "V13 derived-hash witness violates exact AIR";
    return out;
}

uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns ||
        cs.n_rows == 0) {
        return UINT32_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return UINT32_MAX;
        }
    }
    uint32_t violations = 0;
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool applies =
                constraint.kind == aq::AirKind::kEverywhere ||
                (constraint.kind == aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind == aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows) ||
                (constraint.kind == aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows);
            if (applies &&
                !gf::IsZero(
                    constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool ProveV1(
    const ProductV1& product,
    const uint256& fs_seed,
    ProofV1& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.violations != 0 ||
        fs_seed.IsNull() ||
        product.proof_tape_same_parent_equality_executed ||
        product.recursively_consumed ||
        product.recursive_authority_ready) {
        return Fail(why, "prove_input");
    }
    const auto proved =
        aq::AirQuotientProveRows(
            product.cs, product.columns, fs_seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "prove:" + proved.note);
    }
    out.binding = product.binding;
    out.proof = proved.proof;
    out.proof_tape_same_parent_equality_executed = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.note =
        "derived hashes proved; same-parent tape join remains";
    return true;
}

bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const BindingV1& expected_binding,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (proof.version != kDerivedHashAirVersionV1 ||
        proof.binding != expected_binding ||
        fs_seed.IsNull() ||
        proof.proof_tape_same_parent_equality_executed ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready) {
        return Fail(why, "proof_envelope");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildConstraintSystemV1(
            shape, expected_binding,
            cs, nullptr, nullptr, why)) {
        return false;
    }
    return aq::AirQuotientVerifyRows(
        cs, proof.proof, fs_seed, why);
}

} // namespace matmul::v4::rc::stage3_v13_derived_hash_air
