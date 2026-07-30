// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v14_protocol_prefix_join.h>

#include <hash.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace matmul::v4::rc::stage3_v14_protocol_prefix_join {
namespace {

using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:v14_protocol_prefix_join:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

std::vector<Fp3> Selector(
    uint32_t rows,
    const std::set<uint32_t>& selected)
{
    std::vector<Fp3> out(rows, Fp3::Zero());
    for (const uint32_t row : selected) {
        if (row < rows) out[row] = Fp3::One();
    }
    return out;
}

void AddPreprocessed(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column,
    std::vector<Fp3> values)
{
    cs.preprocessed.emplace_back(column, values);
}

template <typename Eval>
void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    Eval&& eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval =
        std::forward<Eval>(eval);
    cs.constraints.push_back(
        std::move(constraint));
}

bool SameDerivedBinding(
    const derived::BindingV1& left,
    const derived::BindingV1& right)
{
    return left == right;
}

uint256 CommitPlan(const PlanV1& plan)
{
    HashWriter writer;
    writer << std::string(
        "BTX_RC_STAGE3_V14_PROTOCOL_PREFIX_PLAN_V1");
    writer << plan.version
           << plan.provenance_plan_root
           << plan.trace_rows
           << plan.provenance_columns
           << plan.consumer_bit_base
           << plan.message_active_base
           << plan.byte_active_base
           << plan.expected_byte_base
           << plan.dependent_zero
           << plan.total_columns
           << plan.transcript_events
           << plan.protocol_constant_occurrences;
    writer << static_cast<uint64_t>(
        plan.occurrences.size());
    for (const auto& item : plan.occurrences) {
        writer << item.event
               << item.prefix_offset
               << item.message_ordinal
               << item.byte_in_message_word
               << item.expected_byte
               << item.message.column
               << item.message.row;
    }
    writer << plan.exact_manifest_rebuilt
           << plan.exact_byte_positions
           << plan.exact_multiplicity
           << plan.mixed_constant_abi_word_covered
           << plan.valid;
    return writer.GetHash();
}

bool CanonicalU32(const Fp3& value, uint32_t& out)
{
    if (value.c1 != 0 || value.c2 != 0) return false;
    const uint64_t raw = gf::Canonical(value.c0);
    if (raw > UINT32_MAX) return false;
    out = static_cast<uint32_t>(raw);
    return true;
}

struct GridV1 {
    std::array<std::set<uint32_t>, kMessageLanesV1>
        message_active;
    std::array<
        std::array<std::set<uint32_t>,
                   kBytesPerMessageWordV1>,
        kMessageLanesV1> byte_active;
    std::array<
        std::array<std::map<uint32_t, uint8_t>,
                   kBytesPerMessageWordV1>,
        kMessageLanesV1> expected;
};

bool BuildGrid(const PlanV1& plan, GridV1& out)
{
    out = {};
    for (const auto& item : plan.occurrences) {
        const uint32_t lane =
            item.message_ordinal % kMessageLanesV1;
        if (lane >= kMessageLanesV1 ||
            item.byte_in_message_word >=
                kBytesPerMessageWordV1 ||
            item.message.row >= plan.trace_rows) {
            return false;
        }
        out.message_active[lane].insert(
            item.message.row);
        out.byte_active[lane]
                       [item.byte_in_message_word]
                           .insert(item.message.row);
        auto& expected =
            out.expected[lane]
                        [item.byte_in_message_word];
        const auto [position, inserted] =
            expected.emplace(
                item.message.row,
                item.expected_byte);
        if (!inserted &&
            position->second != item.expected_byte) {
            return false;
        }
    }
    return true;
}

std::vector<Fp3> ExpectedColumn(
    uint32_t rows,
    const std::map<uint32_t, uint8_t>& expected)
{
    std::vector<Fp3> out(rows, Fp3::Zero());
    for (const auto& [row, byte] : expected) {
        if (row < rows) out[row] = U(byte);
    }
    return out;
}

bool SamePublicProduct(
    const occurrence::ManifestV1& manifest,
    const provenance::ProductV1& product)
{
    return manifest.valid &&
        product.valid &&
        product.program_root == manifest.program_root &&
        product.plan.valid &&
        product.plan.plan_root != uint256{} &&
        product.plan.trace_rows == product.cs.n_rows &&
        product.plan.total_columns ==
            product.cs.n_columns &&
        product.canonical_abi_occurrences_bound == false &&
        product.protocol_constant_occurrences_bound == false &&
        product.recursively_consumed == false &&
        product.recursive_authority_ready == false;
}

} // namespace

bool BuildCanonicalPlanV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    PlanV1& out,
    std::string* why)
{
    out = {};
    provenance::PlanV1 base;
    if (!manifest.valid ||
        expected_transcript_commitment ==
            alg_hash::Digest{} ||
        !provenance::BuildCanonicalPlanV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            base, why)) {
        return Fail(why, "base_plan");
    }
    out.provenance_plan_root = base.plan_root;
    out.trace_rows = base.trace_rows;
    out.provenance_columns = base.total_columns;
    out.consumer_bit_base = out.provenance_columns;
    out.message_active_base =
        out.consumer_bit_base +
        kMessageLanesV1 * kBitsPerMessageWordV1;
    out.byte_active_base =
        out.message_active_base +
        kMessageLanesV1;
    out.expected_byte_base =
        out.byte_active_base +
        kMessageLanesV1 *
            kBytesPerMessageWordV1;
    out.dependent_zero =
        out.expected_byte_base +
        kMessageLanesV1 *
            kBytesPerMessageWordV1;
    out.total_columns = out.dependent_zero + 1;

    std::map<uint32_t,
             std::vector<const occurrence::ByteOccurrenceV1*>>
        by_event;
    for (const auto& item :
         manifest.byte_occurrences) {
        if (item.source_kind !=
                occurrence::ByteSourceKindV1::
                    ProtocolConstant) {
            continue;
        }
        if (item.canonical_abi_source ||
            item.prior_event_output_source ||
            item.outer_fri_seed_feedback_source ||
            item.derived_hash_source ||
            item.selector_family !=
                occurrence::SelectorFamilyV1::None ||
            item.byte_in_message_word >=
                kBytesPerMessageWordV1) {
            return Fail(why, "constant_source_flags");
        }
        by_event[item.consumer_event].push_back(&item);
    }
    if (by_event.empty()) {
        return Fail(why, "no_constant_occurrences");
    }

    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    for (auto& [event, items] : by_event) {
        std::sort(
            items.begin(), items.end(),
            [](const auto* left, const auto* right) {
                return std::tie(
                           left->consumer_message_ordinal,
                           left->byte_in_message_word) <
                    std::tie(
                           right->consumer_message_ordinal,
                           right->byte_in_message_word);
            });
        if (items.size() != kProtocolPrefixBytesV1) {
            return Fail(why, "event_prefix_cardinality");
        }
        for (uint32_t offset = 0;
             offset < kProtocolPrefixBytesV1;
             ++offset) {
            const auto& item = *items[offset];
            const uint32_t ordinal = 4 + offset / 4;
            const uint8_t byte =
                static_cast<uint8_t>(offset % 4);
            if (item.consumer_event != event ||
                item.consumer_message_ordinal != ordinal ||
                item.byte_in_message_word != byte ||
                item.consumer_column !=
                    v14_layout.Message(
                        ordinal % kMessageLanesV1) ||
                item.consumer_row >= out.trace_rows) {
                return Fail(why, "constant_byte_position");
            }
            PrefixOccurrenceV1 mapped;
            mapped.event = event;
            mapped.prefix_offset = offset;
            mapped.message_ordinal = ordinal;
            mapped.byte_in_message_word = byte;
            mapped.expected_byte =
                static_cast<uint8_t>(
                    kProtocolPrefixV1[offset]);
            mapped.message = {
                base.fused_offset +
                    item.consumer_column,
                item.consumer_row};
            out.occurrences.push_back(mapped);
        }
    }

    out.transcript_events =
        static_cast<uint32_t>(by_event.size());
    out.protocol_constant_occurrences =
        static_cast<uint32_t>(
            out.occurrences.size());
    out.exact_manifest_rebuilt = true;
    out.exact_byte_positions =
        std::all_of(
            out.occurrences.begin(),
            out.occurrences.end(),
            [](const auto& item) {
                return item.expected_byte ==
                    static_cast<uint8_t>(
                        kProtocolPrefixV1[
                            item.prefix_offset]);
            });
    out.exact_multiplicity =
        out.protocol_constant_occurrences ==
            manifest
                .protocol_constant_byte_occurrences &&
        out.protocol_constant_occurrences ==
            out.transcript_events *
                kProtocolPrefixBytesV1;
    out.mixed_constant_abi_word_covered =
        std::count_if(
            out.occurrences.begin(),
            out.occurrences.end(),
            [](const auto& item) {
                return item.prefix_offset ==
                    kProtocolPrefixBytesV1 - 1 &&
                    item.byte_in_message_word == 0;
            }) == out.transcript_events;
    out.valid =
        out.provenance_plan_root != uint256{} &&
        out.trace_rows > 0 &&
        out.provenance_columns > 0 &&
        out.exact_manifest_rebuilt &&
        out.exact_byte_positions &&
        out.exact_multiplicity &&
        out.mixed_constant_abi_word_covered;
    out.note = out.valid
        ? "all V13 protocol-prefix bytes mapped to exact "
          "proof-owned V14 consumers"
        : "protocol-prefix map incomplete";
    out.plan_root = CommitPlan(out);
    if (!out.valid || out.plan_root == uint256{}) {
        return Fail(why, "plan");
    }
    if (why != nullptr) {
        *why =
            "stage3:v14_protocol_prefix_join:plan";
    }
    return true;
}

bool BuildConstraintSystemV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    aq::AirConstraintSystem<Fp3>& out,
    PlanV1* plan_out,
    std::string* why)
{
    out = {};
    PlanV1 plan;
    provenance::PlanV1 base_plan;
    if (!provenance::BuildConstraintSystemV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            out, &base_plan, why) ||
        !BuildCanonicalPlanV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            plan, why) ||
        base_plan.plan_root !=
            plan.provenance_plan_root ||
        out.n_columns != plan.provenance_columns) {
        return Fail(why, "base_constraint_system");
    }
    out.n_columns = plan.total_columns;
    GridV1 grid;
    if (!BuildGrid(plan, grid)) {
        return Fail(why, "grid");
    }
    for (uint32_t lane = 0;
         lane < kMessageLanesV1; ++lane) {
        AddPreprocessed(
            out, plan.MessageActive(lane),
            Selector(
                plan.trace_rows,
                grid.message_active[lane]));
        for (uint32_t byte = 0;
             byte < kBytesPerMessageWordV1;
             ++byte) {
            AddPreprocessed(
                out, plan.ByteActive(lane, byte),
                Selector(
                    plan.trace_rows,
                    grid.byte_active[lane][byte]));
            AddPreprocessed(
                out, plan.ExpectedByte(lane, byte),
                ExpectedColumn(
                    plan.trace_rows,
                    grid.expected[lane][byte]));
        }
    }

    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    for (uint32_t lane = 0;
         lane < kMessageLanesV1; ++lane) {
        for (uint32_t bit = 0;
             bit < kBitsPerMessageWordV1; ++bit) {
            AddConstraint(
                out, "stage3.prefix.consumer_bit",
                aq::AirKind::kEverywhere, 3,
                [mask = plan.MessageActive(lane),
                 column = plan.ConsumerBit(lane, bit)](
                    const auto& current,
                    const auto&) {
                    return gf::Mul(
                        current[mask],
                        gf::Mul(
                            current[column],
                            gf::Sub(
                                current[column],
                                Fp3::One())));
                });
        }
        AddConstraint(
            out, "stage3.prefix.consumer_u32",
            aq::AirKind::kEverywhere, 2,
            [plan, lane,
             message =
                 base_plan.fused_offset +
                 v14_layout.Message(lane)](
                const auto& current,
                const auto&) {
                Fp3 rebuilt = Fp3::Zero();
                Fp3 power = Fp3::One();
                for (uint32_t bit = 0;
                     bit < kBitsPerMessageWordV1;
                     ++bit) {
                    rebuilt = gf::Add(
                        rebuilt,
                        gf::Mul(
                            power,
                            current[
                                plan.ConsumerBit(
                                    lane, bit)]));
                    power = gf::Add(power, power);
                }
                return gf::Mul(
                    current[
                        plan.MessageActive(lane)],
                    gf::Sub(
                        current[message],
                        rebuilt));
            });
        for (uint32_t byte = 0;
             byte < kBytesPerMessageWordV1;
             ++byte) {
            AddConstraint(
                out, "stage3.prefix.byte_equality",
                aq::AirKind::kEverywhere, 2,
                [plan, lane, byte](
                    const auto& current,
                    const auto&) {
                    Fp3 rebuilt = Fp3::Zero();
                    Fp3 power = Fp3::One();
                    for (uint32_t bit = 0;
                         bit < 8; ++bit) {
                        rebuilt = gf::Add(
                            rebuilt,
                            gf::Mul(
                                power,
                                current[
                                    plan.ConsumerBit(
                                        lane,
                                        8 * byte +
                                            bit)]));
                        power = gf::Add(power, power);
                    }
                    return gf::Mul(
                        current[
                            plan.ByteActive(
                                lane, byte)],
                        gf::Sub(
                            rebuilt,
                            current[
                                plan.ExpectedByte(
                                    lane, byte)]));
                });
        }
    }
    AddConstraint(
        out, "stage3.prefix.dependent_zero",
        aq::AirKind::kEverywhere, 1,
        [column = plan.dependent_zero](
            const auto& current,
            const auto&) {
            return current[column];
        });
    if (plan_out != nullptr) *plan_out = plan;
    if (why != nullptr) {
        *why =
            "stage3:v14_protocol_prefix_join:cs";
    }
    return true;
}

ProductV1 BuildProductV1(
    const occurrence::ManifestV1& manifest,
    const provenance::ProductV1& provenance_product)
{
    ProductV1 out;
    std::string why;
    if (!SamePublicProduct(
            manifest, provenance_product) ||
        !BuildConstraintSystemV1(
            manifest,
            provenance_product.transcript_commitment,
            provenance_product.derived_binding,
            out.cs, &out.plan, &why)) {
        out.note = why.empty()
            ? "stage3:prefix:product_input"
            : why;
        return out;
    }
    out.program_root = manifest.program_root;
    out.transcript_commitment =
        provenance_product.transcript_commitment;
    out.derived_binding =
        provenance_product.derived_binding;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows, Fp3::Zero()));
    for (uint32_t column = 0;
         column < provenance_product.columns.size();
         ++column) {
        out.columns[column] =
            provenance_product.columns[column];
    }
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        if (column >=
            provenance_product.columns.size()) {
            out.columns[column] = values;
        }
    }

    GridV1 grid;
    if (!BuildGrid(out.plan, grid)) {
        out.note = "stage3:prefix:grid";
        return out;
    }
    const bridge::TypedSafeDirectParentLayoutV14
        v14_layout;
    provenance::PlanV1 base_plan;
    if (!provenance::BuildCanonicalPlanV1(
            manifest,
            provenance_product.transcript_commitment,
            provenance_product.derived_binding,
            base_plan, &why)) {
        out.note = why;
        return out;
    }
    for (uint32_t lane = 0;
         lane < kMessageLanesV1; ++lane) {
        for (const uint32_t row :
             grid.message_active[lane]) {
            uint32_t value = 0;
            if (!CanonicalU32(
                    out.columns[
                        base_plan.fused_offset +
                        v14_layout.Message(lane)]
                               [row],
                    value)) {
                out.note =
                    "stage3:prefix:consumer_not_u32";
                return out;
            }
            for (uint32_t bit = 0;
                 bit < kBitsPerMessageWordV1;
                 ++bit) {
                out.columns[
                    out.plan.ConsumerBit(lane, bit)]
                           [row] =
                    U((value >> bit) & 1U);
            }
        }
    }
    out.violations =
        CountViolationsV1(
            out.cs, out.columns);
    out.provenance_relation_resident =
        provenance_product.valid &&
        out.plan.provenance_plan_root ==
            provenance_product.plan.plan_root;
    out.verifier_rebuilt_prefix_preprocessed =
        out.plan.exact_manifest_rebuilt &&
        out.plan.exact_byte_positions;
    out.consumer_u32_decomposition_constrained = true;
    out.every_prefix_occurrence_bound =
        out.plan.protocol_constant_occurrences ==
            manifest
                .protocol_constant_byte_occurrences;
    out.exact_multiplicity_consumed =
        out.plan.exact_multiplicity;
    out.canonical_abi_relation_resident = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.provenance_relation_resident &&
        out.verifier_rebuilt_prefix_preprocessed &&
        out.consumer_u32_decomposition_constrained &&
        out.every_prefix_occurrence_bound &&
        out.exact_multiplicity_consumed &&
        !out.canonical_abi_relation_resident &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "all fixed V13 prefix bytes equality-bound; "
          "canonical ABI LogUp remains a separate "
          "same-parent executable relation"
        : "protocol-prefix equality violation";
    return out;
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
        product.canonical_abi_relation_resident ||
        product.recursively_consumed ||
        product.recursive_authority_ready) {
        return Fail(why, "prove_input");
    }
    const auto proved =
        aq::AirQuotientProveRows(
            product.cs, product.columns, fs_seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "air_prove:" + proved.note);
    }
    out.plan_root = product.plan.plan_root;
    out.program_root = product.program_root;
    out.transcript_commitment =
        product.transcript_commitment;
    out.derived_binding =
        product.derived_binding;
    out.proof = proved.proof;
    out.canonical_abi_relation_resident = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.note =
        "fixed protocol-prefix equality proof; ABI "
        "LogUp and recursive consumption remain separate";
    if (why != nullptr) {
        *why =
            "stage3:v14_protocol_prefix_join:proved";
    }
    return true;
}

bool VerifyV1(
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    const ProofV1& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (proof.version !=
            kProtocolPrefixJoinVersionV1 ||
        proof.program_root != manifest.program_root ||
        proof.transcript_commitment !=
            expected_transcript_commitment ||
        !SameDerivedBinding(
            proof.derived_binding,
            expected_derived_binding) ||
        proof.canonical_abi_relation_resident ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        fs_seed.IsNull()) {
        return Fail(why, "verify_envelope");
    }
    aq::AirConstraintSystem<Fp3> cs;
    PlanV1 plan;
    if (!BuildConstraintSystemV1(
            manifest,
            expected_transcript_commitment,
            expected_derived_binding,
            cs, &plan, why) ||
        proof.plan_root != plan.plan_root) {
        return Fail(why, "verify_plan");
    }
    std::string verify_why;
    if (!aq::AirQuotientVerifyRows(
            cs, proof.proof,
            fs_seed, &verify_why)) {
        return Fail(
            why, "air_verify:" + verify_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:v14_protocol_prefix_join:verified";
    }
    return true;
}

uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    return provenance::CountViolationsV1(
        cs, columns);
}

} // namespace matmul::v4::rc::stage3_v14_protocol_prefix_join
