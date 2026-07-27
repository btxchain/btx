// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_prefix_source_air.h>

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <utility>

namespace matmul::v4::rc::stage3_p2_prefix_source_air {
namespace {

namespace ah = alg_hash;
namespace ar = air_recurse;

constexpr gf::Fp kTwo32 = UINT64_C(1) << 32;
constexpr gf::Fp kU32Max = UINT64_C(0xffffffff);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:p2_prefix_source_air:" + detail;
    }
    return false;
}

Fp3 U32(uint32_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

bool CanonicalBaseCell(const Fp3& value)
{
    return value.c1 == 0 && value.c2 == 0 &&
        value.c0 == gf::Canonical(value.c0);
}

uint32_t SeedWord(const uint256& seed, uint32_t word)
{
    uint32_t out = 0;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out |= uint32_t{seed.data()[4 * word + byte]}
            << (8 * byte);
    }
    return out;
}

struct SourceValue {
    enum class Kind : uint8_t {
        U32 = 1,
        Fp = 2,
        Fixed = 3,
    };
    Kind kind{Kind::U32};
    uint32_t word{0};
    gf::Fp expected{0};
};

struct PayloadBlock {
    bool shape{false};
    std::array<std::optional<SourceValue>, ah::kAlgHashRate>
        source;
    std::array<bool, ah::kAlgHashRate> padding_one{};
    uint32_t target_row{0};
    uint32_t bank{0};
};

struct CodecOffsets {
    uint32_t n_coeffs_word{5};
    uint32_t width_word{15};
    uint32_t column_len_word{16};
    uint32_t lambda_word{0};
    uint32_t z1_word{0};
    uint32_t z2_word{0};
    uint32_t eval_z1_count_word{0};
    uint32_t eval_z1_word{0};
    uint32_t eval_z2_count_word{0};
    uint32_t eval_z2_word{0};
};

bool BuildCodecOffsets(
    const Fri3AlgBatchProof& proof,
    CodecOffsets& out)
{
    if (proof.column_len.size() >
            std::numeric_limits<uint32_t>::max() ||
        proof.evals_z1.size() >
            std::numeric_limits<uint32_t>::max() ||
        proof.evals_z2.size() >
            std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = CodecOffsets{};
    out.n_coeffs_word = 5;
    out.width_word = 15;
    out.column_len_word = 16;
    uint64_t cursor =
        uint64_t{out.column_len_word} +
        proof.column_len.size();
    out.lambda_word = static_cast<uint32_t>(cursor);
    cursor += 6;
    out.z1_word = static_cast<uint32_t>(cursor);
    cursor += 6;
    out.z2_word = static_cast<uint32_t>(cursor);
    cursor += 6;
    out.eval_z1_count_word =
        static_cast<uint32_t>(cursor++);
    out.eval_z1_word = static_cast<uint32_t>(cursor);
    cursor += uint64_t{6} * proof.evals_z1.size();
    out.eval_z2_count_word =
        static_cast<uint32_t>(cursor++);
    out.eval_z2_word = static_cast<uint32_t>(cursor);
    cursor += uint64_t{6} * proof.evals_z2.size();
    return cursor <= std::numeric_limits<uint32_t>::max();
}

uint32_t CodecWordRow(uint32_t word)
{
    return (5 + word) /
        fp::kNormalizedAlgAirProofFieldBusRate;
}

uint32_t CodecWordPort(uint32_t word)
{
    return (5 + word) %
        fp::kNormalizedAlgAirProofFieldBusRate;
}

uint32_t SourceLastRow(const SourceValue& source)
{
    if (source.kind == SourceValue::Kind::Fixed) {
        return 0;
    }
    return CodecWordRow(
        source.word +
        (source.kind == SourceValue::Kind::Fp ? 1 : 0));
}

gf::Fp SourceValueFromParent(
    const fp::FoldBusComposition& parent,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1&
        proof_bus,
    const SourceValue& source,
    bool* canonical_words = nullptr)
{
    if (source.kind == SourceValue::Kind::Fixed) {
        if (canonical_words != nullptr) {
            *canonical_words = true;
        }
        return gf::Canonical(source.expected);
    }
    const uint32_t row = CodecWordRow(source.word);
    const uint32_t port = CodecWordPort(source.word);
    const Fp3& low =
        parent.columns[proof_bus.layout.Field(port)][row];
    bool canonical = CanonicalBaseCell(low) &&
        gf::Canonical(low.c0) <= kU32Max;
    gf::Fp value = gf::Canonical(low.c0);
    if (source.kind == SourceValue::Kind::Fp) {
        const uint32_t high_word = source.word + 1;
        const uint32_t high_row =
            CodecWordRow(high_word);
        const uint32_t high_port =
            CodecWordPort(high_word);
        const Fp3& high =
            parent.columns[
                proof_bus.layout.Field(high_port)]
                [high_row];
        canonical = canonical &&
            CanonicalBaseCell(high) &&
            gf::Canonical(high.c0) <= kU32Max;
        const uint64_t raw =
            uint64_t{gf::Canonical(low.c0)} |
            (uint64_t{gf::Canonical(high.c0)} << 32);
        canonical = canonical && raw < gf::kP;
        value = gf::FromU64(raw);
    }
    if (canonical_words != nullptr) {
        *canonical_words = canonical;
    }
    return value;
}

SourceValue U32Source(uint32_t word, uint32_t expected)
{
    return {
        SourceValue::Kind::U32,
        word,
        gf::FromU64(expected)};
}

SourceValue FpSource(uint32_t word, gf::Fp expected)
{
    return {
        SourceValue::Kind::Fp,
        word,
        gf::Canonical(expected)};
}

SourceValue FixedSource(uint32_t value)
{
    return {
        SourceValue::Kind::Fixed,
        0,
        gf::FromU64(value)};
}

void AppendFp3Sources(
    uint32_t word,
    const gf::Fp3& value,
    std::vector<SourceValue>& out)
{
    out.push_back(FpSource(word, value.c0));
    out.push_back(FpSource(word + 2, value.c1));
    out.push_back(FpSource(word + 4, value.c2));
}

bool BuildPayloadSources(
    const Fri3AlgBatchProof& proof,
    const CodecOffsets& offsets,
    std::vector<SourceValue>& shape,
    std::vector<SourceValue>& ood)
{
    if (proof.column_len.empty() ||
        proof.evals_z1.empty() ||
        proof.evals_z1.size() != proof.evals_z2.size() ||
        proof.evals_z1.size() != proof.column_len.size()) {
        return false;
    }
    shape.clear();
    ood.clear();
    shape.reserve(proof.column_len.size() + 4);
    shape.push_back(FixedSource(
        static_cast<uint32_t>(
            kRCFri3AlgShapeCommitDomain)));
    shape.push_back(FixedSource(
        static_cast<uint32_t>(
            kRCFri3AlgShapeCommitDomain >> 32)));
    shape.push_back(U32Source(
        offsets.width_word,
        static_cast<uint32_t>(proof.column_len.size())));
    shape.push_back(U32Source(
        offsets.n_coeffs_word, proof.n_coeffs));
    for (uint32_t index = 0;
         index < proof.column_len.size(); ++index) {
        shape.push_back(U32Source(
            offsets.column_len_word + index,
            proof.column_len[index]));
    }

    ood.reserve(10 + 6 * proof.evals_z1.size());
    ood.push_back(FixedSource(
        static_cast<uint32_t>(
            kRCFri3AlgOodEvalCommitDomain)));
    ood.push_back(FixedSource(
        static_cast<uint32_t>(
            kRCFri3AlgOodEvalCommitDomain >> 32)));
    // The verifier separately constrains the two serialized counts equal.
    // Using count1 for both leading lanes then exactly matches the native
    // payload after that equality, while retaining monotone codec order.
    ood.push_back(U32Source(
        offsets.eval_z1_count_word,
        static_cast<uint32_t>(proof.evals_z1.size())));
    ood.push_back(U32Source(
        offsets.eval_z1_count_word,
        static_cast<uint32_t>(proof.evals_z2.size())));
    AppendFp3Sources(offsets.z1_word, proof.z1, ood);
    AppendFp3Sources(offsets.z2_word, proof.z2, ood);
    for (uint32_t index = 0;
         index < proof.evals_z1.size(); ++index) {
        AppendFp3Sources(
            offsets.eval_z1_word + 6 * index,
            proof.evals_z1[index], ood);
    }
    for (uint32_t index = 0;
         index < proof.evals_z2.size(); ++index) {
        AppendFp3Sources(
            offsets.eval_z2_word + 6 * index,
            proof.evals_z2[index], ood);
    }
    return true;
}

bool BuildBlocks(
    const std::vector<SourceValue>& payload,
    bool shape,
    uint32_t& previous_target,
    uint32_t& global_block,
    uint32_t parent_rows,
    std::vector<PayloadBlock>& out)
{
    const size_t padded =
        ((payload.size() + 1 +
          ah::kAlgHashRate - 1) /
         ah::kAlgHashRate) *
        ah::kAlgHashRate;
    if (padded == 0) return false;
    for (size_t offset = 0;
         offset < padded; offset += ah::kAlgHashRate) {
        PayloadBlock block;
        block.shape = shape;
        block.bank = global_block % kGatherBanksV1;
        uint32_t target =
            previous_target == std::numeric_limits<uint32_t>::max()
            ? 0
            : previous_target + 1;
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            const size_t position = offset + lane;
            if (position < payload.size()) {
                block.source[lane] = payload[position];
                target = std::max(
                    target,
                    SourceLastRow(*block.source[lane]));
            } else if (position == payload.size()) {
                block.padding_one[lane] = true;
            }
        }
        if (target >= parent_rows) return false;
        block.target_row = target;
        previous_target = target;
        ++global_block;
        out.push_back(std::move(block));
    }
    return true;
}

void AddPreprocessed(
    fp::FoldBusComposition& parent,
    uint32_t column,
    std::vector<Fp3> values)
{
    parent.columns[column] = values;
    parent.combined.preprocessed.emplace_back(
        column, std::move(values));
}

void AppendConstraint(
    fp::FoldBusComposition& parent,
    aq::AirConstraint<Fp3> constraint)
{
    parent.combined.constraints.push_back(
        std::move(constraint));
}

bool PinSelector(
    fp::FoldBusComposition& parent,
    uint32_t column,
    const std::vector<Fp3>& values)
{
    if (column >= parent.columns.size() ||
        values.size() != parent.combined.n_rows) {
        return false;
    }
    AddPreprocessed(parent, column, values);
    aq::AirConstraint<Fp3> boolean;
    boolean.name =
        "stage3.p2_prefix_source.selector_boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [column](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[column],
                gf::Sub(row[column], Fp3::One()));
        };
    AppendConstraint(parent, std::move(boolean));
    return true;
}

} // namespace

LayoutV1::LayoutV1(uint32_t start)
    : base(start),
      permutation(pa::CanonicalLayout(start)),
      message_base(permutation.End()),
      state_base(message_base + ah::kAlgHashRate),
      active(state_base + ah::kAlgHashT),
      first(active + 1),
      terminal(first + 1),
      shape(terminal + 1),
      ood(shape + 1),
      gather_base(ood + 1),
      gather_load_selector_base(
          gather_base +
          kGatherBanksV1 * kGatherLanesV1),
      gather_carry_selector_base(
          gather_load_selector_base +
          kGatherBanksV1 * kGatherLanesV1),
      gather_target_selector_base(
          gather_carry_selector_base +
          kGatherBanksV1 * kGatherLanesV1),
      gather_u32_port_selector_base(
          gather_target_selector_base +
          kGatherBanksV1 * kGatherLanesV1),
      gather_fp_port_selector_base(
          gather_u32_port_selector_base +
          kGatherBanksV1 * kGatherLanesV1 *
              kSourcePortsV1),
      padding_one_selector_base(
          gather_fp_port_selector_base +
          kGatherBanksV1 * kGatherLanesV1 *
              kSourcePortsV1),
      seed_byte_base(
          padding_one_selector_base +
          ah::kAlgHashRate),
      seed_bit_base(seed_byte_base + kSeedBytesV1),
      seed_word_active_base(
          seed_bit_base + 8 * kSeedBytesV1),
      digest_byte_base(
          seed_word_active_base + kSeedWordsV1),
      digest_bit_base(
          digest_byte_base + kDigestBytesV1),
      digest_high_is_max_base(
          digest_bit_base + 8 * kDigestBytesV1),
      digest_high_delta_inverse_base(
          digest_high_is_max_base + kDigestLanesV1),
      eval_count_carrier(
          digest_high_delta_inverse_base +
          kDigestLanesV1),
      eval_count_load_selector(eval_count_carrier + 1),
      eval_count_carry_selector(
          eval_count_load_selector + 1),
      eval_count_sink_selector(
          eval_count_carry_selector + 1)
{
}

uint32_t LayoutV1::Message(uint32_t lane) const
{
    return message_base + lane;
}

uint32_t LayoutV1::State(uint32_t lane) const
{
    return state_base + lane;
}

uint32_t LayoutV1::Gather(
    uint32_t bank, uint32_t lane) const
{
    return gather_base + bank * kGatherLanesV1 + lane;
}

uint32_t LayoutV1::GatherLoadSelector(
    uint32_t bank, uint32_t lane) const
{
    return gather_load_selector_base +
        bank * kGatherLanesV1 + lane;
}

uint32_t LayoutV1::GatherCarrySelector(
    uint32_t bank, uint32_t lane) const
{
    return gather_carry_selector_base +
        bank * kGatherLanesV1 + lane;
}

uint32_t LayoutV1::GatherTargetSelector(
    uint32_t bank, uint32_t lane) const
{
    return gather_target_selector_base +
        bank * kGatherLanesV1 + lane;
}

uint32_t LayoutV1::GatherU32PortSelector(
    uint32_t bank, uint32_t lane, uint32_t port) const
{
    return gather_u32_port_selector_base +
        (bank * kGatherLanesV1 + lane) *
            kSourcePortsV1 +
        port;
}

uint32_t LayoutV1::GatherFpPortSelector(
    uint32_t bank, uint32_t lane, uint32_t port) const
{
    return gather_fp_port_selector_base +
        (bank * kGatherLanesV1 + lane) *
            kSourcePortsV1 +
        port;
}

uint32_t LayoutV1::PaddingOneSelector(
    uint32_t lane) const
{
    return padding_one_selector_base + lane;
}

uint32_t LayoutV1::SeedByte(
    uint32_t word, uint32_t byte) const
{
    return seed_byte_base + 4 * word + byte;
}

uint32_t LayoutV1::SeedBit(
    uint32_t word, uint32_t byte, uint32_t bit) const
{
    return seed_bit_base +
        32 * word + 8 * byte + bit;
}

uint32_t LayoutV1::SeedWordActive(uint32_t word) const
{
    return seed_word_active_base + word;
}

uint32_t LayoutV1::DigestByte(
    uint32_t lane, uint32_t byte) const
{
    return digest_byte_base + 8 * lane + byte;
}

uint32_t LayoutV1::DigestBit(
    uint32_t lane, uint32_t byte, uint32_t bit) const
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
    return eval_count_sink_selector + 1;
}

uint32_t CountViolations(
    const fp::FoldBusComposition& parent)
{
    return p2join::CountViolations(
        parent.combined, parent.columns);
}

bool AttachV10PrefixSourceAirV1(
    fp::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1&
        proof_bus,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1&
        decoder,
    const ReceiptSeedSourceRefsV1& seed_source,
    AttachmentV1& out,
    std::string* why)
{
    out = AttachmentV1{};
    out.layout = LayoutV1(parent.combined.n_columns);
    out.original_columns = parent.combined.n_columns;
    out.parent_rows = parent.combined.n_rows;
    out.constraint_base =
        static_cast<uint32_t>(
            parent.combined.constraints.size());
    if (proof.version !=
            kRCFri3AlgP2Q192K2ProofVersionV10 ||
        fs_seed.IsNull() ||
        parent.columns.size() !=
            parent.combined.n_columns ||
        parent.combined.n_rows < 2 ||
        (parent.combined.n_rows &
         (parent.combined.n_rows - 1)) != 0 ||
        !proof_bus.valid ||
        proof_bus.layout.End() > out.original_columns ||
        proof_bus.parent_rows != out.parent_rows ||
        !decoder.valid ||
        decoder.parent_rows != out.parent_rows ||
        !seed_source.canonical_receipt_statement ||
        !seed_source.verifier_recomputed_seed ||
        !seed_source.cells_bound_before_first_commitment ||
        seed_source.complete_child_verifier_same_parent) {
        return Fail(why, "input");
    }

    for (uint32_t word = 0; word < kSeedWordsV1; ++word) {
        const auto cell = seed_source.u32_word[word];
        if (cell.column >= out.original_columns ||
            cell.row >= out.parent_rows ||
            !CanonicalBaseCell(
                parent.columns[cell.column][cell.row]) ||
            gf::Canonical(
                parent.columns[cell.column][cell.row].c0) >
                kU32Max ||
            gf::Canonical(
                parent.columns[cell.column][cell.row].c0) !=
                SeedWord(fs_seed, word)) {
            return Fail(why, "receipt_seed_cell");
        }
    }
    out.receipt_seed_cells_preexisting = true;
    out.receipt_seed_canonical_u32 = true;

    CodecOffsets offsets;
    std::vector<SourceValue> shape_sources;
    std::vector<SourceValue> ood_sources;
    if (!BuildCodecOffsets(proof, offsets) ||
        !BuildPayloadSources(
            proof, offsets, shape_sources, ood_sources)) {
        return Fail(why, "payload_shape");
    }
    out.shape_payload_fields =
        static_cast<uint32_t>(shape_sources.size());
    out.ood_payload_fields =
        static_cast<uint32_t>(ood_sources.size());
    for (const auto& source : shape_sources) {
        bool canonical = false;
        if (SourceValueFromParent(
                parent, proof_bus, source,
                &canonical) != source.expected ||
            !canonical) {
            return Fail(why, "shape_codec_source");
        }
    }
    for (const auto& source : ood_sources) {
        bool canonical = false;
        if (SourceValueFromParent(
                parent, proof_bus, source,
                &canonical) != source.expected ||
            !canonical) {
            return Fail(why, "ood_codec_source");
        }
    }
    const SourceValue count1 = U32Source(
        offsets.eval_z1_count_word,
        static_cast<uint32_t>(proof.evals_z1.size()));
    const SourceValue count2 = U32Source(
        offsets.eval_z2_count_word,
        static_cast<uint32_t>(proof.evals_z2.size()));
    if (SourceValueFromParent(
            parent, proof_bus, count1) != count1.expected ||
        SourceValueFromParent(
            parent, proof_bus, count2) != count2.expected) {
        return Fail(why, "eval_count_source");
    }

    std::vector<PayloadBlock> blocks;
    uint32_t previous_target =
        std::numeric_limits<uint32_t>::max();
    uint32_t global_block = 0;
    if (!BuildBlocks(
            shape_sources, true, previous_target,
            global_block, out.parent_rows, blocks)) {
        return Fail(why, "shape_schedule");
    }
    out.shape_blocks = global_block;
    out.shape_terminal_row = previous_target;
    const uint32_t before_ood = global_block;
    if (!BuildBlocks(
            ood_sources, false, previous_target,
            global_block, out.parent_rows, blocks)) {
        return Fail(why, "ood_schedule");
    }
    out.ood_blocks = global_block - before_ood;
    out.ood_terminal_row = previous_target;
    if (out.shape_terminal_row >= out.ood_terminal_row) {
        return Fail(why, "session_order");
    }

    parent.columns.resize(
        out.layout.End(),
        std::vector<Fp3>(
            out.parent_rows, Fp3::Zero()));
    parent.combined.n_columns = out.layout.End();
    out.added_columns =
        out.layout.End() - out.layout.base;

    std::vector<Fp3> active(out.parent_rows, Fp3::Zero());
    std::vector<Fp3> first(out.parent_rows, Fp3::Zero());
    std::vector<Fp3> terminal(
        out.parent_rows, Fp3::Zero());
    std::vector<Fp3> shape_selector(
        out.parent_rows, Fp3::Zero());
    std::vector<Fp3> ood_selector(
        out.parent_rows, Fp3::Zero());
    std::array<std::vector<Fp3>, ah::kAlgHashRate>
        padding_one;
    for (auto& column : padding_one) {
        column.assign(out.parent_rows, Fp3::Zero());
    }
    std::array<
        std::array<std::vector<Fp3>, kGatherLanesV1>,
        kGatherBanksV1> load_selector;
    std::array<
        std::array<std::vector<Fp3>, kGatherLanesV1>,
        kGatherBanksV1> carry_selector;
    std::array<
        std::array<std::vector<Fp3>, kGatherLanesV1>,
        kGatherBanksV1> target_selector;
    std::array<
        std::array<
            std::array<std::vector<Fp3>, kSourcePortsV1>,
            kGatherLanesV1>,
        kGatherBanksV1> u32_port_selector;
    std::array<
        std::array<
            std::array<std::vector<Fp3>, kSourcePortsV1>,
            kGatherLanesV1>,
        kGatherBanksV1> fp_port_selector;
    for (uint32_t bank = 0; bank < kGatherBanksV1; ++bank) {
        for (uint32_t lane = 0; lane < kGatherLanesV1; ++lane) {
            load_selector[bank][lane].assign(
                out.parent_rows, Fp3::Zero());
            carry_selector[bank][lane].assign(
                out.parent_rows, Fp3::Zero());
            target_selector[bank][lane].assign(
                out.parent_rows, Fp3::Zero());
            for (uint32_t port = 0;
                 port < kSourcePortsV1; ++port) {
                u32_port_selector[bank][lane][port].assign(
                    out.parent_rows, Fp3::Zero());
                fp_port_selector[bank][lane][port].assign(
                    out.parent_rows, Fp3::Zero());
            }
        }
    }

    std::array<
        std::array<int64_t, kGatherLanesV1>,
        kGatherBanksV1> busy_until{};
    for (auto& bank : busy_until) {
        bank.fill(-1);
    }
    uint32_t shape_block_index = 0;
    uint32_t ood_block_index = 0;
    for (const auto& block : blocks) {
        active[block.target_row] = Fp3::One();
        (block.shape ? shape_selector : ood_selector)
            [block.target_row] = Fp3::One();
        const uint32_t local_block =
            block.shape
            ? shape_block_index++
            : ood_block_index++;
        if (local_block == 0) {
            first[block.target_row] = Fp3::One();
        }
        if ((block.shape &&
             local_block + 1 == out.shape_blocks) ||
            (!block.shape &&
             local_block + 1 == out.ood_blocks)) {
            terminal[block.target_row] = Fp3::One();
        }
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            if (block.padding_one[lane]) {
                padding_one[lane][block.target_row] =
                    Fp3::One();
            }
            if (!block.source[lane].has_value()) continue;
            const SourceValue source = *block.source[lane];
            if (source.kind == SourceValue::Kind::Fixed) {
                // The two domain-separator words are protocol constants, not
                // proof-codec fields. They are constrained below against the
                // session selector and must not occupy a gather port.
                parent.columns[out.layout.Message(lane)]
                    [block.target_row] =
                    Fp3::FromFp(source.expected);
                continue;
            }
            const uint32_t source_row =
                CodecWordRow(source.word);
            const uint32_t port =
                CodecWordPort(source.word);
            if (source_row > block.target_row ||
                busy_until[block.bank][lane] >=
                    static_cast<int64_t>(source_row)) {
                return Fail(why, "gather_bank_collision");
            }
            busy_until[block.bank][lane] =
                block.target_row;
            load_selector[block.bank][lane][source_row] =
                Fp3::One();
            target_selector[block.bank][lane]
                [block.target_row] = Fp3::One();
            (source.kind == SourceValue::Kind::U32
                 ? u32_port_selector
                 : fp_port_selector)
                [block.bank][lane][port][source_row] =
                    Fp3::One();
            for (uint32_t row = source_row;
                 row < block.target_row; ++row) {
                carry_selector[block.bank][lane][row] =
                    Fp3::One();
            }
            ++out.gathered_source_fields;
            if (source.kind == SourceValue::Kind::Fp &&
                CodecWordRow(source.word + 1) !=
                    source_row) {
                ++out.cross_row_fp_sources;
            }
            parent.columns[
                out.layout.Gather(
                    block.bank, lane)][source_row] =
                Fp3::FromFp(source.expected);
            for (uint32_t row = source_row + 1;
                 row <= block.target_row; ++row) {
                parent.columns[
                    out.layout.Gather(
                        block.bank, lane)][row] =
                    Fp3::FromFp(source.expected);
            }
            parent.columns[out.layout.Message(lane)]
                [block.target_row] =
                Fp3::FromFp(source.expected);
        }
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate; ++lane) {
            if (block.padding_one[lane]) {
                parent.columns[out.layout.Message(lane)]
                    [block.target_row] = Fp3::One();
            }
        }
    }

    if (!PinSelector(
            parent, out.layout.active, active) ||
        !PinSelector(
            parent, out.layout.first, first) ||
        !PinSelector(
            parent, out.layout.terminal, terminal) ||
        !PinSelector(
            parent, out.layout.shape, shape_selector) ||
        !PinSelector(
            parent, out.layout.ood, ood_selector)) {
        return Fail(why, "session_selectors");
    }
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        if (!PinSelector(
                parent,
                out.layout.PaddingOneSelector(lane),
                padding_one[lane])) {
            return Fail(why, "padding_selector");
        }
    }
    for (uint32_t bank = 0; bank < kGatherBanksV1; ++bank) {
        for (uint32_t lane = 0; lane < kGatherLanesV1; ++lane) {
            if (!PinSelector(
                    parent,
                    out.layout.GatherLoadSelector(
                        bank, lane),
                    load_selector[bank][lane]) ||
                !PinSelector(
                    parent,
                    out.layout.GatherCarrySelector(
                        bank, lane),
                    carry_selector[bank][lane]) ||
                !PinSelector(
                    parent,
                    out.layout.GatherTargetSelector(
                        bank, lane),
                    target_selector[bank][lane])) {
                return Fail(why, "gather_selector");
            }
            for (uint32_t port = 0;
                 port < kSourcePortsV1; ++port) {
                if (!PinSelector(
                        parent,
                        out.layout.GatherU32PortSelector(
                            bank, lane, port),
                        u32_port_selector[bank][lane][port]) ||
                    !PinSelector(
                        parent,
                        out.layout.GatherFpPortSelector(
                            bank, lane, port),
                        fp_port_selector[bank][lane][port])) {
                    return Fail(why, "source_port_selector");
                }
            }
        }
    }

    // Seed u32 -> bytes -> bits, at the existing source cell's own row.
    for (uint32_t word = 0; word < kSeedWordsV1; ++word) {
        const uint32_t row = seed_source.u32_word[word].row;
        std::vector<Fp3> word_active(
            out.parent_rows, Fp3::Zero());
        word_active[row] = Fp3::One();
        if (!PinSelector(
                parent,
                out.layout.SeedWordActive(word),
                word_active)) {
            return Fail(why, "seed_selector");
        }
        const uint32_t value = SeedWord(fs_seed, word);
        for (uint32_t byte = 0; byte < 4; ++byte) {
            const uint32_t octet =
                (value >> (8 * byte)) & 0xff;
            parent.columns[
                out.layout.SeedByte(word, byte)][row] =
                U32(octet);
            for (uint32_t bit = 0; bit < 8; ++bit) {
                parent.columns[
                    out.layout.SeedBit(
                        word, byte, bit)][row] =
                    U32((octet >> bit) & 1U);
            }
        }
        aq::AirConstraint<Fp3> word_alias;
        word_alias.name =
            "stage3.p2_prefix_source.seed_word_alias";
        word_alias.kind = aq::AirKind::kEverywhere;
        word_alias.alg_degree = 2;
        const auto source = seed_source.u32_word[word];
        const LayoutV1 layout = out.layout;
        word_alias.eval =
            [layout, word, source](
                const std::vector<Fp3>& row_values,
                const std::vector<Fp3>&) {
                Fp3 reconstructed = Fp3::Zero();
                for (uint32_t byte = 0; byte < 4; ++byte) {
                    reconstructed = gf::Add(
                        reconstructed,
                        gf::Mul(
                            Fp3::FromFp(gf::FromU64(
                                uint64_t{1} << (8 * byte))),
                            row_values[
                                layout.SeedByte(
                                    word, byte)]));
                }
                return gf::Mul(
                    row_values[
                        layout.SeedWordActive(word)],
                    gf::Sub(
                        reconstructed,
                        row_values[source.column]));
            };
        AppendConstraint(parent, std::move(word_alias));
    }

    for (uint32_t word = 0; word < kSeedWordsV1; ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            aq::AirConstraint<Fp3> reconstruct;
            reconstruct.name =
                "stage3.p2_prefix_source.seed_byte_bits";
            reconstruct.kind = aq::AirKind::kEverywhere;
            reconstruct.alg_degree = 1;
            const LayoutV1 layout = out.layout;
            reconstruct.eval =
                [layout, word, byte](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    Fp3 value = Fp3::Zero();
                    for (uint32_t bit = 0; bit < 8; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                Fp3::FromFp(gf::FromU64(
                                    uint32_t{1} << bit)),
                                row[layout.SeedBit(
                                    word, byte, bit)]));
                    }
                    return gf::Sub(
                        row[layout.SeedByte(word, byte)],
                        value);
                };
            AppendConstraint(parent, std::move(reconstruct));
            for (uint32_t bit = 0; bit < 8; ++bit) {
                aq::AirConstraint<Fp3> boolean;
                boolean.name =
                    "stage3.p2_prefix_source.seed_bit_boolean";
                boolean.kind = aq::AirKind::kEverywhere;
                boolean.alg_degree = 2;
                const uint32_t column =
                    out.layout.SeedBit(word, byte, bit);
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
                AppendConstraint(parent, std::move(boolean));
            }
        }
    }
    out.receipt_seed_byte_decomposition_constrained = true;

    // Deterministic codec gather. No random batching or prover-selected
    // permutation is used, so this copy relation has no transcript-order
    // assumption.
    for (uint32_t bank = 0; bank < kGatherBanksV1; ++bank) {
        for (uint32_t lane = 0; lane < kGatherLanesV1; ++lane) {
            aq::AirConstraint<Fp3> load;
            load.name =
                "stage3.p2_prefix_source.gather_load";
            load.kind = aq::AirKind::kTransition;
            load.alg_degree = 2;
            const LayoutV1 layout = out.layout;
            const auto proof_layout = proof_bus.layout;
            load.eval =
                [layout, proof_layout, bank, lane](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    Fp3 selected = Fp3::Zero();
                    Fp3 selector_sum = Fp3::Zero();
                    for (uint32_t port = 0;
                         port < kSourcePortsV1; ++port) {
                        const Fp3 u32_selector =
                            row[layout.
                                GatherU32PortSelector(
                                    bank, lane, port)];
                        const Fp3 fp_selector =
                            row[layout.
                                GatherFpPortSelector(
                                    bank, lane, port)];
                        selector_sum = gf::Add(
                            selector_sum,
                            gf::Add(
                                u32_selector,
                                fp_selector));
                        selected = gf::Add(
                            selected,
                            gf::Mul(
                                u32_selector,
                                row[proof_layout.Field(port)]));
                        const uint32_t high_absolute =
                            port + 1;
                        const Fp3 high =
                            high_absolute < kSourcePortsV1
                            ? row[proof_layout.Field(
                                  high_absolute)]
                            : next[proof_layout.Field(0)];
                        const Fp3 fp_value =
                            gf::Add(
                                row[proof_layout.Field(port)],
                                gf::Mul(
                                    Fp3::FromFp(kTwo32),
                                    high));
                        selected = gf::Add(
                            selected,
                            gf::Mul(
                                fp_selector, fp_value));
                    }
                    return gf::Sub(
                        gf::Mul(
                            row[layout.
                                GatherLoadSelector(
                                    bank, lane)],
                            row[layout.Gather(bank, lane)]),
                        selected);
                };
            AppendConstraint(parent, std::move(load));

            aq::AirConstraint<Fp3> load_schedule;
            load_schedule.name =
                "stage3.p2_prefix_source.gather_load_schedule";
            load_schedule.kind = aq::AirKind::kEverywhere;
            load_schedule.alg_degree = 1;
            load_schedule.eval =
                [layout = out.layout, bank, lane](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    Fp3 sum = Fp3::Zero();
                    for (uint32_t port = 0;
                         port < kSourcePortsV1; ++port) {
                        sum = gf::Add(
                            sum,
                            gf::Add(
                                row[layout.
                                    GatherU32PortSelector(
                                        bank, lane, port)],
                                row[layout.
                                    GatherFpPortSelector(
                                        bank, lane, port)]));
                    }
                    return gf::Sub(
                        row[layout.GatherLoadSelector(
                            bank, lane)],
                        sum);
                };
            AppendConstraint(
                parent, std::move(load_schedule));

            aq::AirConstraint<Fp3> carry;
            carry.name =
                "stage3.p2_prefix_source.gather_carry";
            carry.kind = aq::AirKind::kTransition;
            carry.alg_degree = 2;
            carry.eval =
                [layout = out.layout, bank, lane](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>& next) {
                    return gf::Mul(
                        row[layout.GatherCarrySelector(
                            bank, lane)],
                        gf::Sub(
                            next[layout.Gather(bank, lane)],
                            row[layout.Gather(bank, lane)]));
                };
            AppendConstraint(parent, std::move(carry));

            aq::AirConstraint<Fp3> target;
            target.name =
                "stage3.p2_prefix_source.gather_target";
            target.kind = aq::AirKind::kEverywhere;
            target.alg_degree = 2;
            target.eval =
                [layout = out.layout, bank, lane](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[layout.GatherTargetSelector(
                            bank, lane)],
                        gf::Sub(
                            row[layout.Message(lane)],
                            row[layout.Gather(bank, lane)]));
                };
            AppendConstraint(parent, std::move(target));
        }
    }
    out.shape_payload_direct_codec_aliases = true;
    out.ood_payload_direct_codec_aliases = true;

    // Serialized eval counts must match. This makes the monotone OOD payload
    // schedule's duplicated first count exactly equal to the native pair.
    const uint32_t count1_row =
        CodecWordRow(offsets.eval_z1_count_word);
    const uint32_t count2_row =
        CodecWordRow(offsets.eval_z2_count_word);
    if (count1_row > count2_row ||
        count2_row >= out.parent_rows) {
        return Fail(why, "eval_count_rows");
    }
    std::vector<Fp3> count_load(
        out.parent_rows, Fp3::Zero());
    std::vector<Fp3> count_carry(
        out.parent_rows, Fp3::Zero());
    std::vector<Fp3> count_sink(
        out.parent_rows, Fp3::Zero());
    count_load[count1_row] = Fp3::One();
    count_sink[count2_row] = Fp3::One();
    for (uint32_t row = count1_row;
         row < count2_row; ++row) {
        count_carry[row] = Fp3::One();
    }
    if (!PinSelector(
            parent, out.layout.eval_count_load_selector,
            count_load) ||
        !PinSelector(
            parent, out.layout.eval_count_carry_selector,
            count_carry) ||
        !PinSelector(
            parent, out.layout.eval_count_sink_selector,
            count_sink)) {
        return Fail(why, "eval_count_selectors");
    }
    parent.columns[out.layout.eval_count_carrier][count1_row] =
        Fp3::FromFp(count1.expected);
    for (uint32_t row = count1_row + 1;
         row <= count2_row; ++row) {
        parent.columns[out.layout.eval_count_carrier][row] =
            Fp3::FromFp(count1.expected);
    }
    {
        aq::AirConstraint<Fp3> load;
        load.name =
            "stage3.p2_prefix_source.eval_count_load";
        load.kind = aq::AirKind::kEverywhere;
        load.alg_degree = 2;
        const uint32_t source =
            proof_bus.layout.Field(
                CodecWordPort(
                    offsets.eval_z1_count_word));
        load.eval =
            [layout = out.layout, source](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.eval_count_load_selector],
                    gf::Sub(
                        row[layout.eval_count_carrier],
                        row[source]));
            };
        AppendConstraint(parent, std::move(load));
    }
    {
        aq::AirConstraint<Fp3> carry;
        carry.name =
            "stage3.p2_prefix_source.eval_count_carry";
        carry.kind = aq::AirKind::kTransition;
        carry.alg_degree = 2;
        carry.eval =
            [layout = out.layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                return gf::Mul(
                    row[layout.eval_count_carry_selector],
                    gf::Sub(
                        next[layout.eval_count_carrier],
                        row[layout.eval_count_carrier]));
            };
        AppendConstraint(parent, std::move(carry));
    }
    {
        aq::AirConstraint<Fp3> sink;
        sink.name =
            "stage3.p2_prefix_source.eval_count_sink";
        sink.kind = aq::AirKind::kEverywhere;
        sink.alg_degree = 2;
        const uint32_t source =
            proof_bus.layout.Field(
                CodecWordPort(
                    offsets.eval_z2_count_word));
        sink.eval =
            [layout = out.layout, source](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[layout.eval_count_sink_selector],
                    gf::Sub(
                        row[layout.eval_count_carrier],
                        row[source]));
            };
        AppendConstraint(parent, std::move(sink));
    }
    out.eval_counts_equality_constrained = true;

    // Message padding and inactive lanes.
    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate; ++lane) {
        if (lane < 2) {
            aq::AirConstraint<Fp3> domain;
            domain.name =
                "stage3.p2_prefix_source.message_domain";
            domain.kind = aq::AirKind::kEverywhere;
            domain.alg_degree = 2;
            const gf::Fp shape_word =
                gf::FromU64(
                    lane == 0
                    ? static_cast<uint32_t>(
                          kRCFri3AlgShapeCommitDomain)
                    : static_cast<uint32_t>(
                          kRCFri3AlgShapeCommitDomain >> 32));
            const gf::Fp ood_word =
                gf::FromU64(
                    lane == 0
                    ? static_cast<uint32_t>(
                          kRCFri3AlgOodEvalCommitDomain)
                    : static_cast<uint32_t>(
                          kRCFri3AlgOodEvalCommitDomain >> 32));
            domain.eval =
                [layout = out.layout, lane,
                 shape_word, ood_word](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    const Fp3 expected =
                        gf::Add(
                            gf::Mul(
                                row[layout.shape],
                                Fp3::FromFp(shape_word)),
                            gf::Mul(
                                row[layout.ood],
                                Fp3::FromFp(ood_word)));
                    return gf::Mul(
                        row[layout.first],
                        gf::Sub(
                            row[layout.Message(lane)],
                            expected));
                };
            AppendConstraint(parent, std::move(domain));
        }

        aq::AirConstraint<Fp3> padding;
        padding.name =
            "stage3.p2_prefix_source.message_padding";
        padding.kind = aq::AirKind::kEverywhere;
        padding.alg_degree = 2;
        padding.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 source = Fp3::Zero();
                for (uint32_t bank = 0;
                     bank < kGatherBanksV1; ++bank) {
                    source = gf::Add(
                        source,
                        row[layout.GatherTargetSelector(
                            bank, lane)]);
                }
                const Fp3 one =
                    row[layout.PaddingOneSelector(lane)];
                const Fp3 fixed =
                    lane < 2
                    ? row[layout.first]
                    : Fp3::Zero();
                const Fp3 zero_selector =
                    gf::Sub(
                        row[layout.active],
                        gf::Add(
                            source,
                            gf::Add(one, fixed)));
                return gf::Add(
                    gf::Mul(
                        one,
                        gf::Sub(
                            row[layout.Message(lane)],
                            Fp3::One())),
                    gf::Mul(
                        zero_selector,
                        row[layout.Message(lane)]));
            };
        AppendConstraint(parent, std::move(padding));

        aq::AirConstraint<Fp3> inactive;
        inactive.name =
            "stage3.p2_prefix_source.message_inactive";
        inactive.kind = aq::AirKind::kEverywhere;
        inactive.alg_degree = 2;
        inactive.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        row[layout.active]),
                    row[layout.Message(lane)]);
            };
        AppendConstraint(parent, std::move(inactive));
    }

    // Materialize the sparse sponge sessions and state carriers.
    ah::State state{};
    for (uint32_t row = 0;
         row < out.parent_rows; ++row) {
        for (uint32_t lane = 0;
             lane < ah::kAlgHashT; ++lane) {
            parent.columns[out.layout.State(lane)][row] =
                Fp3::FromFp(state[lane]);
        }
        ah::State input{};
        if (!gf::IsZero(active[row])) {
            if (gf::IsZero(first[row])) {
                input = state;
            }
            for (uint32_t lane = 0;
                 lane < ah::kAlgHashRate; ++lane) {
                input[lane] = gf::Add(
                    input[lane],
                    parent.columns[
                        out.layout.Message(lane)][row].c0);
            }
        }
        const pa::Witness witness =
            pa::BuildWitness(out.layout.permutation, input);
        for (uint32_t column =
                 out.layout.permutation.perm.base;
             column < out.layout.permutation.End();
             ++column) {
            parent.columns[column][row] =
                witness.row[column];
        }
        if (!gf::IsZero(active[row])) {
            state = witness.output;
        }
    }
    auto poseidon_constraints =
        pa::BuildFixedConstraints(out.layout.permutation);
    for (auto& constraint : poseidon_constraints) {
        AppendConstraint(parent, std::move(constraint));
    }
    out.sparse_poseidon_permutations_constrained = true;

    for (uint32_t lane = 0;
         lane < ah::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> input;
        input.name =
            "stage3.p2_prefix_source.sponge_input";
        input.kind = aq::AirKind::kEverywhere;
        input.alg_degree = 2;
        const uint32_t input_column =
            out.layout.permutation.perm.InputCol(lane);
        input.eval =
            [layout = out.layout, lane, input_column](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                const Fp3 message =
                    lane < ah::kAlgHashRate
                    ? row[layout.Message(lane)]
                    : Fp3::Zero();
                const Fp3 continued =
                    gf::Add(row[layout.State(lane)], message);
                const Fp3 reset = message;
                Fp3 expected = gf::Add(
                    gf::Mul(row[layout.first], reset),
                    gf::Mul(
                        gf::Sub(
                            row[layout.active],
                            row[layout.first]),
                        continued));
                return gf::Add(
                    gf::Mul(
                        row[layout.active],
                        gf::Sub(
                            row[input_column],
                            expected)),
                    gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            row[layout.active]),
                        row[input_column]));
            };
        AppendConstraint(parent, std::move(input));

        aq::AirConstraint<Fp3> state_transition;
        state_transition.name =
            "stage3.p2_prefix_source.state_transition";
        state_transition.kind = aq::AirKind::kTransition;
        state_transition.alg_degree = 2;
        state_transition.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>& next) {
                const Fp3 updated =
                    ar::PermOutputLane(
                        layout.permutation.perm,
                        row, lane);
                const Fp3 expected =
                    gf::Add(
                        gf::Mul(
                            row[layout.active],
                            updated),
                        gf::Mul(
                            gf::Sub(
                                Fp3::One(),
                                row[layout.active]),
                            row[layout.State(lane)]));
                return gf::Sub(
                    next[layout.State(lane)],
                    expected);
            };
        AppendConstraint(
            parent, std::move(state_transition));

        aq::AirConstraint<Fp3> initial_state;
        initial_state.name =
            "stage3.p2_prefix_source.initial_state_zero";
        initial_state.kind = aq::AirKind::kFirstRow;
        initial_state.alg_degree = 1;
        initial_state.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return row[layout.State(lane)];
            };
        AppendConstraint(
            parent, std::move(initial_state));
    }
    for (const uint32_t selector :
         std::array<uint32_t, 2>{
             out.layout.first, out.layout.terminal}) {
        aq::AirConstraint<Fp3> subset;
        subset.name =
            "stage3.p2_prefix_source.session_subset";
        subset.kind = aq::AirKind::kEverywhere;
        subset.alg_degree = 2;
        subset.eval =
            [layout = out.layout, selector](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    row[selector],
                    gf::Sub(
                        Fp3::One(),
                        row[layout.active]));
            };
        AppendConstraint(parent, std::move(subset));
    }
    {
        aq::AirConstraint<Fp3> family;
        family.name =
            "stage3.p2_prefix_source.family_partition";
        family.kind = aq::AirKind::kEverywhere;
        family.alg_degree = 1;
        family.eval =
            [layout = out.layout](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    row[layout.active],
                    gf::Add(
                        row[layout.shape],
                        row[layout.ood]));
            };
        AppendConstraint(parent, std::move(family));
    }
    out.sponge_state_transitions_constrained = true;
    out.exact_10star_padding = true;

    const Fri3AlgDigest shape_digest =
        Fri3AlgShapeCommit(
            proof.n_coeffs, proof.column_len);
    const Fri3AlgDigest ood_digest =
        Fri3AlgOodEvalCommit(
            proof.z1, proof.z2,
            proof.evals_z1, proof.evals_z2);
    const std::array<
        std::pair<uint32_t, const Fri3AlgDigest*>, 2>
        digest_rows{{
            {out.shape_terminal_row, &shape_digest},
            {out.ood_terminal_row, &ood_digest},
        }};
    for (const auto& [row, digest] : digest_rows) {
        for (uint32_t lane = 0;
             lane < kDigestLanesV1; ++lane) {
            const uint64_t value = gf::Canonical((*digest)[lane]);
            for (uint32_t byte = 0; byte < 8; ++byte) {
                const uint32_t octet =
                    (value >> (8 * byte)) & 0xff;
                parent.columns[
                    out.layout.DigestByte(lane, byte)][row] =
                    U32(octet);
                for (uint32_t bit = 0; bit < 8; ++bit) {
                    parent.columns[
                        out.layout.DigestBit(
                            lane, byte, bit)][row] =
                        U32((octet >> bit) & 1U);
                }
            }
            const uint32_t high =
                static_cast<uint32_t>(value >> 32);
            const gf::Fp delta = gf::Sub(
                kU32Max, gf::FromU64(high));
            const bool is_max = high == UINT32_MAX;
            parent.columns[
                out.layout.DigestHighIsMax(lane)][row] =
                is_max ? Fp3::One() : Fp3::Zero();
            parent.columns[
                out.layout.DigestHighDeltaInverse(lane)]
                [row] =
                is_max
                ? Fp3::Zero()
                : Fp3::FromFp(gf::Inv(delta));
        }
    }

    for (uint32_t lane = 0;
         lane < kDigestLanesV1; ++lane) {
        for (uint32_t byte = 0; byte < 8; ++byte) {
            aq::AirConstraint<Fp3> reconstruct;
            reconstruct.name =
                "stage3.p2_prefix_source.digest_byte_bits";
            reconstruct.kind = aq::AirKind::kEverywhere;
            reconstruct.alg_degree = 1;
            reconstruct.eval =
                [layout = out.layout, lane, byte](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    Fp3 value = Fp3::Zero();
                    for (uint32_t bit = 0; bit < 8; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                Fp3::FromFp(gf::FromU64(
                                    uint32_t{1} << bit)),
                                row[layout.DigestBit(
                                    lane, byte, bit)]));
                    }
                    return gf::Sub(
                        row[layout.DigestByte(lane, byte)],
                        value);
                };
            AppendConstraint(parent, std::move(reconstruct));
            for (uint32_t bit = 0; bit < 8; ++bit) {
                aq::AirConstraint<Fp3> boolean;
                boolean.name =
                    "stage3.p2_prefix_source.digest_bit_boolean";
                boolean.kind = aq::AirKind::kEverywhere;
                boolean.alg_degree = 2;
                const uint32_t column =
                    out.layout.DigestBit(
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
                AppendConstraint(parent, std::move(boolean));
            }
        }
        aq::AirConstraint<Fp3> output;
        output.name =
            "stage3.p2_prefix_source.digest_output";
        output.kind = aq::AirKind::kEverywhere;
        output.alg_degree = 2;
        output.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 encoded = Fp3::Zero();
                for (uint32_t byte = 0; byte < 8; ++byte) {
                    encoded = gf::Add(
                        encoded,
                        gf::Mul(
                            Fp3::FromFp(gf::FromU64(
                                uint64_t{1} << (8 * byte))),
                            row[layout.DigestByte(
                                lane, byte)]));
                }
                return gf::Mul(
                    row[layout.terminal],
                    gf::Sub(
                        encoded,
                        ar::PermOutputLane(
                            layout.permutation.perm,
                            row, lane)));
            };
        AppendConstraint(parent, std::move(output));

        aq::AirConstraint<Fp3> high_is_max;
        high_is_max.name =
            "stage3.p2_prefix_source.digest_high_is_max";
        high_is_max.kind = aq::AirKind::kEverywhere;
        high_is_max.alg_degree = 3;
        high_is_max.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 high = Fp3::Zero();
                for (uint32_t byte = 0; byte < 4; ++byte) {
                    const Fp3 coefficient =
                        Fp3::FromFp(gf::FromU64(
                            uint64_t{1} << (8 * byte)));
                    high = gf::Add(
                        high,
                        gf::Mul(
                            coefficient,
                            row[layout.DigestByte(
                                lane, 4 + byte)]));
                }
                const Fp3 delta = gf::Sub(
                    Fp3::FromFp(kU32Max), high);
                const Fp3 is_max =
                    row[layout.DigestHighIsMax(lane)];
                const Fp3 inverse =
                    row[layout.
                        DigestHighDeltaInverse(lane)];
                return gf::Mul(
                    row[layout.terminal],
                    gf::Sub(
                        is_max,
                        gf::Sub(
                            Fp3::One(),
                            gf::Mul(delta, inverse))));
            };
        AppendConstraint(parent, std::move(high_is_max));

        aq::AirConstraint<Fp3> canonical_low;
        canonical_low.name =
            "stage3.p2_prefix_source.digest_canonical_low";
        canonical_low.kind = aq::AirKind::kEverywhere;
        canonical_low.alg_degree = 3;
        canonical_low.eval =
            [layout = out.layout, lane](
                const std::vector<Fp3>& row,
                const std::vector<Fp3>&) {
                Fp3 low = Fp3::Zero();
                for (uint32_t byte = 0; byte < 4; ++byte) {
                    low = gf::Add(
                        low,
                        gf::Mul(
                            Fp3::FromFp(gf::FromU64(
                                uint64_t{1} << (8 * byte))),
                            row[layout.DigestByte(
                                lane, byte)]));
                }
                return gf::Mul(
                    row[layout.terminal],
                    gf::Mul(
                        row[layout.DigestHighIsMax(lane)],
                        low));
            };
        AppendConstraint(parent, std::move(canonical_low));
    }
    out.digest_outputs_canonical_bytes = true;

    out.exports.fs_seed.byte.reserve(kSeedBytesV1);
    for (uint32_t word = 0; word < kSeedWordsV1; ++word) {
        const uint32_t row = seed_source.u32_word[word].row;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.exports.fs_seed.byte.push_back({
                out.layout.SeedByte(word, byte), row});
        }
    }
    for (uint32_t lane = 0;
         lane < kDigestLanesV1; ++lane) {
        for (uint32_t byte = 0; byte < 8; ++byte) {
            out.exports.shape_commit.byte.push_back({
                out.layout.DigestByte(lane, byte),
                out.shape_terminal_row});
            out.exports.ood_eval_commit.byte.push_back({
                out.layout.DigestByte(lane, byte),
                out.ood_terminal_row});
        }
    }
    out.exports.seed_from_canonical_receipt_statement =
        true;
    out.exports.seed_bound_before_first_commitment = true;
    out.exports.shape_commit_derived_by_p2_air = true;
    out.exports.ood_eval_commit_derived_by_p2_air = true;
    out.exports.source_cells_canonical = true;
    out.exports.complete_child_verifier_same_parent = false;
    out.exports.recursively_consumed = false;

    // Values are never preprocessed; only the verifier-regenerated schedule
    // selectors above are.
    out.source_values_preprocessed = false;
    out.selectors_only_preprocessed =
        std::none_of(
            parent.combined.preprocessed.begin(),
            parent.combined.preprocessed.end(),
            [&out](const auto& pin) {
                const uint32_t column = pin.first;
                return
                    (column >= out.layout.message_base &&
                     column <
                         out.layout.message_base +
                             ah::kAlgHashRate) ||
                    (column >= out.layout.seed_byte_base &&
                     column <
                         out.layout.seed_word_active_base) ||
                    (column >= out.layout.digest_byte_base &&
                     column <
                         out.layout.digest_high_is_max_base) ||
                    column == out.layout.eval_count_carrier;
            });
    out.complete_child_verifier_same_parent = false;
    out.recursively_consumed = false;
    out.recursive_authority = false;
    out.residuals = {
        "complete_receipt_child_verifier_same_parent_consumption",
        "normalized_parent_proof_recursive_consumption",
    };
    out.added_constraints =
        static_cast<uint32_t>(
            parent.combined.constraints.size()) -
        out.constraint_base;
    out.violations = CountViolations(parent);
    out.valid =
        out.receipt_seed_cells_preexisting &&
        out.receipt_seed_canonical_u32 &&
        out.receipt_seed_byte_decomposition_constrained &&
        out.shape_payload_direct_codec_aliases &&
        out.ood_payload_direct_codec_aliases &&
        out.eval_counts_equality_constrained &&
        out.sparse_poseidon_permutations_constrained &&
        out.sponge_state_transitions_constrained &&
        out.exact_10star_padding &&
        out.digest_outputs_canonical_bytes &&
        !out.source_values_preprocessed &&
        out.selectors_only_preprocessed &&
        !out.complete_child_verifier_same_parent &&
        !out.recursively_consumed &&
        !out.recursive_authority &&
        out.exports.fs_seed.byte.size() == kSeedBytesV1 &&
        out.exports.shape_commit.byte.size() ==
            kDigestBytesV1 &&
        out.exports.ood_eval_commit.byte.size() ==
            kDigestBytesV1 &&
        out.violations == 0;
    out.note = out.valid
        ? "stage3:p2_prefix_source_air:"
          "seed_shape_ood_locally_proof_owned;"
          "complete_child_consumption_open"
        : "stage3:p2_prefix_source_air:invalid";
    if (!out.valid) {
        uint32_t first_row = 0;
        std::string first_constraint;
        (void)fp::CountHashOpeningViolations(
            parent.combined, parent.columns,
            &first_row, &first_constraint);
        return Fail(
            why,
            "final:violations=" +
                std::to_string(out.violations) +
                ":first=" + first_constraint +
                "@" + std::to_string(first_row) +
                ":selectors_only=" +
                std::to_string(
                    out.selectors_only_preprocessed) +
                ":seed=" +
                std::to_string(
                    out.
                        receipt_seed_byte_decomposition_constrained) +
                ":shape=" +
                std::to_string(
                    out.shape_payload_direct_codec_aliases) +
                ":ood=" +
                std::to_string(
                    out.ood_payload_direct_codec_aliases) +
                ":digest=" +
                std::to_string(
                    out.digest_outputs_canonical_bytes));
    }
    parent.violations = out.violations;
    return true;
}

bool ValidateV10PrefixSourceAirV1(
    const fp::FoldBusComposition& parent,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1&
        proof_bus,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1&
        decoder,
    const ReceiptSeedSourceRefsV1& seed_source,
    const AttachmentV1& attachment,
    std::string* why)
{
    if (!attachment.valid ||
        attachment.version != kPrefixSourceAirVersionV1 ||
        proof.version !=
            kRCFri3AlgP2Q192K2ProofVersionV10 ||
        fs_seed.IsNull() ||
        !proof_bus.valid ||
        !decoder.valid ||
        attachment.original_columns !=
            attachment.layout.base ||
        attachment.layout.End() !=
            parent.combined.n_columns ||
        attachment.parent_rows !=
            parent.combined.n_rows ||
        attachment.added_columns !=
            attachment.layout.End() -
                attachment.layout.base ||
        attachment.constraint_base +
                attachment.added_constraints !=
            parent.combined.constraints.size() ||
        !attachment.receipt_seed_cells_preexisting ||
        !attachment.receipt_seed_canonical_u32 ||
        !attachment.
            receipt_seed_byte_decomposition_constrained ||
        !attachment.shape_payload_direct_codec_aliases ||
        !attachment.ood_payload_direct_codec_aliases ||
        !attachment.eval_counts_equality_constrained ||
        !attachment.
            sparse_poseidon_permutations_constrained ||
        !attachment.sponge_state_transitions_constrained ||
        !attachment.exact_10star_padding ||
        !attachment.digest_outputs_canonical_bytes ||
        attachment.source_values_preprocessed ||
        !attachment.selectors_only_preprocessed ||
        attachment.complete_child_verifier_same_parent ||
        attachment.recursively_consumed ||
        attachment.recursive_authority ||
        seed_source.complete_child_verifier_same_parent ||
        attachment.exports.fs_seed.byte.size() !=
            kSeedBytesV1 ||
        attachment.exports.shape_commit.byte.size() !=
            kDigestBytesV1 ||
        attachment.exports.ood_eval_commit.byte.size() !=
            kDigestBytesV1 ||
        !attachment.exports.
            seed_from_canonical_receipt_statement ||
        !attachment.exports.seed_bound_before_first_commitment ||
        !attachment.exports.shape_commit_derived_by_p2_air ||
        !attachment.exports.ood_eval_commit_derived_by_p2_air ||
        !attachment.exports.source_cells_canonical ||
        attachment.exports.
            complete_child_verifier_same_parent ||
        attachment.exports.recursively_consumed ||
        CountViolations(parent) != 0) {
        return Fail(why, "shape");
    }
    for (uint32_t word = 0; word < kSeedWordsV1; ++word) {
        const auto cell = seed_source.u32_word[word];
        if (cell.column >= attachment.original_columns ||
            cell.row >= attachment.parent_rows ||
            !CanonicalBaseCell(
                parent.columns[cell.column][cell.row]) ||
            gf::Canonical(
                parent.columns[cell.column][cell.row].c0) !=
                SeedWord(fs_seed, word)) {
            return Fail(why, "seed");
        }
        for (uint32_t byte = 0; byte < 4; ++byte) {
            const auto exported =
                attachment.exports.fs_seed.byte[
                    4 * word + byte];
            const uint8_t expected =
                (SeedWord(fs_seed, word) >>
                 (8 * byte)) &
                0xff;
            if (exported.column !=
                    attachment.layout.SeedByte(
                        word, byte) ||
                exported.row != cell.row ||
                !gf::Eq(
                    parent.columns[exported.column]
                        [exported.row],
                    U32(expected))) {
                return Fail(why, "seed_export");
            }
        }
    }
    const Fri3AlgDigest shape =
        Fri3AlgShapeCommit(
            proof.n_coeffs, proof.column_len);
    const Fri3AlgDigest ood =
        Fri3AlgOodEvalCommit(
            proof.z1, proof.z2,
            proof.evals_z1, proof.evals_z2);
    for (uint32_t lane = 0;
         lane < kDigestLanesV1; ++lane) {
        for (uint32_t byte = 0; byte < 8; ++byte) {
            const auto shape_cell =
                attachment.exports.shape_commit.byte[
                    8 * lane + byte];
            const auto ood_cell =
                attachment.exports.ood_eval_commit.byte[
                    8 * lane + byte];
            const uint8_t expected_shape =
                gf::Canonical(shape[lane]) >>
                (8 * byte);
            const uint8_t expected_ood =
                gf::Canonical(ood[lane]) >>
                (8 * byte);
            if (shape_cell.column !=
                    attachment.layout.DigestByte(
                        lane, byte) ||
                shape_cell.row !=
                    attachment.shape_terminal_row ||
                ood_cell.column !=
                    attachment.layout.DigestByte(
                        lane, byte) ||
                ood_cell.row !=
                    attachment.ood_terminal_row ||
                !gf::Eq(
                    parent.columns[shape_cell.column]
                        [shape_cell.row],
                    U32(expected_shape)) ||
                !gf::Eq(
                    parent.columns[ood_cell.column]
                        [ood_cell.row],
                    U32(expected_ood))) {
                return Fail(why, "digest_bytes");
            }
        }
    }
    if (attachment.residuals.size() != 2) {
        return Fail(why, "exports");
    }
    if (why != nullptr) {
        *why =
            "stage3:p2_prefix_source_air:validate_ok";
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_p2_prefix_source_air
