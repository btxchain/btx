// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_normalized_exports.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <numeric>
#include <utility>

namespace matmul::v4::rc::stage3_p2_normalized_exports {
namespace {

namespace ah = alg_hash;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:p2_normalized_exports:" + message;
    }
    return false;
}

struct CodecOffsetsV10 {
    uint32_t nonce{8};
    uint32_t blowup{16};
    uint32_t n_coeffs{20};
    uint32_t row_root{24};
    uint32_t width{60};
    uint32_t lambda{0};
    uint32_t z1{0};
    uint32_t z2{0};
    uint32_t w1{0};
    uint32_t w2{0};
    std::vector<uint32_t> fold_roots;
    std::vector<uint32_t> fold_challenges;
    std::vector<uint32_t> query_indices;
    uint32_t end{0};
};

bool AddCursor(
    uint64_t& cursor, uint64_t amount, uint64_t limit)
{
    if (amount > limit || cursor > limit - amount) {
        return false;
    }
    cursor += amount;
    return true;
}

bool BuildCodecOffsetsV10(
    const Fri3AlgBatchProof& proof,
    size_t encoded_size,
    CodecOffsetsV10& out)
{
    out = {};
    uint64_t cursor = 64;
    const uint64_t limit = encoded_size;
    if (!AddCursor(
            cursor, uint64_t{4} * proof.column_len.size(),
            limit)) {
        return false;
    }
    out.lambda = static_cast<uint32_t>(cursor);
    if (!AddCursor(cursor, 24, limit)) return false;
    out.z1 = static_cast<uint32_t>(cursor);
    if (!AddCursor(cursor, 24, limit)) return false;
    out.z2 = static_cast<uint32_t>(cursor);
    if (!AddCursor(cursor, 24, limit) ||
        !AddCursor(cursor, 4, limit) ||
        !AddCursor(
            cursor, uint64_t{24} * proof.evals_z1.size(),
            limit) ||
        !AddCursor(cursor, 4, limit) ||
        !AddCursor(
            cursor, uint64_t{24} * proof.evals_z2.size(),
            limit)) {
        return false;
    }
    out.w1 = static_cast<uint32_t>(cursor);
    if (!AddCursor(cursor, 24, limit)) return false;
    out.w2 = static_cast<uint32_t>(cursor);
    if (!AddCursor(cursor, 24, limit) ||
        !AddCursor(cursor, 4, limit)) {
        return false;
    }
    out.fold_roots.reserve(proof.fold_layers.size());
    for (const auto& layer : proof.fold_layers) {
        (void)layer;
        out.fold_roots.push_back(
            static_cast<uint32_t>(cursor));
        if (!AddCursor(cursor, 32 + 4, limit)) {
            return false;
        }
    }
    if (!AddCursor(cursor, 24 + 4, limit)) return false;
    out.fold_challenges.reserve(
        proof.fold_challenges.size());
    for (const auto& challenge : proof.fold_challenges) {
        (void)challenge;
        out.fold_challenges.push_back(
            static_cast<uint32_t>(cursor));
        if (!AddCursor(cursor, 24, limit)) return false;
    }
    if (!AddCursor(cursor, 4, limit)) return false;
    out.query_indices.reserve(proof.queries.size());
    for (const auto& query : proof.queries) {
        out.query_indices.push_back(
            static_cast<uint32_t>(cursor));
        if (!AddCursor(cursor, 4 + 4, limit) ||
            !AddCursor(
                cursor, uint64_t{24} *
                    query.row.values.size(), limit) ||
            !AddCursor(cursor, 4, limit) ||
            !AddCursor(
                cursor, uint64_t{32} *
                    query.row.siblings.size(), limit) ||
            !AddCursor(cursor, 4, limit)) {
            return false;
        }
        for (const auto& step : query.steps) {
            if (!AddCursor(cursor, 4 + 4 + 24 + 24 + 4,
                           limit) ||
                !AddCursor(
                    cursor, uint64_t{32} *
                        step.even_siblings.size(), limit) ||
                !AddCursor(cursor, 4, limit) ||
                !AddCursor(
                    cursor, uint64_t{32} *
                        step.odd_siblings.size(), limit)) {
                return false;
            }
        }
    }
    if (cursor != limit ||
        cursor > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out.end = static_cast<uint32_t>(cursor);
    return true;
}

bool SameCodecMap(
    const fp::NormalizedAlgAirBatchCodecMapV1& a,
    const fp::NormalizedAlgAirBatchCodecMapV1& b)
{
    if (!a.valid || !b.valid ||
        a.codec_bytes != b.codec_bytes ||
        a.codec_words != b.codec_words ||
        a.fp_elements != b.fp_elements ||
        a.entries.size() != b.entries.size() ||
        a.semantic_tokens.size() !=
            b.semantic_tokens.size()) {
        return false;
    }
    for (size_t i = 0; i < a.entries.size(); ++i) {
        const auto& x = a.entries[i];
        const auto& y = b.entries[i];
        if (x.word_index != y.word_index ||
            x.byte_offset != y.byte_offset ||
            x.value != y.value ||
            x.semantic_ordinal != y.semantic_ordinal ||
            x.kind != y.kind ||
            x.consumed_by_existing_verifier_chip !=
                y.consumed_by_existing_verifier_chip) {
            return false;
        }
    }
    for (size_t i = 0;
         i < a.semantic_tokens.size(); ++i) {
        const auto& x = a.semantic_tokens[i];
        const auto& y = b.semantic_tokens[i];
        if (x.address != y.address ||
            x.word_index != y.word_index ||
            !gf::Eq(x.value, y.value) ||
            x.kind != y.kind ||
            x.owner != y.owner ||
            x.consumed_by_existing_verifier_chip !=
                y.consumed_by_existing_verifier_chip) {
            return false;
        }
    }
    return true;
}

p2join::CellRefV1 DecoderByteCell(
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1&
        decoder,
    uint32_t codec_offset)
{
    const uint32_t word = codec_offset / 4;
    const uint32_t position = 5 + word;
    const uint32_t row =
        position / fp::kNormalizedAlgAirCodecWordLanes;
    const uint32_t lane =
        position % fp::kNormalizedAlgAirCodecWordLanes;
    return {
        decoder.layout.Byte(lane, codec_offset % 4),
        row};
}

uint8_t CodecByte(
    const fp::NormalizedAlgAirBatchCodecMapV1& map,
    uint32_t offset)
{
    const uint32_t word = offset / 4;
    return static_cast<uint8_t>(
        map.entries[word].value >>
        (8 * (offset % 4)));
}

bool DecoderCellsExact(
    const fp::FoldBusComposition& composition,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1&
        decoder)
{
    if (composition.columns.size() <
            decoder.layout.End() ||
        composition.combined.n_rows <
            decoder.parent_rows) {
        return false;
    }
    for (uint32_t offset = 0;
         offset < decoder.map.codec_bytes; ++offset) {
        const p2join::CellRefV1 cell =
            DecoderByteCell(decoder, offset);
        if (cell.column >= composition.columns.size() ||
            cell.row >= composition.columns[cell.column].size() ||
            !gf::Eq(
                composition.columns[cell.column][cell.row],
                gf::Fp3::FromFp(gf::FromU64(
                    CodecByte(decoder.map, offset))))) {
            return false;
        }
    }
    return true;
}

const fp::NormalizedAlgAirCodecSemanticTokenV1*
FindTokenByWord(
    const fp::NormalizedAlgAirBatchCodecMapV1& map,
    uint32_t word,
    fp::NormalizedAlgAirCodecTokenKind kind)
{
    const fp::NormalizedAlgAirCodecSemanticTokenV1* found =
        nullptr;
    for (const auto& token : map.semantic_tokens) {
        if (token.word_index != word ||
            token.kind != kind) {
            continue;
        }
        if (found != nullptr) return nullptr;
        found = &token;
    }
    return found;
}

bool FindRemoteProducerCell(
    const fp::FoldBusComposition& composition,
    const fp::NormalizedAlgAirRemoteExportAttachmentV1&
        remote,
    uint32_t address,
    const gf::Fp3& expected,
    p2join::CellRefV1& out)
{
    bool found = false;
    for (uint32_t row = 0;
         row < remote.parent_rows; ++row) {
        for (uint32_t port = 0;
             port <
                 fp::NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            const uint32_t active_col =
                remote.layout.bus.Active(false, port);
            const uint32_t address_col =
                remote.layout.bus.Address(false, port);
            const uint32_t value_col =
                remote.layout.bus.Value(false, port);
            if (value_col >= composition.columns.size() ||
                row >= composition.columns[value_col].size() ||
                gf::IsZero(
                    composition.columns[active_col][row])) {
                continue;
            }
            const gf::Fp3& actual_address =
                composition.columns[address_col][row];
            if (actual_address.c1 != 0 ||
                actual_address.c2 != 0 ||
                gf::Canonical(actual_address.c0) != address) {
                continue;
            }
            if (!gf::Eq(
                    composition.columns[value_col][row],
                    expected) ||
                found) {
                return false;
            }
            found = true;
            out = {value_col, row};
        }
    }
    return found;
}

bool FindCodecCtlProducerCell(
    const fp::FoldBusComposition& composition,
    const fp::NormalizedAlgAirCodecCtlAttachmentV1& codec_ctl,
    const fp::NormalizedAlgAirCodecSemanticTokenV1& token,
    p2join::CellRefV1& out)
{
    const uint32_t position = 5 + token.word_index;
    const uint32_t row =
        position /
        fp::NormalizedAlgAirCodecCtlLayout::kPorts;
    const uint32_t port =
        position %
        fp::NormalizedAlgAirCodecCtlLayout::kPorts;
    if (row >= codec_ctl.parent_rows ||
        codec_ctl.layout.End() >
            composition.combined.n_columns) {
        return false;
    }
    const uint32_t value_col =
        codec_ctl.layout.Value(false, port);
    const uint32_t address_col =
        codec_ctl.layout.Address(false, port);
    const uint32_t active_col =
        codec_ctl.layout.Active(false, port);
    const uint32_t fp3_col =
        codec_ctl.layout.ProducerFp3(port);
    if (value_col >= composition.columns.size() ||
        row >= composition.columns[value_col].size() ||
        !gf::Eq(
            composition.columns[value_col][row],
            token.value) ||
        !gf::Eq(
            composition.columns[address_col][row],
            gf::Fp3::FromFp(gf::FromU64(
                token.address))) ||
        !gf::Eq(
            composition.columns[active_col][row],
            gf::Fp3::One()) ||
        !gf::Eq(
            composition.columns[fp3_col][row],
            gf::Fp3::One())) {
        return false;
    }
    out = {value_col, row};
    return true;
}

struct ByteBuilder {
    PrefixScheduleExportsV1* schedule{nullptr};
    const std::vector<unsigned char>* actual{nullptr};
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1*
        decoder{nullptr};
    const fp::FoldBusComposition* composition{nullptr};
    InventoryV1* inventory{nullptr};
    bool ok{true};

    void Fixed(uint8_t value)
    {
        PrefixByteExportV1 byte;
        byte.kind = PrefixByteOriginKindV1::FixedProtocol;
        byte.fixed_value = value;
        Add(std::move(byte), value);
        ++inventory->fixed_protocol_bytes;
    }

    void Missing(PrefixByteOriginKindV1 kind)
    {
        PrefixByteExportV1 byte;
        byte.kind = kind;
        Add(std::move(byte), (*actual)[schedule->bytes.size()]);
        switch (kind) {
        case PrefixByteOriginKindV1::MissingSeed:
            ++inventory->missing_seed_bytes;
            break;
        case PrefixByteOriginKindV1::MissingShapeCommit:
            ++inventory->missing_shape_commit_bytes;
            break;
        case PrefixByteOriginKindV1::MissingOodEvalCommit:
            ++inventory->missing_ood_eval_commit_bytes;
            break;
        default:
            ok = false;
            break;
        }
    }

    void Codec(uint32_t offset)
    {
        PrefixByteExportV1 byte;
        byte.kind = PrefixByteOriginKindV1::CodecDecoder;
        byte.codec_offset = offset;
        byte.decoder_cell =
            DecoderByteCell(*decoder, offset);
        Add(std::move(byte),
            CodecByte(decoder->map, offset));
        ++inventory->codec_decoder_owned_bytes;
    }

    void ProofOwned(
        PrefixByteOriginKindV1 kind,
        const p2join::BytesCellRefsV1& refs,
        uint32_t index)
    {
        if (index >= refs.byte.size() ||
            composition == nullptr) {
            ok = false;
            return;
        }
        const p2join::CellRefV1 cell = refs.byte[index];
        if (cell.column >= composition->columns.size() ||
            cell.row >=
                composition->columns[cell.column].size()) {
            ok = false;
            return;
        }
        const gf::Fp3& value =
            composition->columns[cell.column][cell.row];
        if (value.c1 != 0 || value.c2 != 0 ||
            value.c0 != gf::Canonical(value.c0) ||
            gf::Canonical(value.c0) > 0xff) {
            ok = false;
            return;
        }
        PrefixByteExportV1 byte;
        byte.kind = kind;
        byte.decoder_cell = cell;
        Add(std::move(byte), static_cast<uint8_t>(
            gf::Canonical(value.c0)));
    }

    void Add(PrefixByteExportV1 byte, uint8_t expected)
    {
        const size_t offset = schedule->bytes.size();
        if (offset >= actual->size() ||
            (*actual)[offset] != expected) {
            ok = false;
            return;
        }
        byte.schedule = schedule->schedule;
        byte.prefix_offset =
            static_cast<uint32_t>(offset);
        schedule->bytes.push_back(std::move(byte));
        ++inventory->total_distinct_prefix_bytes;
    }
};

bool BuildPrefixSchedule(
    const Fri3AlgBatchProof& proof,
    const p2bind::BindingResult& binding,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1&
        decoder,
    const fp::FoldBusComposition& composition,
    const ProofOwnedPrefixSourceRefsV1* prefix_sources,
    const CodecOffsetsV10& offsets,
    InventoryV1& out)
{
    const size_t folds = proof.fold_challenges.size();
    if (proof.fold_layers.size() != folds + 1 ||
        binding.prefix_schedule.size() != folds + 5) {
        return false;
    }
    const size_t domain_len =
        std::strlen(kRCFri3AlgP2Q192K2DomainTagV10);
    for (size_t index = 0;
         index < binding.prefix_schedule.size(); ++index) {
        const auto& source = binding.prefix_schedule[index];
        PrefixScheduleExportsV1 schedule;
        schedule.schedule = static_cast<uint32_t>(index);
        schedule.source_kind = source.source_kind;
        schedule.first_event_ordinal =
            source.first_event_ordinal;
        if (index == 0) {
            if (!source.fs_prefix.empty()) return false;
            out.prefix_schedules.push_back(
                std::move(schedule));
            continue;
        }
        ByteBuilder bytes{
            &schedule, &source.fs_prefix,
            &decoder, &composition, &out, true};
        const char* domain =
            kRCFri3AlgP2Q192K2DomainTagV10;
        for (size_t i = 0; i < domain_len; ++i) {
            bytes.Fixed(static_cast<uint8_t>(domain[i]));
        }
        for (uint32_t i = 0; i < 32; ++i) {
            if (prefix_sources != nullptr) {
                bytes.ProofOwned(
                    PrefixByteOriginKindV1::
                        ReceiptStatementSeed,
                    prefix_sources->fs_seed, i);
            } else {
                bytes.Missing(
                    PrefixByteOriginKindV1::MissingSeed);
            }
        }
        for (uint32_t i = 0; i < 8; ++i) {
            bytes.Codec(offsets.nonce + i);
        }
        for (uint32_t i = 0; i < 4; ++i) {
            bytes.Codec(offsets.blowup + i);
        }
        for (uint32_t i = 0; i < 4; ++i) {
            bytes.Codec(offsets.n_coeffs + i);
        }
        for (uint32_t i = 0; i < 4; ++i) {
            bytes.Codec(4 + i);
        }
        for (uint32_t i = 0; i < 4; ++i) {
            bytes.Codec(offsets.width + i);
        }
        for (uint32_t i = 0; i < 32; ++i) {
            if (prefix_sources != nullptr) {
                bytes.ProofOwned(
                    PrefixByteOriginKindV1::
                        DerivedShapeCommit,
                    prefix_sources->shape_commit, i);
            } else {
                bytes.Missing(
                    PrefixByteOriginKindV1::
                        MissingShapeCommit);
            }
        }
        for (uint32_t i = 0; i < 32; ++i) {
            bytes.Codec(offsets.row_root + i);
        }
        if (index >= 2) {
            for (uint32_t i = 0; i < 24; ++i) {
                bytes.Codec(offsets.lambda + i);
            }
        }
        if (index >= 3) {
            for (uint32_t i = 0; i < 24; ++i) {
                bytes.Codec(offsets.z1 + i);
            }
            for (uint32_t i = 0; i < 24; ++i) {
                bytes.Codec(offsets.z2 + i);
            }
            for (uint32_t i = 0; i < 32; ++i) {
                if (prefix_sources != nullptr) {
                    bytes.ProofOwned(
                        PrefixByteOriginKindV1::
                            DerivedOodEvalCommit,
                        prefix_sources->ood_eval_commit,
                        i);
                } else {
                    bytes.Missing(
                        PrefixByteOriginKindV1::
                            MissingOodEvalCommit);
                }
            }
        }
        if (index >= 4) {
            for (uint32_t i = 0; i < 24; ++i) {
                bytes.Codec(offsets.w1 + i);
            }
            for (uint32_t i = 0; i < 24; ++i) {
                bytes.Codec(offsets.w2 + i);
            }
            const size_t roots =
                index == folds + 4
                    ? folds + 1
                    : index - 3;
            if (roots > offsets.fold_roots.size()) {
                return false;
            }
            for (size_t root = 0; root < roots; ++root) {
                for (uint32_t i = 0; i < 32; ++i) {
                    bytes.Codec(
                        offsets.fold_roots[root] + i);
                }
            }
        }
        if (!bytes.ok ||
            schedule.bytes.size() !=
                source.fs_prefix.size()) {
            return false;
        }
        out.prefix_schedules.push_back(
            std::move(schedule));
    }
    return true;
}

bool FindEventRows(
    const p2air::BuildResult& transcript,
    uint32_t ordinal,
    uint32_t& start,
    uint32_t& terminal)
{
    bool found_start = false;
    bool found_terminal = false;
    for (uint32_t row = 0;
         row < transcript.cs.n_rows; ++row) {
        if (gf::IsZero(
                transcript.columns[
                    transcript.layout.active_col][row]) ||
            gf::Canonical(
                transcript.columns[
                    transcript.layout.event_ordinal_col]
                    [row].c0) != ordinal) {
            continue;
        }
        if (!gf::IsZero(
                transcript.columns[
                    transcript.layout.event_start_col][row])) {
            start = row;
            found_start = true;
        }
        if (!gf::IsZero(
                transcript.columns[
                    transcript.layout.terminal_col][row])) {
            terminal = row;
            found_terminal = true;
        }
    }
    return found_start && found_terminal && start <= terminal;
}

void CountOwner(InventoryV1& out, ConsumerExportV1& consumer)
{
    if (consumer.verifier_owned) {
        ++out.verifier_owned_consumer_events;
        if (consumer.owner == ConsumerOwnerV1::FoldBusBeta) {
            ++out.verifier_owned_fold_events;
        } else if (consumer.owner ==
                   ConsumerOwnerV1::HashOpeningQueryIndex) {
            ++out.verifier_owned_query_events;
        } else if (
            consumer.owner ==
                ConsumerOwnerV1::NormalizedDeepCodecInput) {
            ++out.verifier_owned_deep_fs_events;
        }
    } else {
        ++out.missing_fiat_shamir_consumer_events;
    }
}

} // namespace

bool BuildNormalizedV10ExportInventoryV1(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const p2bind::BindingResult& binding,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1&
        decoder,
    const fp::NormalizedAlgAirCodecCtlAttachmentV1*
        codec_ctl,
    const fp::FoldBusComposition* composition,
    const fp::NormalizedAlgAirRemoteExportAttachmentV1*
        remote_exports,
    const ProofOwnedPrefixSourceRefsV1* prefix_sources,
    InventoryV1& out,
    std::string* why)
{
    out = {};
    if (proof.version !=
            kRCFri3AlgP2Q192K2ProofVersionV10 ||
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            binding, proof, fs_seed, why)) {
        return false;
    }
    out.canonical_v10_binding = true;

    fp::NormalizedAlgAirBatchCodecMapV1 exact_map;
    if (!fp::BuildNormalizedAlgAirBatchCodecMapV1(
            proof, exact_map, why) ||
        !SameCodecMap(exact_map, decoder.map) ||
        !decoder.valid ||
        decoder.parent_rows == 0 ||
        decoder.map.codec_bytes % 4 != 0) {
        return Fail(why, "v10_decoder_map_not_exact");
    }
    out.codec_map_exact = true;
    out.decoder_bytes_range_owned =
        decoder.every_word_decomposed &&
        decoder.every_byte_range_checked &&
        decoder.exact_length_constrained &&
        decoder.no_unconsumed_codec_bytes &&
        composition != nullptr &&
        DecoderCellsExact(*composition, decoder);
    out.decoder_little_endian_owned =
        decoder.little_endian_recomposition_constrained &&
        decoder.final_word_padding_zero;
    out.decoder_goldilocks_canonical =
        decoder.every_fp_encoding_canonical;
    if (!out.decoder_bytes_range_owned ||
        !out.decoder_little_endian_owned ||
        !out.decoder_goldilocks_canonical) {
        return Fail(
            why, "v10_decoder_cells_not_owned");
    }

    std::vector<unsigned char> encoded;
    if (SerializeFri3AlgBatchProof(proof, encoded) == 0 ||
        encoded != binding.canonical_proof_bytes) {
        return Fail(why, "v10_codec_binding");
    }
    if (prefix_sources != nullptr &&
        (composition == nullptr ||
         prefix_sources->fs_seed.byte.size() != 32 ||
         prefix_sources->shape_commit.byte.size() != 32 ||
         prefix_sources->ood_eval_commit.byte.size() != 32 ||
         !prefix_sources->
             seed_from_canonical_receipt_statement ||
         !prefix_sources->
             seed_bound_before_first_commitment ||
         !prefix_sources->shape_commit_derived_by_p2_air ||
         !prefix_sources->ood_eval_commit_derived_by_p2_air ||
         !prefix_sources->source_cells_canonical ||
         prefix_sources->complete_child_verifier_same_parent ||
         prefix_sources->recursively_consumed)) {
        return Fail(why, "v10_prefix_sources_not_local_owned");
    }
    CodecOffsetsV10 offsets;
    if (!BuildCodecOffsetsV10(
            proof, encoded.size(), offsets) ||
        !BuildPrefixSchedule(
            proof, binding, decoder, *composition,
            prefix_sources, offsets, out)) {
        return Fail(why, "v10_prefix_offset_map");
    }
    out.row_commit_root.byte.reserve(32);
    for (uint32_t byte = 0; byte < 32; ++byte) {
        out.row_commit_root.byte.push_back(
            DecoderByteCell(
                decoder, offsets.row_root + byte));
    }
    out.fold_roots.resize(offsets.fold_roots.size());
    for (size_t root = 0;
         root < offsets.fold_roots.size(); ++root) {
        out.fold_roots[root].byte.reserve(32);
        for (uint32_t byte = 0; byte < 32; ++byte) {
            out.fold_roots[root].byte.push_back(
                DecoderByteCell(
                    decoder,
                    offsets.fold_roots[root] + byte));
        }
    }

    const bool remote_ready =
        composition != nullptr &&
        remote_exports != nullptr &&
        remote_exports->valid &&
        remote_exports->literal_same_row_aliases &&
        remote_exports->layout.End() <=
            composition->combined.n_columns &&
        remote_exports->parent_rows ==
            composition->combined.n_rows;
    const bool codec_ctl_ready =
        composition != nullptr &&
        codec_ctl != nullptr &&
        codec_ctl->valid &&
        codec_ctl->exact_semantic_addresses &&
        codec_ctl->exact_multiplicity_one &&
        codec_ctl->dual_rational_identity_terminal_zero &&
        codec_ctl->denominator_nonzero &&
        codec_ctl->decoder_values_aliased &&
        codec_ctl->parent_rows ==
            composition->combined.n_rows &&
        codec_ctl->layout.End() <=
            composition->combined.n_columns;
    out.total_consumer_events =
        static_cast<uint32_t>(
            binding.consumer_manifest.entries.size());
    out.consumers.reserve(out.total_consumer_events);
    const size_t folds = proof.fold_challenges.size();
    for (const auto& event :
         binding.consumer_manifest.entries) {
        ConsumerExportV1 consumer;
        consumer.event_ordinal = event.event_ordinal;
        consumer.kind = event.kind;
        consumer.semantic_index = event.semantic_index;
        if (event.event_ordinal < 5) {
            const uint32_t direct_offsets[5] = {
                offsets.lambda, offsets.z1, offsets.z2,
                offsets.w1, offsets.w2};
            consumer.owner =
                ConsumerOwnerV1::NormalizedDeepCodecInput;
            consumer.codec_word =
                direct_offsets[event.event_ordinal] / 4;
            const auto* token = FindTokenByWord(
                decoder.map, consumer.codec_word,
                fp::NormalizedAlgAirCodecTokenKind::Fp3);
            if (token == nullptr ||
                !gf::Eq(token->value, event.fp3_value)) {
                return Fail(
                    why, "deep_fs_consumer_semantic_token");
            }
            consumer.semantic_address = token->address;
            consumer.verifier_owned =
                codec_ctl_ready &&
                FindCodecCtlProducerCell(
                    *composition, *codec_ctl, *token,
                    consumer.parent_cell);
            CountOwner(out, consumer);
            out.consumers.push_back(consumer);
            continue;
        }
        uint32_t codec_offset = 0;
        fp::NormalizedAlgAirCodecTokenKind token_kind =
            fp::NormalizedAlgAirCodecTokenKind::Fp3;
        gf::Fp3 expected = event.fp3_value;
        if (event.event_ordinal < 5 + folds) {
            const size_t fold = event.event_ordinal - 5;
            consumer.owner = ConsumerOwnerV1::FoldBusBeta;
            codec_offset = offsets.fold_challenges[fold];
        } else {
            const size_t query =
                event.event_ordinal - 5 - folds;
            if (query >= offsets.query_indices.size()) {
                return Fail(why, "query_consumer_offset");
            }
            consumer.owner =
                ConsumerOwnerV1::HashOpeningQueryIndex;
            codec_offset = offsets.query_indices[query];
            token_kind =
                fp::NormalizedAlgAirCodecTokenKind::U32;
            expected =
                gf::Fp3::FromFp(gf::FromU64(
                    event.index_value));
        }
        consumer.codec_word = codec_offset / 4;
        const auto* token = FindTokenByWord(
            decoder.map, consumer.codec_word,
            token_kind);
        if (token == nullptr) {
            return Fail(why, "consumer_semantic_token");
        }
        consumer.semantic_address = token->address;
        consumer.verifier_owned =
            remote_ready &&
            FindRemoteProducerCell(
                *composition, *remote_exports,
                token->address, expected,
                consumer.parent_cell);
        CountOwner(out, consumer);
        out.consumers.push_back(consumer);
    }
    out.fold_query_remote_exports_owned =
        out.verifier_owned_fold_events == folds &&
        out.verifier_owned_query_events ==
            proof.queries.size();
    out.every_prefix_byte_owned =
        out.decoder_bytes_range_owned &&
        out.missing_seed_bytes == 0 &&
        out.missing_shape_commit_bytes == 0 &&
        out.missing_ood_eval_commit_bytes == 0;
    out.every_consumer_owned =
        out.verifier_owned_consumer_events ==
            out.total_consumer_events;
    out.recursive_authority = false;
    if (out.missing_seed_bytes != 0) {
        out.residuals.push_back(
            "proof_owned_fs_seed_byte_exports_missing");
    }
    if (out.missing_shape_commit_bytes != 0) {
        out.residuals.push_back(
            "proof_owned_shape_commit_byte_exports_missing");
    }
    if (out.missing_ood_eval_commit_bytes != 0) {
        out.residuals.push_back(
            "proof_owned_ood_eval_commit_byte_exports_missing");
    }
    if (!out.fold_query_remote_exports_owned) {
        out.residuals.push_back(
            "fold_or_query_remote_consumer_cells_missing");
    }
    if (out.missing_fiat_shamir_consumer_events != 0) {
        out.residuals.push_back(
            "lambda_z_w_fiat_shamir_consumer_cells_missing");
    }
    out.residuals.push_back(
        "normalized_v10_join_not_recursively_consumed");
    out.valid =
        out.canonical_v10_binding &&
        out.codec_map_exact &&
        out.decoder_bytes_range_owned &&
        out.decoder_little_endian_owned &&
        out.decoder_goldilocks_canonical &&
        out.total_consumer_events ==
            out.consumers.size() &&
        !out.prefix_schedules.empty() &&
        !out.recursive_authority;
    out.note = out.valid
        ? (out.every_prefix_byte_owned
               ? "stage3:p2_normalized_exports:"
                 "v10_exact_all_prefix_sources_locally_owned;"
                 "recursive_child_consumption_open"
               : "stage3:p2_normalized_exports:"
                 "v10_exact_partial_ownership_inventory_ok")
        : "stage3:p2_normalized_exports:"
          "v10_ownership_inventory_invalid";
    if (!out.valid) {
        return Fail(why, "v10_inventory");
    }
    return true;
}

bool BuildOwnedSubsetJoinPlanV1(
    const InventoryV1& inventory,
    const p2air::BuildResult& transcript,
    p2join::JoinPlanV1& out,
    uint32_t& joined_prefix_words,
    uint32_t& cross_decoder_row_words,
    std::vector<std::string>& residuals,
    std::string* why)
{
    out = {};
    joined_prefix_words = 0;
    cross_decoder_row_words = 0;
    residuals.clear();
    if (!inventory.valid || !transcript.valid ||
        inventory.prefix_schedules.empty() ||
        inventory.total_consumer_events !=
            transcript.manifest.size()) {
        return Fail(why, "join_input");
    }
    for (const auto& schedule :
         inventory.prefix_schedules) {
        if (schedule.bytes.empty()) continue;
        uint32_t start = 0;
        uint32_t terminal = 0;
        if (!FindEventRows(
                transcript, schedule.first_event_ordinal,
                start, terminal)) {
            return Fail(why, "prefix_event_row");
        }
        (void)terminal;
        for (size_t offset = 0;
             offset < schedule.bytes.size(); offset += 4) {
            p2join::EndpointV1 source;
            source.kind =
                p2join::EndpointKindV1::LinearCombination;
            bool missing = false;
            bool has_owned_cell = false;
            bool crosses_decoder_rows = false;
            uint32_t first_decoder_row =
                std::numeric_limits<uint32_t>::max();
            for (size_t byte = 0;
                 byte < 4 &&
                 offset + byte < schedule.bytes.size();
                 ++byte) {
                const auto& origin =
                    schedule.bytes[offset + byte];
                const uint32_t coefficient =
                    uint32_t{1} << (8 * byte);
                if (origin.kind ==
                        PrefixByteOriginKindV1::
                            FixedProtocol) {
                    source.constant = gf::Add(
                        source.constant,
                        gf::Fp3::FromFp(gf::FromU64(
                            uint64_t{origin.fixed_value} *
                            coefficient)));
                } else if (
                    origin.kind ==
                        PrefixByteOriginKindV1::CodecDecoder ||
                    origin.kind ==
                        PrefixByteOriginKindV1::
                            ReceiptStatementSeed ||
                    origin.kind ==
                        PrefixByteOriginKindV1::
                            DerivedShapeCommit ||
                    origin.kind ==
                        PrefixByteOriginKindV1::
                            DerivedOodEvalCommit) {
                    has_owned_cell = true;
                    if (first_decoder_row ==
                            std::numeric_limits<uint32_t>::max()) {
                        first_decoder_row =
                            origin.decoder_cell.row;
                    } else if (
                        first_decoder_row !=
                            origin.decoder_cell.row) {
                        crosses_decoder_rows = true;
                    }
                    source.linear_terms.push_back({
                        origin.decoder_cell,
                        coefficient});
                } else {
                    missing = true;
                    break;
                }
            }
            if (missing || !has_owned_cell) continue;
            p2join::EndpointV1 sink;
            sink.kind = p2join::EndpointKindV1::Cell;
            sink.cell = {
                transcript.layout.MessageCol(
                    0, (3 + offset / 4) %
                        ah::kAlgHashRate),
                static_cast<uint32_t>(
                    start + (3 + offset / 4) /
                        ah::kAlgHashRate)};
            sink.row = sink.cell.row;
            source.row = sink.row;
            if (crosses_decoder_rows) {
                ++cross_decoder_row_words;
            }
            out.equalities.push_back({
                p2join::EqualityRoleV1::FriProofSource,
                schedule.schedule,
                static_cast<uint32_t>(offset / 4),
                std::move(source), std::move(sink)});
            ++out.fri_source_equalities;
            ++joined_prefix_words;
        }
    }
    for (const auto& consumer : inventory.consumers) {
        if (!consumer.verifier_owned) continue;
        uint32_t start = 0;
        uint32_t terminal = 0;
        if (!FindEventRows(
                transcript, consumer.event_ordinal,
                start, terminal)) {
            return Fail(why, "consumer_event_row");
        }
        (void)start;
        p2join::EndpointV1 source;
        source.row = terminal;
        if (consumer.kind == p2air::EventKind::Query) {
            source.kind = p2join::EndpointKindV1::Cell;
            source.cell = {
                transcript.layout.query_index_col,
                terminal};
        } else if (
            consumer.kind == p2air::EventKind::OodZ1 ||
            consumer.kind == p2air::EventKind::OodZ2) {
            source.kind =
                p2join::EndpointKindV1::Fp3Coordinates;
            const uint32_t slot =
                consumer.kind == p2air::EventKind::OodZ1
                ? 0 : 1;
            for (uint32_t coord = 0; coord < 3; ++coord) {
                source.fp3_coordinates.coord[coord] = {
                    transcript.layout.SelectedCol(
                        slot, coord),
                    terminal};
            }
        } else {
            source.kind =
                p2join::EndpointKindV1::PoseidonOutputFp3;
            source.poseidon =
                transcript.layout.candidate[0];
        }
        p2join::EndpointV1 sink;
        sink.kind = p2join::EndpointKindV1::Cell;
        sink.cell = consumer.parent_cell;
        sink.row = consumer.parent_cell.row;
        out.equalities.push_back({
            p2join::EqualityRoleV1::
                FriVerifierConsumer,
            consumer.event_ordinal, 0,
            std::move(source), std::move(sink)});
        ++out.fri_consumer_equalities;
    }
    const uint32_t total_words =
        static_cast<uint32_t>(
            std::accumulate(
                inventory.prefix_schedules.begin(),
                inventory.prefix_schedules.end(),
                uint64_t{0},
                [](uint64_t sum, const auto& schedule) {
                    return sum +
                        (schedule.bytes.size() + 3) / 4;
                }));
    if (joined_prefix_words != total_words) {
        residuals.push_back(
            "seed_or_derived_digest_prefix_words_unjoined=" +
            std::to_string(
                total_words - joined_prefix_words));
    }
    if (out.fri_consumer_equalities !=
            inventory.total_consumer_events) {
        residuals.push_back(
            "fiat_shamir_consumer_events_unjoined=" +
            std::to_string(
                inventory.total_consumer_events -
                out.fri_consumer_equalities));
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_p2_normalized_exports
