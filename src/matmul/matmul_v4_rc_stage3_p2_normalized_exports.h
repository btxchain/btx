// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_NORMALIZED_EXPORTS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_NORMALIZED_EXPORTS_H

#include <matmul/matmul_v4_rc_stage3_p2_same_parent_join.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// V10 proof-source/consumer exports from the normalized FoldBus parent.
//
// The existing normalized codec decoder owns the canonical batch-proof bytes:
// every byte is decomposed into eight boolean bits, every LE32 word is
// recomposed, and every Goldilocks element is canonical. This module exposes
// those existing cells to the V10 P2 transcript join without copying host
// values.
//
// The V10 FS prefix is not the batch codec. Its 30-byte domain misaligns every
// subsequent u32 field. `PrefixByteExportV1` therefore records origins at byte
// granularity. Seed bytes and the derived ShapeCommit/OodEvalCommit digests
// remain absent until their owning parent chips exist.
//
// Existing FoldBus remote exports own fold-beta and query-index consumers.
// The normalized DEEP codec CTL owns the lambda/z/w consumer cells.  The
// resulting aliases constrain all consumer events, but they are not recursive
// authority until the normalized parent verifies and consumes the complete
// child receipt.
// ============================================================================

namespace matmul::v4::rc::stage3_p2_normalized_exports {

namespace fp = recursive_fixedpoint;
namespace p2join = stage3_p2_same_parent_join;
namespace p2bind = stage3_p2_transcript_binding;
namespace p2air = stage3_p2_transcript_air;
namespace gf = gkr_field;

enum class PrefixByteOriginKindV1 : uint8_t {
    FixedProtocol = 1,
    CodecDecoder = 2,
    MissingSeed = 3,
    MissingShapeCommit = 4,
    MissingOodEvalCommit = 5,
    ReceiptStatementSeed = 6,
    DerivedShapeCommit = 7,
    DerivedOodEvalCommit = 8,
};

struct PrefixByteExportV1 {
    PrefixByteOriginKindV1 kind{
        PrefixByteOriginKindV1::FixedProtocol};
    uint32_t schedule{0};
    uint32_t prefix_offset{0};
    uint8_t fixed_value{0};
    uint32_t codec_offset{0};
    p2join::CellRefV1 decoder_cell{};
};

struct PrefixScheduleExportsV1 {
    uint32_t schedule{0};
    p2bind::PrefixSourceKind source_kind{
        p2bind::PrefixSourceKind::MissingAirqTranscript};
    uint32_t first_event_ordinal{0};
    std::vector<PrefixByteExportV1> bytes;
};

/**
 * Exact byte cells exported by proof-producing chips already resident in the
 * normalized parent.  The seed must be decomposed from the canonical
 * receipt/public-statement cells that were present before the parent's first
 * commitment.  ShapeCommit and OodEvalCommit must be outputs of an in-parent
 * Poseidon2 derivation over proof-owned codec fields.
 *
 * These predicates describe locally executable ownership only.  They cannot
 * make recursive authority true: the complete child verifier must still
 * consume the receipt that owns the seed and codec fields.
 */
struct ProofOwnedPrefixSourceRefsV1 {
    p2join::BytesCellRefsV1 fs_seed;
    p2join::BytesCellRefsV1 shape_commit;
    p2join::BytesCellRefsV1 ood_eval_commit;
    bool seed_from_canonical_receipt_statement{false};
    bool seed_bound_before_first_commitment{false};
    bool shape_commit_derived_by_p2_air{false};
    bool ood_eval_commit_derived_by_p2_air{false};
    bool source_cells_canonical{false};
    bool complete_child_verifier_same_parent{false};
    bool recursively_consumed{false};
};

enum class ConsumerOwnerV1 : uint8_t {
    MissingFiatShamir = 1,
    FoldBusBeta = 2,
    HashOpeningQueryIndex = 3,
    NormalizedDeepCodecInput = 4,
};

struct ConsumerExportV1 {
    uint32_t event_ordinal{0};
    p2air::EventKind kind{
        p2air::EventKind::FriLambda};
    uint32_t semantic_index{0};
    ConsumerOwnerV1 owner{
        ConsumerOwnerV1::MissingFiatShamir};
    uint32_t codec_word{0};
    uint32_t semantic_address{0};
    p2join::CellRefV1 parent_cell{};
    bool verifier_owned{false};
};

struct InventoryV1 {
    std::vector<PrefixScheduleExportsV1> prefix_schedules;
    std::vector<ConsumerExportV1> consumers;

    // Named aliases into the canonical decoder. These are existing proof
    // cells, not copied witness values.
    p2join::BytesCellRefsV1 row_commit_root;
    std::vector<p2join::BytesCellRefsV1> fold_roots;

    uint32_t total_distinct_prefix_bytes{0};
    uint32_t fixed_protocol_bytes{0};
    uint32_t codec_decoder_owned_bytes{0};
    uint32_t missing_seed_bytes{0};
    uint32_t missing_shape_commit_bytes{0};
    uint32_t missing_ood_eval_commit_bytes{0};

    uint32_t total_consumer_events{0};
    uint32_t verifier_owned_consumer_events{0};
    uint32_t verifier_owned_fold_events{0};
    uint32_t verifier_owned_query_events{0};
    uint32_t verifier_owned_deep_fs_events{0};
    uint32_t missing_fiat_shamir_consumer_events{0};

    bool canonical_v10_binding{false};
    bool codec_map_exact{false};
    bool decoder_bytes_range_owned{false};
    bool decoder_little_endian_owned{false};
    bool decoder_goldilocks_canonical{false};
    bool fold_query_remote_exports_owned{false};
    bool every_prefix_byte_owned{false};
    bool every_consumer_owned{false};
    bool recursive_authority{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Inventory all exact V10 prefix-byte origins and all consumer owners.
 *
 * `proof` must be the exact proof used to build `binding` and `decoder`.
 * `composition` is mandatory because byte ownership is a claim about literal
 * decoder cells, not merely a host-side codec map. Passing null
 * `remote_exports` still returns the complete byte inventory, but fold/query
 * consumers remain unowned. Passing null `prefix_sources` leaves the seed and
 * two derived digest families as exact residuals.
 */
[[nodiscard]] bool BuildNormalizedV10ExportInventoryV1(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    const p2bind::BindingResult& binding,
    const fp::NormalizedAlgAirCodecDecoderAttachmentV1& decoder,
    const fp::NormalizedAlgAirCodecCtlAttachmentV1* codec_ctl,
    const fp::FoldBusComposition* composition,
    const fp::NormalizedAlgAirRemoteExportAttachmentV1* remote_exports,
    const ProofOwnedPrefixSourceRefsV1* prefix_sources,
    InventoryV1& out,
    std::string* why = nullptr);

/**
 * Construct the maximal same-parent join supported by the inventory.
 *
 * Complete fixed/decoder-owned prefix words are joined. Fold betas and query
 * indices are joined to literal remote verifier cells; lambda/z/w events are
 * joined to the normalized DEEP codec CTL. Seed/derived-digest words remain
 * exact residual counts.
 *
 * `cross_decoder_row_words` reports how many packed words required the
 * carry-safe cross-row transport gadget. Those words are closed equalities,
 * not residuals.
 */
[[nodiscard]] bool BuildOwnedSubsetJoinPlanV1(
    const InventoryV1& inventory,
    const p2air::BuildResult& transcript,
    p2join::JoinPlanV1& out,
    uint32_t& joined_prefix_words,
    uint32_t& cross_decoder_row_words,
    std::vector<std::string>& residuals,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::stage3_p2_normalized_exports

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_NORMALIZED_EXPORTS_H
