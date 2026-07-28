// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_CAPTURE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_CAPTURE_H

#include <matmul/matmul_v4_rc_coupled.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class CBlockHeader;

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3CoupledWinnerCaptureVersionV1 = 1;

/**
 * One exact page occurrence in the immutable full-bank schedule.
 *
 * The roots commit the borrowed A/B/Y cells and the cumulative partial sum
 * before and after this page.  They are proof inputs, not an authority claim:
 * the recursive GEMM child still has to prove
 *
 *     Y = A * B                 and
 *     accumulation_after = accumulation_before + Y.
 */
struct RCStage3CoupledPageCaptureV1 {
    uint32_t barrier{0};
    uint32_t lobe{0};
    uint32_t page_ordinal{0};
    uint32_t page_id{0};
    uint256 operand_a_root{};
    uint256 operand_b_root{};
    uint256 gemm_y_root{};
    uint256 accumulation_before_root{};
    uint256 accumulation_after_root{};
    uint256 event_commitment{};

    bool operator==(const RCStage3CoupledPageCaptureV1&) const =
        default;
};

/** One complete, ordered multi-page accumulation for (barrier,lobe). */
struct RCStage3CoupledLobeCaptureV1 {
    uint32_t barrier{0};
    uint32_t lobe{0};
    uint256 input_state_lobe_root{};
    std::vector<RCStage3CoupledPageCaptureV1> pages;
    uint256 final_accumulation_root{};
    uint256 lobe_commitment{};

    bool operator==(const RCStage3CoupledLobeCaptureV1&) const =
        default;
};

struct RCStage3CoupledExchangeCaptureV1 {
    uint32_t round{0};
    uint256 input_root{};
    uint256 output_root{};

    bool operator==(const RCStage3CoupledExchangeCaptureV1&) const =
        default;
};

/**
 * Exact stage boundary inventory for one barrier.
 *
 * Equal roots on adjacent endpoints are checked while the borrowed views are
 * live and checked again from the receipt.  The next barrier's lobe roots are
 * derived directly from this barrier's Extract output.
 */
struct RCStage3CoupledBarrierCaptureV1 {
    uint32_t barrier{0};
    std::vector<uint256> input_state_lobe_roots;
    std::vector<RCStage3CoupledLobeCaptureV1> lobes;
    uint256 gemm_accumulation_root{};
    uint256 permutation_input_root{};
    uint256 permutation_output_root{};
    uint256 mix_input_root{};
    uint256 mix_output_root{};
    std::vector<RCStage3CoupledExchangeCaptureV1>
        material_exchange;
    uint256 extract_prf{};
    uint256 extract_input_root{};
    uint256 extract_output_root{};
    std::vector<uint256> extract_output_lobe_roots;
    uint256 barrier_root{};
    uint256 stage_adjacency_commitment{};

    bool operator==(const RCStage3CoupledBarrierCaptureV1&) const =
        default;
};

/**
 * Bounded winner-only capture artifact.
 *
 * At production V3 shape it retains 1536 page records and eight barrier
 * records, plus one M*W int64 accumulation scratch while callbacks execute.
 * It never retains a bank page, a full state, or the ~50M flat dot-product
 * proofs.  All roots are keyed to the finalized header.
 *
 * `capture_complete` means the exact callback schedule and every in-memory
 * stage adjacency were observed.  `recursive_relation_proofs_bound` remains
 * false until the normalized builder attaches the corresponding proof-owned
 * GEMM/bank/permutation/mix/extract/hash child receipts.
 */
struct RCStage3CoupledWinnerReceiptV1 {
    uint16_t version{
        kRCStage3CoupledWinnerCaptureVersionV1};
    uint256 finalized_header_hash{};
    uint256 sigma{};
    int32_t height{-1};
    RCCoupParams params{};
    uint32_t transcript_version{0};
    bool full_bank_schedule{false};
    bool material_exchange{false};
    uint32_t exchange_rows{0};
    uint32_t exchange_rounds{0};
    bool force_signed_mix{false};
    uint256 context_commitment{};
    uint256 initial_state_root{};
    std::vector<uint256> initial_state_lobe_roots;
    std::vector<RCStage3CoupledBarrierCaptureV1> barriers;
    uint256 scheduled_bank_pages_commitment{};
    uint256 bank_root{};
    std::vector<uint256> barrier_roots;
    uint256 coupled_digest{};
    uint64_t gemm_callbacks{0};
    uint64_t captured_payload_bytes{0};
    uint64_t retained_receipt_bytes_upper_bound{0};
    uint64_t peak_accumulation_scratch_bytes{0};
    bool capture_complete{false};
    bool no_bank_pages_retained{true};
    bool no_flat_tile_proofs_materialized{true};
    bool recursive_relation_proofs_bound{false};
    uint256 receipt_commitment{};
};

[[nodiscard]] uint256
CommitRCStage3CoupledWinnerContextV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options);

[[nodiscard]] uint256
CommitRCStage3CoupledWinnerReceiptV1(
    const RCStage3CoupledWinnerReceiptV1& receipt);

[[nodiscard]] uint256
CommitRCStage3CoupledPageCaptureV1(
    const RCStage3CoupledPageCaptureV1& page);
[[nodiscard]] uint256
CommitRCStage3CoupledLobeCaptureV1(
    const RCStage3CoupledLobeCaptureV1& lobe);
[[nodiscard]] uint256
CommitRCStage3CoupledBarrierCaptureV1(
    const RCStage3CoupledBarrierCaptureV1& barrier);

/**
 * Public structural verifier for a completed capture.
 *
 * This verifies the finalized-header key, complete callback inventory,
 * immutable page schedule, cross-stage equalities, bank-page consistency,
 * native barrier/digest roots, and the canonical receipt commitment.  It
 * deliberately refuses to report recursive proof closure.
 */
[[nodiscard]] bool
VerifyRCStage3CoupledWinnerReceiptV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3CoupledWinnerReceiptV1& receipt,
    std::string* why = nullptr);

/**
 * Streaming sink attached to the winner's already-required CPU reseal.
 *
 * Every callback is accepted only in the canonical oracle order.  Borrowed
 * arrays are hashed and, for one lobe at a time, accumulated synchronously.
 * The capture never invokes RecomputeCoupledPuzzleReference.
 */
class RCStage3CoupledWinnerCaptureV1 final
    : public RCCoupProofWitnessSink {
public:
    RCStage3CoupledWinnerCaptureV1(
        const CBlockHeader& finalized_header,
        int32_t height,
        const RCCoupParams& params,
        const RCCoupOptions& options);
    ~RCStage3CoupledWinnerCaptureV1() override;

    void OnInitialState(
        const RCCoupInitialStateProofWitnessView& view) override;
    void OnGemm(
        const RCCoupGemmProofWitnessView& view) override;
    void OnPermutation(
        const RCCoupPermutationProofWitnessView& view) override;
    void OnMix(
        const RCCoupMixProofWitnessView& view) override;
    void OnMaterialExchange(
        const RCCoupMaterialExchangeProofWitnessView& view) override;
    void OnBarrier(
        const RCCoupBarrierProofWitnessView& view) override;
    void OnEpisode(
        const RCCoupEpisodeProofWitnessView& view) override;

    [[nodiscard]] bool Complete(
        std::string* why = nullptr) const;
    [[nodiscard]] const RCStage3CoupledWinnerReceiptV1&
    Receipt() const
    {
        return m_receipt;
    }

private:
    class BoundaryHasher;

    void Reject(const std::string& why);
    [[nodiscard]] bool ReadyForBarrierStage(
        uint32_t barrier,
        const char* stage);
    void StartBarrier(uint32_t barrier);

    std::unique_ptr<const CBlockHeader> m_header;
    RCCoupOptions m_options{};
    RCStage3CoupledWinnerReceiptV1 m_receipt{};
    RCStage3CoupledBarrierCaptureV1 m_current_barrier{};
    std::vector<uint256> m_expected_lobe_roots;
    std::vector<uint256> m_bank_page_roots;
    std::vector<bool> m_bank_page_seen;
    std::vector<int64_t> m_lobe_accumulator;
    std::unique_ptr<BoundaryHasher> m_gemm_boundary;
    uint32_t m_next_barrier{0};
    uint32_t m_next_lobe{0};
    uint32_t m_next_page{0};
    uint32_t m_next_exchange_round{0};
    uint256 m_post_stage_root{};
    bool m_initial_seen{false};
    bool m_permutation_seen{false};
    bool m_mix_seen{false};
    bool m_episode_seen{false};
    mutable bool m_complete_checked{false};
    mutable bool m_complete_ok{false};
    mutable std::string m_complete_error;
    std::string m_error;
};

/**
 * Winner-only process-local handoff to the normalized proof producer.
 *
 * The finalized header hash is the key and the store retains at most one
 * completed capture. A stale capture therefore cannot be selected for a
 * different winner, and losing-nonce witnesses are never retained.
 */
[[nodiscard]] bool RCStage3CoupledWinnerStorePutV1(
    const uint256& finalized_header_hash,
    std::shared_ptr<const RCStage3CoupledWinnerCaptureV1> capture,
    std::string* why = nullptr);
[[nodiscard]] std::shared_ptr<
    const RCStage3CoupledWinnerCaptureV1>
RCStage3CoupledWinnerStoreGetV1(
    const uint256& finalized_header_hash);
void RCStage3CoupledWinnerStoreEraseV1(
    const uint256& finalized_header_hash);
void RCStage3CoupledWinnerStoreClearForTestV1();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_WINNER_CAPTURE_H
