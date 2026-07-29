// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SIGNED_RANGE_STREAM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SIGNED_RANGE_STREAM_H

#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::coupled_signed_range_stream {

inline constexpr uint16_t kReceiptVersionV1 = 1;
inline constexpr uint64_t kMaxRetainedNativeYBytesV1 =
    uint64_t{kRCStage3SignedRangeMaxShardRows} * sizeof(int64_t);

/**
 * One canonical interval of solver-owned GEMM Y cells.
 *
 * callback_y_root and the signed-range VALUE-column root are the same
 * commitment construction over the same padded Fp3 vector.  The equality is
 * therefore exact.  gemm_child_ctl_consumed intentionally remains false until
 * the coupled GEMM child proof exports and consumes this interval root.
 */
struct YIntervalLinkV1 {
    uint32_t shard_index{0};
    uint64_t cell_begin{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 callback_y_root{};
    uint256 range_value_root{};
    uint256 range_child_proof_commitment{};
    uint256 link_commitment{};
    bool gemm_child_ctl_consumed{false};

    bool operator==(const YIntervalLinkV1&) const = default;
};

struct ReceiptV1 {
    uint16_t version{kReceiptVersionV1};
    RCStage3CoupledSignedRangeExecution execution;
    std::vector<YIntervalLinkV1> intervals;
    uint256 gemm_schedule_commitment{};
    uint64_t observed_gemm_callbacks{0};
    uint64_t peak_retained_native_y_bytes{0};
    uint256 receipt_commitment{};
    bool every_range_child_verified{false};
    bool gemm_y_interval_ctl_consumed{false};
    bool normalized_parent_consumed{false};
    bool production_authority{false};
};

[[nodiscard]] uint256 CommitAirQuotientProofV1(
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof);
[[nodiscard]] uint256 CommitYIntervalLinkV1(
    const YIntervalLinkV1& link);
[[nodiscard]] uint256 CommitReceiptV1(const ReceiptV1& receipt);

[[nodiscard]] bool VerifyReceiptV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ReceiptV1& receipt,
    std::string* why = nullptr);

/**
 * Callback-time all-output signed-range prover.
 *
 * The class is a real RCCoupProofWitnessSink.  OnGemm accepts only the next
 * canonical (barrier,lobe,page) tuple, copies at most one fixed range shard,
 * proves it, and releases the native int64 buffer before accepting more work.
 * Complete fails on an omitted, duplicated, reordered or malformed callback.
 *
 * This closes bounded native Y residency and the range AIR itself.  It does
 * NOT claim the final GEMM-child equality CTL or normalized-parent consume;
 * both booleans remain false and therefore production_authority is false.
 */
class StreamProverV1 final : public RCCoupProofWitnessSink {
public:
    StreamProverV1(
        const RCStage3SuccinctProof& statement,
        const RCStage3CoupledShape& shape);

    void OnInitialState(
        const RCCoupInitialStateProofWitnessView&) override {}
    void OnGemm(const RCCoupGemmProofWitnessView& view) override;
    void OnPermutation(
        const RCCoupPermutationProofWitnessView&) override {}
    void OnMix(const RCCoupMixProofWitnessView&) override {}
    void OnMaterialExchange(
        const RCCoupMaterialExchangeProofWitnessView&) override {}
    void OnBarrier(const RCCoupBarrierProofWitnessView&) override {}
    void OnEpisode(const RCCoupEpisodeProofWitnessView&) override {}

    [[nodiscard]] bool Complete(std::string* why = nullptr);
    [[nodiscard]] const ReceiptV1& Receipt() const { return receipt_; }
    [[nodiscard]] uint64_t RetainedNativeYBytes() const;
    [[nodiscard]] uint64_t PeakRetainedNativeYBytes() const
    {
        return peak_retained_native_y_bytes_;
    }
    [[nodiscard]] bool Poisoned() const { return poisoned_; }
    [[nodiscard]] const std::string& Failure() const { return failure_; }

private:
    [[nodiscard]] bool AcceptGemm(
        const RCCoupGemmProofWitnessView& view);
    [[nodiscard]] bool FlushCurrentShard();
    void Poison(const std::string& detail);

    RCStage3SuccinctProof statement_;
    RCStage3CoupledShape shape_;
    RCStage3CoupledSignedRangeManifest manifest_;
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule_;
    uint256 gemm_schedule_commitment_{};
    uint64_t callback_cursor_{0};
    uint64_t cell_cursor_{0};
    uint32_t shard_cursor_{0};
    std::vector<int64_t> current_values_;
    RCStage3CoupledSignedRangeExecution execution_;
    std::vector<YIntervalLinkV1> intervals_;
    uint64_t peak_retained_native_y_bytes_{0};
    bool initialized_{false};
    bool poisoned_{false};
    bool complete_{false};
    std::string failure_;
    ReceiptV1 receipt_;
};

} // namespace matmul::v4::rc::coupled_signed_range_stream

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_SIGNED_RANGE_STREAM_H
