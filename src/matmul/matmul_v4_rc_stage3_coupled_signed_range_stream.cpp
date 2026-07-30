// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_signed_range_stream.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::coupled_signed_range_stream {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SIGNED_RANGE_AIR_PROOF_V1";
constexpr char INTERVAL_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SIGNED_RANGE_Y_INTERVAL_V1";
constexpr char RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_SIGNED_RANGE_STREAM_RECEIPT_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_signed_range_stream:" + detail;
    }
    return false;
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

void HashRoots(HashWriter& hash, const std::vector<uint256>& roots)
{
    hash << static_cast<uint64_t>(roots.size());
    for (const auto& root : roots) hash << root;
}

void HashFp3Vector(HashWriter& hash, const std::vector<Fp3>& values)
{
    hash << static_cast<uint64_t>(values.size());
    for (const auto& value : values) HashFp3(hash, value);
}

uint256 RangeValueRoot(const RCStage3SignedRangePin& pin)
{
    if (pin.column_roots.size() != kRCStage3SignedRangeColumns) return {};
    return pin.column_roots[kRCStage3RangeValue].root;
}

bool SamePin(const RCStage3SignedRangePin& a,
             const RCStage3SignedRangePin& b)
{
    if (a.statement_commitment != b.statement_commitment ||
        a.manifest_commitment != b.manifest_commitment ||
        a.layer_ordinal != b.layer_ordinal ||
        a.shard_index != b.shard_index ||
        a.shard_count != b.shard_count ||
        a.cell_begin != b.cell_begin ||
        a.logical_rows != b.logical_rows ||
        a.n_rows != b.n_rows ||
        a.max_abs != b.max_abs ||
        a.column_roots.size() != b.column_roots.size()) {
        return false;
    }
    for (uint32_t i = 0; i < a.column_roots.size(); ++i) {
        // A freshly derived canonical pin carries column identities but null
        // roots.  Those roots become proof-owned only after witness commit.
        // Compare the identities here; Verify...Execution separately requires
        // every populated root and equality to the actual FRI proof.
        if (a.column_roots[i].column != b.column_roots[i].column) {
            return false;
        }
    }
    return true;
}

} // namespace

uint256 CommitAirQuotientProofV1(
    const aq::AirQuotientProof<Fp3>& proof)
{
    // This is a canonical commitment to every field of the default Fp3
    // batched-FRI proof and every supplemental AIR opening.  It is deliberately
    // independent of object layout/padding and therefore stable across builds.
    HashWriter hash;
    hash << PROOF_DOMAIN << kReceiptVersionV1;
    const auto& batch = proof.batch;
    hash << batch.version << batch.pow_grind_nonce;
    hash << batch.blowup << batch.n_coeffs;
    hash << static_cast<uint64_t>(batch.columns.size());
    for (const auto& column : batch.columns) {
        hash << column.root << column.n_leaves;
    }
    hash << static_cast<uint64_t>(batch.column_len.size());
    for (const uint32_t value : batch.column_len) hash << value;
    HashFp3(hash, batch.lambda);
    HashFp3(hash, batch.z1);
    HashFp3(hash, batch.z2);
    HashFp3Vector(hash, batch.evals_z1);
    HashFp3Vector(hash, batch.evals_z2);
    HashFp3(hash, batch.w1);
    HashFp3(hash, batch.w2);
    hash << static_cast<uint64_t>(batch.fold_layers.size());
    for (const auto& layer : batch.fold_layers) {
        hash << layer.root << layer.n_leaves;
    }
    HashFp3(hash, batch.final_value);
    HashFp3Vector(hash, batch.fold_challenges);
    hash << static_cast<uint64_t>(batch.queries.size());
    for (const auto& query : batch.queries) {
        hash << query.index;
        hash << static_cast<uint64_t>(query.columns.size());
        for (const auto& column : query.columns) {
            HashFp3(hash, column.value);
            HashRoots(hash, column.siblings);
        }
        hash << static_cast<uint64_t>(query.steps.size());
        for (const auto& step : query.steps) {
            hash << step.even_index << step.odd_index;
            HashFp3(hash, step.even);
            HashFp3(hash, step.odd);
            HashRoots(hash, step.even_siblings);
            HashRoots(hash, step.odd_siblings);
        }
    }
    hash << static_cast<uint64_t>(proof.next_openings.size());
    for (const auto& query_openings : proof.next_openings) {
        hash << static_cast<uint64_t>(query_openings.size());
        for (const auto& opening : query_openings) {
            hash << opening.index;
            HashFp3(hash, opening.leaf);
            HashRoots(hash, opening.siblings);
        }
    }
    hash << proof.trace_commit;
    return hash.GetHash();
}

uint256 CommitYIntervalLinkV1(const YIntervalLinkV1& link)
{
    if (link.callback_y_root.IsNull() ||
        link.range_value_root.IsNull() ||
        link.range_child_proof_commitment.IsNull() ||
        link.logical_rows == 0 || link.n_rows < link.logical_rows ||
        link.gemm_child_ctl_consumed) {
        return {};
    }
    HashWriter hash;
    hash << INTERVAL_DOMAIN << kReceiptVersionV1;
    hash << link.shard_index << link.cell_begin;
    hash << link.logical_rows << link.n_rows;
    hash << link.callback_y_root << link.range_value_root;
    hash << link.range_child_proof_commitment;
    hash << link.gemm_child_ctl_consumed;
    return hash.GetHash();
}

uint256 CommitReceiptV1(const ReceiptV1& receipt)
{
    if (receipt.version != kReceiptVersionV1 ||
        receipt.execution.manifest.commitment.IsNull() ||
        receipt.execution.value_roots_commitment.IsNull() ||
        receipt.gemm_schedule_commitment.IsNull() ||
        receipt.intervals.empty() ||
        !receipt.every_range_child_verified ||
        receipt.gemm_y_interval_ctl_consumed ||
        receipt.normalized_parent_consumed ||
        receipt.production_authority) {
        return {};
    }
    HashWriter hash;
    hash << RECEIPT_DOMAIN << receipt.version;
    hash << receipt.execution.manifest.commitment;
    hash << receipt.execution.value_roots_commitment;
    hash << receipt.gemm_schedule_commitment;
    hash << receipt.observed_gemm_callbacks;
    hash << receipt.peak_retained_native_y_bytes;
    hash << static_cast<uint32_t>(receipt.intervals.size());
    for (const auto& interval : receipt.intervals) {
        const uint256 commitment = CommitYIntervalLinkV1(interval);
        if (commitment.IsNull() ||
            commitment != interval.link_commitment) {
            return {};
        }
        hash << commitment;
    }
    hash << receipt.every_range_child_verified;
    hash << receipt.gemm_y_interval_ctl_consumed;
    hash << receipt.normalized_parent_consumed;
    hash << receipt.production_authority;
    return hash.GetHash();
}

bool VerifyReceiptV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const ReceiptV1& receipt,
    std::string* why)
{
    if (receipt.version != kReceiptVersionV1 ||
        receipt.gemm_y_interval_ctl_consumed ||
        receipt.normalized_parent_consumed ||
        receipt.production_authority ||
        !receipt.every_range_child_verified) {
        return Fail(why, "flags");
    }
    std::vector<RCStage3CoupledGemmScheduleEntry> schedule;
    uint256 schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, schedule, schedule_commitment, why) ||
        receipt.gemm_schedule_commitment != schedule_commitment ||
        receipt.observed_gemm_callbacks != schedule.size()) {
        return Fail(why, "gemm_schedule");
    }
    if (receipt.peak_retained_native_y_bytes == 0 ||
        receipt.peak_retained_native_y_bytes >
            kMaxRetainedNativeYBytesV1) {
        return Fail(why, "native_y_budget");
    }
    std::string execution_why;
    if (!VerifyRCStage3CoupledSignedRangeExecution(
            statement, shape, receipt.execution, &execution_why)) {
        return Fail(why, "range_execution:" + execution_why);
    }
    if (receipt.intervals.size() !=
            receipt.execution.shards.size()) {
        return Fail(why, "interval_count");
    }
    for (uint32_t i = 0; i < receipt.intervals.size(); ++i) {
        RCStage3SignedRangePin expected;
        if (!MakeRCStage3CoupledSignedRangePin(
                receipt.execution.manifest, i, expected, why)) {
            return false;
        }
        const auto& shard = receipt.execution.shards[i];
        const auto& link = receipt.intervals[i];
        const uint256 proof_commitment =
            CommitAirQuotientProofV1(shard.proof);
        if (!SamePin(shard.pin, expected) ||
            link.shard_index != i ||
            link.cell_begin != expected.cell_begin ||
            link.logical_rows != expected.logical_rows ||
            link.n_rows != expected.n_rows ||
            link.gemm_child_ctl_consumed ||
            link.callback_y_root.IsNull() ||
            link.callback_y_root != RangeValueRoot(shard.pin) ||
            link.range_value_root != RangeValueRoot(shard.pin) ||
            link.range_child_proof_commitment != proof_commitment ||
            proof_commitment.IsNull() ||
            link.link_commitment != CommitYIntervalLinkV1(link)) {
            return Fail(why, "interval_binding");
        }
    }
    const uint256 commitment = CommitReceiptV1(receipt);
    if (commitment.IsNull() ||
        commitment != receipt.receipt_commitment) {
        return Fail(why, "receipt_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_signed_range_stream:range_children_verified;"
            "gemm_y_interval_ctl_pending;normalized_parent_pending";
    }
    return true;
}

StreamProverV1::StreamProverV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape)
    : statement_(statement), shape_(shape)
{
    std::string why;
    if (!BuildRCStage3CoupledSignedRangeManifest(
            statement_, shape_, manifest_, &why) ||
        !BuildRCStage3CoupledGemmSchedule(
            statement_, shape_, schedule_,
            gemm_schedule_commitment_, &why) ||
        manifest_.scheduled_gemms != schedule_.size()) {
        Poison("initialize:" + why);
        return;
    }
    execution_.manifest = manifest_;
    execution_.shards.reserve(manifest_.shard_count);
    intervals_.reserve(manifest_.shard_count);
    RCStage3SignedRangePin first;
    if (!MakeRCStage3CoupledSignedRangePin(
            manifest_, 0, first, &why)) {
        Poison("initialize_pin:" + why);
        return;
    }
    current_values_.reserve(first.logical_rows);
    initialized_ = true;
}

void StreamProverV1::Poison(const std::string& detail)
{
    if (!poisoned_) failure_ = detail;
    poisoned_ = true;
}

uint64_t StreamProverV1::RetainedNativeYBytes() const
{
    return static_cast<uint64_t>(current_values_.size()) *
           sizeof(int64_t);
}

void StreamProverV1::OnGemm(
    const RCCoupGemmProofWitnessView& view)
{
    if (!AcceptGemm(view) && !poisoned_) {
        Poison("gemm_rejected");
    }
}

bool StreamProverV1::AcceptGemm(
    const RCCoupGemmProofWitnessView& view)
{
    if (!initialized_ || poisoned_ || complete_ ||
        callback_cursor_ >= schedule_.size()) {
        Poison("callback_state");
        return false;
    }
    const auto& expected = schedule_[callback_cursor_];
    if (view.barrier != expected.barrier ||
        view.lobe != expected.lobe ||
        view.page_id != expected.page_id ||
        view.rows != shape_.rows_per_lobe ||
        view.width != shape_.lobe_width ||
        view.gemm_y == nullptr) {
        Poison("callback_schedule");
        return false;
    }
    const uint64_t cells =
        static_cast<uint64_t>(view.rows) * view.width;
    if (view.rows != 0 &&
        cells / view.rows != view.width) {
        Poison("callback_overflow");
        return false;
    }
    uint64_t consumed = 0;
    while (consumed < cells) {
        if (shard_cursor_ >= manifest_.shard_count) {
            Poison("callback_excess_cells");
            return false;
        }
        RCStage3SignedRangePin pin;
        std::string why;
        if (!MakeRCStage3CoupledSignedRangePin(
                manifest_, shard_cursor_, pin, &why)) {
            Poison("callback_pin:" + why);
            return false;
        }
        if (current_values_.size() > pin.logical_rows) {
            Poison("callback_shard_overfull");
            return false;
        }
        const uint64_t available =
            pin.logical_rows - current_values_.size();
        const uint64_t take =
            std::min<uint64_t>(available, cells - consumed);
        current_values_.insert(
            current_values_.end(),
            view.gemm_y + consumed,
            view.gemm_y + consumed + take);
        consumed += take;
        cell_cursor_ += take;
        peak_retained_native_y_bytes_ =
            std::max(
                peak_retained_native_y_bytes_,
                RetainedNativeYBytes());
        if (current_values_.size() == pin.logical_rows &&
            !FlushCurrentShard()) {
            return false;
        }
    }
    ++callback_cursor_;
    return true;
}

bool StreamProverV1::FlushCurrentShard()
{
    RCStage3SignedRangePin pin;
    std::string why;
    if (!MakeRCStage3CoupledSignedRangePin(
            manifest_, shard_cursor_, pin, &why) ||
        current_values_.size() != pin.logical_rows) {
        Poison("flush_pin:" + why);
        return false;
    }
    std::vector<std::vector<Fp3>> columns;
    if (!BuildRCStage3SignedRangeColumns(
            pin, current_values_, columns, &why) ||
        columns.size() != kRCStage3SignedRangeColumns) {
        Poison("flush_columns:" + why);
        return false;
    }
    for (uint32_t i = 0; i < columns.size(); ++i) {
        pin.column_roots[i].column = i;
        pin.column_roots[i].root =
            aq::AirCommittedValuesRoot<Fp3>(
                columns[i], pin.n_rows);
        if (pin.column_roots[i].root.IsNull()) {
            Poison("flush_column_root");
            return false;
        }
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!ResolveRCStage3SignedRangeKernelConstraintSystem(
            pin, cs, &why)) {
        Poison("flush_cs:" + why);
        return false;
    }
    const auto proved = aq::AirQuotientProve<Fp3>(
        cs, columns, ComputeRCStage3SignedRangeSeed(pin));
    if (!proved.ok || !proved.division_exact) {
        Poison("flush_prove:" + proved.note);
        return false;
    }
    RCStage3CoupledSignedRangeShardProof shard;
    shard.pin = std::move(pin);
    shard.proof = proved.proof;
    const uint256 proof_commitment =
        CommitAirQuotientProofV1(shard.proof);
    const uint256 value_root = RangeValueRoot(shard.pin);
    if (proof_commitment.IsNull() || value_root.IsNull()) {
        Poison("flush_proof_commitment");
        return false;
    }
    YIntervalLinkV1 interval;
    interval.shard_index = shard_cursor_;
    interval.cell_begin = shard.pin.cell_begin;
    interval.logical_rows = shard.pin.logical_rows;
    interval.n_rows = shard.pin.n_rows;
    interval.callback_y_root = value_root;
    interval.range_value_root = value_root;
    interval.range_child_proof_commitment = proof_commitment;
    interval.link_commitment =
        CommitYIntervalLinkV1(interval);
    if (interval.link_commitment.IsNull()) {
        Poison("flush_interval");
        return false;
    }
    execution_.shards.push_back(std::move(shard));
    intervals_.push_back(std::move(interval));
    ++shard_cursor_;
    std::vector<int64_t>().swap(current_values_);
    if (shard_cursor_ < manifest_.shard_count) {
        RCStage3SignedRangePin next;
        if (!MakeRCStage3CoupledSignedRangePin(
                manifest_, shard_cursor_, next, &why)) {
            Poison("flush_next_pin:" + why);
            return false;
        }
        current_values_.reserve(next.logical_rows);
    }
    return true;
}

bool StreamProverV1::Complete(std::string* why)
{
    if (complete_) {
        if (why != nullptr) {
            *why = poisoned_ ? failure_ : "complete";
        }
        return !poisoned_;
    }
    if (!initialized_ || poisoned_) {
        return Fail(why, failure_.empty() ? "not_initialized" : failure_);
    }
    if (callback_cursor_ != schedule_.size() ||
        cell_cursor_ != manifest_.total_output_cells ||
        shard_cursor_ != manifest_.shard_count ||
        !current_values_.empty() ||
        execution_.shards.size() != manifest_.shard_count ||
        intervals_.size() != manifest_.shard_count) {
        Poison("incomplete_schedule");
        return Fail(why, failure_);
    }
    execution_.value_roots_commitment =
        CommitRCStage3CoupledSignedRangeValueRoots(
            execution_.manifest, execution_.shards);
    if (execution_.value_roots_commitment.IsNull()) {
        Poison("value_roots_commitment");
        return Fail(why, failure_);
    }
    receipt_ = {};
    receipt_.execution = std::move(execution_);
    receipt_.intervals = std::move(intervals_);
    receipt_.gemm_schedule_commitment =
        gemm_schedule_commitment_;
    receipt_.observed_gemm_callbacks = callback_cursor_;
    receipt_.peak_retained_native_y_bytes =
        peak_retained_native_y_bytes_;
    receipt_.every_range_child_verified = true;
    receipt_.receipt_commitment =
        CommitReceiptV1(receipt_);
    if (receipt_.receipt_commitment.IsNull()) {
        Poison("receipt_commitment");
        return Fail(why, failure_);
    }
    std::string verify_why;
    if (!VerifyReceiptV1(
            statement_, shape_, receipt_, &verify_why)) {
        Poison("self_verify:" + verify_why);
        return Fail(why, failure_);
    }
    complete_ = true;
    if (why != nullptr) *why = verify_why;
    return true;
}

} // namespace matmul::v4::rc::coupled_signed_range_stream
