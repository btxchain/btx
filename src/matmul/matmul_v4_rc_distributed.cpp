// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_distributed.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>

#include <cassert>
#include <future>
#include <cstring>
#include <memory>
#include <utility>

namespace matmul::v4::rc {
namespace {

uint256 Sha256dBytes(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    uint256 out;
    std::memcpy(out.data(), d2, 32);
    return out;
}

uint256 DeriveTagged(const uint256& seed, const char* tag)
{
    std::vector<unsigned char> buf;
    const size_t tag_len = std::strlen(tag);
    buf.reserve(tag_len + 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tag),
               reinterpret_cast<const unsigned char*>(tag) + tag_len);
    buf.insert(buf.end(), seed.begin(), seed.end());
    return Sha256dBytes(buf.data(), buf.size());
}

void AppendLE32(std::vector<unsigned char>& buf, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    buf.insert(buf.end(), b, b + 4);
}

void AppendInt64LE(std::vector<unsigned char>& buf, int64_t v)
{
    unsigned char b[8];
    WriteLE64(b, static_cast<uint64_t>(v));
    buf.insert(buf.end(), b, b + 8);
}

void AddInPlace(std::vector<int64_t>& acc, const std::vector<int64_t>& add)
{
    assert(acc.size() == add.size());
    for (size_t i = 0; i < acc.size(); ++i) {
        acc[i] += add[i];
    }
}

std::vector<int64_t> AddMats(const std::vector<int64_t>& a, const std::vector<int64_t>& b)
{
    assert(a.size() == b.size());
    std::vector<int64_t> out = a;
    AddInPlace(out, b);
    return out;
}

} // namespace

std::vector<RCRowRange> CanonicalRCRowRanges(
    uint32_t rows, uint32_t shard_count, uint32_t alignment)
{
    if (rows == 0 || shard_count == 0 || alignment == 0 ||
        rows % alignment != 0 || shard_count > rows / alignment) {
        return {};
    }
    const uint32_t units{rows / alignment};
    const uint32_t base{units / shard_count};
    const uint32_t extra{units % shard_count};
    std::vector<RCRowRange> ranges;
    ranges.reserve(shard_count);
    uint32_t begin{0};
    for (uint32_t shard = 0; shard < shard_count; ++shard) {
        const uint32_t count_units{base + (shard < extra ? 1u : 0u)};
        const uint32_t count{count_units * alignment};
        ranges.push_back({begin, count});
        begin += count;
    }
    assert(begin == rows);
    return ranges;
}

uint256 CommitRCFfnRowShardRequest(const RCFfnRowShardRequest& request)
{
    static constexpr char tag[] = "BTX_RC_FFN_ROW_SHARD_REQ_V1";
    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), tag, tag + sizeof(tag) - 1);
    bytes.insert(
        bytes.end(), request.episode_id.begin(), request.episode_id.end());
    AppendLE32(bytes, request.round_ordinal);
    AppendLE32(bytes, request.layer_ordinal);
    AppendLE32(bytes, request.rows.begin);
    AppendLE32(bytes, request.rows.count);
    AppendLE32(bytes, request.d_model);
    AppendLE32(bytes, request.d_ff);
    bytes.insert(bytes.end(), request.prf_up.begin(), request.prf_up.end());
    bytes.insert(bytes.end(), request.prf_down.begin(), request.prf_down.end());
    const auto append_vec = [&](const std::shared_ptr<const std::vector<int8_t>>& values) {
        AppendLE32(bytes, values ? values->size() : 0);
        if (values) {
            bytes.insert(
                bytes.end(),
                reinterpret_cast<const unsigned char*>(values->data()),
                reinterpret_cast<const unsigned char*>(values->data()) +
                    values->size());
        }
    };
    append_vec(request.x_rows);
    append_vec(request.w_up);
    append_vec(request.w_down);
    return Sha256dBytes(bytes.data(), bytes.size());
}

uint256 CommitRCFfnRowShardOutput(
    const RCFfnRowShardRequest& request,
    const std::vector<int8_t>& output_rows)
{
    static constexpr char tag[] = "BTX_RC_FFN_ROW_SHARD_OUT_V1";
    const uint256 request_commitment{CommitRCFfnRowShardRequest(request)};
    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), tag, tag + sizeof(tag) - 1);
    bytes.insert(
        bytes.end(), request_commitment.begin(), request_commitment.end());
    bytes.insert(
        bytes.end(),
        reinterpret_cast<const unsigned char*>(output_rows.data()),
        reinterpret_cast<const unsigned char*>(output_rows.data()) +
            output_rows.size());
    return Sha256dBytes(bytes.data(), bytes.size());
}

RCFfnRowShardResponse ExecuteRCFfnRowShardLocal(
    const RCFfnRowShardRequest& request,
    const matmul::v4::lt::ExactGemmBackend& backend)
{
    RCFfnRowShardResponse response;
    response.rows = request.rows;
    response.request_commitment = CommitRCFfnRowShardRequest(request);
    if (!request.x_rows || !request.w_up || !request.w_down) {
        response.error = "missing immutable operand";
        return response;
    }
    response.ok = ComputeRCFfnRowShard(
        *request.x_rows, *request.w_up, *request.w_down,
        request.prf_up, request.prf_down,
        request.rows.begin, request.rows.count,
        request.d_model, request.d_ff, backend,
        response.output_rows);
    if (!response.ok) {
        response.error = "exact FFN shard execution failed";
        response.output_rows.clear();
        return response;
    }
    response.output_commitment =
        CommitRCFfnRowShardOutput(request, response.output_rows);
    return response;
}

RCDistributedFfnResult ExecuteTrustedRCFfnLayer(
    const uint256& episode_id,
    uint32_t round_ordinal,
    uint32_t layer_ordinal,
    const std::vector<int8_t>& x,
    const std::vector<int8_t>& w_up,
    const std::vector<int8_t>& w_down,
    const uint256& prf_up,
    const uint256& prf_down,
    uint32_t rows,
    uint32_t d_model,
    uint32_t d_ff,
    const std::vector<RCFfnRowShardExecutor>& executors)
{
    RCDistributedFfnResult result;
    const auto ranges{
        CanonicalRCRowRanges(rows, executors.size(), /*alignment=*/32)};
    if (ranges.empty() ||
        x.size() != static_cast<size_t>(rows) * d_model ||
        w_up.size() != static_cast<size_t>(d_model) * d_ff ||
        w_down.size() != static_cast<size_t>(d_ff) * d_model) {
        result.error = "invalid distributed FFN shape";
        return result;
    }
    const auto shared_up{
        std::make_shared<const std::vector<int8_t>>(w_up)};
    const auto shared_down{
        std::make_shared<const std::vector<int8_t>>(w_down)};
    std::vector<RCFfnRowShardRequest> requests;
    std::vector<std::future<RCFfnRowShardResponse>> futures;
    requests.reserve(ranges.size());
    futures.reserve(ranges.size());
    for (size_t shard = 0; shard < ranges.size(); ++shard) {
        const RCRowRange range{ranges[shard]};
        auto rows_owned{std::make_shared<std::vector<int8_t>>(
            x.begin() + static_cast<size_t>(range.begin) * d_model,
            x.begin() + static_cast<size_t>(range.begin + range.count) * d_model)};
        requests.push_back({
            .episode_id = episode_id,
            .round_ordinal = round_ordinal,
            .layer_ordinal = layer_ordinal,
            .rows = range,
            .d_model = d_model,
            .d_ff = d_ff,
            .prf_up = prf_up,
            .prf_down = prf_down,
            .x_rows = std::move(rows_owned),
            .w_up = shared_up,
            .w_down = shared_down,
        });
        futures.push_back(std::async(
            std::launch::async, executors[shard], std::cref(requests.back())));
    }

    result.output.resize(static_cast<size_t>(rows) * d_model);
    result.request_commitments.reserve(ranges.size());
    result.output_commitments.reserve(ranges.size());
    for (size_t shard = 0; shard < ranges.size(); ++shard) {
        RCFfnRowShardResponse response{futures[shard].get()};
        const RCFfnRowShardRequest& request{requests[shard]};
        const uint256 request_commitment{CommitRCFfnRowShardRequest(request)};
        if (!response.ok || response.rows.begin != request.rows.begin ||
            response.rows.count != request.rows.count ||
            response.request_commitment != request_commitment ||
            response.output_rows.size() !=
                static_cast<size_t>(request.rows.count) * d_model ||
            response.output_commitment !=
                CommitRCFfnRowShardOutput(request, response.output_rows)) {
            result.output.clear();
            result.error = response.error.empty()
                ? "trusted shard response failed commitment/range checks"
                : response.error;
            return result;
        }
        std::copy(
            response.output_rows.begin(), response.output_rows.end(),
            result.output.begin() +
                static_cast<size_t>(request.rows.begin) * d_model);
        result.request_commitments.push_back(request_commitment);
        result.output_commitments.push_back(response.output_commitment);
    }
    result.ok = true;
    return result;
}

void ExpandSynthOperands(const uint256& seed, const DistSynthShape& shape,
                         std::vector<int8_t>& A, std::vector<int8_t>& B)
{
    assert(shape.m > 0 && shape.n > 0 && shape.k > 0);
    assert(shape.seg_len > 0);
    assert((shape.n % kRCMxBlockLen) == 0);

    const uint256 seed_A = DeriveTagged(seed, "BTX_RC_DIST_A_V1");
    const uint256 seed_B = DeriveTagged(seed, "BTX_RC_DIST_B_V1");
    // Reuse MX dequant expand so values stay in the Extract operand alphabet.
    A = ExpandMxDequantInt8(seed_A, shape.m, shape.k);
    B = ExpandMxDequantInt8(seed_B, shape.k, shape.n);
}

std::vector<int64_t> SynthSegmentPartial(const std::vector<int8_t>& A,
                                         const std::vector<int8_t>& B,
                                         const DistSynthShape& shape, uint32_t segment_id)
{
    assert(A.size() == static_cast<size_t>(shape.m) * shape.k);
    assert(B.size() == static_cast<size_t>(shape.k) * shape.n);
    const uint32_t n_segs = DistNumSegs(shape.k, shape.seg_len);
    assert(segment_id < n_segs);

    const uint32_t k0 = segment_id * shape.seg_len;
    const uint32_t len = std::min(shape.seg_len, shape.k - k0);
    std::vector<int64_t> out(static_cast<size_t>(shape.m) * shape.n, 0);
    for (uint32_t i = 0; i < shape.m; ++i) {
        for (uint32_t j = 0; j < shape.n; ++j) {
            int64_t acc = 0;
            for (uint32_t t = 0; t < len; ++t) {
                const uint32_t kk = k0 + t;
                const int64_t a = A[static_cast<size_t>(i) * shape.k + kk];
                const int64_t b = B[static_cast<size_t>(kk) * shape.n + j];
                acc += a * b;
            }
            out[static_cast<size_t>(i) * shape.n + j] = acc;
        }
    }
    return out;
}

DistDevicePartials SimulateDevices(const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                                   const DistSynthShape& shape, uint32_t n_devices)
{
    assert(n_devices >= 1);
    DistDevicePartials out;
    const uint32_t n_segs = DistNumSegs(shape.k, shape.seg_len);
    out.segs.resize(n_segs);
    out.per_device.assign(n_devices,
                          std::vector<int64_t>(static_cast<size_t>(shape.m) * shape.n, 0));

    for (uint32_t sid = 0; sid < n_segs; ++sid) {
        // Consensus ID is sid — never remapped by N.
        assert(ConsensusSegmentId(sid * shape.seg_len, shape.seg_len) == sid);
        out.segs[sid] = SynthSegmentPartial(A, B, shape, sid);
        const uint32_t owner = DeviceForSegment(sid, n_devices);
        AddInPlace(out.per_device[owner], out.segs[sid]);
    }
    return out;
}

std::vector<int64_t> ReduceDevicePartials(const std::vector<std::vector<int64_t>>& per_device,
                                          DistReduceOrder order)
{
    assert(!per_device.empty());
    const size_t N = per_device.size();
    const size_t elems = per_device[0].size();
    for (const auto& d : per_device) {
        assert(d.size() == elems);
    }

    switch (order) {
    case DistReduceOrder::TreeLeftToRight: {
        std::vector<int64_t> acc = per_device[0];
        for (size_t i = 1; i < N; ++i) {
            AddInPlace(acc, per_device[i]);
        }
        return acc;
    }
    case DistReduceOrder::TreeRightToLeft: {
        std::vector<int64_t> acc = per_device[N - 1];
        for (size_t i = N - 1; i > 0; --i) {
            // fold from the right: (... (d[N-1]) + d[N-2]) + ...
            acc = AddMats(per_device[i - 1], acc);
        }
        return acc;
    }
    case DistReduceOrder::PairwiseButterfly: {
        // Classic butterfly / recursive doubling: N must be a power of two.
        assert((N & (N - 1)) == 0);
        std::vector<std::vector<int64_t>> cur = per_device;
        for (size_t stride = 1; stride < N; stride *= 2) {
            std::vector<std::vector<int64_t>> nxt = cur;
            for (size_t i = 0; i < N; i += 2 * stride) {
                for (size_t j = 0; j < stride; ++j) {
                    const size_t a = i + j;
                    const size_t b = i + j + stride;
                    if (b >= N) continue;
                    const auto sum = AddMats(cur[a], cur[b]);
                    nxt[a] = sum;
                    nxt[b] = sum; // both lanes hold the reduced pair (simulates all-reduce)
                }
            }
            cur = std::move(nxt);
        }
        return cur[0];
    }
    }
    return per_device[0];
}

std::vector<int64_t> SumSegmentPartials(const std::vector<std::vector<int64_t>>& segs)
{
    assert(!segs.empty());
    std::vector<int64_t> acc = segs[0];
    for (size_t s = 1; s < segs.size(); ++s) {
        AddInPlace(acc, segs[s]);
    }
    return acc;
}

std::vector<int8_t> ExtractOnce(const uint256& seed_extract, const std::vector<int64_t>& Y,
                                uint32_t m, uint32_t n)
{
    assert(Y.size() == static_cast<size_t>(m) * n);
    assert((n % kRCMxBlockLen) == 0);
    const uint256 prf = lt::DeriveMatExpandPrfKey(seed_extract);
    std::vector<int8_t> out(Y.size());
    ExtractMXMatrixInt64(prf, Y.data(), m, n, out.data());
    return out;
}

uint256 DigestSyntheticDistributed(const DistSynthShape& shape,
                                   const std::vector<std::vector<int64_t>>& segs,
                                   const std::vector<int8_t>& extracted)
{
    static constexpr char kTag[] = "BTX_RC_DIST_SYNTH_V1";
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kTag),
               reinterpret_cast<const unsigned char*>(kTag) + sizeof(kTag) - 1);
    AppendLE32(buf, shape.m);
    AppendLE32(buf, shape.n);
    AppendLE32(buf, shape.k);
    AppendLE32(buf, shape.seg_len);
    for (const auto& seg : segs) {
        for (int64_t v : seg) {
            AppendInt64LE(buf, v);
        }
    }
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(extracted.data()),
               reinterpret_cast<const unsigned char*>(extracted.data()) + extracted.size());
    return Sha256dBytes(buf.data(), buf.size());
}

DistEpisodeResult RunSyntheticDistributed(const uint256& seed, const DistSynthShape& shape,
                                          uint32_t n_devices, DistReduceOrder order)
{
    assert(n_devices >= 1);
    if (order == DistReduceOrder::PairwiseButterfly) {
        assert((n_devices & (n_devices - 1)) == 0);
    }

    std::vector<int8_t> A, B;
    ExpandSynthOperands(seed, shape, A, B);
    auto parts = SimulateDevices(A, B, shape, n_devices);

    // Canonical pre-Extract sum = ascending segment_id integer sum.
    const auto canonical_sum = SumSegmentPartials(parts.segs);
    // Device-tree reduce must match canonical (integer addition associative).
    const auto reduced = ReduceDevicePartials(parts.per_device, order);
    assert(reduced == canonical_sum);

    const uint256 seed_extract = DeriveTagged(seed, "BTX_RC_DIST_EXTRACT_V1");
    auto extracted = ExtractOnce(seed_extract, canonical_sum, shape.m, shape.n);
    const uint256 digest = DigestSyntheticDistributed(shape, parts.segs, extracted);

    DistEpisodeResult r;
    r.pre_extract_sum = std::move(canonical_sum);
    r.extracted = std::move(extracted);
    r.digest = digest;
    r.n_segs = DistNumSegs(shape.k, shape.seg_len);
    r.n_devices = n_devices;
    r.order = order;
    return r;
}

const char* DistReduceOrderName(DistReduceOrder order)
{
    switch (order) {
    case DistReduceOrder::TreeLeftToRight:
        return "tree_lr";
    case DistReduceOrder::TreeRightToLeft:
        return "tree_rl";
    case DistReduceOrder::PairwiseButterfly:
        return "butterfly";
    }
    return "unknown";
}

} // namespace matmul::v4::rc
