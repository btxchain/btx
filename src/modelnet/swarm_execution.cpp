// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execution.h>

#include <modelnet/swarm_codec.h>

#include <algorithm>
#include <sstream>

namespace modelnet {
namespace {

bool InRange(int value)
{
    return value >= 1 && value <= 4096;
}

std::string JoinIds(const std::vector<std::string>& ids)
{
    std::string out = "[";
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) out += ',';
        out += '"';
        out += ids[i];
        out += '"';
    }
    out += ']';
    return out;
}

std::string JoinInts(const std::vector<int>& values)
{
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out += ',';
        out += std::to_string(values[i]);
    }
    out += ']';
    return out;
}

} // namespace

std::string SwarmKvFingerprint(const SwarmKvConfig& config, std::string& err)
{
    if (!SwarmFixedId(config.checkpoint) || !SwarmFixedId(config.architecture) ||
        !SwarmFixedId(config.tokenizer) || !SwarmFixedId(config.runtime_build)) {
        err = "ID";
        return {};
    }
    if (!InRange(config.layers) || !InRange(config.kv_heads) || !InRange(config.head_dim) || config.tenant_epoch < 0) {
        err = "KV_RANGE";
        return {};
    }
    if (config.layout != "BHTD" || (config.dtype != "F32" && config.dtype != "F16" && config.dtype != "BF16") ||
        config.attention_mask != "causal") {
        err = "KV_LAYOUT";
        return {};
    }
    if (config.adapter_ids.size() > 64 || config.adapter_order.size() != config.adapter_ids.size()) {
        err = "KV_ADAPTERS";
        return {};
    }
    std::vector<int> expected(config.adapter_ids.size());
    for (size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<int>(i);
    if (config.adapter_order != expected) {
        err = "KV_ADAPTER_ORDER";
        return {};
    }
    for (const std::string& id : config.adapter_ids) {
        if (!SwarmFixedId(id)) {
            err = "ID";
            return {};
        }
    }
    std::ostringstream body;
    body << "{\"adapter_ids\":" << JoinIds(config.adapter_ids)
         << ",\"adapter_order\":" << JoinInts(config.adapter_order)
         << ",\"architecture\":\"" << config.architecture
         << "\",\"attention_mask\":\"" << config.attention_mask
         << "\",\"checkpoint\":\"" << config.checkpoint
         << "\",\"dtype\":\"" << config.dtype
         << "\",\"head_dim\":" << config.head_dim
         << ",\"kv_heads\":" << config.kv_heads
         << ",\"layers\":" << config.layers
         << ",\"layout\":\"" << config.layout
         << "\",\"position_encoding\":\"" << config.position_encoding
         << "\",\"quantization\":\"" << config.quantization
         << "\",\"runtime_build\":\"" << config.runtime_build
         << "\",\"tenant_epoch\":" << config.tenant_epoch
         << ",\"tokenizer\":\"" << config.tokenizer << "\"}";
    err.clear();
    return SwarmDigest("BTX/KVFingerprint/1", body.str());
}

std::string SwarmAcceptKv(const std::string& expected_fingerprint, const std::vector<SwarmKvPage>& pages,
                           int token_count, int64_t now_ms)
{
    if (expected_fingerprint.empty() || token_count < 1) return "KV_INCOMPLETE";
    int cursor = 0;
    for (const SwarmKvPage& page : pages) {
        if (page.fingerprint != expected_fingerprint) return "KV_MISMATCH";
        if (!page.finite) return "KV_NONFINITE";
        if (page.expires_ms <= now_ms) return "CACHE_EXPIRED";
        if (page.start != cursor || page.end <= cursor || page.end > token_count) return "KV_PAGE_GAP";
        cursor = page.end;
    }
    if (cursor != token_count) return "KV_INCOMPLETE";
    return "OK";
}

SwarmPlacement SwarmChooseExecution(int64_t prefill_ms, int64_t remote_queue_ms, int64_t local_queue_ms,
                                    int64_t bytes_to_move, int64_t bandwidth_bps, int64_t rtt_ms,
                                    int64_t decode_remote_ms, int64_t decode_local_ms)
{
    SwarmPlacement out;
    const int64_t values[] = {prefill_ms, remote_queue_ms, local_queue_ms, bytes_to_move, rtt_ms, decode_remote_ms, decode_local_ms};
    for (int64_t value : values) {
        if (value < 0) {
            out.code = "RANGE";
            return out;
        }
    }
    if (bandwidth_bps < 1) {
        out.code = "BANDWIDTH";
        return out;
    }
    out.recompute_ms = local_queue_ms + prefill_ms + decode_local_ms;
    out.transfer_ms = local_queue_ms + rtt_ms + (bytes_to_move * 8 * 1000 + bandwidth_bps - 1) / bandwidth_bps + decode_local_ms;
    out.route_ms = remote_queue_ms + rtt_ms + decode_remote_ms;
    out.choice = "RECOMPUTE_LOCAL";
    int64_t best = out.recompute_ms;
    if (out.route_ms < best || (out.route_ms == best && std::string("ROUTE_TO_OWNER") < out.choice)) {
        best = out.route_ms;
        out.choice = "ROUTE_TO_OWNER";
    }
    if (out.transfer_ms < best || (out.transfer_ms == best && std::string("TRANSFER_KV") < out.choice)) {
        out.choice = "TRANSFER_KV";
    }
    out.measured_benchmark = false;
    out.ok = true;
    out.code = "PLACED";
    return out;
}

SwarmPlacement SwarmExecutePlacement(const SwarmPlacement& choice, bool engine_present)
{
    SwarmPlacement out = choice;
    out.bytes_moved = false;
    if (!choice.ok) return out;
    if (choice.choice == "TRANSFER_KV" && !engine_present) {
        out.ok = false;
        out.code = "ENGINE_ABSENT";
        return out;
    }
    if (choice.choice == "RECOMPUTE_LOCAL" || choice.choice == "ROUTE_TO_OWNER") {
        out.code = "EXECUTED_WITHOUT_TRANSFER";
        return out;
    }
    if (!engine_present) {
        out.ok = false;
        out.code = "ENGINE_ABSENT";
        return out;
    }
    // An engine flag is not a completed tensor transfer.
    out.bytes_moved = false;
    out.code = "LOCAL";
    return out;
}

bool SwarmMayAverage(const SwarmCohort& a, const SwarmCohort& b)
{
    return a.compatible && b.compatible && !a.checkpoint.empty() && a.checkpoint == b.checkpoint && a.recipe == b.recipe;
}

bool SwarmResumeReference(const IntegerState& checkpoint, IntegerState& out, std::string& err)
{
    IntegerTrainer trainer;
    if (!trainer.Resume(checkpoint, err)) return false;
    out = trainer.State();
    return true;
}

std::string SwarmCandidateId(const std::string& parent, const std::string& recipe,
                             const std::string& weights, const std::string& nonce)
{
    const std::string body = SwarmCanonical({
        {"nonce", nonce},
        {"parent", parent},
        {"recipe", recipe},
        {"weights", weights},
    });
    return SwarmDigest("BTX/CandidateCheckpoint/1", body);
}

void SwarmQuarantine(std::set<std::string>& quarantined, const std::string& digest)
{
    if (!digest.empty()) quarantined.insert(digest);
}

bool SwarmIsQuarantined(const std::set<std::string>& quarantined, const std::string& digest)
{
    return quarantined.count(digest) != 0;
}

} // namespace modelnet
