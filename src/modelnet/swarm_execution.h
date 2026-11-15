// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECUTION_H
#define BITCOIN_MODELNET_SWARM_EXECUTION_H

#include <modelnet/training_integer.h>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmKvConfig {
    std::string checkpoint;
    std::string architecture;
    std::string tokenizer;
    std::vector<std::string> adapter_ids;
    std::vector<int> adapter_order;
    std::string dtype;
    std::string layout;
    std::string runtime_build;
    std::string position_encoding;
    std::string attention_mask;
    std::string quantization;
    int64_t tenant_epoch{0};
    int layers{0};
    int kv_heads{0};
    int head_dim{0};
};

std::string SwarmKvFingerprint(const SwarmKvConfig& config, std::string& err);

struct SwarmKvPage {
    int start{0};
    int end{0};
    std::string fingerprint;
    bool finite{true};
    int64_t expires_ms{0};
};

/** OK, or KV_MISMATCH, KV_PAGE_GAP, CACHE_EXPIRED, KV_NONFINITE, KV_INCOMPLETE. */
std::string SwarmAcceptKv(const std::string& expected_fingerprint, const std::vector<SwarmKvPage>& pages,
                           int token_count, int64_t now_ms);

struct SwarmPlacement {
    bool ok{false};
    std::string code;
    std::string choice;
    int64_t recompute_ms{0};
    int64_t transfer_ms{0};
    int64_t route_ms{0};
    bool measured_benchmark{false};
    bool bytes_moved{false};
};

SwarmPlacement SwarmChooseExecution(int64_t prefill_ms, int64_t remote_queue_ms, int64_t local_queue_ms,
                                    int64_t bytes_to_move, int64_t bandwidth_bps, int64_t rtt_ms,
                                    int64_t decode_remote_ms, int64_t decode_local_ms);

/** A transfer without an engine is ENGINE_ABSENT. With an engine the code is LOCAL and no bytes move. */
SwarmPlacement SwarmExecutePlacement(const SwarmPlacement& choice, bool engine_present);

struct SwarmCohort {
    std::string checkpoint;
    std::string recipe;
    bool compatible{true};
};

bool SwarmMayAverage(const SwarmCohort& a, const SwarmCohort& b);

bool SwarmResumeReference(const IntegerState& checkpoint, IntegerState& out, std::string& err);

std::string SwarmCandidateId(const std::string& parent, const std::string& recipe,
                             const std::string& weights, const std::string& nonce);

void SwarmQuarantine(std::set<std::string>& quarantined, const std::string& digest);
bool SwarmIsQuarantined(const std::set<std::string>& quarantined, const std::string& digest);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECUTION_H
