// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_REACHABILITY_H
#define BITCOIN_MODELNET_REACHABILITY_H

#include <univalue.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

enum class ReachabilityState {
    UNKNOWN = 0,
    PRIVATE = 1,
    PUBLIC_DIRECT = 2,
    PUBLIC_MAPPED = 3,
    RELAY_REACHABLE = 4,
    DEGRADED = 5,
};

enum class PathKind {
    IPV6_DIRECT = 0,
    IPV4_DIRECT = 1,
    MAPPED = 2,
    RELAY = 3,
};

struct DialbackRequest {
    std::string request_id;
    std::string candidate;
    std::string requester;
    std::string requester_netgroup;
    int64_t now_ms{0};
    int64_t ttl_ms{60000};
};

struct DialbackReport {
    std::string request_id;
    std::string observer_id;
    std::string observer_netgroup;
    std::string observed_endpoint;
    bool ok{false};
    int64_t at_ms{0};
};

struct ReachabilityLimits {
    int min_independent_ok{2};
    int max_probes_per_requester_per_minute{4};
    int max_probes_per_netgroup_per_minute{8};
    int max_concurrent{4};
    int max_targets_per_request{2};
    size_t max_probe_bytes{4096};
    int64_t proof_ttl_ms{15 * 60 * 1000};
};

struct AddressObservation {
    std::string observer_id;
    std::string observer_netgroup;
    std::string observed;
    int64_t at_ms{0};
};

class ReachabilityTracker {
    ReachabilityLimits m_lim;
    ReachabilityState m_state{ReachabilityState::UNKNOWN};
    uint64_t m_epoch{0};
    int64_t m_last_transition_ms{0};
    int64_t m_last_test_ms{0};
    std::vector<DialbackReport> m_ok;
    std::vector<AddressObservation> m_obs;
    std::map<std::string, std::vector<int64_t>> m_req_times;
    std::map<std::string, std::vector<int64_t>> m_ng_times;
    int m_concurrent{0};
    std::string m_listen;
    std::string m_mapped;
    std::string m_relay;
    bool m_local_test{false};

public:
    explicit ReachabilityTracker(ReachabilityLimits lim = {});

    void SetLocalTest(bool on) { m_local_test = on; }
    void SetListen(const std::string& a) { m_listen = a; }
    void SetMapped(const std::string& a) { m_mapped = a; }
    void SetRelay(const std::string& a) { m_relay = a; }
    void NoteEpoch(uint64_t epoch, int64_t now_ms);

    bool ValidateProbeTarget(const std::string& candidate, std::string& err) const;
    bool AdmitProbe(const DialbackRequest& req, std::string& err);
    void FinishProbe();
    void NoteReport(const DialbackReport& r, int64_t now_ms);
    void NoteObservation(const AddressObservation& o, int64_t now_ms);
    void NoteRelayHealthy(bool ok, int64_t now_ms);
    void Expire(int64_t now_ms);

    ReachabilityState State() const { return m_state; }
    uint64_t Epoch() const { return m_epoch; }
    bool MayAdvertiseHost(bool operator_host) const;
    void WithdrawHost() { m_state = ReachabilityState::PRIVATE; }

    UniValue StatusJson() const;
    std::string BestCandidate() const;
    std::vector<std::string> CandidateOrder() const;
};

const char* ReachabilityStateName(ReachabilityState s);
const char* PathKindName(PathKind k);
bool IsPrivateRfc1918(const std::string& endpoint);
bool IsRoutingServer(ReachabilityState s);
std::vector<std::string> RaceBounded(const std::vector<std::string>& candidates, size_t max_race = 3);
bool ConnectionFullyReady(bool transport_ok, bool pq1_ok, bool identity_match);

} // namespace modelnet

#endif // BITCOIN_MODELNET_REACHABILITY_H
