// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RELAY_RESERVE_H
#define BITCOIN_MODELNET_RELAY_RESERVE_H

#include <univalue.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

constexpr int64_t RELAY_DEFAULT_TTL_MS = 60 * 60 * 1000;
constexpr uint64_t RELAY_DEFAULT_BYTE_CEILING = 32ull << 20;
constexpr int RELAY_DEFAULT_CONN_CEILING = 4;
constexpr int RELAY_DEFAULT_STREAM_CEILING = 8;
constexpr int RELAY_MAX_RESERVATIONS = 128;
constexpr int RELAY_MAX_PER_IDENTITY = 2;
constexpr int RELAY_MAX_PER_NETGROUP = 8;
constexpr int64_t RELAY_IDLE_MS = 2 * 60 * 1000;

struct RelayReservation {
    std::string reservation_id;
    std::string service_id;
    std::string netgroup;
    std::string relay_endpoint;
    int64_t expiry_ms{0};
    uint64_t byte_ceiling{RELAY_DEFAULT_BYTE_CEILING};
    int conn_ceiling{RELAY_DEFAULT_CONN_CEILING};
    int stream_ceiling{RELAY_DEFAULT_STREAM_CEILING};
    uint64_t bytes_used{0};
    int conns{0};
    int streams{0};
    int64_t last_activity_ms{0};
};

struct RelayLimits {
    int64_t ttl_ms{RELAY_DEFAULT_TTL_MS};
    uint64_t byte_ceiling{RELAY_DEFAULT_BYTE_CEILING};
    int conn_ceiling{RELAY_DEFAULT_CONN_CEILING};
    int stream_ceiling{RELAY_DEFAULT_STREAM_CEILING};
    int max_reservations{RELAY_MAX_RESERVATIONS};
    int max_per_identity{RELAY_MAX_PER_IDENTITY};
    int max_per_netgroup{RELAY_MAX_PER_NETGROUP};
    int64_t idle_ms{RELAY_IDLE_MS};
};

class RelayTable {
    RelayLimits m_lim;
    std::vector<RelayReservation> m_rsvp;
    uint64_t m_forwarded{0};
    int m_active_fwd{0};

public:
    explicit RelayTable(RelayLimits lim = {});

    bool Reserve(const std::string& service_id, const std::string& netgroup,
                  const std::string& relay_endpoint, int64_t now_ms,
                  RelayReservation& out, std::string& err);
    void Expire(int64_t now_ms);
    bool AllowForward(const std::string& reservation_id, uint64_t nbytes, int64_t now_ms, std::string& err);
    void AddForwardedBytes(const std::string& reservation_id, uint64_t nbytes, int64_t now_ms);
    void CloseConn(const std::string& reservation_id);
    bool Has(const std::string& reservation_id) const;
    bool Get(const std::string& reservation_id, RelayReservation& out) const;
    std::vector<RelayReservation> ForIdentity(const std::string& service_id) const;
    std::string Alternate(const std::string& dead_relay, const std::string& service_id) const;
    UniValue StatusJson() const;
    uint64_t ForwardedBytes() const { return m_forwarded; }
    size_t Size() const { return m_rsvp.size(); }
};

struct PunchPlan {
    std::string via_relay;
    std::string reservation_id;
    std::vector<std::string> local_candidates;
    std::vector<std::string> remote_candidates;
    int64_t rtt_ms{0};
    int64_t attempt_at_ms{0};
    int attempts{0};
    int max_attempts{3};
};

enum class PunchResult {
    DIRECT_OK = 0,
    RETAIN_RELAY = 1,
    RETRY_LATER = 2,
};

bool PlanHolePunch(const std::vector<std::string>& local_cands,
                    const std::vector<std::string>& remote_cands,
                    int64_t now_ms, int64_t rtt_ms, PunchPlan& out, std::string& err);
PunchResult RecordPunchAttempt(PunchPlan& plan, bool direct_transport, bool pq1_ok, bool identity_match,
                              bool network_changed);
bool PunchIdentityIndependentOfRelay();

} // namespace modelnet

#endif // BITCOIN_MODELNET_RELAY_RESERVE_H
