// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/reachability.h>
#include <modelnet/model_nat.h>

#include <algorithm>
#include <cstdio>
#include <set>
#include <sstream>

namespace modelnet {
namespace {

std::string HostOf(const std::string& endpoint)
{
    std::string host;
    uint16_t port = 0;
    if (!SplitListenBind(endpoint, host, port)) return endpoint;
    return host;
}

bool ParseIpv4(const std::string& host, unsigned a[4])
{
    int b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    char extra = 0;
    if (std::sscanf(host.c_str(), "%d.%d.%d.%d%c", &b0, &b1, &b2, &b3, &extra) != 4) return false;
    if (b0 < 0 || b0 > 255 || b1 < 0 || b1 > 255 || b2 < 0 || b2 > 255 || b3 < 0 || b3 > 255) return false;
    a[0] = static_cast<unsigned>(b0);
    a[1] = static_cast<unsigned>(b1);
    a[2] = static_cast<unsigned>(b2);
    a[3] = static_cast<unsigned>(b3);
    return true;
}

void PruneTimes(std::vector<int64_t>& times, int64_t now_ms)
{
    times.erase(std::remove_if(times.begin(), times.end(),
                               [&](int64_t t) { return now_ms - t > 60000; }),
                times.end());
}

} // namespace

const char* ReachabilityStateName(ReachabilityState s)
{
    switch (s) {
    case ReachabilityState::PRIVATE: return "PRIVATE";
    case ReachabilityState::PUBLIC_DIRECT: return "PUBLIC_DIRECT";
    case ReachabilityState::PUBLIC_MAPPED: return "PUBLIC_MAPPED";
    case ReachabilityState::RELAY_REACHABLE: return "RELAY_REACHABLE";
    case ReachabilityState::DEGRADED: return "DEGRADED";
    case ReachabilityState::UNKNOWN:
    default: return "UNKNOWN";
    }
}

const char* PathKindName(PathKind k)
{
    switch (k) {
    case PathKind::IPV6_DIRECT: return "ipv6_direct";
    case PathKind::IPV4_DIRECT: return "ipv4_direct";
    case PathKind::MAPPED: return "mapped";
    case PathKind::RELAY: return "relay";
    }
    return "unknown";
}

bool IsPrivateRfc1918(const std::string& endpoint)
{
    const std::string host = HostOf(endpoint);
    if (host == "127.0.0.1" || host == "::1" || host == "localhost") return true;
    unsigned a[4] = {};
    if (!ParseIpv4(host, a)) {
        if (host.rfind("fe80:", 0) == 0 || host.rfind("fd", 0) == 0 || host.rfind("fc", 0) == 0) return true;
        return false;
    }
    if (a[0] == 10) return true;
    if (a[0] == 192 && a[1] == 168) return true;
    if (a[0] == 172 && a[1] >= 16 && a[1] <= 31) return true;
    if (a[0] == 169 && a[1] == 254) return true;
    return false;
}

ReachabilityTracker::ReachabilityTracker(ReachabilityLimits lim) : m_lim(lim) {}

void ReachabilityTracker::NoteEpoch(uint64_t epoch, int64_t now_ms)
{
    if (epoch == m_epoch) return;
    m_epoch = epoch;
    m_ok.clear();
    m_obs.clear();
    if (m_state == ReachabilityState::PUBLIC_DIRECT || m_state == ReachabilityState::PUBLIC_MAPPED) {
        m_state = ReachabilityState::DEGRADED;
        m_last_transition_ms = now_ms;
    }
}

bool ReachabilityTracker::ValidateProbeTarget(const std::string& candidate, std::string& err) const
{
    if (IsForbiddenControlEndpoint(candidate, err)) return false;
    std::string host;
    uint16_t port = 0;
    if (!SplitListenBind(candidate, host, port)) {
        err = "bad candidate";
        return false;
    }
    if (port != DEFAULT_MODEL_PORT && port < 1024) {
        err = "not a model-plane port";
        return false;
    }
    if (!m_local_test && IsPrivateRfc1918(candidate)) {
        err = "private target";
        return false;
    }
    return true;
}

bool ReachabilityTracker::AdmitProbe(const DialbackRequest& req, std::string& err)
{
    if (req.request_id.empty() || req.request_id.size() > 64) {
        err = "request_id";
        return false;
    }
    if (req.ttl_ms <= 0 || req.ttl_ms > 5 * 60 * 1000) {
        err = "ttl";
        return false;
    }
    if (!ValidateProbeTarget(req.candidate, err)) return false;
    if (m_concurrent >= m_lim.max_concurrent) {
        err = "concurrent probes";
        return false;
    }
    auto& rt = m_req_times[req.requester];
    PruneTimes(rt, req.now_ms);
    if (static_cast<int>(rt.size()) >= m_lim.max_probes_per_requester_per_minute) {
        err = "requester rate";
        return false;
    }
    auto& ng = m_ng_times[req.requester_netgroup];
    PruneTimes(ng, req.now_ms);
    if (static_cast<int>(ng.size()) >= m_lim.max_probes_per_netgroup_per_minute) {
        err = "netgroup rate";
        return false;
    }
    rt.push_back(req.now_ms);
    ng.push_back(req.now_ms);
    ++m_concurrent;
    return true;
}

void ReachabilityTracker::FinishProbe()
{
    if (m_concurrent > 0) --m_concurrent;
}

void ReachabilityTracker::NoteReport(const DialbackReport& r, int64_t now_ms)
{
    Expire(now_ms);
    m_last_test_ms = now_ms;
    if (!r.ok) {
        if (m_ok.empty()) {
            m_state = ReachabilityState::PRIVATE;
            m_last_transition_ms = now_ms;
        }
        return;
    }
    for (const auto& prev : m_ok) {
        if (prev.observer_id == r.observer_id && prev.request_id == r.request_id) return;
    }
    m_ok.push_back(r);
    std::set<std::string> ngs;
    for (const auto& p : m_ok) ngs.insert(p.observer_netgroup.empty() ? p.observer_id : p.observer_netgroup);
    if (static_cast<int>(ngs.size()) >= m_lim.min_independent_ok) {
        m_state = m_mapped.empty() ? ReachabilityState::PUBLIC_DIRECT : ReachabilityState::PUBLIC_MAPPED;
        m_last_transition_ms = now_ms;
    }
}

void ReachabilityTracker::NoteObservation(const AddressObservation& o, int64_t now_ms)
{
    if (o.observer_id.empty() || o.observed.empty()) return;
    std::string err;
    if (IsForbiddenControlEndpoint(o.observed, err)) return;
    for (auto& prev : m_obs) {
        if (prev.observer_id == o.observer_id) {
            prev = o;
            prev.at_ms = now_ms;
            return;
        }
    }
    if (m_obs.size() >= 16) m_obs.erase(m_obs.begin());
    AddressObservation x = o;
    x.at_ms = now_ms;
    m_obs.push_back(x);
}

void ReachabilityTracker::NoteRelayHealthy(bool ok, int64_t now_ms)
{
    if (ok && (m_state == ReachabilityState::UNKNOWN || m_state == ReachabilityState::PRIVATE ||
               m_state == ReachabilityState::DEGRADED)) {
        m_state = ReachabilityState::RELAY_REACHABLE;
        m_last_transition_ms = now_ms;
    }
}

void ReachabilityTracker::Expire(int64_t now_ms)
{
    m_ok.erase(std::remove_if(m_ok.begin(), m_ok.end(),
                              [&](const DialbackReport& r) { return now_ms - r.at_ms > m_lim.proof_ttl_ms; }),
               m_ok.end());
    m_obs.erase(std::remove_if(m_obs.begin(), m_obs.end(),
                                [&](const AddressObservation& o) { return now_ms - o.at_ms > m_lim.proof_ttl_ms; }),
                m_obs.end());
    std::set<std::string> ngs;
    for (const auto& p : m_ok) ngs.insert(p.observer_netgroup.empty() ? p.observer_id : p.observer_netgroup);
    if (static_cast<int>(ngs.size()) < m_lim.min_independent_ok &&
        (m_state == ReachabilityState::PUBLIC_DIRECT || m_state == ReachabilityState::PUBLIC_MAPPED)) {
        m_state = m_relay.empty() ? ReachabilityState::PRIVATE : ReachabilityState::RELAY_REACHABLE;
        m_last_transition_ms = now_ms;
    }
}

bool ReachabilityTracker::MayAdvertiseHost(bool operator_host) const
{
    if (!operator_host) return false;
    return m_state == ReachabilityState::PUBLIC_DIRECT || m_state == ReachabilityState::PUBLIC_MAPPED;
}

std::string ReachabilityTracker::BestCandidate() const
{
    if (m_state == ReachabilityState::PUBLIC_DIRECT || m_state == ReachabilityState::PUBLIC_MAPPED) {
        if (!m_mapped.empty()) return m_mapped;
        if (!m_listen.empty() && !IsPrivateRfc1918(m_listen)) return m_listen;
    }
    if (!m_relay.empty()) return m_relay;
    return m_listen;
}

std::vector<std::string> ReachabilityTracker::CandidateOrder() const
{
    std::vector<std::string> out;
    auto add = [&](const std::string& a) {
        if (a.empty()) return;
        if (std::find(out.begin(), out.end(), a) == out.end()) out.push_back(a);
    };
    if (!m_listen.empty() && m_listen.find(':') != std::string::npos && m_listen.find('.') == std::string::npos) {
        add(m_listen);
    }
    add(m_mapped);
    add(m_listen);
    add(m_relay);
    return RaceBounded(out, 3);
}

UniValue ReachabilityTracker::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("reachability_state", ReachabilityStateName(m_state));
    o.pushKV("listen", m_listen);
    o.pushKV("mapped_endpoint", m_mapped);
    o.pushKV("relay", m_relay);
    o.pushKV("network_epoch", static_cast<int64_t>(m_epoch));
    o.pushKV("last_reachability_test_ms", m_last_test_ms);
    o.pushKV("independent_ok", static_cast<int>(m_ok.size()));
    o.pushKV("observations", static_cast<int>(m_obs.size()));
    o.pushKV("may_advertise_host", MayAdvertiseHost(true));
    return o;
}

std::vector<std::string> RaceBounded(const std::vector<std::string>& candidates, size_t max_race)
{
    std::vector<std::string> out;
    for (const auto& c : candidates) {
        if (out.size() >= max_race) break;
        if (c.empty()) continue;
        out.push_back(c);
    }
    return out;
}

bool ConnectionFullyReady(bool transport_ok, bool pq1_ok, bool identity_match)
{
    return transport_ok && pq1_ok && identity_match;
}

bool IsRoutingServer(ReachabilityState s)
{
    return s == ReachabilityState::PUBLIC_DIRECT || s == ReachabilityState::PUBLIC_MAPPED;
}

} // namespace modelnet
