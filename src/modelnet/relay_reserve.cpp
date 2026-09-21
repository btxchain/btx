// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/relay_reserve.h>
#include <modelnet/model_nat.h>

#include <algorithm>
#include <random.h>
#include <util/strencodings.h>

namespace modelnet {
namespace {

std::string NewId()
{
    unsigned char b[8];
    GetStrongRandBytes(Span<unsigned char>{b, sizeof(b)});
    return HexStr(Span<const unsigned char>{b, sizeof(b)});
}

} // namespace

RelayTable::RelayTable(RelayLimits lim) : m_lim(lim) {}

bool RelayTable::Reserve(const std::string& service_id, const std::string& netgroup,
                           const std::string& relay_endpoint, int64_t now_ms,
                           RelayReservation& out, std::string& err)
{
    Expire(now_ms);
    if (service_id.empty()) {
        err = "service_id";
        return false;
    }
    if (IsForbiddenRelayEndpoint(relay_endpoint, err)) return false;
    int per_id = 0, per_ng = 0;
    for (const auto& r : m_rsvp) {
        if (r.service_id == service_id) ++per_id;
        if (r.netgroup == netgroup && !netgroup.empty()) ++per_ng;
    }
    if (per_id >= m_lim.max_per_identity) {
        err = "identity reservation cap";
        return false;
    }
    if (per_ng >= m_lim.max_per_netgroup) {
        err = "netgroup reservation cap";
        return false;
    }
    if (static_cast<int>(m_rsvp.size()) >= m_lim.max_reservations) {
        err = "global reservation cap";
        return false;
    }
    out = {};
    out.reservation_id = NewId();
    out.service_id = service_id;
    out.netgroup = netgroup;
    out.relay_endpoint = relay_endpoint;
    out.expiry_ms = now_ms + m_lim.ttl_ms;
    out.byte_ceiling = m_lim.byte_ceiling;
    out.conn_ceiling = m_lim.conn_ceiling;
    out.stream_ceiling = m_lim.stream_ceiling;
    out.last_activity_ms = now_ms;
    m_rsvp.push_back(out);
    return true;
}

void RelayTable::Expire(int64_t now_ms)
{
    m_rsvp.erase(std::remove_if(m_rsvp.begin(), m_rsvp.end(),
                                [&](const RelayReservation& r) {
                                    if (r.expiry_ms <= now_ms) return true;
                                    return now_ms - r.last_activity_ms > m_lim.idle_ms;
                                }),
                 m_rsvp.end());
}

bool RelayTable::AllowForward(const std::string& reservation_id, uint64_t nbytes, int64_t now_ms, std::string& err)
{
    Expire(now_ms);
    for (auto& r : m_rsvp) {
        if (r.reservation_id != reservation_id) continue;
        if (r.expiry_ms <= now_ms) {
            err = "expired";
            return false;
        }
        if (r.conns >= r.conn_ceiling) {
            err = "connection ceiling";
            return false;
        }
        if (r.bytes_used + nbytes > r.byte_ceiling) {
            err = "byte ceiling";
            return false;
        }
        r.bytes_used += nbytes;
        r.conns += 1;
        r.last_activity_ms = now_ms;
        m_forwarded += nbytes;
        ++m_active_fwd;
        return true;
    }
    err = "no reservation";
    return false;
}

void RelayTable::AddForwardedBytes(const std::string& reservation_id, uint64_t nbytes, int64_t now_ms)
{
    if (nbytes == 0) return;
    for (auto& r : m_rsvp) {
        if (r.reservation_id != reservation_id) continue;
        r.bytes_used += nbytes;
        r.last_activity_ms = now_ms;
        m_forwarded += nbytes;
        return;
    }
}

void RelayTable::CloseConn(const std::string& reservation_id)
{
    for (auto& r : m_rsvp) {
        if (r.reservation_id == reservation_id && r.conns > 0) {
            --r.conns;
            if (m_active_fwd > 0) --m_active_fwd;
            return;
        }
    }
}

bool RelayTable::Has(const std::string& reservation_id) const
{
    for (const auto& r : m_rsvp) {
        if (r.reservation_id == reservation_id) return true;
    }
    return false;
}

bool RelayTable::Get(const std::string& reservation_id, RelayReservation& out) const
{
    for (const auto& r : m_rsvp) {
        if (r.reservation_id == reservation_id) {
            out = r;
            return true;
        }
    }
    return false;
}

std::vector<RelayReservation> RelayTable::ForIdentity(const std::string& service_id) const
{
    std::vector<RelayReservation> out;
    for (const auto& r : m_rsvp) {
        if (r.service_id == service_id) out.push_back(r);
    }
    return out;
}

std::string RelayTable::Alternate(const std::string& dead_relay, const std::string& service_id) const
{
    for (const auto& r : m_rsvp) {
        if (r.service_id == service_id && r.relay_endpoint != dead_relay) return r.relay_endpoint;
    }
    return {};
}

UniValue RelayTable::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("reservations", static_cast<int>(m_rsvp.size()));
    o.pushKV("forwarded_bytes", m_forwarded);
    o.pushKV("active_forwarded", m_active_fwd);
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

bool PlanHolePunch(const std::vector<std::string>& local_cands,
                    const std::vector<std::string>& remote_cands,
                    int64_t now_ms, int64_t rtt_ms, PunchPlan& out, std::string& err)
{
    if (local_cands.empty() || remote_cands.empty()) {
        err = "candidates";
        return false;
    }
    out = {};
    out.local_candidates = local_cands;
    out.remote_candidates = remote_cands;
    out.rtt_ms = rtt_ms < 0 ? 0 : rtt_ms;
    out.attempt_at_ms = now_ms + out.rtt_ms / 2 + 20;
    out.attempts = 0;
    out.max_attempts = 3;
    return true;
}

PunchResult RecordPunchAttempt(PunchPlan& plan, bool direct_transport, bool pq1_ok, bool identity_match,
                                bool network_changed)
{
    ++plan.attempts;
    if (direct_transport && pq1_ok && identity_match) return PunchResult::DIRECT_OK;
    if (plan.attempts >= plan.max_attempts && !network_changed) return PunchResult::RETAIN_RELAY;
    if (network_changed) {
        plan.attempts = 0;
        return PunchResult::RETRY_LATER;
    }
    if (plan.attempts < plan.max_attempts) return PunchResult::RETRY_LATER;
    return PunchResult::RETAIN_RELAY;
}

bool PunchIdentityIndependentOfRelay()
{
    return true;
}

} // namespace modelnet
