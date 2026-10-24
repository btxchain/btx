// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_discover/swarm_discover.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

namespace {

bool KnownScope(const std::string& scope)
{
    return scope == kSwarmDiscoverLan || scope == kSwarmDiscoverWan ||
           scope == kSwarmDiscoverPrivate || scope == kSwarmDiscoverPublic;
}

} // namespace

bool SwarmDiscover::Offer(const std::string& peer, const std::string& scope, const std::string& endpoint, int64_t until_ms, int64_t now_ms, std::string& err)
{
    if (peer.empty() || scope.empty() || endpoint.empty()) {
        err = kSwarmDiscoverPeer;
        return false;
    }
    if (!KnownScope(scope)) {
        err = kSwarmDiscoverScope;
        return false;
    }
    if (now_ms >= until_ms) {
        err = kSwarmDiscoverExpired;
        return false;
    }
    if (m_offers.find(peer) != m_offers.end()) {
        err = kSwarmDiscoverReplay;
        return false;
    }

    OfferRecord record;
    record.scope = scope;
    record.endpoint = endpoint;
    record.until_ms = until_ms;
    record.granted = false;
    m_offers.emplace(peer, std::move(record));
    err.clear();
    return true;
}

bool SwarmDiscover::Grant(const std::string& peer, const std::string& scope, std::string& err)
{
    const auto it = m_offers.find(peer);
    if (it == m_offers.end()) {
        err = kSwarmDiscoverPeer;
        return false;
    }
    if (scope != it->second.scope) {
        err = kSwarmDiscoverScope;
        return false;
    }
    it->second.granted = true;
    err.clear();
    return true;
}

bool SwarmDiscover::Use(const std::string& peer, std::string& err)
{
    const auto it = m_offers.find(peer);
    if (it == m_offers.end() || !it->second.granted) {
        err = kSwarmDiscoverNotAuthorized;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmDiscover::Scan(const std::string& prefix, std::string& err)
{
    // The prefix is not walked. Discovery does not scan.
    (void)prefix;
    err = kSwarmDiscoverNotScan;
    return false;
}

bool SwarmDiscover::Route(const std::string& object_id, const std::string& peer, const std::string& grant_id, int64_t rtt_ms, std::string& err)
{
    if (object_id.empty() || grant_id.empty()) {
        err = kSwarmDiscoverRoute;
        return false;
    }
    const auto offer = m_offers.find(peer);
    if (offer == m_offers.end() || !offer->second.granted) {
        err = kSwarmDiscoverNotAuthorized;
        return false;
    }
    if (rtt_ms < 0) {
        err = kSwarmDiscoverRtt;
        return false;
    }

    const auto existing = m_routes.find(object_id);
    if (existing == m_routes.end()) {
        RouteRecord record;
        record.peer = peer;
        record.grant_id = grant_id;
        record.rtt_ms = rtt_ms;
        m_routes.emplace(object_id, std::move(record));
        err.clear();
        return true;
    }

    // Scope is decided before a lower rtt is allowed to replace the peer.
    if (existing->second.grant_id != grant_id) {
        err = kSwarmDiscoverScope;
        return false;
    }
    if (rtt_ms < existing->second.rtt_ms) {
        existing->second.peer = peer;
        existing->second.rtt_ms = rtt_ms;
        err.clear();
        return true;
    }
    err = kSwarmDiscoverRtt;
    return false;
}

bool SwarmDiscover::Partition(bool reachable, std::string& err)
{
    if (!reachable) {
        m_status = kSwarmDiscoverPartition;
        err = kSwarmDiscoverPartition;
        return false;
    }
    m_status = kSwarmDiscoverLocal;
    err.clear();
    return true;
}

bool SwarmDiscover::offered(const std::string& peer) const
{
    return m_offers.find(peer) != m_offers.end();
}

bool SwarmDiscover::granted(const std::string& peer) const
{
    const auto it = m_offers.find(peer);
    return it != m_offers.end() && it->second.granted;
}

std::string SwarmDiscover::scope_of(const std::string& peer) const
{
    const auto it = m_offers.find(peer);
    if (it == m_offers.end()) {
        return {};
    }
    return it->second.scope;
}

std::string SwarmDiscover::endpoint_of(const std::string& peer) const
{
    const auto it = m_offers.find(peer);
    if (it == m_offers.end()) {
        return {};
    }
    return it->second.endpoint;
}

int64_t SwarmDiscover::until_ms_of(const std::string& peer) const
{
    const auto it = m_offers.find(peer);
    if (it == m_offers.end()) {
        return 0;
    }
    return it->second.until_ms;
}

bool SwarmDiscover::routed(const std::string& object_id) const
{
    return m_routes.find(object_id) != m_routes.end();
}

std::string SwarmDiscover::route_peer(const std::string& object_id) const
{
    const auto it = m_routes.find(object_id);
    if (it == m_routes.end()) {
        return {};
    }
    return it->second.peer;
}

std::string SwarmDiscover::route_grant_id(const std::string& object_id) const
{
    const auto it = m_routes.find(object_id);
    if (it == m_routes.end()) {
        return {};
    }
    return it->second.grant_id;
}

int64_t SwarmDiscover::route_rtt_ms(const std::string& object_id) const
{
    const auto it = m_routes.find(object_id);
    if (it == m_routes.end()) {
        return 0;
    }
    return it->second.rtt_ms;
}

const std::string& SwarmDiscover::status() const
{
    return m_status;
}

bool SwarmDiscover::launched() const
{
    return kSwarmDiscoverLaunched;
}

bool SwarmDiscover::gpu() const
{
    return kSwarmDiscoverGpu;
}

bool SwarmDiscover::broadcast() const
{
    return kSwarmDiscoverBroadcast;
}

bool SwarmDiscover::connected() const
{
    return kSwarmDiscoverConnected;
}

std::string SwarmDiscover::automatic_spend() const
{
    return std::string{kSwarmDiscoverAutomaticSpend};
}

int64_t SwarmDiscover::bytes_moved() const
{
    return kSwarmDiscoverBytesMoved;
}

} // namespace modelnet
