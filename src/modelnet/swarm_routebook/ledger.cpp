// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/ledger.h>

#include <modelnet/swarm_routebook/codes.h>
#include <modelnet/swarm_routebook/hops.h>
#include <modelnet/swarm_routebook/slack.h>

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmRouteBookLedger::AddHop(const std::string& route, const std::string& hop, int64_t cltv_expiry, std::string& err)
{
    if (!SwarmRouteBookNamesPresent(route, hop, err)) {
        return false;
    }
    const auto it = m_paths.find(route);
    if (it == m_paths.end()) {
        SwarmRouteBookPath created;
        if (!SwarmRouteBookAppendHop(created, hop, cltv_expiry, err)) {
            return false;
        }
        if (created.hops.empty()) {
            err = SWARM_ROUTEBOOK_ROUTE;
            return false;
        }
        m_paths.emplace(route, std::move(created));
        return true;
    }
    return SwarmRouteBookAppendHop(it->second, hop, cltv_expiry, err);
}

bool SwarmRouteBookLedger::known(const std::string& route) const
{
    return m_paths.find(route) != m_paths.end();
}

SwarmRouteBookPath* SwarmRouteBookLedger::Find(const std::string& route)
{
    const auto it = m_paths.find(route);
    if (it == m_paths.end()) {
        return nullptr;
    }
    return &it->second;
}

const SwarmRouteBookPath* SwarmRouteBookLedger::Find(const std::string& route) const
{
    const auto it = m_paths.find(route);
    if (it == m_paths.end()) {
        return nullptr;
    }
    return &it->second;
}

int64_t SwarmRouteBookLedger::hop_count(const std::string& route) const
{
    const SwarmRouteBookPath* path = Find(route);
    if (path == nullptr) {
        return 0;
    }
    return SwarmRouteBookHopCountOf(*path);
}

int64_t SwarmRouteBookLedger::required_slack(const std::string& route) const
{
    int64_t slack = 0;
    if (!SwarmRouteBookRequiredSlack(hop_count(route), slack)) {
        return std::numeric_limits<int64_t>::max();
    }
    return slack;
}

int64_t SwarmRouteBookLedger::bound_delta(const std::string& route) const
{
    const SwarmRouteBookPath* path = Find(route);
    if (path == nullptr || !path->delta_bound) {
        return 0;
    }
    return path->bound_delta;
}

bool SwarmRouteBookLedger::cltv_expiry(const std::string& route, const std::string& hop, int64_t& expiry) const
{
    const SwarmRouteBookPath* path = Find(route);
    if (path == nullptr) {
        return false;
    }
    const SwarmRouteBookHopRecord* record = SwarmRouteBookFindHop(*path, hop);
    if (record == nullptr) {
        return false;
    }
    expiry = record->cltv_expiry;
    return true;
}

bool SwarmRouteBookLedger::outputs_covered(const std::string& route) const
{
    const SwarmRouteBookPath* path = Find(route);
    return path != nullptr && path->outputs_covered;
}

} // namespace modelnet
