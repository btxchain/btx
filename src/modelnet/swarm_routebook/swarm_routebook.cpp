// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_routebook/swarm_routebook.h>

#include <modelnet/swarm_routebook/bind.h>
#include <modelnet/swarm_routebook/claim.h>
#include <modelnet/swarm_routebook/codes.h>
#include <modelnet/swarm_routebook/hashlock.h>
#include <modelnet/swarm_routebook/sighash.h>
#include <modelnet/swarm_routebook/types.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmRouteBook::AddHop(const std::string& route, const std::string& hop, int64_t cltv_expiry, std::string& err)
{
    return m_ledger.AddHop(route, hop, cltv_expiry, err);
}

bool SwarmRouteBook::Bind(const std::string& route, int64_t upstream_delta, std::string& err)
{
    SwarmRouteBookPath* path = m_ledger.Find(route);
    if (path == nullptr) {
        err = SWARM_ROUTEBOOK_ROUTE;
        return false;
    }
    return SwarmRouteBookApplyBind(*path, upstream_delta, err);
}

bool SwarmRouteBook::Hashlock(const std::string& route, int64_t preimage_len, std::string& err)
{
    return SwarmRouteBookClassifyHashlock(m_ledger.known(route), preimage_len, err);
}

bool SwarmRouteBook::Sighash(const std::string& route, bool covers_outputs, std::string& err)
{
    SwarmRouteBookPath* path = m_ledger.Find(route);
    if (path == nullptr) {
        err = SWARM_ROUTEBOOK_ROUTE;
        return false;
    }
    return SwarmRouteBookApplySighash(*path, covers_outputs, err);
}

bool SwarmRouteBook::Claim(const std::string& route, std::string& err)
{
    return SwarmRouteBookRefuseClaim(route, err);
}

int64_t SwarmRouteBook::hop_count(const std::string& route) const
{
    return m_ledger.hop_count(route);
}

int64_t SwarmRouteBook::required_slack(const std::string& route) const
{
    return m_ledger.required_slack(route);
}

int64_t SwarmRouteBook::bound_delta(const std::string& route) const
{
    return m_ledger.bound_delta(route);
}

bool SwarmRouteBook::cltv_expiry(const std::string& route, const std::string& hop, int64_t& expiry) const
{
    return m_ledger.cltv_expiry(route, hop, expiry);
}

bool SwarmRouteBook::outputs_covered(const std::string& route) const
{
    return m_ledger.outputs_covered(route);
}

bool SwarmRouteBook::qualified() const
{
    return m_flags.qualified();
}

bool SwarmRouteBook::secp_penalty() const
{
    return m_flags.secp_penalty();
}

bool SwarmRouteBook::broadcast() const
{
    return m_flags.broadcast();
}

bool SwarmRouteBook::launched() const
{
    return m_flags.launched();
}

bool SwarmRouteBook::gpu() const
{
    return m_flags.gpu();
}

int64_t SwarmRouteBook::atoms_moved() const
{
    return m_flags.atoms_moved();
}

std::string SwarmRouteBook::automatic_spend() const
{
    return m_flags.automatic_spend();
}

bool SwarmRouteBook::signed_ok() const
{
    return m_flags.signed_ok();
}

} // namespace modelnet
