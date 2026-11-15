// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_egress/nif_egress.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <string>
#include <vector>

namespace modelnet {

bool NifEgress::KnownScope(const std::string& scope)
{
    return scope == "local" || scope == "lan" || scope == "peer";
}

bool NifEgress::SetScope(const std::string& scope, std::string& err)
{
    if (!KnownScope(scope)) {
        err = NIF_EGRESS_SCOPE;
        return false;
    }
    m_scope = scope;
    err.clear();
    return true;
}

void NifEgress::SetAirgap(bool on)
{
    m_airgap = on;
}

bool NifEgress::Send(const std::vector<unsigned char>& payload, std::string& err)
{
    if (m_airgap) {
        err = NIF_EGRESS_POLICY;
        return false;
    }
    if (m_scope == "local") {
        if (payload.empty()) {
            err = kSwarmLanWirePayload;
            return false;
        }
        m_stored = payload;
        err.clear();
        return true;
    }
    if (m_scope != "lan" && m_scope != "peer") {
        err = NIF_EGRESS_SCOPE;
        return false;
    }
    if (!m_wire.Exchange(payload, err)) {
        return false;
    }
    m_stored = m_wire.received();
    return true;
}

bool NifEgress::SendWan(std::string& err)
{
    m_wire.Wan(err);
    err = NIFDT_NO_ROUTE;
    return false;
}

bool NifEgress::Scan(const std::string& prefix, std::string& err)
{
    m_wire.Scan(prefix, err);
    err = NIFDT_NOT_SCAN;
    return false;
}

} // namespace modelnet
