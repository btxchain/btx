// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_scope/nif_scope.h>

namespace modelnet {

bool NifScope::SetPolicy(NifPrivacy policy, std::string& err)
{
    m_policy = policy;
    err.clear();
    return true;
}

bool NifScope::ObserveBeacon(const std::string& endpoint, std::string& err)
{
    if (endpoint.empty()) {
        err = "ENDPOINT";
        return false;
    }
    m_beacon = endpoint;
    err.clear();
    return true;
}

bool NifScope::SendLocal(const std::vector<unsigned char>& payload, std::string& err)
{
    if (payload.empty()) {
        err = "PAYLOAD";
        return false;
    }
    if (m_policy == NifPrivacy::LocalOnly) {
        m_received = payload;
        err.clear();
        return true;
    }
    if (!m_lan.Exchange(payload, err)) return false;
    m_received = m_lan.received();
    err.clear();
    return true;
}

bool NifScope::SendWan(std::string& err)
{
    return m_lan.Wan(err);
}

bool NifScope::Scan(const std::string& prefix, std::string& err)
{
    return m_lan.Scan(prefix, err);
}

} // namespace modelnet
