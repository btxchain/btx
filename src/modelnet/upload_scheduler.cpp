// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/upload_scheduler.h>

#include <algorithm>

namespace modelnet {

UploadScheduler::UploadScheduler(UploadAdmission adm) : m_adm(adm) {}

UploadDecision UploadScheduler::Admit(const UploadRequest& req)
{
    UploadDecision d;
    if (m_active >= m_adm.slots) {
        d.reason = "slots full";
        return d;
    }
    const int id_n = static_cast<int>(std::count(m_identities.begin(), m_identities.end(), req.identity));
    if (!req.identity.empty() && id_n >= m_adm.per_identity) {
        d.reason = "per-identity";
        return d;
    }
    const int ng_n = static_cast<int>(std::count(m_netgroups.begin(), m_netgroups.end(), req.netgroup));
    if (!req.netgroup.empty() && ng_n >= m_adm.per_netgroup) {
        d.reason = "per-netgroup";
        return d;
    }
    d.admitted = true;
    d.slot = m_active;
    m_identities.push_back(req.identity);
    m_netgroups.push_back(req.netgroup);
    ++m_active;
    return d;
}

void UploadScheduler::Release(const UploadRequest& req)
{
    if (m_active > 0) --m_active;
    auto it = std::find(m_identities.begin(), m_identities.end(), req.identity);
    if (it != m_identities.end()) m_identities.erase(it);
    auto ng = std::find(m_netgroups.begin(), m_netgroups.end(), req.netgroup);
    if (ng != m_netgroups.end()) m_netgroups.erase(ng);
}

} // namespace modelnet
