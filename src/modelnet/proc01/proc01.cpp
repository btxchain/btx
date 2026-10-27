// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc01/proc01.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

bool Proc01::Observe(const std::string& id, bool advertised, bool measured, const std::string& evidence, std::string& err)
{
    if (id.empty()) {
        err = "ID";
        return false;
    }
    if (m_rows.find(id) != m_rows.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (advertised && !measured) {
        // Evidence is ignored. The stored capability stays unqualified.
        m_rows.emplace(id, Row{true, false});
        err.clear();
        return true;
    }
    if (!advertised && measured) {
        // A measurement cannot qualify a capability that was not advertised.
        m_rows.emplace(id, Row{false, false});
        err.clear();
        return true;
    }
    if (advertised && measured && evidence.empty()) {
        err = "FIELD";
        return false;
    }
    if (advertised && measured && evidence == "claim") {
        err = "CLAIM";
        return false;
    }
    if (advertised && measured && !evidence.empty()) {
        m_rows.emplace(id, Row{true, true});
        err.clear();
        return true;
    }
    err = "FIELD";
    return false;
}

bool Proc01::advertised(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return false;
    return it->second.advertised;
}

bool Proc01::qualified(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return false;
    return it->second.qualified;
}

int Proc01::count() const
{
    return static_cast<int>(m_rows.size());
}

} // namespace modelnet
