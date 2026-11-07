// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp23/grp23.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp23::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp23::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp23::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp23::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp23::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp23::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp23::classification(const std::string& id) const
{
    if (id.rfind("P2P-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp23::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp23::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp23::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp23::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp23::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id == "DS-STD-002") {
        if (aux > static_cast<int64_t>(100) || aux < static_cast<int64_t>(1)) {
            err = "BOUND";
            return false;
        }
        if (!flag) {
            err = "TAXII";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-STD-003") {
        if (extra.empty()) {
            err = "OCSF";
            return false;
        }
        if (Has(id) && text_of(id) != text) {
            err = "LINEAGE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-STD-004") {
        if (extra.empty()) {
            err = "BACKEND";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-STD-005") {
        if (text == "malformed" || aux > static_cast<int64_t>(1000000) || aux < static_cast<int64_t>(1)) {
            err = "MALFORMED";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-STD-006") {
        if (text != "contain" && text != "allow" && text != "deny" && text != "log") {
            err = "CACAO";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-A") {
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "local");
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-B") {
        err = "HINT";
        return false;
    }
    if (id == "P2P-SCN-C") {
        if (op != "airgap") {
            err = NIFDT_NO_ROUTE;
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "lan");
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-D") {
        if (aux != static_cast<int64_t>(1)) {
            err = "HOSTS";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-E") {
        if (op == "lose") {
            err = "KEPT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-F") {
        if (text.find("cloud") != std::string::npos) {
            err = "SCHEDULER";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-G") {
        if (text.find("api-key") != std::string::npos || text != "memory") {
            err = "API";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "memory");
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-H") {
        if (text != "local-kv") {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "local-kv");
        err.clear();
        return true;
    }
    if (id == "P2P-SCN-I") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "P2P-SCN-J") {
        if (extra.empty() || extra == text) {
            err = "SELF";
            return false;
        }
        if (aux < static_cast<int64_t>(2)) {
            err = "QUORUM";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text + "," + extra);
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
