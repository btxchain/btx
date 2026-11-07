// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp14/grp14.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp14::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp14::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp14::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp14::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || it->second.n == static_cast<int64_t>(0)) {
        return static_cast<int64_t>(0);
    }
    return it->second.n;
}

std::string Grp14::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp14::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp14::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp14::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp14::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp14::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp14::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp14::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t /*now_ms*/, int64_t aux, bool flag, std::string& err)
{
    if (id == "ASR-NAT-005") {
        if (aux != static_cast<int64_t>(0)) {
            err = "BUDGET";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(0), "observer");
        err.clear();
        return true;
    }
    if (id == "ASR-NAT-006") {
        if (Has(id) && text != text_of(id)) {
            err = "POLICY";
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
    if (id == "ASR-NET-001") {
        m_wire.Scan(text, err);
        err = NIFDT_NOT_SCAN;
        return false;
    }
    if (id == "ASR-NET-002") {
        if (text == "wan") {
            m_wire.Wan(err);
            err = NIFDT_NO_ROUTE;
            return false;
        }
        if (text != "local") {
            err = "SCOPE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "local");
        err.clear();
        return true;
    }
    if (id == "ASR-NET-003") {
        if (extra.empty()) {
            err = "GRANT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), extra);
        err.clear();
        return true;
    }
    if (id == "ASR-NET-004") {
        if (!flag) {
            err = "PINNED";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "ASR-NET-005") {
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "limited");
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "ASR-OBS-001") {
        if (op == "qualify") {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
        if (op != "advertise") {
            err = "STATUS";
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
    if (id == "ASR-PAY-001") {
        if (!text.empty() && text == extra) {
            err = "POOL";
            return false;
        }
        if (aux <= static_cast<int64_t>(0)) {
            err = "BYTES";
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
    if (id == "ASR-PAY-002") {
        if (op == "fail") {
            if (!Has(id)) {
                Put(id, static_cast<int64_t>(1), text);
            }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-PAY-003") {
        if (!Has(id)) {
            Put(id, static_cast<int64_t>(1), extra);
            err.clear();
            return true;
        }
        if (extra != text_of(id)) {
            err = "TERMS";
            return false;
        }
        err = NIFDT_REPLAY;
        return false;
    }
    if (id == "ASR-PAY-004") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "ASR-PLN-001") {
        if (text.empty()) {
            err = "PLAN";
            return false;
        }
        if (op == "replace") {
            if (!Has(id)) {
                err = "PLAN";
                return false;
            }
            err.clear();
            return true;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-PLN-002") {
        if (text.empty()) {
            err = "CURSOR";
            return false;
        }
        if (Has(id) && text == text_of(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        const int64_t n = Has(id) ? stored(id) + static_cast<int64_t>(1) : static_cast<int64_t>(1);
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "ASR-PLN-003") {
        if (Has(id) && aux < stored(id)) {
            err = "STALE";
            return false;
        }
        if (aux > static_cast<int64_t>(0)) {
            Put(id, aux, text);
            err.clear();
            return true;
        }
        err = "GEN";
        return false;
    }
    if (id == "ASR-PLN-004") {
        if (aux > static_cast<int64_t>(8) || aux < static_cast<int64_t>(1)) {
            err = "COST";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, std::to_string(aux));
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
