// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp21/grp21.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool PathWords(const std::string& text)
{
    return text.find("expiry") != std::string::npos &&
           text.find("fee") != std::string::npos &&
           text.find("stale") != std::string::npos &&
           text.find("watch") != std::string::npos;
}

bool Listed(const std::string& joined, const std::string& text)
{
    if (text.empty()) return false;
    std::string::size_type start = 0;
    while (start <= joined.size()) {
        const std::string::size_type comma = joined.find(',', start);
        const std::string::size_type end = comma == std::string::npos ? joined.size() : comma;
        if (joined.compare(start, end - start, text) == 0) return true;
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

} // namespace

bool Grp21::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp21::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp21::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp21::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || it->second.n == static_cast<int64_t>(0)) {
        return static_cast<int64_t>(0);
    }
    return it->second.n;
}

std::string Grp21::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp21::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp21::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp21::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp21::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp21::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp21::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp21::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id == "DS-PAY-002") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DS-PAY-003") {
        if (!PathWords(text)) {
            err = "PATH";
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
    if (id == "DS-PAY-004") {
        if (op == "credit") {
            err = "SEPARATE";
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
    if (id == "DS-PAY-005") {
        if (aux < static_cast<int64_t>(1)) {
            err = "LIQUIDITY";
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
    if (id == "DS-PAY-006") {
        if (op == "fail" || op == "reorg") {
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (!text_of(id).empty()) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (text.empty()) {
            err.clear();
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-PLAN-001") {
        if (op == "negative") {
            if (!Has(id)) {
                if (text.empty()) {
                    err = "HYPOTHESIS";
                    return false;
                }
                Put(id, static_cast<int64_t>(1), text);
            }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (text.empty()) {
            err = "HYPOTHESIS";
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
    if (id == "DS-PLAN-002") {
        if (extra.empty() || extra == text) {
            err = "SERIAL";
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
    if (id == "DS-PLAN-003") {
        if (aux == static_cast<int64_t>(0)) {
            err = "PROGRESS";
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
    if (id == "DS-PLAN-004") {
        if (op == "retract") {
            if (!Has(id)) {
                err.clear();
                return false;
            }
            const std::string kept = text_of(id);
            Put(id, static_cast<int64_t>(0), kept);
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        const int64_t n = aux > static_cast<int64_t>(0) ? aux : static_cast<int64_t>(1);
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "DS-PLAN-005") {
        if (aux > static_cast<int64_t>(8) || aux < static_cast<int64_t>(1)) {
            err = "COST";
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
    if (id == "DS-PLAN-006") {
        if (op == "lost") {
            err = "KEPT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (text.empty()) {
            err.clear();
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-POOL-001") {
        if (text != "readiness" && text != "incident" && text != "family") {
            err = "POOL";
            return false;
        }
        if (Listed(text_of(id), text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (Has(id)) {
            const int64_t n = stored(id) + static_cast<int64_t>(1);
            Put(id, n, text_of(id) + "," + text);
        } else {
            Put(id, static_cast<int64_t>(1), text);
        }
        err.clear();
        return true;
    }
    if (id == "DS-POOL-002") {
        if (Has(id)) {
            if (extra == text_of(id)) {
                err = "COLLATERAL";
                return false;
            }
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), extra);
        err.clear();
        return true;
    }
    if (id == "DS-POOL-003") {
        if (!flag || aux <= static_cast<int64_t>(0)) {
            err = "BALANCE";
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
    if (id == "DS-POOL-004") {
        if (text == "membership") {
            err = "MEMBER";
            return false;
        }
        if (text != "work" && text != "readiness") {
            err = "BYTES";
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
    err = "ID";
    return false;
}

} // namespace modelnet
