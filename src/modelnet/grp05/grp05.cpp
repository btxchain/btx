// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp05/grp05.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool ParseI64(const std::string& s, int64_t& out)
{
    if (s.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
        if (i == s.size()) return false;
    }
    __int128 v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (s[i] - '0');
        if (v > static_cast<__int128>(INT64_MAX)) return false;
    }
    if (neg) v = -v;
    out = static_cast<int64_t>(v);
    return true;
}

bool AddOk(int64_t a, int64_t b, int64_t& out)
{
    const __int128 s = static_cast<__int128>(a) + static_cast<__int128>(b);
    if (s > static_cast<__int128>(INT64_MAX) || s < static_cast<__int128>(INT64_MIN)) return false;
    out = static_cast<int64_t>(s);
    return true;
}

bool MulOk(int64_t a, int64_t b, int64_t& out)
{
    const __int128 s = static_cast<__int128>(a) * static_cast<__int128>(b);
    if (s > static_cast<__int128>(INT64_MAX) || s < static_cast<__int128>(INT64_MIN)) return false;
    out = static_cast<int64_t>(s);
    return true;
}

bool LowerHex(const std::string& s, size_t n)
{
    if (s.size() != n) return false;
    for (unsigned char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

} // namespace

bool Grp05::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp05::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp05::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp05::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp05::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp05::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp05::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp05::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp05::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp05::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp05::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DT-EVD-001") {
        if (text != "documented" && text != "hypothesis" && text != "design") { err = "CLASS"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, text);
        int64_t n = Has(id) ? stored(id) : 0;
        Put(id, n + 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-002") {
        if (text.empty()) { err = "BASELINE"; return false; }
        if (Has(id) && text_of(id) != text) { err = "ALTERED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-003") {
        if (op == "replace") { err = "REPLACE"; return false; }
        if (text != "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01") { err = "PIN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-004") {
        if (text != "grok-4.7-high") { err = "MODEL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-005") {
        if (op == "git") { err = "PRIVATE"; return false; }
        if (text != "outside") { err = "STORE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-006") {
        if (text != "component" && text != "native" && text != "hardware" && text != "release") { err = "CLASS"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, text);
        int64_t n = Has(id) ? stored(id) : 0;
        Put(id, n + 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-007") {
        if (text.empty()) { err = "ATTRIBUTION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-EVD-008") {
        if (text == "complete" || text == "missing") { err = "UNINSPECTED"; return false; }
        if (text != "uninspected") { err = "CLASS"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 0, text);
        err.clear();
        return true;
    }
    if (id == "DT-NAT-001") {
        if (op != "btxd") { err = "OWNER"; return false; }
        if (!text.empty()) { err = "FLAG"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "btxd");
        err.clear();
        return true;
    }
    if (id == "DT-NAT-002") {
        if (text.empty()) { err = "COHORT"; return false; }
        if (now_ms >= aux) { err = "EXPIRED"; return false; }
        if (op == "commit") {
            if (!Has(id) || text_of(id) != text) { err = "COHORT"; return false; }
            if (bit_of(id)) { err = NIFDT_REPLAY; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-NAT-003") {
        if (text.empty()) { err = "COHORT"; return false; }
        if (now_ms >= aux) { err = "EXPIRED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-NAT-004") {
        if (op == "schedule") {
            if (!Has(id)) { err = "ORDER"; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op != "reserve") { err = "ORDER"; return false; }
        if (aux < 1) { err = "BYTES"; return false; }
        if (aux > 100) { err = "CAPACITY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "reserved");
        err.clear();
        return true;
    }
    if (id == "DT-NAT-005") {
        if (op == "reserve") {
            if (aux < 1) { err = "BYTES"; return false; }
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, aux, "held");
            err.clear();
            return true;
        }
        if (op == "cancel") {
            if (!Has(id)) { err = "REQUEST"; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        err = "PINNED";
        return false;
    }
    if (id == "DT-NAT-006") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-NAT-007") {
        if (op == "stage") {
            if (text.empty()) { err = "CANDIDATE"; return false; }
            Put(id + "#cand", aux, text);
            if (!Has(id)) Put(id, 0, "staged");
            err.clear();
            return true;
        }
        if (op == "commit") {
            if (!Has(id + "#cand")) { err = "PLAN"; return false; }
            if (!flag) { err = "JOURNAL"; return false; }
            Put(id, stored(id + "#cand"), text_of(id + "#cand"));
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-NAT-008") {
        if (flag) { err = "API"; return false; }
        if (op == "wan") { err = NIFDT_NO_ROUTE; return false; }
        if (text != "local") { err = "SCOPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
