// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp01/grp01.h>
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

bool Grp01::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp01::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp01::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp01::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp01::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp01::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp01::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp01::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "NIF-NAT-001") {
        if (op != "btxd") { err = "OWNER"; return false; }
        if (!text.empty()) { err = "FLAG"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "btxd");
        err.clear();
        return true;
    }
    if (id == "NIF-NAT-002") {
        const size_t bar = extra.find('|');
        if (text.empty() || op.empty() || bar == std::string::npos || extra.substr(0, bar).empty() || extra.substr(bar + 1).empty()) {
            err = "BIND";
            return false;
        }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 4, text);
        err.clear();
        return true;
    }
    if (id == "NIF-NAT-003") {
        if (text.empty()) { err = "REQUEST"; return false; }
        if (!flag) { err = "JOURNAL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "NIF-NAT-004") {
        if (aux < 1) { err = "BYTES"; return false; }
        if (aux > 100) { err = "CAPACITY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "reserved");
        err.clear();
        return true;
    }
    if (id == "NIF-NAT-005") {
        if (op != "fail") { err = "WORKER"; return false; }
        if (!Has(id)) Put(id, 1, "ok");
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "NIF-NAT-006") {
        if (text != "component" && text != "native") { err = "CLASS"; return false; }
        if (op.empty()) { err = "NAME"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, text == "native" ? 2 : 1, op);
        err.clear();
        return true;
    }
    if (id == "NIF-FORK-001") {
        if (text != "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01") { err = "PIN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 40, text);
        err.clear();
        return true;
    }
    if (id == "NIF-FORK-002") {
        if (text.empty()) { err = "LICENSE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(text.size()), text);
        err.clear();
        return true;
    }
    if (id == "NIF-FORK-003") {
        if (text.empty()) { err = "GENERATION"; return false; }
        if (Has(id) && text_of(id) != text) { err = "GENERATION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-FORK-004") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "NIF-FORK-005") {
        if (text != "local") { err = "SCOPE"; return false; }
        if (aux < 1) { err = "BATCH"; return false; }
        if (flag) { err = NIFDT_ENGINE_ABSENT; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "local");
        err.clear();
        return true;
    }
    if (id == "NIF-FORK-006") {
        if (op == "apply") { err = "UPGRADE"; return false; }
        if (text.empty()) { err = "DELTA"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PROF-001") {
        if (text.empty()) { err = "PLATFORM"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PROF-002") {
        if (text == "deepseek-v4.1" || text == "v4.1") { err = "V41"; return false; }
        if (text.empty()) { err = "PROFILE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PROF-003") {
        if (text.empty()) { err = "DOMAIN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PROF-004") {
        if (text != "throughput" && text != "approximate") { err = "CLASS"; return false; }
        if (!LowerHex(op, 2)) { err = "DIGEST"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, op);
        if (!Has(id)) Put(id, 1, op);
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
