// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp04/grp04.h>
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

bool Grp04::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp04::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp04::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp04::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp04::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp04::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp04::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp04::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp04::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp04::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "NIF-DATA-004") {
        if (op == "remote") { err = "DOWNLOAD"; return false; }
        if (!flag) { err = "DENIED"; return false; }
        if (text == "PYTHON_PICKLE" || text == "elf") { err = "CODE"; return false; }
        if (text.empty()) { err = "MEDIA"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(text.size()), text);
        err.clear();
        return true;
    }
    if (id == "NIF-DATA-005") {
        if (text.empty() || op.empty()) { err = "CASE"; return false; }
        if (text != "public") { err = NIFDT_PRIVATE_DATA; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-ECON-001") {
        if (op == "draft") {
            if (aux < 1) { err = "ATOMS"; return false; }
            Put(id + "#draft", aux, "draft");
            if (!Has(id)) Put(id, 0, "draft");
            err.clear();
            return true;
        }
        if (op == "accept") {
            if (!Has(id + "#draft")) { err = "DRAFT"; return false; }
            if (bit_of(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, aux, "accepted");
            SetBit(id, true);
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "NIF-ECON-002") {
        if (aux < 0 || now_ms < 0) { err = "BOUND"; return false; }
        if (aux > now_ms) { err = "OVER"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "quote");
        err.clear();
        return true;
    }
    if (id == "NIF-ECON-003") {
        if (flag) {
            if (!Has(id)) Put(id, 0, "");
            SetBit(id, true);
            err = "STALE";
            return false;
        }
        if (op == "pay") {
            if (bit_of(id)) { err = "STALE"; return false; }
            err = "HELD";
            return false;
        }
        err = "ORDER";
        return false;
    }
    if (id == "NIF-ECON-004") {
        if (text == "wallet") { err = "WALLET"; return false; }
        if (text.empty()) { err = "KEY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-QA-002") {
        if (text != "fixture" && text != "useful") { err = "CLASS"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, text);
        const int64_t n = (Has(id + "#fixture") ? 1 : 0) + (Has(id + "#useful") ? 1 : 0);
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "NIF-QA-003") {
        if (text != "batch" && text != "stochastic") { err = "CLASS"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, text);
        const int64_t n = (Has(id + "#batch") ? 1 : 0) + (Has(id + "#stochastic") ? 1 : 0);
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "NIF-QA-004") {
        if (text != "cold" && text != "warm" && text != "local" && text != "remote") { err = "CLASS"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, text);
        int64_t n = 0;
        if (Has(id)) n = stored(id);
        Put(id, n + 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-QA-005") {
        if (text != "privacy" && text != "failure" && text != "resource") { err = "CLASS"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, text);
        int64_t n = Has(id) ? stored(id) : 0;
        Put(id, n + 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-QA-006") {
        if (text.empty()) { err = "PROVENANCE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-QA-007") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "NIF-GOV-001") {
        if (text != "grok-4.7-high") { err = "MODEL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-GOV-002") {
        if (op == "public") { err = "PUBLIC"; return false; }
        if (text != "private") { err = "STORE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-GOV-003") {
        if (text.empty()) { err = "OWNER"; return false; }
        if (Has(id) && text_of(id) != text) { err = "CONFLICT"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-GOV-004") {
        err = "UNAUTHORIZED";
        return false;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
