// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp07/grp07.h>
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

bool Grp07::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp07::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp07::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp07::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp07::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp07::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp07::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp07::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp07::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp07::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp07::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp07::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DT-OPT-001") {
        if (text != "adamw" && text != "sgd") { err = "RECIPE"; return false; }
        if (Has(id) && text_of(id) != text) { err = "FROZEN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-OPT-002") {
        if (text != "matrix" && text != "embedding" && text != "scalar") { err = "ROLE"; return false; }
        if (op.empty()) { err = "RULE"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, op);
        int64_t n = 0;
        if (Has(id + "#matrix")) ++n;
        if (Has(id + "#embedding")) ++n;
        if (Has(id + "#scalar")) ++n;
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "DT-OPT-003") {
        if (!flag || text != "finite") { err = "FINITE"; return false; }
        if (!Has(id)) Put(id, 10, "w");
        Put(id, stored(id) - 1, "w");
        err.clear();
        return true;
    }
    if (id == "DT-OPT-004") {
        if (text.empty()) { err = "STATE"; return false; }
        int bars = 0;
        for (char c : text) if (c == '|') ++bars;
        if (bars != 3) { err = "STATE"; return false; }
        if (!flag) { err = "JOURNAL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-OPT-005") {
        if (text == "fp8" || text == "fp4") { err = NIFDT_ENGINE_ABSENT; return false; }
        if (text != "fp32") { err = "PROFILE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux < 1 ? 1 : aux, text);
        err.clear();
        return true;
    }
    if (id == "DT-OPT-006") {
        if (text == "fp4-weight" || text == "fp4-grad" || text == "fp4-optimizer") { err = NIFDT_ENGINE_ABSENT; return false; }
        if (text != "fp4-cache") { err = "LABEL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-OPT-007") {
        if (text != "adamw" && text != "sgd") { err = "RECIPE"; return false; }
        if (Has(id) && text_of(id) != text) { err = "FROZEN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-OPT-008") {
        if (op == "draft") {
            Put(id + "#draft", aux, "draft");
            if (!Has(id)) Put(id, 1, "backbone");
            err.clear();
            return true;
        }
        if (op == "backbone") {
            if (text != "authorized") { err = "RECIPE"; return false; }
            Put(id, 2, "backbone");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-DAT-001") {
        if (extra.empty()) { err = "LICENSE"; return false; }
        if (text != "public_trajectory" && text != "synthetic_trajectory") { err = NIFDT_PRIVATE_DATA; return false; }
        if (op != "training" && op != "evaluation") { err = "PURPOSE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-DAT-002") {
        if (op != "training" && op != "validation" && op != "evaluation") { err = "PURPOSE"; return false; }
        Put(id + "#" + op, aux, op);
        if (op == "training") Put(id, aux, "training");
        else if (!Has(id)) Put(id, 0, "isolated");
        err.clear();
        return true;
    }
    if (id == "DT-DAT-003") {
        if (text.empty()) { err = "PACK"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-DAT-004") {
        if (text.empty()) { err = "CURSOR"; return false; }
        if (!flag) { err = "JOURNAL"; return false; }
        if (Has(id) && text_of(id) == text && stored(id) == aux) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DT-DAT-005") {
        if (text.empty()) { err = "SHARD"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-DAT-006") {
        if (text == "learnable") { err = "FREEZE"; return false; }
        if (text.empty()) { err = "CACHE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-DAT-007") {
        if (text.find("solution") != std::string::npos) { err = "LEAK"; return false; }
        if (text.empty()) { err = "TASK"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
