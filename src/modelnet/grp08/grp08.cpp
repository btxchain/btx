// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp08/grp08.h>
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

bool Grp08::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp08::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp08::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp08::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp08::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp08::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp08::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp08::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp08::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp08::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp08::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp08::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DT-DAT-008") {
        if (text.empty()) { err = "REVISION"; return false; }
        if (Has(id) && text_of(id) == text) { err = NIFDT_REPLAY; return false; }
        if (Has(id)) { err = "ALTERED"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-RLP-001") {
        int bars = 0;
        for (char c : text) if (c == '|') ++bars;
        if (text.empty() || bars != 3) { err = "POLICY"; return false; }
        if (Has(id) && text_of(id) != text) { err = "COMPAT"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-RLP-002") {
        const size_t c = text.find(',');
        int64_t a = 0, b = 0;
        if (c == std::string::npos || !ParseI64(text.substr(0, c), a) || !ParseI64(text.substr(c + 1), b)) { err = "GROUP"; return false; }
        const int64_t mean = (a + b) / 2;
        const int64_t left = a - mean;
        const int64_t right = b - mean;
        Put(id, 1, std::to_string(left) + "," + std::to_string(right));
        err.clear();
        return true;
    }
    if (id == "DT-RLP-003") {
        if (!flag) { err = "GROUP"; return false; }
        const size_t c = text.find(',');
        int64_t a = 0, b = 0;
        if (c == std::string::npos || !ParseI64(text.substr(0, c), a) || !ParseI64(text.substr(c + 1), b)) { err = "GROUP"; return false; }
        const int64_t mean = (a + b) / 2;
        Put(id, 1, std::to_string(a - mean) + "," + std::to_string(b - mean));
        err.clear();
        return true;
    }
    if (id == "DT-RLP-004") {
        if (aux < 0 || aux > 2) { err = "STALE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "lag2");
        err.clear();
        return true;
    }
    if (id == "DT-RLP-005") {
        if (op == "need") {
            if (stored(id) < aux) { err = "SHORT"; return false; }
            err.clear();
            return true;
        }
        if (flag) {
            if (!Has(id)) Put(id, 0, "open");
            err.clear();
            return true;
        }
        if (aux < 1) { err = "LENGTH"; return false; }
        const int64_t n = Has(id) ? stored(id) : 0;
        Put(id, n + 1, "full");
        err.clear();
        return true;
    }
    if (id == "DT-RLP-008") {
        if (op.empty() || text.empty()) { err = "RIGHTS"; return false; }
        if (op == text) { err = "SELF"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-CKP-001") {
        if (text.empty()) { err = "MANIFEST"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-CKP-002") {
        if (flag) { err = "BUFFER"; return false; }
        if (aux < 1 || aux > 4194304) { err = "PIECE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "piece");
        err.clear();
        return true;
    }
    if (id == "DT-CKP-003") {
        if (text == "PYTHON_PICKLE" || text == "elf") { err = "CODE"; return false; }
        if (text.empty()) { err = "BODY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-CKP-005") {
        if (text.empty()) { err = "GENERATION"; return false; }
        if (!flag) { err = "JOURNAL"; return false; }
        if (Has(id) && text_of(id) == text) { err = NIFDT_REPLAY; return false; }
        const int64_t n = Has(id) ? stored(id) : 0;
        Put(id, n + 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-CKP-006") {
        if (op == "mutate") {
            if (!Has(id)) { err = "ORDER"; return false; }
            err = "IMMUTABLE";
            return false;
        }
        if (text.empty()) { err = "SNAP"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-CKP-007") {
        if (text == "PYTHON_PICKLE" || text == "elf") { err = "CODE"; return false; }
        if (op != "export") { err = "ORDER"; return false; }
        if (text.empty()) { err = "BODY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-CKP-008") {
        if (op == "promote" || op == "activate") { err = NIFDT_UNQUALIFIED; return false; }
        if (op != "valid") { err = "ORDER"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "valid");
        err.clear();
        return true;
    }
    if (id == "DT-WAN-001") {
        if (op == "perlayer" || flag) { err = NIFDT_NO_ROUTE; return false; }
        if (op != "coarse") { err = "ORDER"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "coarse");
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
