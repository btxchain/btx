// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp03/grp03.h>
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

bool Grp03::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp03::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp03::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp03::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp03::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp03::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp03::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp03::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp03::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp03::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp03::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "NIF-LAN-005") {
        if (op == "airgap") {
            if (!Has(id)) { err = "SCOPE"; return false; }
            SetBit(id, flag);
            err.clear();
            return true;
        }
        if (text != "local" && text != "lan" && text != "peer") { err = "SCOPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-006") {
        if (op == "discover") {
            if (bit_of(id)) { err = "DENIED"; return false; }
            err = "IFACE";
            return false;
        }
        if (text.empty()) { err = "IFACE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-007") {
        if (flag) { err = "WALLET"; return false; }
        if (text.empty()) { err = "REQUEST"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "free");
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-008") {
        if (op == "airgap") {
            if (!Has(id)) { err = "SCOPE"; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "internet") {
            if (bit_of(id) || flag) { err = "POLICY"; return false; }
            err = "POLICY";
            return false;
        }
        if (text != "local" && text != "lan" && text != "peer") { err = "SCOPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-ISL-001") {
        if (text.empty() || aux < 1) { err = "TOPOLOGY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "NIF-ISL-002") {
        if (flag) { err = NIFDT_NO_ROUTE; return false; }
        if (op != "collective") { err = "ORDER"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "local");
        err.clear();
        return true;
    }
    if (id == "NIF-ISL-003") {
        if (aux < 1) { err = "BYTES"; return false; }
        int64_t sum = aux;
        if (Has(id) && !AddOk(stored(id), aux, sum)) { err = "OVERFLOW"; return false; }
        if (sum > 8) { err = "BACKPRESSURE"; return false; }
        Put(id, sum, "queued");
        err.clear();
        return true;
    }
    if (id == "NIF-ISL-005") {
        if (op == "fail") {
            if (text.empty()) { err = "REQUEST"; return false; }
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, 1, text);
            err.clear();
            return true;
        }
        if (op == "restore") {
            if (!Has(id) || text_of(id) != text) { err = "MISMATCH"; return false; }
            err.clear();
            return true;
        }
        err = "REQUEST";
        return false;
    }
    if (id == "NIF-PKG-001") {
        if (op == "execute") { err = NIFDT_ENGINE_ABSENT; return false; }
        if (!LowerHex(text, 2)) { err = "DIGEST"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PKG-002") {
        if (!LowerHex(text, 2)) { err = "DIGEST"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PKG-003") {
        if (op == "egress") { err = "DENIED"; return false; }
        if (op == "download") { err = "DOWNLOAD"; return false; }
        if (text == "PYTHON_PICKLE" || text == "elf") { err = "CODE"; return false; }
        if (text.empty()) { err = "BODY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(text.size()), text);
        err.clear();
        return true;
    }
    if (id == "NIF-PKG-004") {
        if (text.empty() || op.empty() || text == op) { err = "AUTHORITY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-PKG-005") {
        if (op == "bind") {
            if (text.empty()) { err = "DIGEST"; return false; }
            if (!Has(id)) { Put(id, 1, text); err.clear(); return true; }
            if (text_of(id) == text) { err = NIFDT_REPLAY; return false; }
            Put(id + "#prev", 1, text_of(id));
            Put(id, 2, text);
            err.clear();
            return true;
        }
        if (op == "rollback") {
            if (!Has(id + "#prev") || stored(id) < 2) { err = "EMPTY"; return false; }
            Put(id, 1, text_of(id + "#prev"));
            m_rows.erase(id + "#prev");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "NIF-DATA-001") {
        if (text.empty() || op.empty()) { err = "ENCODING"; return false; }
        if (Has(id) && text_of(id) != text) { err = "ENCODING"; return false; }
        if (text != op) { err = "ENCODING"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-DATA-002") {
        if (text == "<eos>") { err = "LOOKALIKE"; return false; }
        if (Has(id) && aux != 1) { err = "TOKEN"; return false; }
        if (aux != 1) { err = "TOKEN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "special");
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "NIF-DATA-003") {
        if (text != "c3a9") { err = "BOUNDARY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 2, text);
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
