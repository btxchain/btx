// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp02/grp02.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/identity.h>
#include <util/strencodings.h>


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

bool Grp02::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp02::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp02::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp02::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp02::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp02::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp02::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp02::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp02::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "NIF-PROF-005") {
        if (aux != 8 || now_ms != 0) {
            if (aux != 8) { err = "SEMANTIC"; return false; }
        }
        if (text != "" && text != "8,2,2") { err = "SEMANTIC"; return false; }
        if (aux != 8) { err = "SEMANTIC"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 8, "8,2,2");
        err.clear();
        return true;
    }
    if (id == "NIF-PROF-006") {
        if (op == "release") {
            if (!Has(id)) { err = "PROFILE"; return false; }
            err = "PINNED";
            return false;
        }
        if (aux < 1 || now_ms < 0) { err = "BYTES"; return false; }
        int64_t sum = 0;
        if (!AddOk(aux, now_ms, sum) || sum > 100) { err = "CAPACITY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, sum, std::to_string(aux) + "+" + std::to_string(now_ms));
        err.clear();
        return true;
    }
    if (id == "NIF-EXEC-001") {
        if (op.empty()) { err = "STATE"; return false; }
        if (text.empty()) { err = "CHUNK"; return false; }
        if (aux < 1) { err = "BYTES"; return false; }
        if (Has(id + "#" + text)) { err = NIFDT_REPLAY; return false; }
        if (Has(id) && text_of(id) != op) { err = "STALE"; return false; }
        int64_t sum = aux;
        if (Has(id) && !AddOk(stored(id), aux, sum)) { err = "OVERFLOW"; return false; }
        Put(id + "#" + text, aux, op);
        Put(id, sum, op);
        err.clear();
        return true;
    }
    if (id == "NIF-EXEC-002") {
        if (aux < 1 || aux > 4096) { err = "PIPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "pipe");
        err.clear();
        return true;
    }
    if (id == "NIF-EXEC-003") {
        if (op == "hold") {
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
        if (op == "release") { err = "PINNED"; return false; }
        err = "ORDER";
        return false;
    }
    if (id == "NIF-EXEC-004") {
        if (text.empty()) { err = "REQUEST"; return false; }
        if (Has(id) && text_of(id) != text) { err = "ALTERED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "NIF-EXEC-005") {
        if (op.empty() || op == "open") {
            if (aux < 1) { err = "DEADLINE"; return false; }
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, aux, "open");
            err.clear();
            return true;
        }
        if (!Has(id)) { err = "REQUEST"; return false; }
        if (op == "cancel") {
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "drain") {
            if (!bit_of(id)) { err = "ORDER"; return false; }
            if (text_of(id) == "drained") { err = "UNCHANGED"; return false; }
            if (now_ms >= stored(id)) { err = "EXPIRED"; return false; }
            const bool keep = bit_of(id);
            Put(id, 0, "drained");
            if (keep) SetBit(id, true);
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "NIF-EXEC-006") {
        if (op == "tool") {
            if (text.empty()) { err = "TOOL"; return false; }
            if (!flag) { err = "DENIED"; return false; }
            if (bit_of(id)) { err = NIFDT_REPLAY; return false; }
            if (!Has(id)) Put(id, 0, "");
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (aux < 1 || aux > 1024) { err = "GRAMMAR"; return false; }
        if (Has(id) && text_of(id) == "grammar") { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "grammar");
        err.clear();
        return true;
    }
    if (id == "NIF-KV-001") {
        const size_t bar = extra.find('|');
        if (text.empty() || op.empty() || bar == std::string::npos || extra.substr(0, bar).empty() || extra.substr(bar + 1).empty()) {
            err = "COMPONENT";
            return false;
        }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 4, text);
        err.clear();
        return true;
    }
    if (id == "NIF-KV-003") {
        if (text.empty() || op.empty() || extra.empty()) { err = "COMPONENT"; return false; }
        const std::string joined = text + "|" + op + "|" + extra + "|" + std::to_string(now_ms);
        if (Has(id) && text_of(id) != joined) { err = "GENERATION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, joined);
        err.clear();
        return true;
    }
    if (id == "NIF-KV-004") {
        if (flag) { err = NIFDT_ENGINE_ABSENT; return false; }
        if (aux < 1) { err = "BYTES"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, "local");
        err.clear();
        return true;
    }
    if (id == "NIF-KV-005") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "NIF-KV-006") {
        if (op == "submit") {
            if (aux != 0 && aux != 1) { err = "RANK"; return false; }
            const std::string key = id + "#" + std::to_string(aux);
            if (Has(key)) { err = NIFDT_REPLAY; return false; }
            Put(key, 1, "rank");
            const int64_t n = (Has(id + "#0") ? 1 : 0) + (Has(id + "#1") ? 1 : 0);
            Put(id, n, "rank");
            err.clear();
            return true;
        }
        if (op == "restore") {
            if (!Has(id + "#0") || !Has(id + "#1")) { err = "MISSING"; return false; }
            if (text_of(id) == "restored") { err = NIFDT_REPLAY; return false; }
            Put(id, 2, "restored");
            err.clear();
            return true;
        }
        err = "RANK";
        return false;
    }
    if (id == "NIF-KV-008") {
        if (flag) { err = NIFDT_ENGINE_ABSENT; return false; }
        if (aux < 1 || aux > 1024) { err = "MEMORY"; return false; }
        if (text.empty()) { err = "GENERATION"; return false; }
        if (Has(id) && text_of(id) != text) { err = "GENERATION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-003") {
        if (text.empty()) { err = "PEER"; return false; }
        if (flag) {
            if (!Has(id)) Put(id, 0, text);
            SetBit(id, false);
            err = "HINT";
            return false;
        }
        const std::vector<unsigned char> pk = ParseHex(op);
        const std::vector<unsigned char> sig = ParseHex(extra);
        if (pk.size() != 1312 || sig.size() != 2420) { err = "KEY"; return false; }
        const Span<const unsigned char> msg(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        if (!VerifyMlDsa44(Span<const unsigned char>(pk.data(), pk.size()), msg, Span<const unsigned char>(sig.data(), sig.size()))) {
            err = "AUTH";
            return false;
        }
        if (Has(id) && bit_of(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        SetBit(id, true);
        err.clear();
        return true;
    }
    if (id == "NIF-LAN-004") {
        if (op == "wan") { err = NIFDT_NO_ROUTE; return false; }
        if (text != "local" && text != "lan" && text != "peer") { err = "SCOPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
