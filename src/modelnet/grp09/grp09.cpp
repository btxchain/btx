// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp09/grp09.h>
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

bool Grp09::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp09::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp09::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp09::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp09::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp09::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp09::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp09::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp09::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp09::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp09::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp09::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DT-WAN-002") {
        if (text != "local-sgd") { err = "NAME"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-WAN-003") {
        if (op == "qualify") { err = NIFDT_UNQUALIFIED; return false; }
        if (text != "diloco") { err = "NAME"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-WAN-004") {
        if (op == "replace") {
            if (!Has(id) || text_of(id) != extra || text.empty()) { err = "SYNC"; return false; }
            Put(id, 1, text);
            err.clear();
            return true;
        }
        if (text.empty()) { err = "SYNC"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-WAN-005") {
        if (op == "partition") {
            Put(id, 1, "partition");
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "commit") {
            if (bit_of(id)) { err = "PARTITION"; return false; }
            if (text_of(id) == "commit") { err = NIFDT_REPLAY; return false; }
            Put(id, 2, "commit");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-WAN-007") {
        if (text.empty()) { err = "EPOCH"; return false; }
        if (!flag) { err = "JOURNAL"; return false; }
        if (Has(id) && text_of(id) == text) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DT-WAN-008") {
        if (op.empty() || text.empty()) { err = "FORK"; return false; }
        if (op == text) { err = "SELF"; return false; }
        if (op == "distill") {
            if (text_of(id) != "fork") { err = "FORK"; return false; }
            Put(id, 2, "distill");
            err.clear();
            return true;
        }
        if (op != "fork") { err = "FORK"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "fork");
        err.clear();
        return true;
    }
    if (id == "DT-SEC-001") {
        if (text.empty()) { err = "IDENTITY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-SEC-002") {
        err = "NORM";
        return false;
    }
    if (id == "DT-SEC-003") {
        if (text != "public_trajectory" && text != "synthetic_trajectory") { err = NIFDT_PRIVATE_DATA; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-SEC-004") {
        if (text.empty()) { err = "MANDATE"; return false; }
        if (op == "pay") { err = "HELD"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-SEC-005") {
        if (text != "accepted" && text != "synthetic" && text != "repeated" && text != "speculative") { err = "CLASS"; return false; }
        Put(id + "#" + text, 1, text);
        if (text == "accepted") {
            Put(id, 1, "accepted");
            SetBit(id, true);
        } else if (!Has(id)) {
            Put(id, 0, text);
        }
        err.clear();
        return true;
    }
    if (id == "DT-SEC-006") {
        if (op == "download") { err = "DOWNLOAD"; return false; }
        if (text == "elf" || text == "PYTHON_PICKLE") { err = "CODE"; return false; }
        if (text.empty()) { err = "BODY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "isolated");
        err.clear();
        return true;
    }
    if (id == "DT-SEC-007") {
        if (op == "release") { err = NIFDT_UNQUALIFIED; return false; }
        if (op != "candidate" || text.empty()) { err = "CANDIDATE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, "candidate");
        err.clear();
        return true;
    }
    if (id == "DT-SEC-008") {
        if (op == "arm") {
            if (aux < 1) { err = "DEADLINE"; return false; }
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, aux, "deadline");
            err.clear();
            return true;
        }
        if (op == "fail") {
            if (!Has(id)) { err = "ORDER"; return false; }
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-SIM-001") {
        if (text.empty()) { err = "ASSUMPTION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
