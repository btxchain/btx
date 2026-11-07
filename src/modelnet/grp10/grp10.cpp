// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp10/grp10.h>
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

bool Grp10::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp10::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp10::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp10::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp10::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp10::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp10::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp10::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp10::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp10::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp10::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp10::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DT-SIM-002") {
        if (text == "2" && text_of(id) != "1") { err = "DEPENDENCY"; return false; }
        if (text != "1" && text != "2") { err = "ORDER"; return false; }
        if (text == "1" && Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, text == "1" ? 1 : 2, text);
        err.clear();
        return true;
    }
    if (id == "DT-SIM-003") {
        if (op == "dualpipe") { err = NIFDT_ENGINE_ABSENT; return false; }
        if (now_ms < 1 || aux < 1) { err = "BUBBLE"; return false; }
        int64_t gpipe = 0;
        if (!MulOk(now_ms - 1, aux, gpipe)) { err = "OVERFLOW"; return false; }
        const int64_t f1b = now_ms - 1;
        Put(id, gpipe, std::to_string(gpipe) + "/" + std::to_string(f1b));
        err.clear();
        return true;
    }
    if (id == "DT-SIM-004") {
        if (text != "bandwidth" && text != "latency" && text != "memory") { err = "SWEEP"; return false; }
        Put(id + "#" + text, 1, text);
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-SIM-005") {
        if (text.empty() || text == "missing") { err = "UNMEASURED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-SIM-006") {
        if (op == "check") {
            if (!Has(id + "#0") || !Has(id + "#1")) { err = "MISSING"; return false; }
            if (stored(id + "#0") != stored(id + "#1")) { err = "DISAGREE"; return false; }
            Put(id, 1, "agree");
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op != "0" && op != "1") { err = "RANK"; return false; }
        if (bit_of(id)) { err = NIFDT_REPLAY; return false; }
        Put(id + "#" + op, aux, op);
        err.clear();
        return true;
    }
    if (id == "DT-SIM-007") {
        if (text != "quality" && text != "throughput") { err = "CLASS"; return false; }
        if (text == "quality") {
            Put(id, 1, "quality");
        } else if (!Has(id)) {
            Put(id, 0, "throughput");
        }
        err.clear();
        return true;
    }
    if (id == "DT-SIM-008") {
        if (op == "fail") {
            if (!Has(id)) { err = "ORDER"; return false; }
            SetBit(id, true);
            err = "FAILED";
            return false;
        }
        if (op == "rollback") {
            if (!bit_of(id) || !Has(id + "#prev")) { err = "ORDER"; return false; }
            Put(id, 1, text_of(id + "#prev"));
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op != "commit" || text.empty()) { err = "ORDER"; return false; }
        if (Has(id)) Put(id + "#prev", 1, text_of(id));
        const int64_t n = Has(id) ? stored(id) + 1 : 1;
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "DT-REL-001") {
        if (text != "binding") { err = "OBLIGATION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-REL-002") {
        if (op != "startup" && op != "shutdown") { err = "PATH"; return false; }
        const std::string key = id + "#" + op;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, op);
        int64_t n = Has(id) ? stored(id) : 0;
        Put(id, n + 1, op);
        err.clear();
        return true;
    }
    if (id == "DT-REL-003") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-REL-004") {
        if (text.empty()) { err = "NAME"; return false; }
        Put(id, 0, text + "=absent");
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "DT-REL-005") {
        if (!flag) { err = "REFUSED"; return false; }
        if (text.empty()) { err = "DOC"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-REL-006") {
        if (text.empty()) { err = "PROVENANCE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-REL-007") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-REL-008") {
        err = "UNAUTHORIZED";
        return false;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
