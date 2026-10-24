// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp06/grp06.h>
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

bool Grp06::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp06::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp06::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp06::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp06::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp06::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp06::classification(const std::string& id) const
{
    if (id.rfind("DT-SIM-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp06::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp06::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp06::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp06::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp06::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DT-GRD-001") {
        if (op == "init") {
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, 10, "w");
            err.clear();
            return true;
        }
        if (op == "step") {
            if (!Has(id)) { err = "ORDER"; return false; }
            if (!flag) { err = "FINITE"; return false; }
            Put(id, stored(id) - aux, "w");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-GRD-002") {
        if (text.empty()) { err = "MICRO"; return false; }
        if (op.empty()) { err = "OWNER"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, op);
        if (!Has(id)) Put(id, 1, op);
        err.clear();
        return true;
    }
    if (id == "DT-GRD-004") {
        if (op == "forward") {
            Put(id, 0, "alive");
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "remat" || op == "backward") {
            if (!bit_of(id)) { err = "ORDER"; return false; }
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-GRD-005") {
        if (op == "remat") {
            if (!Has(id)) Put(id, 0, "route");
            err.clear();
            return true;
        }
        if (op == "token") {
            const int64_t n = Has(id) ? stored(id) : 0;
            Put(id, n + 1, "token");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-GRD-006") {
        if (op == "bias") {
            Put(id + "#bias", aux, "bias");
            Put(id, aux, "bias");
            err.clear();
            return true;
        }
        if (op == "mix") {
            if (!Has(id + "#bias")) { err = "BIAS"; return false; }
            Put(id + "#mix", aux, "mix");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-GRD-007") {
        if (op == "detach") {
            if (!Has(id)) { err = "ORDER"; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "grad") {
            if (bit_of(id)) { err = "DETACHED"; return false; }
            Put(id, aux, "grad");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-GRD-008") {
        if (op == "advertise") { err = NIFDT_UNQUALIFIED; return false; }
        if (text != "ced" && text != "csa2" && text != "engram" && text != "mhc") { err = "NAME"; return false; }
        if (aux < 1) { err = "SHAPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DT-PAR-001") {
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        std::vector<int64_t> parts;
        std::string cur;
        auto flush = [&]() {
            int64_t v = 0;
            if (!ParseI64(cur, v)) return false;
            parts.push_back(v);
            cur.clear();
            return true;
        };
        for (char c : text) {
            if (c == ',') { if (!flush()) { err = "RANK"; return false; } }
            else cur.push_back(c);
        }
        if (!flush() || parts.size() != 5) { err = "RANK"; return false; }
        int64_t prod = 1;
        for (int64_t v : parts) {
            if (v < 1) { err = "RANK"; return false; }
            int64_t next = 0;
            if (!MulOk(prod, v, next)) { err = "OVERFLOW"; return false; }
            prod = next;
        }
        Put(id, prod, text);
        err.clear();
        return true;
    }
    if (id == "DT-PAR-002") {
        if (op == "freeze") {
            if (!Has(id)) { err = "PLAN"; return false; }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (bit_of(id)) { err = "FROZEN"; return false; }
        if (text.empty()) { err = "PLAN"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-PAR-003") {
        if (op == "dispatch") {
            if (text.empty()) { err = "ROUTE"; return false; }
            if (Has(id)) { err = NIFDT_REPLAY; return false; }
            Put(id, 1, text);
            err.clear();
            return true;
        }
        if (op == "drop") {
            if (text_of(id) != "done") { err = "OPEN"; return false; }
            err.clear();
            return true;
        }
        if (op == "backward") {
            if (!Has(id)) { err = "ORDER"; return false; }
            if (text_of(id) == "done") { err = NIFDT_REPLAY; return false; }
            Put(id, 1, "done");
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "DT-PAR-004") {
        if (op != "forward" && op != "dgrad" && op != "wgrad") { err = "KERNEL"; return false; }
        const std::string key = id + "#" + op;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, 1, op);
        int64_t n = 0;
        if (Has(id + "#forward")) ++n;
        if (Has(id + "#dgrad")) ++n;
        if (Has(id + "#wgrad")) ++n;
        Put(id, n, op);
        err.clear();
        return true;
    }
    if (id == "DT-PAR-005") {
        if (text != "matrix" && text != "head") { err = "UNIT"; return false; }
        if (aux < 1) { err = "UNIT"; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DT-PAR-006") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "DT-PAR-007") {
        if (text.empty()) { err = "OWNER"; return false; }
        if (Has(id) && text_of(id) == text) { err = NIFDT_REPLAY; return false; }
        if (Has(id)) { err = "OWNER"; return false; }
        Put(id, 1, text);
        err.clear();
        return true;
    }
    if (id == "DT-PAR-008") {
        const size_t cg = text.find(',');
        const size_t ct = extra.find(',');
        int64_t g1 = 0, g2 = 0, t1 = 0, t2 = 0;
        if (cg == std::string::npos || ct == std::string::npos || !ParseI64(text.substr(0, cg), g1) || !ParseI64(text.substr(cg + 1), g2) || !ParseI64(extra.substr(0, ct), t1) || !ParseI64(extra.substr(ct + 1), t2)) {
            err = "SAMPLE";
            return false;
        }
        if (t1 < 1 || t2 < 1) { err = "MASK"; return false; }
        int64_t gs = 0, ts = 0;
        if (!AddOk(g1, g2, gs) || !AddOk(t1, t2, ts) || ts == 0) { err = "OVERFLOW"; return false; }
        int64_t a = gs < 0 ? -gs : gs;
        int64_t b = ts < 0 ? -ts : ts;
        while (b != 0) { const int64_t r = a % b; a = b; b = r; }
        const int64_t g = a == 0 ? 1 : a;
        Put(id, gs / g, std::to_string(gs / g) + "/" + std::to_string(ts / g));
        err.clear();
        return true;
    }
    err = "UNKNOWN";
    return false;
}

} // namespace modelnet
