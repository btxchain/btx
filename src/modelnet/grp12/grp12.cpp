// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp12/grp12.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <string>

namespace modelnet {
namespace {

std::string SeenKey(const std::string& id, const std::string& op, const std::string& text)
{
    return std::to_string(id.size()) + "\n" + id + "\n" + std::to_string(op.size()) + "\n" + op + "\n" +
           std::to_string(text.size()) + "\n" + text;
}

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "ASR-EVO-001", "ASR-EVO-002", "ASR-EVO-003", "ASR-EVO-004",
        "ASR-EXE-001", "ASR-EXE-002", "ASR-EXE-003", "ASR-EXE-004",
        "ASR-EXE-005", "ASR-EXE-006", "ASR-EXE-007",
        "ASR-GRF-001", "ASR-GRF-002", "ASR-GRF-003", "ASR-GRF-004", "ASR-GRF-005",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool ViewName(const std::string& text)
{
    return text == "dependency" || text == "evidence" || text == "payment" || text == "resource";
}

} // namespace

bool Grp12::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp12::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp12::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

bool Grp12::Seen(const std::string& id, const std::string& op, const std::string& text) const
{
    return m_seen.find(SeenKey(id, op, text)) != m_seen.end();
}

void Grp12::Mark(const std::string& id, const std::string& op, const std::string& text)
{
    m_seen.insert(SeenKey(id, op, text));
}

bool Grp12::Store(const std::string& id, const std::string& op, const std::string& text, int64_t n,
                  const std::string& saved, std::string& err)
{
    if (Seen(id, op, text)) {
        err = NIFDT_REPLAY;
        return false;
    }
    Put(id, n, saved);
    Mark(id, op, text);
    err.clear();
    return true;
}

int64_t Grp12::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || it->second.n == 0) return static_cast<int64_t>(0);
    return it->second.n;
}

std::string Grp12::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp12::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp12::classification(const std::string&) const
{
    return "COMPONENT";
}

bool Grp12::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp12::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp12::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp12::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp12::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (!Known(id)) {
        err = "ID";
        return false;
    }
    if (id == "ASR-EVO-001") {
        if (!flag) { err = "UNVERIFIED"; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text, err);
    }
    if (id == "ASR-EVO-002") {
        if (aux < 1) { err = "NICHE"; return false; }
        return Store(id, op, text, aux, "niche", err);
    }
    if (id == "ASR-EVO-003") {
        if (extra.empty()) { err = "BASELINE"; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text, err);
    }
    if (id == "ASR-EVO-004") {
        if (op != "shadow") { err = NIFDT_UNQUALIFIED; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text, err);
    }
    if (id == "ASR-EXE-001") {
        if (text.empty() || extra.empty()) { err = "SEPARATE"; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text + "|" + extra, err);
    }
    if (id == "ASR-EXE-002") {
        if (Has(id) && text_of(id) != text) { err = "ALTERED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        Mark(id, op, text);
        err.clear();
        return true;
    }
    if (id == "ASR-EXE-003") {
        if (!flag) { err = "UNKNOWN"; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text, err);
    }
    if (id == "ASR-EXE-004") {
        if (extra.empty()) { err = "FENCE"; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), extra, err);
    }
    if (id == "ASR-EXE-005") {
        if (now_ms >= aux) { err = "EXPIRED"; return false; }
        return Store(id, op, text, aux, text, err);
    }
    if (id == "ASR-EXE-006") {
        if (flag) { err = NIFDT_REVOKED; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text, err);
    }
    if (id == "ASR-EXE-007") {
        if (Seen(id, op, text)) { err = NIFDT_REPLAY; return false; }
        if (Has(id)) { err = "UNCHANGED"; return false; }
        Put(id, aux, text);
        Mark(id, op, text);
        err.clear();
        return true;
    }
    if (id == "ASR-GRF-001") {
        if (!ViewName(text)) { err = "VIEW"; return false; }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, static_cast<int64_t>(1), text);
        const int64_t n = Has(id) ? stored(id) : static_cast<int64_t>(0);
        Put(id, n + static_cast<int64_t>(1), text);
        Mark(id, op, text);
        err.clear();
        return true;
    }
    if (id == "ASR-GRF-002") {
        if (!text.empty() && text == extra) { err = "CYCLE"; return false; }
        return Store(id, op, text, static_cast<int64_t>(1), text, err);
    }
    if (id == "ASR-GRF-003") {
        if (op == "retract") {
            if (Seen(id, op, text)) { err = NIFDT_REPLAY; return false; }
            if (!Has(id)) {
                const int64_t n = aux > static_cast<int64_t>(0) ? aux : static_cast<int64_t>(1);
                Put(id, n, text);
            }
            SetBit(id, true);
            Mark(id, op, text);
            err.clear();
            return true;
        }
        if (Seen(id, op, text) || Has(id)) { err = NIFDT_REPLAY; return false; }
        const int64_t n = aux > static_cast<int64_t>(0) ? aux : static_cast<int64_t>(1);
        Put(id, n, text);
        Mark(id, op, text);
        err.clear();
        return true;
    }
    if (id == "ASR-GRF-004") {
        if (op == "rank") {
            if (!Has(id + "#filter")) { err = "ORDER"; return false; }
            return Store(id, op, text, aux, text, err);
        }
        if (op == "filter") {
            if (Seen(id, op, text)) { err = NIFDT_REPLAY; return false; }
            Put(id + "#filter", static_cast<int64_t>(1), "filter");
            Mark(id, op, text);
            err.clear();
            return true;
        }
        err = "ORDER";
        return false;
    }
    if (id == "ASR-GRF-005") {
        if (aux > 4 || aux < 1) { err = "BOUND"; return false; }
        return Store(id, op, text, aux, text, err);
    }
    err = "ID";
    return false;
}

} // namespace modelnet
