// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp11/grp11.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp11::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp11::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp11::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp11::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp11::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp11::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp11::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp11::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp11::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp11::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp11::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp11::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t /*now_ms*/, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "ID";
        return false;
    }
    if (id == "ASR-ACC-001") {
        if (aux < static_cast<int64_t>(2)) { err = "PARTICIPANTS"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "ASR-ACC-002") {
        err = "HARDWARE";
        return false;
    }
    if (id == "ASR-ART-001") {
        if (extra.empty() || !flag) { err = "MANIFEST"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-ART-002") {
        if (aux < static_cast<int64_t>(1) || aux > static_cast<int64_t>(64)) { err = "OVERFLOW"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "ASR-ART-003") {
        if (aux < static_cast<int64_t>(1) || aux > static_cast<int64_t>(4194304)) { err = "PIECE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "ASR-ART-004") {
        if (Has(id) && text_of(id) != text) { err = "CONFLICT"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-ART-005") {
        if (extra.empty()) { err = "DIGEST"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-CAP-001") {
        if (text != "none") { err = "INTERPRETER"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-CAP-002") {
        if (!flag) { err = NIFDT_UNQUALIFIED; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-CAP-003") {
        if (!text.empty() && text == extra) { err = "AUTHORITY"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-CAP-004") {
        if (extra.empty() || !text.starts_with(extra)) { err = "DENIED"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-EVD-001") {
        if (text.find("private") != std::string::npos) { err = NIFDT_PRIVATE_DATA; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-EVD-002") {
        if (extra.empty()) { err = "SOURCE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-EVD-003") {
        if (text.find("ignore previous") != std::string::npos) { err = "INJECTION"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-EVD-004") {
        if (!flag) { err = NIFDT_REVOKED; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-EVD-005") {
        if (op == "retrieve") { err = "ABSENT"; return false; }
        if (op != "promise") { err = "ABSENT"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
