// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp19/grp19.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <string>

namespace modelnet {

bool Grp19::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp19::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp19::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp19::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on || it->second.n == static_cast<int64_t>(0) ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp19::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp19::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp19::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp19::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp19::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp19::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp19::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp19::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id.empty()) {
        err = "REQUEST";
        return false;
    }
    if (id == "DS-HIRE-002") {
        if (op == "family") {
            if (text != "family") { err = "ADMISSION"; return false; }
            const std::string key = id + "#family";
            if (Has(key)) { err = NIFDT_REPLAY; return false; }
            Put(key, static_cast<int64_t>(1), "family");
            if (!Has(id + "#private")) Put(id, static_cast<int64_t>(1), "family");
            err.clear();
            return true;
        }
        if (op == "private") {
            if (text != "private") { err = "ADMISSION"; return false; }
            if (extra.empty()) { err = "ADMISSION"; return false; }
            const std::string key = id + "#private";
            if (Has(key)) { err = NIFDT_REPLAY; return false; }
            Put(key, static_cast<int64_t>(1), "private");
            SetBit(key, true);
            Put(id, static_cast<int64_t>(1), "private");
            SetBit(id, true);
            err.clear();
            return true;
        }
        err = "ADMISSION";
        return false;
    }
    if (id == "DS-HIRE-003") {
        if (!flag) { err = NIFDT_UNQUALIFIED; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-HIRE-004") {
        if (!Has(id)) {
            Put(id, static_cast<int64_t>(1), text);
            err.clear();
            return true;
        }
        if (text_of(id) != text) { err = "SUBSTITUTE"; return false; }
        err = NIFDT_REPLAY;
        return false;
    }
    if (id == "DS-HIRE-005") {
        if (extra.empty()) { err = "CONFIG"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), extra);
        err.clear();
        return true;
    }
    if (id == "DS-HIRE-006") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DS-LEARN-001") {
        if (text.empty()) { err = "RELEASE"; return false; }
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DS-LEARN-002") {
        if (text != "time" && text != "campaign" && text != "tenant" && text != "lineage") {
            err = "HOLDOUT";
            return false;
        }
        const std::string key = id + "#" + text;
        if (Has(key)) { err = NIFDT_REPLAY; return false; }
        Put(key, static_cast<int64_t>(1), text);
        int64_t n = static_cast<int64_t>(0);
        if (Has(id + "#time")) ++n;
        if (Has(id + "#campaign")) ++n;
        if (Has(id + "#tenant")) ++n;
        if (Has(id + "#lineage")) ++n;
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "DS-LEARN-003") {
        if (text != "public" && text != "synthetic") { err = NIFDT_PRIVATE_DATA; return false; }
        if (extra.empty()) { err = "LICENSE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-LEARN-004") {
        if (extra.empty()) { err = "HARM"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-LEARN-005") {
        if (extra.empty() || extra == text) { err = "SELF"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text + "," + extra);
        err.clear();
        return true;
    }
    if (id == "DS-LEARN-006") {
        if (aux < static_cast<int64_t>(2)) { err = "SHORT"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-MODEL-001") {
        if (text.empty() || extra.empty()) { err = "SCOPE"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), text + "|" + extra);
        err.clear();
        return true;
    }
    if (id == "DS-MODEL-002") {
        if (text == "private") { err = NIFDT_PRIVATE_DATA; return false; }
        if (text != "public" || !flag) { err = "APPROVAL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, static_cast<int64_t>(1), "public");
        err.clear();
        return true;
    }
    if (id == "DS-MODEL-003") {
        if (text == "nixl" || text == "mooncake" || text == "rdma") {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
        if (!flag || aux <= static_cast<int64_t>(0)) { err = "PARTIAL"; return false; }
        if (Has(id)) { err = NIFDT_REPLAY; return false; }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-MODEL-004") {
        if (!Has(id)) {
            Put(id, static_cast<int64_t>(1), text);
            err.clear();
            return true;
        }
        if (text_of(id) != text) { err = "PIN"; return false; }
        err = NIFDT_REPLAY;
        return false;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
