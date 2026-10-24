// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp22/grp22.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp22::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

bool Grp22::Seen(const std::string& id, const std::string& op, const std::string& text) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || !it->second.has_sig) return false;
    return it->second.sig == op + "\n" + text;
}

void Grp22::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = s;
}

void Grp22::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

void Grp22::Remember(const std::string& id, const std::string& op, const std::string& text)
{
    Row& row = m_rows[id];
    row.has_sig = true;
    row.sig = op + "\n" + text;
}

int64_t Grp22::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp22::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp22::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp22::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp22::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp22::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp22::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp22::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp22::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (id.empty()) {
        err = "ID";
        return false;
    }
    if (id == "DS-POOL-005") {
        if (aux > static_cast<int64_t>(100) || aux < static_cast<int64_t>(0)) {
            err = "CAP";
            return false;
        }
        if (Has(id) && text_of(id) == "cap" && stored(id) == aux) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, "cap");
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-POOL-006") {
        if (!text.empty() && text == extra) {
            err = "SELF";
            return false;
        }
        if (Has(id) && text_of(id) == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-REC-001") {
        if (!flag) {
            err = "SOURCE";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-REC-002") {
        if (!Has(id)) {
            Put(id, static_cast<int64_t>(1), text);
            Remember(id, op, text);
            err.clear();
            return true;
        }
        if (text_of(id) == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "FENCE";
        return false;
    }
    if (id == "DS-REC-003") {
        if (flag) {
            err = NIFDT_REVOKED;
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-REC-004") {
        if (op == "payrecover") {
            err = "KEPT";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-REC-005") {
        if (op == "correct") {
            if (Seen(id, op, text)) {
                err = NIFDT_REPLAY;
                return false;
            }
            if (!Has(id)) Put(id, static_cast<int64_t>(1), text);
            SetBit(id, true);
            Remember(id, op, text);
            err.clear();
            return true;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-REC-006") {
        const bool complete = text.find("partition") != std::string::npos &&
                              text.find("clock") != std::string::npos &&
                              text.find("response") != std::string::npos &&
                              text.find("liquidity") != std::string::npos;
        if (!complete) {
            err = "PARTIAL";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        SetBit(id, true);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-SHARE-001") {
        if (text.find("tlp") == std::string::npos || extra.empty()) {
            err = "TLP";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text + "|" + extra);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-SHARE-002") {
        if (now_ms >= aux) {
            err = "EMBARGO";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-SHARE-003") {
        if (!flag) {
            err = "SANITIZE";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-SHARE-004") {
        if (text != extra || text.empty()) {
            err = "LEAK";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-SHARE-005") {
        if (op != "retract") {
            err = "LOCAL";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-SHARE-006") {
        if (extra == "share" || extra == "share-only" ||
            (extra.find("share") != std::string::npos && op == "train")) {
            err = "CONSENT";
            return false;
        }
        if (extra != "train") {
            err = "CONSENT";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    if (id == "DS-STD-001") {
        if (text.empty() || extra.empty()) {
            err = "STIX";
            return false;
        }
        if (Seen(id, op, text)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        Remember(id, op, text);
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
