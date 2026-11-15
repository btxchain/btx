// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp17/grp17.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp17::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.kept;
}

void Grp17::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.kept = true;
    row.n = n;
    row.s = s;
}

int64_t Grp17::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || it->second.n == static_cast<int64_t>(0)) {
        return static_cast<int64_t>(0);
    }
    return it->second.n;
}

std::string Grp17::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp17::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp17::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp17::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp17::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp17::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp17::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp17::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)op;
    if (id.empty() || (
            id != "DS-ACT-002" && id != "DS-ACT-003" && id != "DS-ACT-004" &&
            id != "DS-ACT-005" && id != "DS-ACT-006" &&
            id != "DS-AUTH-001" && id != "DS-AUTH-002" && id != "DS-AUTH-003" &&
            id != "DS-AUTH-004" && id != "DS-AUTH-005" && id != "DS-AUTH-006" &&
            id != "DS-DATA-001" && id != "DS-DATA-002" && id != "DS-DATA-003" &&
            id != "DS-DATA-004")) {
        err = "ID";
        return false;
    }
    if (id == "DS-ACT-002") {
        if (text == "D3" && !flag) {
            err = "APPROVAL";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-ACT-003") {
        if (text.empty()) {
            err = "ASSET";
            return false;
        }
        if (aux > static_cast<int64_t>(10)) {
            err = "RADIUS";
            return false;
        }
        if (!(aux > static_cast<int64_t>(0))) {
            err = "BYTES";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-ACT-004") {
        if (!flag) {
            err = "UNKNOWN";
            return false;
        }
        if (Has(id) && text_of(id) != text) {
            err = "ALTERED";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-ACT-005") {
        if (extra.empty()) {
            err = "CANARY";
            return false;
        }
        if (extra == "restore" && Has(id)) {
            const std::string prior = m_rows[id].prior;
            Put(id, static_cast<int64_t>(1), prior);
            err.clear();
            return true;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        m_rows[id].prior = text;
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-ACT-006") {
        if (text.find("retaliate") != std::string::npos) {
            err = "SCOPE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-AUTH-001") {
        if (text.empty()) {
            err = "ASSET";
            return false;
        }
        if (extra.empty()) {
            err = "MANDATE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text + "|" + extra);
        err.clear();
        return true;
    }
    if (id == "DS-AUTH-002") {
        if (text.empty() || extra.empty()) {
            err = "GENERATION";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text + "|" + extra);
        err.clear();
        return true;
    }
    if (id == "DS-AUTH-003") {
        if (now_ms >= aux) {
            err = "EXPIRED";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-AUTH-004") {
        if (Has(id) && text_of(id) != text) {
            err = "UNCHANGED";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-AUTH-005") {
        if (text != "read" && text != "effect" && text != "release" && text != "spend") {
            err = "PURPOSE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-AUTH-006") {
        if (flag) {
            err = NIFDT_REVOKED;
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-DATA-001") {
        if (extra.empty()) {
            err = "PROVENANCE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-DATA-002") {
        if (!text.empty() && text == extra) {
            err = "SEPARATE";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (!extra.empty()) {
            Put(id, static_cast<int64_t>(1), text + "|" + extra);
        } else {
            Put(id, static_cast<int64_t>(1), text);
        }
        err.clear();
        return true;
    }
    if (id == "DS-DATA-003") {
        if (text.empty() || aux > static_cast<int64_t>(1000) || aux < static_cast<int64_t>(1)) {
            err = "BOUND";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, text);
        err.clear();
        return true;
    }
    if (id == "DS-DATA-004") {
        if (extra.empty()) {
            err = NIFDT_PRIVATE_DATA;
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
