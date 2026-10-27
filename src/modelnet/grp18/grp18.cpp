// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp18/grp18.h>
#include <modelnet/nifdt_contract/contract.h>


#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool IsIdent(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool HasWord(const std::string& text, const std::string& word)
{
    if (word.empty()) return false;
    std::size_t pos = 0;
    while ((pos = text.find(word, pos)) != std::string::npos) {
        const bool left = pos == 0 || !IsIdent(static_cast<unsigned char>(text[pos - 1]));
        const std::size_t end = pos + word.size();
        const bool right = end == text.size() || !IsIdent(static_cast<unsigned char>(text[end]));
        if (left && right) return true;
        pos = end;
    }
    return false;
}

bool Tainted(const std::string& text)
{
    return text.find("ignore previous") != std::string::npos || HasWord(text, "instruction");
}

int CommaCount(const std::string& text)
{
    int n = 0;
    for (unsigned char c : text) {
        if (c == ',') ++n;
    }
    return n;
}

bool Measured(const std::string& text)
{
    return text.find("triage") != std::string::npos &&
           text.find("effect") != std::string::npos &&
           text.find("false") != std::string::npos &&
           text.find("cost") != std::string::npos;
}

} // namespace

bool Grp18::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.kept;
}

void Grp18::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.kept = true;
    row.n = n;
    row.s = s;
}

void Grp18::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp18::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on || it->second.n == static_cast<int64_t>(0)) {
        return static_cast<int64_t>(0);
    }
    return it->second.n;
}

std::string Grp18::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp18::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp18::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp18::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp18::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp18::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp18::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp18::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)op;
    (void)now_ms;
    (void)aux;
    if (id.empty() || (
            id != "DS-DATA-005" && id != "DS-DATA-006" &&
            id != "DS-DEL-001" && id != "DS-DEL-002" && id != "DS-DEL-003" &&
            id != "DS-DEL-004" && id != "DS-DEL-005" && id != "DS-DEL-006" &&
            id != "DS-EVAL-001" && id != "DS-EVAL-002" && id != "DS-EVAL-003" &&
            id != "DS-EVAL-004" && id != "DS-EVAL-005" && id != "DS-EVAL-006" &&
            id != "DS-HIRE-001")) {
        err = "ID";
        return false;
    }
    if (id == "DS-DATA-005") {
        if (Tainted(text)) {
            SetBit(id, true);
            err = "TAINT";
            return false;
        }
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        SetBit(id, false);
        err.clear();
        return true;
    }
    if (id == "DS-DATA-006") {
        if (text != "clock" && text != "loss" && text != "duplicate" && text != "missing") {
            err = "GAP";
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
    if (id == "DS-DEL-001") {
        err = "OUTSIDE";
        return false;
    }
    if (id == "DS-DEL-002") {
        if (text.empty()) {
            err = "LICENSE";
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
    if (id == "DS-DEL-003") {
        if (!flag) {
            err = "DOC";
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
    if (id == "DS-DEL-004") {
        if (flag) {
            err = "ASSURANCE";
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
    if (id == "DS-DEL-005") {
        if (extra.empty()) {
            err = "FINGERPRINT";
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
    if (id == "DS-DEL-006") {
        err = "UNAUTHORIZED";
        return false;
    }
    if (id == "DS-EVAL-001") {
        if (extra.empty()) {
            err = "BASELINE";
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
    if (id == "DS-EVAL-002") {
        if (!Measured(text)) {
            err = "MEASURE";
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
    if (id == "DS-EVAL-003") {
        if (text != "cold" && text != "warm" && text != "external") {
            err = "DELAY";
            return false;
        }
        const std::string key = id + "#" + text;
        if (Has(key)) {
            err = NIFDT_REPLAY;
            return false;
        }
        const int64_t n = stored(id) + static_cast<int64_t>(1);
        Put(key, static_cast<int64_t>(1), text);
        Put(id, n, text);
        err.clear();
        return true;
    }
    if (id == "DS-EVAL-004") {
        if (Has(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "DS-EVAL-005") {
        if (!text.empty() && text == extra) {
            err = "SELF";
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
    if (id == "DS-EVAL-006") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DS-HIRE-001") {
        if (CommaCount(text) < 2) {
            err = "FINGERPRINT";
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
