// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp15/grp15.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

bool Grp15::Held(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.held;
}

void Grp15::Put(const std::string& id, int64_t n, const std::string& s)
{
    Row& row = m_rows[id];
    row.on = true;
    row.held = true;
    row.n = n;
    row.s = s;
}

void Grp15::SetBit(const std::string& id, bool bit)
{
    Row& row = m_rows[id];
    row.on = true;
    row.bit = bit;
}

int64_t Grp15::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on || it->second.n == 0 ? static_cast<int64_t>(0) : it->second.n;
}

std::string Grp15::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() || !it->second.on ? std::string() : it->second.s;
}

bool Grp15::bit_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on && it->second.bit;
}

std::string Grp15::classification(const std::string& id) const
{
    (void)id;
    return "COMPONENT";
}

bool Grp15::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp15::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp15::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp15::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp15::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    (void)now_ms;
    if (id.empty()) {
        err = "ID";
        return false;
    }

    if (id == "ASR-PLN-005") {
        if (op == "quiesce") {
            if (Held(id)) {
                err = NIFDT_REPLAY;
                return false;
            }
            Put(id, static_cast<int64_t>(1), "quiesce");
            SetBit(id, true);
            err.clear();
            return true;
        }
        err = "QUIET";
        return false;
    }
    if (id == "ASR-PLN-006") {
        if (aux < static_cast<int64_t>(2)) {
            err = "QUORUM";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, "");
        err.clear();
        return true;
    }
    if (id == "ASR-PLN-007") {
        if (!flag) {
            err = "HISTORY";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        const int64_t n = aux > static_cast<int64_t>(0) ? aux : static_cast<int64_t>(1);
        Put(id, n, "");
        err.clear();
        return true;
    }
    if (id == "ASR-PRG-001") {
        if (aux == static_cast<int64_t>(0)) {
            err = "DELTA";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, "");
        err.clear();
        return true;
    }
    if (id == "ASR-PRG-002") {
        Row& row = m_rows[id];
        if (row.passes >= static_cast<int64_t>(3)) {
            err = "UNCHANGED";
            return false;
        }
        row.on = true;
        row.held = true;
        row.passes += static_cast<int64_t>(1);
        row.n = row.passes;
        row.s.clear();
        if (row.passes == static_cast<int64_t>(3)) row.bit = true;
        err.clear();
        return true;
    }
    if (id == "ASR-PRG-003") {
        if (Held(id)) {
            if (text != text_of(id)) {
                err = "RECIPE";
                return false;
            }
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-PRG-004") {
        if (aux < static_cast<int64_t>(5)) {
            err = "KEPT";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, "");
        err.clear();
        return true;
    }
    if (id == "ASR-PRT-001") {
        if (text != "btx") {
            err = "ENVELOPE";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), "btx");
        err.clear();
        return true;
    }
    if (id == "ASR-PRT-002") {
        if (op == "cancel") {
            if (bit_of(id)) {
                err = NIFDT_REPLAY;
                return false;
            }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (op == "status") {
            if (!bit_of(id)) {
                err = "QUIET";
                return false;
            }
            if (Held(id)) {
                err = NIFDT_REPLAY;
                return false;
            }
            Put(id, static_cast<int64_t>(1), "quiesced");
            err.clear();
            return true;
        }
        err = "QUIET";
        return false;
    }
    if (id == "ASR-PUB-001") {
        err = "OUTSIDE";
        return false;
    }
    if (id == "ASR-PUB-002") {
        if (extra.empty()) {
            err = "HISTORY";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-PUB-003") {
        if (!flag) {
            err = "DOC";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-PUB-004") {
        if (text.empty()) {
            err = "LICENSE";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, static_cast<int64_t>(1), text);
        err.clear();
        return true;
    }
    if (id == "ASR-REC-001") {
        if (op == "fail") {
            if (bit_of(id)) {
                err = NIFDT_REPLAY;
                return false;
            }
            SetBit(id, true);
            err.clear();
            return true;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, "");
        err.clear();
        return true;
    }
    if (id == "ASR-REC-002") {
        if (!flag || aux <= static_cast<int64_t>(0)) {
            err = "PREFIX";
            return false;
        }
        if (Held(id)) {
            err = NIFDT_REPLAY;
            return false;
        }
        Put(id, aux, "");
        err.clear();
        return true;
    }
    err = "ID";
    return false;
}

} // namespace modelnet
