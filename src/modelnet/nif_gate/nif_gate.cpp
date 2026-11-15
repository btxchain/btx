// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_gate/nif_gate.h>

#include <modelnet/nifdt_contract/contract.h>

#include <string>
#include <vector>

namespace modelnet {

NifGate::KindNote* NifGate::Find(const std::string& kind)
{
    if (kind == "gpu") return &m_gpu;
    if (kind == "lan") return &m_lan;
    if (kind == "wan") return &m_wan;
    if (kind == "security") return &m_security;
    if (kind == "payment") return &m_payment;
    return nullptr;
}

const NifGate::KindNote* NifGate::Find(const std::string& kind) const
{
    if (kind == "gpu") return &m_gpu;
    if (kind == "lan") return &m_lan;
    if (kind == "wan") return &m_wan;
    if (kind == "security") return &m_security;
    if (kind == "payment") return &m_payment;
    return nullptr;
}

int64_t NifGate::PassedCount() const
{
    int64_t n = static_cast<int64_t>(0);
    if (m_gpu.passed) n += static_cast<int64_t>(1);
    if (m_lan.passed) n += static_cast<int64_t>(1);
    if (m_wan.passed) n += static_cast<int64_t>(1);
    if (m_security.passed) n += static_cast<int64_t>(1);
    if (m_payment.passed) n += static_cast<int64_t>(1);
    return n;
}

bool NifGate::Absent(const std::string& name) const
{
    for (const std::string& row : m_absent) {
        if (row == name) return true;
    }
    return false;
}

bool NifGate::kind_passed(const std::string& kind) const
{
    const KindNote* slot = Find(kind);
    return slot != nullptr && slot->passed;
}

std::string NifGate::noted_name(const std::string& kind) const
{
    const KindNote* slot = Find(kind);
    if (slot == nullptr || !slot->passed) return {};
    return slot->name;
}

bool NifGate::Note(const std::string& kind, const std::string& name, std::string& err)
{
    KindNote* slot = Find(kind);
    if (slot == nullptr) {
        err = NIF_GATE_CLASS;
        return false;
    }
    if (name.empty()) {
        err = NIF_GATE_NAME;
        return false;
    }
    if (!NifDtEngineLinked(name)) {
        if (!Absent(name)) {
            m_absent.push_back(name);
        }
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (slot->passed) {
        err = NIFDT_REPLAY;
        return false;
    }
    slot->passed = true;
    slot->name = name;
    err.clear();
    return true;
}

bool NifGate::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
