// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_capsule/research_capsule.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

const std::string* ResearchCapsule::Find(const std::string& id) const
{
    for (const Sealed& row : m_sealed) {
        if (row.id == id) return &row.hash;
    }
    return nullptr;
}

bool ResearchCapsule::Seal(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = "FIELD";
        return false;
    }
    if (Find(id) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    IntegerTrainer trainer;
    if (!trainer.Step(err)) return false;
    m_sealed.push_back(Sealed{id, IntegerStateHash(trainer.State())});
    err.clear();
    return true;
}

std::string ResearchCapsule::Open(const std::string& id, std::string& err) const
{
    const std::string* hash = Find(id);
    if (hash == nullptr) {
        err = "CAPSULE";
        return {};
    }
    err.clear();
    return *hash;
}

bool ResearchCapsule::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool ResearchCapsule::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ResearchCapsule::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ResearchCapsule::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
