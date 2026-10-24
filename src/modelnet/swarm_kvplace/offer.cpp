// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/offer.h>

#include <modelnet/swarm_kvplace/codes.h>
#include <modelnet/swarm_kvplace/quantization.h>

#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmKvPlaceBook::Offer(const std::string& fingerprint, const std::string& quantization,
                             const std::string& checkpoint, const std::string& recipe, std::string& err)
{
    if (fingerprint.empty()) {
        err = SWARM_KVPLACE_FINGERPRINT;
        return false;
    }
    if (Find(fingerprint) != nullptr) {
        err = SWARM_KVPLACE_REPLAY;
        return false;
    }
    const SwarmKvPlaceQuant kind = SwarmKvPlaceClassify(quantization, checkpoint, recipe);
    if (kind == SwarmKvPlaceQuant::Reject) {
        err = SWARM_KVPLACE_QUANTIZATION;
        return false;
    }

    SwarmKvPlaceRecord row;
    row.fingerprint = fingerprint;
    row.quantization = quantization;
    row.checkpoint = checkpoint;
    row.recipe = recipe;
    row.family = true;
    row.kv = kind == SwarmKvPlaceQuant::Cohort;
    row.cohort = row.kv;
    m_records.emplace(fingerprint, std::move(row));
    err.clear();
    return true;
}

bool SwarmKvPlaceBook::Has(const std::string& fingerprint) const
{
    return Find(fingerprint) != nullptr;
}

bool SwarmKvPlaceBook::in_family(const std::string& fingerprint) const
{
    const SwarmKvPlaceRecord* row = Find(fingerprint);
    return row != nullptr && row->family;
}

bool SwarmKvPlaceBook::in_kv(const std::string& fingerprint) const
{
    const SwarmKvPlaceRecord* row = Find(fingerprint);
    return row != nullptr && row->kv;
}

bool SwarmKvPlaceBook::in_cohort(const std::string& fingerprint) const
{
    const SwarmKvPlaceRecord* row = Find(fingerprint);
    return row != nullptr && row->cohort;
}

const SwarmKvPlaceRecord* SwarmKvPlaceBook::Find(const std::string& fingerprint) const
{
    const auto found = m_records.find(fingerprint);
    if (found == m_records.end()) return nullptr;
    return &found->second;
}

SwarmKvPlaceRecord* SwarmKvPlaceBook::Find(const std::string& fingerprint)
{
    const auto found = m_records.find(fingerprint);
    if (found == m_records.end()) return nullptr;
    return &found->second;
}

} // namespace modelnet
