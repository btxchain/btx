// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_reqbind/nif_reqbind.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool NifReqBind::Bind(const NifRequestRecord& record, std::string& err)
{
    // First empty string wins. Later empties are not reported.
    if (record.principal.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    if (record.receiver.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    if (record.realm.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    if (record.generation.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    if (record.runtime_image.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    if (record.commitment.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    if (record.attempt.empty()) {
        err = NIF_REQBIND_FIELD;
        return false;
    }
    // First zero numeric wins. A zero does not insert.
    if (record.epoch == static_cast<std::uint64_t>(0)) {
        err = NIF_REQBIND_BOUND;
        return false;
    }
    if (record.ceiling_bytes == static_cast<std::uint64_t>(0)) {
        err = NIF_REQBIND_BOUND;
        return false;
    }
    if (record.lease_until_ms == static_cast<std::uint64_t>(0)) {
        err = NIF_REQBIND_BOUND;
        return false;
    }
    // The attempt is already stored. Keep that record.
    if (m_by_attempt.find(record.attempt) != m_by_attempt.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_by_attempt.emplace(record.attempt, record);
    err.clear();
    return true;
}

bool NifReqBind::Find(const std::string& attempt, NifRequestRecord& out) const
{
    const auto it = m_by_attempt.find(attempt);
    if (it == m_by_attempt.end()) {
        return false;
    }
    out = it->second;
    return true;
}

bool NifReqBind::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
