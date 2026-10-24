// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_trust/model_trust.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool ModelTrust::attested(const std::string& channel) const
{
    for (const Row& row : m_rows) {
        if (row.channel == channel) return true;
    }
    return false;
}

int64_t ModelTrust::sequence(const std::string& channel) const
{
    for (const Row& row : m_rows) {
        if (row.channel == channel) return row.sequence;
    }
    return static_cast<int64_t>(0);
}

std::string ModelTrust::digest(const std::string& channel) const
{
    for (const Row& row : m_rows) {
        if (row.channel == channel) return row.digest;
    }
    return std::string();
}

bool ModelTrust::Attest(const std::string& channel, int64_t sequence, const std::string& digest, std::string& err)
{
    if (channel.empty() || digest.empty()) {
        err = "FIELD";
        return false;
    }
    if (sequence < static_cast<int64_t>(1)) {
        err = "SEQUENCE";
        return false;
    }
    for (Row& row : m_rows) {
        if (row.channel != channel) continue;
        if (sequence < row.sequence) {
            err = "ROLLBACK";
            return false;
        }
        if (sequence == row.sequence) {
            if (digest != row.digest) {
                err = "MISMATCH";
                return false;
            }
            err = NIFDT_REPLAY;
            return false;
        }
        row.sequence = sequence;
        row.digest = digest;
        err.clear();
        return true;
    }
    Row row;
    row.channel = channel;
    row.sequence = sequence;
    row.digest = digest;
    m_rows.push_back(row);
    err.clear();
    return true;
}

bool ModelTrust::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool ModelTrust::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ModelTrust::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ModelTrust::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
