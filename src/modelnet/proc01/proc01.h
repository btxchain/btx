// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC01_PROC01_H
#define BITCOIN_MODELNET_PROC01_PROC01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Proc01. ASR-OBS-001. Status keeps an advertised capability apart from a
 * qualified capability.
 * Observe stores one record per id. The first matching rule wins. An empty
 * id returns ID and stores nothing. A second Observe of the same id returns
 * REPLAY and the first record stays. Advertised without a measurement stores
 * advertised and leaves qualified false; evidence is ignored. Measured
 * without advertised stores qualified false. Advertised and measured with
 * empty evidence returns FIELD and stores nothing. Evidence of exactly
 * "claim" returns CLAIM and stores nothing. Any other non-empty evidence
 * qualifies that id only. Any other pair returns FIELD and stores nothing.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND. hosts() stays 1.
 * No socket, process, RPC, wallet, or file.
 */
class Proc01 {
public:
    bool Observe(const std::string& id, bool advertised, bool measured, const std::string& evidence, std::string& err);
    bool advertised(const std::string& id) const;
    bool qualified(const std::string& id) const;
    int count() const;

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        bool advertised{false};
        bool qualified{false};
    };
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
