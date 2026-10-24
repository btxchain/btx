// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SLICE_QUALIFY_SLICE_QUALIFY_H
#define BITCOIN_MODELNET_SLICE_QUALIFY_SLICE_QUALIFY_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Qualification slice. Observe stores nothing.
 * windows, macos, and gpu return NIFDT_UNQUALIFIED.
 * Any other non-empty text returns JOURNEY. Empty text returns FIELD.
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * automatic_spend() stays NIFDT_AUTOMATIC_SPEND. No socket, no process, and no broadcast.
 */
class SliceQualify {
public:
    bool Observe(const std::string& text, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool windows_passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return 0; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
};

} // namespace modelnet

#endif
