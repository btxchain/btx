// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC05_PROC05_H
#define BITCOIN_MODELNET_PROC05_PROC05_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Proc05 implements P2P-SCN-G. A supported local model runs without an
 * external provider key. The model is a fixed integer affine step,
 * output = input * 3 + 1. Weights are the constants 3 and 1. They are
 * present unless the caller passes weights_present false.
 * Run applies the first matching rule. A non-empty provider key returns
 * PROVIDER and leaves ran false. Missing weights return MODEL. A negative
 * input returns BOUND. Those refusals leave output unchanged. Otherwise
 * Run stores output and last_output, sets ran, and clears err. A later
 * successful Run with a different input updates last_output.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND. This class opens no socket, starts no process,
 * touches no file, and spends nothing.
 */
class Proc05 {
public:
    bool Run(const std::string& provider_key, bool weights_present, int64_t input, int64_t& output, std::string& err);

    bool ran() const { return m_ran; }
    int64_t last_output() const { return m_last_output; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_ran{false};
    int64_t m_last_output{0};
};

} // namespace modelnet

#endif
