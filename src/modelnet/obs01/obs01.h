// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_OBS01_OBS01_H
#define BITCOIN_MODELNET_OBS01_OBS01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Obs01. Pass latches. The first Pass default-constructs Prf01 through
 * Prf09, Qat01 through Qat06, and Rel01, and requires every Pass to return
 * true. A later Pass clears err and returns true without constructing them
 * again. Prf03 runs against an empty temporary lab directory, and Prf05
 * runs against a different temporary directory whose lab image is truncated.
 * Both directories are removed before Pass returns, and the previous
 * lab directory is restored. If any of those objects report passed(), gpu_passed(),
 * windows_passed(), release_qualified(), or hardware_qualified(), Pass
 * returns false, sets err to NIFDT_UNQUALIFIED, and leaves the latch clear.
 * windows_passed() is read only when that object declares it. The same
 * accessors on Obs01 stay false, and a true report from Obs01 fails Pass
 * the same way. hosts() stays 1. Release returns NIFDT_UNQUALIFIED.
 * Spend returns NIFDT_AUTOMATIC_SPEND.
 * No process, socket, archive, or spend.
 */
class Obs01 {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
