// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP26_GRP26_H
#define BITCOIN_MODELNET_GRP26_GRP26_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Group 26. Node behaviors 3 and 4.
 * A memory decode stops at 8 bytes, and one authorized integer step runs.
 * GPU training stays absent.
 *
 * Echo opens engine "memory", prompts, and pulls until SwarmDecodeRun
 * returns false. A public prompt that finishes DONE returns true when
 * text().size() is at most 8. A prompt longer than 8 still leaves
 * text().size() at 8. A private prompt returns NIFDT_PRIVATE_DATA and
 * does not pull.
 *
 * Step calls IntegerTrainer::Step once and keeps that trainer. A second
 * Step advances again. IntegerDataset() stays the frozen eight pairs.
 * pairs() returns that size. Gpu returns false with NIFDT_ENGINE_ABSENT
 * and does not change State().
 *
 * Release stays NIFDT_UNQUALIFIED. Spend stays NIFDT_AUTOMATIC_SPEND.
 * Vendor stays NIFDT_ENGINE_ABSENT.
 * qualified(), release_qualified(), hardware_qualified(), launched(),
 * gpu(), and broadcast() stay false.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * automatic_spend() is "0".
 * No socket, no process, and no broadcast.
 */
class Grp26 {
public:
    bool Echo(const std::string& session, const std::string& prompt, std::string& err);
    bool Echo(const std::string& session, const std::string& prompt, bool is_private, std::string& err);
    bool Step(std::string& err);

    const std::string& text() const;
    int64_t tokens() const;
    std::string engine_of(const std::string& session) const;
    const IntegerState& State() const;
    int64_t pairs() const;

    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmDecodeRun m_decode;
    IntegerTrainer m_trainer;
};

} // namespace modelnet

#endif
