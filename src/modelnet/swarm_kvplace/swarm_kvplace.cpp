// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/swarm_kvplace.h>

#include <modelnet/swarm_kvplace/cost.h>
#include <modelnet/swarm_kvplace/decision.h>
#include <modelnet/swarm_kvplace/motion.h>
#include <modelnet/swarm_kvplace/offer.h>
#include <modelnet/swarm_kvplace/prefix.h>
#include <modelnet/swarm_kvplace/prefetch.h>
#include <modelnet/swarm_kvplace/share.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmKvPlace::Offer(const std::string& fingerprint, const std::string& quantization, const std::string& checkpoint,
                         const std::string& recipe, std::string& err)
{
    return m_book.Offer(fingerprint, quantization, checkpoint, recipe, err);
}

bool SwarmKvPlace::Prefix(const std::string& fingerprint, std::int64_t length, const std::string& parent,
                          bool parent_known, std::string& err)
{
    return SwarmKvPlaceApplyPrefix(m_book, fingerprint, length, parent, parent_known, err);
}

bool SwarmKvPlace::Choose(std::int64_t recompute, std::int64_t idle, std::int64_t route, std::int64_t transfer,
                          std::int64_t missing_ppm, std::int64_t memory_pressure, std::int64_t copies,
                          std::int64_t continuation, bool engine_present, std::string& err)
{
    SwarmKvPlaceCosts costs;
    if (!SwarmKvPlaceAdjust(recompute, idle, route, transfer, missing_ppm, memory_pressure, copies, continuation, costs,
                            err)) {
        // PRESSURE stores nothing: the previous winner stays, and no bytes move.
        return false;
    }
    const std::string selected = SwarmKvPlacePick(costs);
    m_winner = selected;
    return SwarmKvPlaceDecide(selected, engine_present, err);
}

bool SwarmKvPlace::Share(const std::string& left_fingerprint, const std::string& right_fingerprint, std::string& err)
{
    return m_shares.Share(m_book, left_fingerprint, right_fingerprint, err);
}

bool SwarmKvPlace::Prefetch(const std::string& fingerprint, std::string& err)
{
    return SwarmKvPlacePrefetch(m_book, fingerprint, err);
}

bool SwarmKvPlace::in_family(const std::string& fingerprint) const
{
    return m_book.in_family(fingerprint);
}

bool SwarmKvPlace::in_kv(const std::string& fingerprint) const
{
    return m_book.in_kv(fingerprint);
}

bool SwarmKvPlace::in_cohort(const std::string& fingerprint) const
{
    return m_book.in_cohort(fingerprint);
}

const std::string& SwarmKvPlace::winner() const
{
    return m_winner;
}

std::int64_t SwarmKvPlace::bytes_moved() const
{
    return SwarmKvPlaceBytesMoved();
}

bool SwarmKvPlace::launched() const
{
    return SwarmKvPlaceLaunched();
}

bool SwarmKvPlace::gpu() const
{
    return SwarmKvPlaceGpu();
}

bool SwarmKvPlace::measured_benchmark() const
{
    return SwarmKvPlaceMeasuredBenchmark();
}

} // namespace modelnet
