// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_replay/slice_replay.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SliceReplay::Pass(std::string& err)
{
    ReplayCheck first;
    ReplayCheck second;
    if (!first.Run(1, err)) return false;
    if (!first.Check(err)) return false;
    if (!second.Run(1, err)) return false;
    if (!second.Check(err)) return false;
    if (first.pairs() != static_cast<int64_t>(8) || second.pairs() != static_cast<int64_t>(8)) {
        err = "PAIRS";
        return false;
    }
    if (first.Tamper(err)) {
        err = "TAMPER";
        return false;
    }
    if (err != "BTX035_ID_MISMATCH") return false;
    if (!second.Check(err)) return false;
    if (!err.empty()) return false;
    if (first.pairs() != static_cast<int64_t>(8) || second.pairs() != static_cast<int64_t>(8)) {
        err = "PAIRS";
        return false;
    }
    if (first.hosts() != 1 || first.physical_hosts() != 1 ||
        second.hosts() != 1 || second.physical_hosts() != 1) {
        err = "HOSTS";
        return false;
    }
    if (first.bytes_moved() != static_cast<int64_t>(0) ||
        second.bytes_moved() != static_cast<int64_t>(0)) {
        err = "BYTES";
        return false;
    }
    if (first.launched() || first.gpu() || first.broadcast() || first.qualified() ||
        first.release_qualified() || second.launched() || second.gpu() || second.broadcast() ||
        second.qualified() || second.release_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (passed() || launched() || gpu() || broadcast() || qualified() || release_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (bytes_moved() != static_cast<int64_t>(0)) {
        err = "BYTES";
        return false;
    }
    err.clear();
    return true;
}

bool SliceReplay::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool SliceReplay::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SliceReplay::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
