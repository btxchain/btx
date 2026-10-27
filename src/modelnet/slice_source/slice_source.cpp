// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_source/slice_source.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SliceSource::Pass(std::string& err)
{
    SnapshotPull first;
    SnapshotPull second;
    if (!first.Publish(static_cast<int64_t>(1), "d1", "body", err)) return false;
    if (!first.Pull(static_cast<int64_t>(1), "d1", err)) return false;
    if (second.Pull(static_cast<int64_t>(1), "d1", err)) {
        err = SNAPSHOT_PULL_MISMATCH;
        return false;
    }
    if (err != SNAPSHOT_PULL_MISMATCH) return false;
    if (first.Hosts(static_cast<int64_t>(2), err)) {
        err = SNAPSHOT_PULL_HOSTS;
        return false;
    }
    if (err != SNAPSHOT_PULL_HOSTS) return false;
    if (first.hosts() != static_cast<int64_t>(1) ||
        first.physical_hosts() != static_cast<int64_t>(1) ||
        second.hosts() != static_cast<int64_t>(1) ||
        second.physical_hosts() != static_cast<int64_t>(1)) {
        err = SNAPSHOT_PULL_HOSTS;
        return false;
    }
    if (first.logical_peers() != static_cast<int64_t>(2) ||
        second.logical_peers() != static_cast<int64_t>(2)) {
        err = "PEERS";
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
    err.clear();
    return true;
}

bool SliceSource::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SliceSource::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool SliceSource::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool SliceSource::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
