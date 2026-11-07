// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_DIRECTORY_H
#define BITCOIN_MODELNET_SWARM_FORM_DIRECTORY_H

#include <util/fs.h>

#include <filesystem>
#include <string>

namespace modelnet {

/**
 * Opens modeldir/swarm for an in-process formation plane.
 * An empty modeldir is MODELDIR and creates nothing.
 * A symlink at modeldir/swarm is SYMLINK and is not written through.
 * Otherwise the directory is created only when it is missing:
 * fs::create_directories then fs::exists. create_directories returns false
 * when the directory is already present; that return is not a failure.
 * Paths are rebuilt with fs::u8path and utf8string.
 */
class SwarmFormDirectory {
public:
    bool Open(const std::filesystem::path& modeldir, std::string& err);
    const fs::path& path() const { return m_swarm; }
    bool opened() const { return m_opened; }

private:
    fs::path m_swarm;
    bool m_opened{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_DIRECTORY_H
