// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/directory.h>

#include <filesystem>
#include <system_error>

namespace modelnet {

bool SwarmFormDirectory::Open(const std::filesystem::path& modeldir, std::string& err)
{
    m_opened = false;
    m_swarm.clear();
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    const fs::path model = fs::u8path(fs::path(modeldir).utf8string());
    const fs::path swarm = model / "swarm";
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(swarm, ec);
    if (!ec && fs::is_symlink(status)) {
        err = "SYMLINK";
        return false;
    }
    bool created = false;
    try {
        created = fs::create_directories(swarm);
        // create_directories returns false when the directory already exists.
        if (!created && !fs::exists(swarm)) {
            err = "SWARM_DIR";
            return false;
        }
        if (!fs::exists(swarm)) {
            err = "SWARM_DIR";
            return false;
        }
    } catch (const std::filesystem::filesystem_error&) {
        err = "SWARM_DIR";
        return false;
    }
    m_swarm = swarm;
    m_opened = true;
    err.clear();
    return true;
}

} // namespace modelnet
