// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_ATOMIC_H
#define BITCOIN_MODELNET_SWARM_FORM_ATOMIC_H

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Read path into raw if it is a regular file, following a symlink to one. raw is left
 * unchanged on failure. Outside Windows the file is also opened with O_NONBLOCK and checked
 * with fstat on that descriptor, so a FIFO swapped in after the path check is not waited on.
 */
bool SwarmReadRegularFile(const fs::path& path, std::string& raw);

/**
 * Read a regular file. A symlink is SYMLINK and is not followed.
 * A missing path is MISSING. raw is left unchanged on failure.
 */
bool SwarmFormRead(const fs::path& path, std::string& raw, std::string& err);

/**
 * Replace path with body by writing a sibling temp file, committing it to disk and renaming it.
 * A symlink at the destination or the temp path is SYMLINK and is not written through.
 * Outside Windows the temp file is created exclusively; anything else left at the temp path
 * is removed first, so a FIFO there is never opened.
 * A failed write or rename removes the temp file and leaves the destination unchanged.
 * The temp path is built with fs::u8path from the destination's utf8string.
 */
bool SwarmFormWrite(const fs::path& path, const std::string& body, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_ATOMIC_H
