// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_WORKSPACE_GIT_H
#define BITCOIN_MODELNET_WORKSPACE_GIT_H

#include <modelnet/workspace_journal.h>
#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Directory tree under a caller-supplied root.
 * File bytes are stored only through WorkspaceBook at the current generation.
 * A stale generation fails with BTX035_GENERATION and does not create a file.
 * ExportFiles and ExportPublic omit private notes.
 */
class WorkspaceGit {
public:
    explicit WorkspaceGit(fs::path root);

    const fs::path& Root() const { return m_root; }

    bool Create(const std::string& name, std::string& err);
    bool Write(const std::string& name, uint64_t generation, const std::string& path,
               const std::vector<unsigned char>& bytes, std::string& err);
    bool Publish(const std::string& name, uint64_t generation, std::string& err);
    bool NotePrivate(const std::string& name, const std::string& text, std::string& err);

    uint64_t Generation(const std::string& name) const;
    std::vector<std::string> ExportFiles(const std::string& name) const;
    std::string ExportPublic(const std::string& name) const;

private:
    bool Materialize(const fs::path& tree, const std::string& path, const std::vector<unsigned char>& bytes,
                     std::string& err) const;

    fs::path m_root;
    WorkspaceBook m_book;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_WORKSPACE_GIT_H
