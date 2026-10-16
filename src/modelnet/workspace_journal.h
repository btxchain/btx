// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_WORKSPACE_JOURNAL_H
#define BITCOIN_MODELNET_WORKSPACE_JOURNAL_H

#include <cstdint>
#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** True when the two path payloads differ. Equal bytes, including both empty, are not a conflict. */
bool Conflict(const std::vector<unsigned char>& path_a_bytes, const std::vector<unsigned char>& path_b_bytes);

/**
 * In-memory operation journal for one process.
 * Trees are independent. Private notes never appear in ExportPublic.
 * A cancelled op id rejects a later Complete without writing.
 */
class WorkspaceBook {
public:
    bool OpenTree(const std::string& name, std::string& err);
    bool Put(const std::string& name, uint64_t generation, const std::string& path,
             const std::vector<unsigned char>& bytes, std::string& err);
    /** conflict rejects publication. public_ok records a publication id; either way a success bumps generation. */
    bool Publish(const std::string& name, uint64_t generation, bool conflict, bool public_ok, std::string& err);
    bool Undo(const std::string& name, std::string& err);
    bool NotePrivate(const std::string& name, const std::string& text, std::string& err);
    std::string ExportPublic(const std::string& name) const;
    bool Cancel(const std::string& name, const std::string& op_id, std::string& err);
    bool Complete(const std::string& name, const std::string& op_id, uint64_t generation, const std::string& path,
                  const std::vector<unsigned char>& bytes, std::string& err);

    struct TreeImage {
        uint64_t generation{1};
        std::map<std::string, std::vector<unsigned char>> live;
        std::map<uint64_t, std::map<std::string, std::vector<unsigned char>>> closed;
        std::vector<uint64_t> publication_ids;
        uint64_t next_publication{1};
        std::set<std::string> cancelled;
        std::set<std::string> completed;
    };

    std::vector<std::string> TreeNames() const;
    bool ExportTree(const std::string& name, TreeImage& out) const;
    bool ImportTree(const std::string& name, const TreeImage& image, std::string& err);

    uint64_t Generation(const std::string& name) const;
    bool Read(const std::string& name, const std::string& path, std::vector<unsigned char>& bytes) const;
    std::vector<uint64_t> PublicationIds(const std::string& name) const;
    size_t PrivateNoteCount(const std::string& name) const;

private:
    struct Tree {
        uint64_t generation{1};
        std::map<std::string, std::vector<unsigned char>> live;
        /** Path map closed when this generation was published. Undo restores it. */
        std::map<uint64_t, std::map<std::string, std::vector<unsigned char>>> closed;
        std::vector<std::string> private_notes;
        std::vector<uint64_t> publication_ids;
        uint64_t next_publication{1};
        std::set<std::string> cancelled;
        std::set<std::string> completed;
    };

    Tree* Find(const std::string& name);
    const Tree* Find(const std::string& name) const;

    std::map<std::string, Tree> m_trees;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_WORKSPACE_JOURNAL_H
