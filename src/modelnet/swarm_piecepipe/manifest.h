// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_MANIFEST_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_MANIFEST_H

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Manifest roots keyed by artifact id.
 * The slice list is the ordered piece ids of one body. usable starts false.
 * A second put of the same slice list keeps the first, including its usable bit.
 * A different slice list for the same artifact id is refused and the first stays.
 */
class SwarmPiecePipeManifestBook {
public:
    bool Put(const std::string& artifact, const std::vector<std::string>& slice_ids, std::string& err);
    bool contains(const std::string& artifact) const;
    bool same_slices(const std::string& artifact, const std::vector<std::string>& slice_ids) const;
    bool requires_slice(const std::string& id) const;
    bool marked_usable(const std::string& artifact) const;
    void mark_usable(const std::string& artifact);
    void clear_usable(const std::string& artifact);
    std::vector<std::string> slice_ids(const std::string& artifact) const;
    std::size_t count() const;

private:
    struct Row {
        std::vector<std::string> slices;
        bool usable{false};
    };

    void NoteRequired(const std::vector<std::string>& slice_ids);

    std::map<std::string, Row> m_rows;
    std::map<std::string, std::size_t> m_required;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_MANIFEST_H
