// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_QUOTA_H
#define BTX_MODELNET_SWARM_QUOTA_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory piece accounting. A pin occupies its bytes until the book is
 * dropped. This book does not write a file, encrypt a body, or broadcast.
 */
class SwarmQuotaBook {
public:
    /** A non-positive cap is QUOTA. A second Open is REOPEN. */
    bool Open(int64_t cap_bytes, std::string& err);

    /**
     * An empty id or a non-positive size is PIN. The same id and the same
     * size succeeds and does not add the bytes again; that call pins the row.
     * A different size for the same id is CONFLICT. A new row that would
     * exceed the cap is QUOTA and is not stored.
     */
    bool Pin(const std::string& piece_id, int64_t bytes, std::string& err);

    /**
     * Same id and size rules as Pin, and the new row is unpinned. The same
     * id and the same size succeeds, does not add the bytes again, and leaves
     * an existing pin in place. A size that would exceed the cap is QUOTA.
     * That failure leaves Used and Pinned unchanged.
     */
    bool Store(const std::string& piece_id, int64_t bytes, std::string& err);

    int64_t Used() const;
    int Pinned() const;

private:
    struct Row {
        int64_t bytes{0};
        bool pinned{false};
    };

    bool Admit(const std::string& piece_id, int64_t bytes, bool pin, std::string& err);

    bool m_open{false};
    int64_t m_cap{0};
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_QUOTA_H
