// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TOOLREUSE_H
#define BTX_MODELNET_SWARM_TOOLREUSE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * One locally stored tool result. Reuse is not execution and not a transfer.
 * executed and bytes_moved stay false. This book does not launch a process.
 */
struct SwarmToolRecord {
    std::string tool_id;
    std::string arg_digest;
    std::string tenant;
    std::string body;
    bool public_result{false};
    bool private_data{false};
    bool credential{false};
    bool executable{false};
};

struct SwarmToolReuse {
    bool reused{false};
    bool executed{false};
    bool bytes_moved{false};
    std::string body;
    std::string code;
};

/**
 * Local tool-result book. A result is reusable only for the same tool, the
 * same 96-character lowercase argument digest, and the same tenant.
 * Another tenant gets the same absence code as a missing row. The body of
 * another tenant is not copied. This book does not execute and does not
 * move bytes.
 */
class SwarmToolBook {
public:
    /**
     * Order: an empty tool, digest, tenant, or body is TOOL. A digest that
     * is not 96 lowercase hex characters is TOOL. A credential, a private
     * body, or a result that is not marked public is PRIVATE_DATA. An
     * executable body is CODE_REFUSED. Each of those refusals stores nothing.
     * The same key and the same body is idempotent. A different body for
     * that key is CONFLICT and the stored body stays the first one.
     */
    bool Store(const SwarmToolRecord& record, std::string& err);

    /**
     * Order: an empty tool, digest, or tenant is TOOL. A digest that is not
     * 96 lowercase hex characters is TOOL. A key that is not stored for
     * this tenant is TOOL_ABSENT. The body field stays empty on every
     * refusal. A hit copies the stored body, sets reused, and uses OK.
     * executed and bytes_moved stay false. err is clear only on a hit.
     */
    SwarmToolReuse Reuse(const std::string& tool_id, const std::string& arg_digest, const std::string& tenant,
                         std::string& err) const;

private:
    struct Key {
        std::string tenant;
        std::string tool_id;
        std::string arg_digest;
        bool operator<(const Key& other) const
        {
            if (tenant != other.tenant) return tenant < other.tenant;
            if (tool_id != other.tool_id) return tool_id < other.tool_id;
            return arg_digest < other.arg_digest;
        }
    };

    std::map<Key, std::string> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TOOLREUSE_H
