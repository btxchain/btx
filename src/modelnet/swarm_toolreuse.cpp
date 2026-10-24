// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_toolreuse.h>

#include <modelnet/swarm_codec.h>

namespace modelnet {

bool SwarmToolBook::Store(const SwarmToolRecord& record, std::string& err)
{
    if (record.tool_id.empty() || record.arg_digest.empty() || record.tenant.empty() || record.body.empty()) {
        err = "TOOL";
        return false;
    }
    if (!SwarmFixedId(record.arg_digest)) {
        err = "TOOL";
        return false;
    }
    if (record.credential || record.private_data || !record.public_result) {
        err = "PRIVATE_DATA";
        return false;
    }
    if (record.executable) {
        err = "CODE_REFUSED";
        return false;
    }
    const Key key{record.tenant, record.tool_id, record.arg_digest};
    const auto found = m_rows.find(key);
    if (found != m_rows.end()) {
        if (found->second != record.body) {
            err = "CONFLICT";
            return false;
        }
        err.clear();
        return true;
    }
    m_rows.emplace(key, record.body);
    err.clear();
    return true;
}

SwarmToolReuse SwarmToolBook::Reuse(const std::string& tool_id, const std::string& arg_digest, const std::string& tenant,
                                    std::string& err) const
{
    SwarmToolReuse out;
    if (tool_id.empty() || arg_digest.empty() || tenant.empty() || !SwarmFixedId(arg_digest)) {
        out.code = "TOOL";
        err = "TOOL";
        return out;
    }
    const Key key{tenant, tool_id, arg_digest};
    const auto found = m_rows.find(key);
    if (found == m_rows.end()) {
        out.code = "TOOL_ABSENT";
        err = "TOOL_ABSENT";
        return out;
    }
    out.reused = true;
    out.executed = false;
    out.bytes_moved = false;
    out.body = found->second;
    out.code = "OK";
    err.clear();
    return out;
}

} // namespace modelnet
