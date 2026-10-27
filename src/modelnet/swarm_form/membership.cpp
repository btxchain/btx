// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/membership.h>

#include <modelnet/swarm_form/atomic.h>
#include <modelnet/swarm_form/codec.h>

#include <algorithm>
#include <system_error>

namespace modelnet {

bool SwarmFormMembership::Save(const fs::path& swarm_dir, std::string& err)
{
    if (m_member.automatic_spend != kAutomaticSpend) {
        err = "SPEND";
        return false;
    }
    m_member.automatic_spend = kAutomaticSpend;
    if (!SwarmFormWrite(swarm_dir / kMembershipFile, EncodeMember(m_member), err)) return false;
    m_dir = swarm_dir;
    return true;
}

bool SwarmFormMembership::Load(const fs::path& swarm_dir, std::string& err)
{
    std::string raw;
    if (!SwarmFormRead(swarm_dir / kMembershipFile, raw, err)) return false;
    SwarmFormMember decoded;
    if (!DecodeMember(raw, decoded, err)) return false;
    m_member = std::move(decoded);
    m_dir = swarm_dir;
    m_formed = true;
    err.clear();
    return true;
}

bool SwarmFormMembership::Form(const fs::path& swarm_dir, std::string& err)
{
    const fs::path file = swarm_dir / kMembershipFile;
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(file, ec);
    if (!ec && fs::is_symlink(status)) {
        err = "SYMLINK";
        return false;
    }
    if (fs::exists(file)) {
        if (Load(swarm_dir, err)) return true;
        // A crash can leave an empty or torn file. Set a SCHEMA failure aside
        // once and form again, instead of failing on every observer pass.
        // Other refusals (READ, SPEND) stay refusals.
        if (err != "SCHEMA") return false;
        fs::rename(file, fs::u8path(file.utf8string() + ".bad"), ec);
        if (ec) {
            err = "RENAME";
            return false;
        }
    }
    m_member = LocalFormationMember();
    m_formed = true;
    m_dir = swarm_dir;
    if (!Save(swarm_dir, err)) {
        m_formed = false;
        m_member = SwarmFormMember{};
        return false;
    }
    return true;
}

bool SwarmFormMembership::Admit(const fs::path& swarm_dir, const std::string& peer_id, std::string& err)
{
    if (peer_id.empty()) {
        err = "PEER";
        return false;
    }
    if (!m_formed || m_dir != swarm_dir) {
        if (!Load(swarm_dir, err)) return false;
    }
    if (admitted(peer_id)) {
        err.clear();
        return true;
    }
    m_member.admitted.push_back(peer_id);
    std::sort(m_member.admitted.begin(), m_member.admitted.end());
    return Save(swarm_dir, err);
}

bool SwarmFormMembership::admitted(const std::string& node_id) const
{
    return std::find(m_member.admitted.begin(), m_member.admitted.end(), node_id) != m_member.admitted.end();
}

} // namespace modelnet
