// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_MEMBERSHIP_H
#define BITCOIN_MODELNET_SWARM_FORM_MEMBERSHIP_H

#include <modelnet/swarm_form/types.h>

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Local membership file for one swarm directory.
 * The first Form writes the local seeder/evaluator record and admits "local".
 * A later Form of an existing valid membership returns success and does not rewrite the file.
 */
class SwarmFormMembership {
public:
    bool Form(const fs::path& swarm_dir, std::string& err);
    bool Load(const fs::path& swarm_dir, std::string& err);
    bool Admit(const fs::path& swarm_dir, const std::string& peer_id, std::string& err);
    bool admitted(const std::string& node_id) const;
    bool formed() const { return m_formed; }
    const SwarmFormMember& member() const { return m_member; }

private:
    bool Save(const fs::path& swarm_dir, std::string& err);
    SwarmFormMember m_member;
    fs::path m_dir;
    bool m_formed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_MEMBERSHIP_H
