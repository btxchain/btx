// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_H
#define BITCOIN_MODELNET_SWARM_REMEDY_H

#include <modelnet/swarm_remedy/book.h>
#include <modelnet/swarm_remedy/hold.h>
#include <modelnet/swarm_remedy/leaf.h>
#include <modelnet/swarm_remedy/members.h>
#include <modelnet/swarm_remedy/watch.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory revocation plane.
 * Open calls SwarmNewRevocation. sequence below 1 is SEQUENCE and stores
 * nothing. A second Open is REPLAY and leaves the first. secret_released()
 * stays false after Open.
 * Supersede builds the next revocation and calls SwarmSupersede. A sequence
 * that does not advance is STALE and does not replace the prior. On success
 * the prior keeps the released flag SwarmSupersede wrote. This plane does
 * not assign that flag true.
 * Read of a revoked member is NOT_READ and does not record that read.
 * Revoke of an empty member is MEMBER. A duplicate revoke is REPLAY.
 * Script calls SwarmRemedyScript. An empty hash or pubkey is KEY and returns
 * an empty script. A script that is stored stays local.
 * Watch reports a sequence and does not release a secret.
 * broadcast() is false. bytes_moved() is 0. mined() is false.
 */
class SwarmRemedy {
public:
    bool Open(int sequence, unsigned char fill, std::string& err);
    bool Supersede(int sequence, unsigned char fill, std::string& err);
    bool Revoke(const std::string& member, std::string& err);
    bool Read(const std::string& member, std::string& err);
    std::vector<unsigned char> Script(const std::vector<unsigned char>& secret_hash,
                                      const std::vector<unsigned char>& counterparty_pubkey, std::string& err);
    SwarmRemedyReport Watch(int observed_sequence, int height, int refund_height) const;

    bool broadcast() const { return m_hold.broadcast(); }
    int64_t bytes_moved() const { return m_hold.bytes_moved(); }
    bool mined() const { return m_hold.mined(); }
    bool secret_released() const { return m_book.secret_released(); }

    bool opened() const { return m_book.opened(); }
    bool has_prior() const { return m_book.has_prior(); }
    int sequence() const { return m_book.sequence(); }
    const SwarmRevocation& current() const { return m_book.current(); }
    const SwarmRevocation& prior() const { return m_book.prior(); }
    bool revoked(const std::string& member) const { return m_members.revoked(member); }
    bool read_recorded(const std::string& member) const { return m_members.recorded(member); }
    const std::vector<unsigned char>& script() const { return m_leaf.script(); }

private:
    SwarmRemedyBook m_book;
    SwarmRemedyMembers m_members;
    SwarmRemedyLeaf m_leaf;
    SwarmRemedyHold m_hold;
    SwarmRemedyWatch m_watch;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_H
