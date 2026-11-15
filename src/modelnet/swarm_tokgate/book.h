// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_BOOK_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_BOOK_H

#include <modelnet/swarm_tokgate/record.h>

#include <map>
#include <string>

namespace modelnet {

/**
 * Sessions stored by a successful Open, keyed by session id.
 * store_open refuses an unusable record and a session already present.
 * store_engine refuses an unknown session, a name outside the catalog,
 * and a session that already has an engine name.
 * store_prompt refuses an unknown session, an empty prompt, and a session
 * that already has a public prompt.
 * A refused store leaves the first model id, engine name, and prompt.
 * There is no erase. The stored prompt is not generated output.
 * This book does not start a process, open a socket, or move bytes.
 */
class SwarmTokenGateBook {
public:
    bool open(const std::string& id) const;
    std::string model_id(const std::string& id) const;
    bool engine_bound(const std::string& id) const;
    std::string engine_name(const std::string& id) const;
    bool prompt_stored(const std::string& id) const;
    std::string stored_prompt(const std::string& id) const;

    /**
     * Store a fresh session.
     * Refuses an unusable record, a duplicate id, a bound engine, or a stored prompt.
     * On refusal the book is unchanged.
     */
    bool store_open(const SwarmTokenGateSession& session);

    /**
     * Store the first catalog engine name on an open session.
     * Refuses an unknown session, a name outside the catalog, and a session
     * that is already bound. On refusal the first engine name stays.
     * This does not start a process.
     */
    bool store_engine(const std::string& id, const std::string& engine_name);

    /**
     * Store the first public prompt on an open session.
     * Refuses an unknown session, an empty prompt, and a session that already
     * has a prompt. On refusal the first prompt stays.
     * The prompt is not copied into generated text.
     */
    bool store_prompt(const std::string& id, const std::string& prompt);

private:
    const SwarmTokenGateSession* find(const std::string& id) const;

    std::map<std::string, SwarmTokenGateSession> m_sessions;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_BOOK_H
