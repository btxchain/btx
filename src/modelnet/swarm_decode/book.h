// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_BOOK_H
#define BITCOIN_MODELNET_SWARM_DECODE_BOOK_H

#include <modelnet/swarm_decode/record.h>

#include <map>
#include <string>

namespace modelnet {

/**
 * Sessions stored by a successful Open, keyed by session id.
 * store_open refuses an unusable record and a session that is already present.
 * store_prompt refuses an unknown session, an empty prompt, and a session that
 * already holds a public prompt. On refusal the first engine and the first prompt stay.
 * There is no erase. Storing a prompt does not copy it into text().
 */
class SwarmDecodeBook {
public:
    bool open(const std::string& id) const;
    std::string engine_of(const std::string& id) const;
    bool prompt_stored(const std::string& id) const;
    std::string stored_prompt(const std::string& id) const;

    /**
     * Store a fresh session and its engine name.
     * Refuses an unusable record and a duplicate id.
     * On refusal the book is unchanged.
     */
    bool store_open(const SwarmDecodeSession& session);

    /**
     * Store the first public prompt on an open session.
     * Refuses an unknown session, an empty prompt, and a session that already
     * has a prompt. On refusal the first prompt stays.
     * The prompt is not copied into generated text.
     */
    bool store_prompt(const std::string& id, const std::string& prompt);

private:
    const SwarmDecodeSession* find(const std::string& id) const;

    std::map<std::string, SwarmDecodeSession> m_sessions;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_BOOK_H
