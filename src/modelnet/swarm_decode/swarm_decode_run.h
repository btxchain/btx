// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_RUN_H
#define BITCOIN_MODELNET_SWARM_DECODE_RUN_H

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/output.h>
#include <modelnet/swarm_decode/status.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process decode run.
 *
 * Open stores a session and one engine name: memory, vllm, sglang, or lmcache.
 * An empty session is SESSION and stores nothing. Any other engine name is
 * ENGINE and stores nothing. A second open of the same session is REPLAY and
 * keeps the first engine.
 *
 * Prompt stores one public prompt. An unknown session is SESSION. A private
 * prompt is PRIVATE_DATA and stores nothing. An empty public prompt is PROMPT
 * and stores nothing. A second different public prompt is HELD and keeps the
 * first. The same public prompt again is REPLAY. text() stays empty until
 * Pull appends a byte. A production engine may store a prompt.
 *
 * Pull on memory appends the next byte of that stored prompt, prompt[tokens()],
 * and increments tokens() by 1. The stream stops when the prompt is exhausted
 * or when 8 bytes have been appended, whichever comes first, and then returns
 * false with DONE. Pull on vllm, sglang, or lmcache returns false with
 * ENGINE_ABSENT, appends nothing, and does not change text() or tokens().
 * Those three engines are not linked.
 *
 * measured(), launched(), and gpu() stay false. bytes_moved() stays 0.
 * The memory echo is the caller's prompt. Appended decode bytes are not counted
 * in bytes_moved().
 */
class SwarmDecodeRun {
public:
    bool Open(const std::string& session, const std::string& engine, std::string& err);
    bool Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err);
    bool Pull(const std::string& session, std::string& err);

    std::string engine_of(const std::string& session) const;
    const std::string& text() const;
    int64_t tokens() const;
    bool measured() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;

private:
    SwarmDecodeBook m_book;
    SwarmDecodeOutput m_output;
    SwarmDecodeStatus m_status;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_RUN_H
