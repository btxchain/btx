// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_H

#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/latency.h>
#include <modelnet/swarm_tokgate/output.h>
#include <modelnet/swarm_tokgate/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process token session gate.
 * This plane records a decode session, one catalog engine name, and one
 * public prompt. It does not exec an engine, open a socket, or move bytes.
 * It does not invent tokens or a latency.
 *
 * Open stores session and model_id. An empty session or an empty model_id
 * is MODEL and stores nothing. A second open of the same session is REPLAY
 * and keeps the first model id. running() stays false.
 *
 * BindEngine stores one of vllm, sglang, or lmcache. An unknown session is
 * SESSION. An empty name, or any other name, is ENGINE and stores nothing.
 * A second bind of the same session and the same name is REPLAY. A different
 * catalog name is HELD and keeps the first. Binding does not start a process.
 * running() stays false.
 *
 * Prompt stores one public prompt. An unknown session is SESSION. A private
 * prompt is PRIVATE_DATA and stores nothing. An empty public prompt is
 * PROMPT and stores nothing. The same public prompt again is REPLAY. A
 * different public prompt is HELD and keeps the first. The stored prompt
 * is not generated output. text() stays empty.
 *
 * Decode returns false. An unknown session is SESSION. Every open session
 * is ENGINE_ABSENT, including a session bound to vllm. A bound engine name
 * is not a generation. tokens() stays 0. text() stays empty.
 *
 * Measure returns false. An unknown session is SESSION. Every open session
 * is NOT_MEASURED. ttft_ms(), p50_ms(), and p95_ms() stay -1. measured()
 * stays false.
 *
 * running(), launched(), and gpu() stay false. bytes_moved() stays 0.
 * There is no method that sets text() non-empty, tokens() above 0, or
 * measured() true.
 */
class SwarmTokenGate {
public:
    bool Open(const std::string& session, const std::string& model_id, std::string& err);
    bool BindEngine(const std::string& session, const std::string& engine_name, std::string& err);
    bool Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err);
    bool Decode(const std::string& session, std::string& err);
    bool Measure(const std::string& session, std::string& err);

    bool open(const std::string& session) const;
    std::string model_id(const std::string& session) const;
    std::string engine_name(const std::string& session) const;
    bool prompt_stored(const std::string& session) const;

    const std::string& text() const;
    int64_t tokens() const;
    int64_t ttft_ms() const;
    int64_t p50_ms() const;
    int64_t p95_ms() const;
    bool measured() const;
    bool running() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;

private:
    SwarmTokenGateBook m_book;
    SwarmTokenGateOutput m_output;
    SwarmTokenGateLatency m_latency;
    SwarmTokenGateQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_H
