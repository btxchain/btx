// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_INFERLINK_H
#define BITCOIN_MODELNET_SWARM_INFERLINK_H

#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** The session id is empty. Nothing is stored. */
inline constexpr char kSwarmInferLinkSession[] = "SESSION";

/** The engine name is not memory, vllm, sglang, or lmcache. Nothing is stored. */
inline constexpr char kSwarmInferLinkEngine[] = "ENGINE";

/** This session is already open. The first engine stays. */
inline constexpr char kSwarmInferLinkReplay[] = "REPLAY";

/** The prompt is private. Nothing is stored. */
inline constexpr char kSwarmInferLinkPrivateData[] = "PRIVATE_DATA";

/** The public prompt is empty. Nothing is stored. */
inline constexpr char kSwarmInferLinkPrompt[] = "PROMPT";

/** vllm, sglang, and lmcache are not linked. Pull appends nothing. */
inline constexpr char kSwarmInferLinkEngineAbsent[] = "ENGINE_ABSENT";

/** The memory pull loop has finished. */
inline constexpr char kSwarmInferLinkDone[] = "DONE";

/** In-process engine. Run opens this name and pulls through SwarmDecodeRun. */
inline constexpr char kSwarmInferLinkMemory[] = "memory";

/** Named engines. RunNamed opens one of these and does not invent decode bytes. */
inline constexpr char kSwarmInferLinkVllm[] = "vllm";
inline constexpr char kSwarmInferLinkSglang[] = "sglang";
inline constexpr char kSwarmInferLinkLmcache[] = "lmcache";

/** automatic_spend() returns this. Nothing is spent. */
inline constexpr char kSwarmInferLinkAutomaticSpend[] = "0";

/**
 * Linked inference session.
 *
 * Open, Prompt, and Pull call SwarmDecodeRun. The memory byte echo stays
 * in that engine. This class does not copy prompt bytes itself.
 *
 * Open stores one session on memory, vllm, sglang, or lmcache. An empty
 * session is SESSION and stores nothing. Any other engine name is ENGINE
 * and stores nothing. A second open of the same session is REPLAY and
 * keeps the first engine.
 *
 * Prompt forwards to SwarmDecodeRun::Prompt. A private prompt is
 * PRIVATE_DATA and stores nothing. Pull forwards to SwarmDecodeRun::Pull.
 *
 * Run opens memory, prompts the text as public, then pulls until the
 * decode engine returns false. A non-empty public prompt ends as DONE.
 * text() is the prompt truncated to 8 bytes, and tokens() is that length.
 * ttft_ms() is steady_clock milliseconds from the start of that pull loop
 * until the first successful pull. When the first pull is the only pull,
 * ttft_ms() is the whole loop. p50_ms() and p95_ms() are that same elapsed
 * loop time: one loop is one sample. These are timings of this in-process
 * loop only. measured_local() becomes true only after memory emitted at
 * least one byte. measured_gpu() stays false. gpu() stays false.
 * launched() stays false.
 *
 * RunNamed for vllm, sglang, or lmcache opens that engine, prompts, pulls
 * once, and returns false with ENGINE_ABSENT. text() stays empty, tokens()
 * stay 0, and measured_local() stays false. No tokens or text are invented.
 *
 * bytes_moved() stays 0. automatic_spend() returns "0". broadcast() stays
 * false. There is no spawn and no sidecar.
 */
class SwarmInferLink {
public:
    /**
     * Open one session.
     * An empty session is SESSION and stores nothing.
     * An engine other than memory, vllm, sglang, or lmcache is ENGINE and
     * stores nothing. A second open of the same session is REPLAY and keeps
     * the first engine.
     */
    bool Open(const std::string& session, const std::string& engine, std::string& err);

    /**
     * Forward to SwarmDecodeRun::Prompt.
     * A private prompt is PRIVATE_DATA and stores nothing.
     */
    bool Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err);

    /** Forward to SwarmDecodeRun::Pull. */
    bool Pull(const std::string& session, std::string& err);

    /**
     * Open memory, prompt text as public, then pull until SwarmDecodeRun
     * returns false.
     * Returns true when that loop finishes with DONE. A non-empty prompt
     * leaves text() as the prompt truncated to 8 bytes and tokens() as
     * that length. The pull-loop clock is stored in ttft_ms(), p50_ms(),
     * and p95_ms(). measured_local() becomes true only after a successful
     * memory pull.
     */
    bool Run(const std::string& session, const std::string& text, std::string& err);

    /**
     * For vllm, sglang, or lmcache: open, prompt as public, pull once, and
     * return false with ENGINE_ABSENT. text() is left empty and tokens()
     * stay 0. measured_local() stays false.
     * Any other engine follows Open and does not pull.
     */
    bool RunNamed(const std::string& session, const std::string& engine, const std::string& text, std::string& err);

    /** Engine stored for session, or empty when the session is not open. */
    std::string engine_of(const std::string& session) const;

    /** Bytes appended by SwarmDecodeRun. Empty until a memory pull. */
    const std::string& text() const;

    /** Count of bytes appended by SwarmDecodeRun. */
    int64_t tokens() const;

    /**
     * Milliseconds from the start of the Run pull loop until the first
     * successful pull. The whole loop when that first pull is the only one.
     */
    int64_t ttft_ms() const;

    /** Elapsed milliseconds of the one Run pull loop. */
    int64_t p50_ms() const;

    /** Same elapsed milliseconds as p50_ms() for that one loop. */
    int64_t p95_ms() const;

    /** True only after a memory pull appended at least one byte. */
    bool measured_local() const;

    /** Stays false. A local loop is not a GPU measurement. */
    bool measured_gpu() const;

    /** Stays false. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

    /** Stays 0. Appended decode bytes are not counted. */
    int64_t bytes_moved() const;

    /** Returns "0". */
    std::string automatic_spend() const;

    /** Stays false. Nothing is broadcast. */
    bool broadcast() const;

private:
    SwarmDecodeRun m_decode;
    int64_t m_ttft_ms{0};
    int64_t m_p50_ms{0};
    int64_t m_p95_ms{0};
    bool m_measured_local{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_INFERLINK_H
