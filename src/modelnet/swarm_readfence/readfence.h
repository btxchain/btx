// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_H
#define BITCOIN_MODELNET_SWARM_READFENCE_H

#include <modelnet/swarm_readfence/book.h>
#include <modelnet/swarm_readfence/engine.h>
#include <modelnet/swarm_readfence/ledger.h>
#include <modelnet/swarm_readfence/quiet.h>
#include <modelnet/swarm_readfence/roster.h>
#include <modelnet/swarm_readfence/span.h>
#include <modelnet/swarm_readfence/warm.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Cache-read fence.
 *
 * A revoked member cannot read a placed page. A missing engine moves
 * no bytes. This plane does not start a process and does not allocate
 * a CUDA buffer.
 *
 * Place stores a page id with its family. An empty page or an empty
 * family is PAGE and stores nothing. A later Place of the same page
 * replaces the family. bytes_moved() stays 0.
 *
 * Probe recognizes vllm, sglang, lmcache, nixl, mooncake, and rdma.
 * present false, or a name outside that set, is ENGINE_ABSENT and
 * leaves the engine status unchanged. present true on a known name
 * sets the status to INSTALLED and records that name. qualified() and
 * advertised() stay false either way. process_started() stays false.
 *
 * Prefetch while the engine status is not INSTALLED is ENGINE_ABSENT
 * and records nothing. While INSTALLED the page id is recorded. The
 * page does not have to be placed. bytes_moved() stays 0.
 * cuda_buffer() stays false.
 *
 * Revoke of an empty member is MEMBER and stores nothing. A second
 * Revoke of the same member is REPLAY. Read of an empty member is
 * MEMBER. Read of an empty page is PAGE. Read of a revoked member is
 * NOT_READ and does not record that read. Read of an unplaced page is
 * PAGE. A member who is not revoked records a read of a placed page.
 * A read recorded before a later revoke stays recorded.
 *
 * Accept stores a size only when size > 0 and size <= 33554432.
 * Any other size is TRUNCATED and nothing new is stored.
 */
class SwarmReadFence {
public:
    bool Place(const std::string& page, const std::string& family, std::string& err);
    bool Probe(const std::string& name, bool present, std::string& err);
    bool Prefetch(const std::string& page, std::string& err);
    bool Revoke(const std::string& member, std::string& err);
    bool Read(const std::string& member, const std::string& page, std::string& err);
    bool Accept(int64_t size, std::string& err);

    bool placed(const std::string& page) const { return m_book.placed(page); }
    std::string family(const std::string& page) const { return m_book.family(page); }
    std::size_t page_count() const { return m_book.size(); }

    bool installed() const { return m_engine.installed(); }
    const std::string& engine_name() const { return m_engine.name(); }
    const std::string& engine_status() const { return m_engine.status(); }

    bool prefetched(const std::string& page) const { return m_warm.noted(page); }
    std::size_t prefetch_count() const { return m_warm.size(); }

    bool revoked(const std::string& member) const { return m_roster.revoked(member); }
    std::size_t revoke_count() const { return m_roster.size(); }

    bool recorded(const std::string& member, const std::string& page) const { return m_ledger.recorded(member, page); }
    std::size_t read_count() const { return m_ledger.size(); }

    bool accepted() const { return m_span.held(); }
    int64_t accepted_size() const { return m_span.size(); }

    int64_t bytes_moved() const { return m_quiet.bytes_moved(); }
    bool qualified() const { return m_quiet.qualified(); }
    bool advertised() const { return m_quiet.advertised(); }
    bool process_started() const { return m_quiet.process_started(); }
    bool cuda_buffer() const { return m_quiet.cuda_buffer(); }

private:
    SwarmReadBook m_book;
    SwarmReadEngine m_engine;
    SwarmReadWarm m_warm;
    SwarmReadRoster m_roster;
    SwarmReadLedger m_ledger;
    SwarmReadSpan m_span;
    SwarmReadQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_H
