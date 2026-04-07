// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <headerssync.h>
#include <logging.h>
#include <pow.h>
#include <util/check.h>
#include <util/time.h>
#include <util/vector.h>

#include <algorithm>
#include <limits>
#include <optional>

// The two constants below are computed using the simulation script in
// contrib/devtools/headerssync-params.py.

//! Store one header commitment per HEADER_COMMITMENT_PERIOD blocks.
constexpr size_t HEADER_COMMITMENT_PERIOD{350};

//! Only feed headers to validation once this many headers on top have been
//! received and validated against commitments.
constexpr size_t REDOWNLOAD_BUFFER_SIZE{7924}; // 7924/350 = ~22.6 commitments

//! Synthetic index history kept for MatMul schedule-aware GetNextWorkRequired replay.
constexpr size_t MATMUL_SYNTHETIC_INDEX_WINDOW{180};

bool IsDisabledHeight(int32_t height)
{
    return height == std::numeric_limits<int32_t>::max();
}

std::optional<int> MatMulRequiredSyntheticFloor(
    const Consensus::Params& params,
    const CBlockIndex* previous_index)
{
    if (!params.fMatMulPOW || previous_index == nullptr) return std::nullopt;

    const int64_t next_height = static_cast<int64_t>(previous_index->nHeight) + 1;
    if (next_height <= params.nMatMulAsertHeight) return std::nullopt;

    int32_t anchor_height = params.nMatMulAsertHeight;
    const bool retune_enabled =
        !IsDisabledHeight(params.nMatMulAsertRetuneHeight) &&
        params.nMatMulAsertRetuneHeight >= params.nMatMulAsertHeight;
    const bool retune2_enabled =
        !IsDisabledHeight(params.nMatMulAsertRetune2Height) &&
        params.nMatMulAsertRetune2Height >= params.nMatMulAsertHeight;

    if (retune2_enabled && previous_index->nHeight >= params.nMatMulAsertRetune2Height) {
        anchor_height = params.nMatMulAsertRetune2Height;
    } else if (retune_enabled && previous_index->nHeight >= params.nMatMulAsertRetuneHeight) {
        anchor_height = params.nMatMulAsertRetuneHeight;
    }

    if (anchor_height > previous_index->nHeight || anchor_height < 0) return std::nullopt;
    return anchor_height;
}

bool IsRepresentableBlockIndexHeight(int64_t height)
{
    return height >= 0 && height <= std::numeric_limits<int>::max();
}

// Our memory analysis assumes 160 bytes for a CompressedHeader (so we should
// re-calculate parameters if we compress further)
static_assert(sizeof(CompressedHeader) == 160);

HeadersSyncState::HeadersSyncState(NodeId id, const Consensus::Params& consensus_params,
        const CBlockIndex* chain_start, const arith_uint256& minimum_required_work) :
    m_commit_offset(FastRandomContext().randrange<unsigned>(HEADER_COMMITMENT_PERIOD)),
    m_id(id), m_consensus_params(consensus_params),
    m_chain_start(chain_start),
    m_minimum_required_work(minimum_required_work),
    m_current_chain_work(chain_start->nChainWork),
    m_last_header_received(m_chain_start->GetBlockHeader()),
    m_current_height(chain_start->nHeight),
    m_presync_last_index(const_cast<CBlockIndex*>(chain_start)),
    m_redownload_last_index(const_cast<CBlockIndex*>(chain_start))
{
    // Estimate the number of blocks that could possibly exist on the peer's
    // chain *right now* using 6 blocks/second (fastest blockrate given the MTP
    // rule) times the number of seconds from the last allowed block until
    // today. This serves as a memory bound on how many commitments we might
    // store from this peer, and we can safely give up syncing if the peer
    // exceeds this bound, because it's not possible for a consensus-valid
    // chain to be longer than this (at the current time -- in the future we
    // could try again, if necessary, to sync a longer chain).
    const int64_t seconds_since_chain_start{
        Ticks<std::chrono::seconds>(NodeClock::now() - NodeSeconds{std::chrono::seconds{chain_start->GetMedianTimePast()}})
    };
    const int64_t bounded_seconds_since_chain_start{
        std::clamp<int64_t>(seconds_since_chain_start,
                            -MAX_FUTURE_BLOCK_TIME,
                            std::numeric_limits<int64_t>::max() - MAX_FUTURE_BLOCK_TIME)
    };
    const uint64_t possible_chain_seconds{
        static_cast<uint64_t>(bounded_seconds_since_chain_start + MAX_FUTURE_BLOCK_TIME)
    };
    const uint64_t max_possible_blocks{
        possible_chain_seconds > (std::numeric_limits<uint64_t>::max() / 6)
            ? std::numeric_limits<uint64_t>::max()
            : possible_chain_seconds * 6
    };
    m_max_commitments = max_possible_blocks / HEADER_COMMITMENT_PERIOD;

    LogDebug(BCLog::NET, "Initial headers sync started with peer=%d: height=%i, max_commitments=%i, min_work=%s\n", m_id, m_current_height, m_max_commitments, m_minimum_required_work.ToString());
}

/** Free any memory in use, and mark this object as no longer usable. This is
 * required to guarantee that we won't reuse this object with the same
 * SaltedTxidHasher for another sync. */
void HeadersSyncState::Finalize()
{
    Assume(m_download_state != State::FINAL);
    ClearShrink(m_header_commitments);
    m_last_header_received.SetNull();
    ClearShrink(m_redownloaded_headers);
    m_redownload_buffer_last_hash.SetNull();
    m_redownload_buffer_first_prev_hash.SetNull();
    m_process_all_remaining_headers = false;
    m_current_height = 0;
    m_presync_last_index = nullptr;
    m_redownload_last_index = nullptr;
    m_presync_index_window.clear();
    m_redownload_index_window.clear();

    m_download_state = State::FINAL;
}

/** Process the next batch of headers received from our peer.
 *  Validate and store commitments, and compare total chainwork to our target to
 *  see if we can switch to REDOWNLOAD mode.  */
HeadersSyncState::ProcessingResult HeadersSyncState::ProcessNextHeaders(const
        std::vector<CBlockHeader>& received_headers, const bool full_headers_message)
{
    ProcessingResult ret;

    Assume(!received_headers.empty());
    if (received_headers.empty()) return ret;

    Assume(m_download_state != State::FINAL);
    if (m_download_state == State::FINAL) return ret;

    if (m_download_state == State::PRESYNC) {
        // During PRESYNC, we minimally validate block headers and
        // occasionally add commitments to them, until we reach our work
        // threshold (at which point m_download_state is updated to REDOWNLOAD).
        ret.success = ValidateAndStoreHeadersCommitments(received_headers);
        if (ret.success) {
            if (full_headers_message || m_download_state == State::REDOWNLOAD) {
                // A full headers message means the peer may have more to give us;
                // also if we just switched to REDOWNLOAD then we need to re-request
                // headers from the beginning.
                ret.request_more = true;
            } else {
                Assume(m_download_state == State::PRESYNC);
                // If we're in PRESYNC and we get a non-full headers
                // message, then the peer's chain has ended and definitely doesn't
                // have enough work, so we can stop our sync.
                LogDebug(
                    BCLog::NET,
                    "Initial headers sync aborted with peer=%d: incomplete headers message at height=%i (presync phase, chain_work=%s, min_work=%s)\n",
                    m_id,
                    m_current_height,
                    m_current_chain_work.ToString(),
                    m_minimum_required_work.ToString());
            }
        }
    } else if (m_download_state == State::REDOWNLOAD) {
        // During REDOWNLOAD, we compare our stored commitments to what we
        // receive, and add headers to our redownload buffer. When the buffer
        // gets big enough (meaning that we've checked enough commitments),
        // we'll return a batch of headers to the caller for processing.
        ret.success = true;
        for (const auto& hdr : received_headers) {
            if (!ValidateAndStoreRedownloadedHeader(hdr)) {
                // Something went wrong -- the peer gave us an unexpected chain.
                // We could consider looking at the reason for failure and
                // punishing the peer, but for now just give up on sync.
                ret.success = false;
                break;
            }
        }

        if (ret.success) {
            // Return any headers that are ready for acceptance.
            ret.pow_validated_headers = PopHeadersReadyForAcceptance();

            // If we hit our target blockhash, then all remaining headers will be
            // returned and we can clear any leftover internal state.
            if (m_redownloaded_headers.empty() && m_process_all_remaining_headers) {
                LogDebug(BCLog::NET, "Initial headers sync complete with peer=%d: releasing all at height=%i (redownload phase)\n", m_id, m_redownload_buffer_last_height);
            } else if (full_headers_message) {
                // If the headers message is full, we need to request more.
                ret.request_more = true;
            } else {
                // For some reason our peer gave us a high-work chain, but is now
                // declining to serve us that full chain again. Give up.
                // Note that there's no more processing to be done with these
                // headers, so we can still return success.
                LogDebug(
                    BCLog::NET,
                    "Initial headers sync aborted with peer=%d: incomplete headers message at height=%i (redownload phase, chain_work=%s, min_work=%s)\n",
                    m_id,
                    m_redownload_buffer_last_height,
                    m_redownload_chain_work.ToString(),
                    m_minimum_required_work.ToString());
            }
        }
    }

    if (!(ret.success && ret.request_more)) Finalize();
    return ret;
}

bool HeadersSyncState::ValidateAndStoreHeadersCommitments(const std::vector<CBlockHeader>& headers)
{
    // The caller should not give us an empty set of headers.
    Assume(headers.size() > 0);
    if (headers.size() == 0) return true;

    Assume(m_download_state == State::PRESYNC);
    if (m_download_state != State::PRESYNC) return false;

    if (headers[0].hashPrevBlock != m_last_header_received.GetHash()) {
        // Somehow our peer gave us a header that doesn't connect.
        // This might be benign -- perhaps our peer reorged away from the chain
        // they were on. Give up on this sync for now (likely we will start a
        // new sync with a new starting point).
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: non-continuous headers at height=%i (presync phase)\n", m_id, m_current_height);
        return false;
    }

    // If it does connect, (minimally) validate and occasionally store
    // commitments.
    for (const auto& hdr : headers) {
        if (!ValidateAndProcessSingleHeader(hdr)) {
            return false;
        }
    }

    if (m_current_chain_work >= m_minimum_required_work) {
        m_redownloaded_headers.clear();
        m_redownload_buffer_last_height = m_chain_start->nHeight;
        m_redownload_buffer_first_prev_hash = m_chain_start->GetBlockHash();
        m_redownload_buffer_last_hash = m_chain_start->GetBlockHash();
        m_redownload_chain_work = m_chain_start->nChainWork;
        m_redownload_last_index = const_cast<CBlockIndex*>(m_chain_start);
        m_redownload_index_window.clear();
        m_download_state = State::REDOWNLOAD;
        LogDebug(
            BCLog::NET,
            "Initial headers sync transition with peer=%d: reached sufficient work at height=%i, redownloading from height=%i (chain_work=%s, min_work=%s)\n",
            m_id,
            m_current_height,
            m_redownload_buffer_last_height,
            m_current_chain_work.ToString(),
            m_minimum_required_work.ToString());
    }
    return true;
}

void HeadersSyncState::AdvanceSyntheticIndexWindow(
    const CBlockHeader& header,
    int64_t next_height,
    CBlockIndex*& last_index,
    std::list<CBlockIndex>& index_window)
{
    Assume(IsRepresentableBlockIndexHeight(next_height));
    index_window.emplace_back(header);
    CBlockIndex& synthesized = index_window.back();
    synthesized.nHeight = static_cast<int>(next_height);
    synthesized.pprev = last_index;
    last_index = &synthesized;

    const std::optional<int> retained_floor = MatMulRequiredSyntheticFloor(m_consensus_params, last_index);

    // Keep bounded memory while retaining chain continuity to m_chain_start.
    // For MatMul ASERT replay, retain the active anchor ancestry floor so
    // GetAncestor(anchor_height) remains valid in long presync/redownload runs.
    while (index_window.size() > MATMUL_SYNTHETIC_INDEX_WINDOW) {
        auto oldest = index_window.begin();
        auto second = oldest;
        ++second;
        if (second == index_window.end()) break;
        if (retained_floor.has_value() && oldest->nHeight >= *retained_floor) break;
        second->pprev = oldest->pprev;
        index_window.erase(oldest);
    }
}

bool HeadersSyncState::ValidateAndAdvanceMatMulDifficulty(
    const CBlockHeader& header,
    int64_t next_height,
    bool redownload_phase)
{
    if (!IsRepresentableBlockIndexHeight(next_height)) return false;
    CBlockIndex* previous = redownload_phase ? m_redownload_last_index : m_presync_last_index;
    if (previous == nullptr) return false;

    const unsigned int expected_nbits = GetNextWorkRequired(previous, &header, m_consensus_params);
    if (header.nBits != expected_nbits) {
        const std::list<CBlockIndex>& index_window = redownload_phase ? m_redownload_index_window : m_presync_index_window;
        const int64_t oldest_height = index_window.empty() ? -1 : index_window.front().nHeight;
        const int64_t newest_height = index_window.empty() ? -1 : index_window.back().nHeight;
        const std::optional<int> retained_floor = MatMulRequiredSyntheticFloor(m_consensus_params, previous);
        LogDebug(
            BCLog::NET,
            "Initial headers sync aborted with peer=%d: MatMul nBits mismatch at height=%lld (%s phase) expected=%08x got=%08x prev_height=%d prev_time=%u header_time=%u retained_floor=%d synthetic_window=[%lld,%lld]\n",
            m_id,
            static_cast<long long>(next_height),
            redownload_phase ? "redownload" : "presync",
            expected_nbits,
            header.nBits,
            previous->nHeight,
            previous->GetBlockTime(),
            header.nTime,
            retained_floor.value_or(-1),
            static_cast<long long>(oldest_height),
            static_cast<long long>(newest_height));
        return false;
    }

    if (redownload_phase) {
        AdvanceSyntheticIndexWindow(header, next_height, m_redownload_last_index, m_redownload_index_window);
    } else {
        AdvanceSyntheticIndexWindow(header, next_height, m_presync_last_index, m_presync_index_window);
    }
    return true;
}

bool HeadersSyncState::ValidateAndProcessSingleHeader(const CBlockHeader& current)
{
    Assume(m_download_state == State::PRESYNC);
    if (m_download_state != State::PRESYNC) return false;

    if (m_current_height == std::numeric_limits<int64_t>::max()) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: height overflow (presync phase)\n", m_id);
        return false;
    }
    const int64_t next_height = m_current_height + 1;
    if (!IsRepresentableBlockIndexHeight(next_height)) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: block index height range exceeded at height=%lld (presync phase)\n", m_id, static_cast<long long>(next_height));
        return false;
    }

    if (m_consensus_params.fMatMulPOW) {
        if (!ValidateAndAdvanceMatMulDifficulty(current, next_height, /*redownload_phase=*/false)) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid MatMul schedule nBits at height=%i (presync phase)\n", m_id, next_height);
            return false;
        }
    } else {
        // Verify that the difficulty isn't growing too fast; an adversary with
        // limited hashing capability has a greater chance of producing a high
        // work chain if they compress the work into as few blocks as possible,
        // so don't let anyone give a chain that would violate the difficulty
        // adjustment maximum.
        if (!PermittedDifficultyTransition(m_consensus_params, next_height,
                    m_last_header_received.nBits, current.nBits)) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (presync phase)\n", m_id, next_height);
            return false;
        }
    }

    if (next_height % HEADER_COMMITMENT_PERIOD == m_commit_offset) {
        // Add a commitment.
        m_header_commitments.push_back(m_hasher(current.GetHash()) & 1);
        if (m_header_commitments.size() > m_max_commitments) {
            // The peer's chain is too long; give up.
            // It's possible the chain grew since we started the sync; so
            // potentially we could succeed in syncing the peer's chain if we
            // try again later.
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: exceeded max commitments at height=%i (presync phase)\n", m_id, next_height);
            return false;
        }
    }

    m_current_chain_work += GetBlockProof(CBlockIndex(current));
    m_last_header_received = current;
    m_current_height = next_height;

    return true;
}

bool HeadersSyncState::ValidateAndStoreRedownloadedHeader(const CBlockHeader& header)
{
    Assume(m_download_state == State::REDOWNLOAD);
    if (m_download_state != State::REDOWNLOAD) return false;

    if (m_redownload_buffer_last_height == std::numeric_limits<int64_t>::max()) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: height overflow (redownload phase)\n", m_id);
        return false;
    }
    const int64_t next_height = m_redownload_buffer_last_height + 1;
    if (!IsRepresentableBlockIndexHeight(next_height)) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: block index height range exceeded at height=%lld (redownload phase)\n", m_id, static_cast<long long>(next_height));
        return false;
    }

    // Ensure that we're working on a header that connects to the chain we're
    // downloading.
    if (header.hashPrevBlock != m_redownload_buffer_last_hash) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: non-continuous headers at height=%i (redownload phase)\n", m_id, next_height);
        return false;
    }

    if (m_consensus_params.fMatMulPOW) {
        if (!ValidateAndAdvanceMatMulDifficulty(header, next_height, /*redownload_phase=*/true)) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid MatMul schedule nBits at height=%i (redownload phase)\n", m_id, next_height);
            return false;
        }
    } else {
        // Check that the difficulty adjustments are within our tolerance:
        uint32_t previous_nBits{0};
        if (!m_redownloaded_headers.empty()) {
            previous_nBits = m_redownloaded_headers.back().nBits;
        } else {
            previous_nBits = m_chain_start->nBits;
        }

        if (!PermittedDifficultyTransition(m_consensus_params, next_height,
                    previous_nBits, header.nBits)) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (redownload phase)\n", m_id, next_height);
            return false;
        }
    }

    // Track work on the redownloaded chain
    m_redownload_chain_work += GetBlockProof(CBlockIndex(header));

    if (m_redownload_chain_work >= m_minimum_required_work) {
        m_process_all_remaining_headers = true;
    }

    // If we're at a header for which we previously stored a commitment, verify
    // it is correct. Failure will result in aborting download.
    // Also, don't check commitments once we've gotten to our target blockhash;
    // it's possible our peer has extended its chain between our first sync and
    // our second, and we don't want to return failure after we've seen our
    // target blockhash just because we ran out of commitments.
    if (!m_process_all_remaining_headers && next_height % HEADER_COMMITMENT_PERIOD == m_commit_offset) {
        if (m_header_commitments.size() == 0) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: commitment overrun at height=%i (redownload phase)\n", m_id, next_height);
            // Somehow our peer managed to feed us a different chain and
            // we've run out of commitments.
            return false;
        }
        bool commitment = m_hasher(header.GetHash()) & 1;
        bool expected_commitment = m_header_commitments.front();
        m_header_commitments.pop_front();
        if (commitment != expected_commitment) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: commitment mismatch at height=%i (redownload phase)\n", m_id, next_height);
            return false;
        }
    }

    // Store this header for later processing.
    m_redownloaded_headers.emplace_back(header);
    m_redownload_buffer_last_height = next_height;
    m_redownload_buffer_last_hash = header.GetHash();

    return true;
}

std::vector<CBlockHeader> HeadersSyncState::PopHeadersReadyForAcceptance()
{
    std::vector<CBlockHeader> ret;

    Assume(m_download_state == State::REDOWNLOAD);
    if (m_download_state != State::REDOWNLOAD) return ret;

    while (m_redownloaded_headers.size() > REDOWNLOAD_BUFFER_SIZE ||
            (m_redownloaded_headers.size() > 0 && m_process_all_remaining_headers)) {
        ret.emplace_back(m_redownloaded_headers.front().GetFullHeader(m_redownload_buffer_first_prev_hash));
        m_redownloaded_headers.pop_front();
        m_redownload_buffer_first_prev_hash = ret.back().GetHash();
    }
    return ret;
}

CBlockLocator HeadersSyncState::NextHeadersRequestLocator() const
{
    Assume(m_download_state != State::FINAL);
    if (m_download_state == State::FINAL) return {};

    auto chain_start_locator = LocatorEntries(m_chain_start);
    std::vector<uint256> locator;

    if (m_download_state == State::PRESYNC) {
        // During pre-synchronization, we continue from the last header received.
        locator.push_back(m_last_header_received.GetHash());
    }

    if (m_download_state == State::REDOWNLOAD) {
        // During redownload, we will download from the last received header that we stored.
        locator.push_back(m_redownload_buffer_last_hash);
    }

    locator.insert(locator.end(), chain_start_locator.begin(), chain_start_locator.end());

    return CBlockLocator{std::move(locator)};
}
