// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC04_PROC04_H
#define BITCOIN_MODELNET_PROC04_PROC04_H

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

/**
 * Proc04. DS-EVAL-001. Compare a fixed three-sentence corpus in this process.
 * The sentences compiled into this class are alpha, beta, and gamma.
 * Compare runs the single-agent length score and the central distinct-character
 * score, stores both, then sets compared(). corpus_count() is 0 before that
 * success and 3 after. A second Compare returns true and does not score again.
 * The fixed corpus has no empty sentence. RefuseEmpty refuses a caller-supplied
 * empty extra sentence with FIELD and leaves the fixed corpus in place. A
 * non-empty extra sentence returns true and also leaves the corpus in place.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND.
 * This class opens no file, socket, process, or wallet.
 */
class Proc04 {
public:
    bool Compare(std::string& err);
    bool RefuseEmpty(const std::string& extra, std::string& err);

    bool compared() const { return m_compared; }
    int single_agent_score() const { return m_single; }
    int central_score() const { return m_central; }
    int corpus_count() const { return m_count; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_compared{false};
    int m_single{0};
    int m_central{0};
    int m_count{0};
};

} // namespace modelnet

#endif
