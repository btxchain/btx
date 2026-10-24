// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEVAL_H
#define BTX_MODELNET_SWARM_NOTNOEVAL_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not evaluate their own report.
 * want_accept asks this note to accept the report.
 *
 * An author does not evaluate their own report. This note accepts
 * nothing and signs nothing. accepted and signed_report stay false
 * on every path.
 */
struct SwarmNotNoEval {
    std::string author_id;
    std::string evaluator_id;
    bool want_accept{false};
};

/**
 * Outcome of noting a self-evaluation claim. accepted and signed_report
 * stay false on every path. An author does not evaluate their own report.
 */
struct SwarmNotNoEvalResult {
    std::string code;
    bool accepted{false};
    bool signed_report{false};
};

/**
 * Note a self-evaluation claim without accepting or signing a report.
 * Order, first match wins:
 * 1. An empty author_id or an empty evaluator_id is AUTHOR. accepted
 *    stays false, signed_report stays false, and err is AUTHOR.
 * 2. If author_id equals evaluator_id, the note is SAME_EVALUATOR even
 *    when want_accept is false. accepted stays false, signed_report
 *    stays false, and err is SAME_EVALUATOR.
 * 3. want_accept is NOT_ACCEPTED. accepted stays false, signed_report
 *    stays false, and err is NOT_ACCEPTED.
 * 4. Otherwise the note is NOTED and err is cleared. accepted stays
 *    false and signed_report stays false.
 * accepted and signed_report stay false on every path. An author does
 * not evaluate their own report.
 */
SwarmNotNoEvalResult SwarmNoteNotNoEval(const SwarmNotNoEval& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEVAL_H
