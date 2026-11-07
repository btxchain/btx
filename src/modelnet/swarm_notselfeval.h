// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSELFEVAL_H
#define BTX_MODELNET_SWARM_NOTSELFEVAL_H

#include <string>

namespace modelnet {

/**
 * A local note that an author is not their own evaluator.
 * want_accept asks this note to accept the evaluation and sign a report.
 *
 * An author cannot evaluate self or sign their own report.
 * accepted and signed_report stay false on every path.
 */
struct SwarmNotSelfEval {
    std::string author_id;
    std::string evaluator_id;
    bool want_accept{false};
};

/**
 * Outcome of noting a self-evaluation refusal. accepted and signed_report
 * stay false on every path.
 */
struct SwarmNotSelfEvalResult {
    std::string code;
    bool accepted{false};
    bool signed_report{false};
};

/**
 * Note that an author cannot evaluate self or sign their own report.
 * Order, first match wins: an empty author_id or an empty evaluator_id is
 * AUTHOR. author_id equal to evaluator_id is SAME_EVALUATOR, even when
 * want_accept is false. want_accept is NOT_ACCEPTED. Otherwise the note is
 * NOTED and err is clear. accepted and signed_report stay false on every
 * path.
 */
SwarmNotSelfEvalResult SwarmNoteNotSelfEval(const SwarmNotSelfEval& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSELFEVAL_H
