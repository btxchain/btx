// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/apply.h>

#include <modelnet/swarm_faultseq/limits.h>

namespace modelnet {

SwarmFaultSeqApplyResult SwarmFaultSeqApply(SwarmFaultJournal& journal, int fault)
{
    SwarmFaultSeqApplyResult out;
    out.earned = journal.earned_atoms();
    out.bytes = journal.bytes_moved();
    if (!SwarmFaultSeqInRange(fault)) {
        out.called = false;
        if (fault > kSwarmFaultSeqLast) {
            out.status = SwarmFaultSeqStep::Done;
            out.err = kSwarmFaultSeqDone;
        } else {
            out.status = SwarmFaultSeqStep::Failed;
            out.err = "FAULT";
        }
        return out;
    }

    const int64_t before = journal.earned_atoms();
    std::string err;
    const bool ok = journal.Apply(fault, err);
    out.called = true;
    out.code = journal.code();
    out.earned = journal.earned_atoms();
    out.bytes = journal.bytes_moved();
    out.held = out.earned == before && out.bytes == 0;
    if (!ok) {
        out.status = SwarmFaultSeqStep::Failed;
        out.err = !out.code.empty() ? out.code : err;
        return out;
    }
    out.status = SwarmFaultSeqStep::Applied;
    out.err = out.code;
    return out;
}

} // namespace modelnet
