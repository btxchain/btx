// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_CURSOR_H
#define BTX_MODELNET_SWARM_FAULTSEQ_CURSOR_H

namespace modelnet {

/**
 * Fault index for one armed sequence. Take yields 1, then 2, through 20.
 * After 20, past_end is true and Take yields 0 so Apply is not called again.
 */
class SwarmFaultSeqCursor {
public:
    void Reset();
    bool past_end() const;
    bool took_last() const;
    int next() const;
    int last() const;
    int Take();

private:
    int m_next{1};
    int m_last{0};
    bool m_took_last{false};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_CURSOR_H
