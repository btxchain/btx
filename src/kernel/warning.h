// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_WARNING_H
#define BITCOIN_KERNEL_WARNING_H

namespace kernel {
enum class Warning {
    UNKNOWN_NEW_RULES_ACTIVATED,
    LARGE_WORK_INVALID_CHAIN,
    UNKNOWN_NEW_RULES_SIGNAL_VBITS,
    UNKNOWN_NEW_RULES_SIGNAL_INTVER,
    SOFTWARE_EXPIRY,
    //! A candidate branch would reorg the active chain by more than the
    //! operator's configured deep-reorg warning threshold (-maxreorgdepthwarn).
    //! This is a loud alarm only; it never changes consensus. See the deep-reorg
    //! handling in Chainstate::ActivateBestChainStep.
    DEEP_REORG_DETECTED,
    //! Strict-device consensus validation has no qualified runtime provider.
    //! Unlike a transient log line, this remains visible through the standard
    //! RPC warnings array, the GUI status, and -alertnotify until the process
    //! is restarted with a fully qualified provider.
    MATMUL_RC_NEXT_BLOCK_UNVERIFIABLE,
    //! Configured node is several blocks behind the highest height it has a
    //! current-key quorum for (including hashes not on the active chain).
    //! Distinguishes a stranded fork from a paused signer: getmatmulattestedtip
    //! hash/on_active_chain only see HAVE_DATA on this node's own chain.
    MATMUL_BEHIND_SIGNED_FRONTIER,
};
} // namespace kernel
#endif // BITCOIN_KERNEL_WARNING_H
