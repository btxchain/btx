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
};
} // namespace kernel
#endif // BITCOIN_KERNEL_WARNING_H
