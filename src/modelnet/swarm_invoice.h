// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INVOICE_H
#define BTX_MODELNET_SWARM_INVOICE_H

#include <uint256.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Direct invoice accounting. Create stores a hashlock and does not spend.
 * Reserve records a liquidity id once. Reveal settles one matching preimage.
 * A hashlock is not a qualified multi-hop network. This book has no broadcast
 * flag and no automatic spend.
 */
class SwarmInvoiceBook {
public:
    /** A second Open is REOPEN. */
    bool Open(std::string& err);

    /**
     * Empty id, beneficiary, or objective, or atoms <= 0, is INVOICE.
     * A duplicate invoice id is REPLAY. The hashlock is stored. This does
     * not spend.
     */
    bool Create(const std::string& invoice_id, const std::string& beneficiary, const std::string& objective, int64_t atoms, const uint256& hashlock, std::string& err);

    /**
     * An unknown invoice is INVOICE. An empty liquidity id is LIQUIDITY.
     * A liquidity id already reserved by any invoice is DOUBLE_RESERVE.
     * The same invoice reserved again with the same liquidity id succeeds
     * and does not double-count.
     */
    bool Reserve(const std::string& invoice_id, const std::string& liquidity_id, std::string& err);

    /**
     * A preimage whose size is not 32 is PREIMAGE. A SHA256 mismatch is
     * HASHLOCK. A matching reveal sets settled. A second matching reveal
     * is REPLAY and does not settle twice.
     */
    bool Reveal(const std::string& invoice_id, const std::vector<unsigned char>& preimage, std::string& err);

    /**
     * Always false. Asking nothing is false. There is no method that sets
     * this true. A hashlock is not a qualified multi-hop network.
     */
    bool MultiHopQualified() const;

private:
    struct Row {
        std::string beneficiary;
        std::string objective;
        int64_t atoms{0};
        uint256 hashlock;
        std::set<std::string> liquidity_ids;
        bool settled{false};
    };

    bool m_open{false};
    std::map<std::string, Row> m_rows;
    std::map<std::string, std::string> m_liquidity_owner;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INVOICE_H
