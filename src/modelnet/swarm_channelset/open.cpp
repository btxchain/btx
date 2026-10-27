// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/open.h>

#include <modelnet/swarm_channelset/error.h>
#include <modelnet/swarm_channelset/keys.h>
#include <modelnet/swarm_channelset/limits.h>

namespace modelnet {

bool ChannelSetOpen(ChannelSetRecord& record, const std::string& name, int64_t capacity,
                    const std::vector<unsigned char>& sponsor_pubkey,
                    const std::vector<unsigned char>& worker_pubkey, std::string& err)
{
    if (name.empty()) {
        err = kChannelSetChannel;
        return false;
    }
    if (capacity < 1) {
        err = kChannelSetCapacity;
        return false;
    }
    if (!ChannelSetPubkey(sponsor_pubkey) || !ChannelSetPubkey(worker_pubkey)) {
        err = kChannelSetKey;
        return false;
    }
    if (record.opened) {
        err = kChannelSetNotOpened;
        return false;
    }

    SwarmChannelTx fresh;
    record.tx = fresh;
    record.tx.capacity = capacity;
    record.tx.fee_reserve = kChannelSetFeeReserve;
    record.tx.sponsor_pubkey = sponsor_pubkey;
    record.tx.worker_pubkey = worker_pubkey;
    record.name = name;
    record.opened = true;
    record.refund_built = false;
    record.payouts = 0;
    err.clear();
    return true;
}

} // namespace modelnet
