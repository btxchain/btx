// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/fund.h>

#include <modelnet/swarm_channelset/error.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

bool ChannelSetFund(ChannelSetRecord& record, std::string& err)
{
    if (!record.opened) {
        err = kChannelSetChannel;
        return false;
    }
    if (record.tx.funded) {
        err = kChannelSetReplay;
        return false;
    }
    return SwarmNoteChannelFunding(record.tx, err);
}

} // namespace modelnet
