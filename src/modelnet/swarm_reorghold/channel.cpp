// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/channel.h>

namespace modelnet {

ReorgHoldChannel ReorgHoldMakeChannel(const std::string& id, int64_t earned)
{
    ReorgHoldChannel channel;
    channel.id = id;
    channel.earned = earned;
    channel.frozen = false;
    return channel;
}

void ReorgHoldFreezeChannel(ReorgHoldChannel& channel)
{
    channel.frozen = true;
}

bool ReorgHoldChannelPaid(const ReorgHoldChannel& /*channel*/)
{
    return false;
}

bool ReorgHoldChannelExited(const ReorgHoldChannel& /*channel*/)
{
    return false;
}

} // namespace modelnet
