// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_CHANNEL_H
#define BITCOIN_MODELNET_PACKAGE_CHANNEL_H

#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** ChannelStatement is coordination, not package-core trust. */
bool ParseChannelStatement(const UniValue& json, UniValue& out, std::string& err_code, std::string& err);
bool ChannelRollback(const std::string& previous_seq, const std::string& next_seq);
bool ChannelEquivocation(const UniValue& a, const UniValue& b);
bool ChannelEconomicsStale(const UniValue& observation, int64_t now_ms, std::string& err_code, std::string& err);
bool PackageTelemetryForbidden(const UniValue& core, std::string& err);
/** A CDN/hostname is never publisher_id trust. */
bool ChannelHostnameIsPublisherTrust(const std::string& hostname);
/** Pin the bytes of a .btx (model_latest analog): identity is package_core_id. */
bool PinChannelPackageBytes(Span<const unsigned char> bytes, Digest48& pinned_core_id, std::string& err);
bool SaveChannelWatch(const std::string& path, const UniValue& statement, std::string& err_code, std::string& err);
bool LoadChannelWatch(const std::string& path, UniValue& out, std::string& err_code, std::string& err);
/** FOLLOW is off unless user_policy.follow_channel is explicitly true. */
bool ChannelFollowIsExplicit(const UniValue& user_policy);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_CHANNEL_H
