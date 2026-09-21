// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_PJSON_H
#define BITCOIN_MODELNET_PACKAGE_PJSON_H

#include <span.h>
#include <univalue.h>

#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/** Spec §4.2 BTX-PJSON1. Distinct from bounty CanonicalEncode (tagged tree). */
inline constexpr size_t PJSON_MAX_DEPTH = 32;
inline constexpr size_t PJSON_MAX_NODES = 65536;
inline constexpr uint64_t PJSON_MAX_SAFE_INT = 9007199254740991ULL; // 2^53-1

bool EncodePjson1(const UniValue& value, std::vector<unsigned char>& out, std::string& err);
/** Reject non-canonical bytes, duplicates, floats, -0, invalid UTF-8. */
bool DecodePjson1(Span<const unsigned char> raw, UniValue& out, std::string& err);
bool Pjson1Equals(Span<const unsigned char> a, Span<const unsigned char> b);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_PJSON_H
