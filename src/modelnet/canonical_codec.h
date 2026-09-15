// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CANONICAL_CODEC_H
#define BITCOIN_MODELNET_CANONICAL_CODEC_H

#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

constexpr size_t CANONICAL_MAX_DEPTH = 16;
constexpr size_t CANONICAL_MAX_FIELDS = 128;
constexpr size_t CANONICAL_MAX_ARRAY = 1024;
constexpr size_t CANONICAL_MAX_STRING = 8192;
constexpr size_t CANONICAL_MAX_ENVELOPE = 262144;

/** Tagged bounded tree encoding matching contrib/modelnet/bounty/reference/CODEC.md. */
bool CanonicalEncode(const UniValue& value, std::vector<unsigned char>& out, std::string& err, int depth = 0);
bool CanonicalDecode(Span<const unsigned char> in, UniValue& out, std::string& err);

/** Reject duplicate keys, floats, leading-zero integers, and unpaired surrogates. */
bool StrictParseJson(std::string_view raw, UniValue& out, std::string& err);

bool EnvelopeDomain(const std::string& record_type, std::vector<unsigned char>& domain, std::string& err);
bool EnvelopePreimage(const UniValue& body, std::vector<unsigned char>& preimage, std::string& err);
bool EnvelopeDigest(const UniValue& body, Digest48& id, std::string& err);
bool EnvelopeNetworkId(const UniValue& body, NetworkId& nid, std::string& err);

bool ValidCanonicalKey(std::string_view key);
bool CanonicalAtoms(const std::string& s, int64_t& n, std::string& err);

const char* KnownRecordType(std::string_view type);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CANONICAL_CODEC_H
