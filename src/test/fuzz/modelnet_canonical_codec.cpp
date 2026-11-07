// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/canonical_codec.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>
#include <util/check.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

/** Every signed-record helper that takes a parsed body. None may throw. */
void ExerciseEnvelopeHelpers(const UniValue& value)
{
    std::string err;
    std::vector<unsigned char> preimage;
    modelnet::Digest48 id;
    modelnet::NetworkId nid;
    (void)modelnet::EnvelopePreimage(value, preimage, err);
    (void)modelnet::EnvelopeDigest(value, id, err);
    (void)modelnet::EnvelopeNetworkId(value, nid, err);
    (void)modelnet::RecordPreimageV11(value, preimage, err);
    (void)modelnet::RecordIdV11(value, id, err);
    (void)modelnet::VerifySignedEnvelopeV11(value, err);
    if (value.isObject() && value.exists("body")) {
        (void)modelnet::RecordIdV11(value["body"], id, err);
        (void)modelnet::EnvelopePreimage(value["body"], preimage, err);
    }
    if (value.isObject() && value.exists("record_type") && value["record_type"].isStr()) {
        std::vector<unsigned char> domain;
        (void)modelnet::KnownRecordType(value["record_type"].get_str());
        (void)modelnet::EnvelopeDomain(value["record_type"].get_str(), domain, err);
    }
}

} // namespace

// Binary canonical tree codec (contrib/modelnet/bounty/reference/CODEC.md).
FUZZ_TARGET(modelnet_canonical_decode)
{
    UniValue decoded;
    std::string err;
    if (!modelnet::CanonicalDecode(buffer, decoded, err)) {
        Assert(!err.empty());
        return;
    }
    // Anything the decoder accepts is inside the encoder's bounds.
    std::vector<unsigned char> encoded;
    Assert(modelnet::CanonicalEncode(decoded, encoded, err));
    Assert(encoded.size() == buffer.size());

    UniValue again;
    Assert(modelnet::CanonicalDecode(encoded, again, err));
    std::vector<unsigned char> reencoded;
    Assert(modelnet::CanonicalEncode(again, reencoded, err));
    Assert(reencoded == encoded);

    // The JSON text path must reach the same canonical bytes.
    UniValue from_text;
    Assert(modelnet::StrictParseJson(decoded.write(), from_text, err));
    std::vector<unsigned char> from_text_encoded;
    Assert(modelnet::CanonicalEncode(from_text, from_text_encoded, err));
    Assert(from_text_encoded == encoded);

    ExerciseEnvelopeHelpers(decoded);
}

// Strict JSON reader and the envelope helpers, on the strict parse and on an
// ordinary UniValue parse of the same text.
FUZZ_TARGET(modelnet_strict_json_envelope)
{
    const std::string_view text{reinterpret_cast<const char*>(buffer.data()), buffer.size()};
    std::string err;
    UniValue strict;
    if (modelnet::StrictParseJson(text, strict, err)) {
        std::vector<unsigned char> encoded;
        Assert(modelnet::CanonicalEncode(strict, encoded, err));
        UniValue decoded;
        Assert(modelnet::CanonicalDecode(encoded, decoded, err));
        std::vector<unsigned char> reencoded;
        Assert(modelnet::CanonicalEncode(decoded, reencoded, err));
        Assert(reencoded == encoded);
        ExerciseEnvelopeHelpers(strict);
    } else {
        Assert(!err.empty());
    }

    UniValue loose;
    if (loose.read(text)) {
        std::vector<unsigned char> encoded;
        (void)modelnet::CanonicalEncode(loose, encoded, err);
        ExerciseEnvelopeHelpers(loose);
    }
}
