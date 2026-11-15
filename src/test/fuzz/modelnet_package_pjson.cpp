// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_pjson.h>
#include <span.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>
#include <util/check.h>

#include <string>
#include <vector>

// BTX-PJSON1 (package payloads, HCP request bodies): bytes the decoder accepts
// are canonical, so encoding the result gives the same bytes back.
FUZZ_TARGET(modelnet_package_pjson_decode)
{
    UniValue decoded;
    std::string err;
    if (!modelnet::DecodePjson1(buffer, decoded, err)) {
        Assert(!err.empty());
        return;
    }
    std::vector<unsigned char> encoded;
    Assert(modelnet::EncodePjson1(decoded, encoded, err));
    Assert(modelnet::Pjson1Equals(encoded, buffer));
}

// Encoder and decoder agree: whatever value the encoder writes, the decoder
// reads back to a value that encodes to the same bytes.
FUZZ_TARGET(modelnet_package_pjson_encode)
{
    UniValue value;
    if (!value.read(std::string{buffer.begin(), buffer.end()})) return;
    std::vector<unsigned char> encoded;
    std::string err;
    if (!modelnet::EncodePjson1(value, encoded, err)) {
        Assert(!err.empty());
        return;
    }
    UniValue back;
    Assert(modelnet::DecodePjson1(encoded, back, err));
    std::vector<unsigned char> again;
    Assert(modelnet::EncodePjson1(back, again, err));
    Assert(again == encoded);
}
