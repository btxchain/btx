// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/v2_bundle.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <ios>
#include <string>

namespace {

using namespace shielded::v2;

template <typename T>
bool RoundTripCheck(const T& obj)
{
    DataStream ds{};
    try {
        ds << obj;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    // Reading drains ds, so keep the first serialization to compare with.
    const std::string serialized{ds.str()};
    T decoded;
    try {
        ds >> decoded;
    } catch (const std::ios_base::failure&) {
        return false;
    }
    assert(ds.empty());

    DataStream ds2{};
    try {
        ds2 << decoded;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    assert(serialized == ds2.str());
    return true;
}

} // namespace

FUZZ_TARGET(shielded_v2_transaction_bundle_deserialize)
{
    DataStream ds{buffer};
    TransactionBundle bundle;
    try {
        ds >> bundle;
    } catch (const std::ios_base::failure&) {
        return;
    }

    (void)bundle.IsValid();
    if (bundle.IsValid()) {
        (void)ComputePayloadDigest(bundle.payload);
        (void)ComputeTransactionBundleId(bundle);
    }
    RoundTripCheck(bundle);
}
