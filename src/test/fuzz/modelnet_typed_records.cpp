// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/identity.h>
#include <modelnet/records.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>
#include <util/check.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> g_pk;
std::vector<unsigned char> g_sk;

void initialize_modelnet_typed_record_verify()
{
    std::string err;
    Assert(modelnet::GenerateMlDsa44(g_pk, g_sk, err));
}

/** Kinds 16..25 are the typed v1.1 records; other values must fail cleanly. */
uint8_t ConsumeKind(FuzzedDataProvider& fdp)
{
    return fdp.ConsumeBool() ? fdp.ConsumeIntegralInRange<uint8_t>(modelnet::RECORD_IDENTITY_CARD, modelnet::RECORD_SAFETY_ADVISORY)
                             : fdp.ConsumeIntegral<uint8_t>();
}

} // namespace

// Typed record payload codec (announce / import / receipt paths).
FUZZ_TARGET(modelnet_typed_record_decode)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const uint8_t kind = ConsumeKind(fdp);
    const std::vector<unsigned char> payload = fdp.ConsumeRemainingBytes<unsigned char>();

    UniValue body;
    std::string err;
    if (!modelnet::DecodeRecord(kind, payload, body, err)) return;

    // The layout is fixed-width or minimally length-prefixed, so a decoded
    // record re-encodes to the exact input bytes.
    std::vector<unsigned char> encoded;
    Assert(modelnet::EncodeRecord(kind, body, encoded, err));
    Assert(encoded == payload);
    modelnet::Digest48 id;
    Assert(modelnet::RecordId(kind, body, id, err));
    Assert(modelnet::SigningMessage(kind, body, id, err));
    (void)modelnet::RecordKindName(kind);

    // An accepted record is stored and served as JSON; it must read back as the same record.
    UniValue reread;
    Assert(reread.read(body.write()));
    std::vector<unsigned char> reencoded;
    Assert(modelnet::EncodeRecord(kind, reread, reencoded, err));
    Assert(reencoded == payload);
}

// Signed typed records. The fuzzer is the signer here, so every check after
// the signature (identity binding, expiry) is reachable.
FUZZ_TARGET(modelnet_typed_record_verify, .init = initialize_modelnet_typed_record_verify)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const uint8_t kind = ConsumeKind(fdp);
    const int64_t now = fdp.ConsumeIntegral<int64_t>();
    const std::vector<unsigned char> raw = fdp.ConsumeRemainingBytes<unsigned char>();

    UniValue body;
    std::string err;
    if (!modelnet::DecodeRecord(kind, raw, body, err)) return;
    const std::string signer = kind == modelnet::RECORD_SAFETY_ADVISORY ? modelnet::PublisherId(g_pk).Hex()
                                                                        : modelnet::ProviderId(g_pk).Hex();
    body.pushKV("signer_id", signer);
    if (kind == modelnet::RECORD_SERVICE_RECEIPT) {
        body.pushKV("buyer_id", signer);
        body.pushKV("provider_id", signer);
    }

    std::vector<unsigned char> payload;
    std::vector<unsigned char> sig;
    modelnet::Digest48 signed_id;
    if (!modelnet::SignTypedRecord(kind, body, g_sk, payload, sig, signed_id, err)) return;

    UniValue verified;
    modelnet::Digest48 verified_id;
    const bool ok = modelnet::VerifyTypedRecord(kind, payload, sig, g_pk, now, verified, verified_id, err);
    if (ok) {
        Assert(verified_id == signed_id);
    } else {
        Assert(err == "expired record" || err == "expiry out of range");
    }
}
