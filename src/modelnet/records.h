// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RECORDS_H
#define BITCOIN_MODELNET_RECORDS_H

#include <modelnet/types.h>

#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

constexpr uint8_t RECORD_IDENTITY_CARD = 16;
constexpr uint8_t RECORD_SERVICE_DELEGATION = 17;
constexpr uint8_t RECORD_REVOCATION = 18;
constexpr uint8_t RECORD_COLLECTION = 19;
constexpr uint8_t RECORD_ALIAS = 20;
constexpr uint8_t RECORD_POLICY_BUNDLE = 21;
constexpr uint8_t RECORD_PRESERVATION_CIRCLE = 22;
constexpr uint8_t RECORD_FREE_GRANT = 23;
constexpr uint8_t RECORD_SERVICE_RECEIPT = 24;

const char* RecordKindName(uint8_t kind);

bool EncodeRecord(uint8_t kind, const UniValue& body, std::vector<unsigned char>& out, std::string& err);
bool DecodeRecord(uint8_t kind, Span<const unsigned char> bytes, UniValue& body, std::string& err);
bool RecordId(uint8_t kind, const UniValue& body, Digest48& id, std::string& err);
bool SigningMessage(uint8_t kind, const UniValue& body, Digest48& msg, std::string& err);

/** Common v1.1 fields. `ttl_s==0` leaves expires_at=0 (allowed for Collection/Circle). */
void FillRecordCommon(UniValue& body, uint8_t signer_role, const Digest48& signer_id, int64_t now, int64_t ttl_s);

bool SignTypedRecord(uint8_t kind, const UniValue& body,
                     Span<const unsigned char> sk,
                     std::vector<unsigned char>& payload,
                     std::vector<unsigned char>& sig,
                     Digest48& record_id,
                     std::string& err);

bool VerifyTypedRecord(uint8_t kind,
                        Span<const unsigned char> payload,
                        Span<const unsigned char> sig,
                        Span<const unsigned char> pk,
                        int64_t now,
                        UniValue& body,
                        Digest48& record_id,
                        std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_RECORDS_H
