// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ERASURE_MANIFEST_H
#define BITCOIN_MODELNET_ERASURE_MANIFEST_H

#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Auxiliary preservation index. Not a new canonical model identity. */
inline constexpr const char* ERASURE_PROFILE_CAUCHY_16_20_V1 = "BTX-EC-Cauchy-16-20-v1";
inline constexpr int ERASURE_K_16_20 = 16;
inline constexpr int ERASURE_N_16_20 = 20;
inline constexpr uint32_t ERASURE_SHARD_BYTES_16_20 = 4194304;
/** The only GF(256) field the codec implements. GfMul hardcodes it. */
inline constexpr const char* ERASURE_FIELD_POLYNOMIAL = "0x11d";
/** Must-understand extension names. An unrecognised entry is a hard parse failure. */
inline constexpr const char* ERASURE_EXT_FAILURE_DOMAIN_V1 = "failure_domain_v1";
/** Domain-separated prefix for the shard inventory commitment. */
inline constexpr const char* ERASURE_SHARD_INDEX_TAG = "BTX-EC-SHARD-INDEX-v1";
inline constexpr size_t ERASURE_MAX_DOMAIN_LEN = 64;
inline constexpr size_t ERASURE_MAX_REQUIRED_EXTENSIONS = 8;

struct ErasureStripe {
    uint32_t stripe_index{0};
    /** Stored coded positions for this stripe only. Duplicates do not count. */
    std::vector<int> positions;
    /** Optional SHA-384 hex per listed position; not a secret. */
    std::vector<std::string> shard_hash_hex;
    /**
     * Failure domain id per stored position: host, peer, rack or region.
     * Parallel to positions when present. Empty means the placement is
     * undeclared, and undeclared placement is never read as independent.
     */
    std::vector<std::string> failure_domains;
};

struct ErasureManifest {
    int version{1};
    std::string profile{ERASURE_PROFILE_CAUCHY_16_20_V1};
    std::string canonical_artifact_id;
    std::string canonical_manifest_id;
    int file_index{0};
    uint64_t file_size_bytes{0};
    int data_shards{ERASURE_K_16_20};
    int total_shards{ERASURE_N_16_20};
    uint32_t shard_bytes{ERASURE_SHARD_BYTES_16_20};
    std::string field_polynomial{ERASURE_FIELD_POLYNOMIAL};
    uint64_t stripe_count{0};
    /**
     * Real data pieces in the tail stripe. A value below data_shards claims
     * dummy-zero padding and is only honoured when file_size_bytes proves it.
     */
    int final_real_piece_count{ERASURE_K_16_20};
    std::string shard_index_root;
    /** Must-understand extension names. An unknown entry fails the parse. */
    std::vector<std::string> required_extensions;
    std::vector<ErasureStripe> stripes;
};

/** SPEC 14 per-stripe preservation record. One stripe, never a global count. */
struct ErasureStripeHealth {
    uint32_t stripe_index{0};
    /** Distinct coded shards this stripe needs to decode: k. */
    int k_required{0};
    /** Distinct stored positions. Never includes dummy-zero padding. */
    int independent_shards{0};
    /** Retained name for independent_shards. Same count, same exclusion. */
    int distinct_stored{0};
    /** Locally supplyable dummy-zero data slots credited to this stripe. */
    int padding_credit{0};
    /** independent_shards + padding_credit. Only the first term is durable. */
    int distinct_effective{0};
    /** Distinct declared failure domains over the distinct stored positions. */
    int distinct_failure_domains{0};
    /** n - k + 1: losing the whole margin must not take the stripe out. */
    int required_failure_domains{0};
    /** False when the stripe declares no domains, so 0 is never read as tolerant. */
    bool failure_domains_declared{false};
    int deficit{0};
    /** Arithmetic sufficiency for this stripe alone. */
    bool reconstructable{false};
    /** reconstructable AND the declared domains meet required_failure_domains. */
    bool preservation_reconstructable{false};
    /** Addressable repair handle. Empty when the stripe has no deficit. */
    std::string repair_target;
    /** Positions a healer may fetch to close the deficit. */
    std::vector<int> repair_fetch_positions;
};

struct ErasureHealth {
    bool reconstructable{false};
    /** Every stripe reconstructable, geometry proven, and domain tolerance met. */
    bool preservation_reconstructable{false};
    /** stripe_count, file_size_bytes, shard_bytes, k and the tail all agree. */
    bool geometry_consistent{false};
    uint64_t stripe_count{0};
    uint64_t reconstructable_stripes{0};
    uint64_t deficit_stripes{0};
    uint64_t preservation_stripes{0};
    /** Informational only. Must never be treated as reconstructability. */
    uint64_t global_position_count{0};
    int k{0};
    int n{0};
    int required_failure_domains{0};
    /** stripe_index credited with dummy-zero padding, or -1 when none is. */
    int64_t padding_credited_stripe{-1};
    std::vector<ErasureStripeHealth> stripes;
};

bool ParseErasureManifest(const UniValue& json, ErasureManifest& out, std::string& err);
UniValue ErasureManifestJson(const ErasureManifest& manifest);
UniValue ErasureHealthJson(const ErasureHealth& health);

/** Stored position sets in stripe order. Does not invent coverage from n or global counts. */
std::vector<std::vector<int>> ErasureStoredPositionSets(const ErasureManifest& manifest);
/**
 * Stored positions plus dummy-zero data slots (final_real_piece_count..k-1),
 * credited only to the stripe whose stripe_index is stripe_count-1, and only
 * when ErasureGeometryConsistent proves the tail is short. Dummy zeros are
 * locally supplyable padding, never independent stored replicas.
 */
std::vector<std::vector<int>> ErasureEffectivePositionSets(const ErasureManifest& manifest);

/**
 * Dummy-zero data slots the tail stripe may claim, or empty when the claim is
 * unproven. A declared final_real_piece_count is never sufficient on its own.
 */
std::vector<int> ErasureTailPaddingSlots(const ErasureManifest& manifest);
/** True iff stripe_count, file_size_bytes, shard_bytes, k and the tail agree. */
bool ErasureGeometryConsistent(const ErasureManifest& manifest);
/** True iff the stripe_index set is exactly {0..stripe_count-1}. */
bool ErasureStripeIndexSetOk(const ErasureManifest& manifest);

/** Stored positions of one named stripe. Array order is not stripe order. */
bool ErasureStripeStoredPositions(const ErasureManifest& manifest, uint64_t stripe_index,
                                  std::vector<int>& out);
/** Sufficiency for one named stripe. Other stripes' surplus is not borrowable. */
bool ErasureStripeIndexReconstructable(const ErasureManifest& manifest, uint64_t stripe_index);
/**
 * Gate for a per-stripe repair: k distinct positions, every one of them stored
 * by THAT stripe, and that stripe reconstructable on its own.
 */
bool ErasureStripeAcceptsPositions(const ErasureManifest& manifest, uint64_t stripe_index,
                                   const std::vector<int>& positions, std::string& err);
/** Canonical commitment over the declared (stripe, position, shard hash) triples. */
bool ErasureShardIndexRootHex(const ErasureManifest& manifest, std::string& out, std::string& err);

/** True iff every stripe has a position set and StripeReconstructable(effective, k). */
bool ErasureManifestReconstructable(const ErasureManifest& manifest);
/** Strictly stronger: reconstructable, geometry proven, domain tolerance met. */
bool ErasureManifestPreservationReconstructable(const ErasureManifest& manifest);
ErasureHealth EvaluateErasureHealth(const ErasureManifest& manifest);

} // namespace modelnet

#endif // BITCOIN_MODELNET_ERASURE_MANIFEST_H
