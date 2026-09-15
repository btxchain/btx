// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CORES_H
#define BITCOIN_MODELNET_CORES_H

#include <modelnet/types.h>

#include <array>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct CoreFile {
    std::string path;
    FileRole role{FileRole::WEIGHTS};
    uint64_t size{0};
    Digest48 sha384;
    Digest48 pieces_root;
};

struct ModelCore {
    uint16_t version{2};
    uint16_t format_profile{1};   // 1 SafeTensors, 2 GGUF
    uint16_t execution_profile{0}; // 0 unqualified
    Digest48 config_sha384;
    Digest48 tokenizer_sha384;
    std::vector<Digest48> base_models;
    std::vector<CoreFile> files;
};

struct ArtifactCore {
    uint16_t version{2};
    uint8_t codec{1}; // 1 plaintext
    Digest48 model_id;
    std::array<unsigned char, 16> encryption_context{};
    std::vector<CoreFile> files;
};

bool EncodeModelCore(const ModelCore& core, std::vector<unsigned char>& out, std::string& err);
bool EncodeArtifactCore(const ArtifactCore& core, std::vector<unsigned char>& out, std::string& err);
Digest48 ModelCoreId(const std::vector<unsigned char>& canonical);
Digest48 ArtifactCoreId(const std::vector<unsigned char>& canonical);

bool EncodeCompactSizeModel(uint64_t n, std::vector<unsigned char>& out, std::string& err);

constexpr size_t MAX_COLLECTION_ENTRIES = 512;

struct CollectionEntry {
    Digest48 model_id;
    uint8_t priority{1};
    uint16_t retention_days{0};
};

bool ValidateCollectionEntries(const std::vector<CollectionEntry>& entries, std::string& err);
bool CanonicalizeCollectionEntries(std::vector<CollectionEntry>& entries, std::string& err);
bool CollectionGrantsQualification(const std::vector<CollectionEntry>& entries, const std::string& filename);
bool CollectionLoadsCode();
/** Follow/subscribe never raises PreservationPolicy::storage_quota_bytes. */
bool CollectionFollowRaisesQuota();
/** Circles are local policy. They never create on-chain membership. */
bool CircleHasOnChainMembership();

Digest48 AliasKey(const Digest48& signer_id, const std::string& slug, std::string& err);

enum class AliasApply : uint8_t {
    ACCEPTED = 0,
    FROZEN_EQUIVOCATION = 1,
    REJECTED_CHAIN = 2,
    REJECTED = 3,
};

class AliasIndex {
    struct Mapping {
        uint64_t sequence{0};
        Digest48 record_id{};
        ResourceKind target_kind{ResourceKind::MODEL};
        Digest48 target_id{};
        bool frozen{false};
    };
    std::map<Digest48, Mapping> m_by_key;

public:
    AliasApply Apply(const Digest48& alias_key,
                     uint64_t sequence,
                     const Digest48& record_id,
                     ResourceKind target_kind,
                     const Digest48& target_id,
                     std::string& err);
    bool Frozen(const Digest48& alias_key) const;
    bool HoldsPrior(const Digest48& alias_key, const Digest48& target_id) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_CORES_H
