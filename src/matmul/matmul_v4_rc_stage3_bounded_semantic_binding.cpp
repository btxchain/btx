// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_binding.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

constexpr uint32_t ENVELOPE_MAGIC = 0x31455342U; // "BSE1"
constexpr uint16_t ENVELOPE_VERSION = 1;
constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_BOUNDED_SEMANTIC_BINDING_MANIFEST_V1";
constexpr char RECORD_DOMAIN[] =
    "BTX_RC_STAGE3_BOUNDED_SEMANTIC_BINDING_RECORD_V1";

using Id = RCStage3BoundedSemanticSidecarId;
using Record = RCStage3BoundedSemanticBindingRecord;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:bounded_semantic_binding:" + detail;
    }
    return false;
}

void WriteU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void WriteUint256(
    std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(
        out.end(), value.data(), value.data() + value.size());
}

class Reader
{
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_bytes(bytes)
    {
    }

    bool ReadU16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
              (static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8);
        m_pos += 2;
        return true;
    }

    bool ReadU32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (uint32_t i = 0; i < 4; ++i) {
            out |= static_cast<uint32_t>(m_bytes[m_pos + i])
                   << (8U * i);
        }
        m_pos += 4;
        return true;
    }

    bool ReadUint256(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(
            m_bytes.data() + m_pos, out.size(), out.data());
        m_pos += out.size();
        return true;
    }

    bool ReadBytes(
        size_t count, std::vector<unsigned char>& out)
    {
        if (count > Remaining()) return false;
        out.assign(
            m_bytes.begin() + m_pos,
            m_bytes.begin() + m_pos + count);
        m_pos += count;
        return true;
    }

    size_t Remaining() const { return m_bytes.size() - m_pos; }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

std::array<Id, kRCStage3BoundedSemanticBindingRecordCount>
RequiredIds()
{
    return {
        Id::PublicComposition,
        Id::EpisodeSeedChain,
        Id::EpisodeOperandXof,
        Id::EpisodeBuilderTrace,
        Id::EpisodeGemmExtractManifest,
        Id::EpisodeGemm,
        Id::EpisodeSignedRange,
        Id::EpisodeExtract,
        Id::EpisodeTileStream,
        Id::EpisodeWiring,
        Id::EpisodeDigestRootChain,
        Id::EpisodeRoundRootProducers,
        Id::EpisodeHeaderTarget,
        Id::EpisodePow,
        Id::CoupledBank,
        Id::CoupledBankRoot,
        Id::CoupledInitialState,
        Id::CoupledGemm,
        Id::CoupledSignedRange,
        Id::CoupledExchangePermutation,
        Id::CoupledMix,
        Id::CoupledExtract,
        Id::CoupledRootChain,
    };
}

uint256 RecordRoot(
    Id id,
    std::initializer_list<uint256> roots)
{
    HashWriter hash;
    hash << RECORD_DOMAIN;
    hash << static_cast<uint16_t>(id);
    hash << static_cast<uint32_t>(roots.size());
    for (const uint256& root : roots) {
        if (root.IsNull()) return {};
        hash << root;
    }
    return hash.GetHash();
}

uint256 EpisodeRangeRoot(
    const std::vector<RCStage3SignedRangeShardProof>& shards)
{
    if (shards.empty() ||
        shards.size() >
            std::numeric_limits<uint32_t>::max()) {
        return {};
    }
    HashWriter hash;
    hash << RECORD_DOMAIN;
    hash << static_cast<uint16_t>(Id::EpisodeSignedRange);
    hash << static_cast<uint32_t>(shards.size());
    for (const auto& shard : shards) {
        const uint256 pin =
            ComputeRCStage3SignedRangePinCommitment(shard.pin);
        if (pin.IsNull()) return {};
        hash << pin;
    }
    return hash.GetHash();
}

bool ValidateManifest(
    const RCStage3BoundedSemanticBindingManifest& manifest,
    std::string* why)
{
    if (manifest.magic !=
            kRCStage3BoundedSemanticBindingMagic ||
        manifest.version !=
            kRCStage3BoundedSemanticBindingVersion ||
        manifest.statement_commitment.IsNull() ||
        manifest.records.size() !=
            kRCStage3BoundedSemanticBindingRecordCount) {
        return Fail(why, "manifest_header");
    }
    const auto ids = RequiredIds();
    for (size_t i = 0; i < ids.size(); ++i) {
        if (manifest.records[i].id != ids[i] ||
            manifest.records[i].root.IsNull()) {
            return Fail(
                why, "manifest_record_" + std::to_string(i));
        }
    }
    const uint256 expected =
        ComputeRCStage3BoundedSemanticBindingCommitment(manifest);
    if (expected.IsNull() ||
        manifest.manifest_commitment != expected) {
        return Fail(why, "manifest_commitment");
    }
    return true;
}

bool SerializeEnvelope(
    const std::vector<unsigned char>& original,
    const RCStage3BoundedSemanticBindingManifest& manifest,
    std::vector<unsigned char>& out,
    std::string* why)
{
    std::vector<unsigned char> encoded_manifest;
    if (original.empty() ||
        original.size() > std::numeric_limits<uint32_t>::max() ||
        !SerializeRCStage3BoundedSemanticBindingManifest(
            manifest, encoded_manifest, why) ||
        encoded_manifest.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "envelope_input");
    }
    out.clear();
    WriteU32(out, ENVELOPE_MAGIC);
    WriteU16(out, ENVELOPE_VERSION);
    WriteU32(out, static_cast<uint32_t>(original.size()));
    out.insert(out.end(), original.begin(), original.end());
    WriteU32(
        out, static_cast<uint32_t>(encoded_manifest.size()));
    out.insert(
        out.end(), encoded_manifest.begin(),
        encoded_manifest.end());
    if (out.size() > kRCStage3MaxProofBytes) {
        out.clear();
        return Fail(why, "envelope_oversize");
    }
    return true;
}

bool DeserializeEnvelope(
    const std::vector<unsigned char>& bytes,
    std::vector<unsigned char>& original,
    RCStage3BoundedSemanticBindingManifest& manifest,
    std::string* why)
{
    Reader reader(bytes);
    uint32_t magic{0};
    uint16_t version{0};
    uint32_t original_size{0};
    uint32_t manifest_size{0};
    std::vector<unsigned char> encoded_manifest;
    if (!reader.ReadU32(magic) ||
        !reader.ReadU16(version) ||
        magic != ENVELOPE_MAGIC ||
        version != ENVELOPE_VERSION ||
        !reader.ReadU32(original_size) ||
        original_size == 0 ||
        !reader.ReadBytes(original_size, original) ||
        !reader.ReadU32(manifest_size) ||
        manifest_size == 0 ||
        !reader.ReadBytes(manifest_size, encoded_manifest) ||
        reader.Remaining() != 0) {
        return Fail(why, "noncanonical_envelope");
    }
    const auto decoded =
        DeserializeRCStage3BoundedSemanticBindingManifest(
            encoded_manifest, why);
    if (!decoded.has_value()) return false;
    manifest = *decoded;
    std::vector<unsigned char> canonical;
    if (!SerializeEnvelope(original, manifest, canonical, why) ||
        canonical != bytes) {
        return Fail(why, "envelope_roundtrip");
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3BoundedSemanticBindingCommitment(
    const RCStage3BoundedSemanticBindingManifest& manifest)
{
    if (manifest.magic !=
            kRCStage3BoundedSemanticBindingMagic ||
        manifest.version !=
            kRCStage3BoundedSemanticBindingVersion ||
        manifest.statement_commitment.IsNull() ||
        manifest.records.size() !=
            kRCStage3BoundedSemanticBindingRecordCount) {
        return {};
    }
    HashWriter hash;
    hash << MANIFEST_DOMAIN;
    hash << manifest.magic;
    hash << manifest.version;
    hash << manifest.statement_commitment;
    hash << static_cast<uint16_t>(manifest.records.size());
    for (const auto& record : manifest.records) {
        if (record.root.IsNull()) return {};
        hash << static_cast<uint16_t>(record.id);
        hash << record.root;
    }
    return hash.GetHash();
}

bool BuildRCStage3BoundedSemanticBindingManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3BoundedSemanticComposition& composition,
    RCStage3BoundedSemanticBindingManifest& out,
    std::string* why)
{
    out = {};
    if (statement.statement !=
        RCStage3StatementKind::Composed) {
        return Fail(why, "statement_kind");
    }
    const auto& e = composition.episode;
    const auto& c = composition.coupled;
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 episode_range =
        EpisodeRangeRoot(e.signed_range);
    const uint256 episode_root_chain = RecordRoot(
        Id::EpisodeDigestRootChain,
        {e.root_chain.manifest.commitment,
         e.root_chain.round_roots_pin.pin_commitment,
         e.root_chain.hash_bundle.manifest_commitment,
         e.root_chain.hash_binding.memory_manifest
             .manifest_commitment,
         e.root_chain.digest_pin.pin_commitment});
    const uint256 header_target = RecordRoot(
        Id::EpisodeHeaderTarget,
        {e.header_target.pin.pin_commitment,
         e.header_target.public_memory_manifest
             .manifest_commitment});
    const uint256 episode_pow = RecordRoot(
        Id::EpisodePow,
        {e.pow_pin.pin_commitment,
         e.pow_proof.pin_commitment});
    const uint256 bank_root = RecordRoot(
        Id::CoupledBankRoot,
        {c.bank_root.manifest.commitment,
         c.bank_root.bank_bytes.semantic_memory_root,
         c.bank_root.bank_digest.semantic_memory_root});
    const uint256 coupled_range = RecordRoot(
        Id::CoupledSignedRange,
        {c.signed_range.manifest.commitment,
         c.signed_range.value_roots_commitment});
    const uint256 coupled_root_chain = RecordRoot(
        Id::CoupledRootChain,
        {c.root_chain.barrier_inputs_pin.pin_commitment,
         c.root_chain.barrier_outputs_pin.pin_commitment,
         c.root_chain.digest_manifest.commitment,
         c.root_chain.digest_inputs_pin.pin_commitment,
         c.root_chain.digest_hash_bundle.manifest_commitment,
         c.root_chain.digest_value_pin.pin_commitment});

    out.statement_commitment = statement_commitment;
    out.records = {
        {Id::PublicComposition,
         RecordRoot(
             Id::PublicComposition, {statement_commitment})},
        {Id::EpisodeSeedChain,
         RecordRoot(
             Id::EpisodeSeedChain,
             {e.seed_chain.product_commitment})},
        {Id::EpisodeOperandXof,
         RecordRoot(
             Id::EpisodeOperandXof,
             {e.operand_xof.product_commitment})},
        {Id::EpisodeBuilderTrace,
         RecordRoot(
             Id::EpisodeBuilderTrace,
             {e.builder_trace.product_commitment})},
        {Id::EpisodeGemmExtractManifest,
         RecordRoot(
             Id::EpisodeGemmExtractManifest,
             {ComputeRCStage3GemmExtractManifestCommitment(
                 e.gemm_extract_manifest)})},
        {Id::EpisodeGemm,
         RecordRoot(
             Id::EpisodeGemm,
             {e.gemm.collection_commitment})},
        {Id::EpisodeSignedRange, episode_range},
        {Id::EpisodeExtract,
         RecordRoot(
             Id::EpisodeExtract,
             {e.extract.collection_commitment})},
        {Id::EpisodeTileStream,
         RecordRoot(
             Id::EpisodeTileStream,
             {e.tile_stream.collection_commitment,
              e.extract_stream_ctl.collection_commitment,
              e.tile_stream_leaf_ctl.collection_commitment,
              e.tile_tree_hash_ctl.collection_commitment})},
        {Id::EpisodeWiring,
         RecordRoot(
             Id::EpisodeWiring,
             {e.wiring.product_commitment})},
        {Id::EpisodeDigestRootChain, episode_root_chain},
        {Id::EpisodeRoundRootProducers,
         RecordRoot(
             Id::EpisodeRoundRootProducers,
             {e.round_root_producers.collection_commitment})},
        {Id::EpisodeHeaderTarget, header_target},
        {Id::EpisodePow, episode_pow},
        {Id::CoupledBank,
         RecordRoot(
             Id::CoupledBank,
             {c.bank.product_commitment})},
        {Id::CoupledBankRoot, bank_root},
        {Id::CoupledInitialState,
         RecordRoot(
             Id::CoupledInitialState,
             {c.initial_state.product_commitment})},
        {Id::CoupledGemm,
         RecordRoot(
             Id::CoupledGemm,
             {c.gemm.product_commitment})},
        {Id::CoupledSignedRange, coupled_range},
        {Id::CoupledExchangePermutation,
         RecordRoot(
             Id::CoupledExchangePermutation,
             {c.exchange_permutation.product_commitment})},
        {Id::CoupledMix,
         RecordRoot(
             Id::CoupledMix,
             {c.mix.product_commitment})},
        {Id::CoupledExtract,
         RecordRoot(
             Id::CoupledExtract,
             {c.extract.product_commitment})},
        {Id::CoupledRootChain, coupled_root_chain},
    };
    for (size_t i = 0; i < out.records.size(); ++i) {
        if (out.records[i].root.IsNull()) {
            out = {};
            return Fail(
                why, "null_sidecar_identity_" +
                         std::to_string(i));
        }
    }
    out.manifest_commitment =
        ComputeRCStage3BoundedSemanticBindingCommitment(out);
    if (!ValidateManifest(out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool SerializeRCStage3BoundedSemanticBindingManifest(
    const RCStage3BoundedSemanticBindingManifest& manifest,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateManifest(manifest, why)) return false;
    WriteU32(out, manifest.magic);
    WriteU16(out, manifest.version);
    WriteU16(
        out, static_cast<uint16_t>(manifest.records.size()));
    WriteUint256(out, manifest.statement_commitment);
    for (const auto& record : manifest.records) {
        WriteU16(out, static_cast<uint16_t>(record.id));
        WriteUint256(out, record.root);
    }
    WriteUint256(out, manifest.manifest_commitment);
    return true;
}

std::optional<RCStage3BoundedSemanticBindingManifest>
DeserializeRCStage3BoundedSemanticBindingManifest(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    Reader reader(bytes);
    RCStage3BoundedSemanticBindingManifest out;
    uint16_t count{0};
    if (!reader.ReadU32(out.magic) ||
        !reader.ReadU16(out.version) ||
        !reader.ReadU16(count) ||
        count != kRCStage3BoundedSemanticBindingRecordCount ||
        !reader.ReadUint256(out.statement_commitment)) {
        Fail(why, "truncated_manifest_header");
        return std::nullopt;
    }
    out.records.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        uint16_t id{0};
        Record record;
        if (!reader.ReadU16(id) ||
            !reader.ReadUint256(record.root)) {
            Fail(why, "truncated_manifest_record");
            return std::nullopt;
        }
        record.id = static_cast<Id>(id);
        out.records.push_back(record);
    }
    if (!reader.ReadUint256(out.manifest_commitment) ||
        reader.Remaining() != 0 ||
        !ValidateManifest(out, why)) {
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (!SerializeRCStage3BoundedSemanticBindingManifest(
            out, canonical, why) ||
        canonical != bytes) {
        Fail(why, "manifest_roundtrip");
        return std::nullopt;
    }
    return out;
}

bool AttachRCStage3BoundedSemanticBinding(
    RCStage3SuccinctProof& statement,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why)
{
    std::string composition_why;
    if (!VerifyRCStage3CompositionLink(
            statement, &composition_why)) {
        return Fail(
            why, "unbound_outer_statement:" +
                     composition_why);
    }
    RCStage3BoundedSemanticBindingManifest manifest;
    if (!BuildRCStage3BoundedSemanticBindingManifest(
            statement, composition, manifest, why)) {
        return false;
    }
    const auto roles =
        RequiredRCStage3RelationRoles(statement.statement);
    const auto role_it = std::find(
        roles.begin(), roles.end(),
        RCStage3RelationRole::CompositionLink);
    if (role_it == roles.end()) {
        return Fail(why, "missing_composition_role");
    }
    const size_t index =
        static_cast<size_t>(role_it - roles.begin());
    if (index >= statement.commitments.size() ||
        index >= statement.sections.size() ||
        statement.commitments[index].role !=
            RCStage3RelationRole::CompositionLink ||
        statement.sections[index].role !=
            RCStage3RelationRole::CompositionLink) {
        return Fail(why, "composition_role_order");
    }
    std::vector<unsigned char> prior;
    RCStage3BoundedSemanticBindingManifest prior_manifest;
    if (DeserializeEnvelope(
            statement.sections[index].proof, prior,
            prior_manifest, nullptr)) {
        return Fail(why, "already_bound");
    }
    std::vector<unsigned char> envelope;
    if (!SerializeEnvelope(
            statement.sections[index].proof,
            manifest, envelope, why)) {
        return false;
    }
    statement.sections[index].proof = std::move(envelope);
    statement.commitments[index].root =
        manifest.manifest_commitment;
    statement.public_inputs.transcript_commitment =
        ComputeRCStage3TranscriptCommitment(statement);
    if (!VerifyRCStage3CompositionLink(
            statement, &composition_why)) {
        return Fail(
            why, "bound_outer_statement:" +
                     composition_why);
    }
    return true;
}

bool VerifyRCStage3BoundedSemanticBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why)
{
    std::string composition_why;
    if (!VerifyRCStage3CompositionLink(
            statement, &composition_why)) {
        return Fail(
            why, "outer_statement:" + composition_why);
    }
    RCStage3BoundedSemanticBindingManifest expected;
    if (!BuildRCStage3BoundedSemanticBindingManifest(
            statement, composition, expected, why)) {
        return false;
    }
    const auto roles =
        RequiredRCStage3RelationRoles(statement.statement);
    const auto role_it = std::find(
        roles.begin(), roles.end(),
        RCStage3RelationRole::CompositionLink);
    if (role_it == roles.end()) {
        return Fail(why, "missing_composition_role");
    }
    const size_t index =
        static_cast<size_t>(role_it - roles.begin());
    if (index >= statement.commitments.size() ||
        index >= statement.sections.size() ||
        statement.commitments[index].root !=
            expected.manifest_commitment) {
        return Fail(why, "outer_manifest_root");
    }
    std::vector<unsigned char> original;
    RCStage3BoundedSemanticBindingManifest actual;
    if (!DeserializeEnvelope(
            statement.sections[index].proof, original,
            actual, why)) {
        return false;
    }
    if (actual != expected) {
        return Fail(why, "typed_sidecar_identity");
    }
    return true;
}

static_assert(
    kRCStage3BoundedSemanticCompositionDurablyCommitmentBound);
static_assert(
    !kRCStage3BoundedSemanticCompositionDurablySerialized);
static_assert(
    !kRCStage3BoundedSemanticCompositionAuthorityReady);

} // namespace matmul::v4::rc
