// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_bank_stream.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <span.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>

namespace matmul::v4::rc {
namespace {

namespace ah = alg_hash;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
using Digest = ah::Digest;

constexpr char SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_SCHEDULE_V1";
constexpr char MANIFEST_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_MANIFEST_V1";
constexpr char LEAF_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_LEAF_SEED_V1";
constexpr char LEAF_COMMITMENT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_LEAF_V1";
constexpr char LEAF_AIR_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_LEAF_AIR_PROOF_V1";
constexpr char INTERVAL_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_INTERVAL_V1";
constexpr char INTERVAL_AIR_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_INTERVAL_AIR_SEED_V1";
constexpr char INTERVAL_AIR_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_INTERVAL_AIR_PROOF_V1";
constexpr char RECURSIVE_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_RECURSIVE_PROOF_V1";
constexpr char NORMALIZED_STEP_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_NORMALIZED_STEP_V1";
constexpr char SECOND_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_STREAM_SECOND_SEED_V1";
constexpr uint64_t SOURCE_LEAF_DOMAIN = UINT64_C(0x4254585342434c31);
constexpr uint64_t SOURCE_PAD_DOMAIN = UINT64_C(0x4254585342504431);

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_bank_stream:" + detail;
    }
    return false;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

uint64_t CeilDiv(uint64_t value, uint64_t divisor)
{
    return value / divisor + (value % divisor != 0 ? 1 : 0);
}

bool NextPowerOfTwo(uint64_t value, uint64_t& out, uint32_t& depth)
{
    if (value == 0 || value > (uint64_t{1} << 32)) return false;
    out = 1;
    depth = 0;
    while (out < value) {
        out <<= 1;
        ++depth;
    }
    return true;
}

gf::Fp Fp(uint64_t value)
{
    return gf::FromU64(value);
}

uint256 Pack(const Digest& digest)
{
    return Fri3AlgDigestToUint256(digest);
}

std::optional<Digest> Unpack(const uint256& packed)
{
    return Fri3AlgDigestFromUint256(packed);
}

Digest SourceLeafDigest(
    uint64_t total_bytes,
    uint64_t chunk_index,
    uint32_t byte_count,
    const std::array<uint8_t, 64>& bytes)
{
    std::vector<gf::Fp> words;
    words.reserve(68);
    words.push_back(Fp(SOURCE_LEAF_DOMAIN));
    words.push_back(Fp(total_bytes));
    words.push_back(Fp(chunk_index));
    words.push_back(Fp(byte_count));
    for (uint8_t byte : bytes) words.push_back(Fp(byte));
    return ah::SpongeHashFp(words);
}

Digest SourcePadDigest(
    uint64_t total_bytes,
    uint64_t source_chunks,
    uint64_t leaf_index)
{
    return ah::SpongeHashFp({
        Fp(SOURCE_PAD_DOMAIN),
        Fp(total_bytes),
        Fp(source_chunks),
        Fp(leaf_index)});
}

uint256 IntervalCommitment(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& receipt)
{
    if (manifest.commitment.IsNull() ||
        receipt.version != kRCStage3CoupledBankStreamVersion ||
        receipt.block_count == 0) {
        return {};
    }
    HashWriter hash;
    hash << INTERVAL_DOMAIN;
    hash << receipt.version;
    hash << manifest.commitment;
    hash << receipt.level;
    hash << receipt.index;
    hash << receipt.first_block;
    hash << receipt.block_count;
    for (uint32_t word : receipt.first_h_in) hash << word;
    for (uint32_t word : receipt.last_h_out) hash << word;
    hash << static_cast<uint32_t>(receipt.child_commitments.size());
    for (const auto& child : receipt.child_commitments) {
        if (child.IsNull()) return {};
        hash << child;
    }
    return hash.GetHash();
}

uint64_t CountAtLevel(
    const RCStage3CoupledBankStreamManifest& manifest,
    uint32_t level)
{
    uint64_t count = manifest.first_pass_blocks;
    for (uint32_t i = 0; i < level; ++i) {
        count = CeilDiv(count, kRCStage3CoupledBankStreamArity);
    }
    return count;
}

bool ValidateIntervalDescriptor(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& receipt,
    std::string* why)
{
    if (receipt.version !=
            kRCStage3CoupledBankStreamVersion ||
        receipt.level > manifest.aggregation_levels ||
        receipt.index >= CountAtLevel(manifest, receipt.level) ||
        receipt.first_block >= manifest.first_pass_blocks ||
        receipt.block_count >
            manifest.first_pass_blocks - receipt.first_block ||
        receipt.commitment.IsNull() ||
        receipt.commitment !=
            IntervalCommitment(manifest, receipt)) {
        return Fail(why, "interval:descriptor");
    }
    if (receipt.level == 0) {
        if (receipt.first_block != receipt.index ||
            receipt.block_count != 1 ||
            receipt.child_commitments.size() != 1) {
            return Fail(why, "interval:leaf");
        }
    } else {
        const uint64_t child_count =
            CountAtLevel(manifest, receipt.level - 1);
        const uint64_t first_child =
            receipt.index * kRCStage3CoupledBankStreamArity;
        const uint64_t required =
            std::min<uint64_t>(
                kRCStage3CoupledBankStreamArity,
                child_count - first_child);
        if (receipt.child_commitments.size() != required) {
            return Fail(why, "interval:child_count");
        }
    }
    return true;
}

bool ExpectedManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& source_root,
    RCStage3CoupledBankStreamManifest& out,
    std::string* why)
{
    out = {};
    if (!IsCoupledStatement(statement) || source_root.IsNull() ||
        statement.public_inputs.coupled_profile != 4 ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version) {
        return Fail(why, "manifest:statement_or_root");
    }
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledBank, shape, why);
    uint64_t page_size{0};
    uint64_t bank_bytes{0};
    if (!counts.has_value() ||
        counts->primary != shape.bank_pages ||
        !CheckedMul(shape.lobe_width, shape.lobe_width, page_size) ||
        !CheckedMul(page_size, shape.bank_pages, bank_bytes) ||
        bank_bytes == 0) {
        return Fail(why, "manifest:shape");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    const uint64_t tag_size = std::strlen(tags.bank);
    uint64_t message_bytes{0};
    uint64_t padded_numerator{0};
    if (!CheckedAdd(tag_size, bank_bytes, message_bytes) ||
        !CheckedAdd(message_bytes, 9, padded_numerator)) {
        return Fail(why, "manifest:size_overflow");
    }
    uint64_t message_bits{0};
    if (!CheckedMul(message_bytes, 8, message_bits)) {
        return Fail(why, "manifest:bit_length");
    }
    const uint64_t blocks = CeilDiv(padded_numerator, 64);
    const uint64_t source_chunks = CeilDiv(bank_bytes, 64);
    uint64_t source_leaves{0};
    uint32_t source_depth{0};
    if (blocks == 0 || source_chunks == 0 ||
        source_chunks >
            std::numeric_limits<uint32_t>::max() ||
        !NextPowerOfTwo(
            source_chunks, source_leaves, source_depth)) {
        return Fail(why, "manifest:tree");
    }

    uint64_t aggregation_count = blocks;
    uint64_t aggregation_sites = 0;
    uint32_t aggregation_levels = 0;
    while (aggregation_count > 1) {
        aggregation_count = CeilDiv(
            aggregation_count,
            kRCStage3CoupledBankStreamArity);
        if (!CheckedAdd(
                aggregation_sites, aggregation_count,
                aggregation_sites)) {
            return Fail(why, "manifest:aggregation_overflow");
        }
        ++aggregation_levels;
    }

    out.statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    out.shape = shape;
    out.bank_page_byte_root = source_root;
    out.bank_page_bytes = bank_bytes;
    out.first_message_bytes = message_bytes;
    out.first_pass_blocks = blocks;
    out.source_chunks = source_chunks;
    out.source_tree_leaves = source_leaves;
    out.source_tree_depth = source_depth;
    out.aggregation_levels = aggregation_levels;
    out.aggregation_parent_sites = aggregation_sites;
    HashWriter schedule;
    schedule << SCHEDULE_DOMAIN;
    schedule << kRCStage3CoupledBankStreamVersion;
    schedule << kRCStage3CoupledBankStreamArity;
    schedule << out.statement_commitment;
    schedule << CommitRCStage3CoupledShape(shape);
    schedule << source_root;
    schedule << tag_size;
    schedule << bank_bytes;
    schedule << message_bytes;
    schedule << message_bits;
    schedule << blocks;
    schedule << source_chunks;
    schedule << source_leaves;
    schedule << source_depth;
    schedule << aggregation_levels;
    schedule << aggregation_sites;
    out.schedule_commitment = schedule.GetHash();
    out.commitment = CommitRCStage3CoupledBankStreamManifest(out);
    return !out.schedule_commitment.IsNull() &&
           !out.commitment.IsNull();
}

std::vector<uint64_t> RequiredSourceChunks(
    const RCStage3CoupledBankStreamManifest& manifest,
    uint64_t block_index)
{
    std::vector<uint64_t> out;
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.shape.transcript_version);
    const uint64_t tag_size = std::strlen(tags.bank);
    const uint64_t block_begin = block_index * 64;
    for (uint64_t lane = 0; lane < 64; ++lane) {
        const uint64_t offset = block_begin + lane;
        if (offset < tag_size ||
            offset >= tag_size + manifest.bank_page_bytes) {
            continue;
        }
        const uint64_t chunk = (offset - tag_size) / 64;
        if (out.empty() || out.back() != chunk) out.push_back(chunk);
    }
    return out;
}

bool CheckCanonicalBlock(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& leaf,
    std::string* why)
{
    const std::vector<uint64_t> required =
        RequiredSourceChunks(manifest, leaf.block_index);
    if (required.size() != leaf.source_openings.size()) {
        return Fail(why, "leaf:source_opening_count");
    }
    for (uint32_t i = 0; i < required.size(); ++i) {
        if (leaf.source_openings[i].chunk_index != required[i] ||
            !VerifyRCStage3CoupledBankSourceOpening(
                manifest, leaf.source_openings[i], why)) {
            return Fail(why, "leaf:source_opening");
        }
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(manifest.shape.transcript_version);
    const uint64_t tag_size = std::strlen(tags.bank);
    const auto* tag_bytes =
        reinterpret_cast<const uint8_t*>(tags.bank);
    uint64_t message_bits{0};
    if (!CheckedMul(manifest.first_message_bytes, 8, message_bits)) {
        return Fail(why, "leaf:bit_length");
    }
    const uint64_t padded_bytes = manifest.first_pass_blocks * 64;
    for (uint64_t lane = 0; lane < 64; ++lane) {
        const uint64_t absolute = leaf.block_index * 64 + lane;
        uint8_t expected{0};
        if (absolute < tag_size) {
            expected = tag_bytes[absolute];
        } else if (
            absolute < tag_size + manifest.bank_page_bytes) {
            const uint64_t bank_offset = absolute - tag_size;
            const uint64_t chunk = bank_offset / 64;
            const uint64_t in_chunk = bank_offset % 64;
            const auto it = std::lower_bound(
                required.begin(), required.end(), chunk);
            if (it == required.end() || *it != chunk) {
                return Fail(why, "leaf:source_lookup");
            }
            const size_t position =
                static_cast<size_t>(it - required.begin());
            expected =
                leaf.source_openings[position].bytes[in_chunk];
        } else if (absolute == manifest.first_message_bytes) {
            expected = 0x80;
        } else if (absolute >= padded_bytes - 8) {
            const uint32_t shift = static_cast<uint32_t>(
                8 * (padded_bytes - 1 - absolute));
            expected = static_cast<uint8_t>(message_bits >> shift);
        }
        if (leaf.padded_block[lane] != expected) {
            return Fail(why, "leaf:padded_block");
        }
    }
    return true;
}

std::array<uint8_t, 64> SecondPassBlock(
    const std::array<uint32_t, 8>& first_terminal)
{
    std::array<uint8_t, 64> block{};
    for (uint32_t i = 0; i < 8; ++i) {
        block[4 * i] =
            static_cast<uint8_t>(first_terminal[i] >> 24);
        block[4 * i + 1] =
            static_cast<uint8_t>(first_terminal[i] >> 16);
        block[4 * i + 2] =
            static_cast<uint8_t>(first_terminal[i] >> 8);
        block[4 * i + 3] =
            static_cast<uint8_t>(first_terminal[i]);
    }
    block[32] = 0x80;
    block[62] = 0x01;
    block[63] = 0x00;
    return block;
}

uint256 DigestWords(const std::array<uint32_t, 8>& words)
{
    std::array<unsigned char, 32> bytes{};
    for (uint32_t i = 0; i < 8; ++i) {
        bytes[4 * i] = words[i] >> 24;
        bytes[4 * i + 1] = words[i] >> 16;
        bytes[4 * i + 2] = words[i] >> 8;
        bytes[4 * i + 3] = words[i];
    }
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

struct IntervalAirLayout {
    uint32_t active{0};
    uint32_t first_block{1};
    uint32_t block_count{2};
    uint32_t h_in{3};
    uint32_t h_out{11};
    uint32_t child_commitment{19};
    uint32_t running_count{27};
    uint32_t is_last{28};
    uint32_t expected{29};
    uint32_t parent_first_block{58};
    uint32_t parent_block_count{59};
    uint32_t parent_h_in{60};
    uint32_t parent_h_out{68};
    uint32_t end{76};
};

constexpr IntervalAirLayout INTERVAL_AIR{};
constexpr uint32_t INTERVAL_DATA_COLUMNS = 29;
constexpr uint32_t INTERVAL_ROWS =
    kRCStage3CoupledBankStreamArity;

gf::Fp3 Fp3FromU64(uint64_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

std::array<uint32_t, 8> Uint256Words(
    const uint256& value)
{
    std::array<uint32_t, 8> words{};
    for (uint32_t limb = 0; limb < words.size(); ++limb) {
        const size_t offset = static_cast<size_t>(limb) * 4;
        words[limb] =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(value.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(value.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(value.begin()[offset + 3]) << 24);
    }
    return words;
}

void AddIntervalConstraint(
    air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    const char* name,
    air_quotient::AirKind kind,
    uint32_t degree,
    std::function<gf::Fp3(
        const std::vector<gf::Fp3>&,
        const std::vector<gf::Fp3>&)> eval)
{
    air_quotient::AirConstraint<gf::Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

bool BuildIntervalAir(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>* witness,
    std::string* why)
{
    RCStage3CoupledBankStreamIntervalReceipt expected_parent;
    if (!BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, children, expected_parent, why) ||
        !(parent == expected_parent)) {
        return Fail(why, "interval_air:parent_statement");
    }

    cs = {};
    cs.n_rows = INTERVAL_ROWS;
    cs.n_columns = INTERVAL_AIR.end;
    cs.preprocessed_pin_ood = true;
    std::vector<std::vector<gf::Fp3>> columns(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));

    uint64_t running = 0;
    for (uint32_t row = 0; row < children.size(); ++row) {
        const auto& child = children[row];
        running += child.block_count;
        columns[INTERVAL_AIR.active][row] = gf::Fp3::One();
        columns[INTERVAL_AIR.first_block][row] =
            Fp3FromU64(child.first_block);
        columns[INTERVAL_AIR.block_count][row] =
            Fp3FromU64(child.block_count);
        for (uint32_t word = 0; word < 8; ++word) {
            columns[INTERVAL_AIR.h_in + word][row] =
                Fp3FromU64(child.first_h_in[word]);
            columns[INTERVAL_AIR.h_out + word][row] =
                Fp3FromU64(child.last_h_out[word]);
        }
        const auto commitment_words =
            Uint256Words(child.commitment);
        for (uint32_t word = 0; word < 8; ++word) {
            columns[
                INTERVAL_AIR.child_commitment + word][row] =
                Fp3FromU64(commitment_words[word]);
        }
        columns[INTERVAL_AIR.running_count][row] =
            Fp3FromU64(running);
    }
    columns[INTERVAL_AIR.is_last][children.size() - 1] =
        gf::Fp3::One();

    // Every child-statement cell is proof-public through an OOD-pinned
    // preprocessed column; the witness cannot substitute a different
    // interval, state, or child receipt.
    for (uint32_t column = 0;
         column < INTERVAL_DATA_COLUMNS; ++column) {
        const uint32_t expected =
            INTERVAL_AIR.expected + column;
        columns[expected] = columns[column];
        cs.preprocessed.emplace_back(
            expected, columns[expected]);
        AddIntervalConstraint(
            cs, "stage3.bank_interval.public_child_pin",
            air_quotient::AirKind::kEverywhere, 1,
            [column, expected](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(cur[column], cur[expected]);
            });
    }

    auto pin_parent =
        [&](uint32_t column, gf::Fp3 value) {
            std::fill(
                columns[column].begin(), columns[column].end(),
                value);
            cs.preprocessed.emplace_back(column, columns[column]);
        };
    pin_parent(
        INTERVAL_AIR.parent_first_block,
        Fp3FromU64(parent.first_block));
    pin_parent(
        INTERVAL_AIR.parent_block_count,
        Fp3FromU64(parent.block_count));
    for (uint32_t word = 0; word < 8; ++word) {
        pin_parent(
            INTERVAL_AIR.parent_h_in + word,
            Fp3FromU64(parent.first_h_in[word]));
        pin_parent(
            INTERVAL_AIR.parent_h_out + word,
            Fp3FromU64(parent.last_h_out[word]));
    }

    AddIntervalConstraint(
        cs, "stage3.bank_interval.active_boolean",
        air_quotient::AirKind::kEverywhere, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[INTERVAL_AIR.active],
                gf::Sub(
                    cur[INTERVAL_AIR.active],
                    gf::Fp3::One()));
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.last_boolean",
        air_quotient::AirKind::kEverywhere, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[INTERVAL_AIR.is_last],
                gf::Sub(
                    cur[INTERVAL_AIR.is_last],
                    gf::Fp3::One()));
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.last_is_active",
        air_quotient::AirKind::kEverywhere, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[INTERVAL_AIR.is_last],
                gf::Sub(
                    gf::Fp3::One(),
                    cur[INTERVAL_AIR.active]));
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.active_prefix",
        air_quotient::AirKind::kTransition, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                next[INTERVAL_AIR.active],
                gf::Sub(
                    gf::Fp3::One(),
                    cur[INTERVAL_AIR.active]));
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.contiguous",
        air_quotient::AirKind::kTransition, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                next[INTERVAL_AIR.active],
                gf::Sub(
                    next[INTERVAL_AIR.first_block],
                    gf::Add(
                        cur[INTERVAL_AIR.first_block],
                        cur[INTERVAL_AIR.block_count])));
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.running_coverage",
        air_quotient::AirKind::kTransition, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                next[INTERVAL_AIR.active],
                gf::Sub(
                    next[INTERVAL_AIR.running_count],
                    gf::Add(
                        cur[INTERVAL_AIR.running_count],
                        next[INTERVAL_AIR.block_count])));
        });
    for (uint32_t word = 0; word < 8; ++word) {
        AddIntervalConstraint(
            cs, "stage3.bank_interval.sha_chain_word",
            air_quotient::AirKind::kTransition, 2,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>& next) {
                return gf::Mul(
                    next[INTERVAL_AIR.active],
                    gf::Sub(
                        next[INTERVAL_AIR.h_in + word],
                        cur[INTERVAL_AIR.h_out + word]));
            });
    }
    AddIntervalConstraint(
        cs, "stage3.bank_interval.parent_first_block",
        air_quotient::AirKind::kFirstRow, 1,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[INTERVAL_AIR.first_block],
                cur[INTERVAL_AIR.parent_first_block]);
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.first_active",
        air_quotient::AirKind::kFirstRow, 1,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[INTERVAL_AIR.active], gf::Fp3::One());
        });
    AddIntervalConstraint(
        cs, "stage3.bank_interval.first_running",
        air_quotient::AirKind::kFirstRow, 1,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[INTERVAL_AIR.running_count],
                cur[INTERVAL_AIR.block_count]);
        });
    for (uint32_t word = 0; word < 8; ++word) {
        AddIntervalConstraint(
            cs, "stage3.bank_interval.parent_first_state",
            air_quotient::AirKind::kFirstRow, 1,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    cur[INTERVAL_AIR.h_in + word],
                    cur[INTERVAL_AIR.parent_h_in + word]);
            });
        AddIntervalConstraint(
            cs, "stage3.bank_interval.parent_last_state",
            air_quotient::AirKind::kEverywhere, 2,
            [word](
                const std::vector<gf::Fp3>& cur,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    cur[INTERVAL_AIR.is_last],
                    gf::Sub(
                        cur[INTERVAL_AIR.h_out + word],
                        cur[INTERVAL_AIR.parent_h_out + word]));
            });
    }
    AddIntervalConstraint(
        cs, "stage3.bank_interval.parent_total_count",
        air_quotient::AirKind::kEverywhere, 2,
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[INTERVAL_AIR.is_last],
                gf::Sub(
                    cur[INTERVAL_AIR.running_count],
                    cur[INTERVAL_AIR.parent_block_count]));
        });

    if (witness != nullptr) *witness = std::move(columns);
    return true;
}

uint256 IntervalAirSeed(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent)
{
    if (manifest.commitment.IsNull() ||
        parent.commitment.IsNull() || children.empty()) {
        return {};
    }
    HashWriter hash;
    hash << INTERVAL_AIR_SEED_DOMAIN;
    hash << kRCStage3CoupledBankStreamVersion;
    hash << manifest.commitment;
    hash << parent.commitment;
    hash << static_cast<uint32_t>(children.size());
    for (const auto& child : children) {
        if (child.commitment.IsNull()) return {};
        hash << child.commitment;
    }
    return hash.GetHash();
}

void HashFp3(HashWriter& hash, const gf::Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

uint256 CommitIntervalAirProof(
    const RCStage3CoupledBankStreamIntervalAirProof& proof)
{
    std::vector<unsigned char> batch;
    if (SerializeFri3AlgBatchProof(proof.batch, batch) !=
            batch.size() ||
        batch.empty() || proof.trace_commit.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << INTERVAL_AIR_PROOF_DOMAIN;
    hash << static_cast<uint32_t>(batch.size());
    for (uint8_t byte : batch) hash << byte;
    hash << proof.trace_commit;
    hash << static_cast<uint32_t>(proof.next_openings.size());
    for (const auto& query : proof.next_openings) {
        hash << static_cast<uint32_t>(query.size());
        for (const auto& path : query) {
            hash << path.index;
            hash << static_cast<uint32_t>(path.values.size());
            for (const auto& value : path.values) {
                HashFp3(hash, value);
            }
            hash << static_cast<uint32_t>(path.siblings.size());
            for (const auto& sibling : path.siblings) {
                for (const auto value : sibling) {
                    hash << gf::Canonical(value);
                }
            }
        }
    }
    return hash.GetHash();
}

uint256 CommitLeafAirProof(
    const ha::FixedProgramProvenanceAirProof& proof)
{
    if (!proof.valid || proof.boundary_statement.IsNull() ||
        proof.challenge_commitment.IsNull()) {
        return {};
    }
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(
            proof.quotient.batch, batch) != batch.size() ||
        batch.empty()) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_AIR_PROOF_DOMAIN;
    hash << proof.version;
    hash << proof.boundary_statement;
    hash << proof.challenge_commitment;
    hash << static_cast<uint32_t>(batch.size());
    for (uint8_t byte : batch) hash << byte;
    hash << static_cast<uint32_t>(
        proof.quotient.next_openings.size());
    for (const auto& query : proof.quotient.next_openings) {
        hash << static_cast<uint32_t>(query.size());
        for (const auto& path : query) {
            hash << path.index;
            HashFp3(hash, path.leaf);
            hash << static_cast<uint32_t>(path.siblings.size());
            for (const auto& sibling : path.siblings) {
                hash << sibling;
            }
        }
    }
    return hash.GetHash();
}

void HashVerifierFamilies(
    HashWriter& hash,
    const air_recurse::VerifierAirFamilies& families)
{
    hash << families.row_merkle;
    hash << families.fold;
    hash << families.deep;
    hash << families.per_point;
    hash << families.next_row;
    hash << families.trace_binding;
}

uint256 NormalizedStepCommitment(
    const RCStage3CoupledBankNormalizedVerifierStep& step)
{
    if (step.version != kRCStage3CoupledBankStreamVersion ||
        step.logical_children == 0 ||
        step.logical_children > kRCStage3CoupledBankStreamArity ||
        step.child_fs_seed.IsNull() ||
        step.parent_fs_seed.IsNull() ||
        step.effective_fs_seed.IsNull() ||
        step.child_statement_commitment.IsNull() ||
        step.normalized_parent_proof_commitment.IsNull() ||
        step.child_pins.size() != step.logical_children ||
        step.lane_public_inputs.size() !=
            step.logical_children *
                kRCFri3AlgDualNumLanes) {
        return {};
    }
    HashWriter hash;
    hash << NORMALIZED_STEP_DOMAIN;
    hash << step.version;
    hash << step.logical_children;
    hash << step.child_fs_seed;
    hash << step.parent_fs_seed;
    hash << step.effective_fs_seed;
    hash << step.child_statement_commitment;
    HashVerifierFamilies(hash, step.families);
    hash << step.normalized_parent_proof_commitment;
    hash << air_recurse::CommitDualV5RecursiveChildPins(
        step.child_pins);
    hash << step.rows;
    hash << step.columns;
    hash << step.constraints;
    hash << step.descendant_free;
    hash << step.all_available_algebraic_families;
    hash << step.complete_child_proof_commitments;
    hash << step.fiat_shamir_replayed_on_host;
    hash << step.fiat_shamir_equations_in_air;
    hash << step.bank_interval_relation_same_trace;
    return hash.GetHash();
}

} // namespace

uint256 CommitRCStage3CoupledBankStreamManifest(
    const RCStage3CoupledBankStreamManifest& manifest)
{
    if (manifest.version != kRCStage3CoupledBankStreamVersion ||
        manifest.aggregation_arity !=
            kRCStage3CoupledBankStreamArity ||
        manifest.statement_commitment.IsNull() ||
        manifest.bank_page_byte_root.IsNull() ||
        manifest.bank_page_bytes == 0 ||
        manifest.first_message_bytes == 0 ||
        manifest.first_pass_blocks == 0 ||
        manifest.source_chunks == 0 ||
        manifest.source_tree_leaves < manifest.source_chunks ||
        manifest.schedule_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << MANIFEST_DOMAIN;
    hash << manifest.version;
    hash << manifest.aggregation_arity;
    hash << manifest.statement_commitment;
    hash << CommitRCStage3CoupledShape(manifest.shape);
    hash << manifest.bank_page_byte_root;
    hash << manifest.bank_page_bytes;
    hash << manifest.first_message_bytes;
    hash << manifest.first_pass_blocks;
    hash << manifest.source_chunks;
    hash << manifest.source_tree_leaves;
    hash << manifest.source_tree_depth;
    hash << manifest.aggregation_levels;
    hash << manifest.aggregation_parent_sites;
    hash << manifest.schedule_commitment;
    return hash.GetHash();
}

bool BuildRCStage3CoupledBankStreamManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const uint256& expected_bank_page_byte_root,
    RCStage3CoupledBankStreamManifest& out,
    std::string* why)
{
    return ExpectedManifest(
        statement, expected_shape,
        expected_bank_page_byte_root, out, why);
}

bool ValidateRCStage3CoupledBankStreamManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const uint256& expected_bank_page_byte_root,
    const RCStage3CoupledBankStreamManifest& manifest,
    std::string* why)
{
    RCStage3CoupledBankStreamManifest expected;
    if (!ExpectedManifest(
            statement, expected_shape,
            expected_bank_page_byte_root, expected, why) ||
        manifest != expected) {
        return Fail(why, "manifest:noncanonical");
    }
    return true;
}

bool VerifyRCStage3CoupledBankSourceOpening(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankSourceOpening& opening,
    std::string* why)
{
    if (opening.chunk_index >= manifest.source_chunks ||
        opening.chunk_index >
            std::numeric_limits<uint32_t>::max() ||
        opening.authentication_path.size() !=
            manifest.source_tree_depth) {
        return Fail(why, "source:position");
    }
    const uint64_t begin = opening.chunk_index * 64;
    const uint32_t expected_count = static_cast<uint32_t>(
        std::min<uint64_t>(64, manifest.bank_page_bytes - begin));
    if (opening.byte_count != expected_count) {
        return Fail(why, "source:byte_count");
    }
    for (uint32_t i = expected_count; i < 64; ++i) {
        if (opening.bytes[i] != 0) {
            return Fail(why, "source:padding");
        }
    }
    Digest current = SourceLeafDigest(
        manifest.bank_page_bytes, opening.chunk_index,
        opening.byte_count, opening.bytes);
    uint64_t index = opening.chunk_index;
    for (const auto& packed_sibling :
         opening.authentication_path) {
        const auto sibling = Unpack(packed_sibling);
        if (!sibling.has_value()) {
            return Fail(why, "source:sibling");
        }
        current = (index & 1U) == 0
            ? ah::Compress(current, *sibling)
            : ah::Compress(*sibling, current);
        index >>= 1;
    }
    if (Pack(current) != manifest.bank_page_byte_root) {
        return Fail(why, "source:root");
    }
    return true;
}

bool BuildRCStage3CoupledBankSourceOpeningForTest(
    const std::vector<uint8_t>& page_bytes,
    uint64_t chunk_index,
    uint256& root,
    RCStage3CoupledBankSourceOpening& opening,
    std::string* why)
{
    root = {};
    opening = {};
    if (page_bytes.empty() ||
        page_bytes.size() >
            kRCStage3CoupledBankStreamTestMaxBytes) {
        return Fail(why, "source_test:size");
    }
    const uint64_t chunks = CeilDiv(page_bytes.size(), 64);
    if (chunk_index >= chunks ||
        chunks > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "source_test:index");
    }
    uint64_t leaves{0};
    uint32_t depth{0};
    if (!NextPowerOfTwo(chunks, leaves, depth)) {
        return Fail(why, "source_test:tree");
    }
    std::vector<Digest> level;
    level.reserve(leaves);
    for (uint64_t index = 0; index < leaves; ++index) {
        if (index < chunks) {
            std::array<uint8_t, 64> bytes{};
            const uint64_t begin = index * 64;
            const uint32_t count = static_cast<uint32_t>(
                std::min<uint64_t>(64, page_bytes.size() - begin));
            std::copy_n(
                page_bytes.begin() + begin, count, bytes.begin());
            level.push_back(SourceLeafDigest(
                page_bytes.size(), index, count, bytes));
            if (index == chunk_index) {
                opening.chunk_index = index;
                opening.byte_count = count;
                opening.bytes = bytes;
            }
        } else {
            level.push_back(SourcePadDigest(
                page_bytes.size(), chunks, index));
        }
    }
    uint64_t cursor = chunk_index;
    while (level.size() > 1) {
        opening.authentication_path.push_back(
            Pack(level[cursor ^ 1U]));
        std::vector<Digest> next(level.size() / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            next[i] = ah::Compress(
                level[2 * i], level[2 * i + 1]);
        }
        level = std::move(next);
        cursor >>= 1;
    }
    root = Pack(level.front());
    return !root.IsNull() &&
           opening.authentication_path.size() == depth;
}

uint256 ComputeRCStage3CoupledBankStreamLeafSeed(
    const RCStage3CoupledBankStreamManifest& manifest,
    uint64_t block_index)
{
    if (manifest.commitment.IsNull() ||
        block_index >= manifest.first_pass_blocks) {
        return {};
    }
    HashWriter hash;
    hash << LEAF_SEED_DOMAIN;
    hash << kRCStage3CoupledBankStreamVersion;
    hash << manifest.commitment;
    hash << block_index;
    return hash.GetHash();
}

uint256 CommitRCStage3CoupledBankStreamLeaf(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& leaf)
{
    if (manifest.commitment.IsNull() ||
        leaf.version != kRCStage3CoupledBankStreamVersion ||
        leaf.block_index >= manifest.first_pass_blocks ||
        leaf.compression_proof.boundary_statement.IsNull() ||
        leaf.compression_proof.challenge_commitment.IsNull()) {
        return {};
    }
    const uint256 proof_commitment =
        CommitLeafAirProof(leaf.compression_proof);
    if (proof_commitment.IsNull()) return {};
    HashWriter hash;
    hash << LEAF_COMMITMENT_DOMAIN;
    hash << leaf.version;
    hash << manifest.commitment;
    hash << leaf.block_index;
    for (uint8_t byte : leaf.padded_block) hash << byte;
    for (uint32_t word : leaf.h_in) hash << word;
    for (uint32_t word : leaf.h_out) hash << word;
    hash << static_cast<uint32_t>(leaf.source_openings.size());
    for (const auto& opening : leaf.source_openings) {
        hash << opening.chunk_index;
        hash << opening.byte_count;
        for (uint8_t byte : opening.bytes) hash << byte;
        hash << static_cast<uint32_t>(
            opening.authentication_path.size());
        for (const auto& sibling : opening.authentication_path) {
            hash << sibling;
        }
    }
    hash << leaf.compression_proof.boundary_statement;
    hash << leaf.compression_proof.challenge_commitment;
    hash << proof_commitment;
    return hash.GetHash();
}

bool VerifyRCStage3CoupledBankStreamLeaf(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& leaf,
    std::string* why)
{
    if (leaf.version != kRCStage3CoupledBankStreamVersion ||
        leaf.block_index >= manifest.first_pass_blocks) {
        return Fail(why, "leaf:shape");
    }
    if (!CheckCanonicalBlock(manifest, leaf, why)) return false;
    if (leaf.block_index == 0 &&
        leaf.h_in != ha::CanonicalSha256InitialState()) {
        return Fail(why, "leaf:initial_state");
    }
    ha::FixedProgramBoundaryInstance boundary;
    if (!ha::BuildSha256CompressionBoundaryInstance(
            leaf.padded_block, leaf.h_in, leaf.h_out,
            boundary, why)) {
        return Fail(why, "leaf:boundary");
    }
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    const uint256 seed =
        ComputeRCStage3CoupledBankStreamLeafSeed(
            manifest, leaf.block_index);
    if (seed.IsNull() ||
        !ha::VerifyFixedProgramProvenanceAir(
            program, boundary.external_values,
            boundary.final_words, seed,
            leaf.compression_proof, why)) {
        return Fail(why, "leaf:compression_proof");
    }
    const uint256 commitment =
        CommitRCStage3CoupledBankStreamLeaf(manifest, leaf);
    if (commitment.IsNull() ||
        leaf.leaf_commitment != commitment) {
        return Fail(why, "leaf:commitment");
    }
    return true;
}

bool BuildRCStage3CoupledBankStreamLeafReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& verified_leaf,
    RCStage3CoupledBankStreamIntervalReceipt& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3CoupledBankStreamLeaf(
            manifest, verified_leaf, why)) {
        return false;
    }
    out.level = 0;
    out.index = verified_leaf.block_index;
    out.first_block = verified_leaf.block_index;
    out.block_count = 1;
    out.first_h_in = verified_leaf.h_in;
    out.last_h_out = verified_leaf.h_out;
    out.child_commitments = {
        verified_leaf.leaf_commitment};
    out.commitment = IntervalCommitment(manifest, out);
    return ValidateIntervalDescriptor(manifest, out, why);
}

uint256 CommitRCStage3CoupledBankStreamIntervalReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& receipt)
{
    return IntervalCommitment(manifest, receipt);
}

bool BuildRCStage3CoupledBankStreamParentReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    RCStage3CoupledBankStreamIntervalReceipt& out,
    std::string* why)
{
    out = {};
    if (children.empty() ||
        children.size() >
            kRCStage3CoupledBankStreamArity) {
        return Fail(why, "parent:child_count");
    }
    const uint32_t child_level = children.front().level;
    if (child_level >= manifest.aggregation_levels) {
        return Fail(why, "parent:level");
    }
    const uint64_t parent_index =
        children.front().index /
        kRCStage3CoupledBankStreamArity;
    const uint64_t first_child =
        parent_index *
        kRCStage3CoupledBankStreamArity;
    const uint64_t level_count =
        CountAtLevel(manifest, child_level);
    const uint64_t expected_count = std::min<uint64_t>(
        kRCStage3CoupledBankStreamArity,
        level_count - first_child);
    if (children.size() != expected_count) {
        return Fail(why, "parent:canonical_arity");
    }
    uint64_t total_blocks = 0;
    for (uint32_t i = 0; i < children.size(); ++i) {
        if (!ValidateIntervalDescriptor(
                manifest, children[i], why) ||
            children[i].level != child_level ||
            children[i].index != first_child + i) {
            return Fail(why, "parent:child_descriptor");
        }
        if (i != 0) {
            const auto& previous = children[i - 1];
            if (children[i].first_block !=
                    previous.first_block +
                    previous.block_count ||
                children[i].first_h_in !=
                    previous.last_h_out) {
                return Fail(why, "parent:chain");
            }
        }
        if (!CheckedAdd(
                total_blocks, children[i].block_count,
                total_blocks)) {
            return Fail(why, "parent:block_overflow");
        }
    }
    out.level = child_level + 1;
    out.index = parent_index;
    out.first_block = children.front().first_block;
    out.block_count = total_blocks;
    out.first_h_in = children.front().first_h_in;
    out.last_h_out = children.back().last_h_out;
    for (const auto& child : children) {
        out.child_commitments.push_back(child.commitment);
    }
    out.commitment = IntervalCommitment(manifest, out);
    return ValidateIntervalDescriptor(manifest, out, why);
}

bool ValidateRCStage3CoupledBankStreamRootReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& root,
    std::string* why)
{
    if (!ValidateIntervalDescriptor(manifest, root, why) ||
        root.level != manifest.aggregation_levels ||
        root.index != 0 ||
        root.first_block != 0 ||
        root.block_count != manifest.first_pass_blocks ||
        root.first_h_in != ha::CanonicalSha256InitialState()) {
        return Fail(why, "root:coverage");
    }
    return true;
}

bool ProveRCStage3CoupledBankStreamIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    RCStage3CoupledBankStreamIntervalAirProof& out,
    std::string* why)
{
    out = {};
    air_quotient::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    if (!BuildIntervalAir(
            manifest, children, parent, cs, &columns, why)) {
        return false;
    }
    const uint256 seed =
        IntervalAirSeed(manifest, children, parent);
    if (seed.IsNull()) {
        return Fail(why, "interval_air:null_seed");
    }
    const auto proved = air_quotient::AirQuotientProve<
        gf::Fp3,
        air_quotient::AirFriBackendAlg<gf::Fp3>>(
        cs, columns, seed, {});
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "interval_air:prove:" + proved.note);
    }
    out = proved.proof;
    if (!air_quotient::AirQuotientVerify<
            gf::Fp3,
            air_quotient::AirFriBackendAlg<gf::Fp3>>(
            cs, out, seed, why)) {
        out = {};
        return Fail(why, "interval_air:self_verify");
    }
    return true;
}

bool BuildRCStage3CoupledBankStreamIntervalConstraintSystem(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    air_quotient::AirConstraintSystem<gf::Fp3>& out,
    std::string* why)
{
    return BuildIntervalAir(
        manifest, children, parent, out, nullptr, why);
}

bool VerifyRCStage3CoupledBankStreamIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    const RCStage3CoupledBankStreamIntervalAirProof& proof,
    std::string* why)
{
    air_quotient::AirConstraintSystem<gf::Fp3> cs;
    if (!BuildIntervalAir(
            manifest, children, parent, cs, nullptr, why)) {
        return false;
    }
    const uint256 seed =
        IntervalAirSeed(manifest, children, parent);
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<
            gf::Fp3,
            air_quotient::AirFriBackendAlg<gf::Fp3>>(
            cs, proof, seed, why)) {
        return Fail(why, "interval_air:verify");
    }
    return true;
}

bool ProveRCStage3CoupledBankStreamDualIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    const uint256& fs_seed,
    RCStage3CoupledBankStreamDualIntervalAirProof& out,
    std::string* why)
{
    out = {};
    air_quotient::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    if (fs_seed.IsNull() ||
        !BuildIntervalAir(
            manifest, children, parent, cs, &columns, why)) {
        return Fail(why, "dual_interval:statement");
    }
    const auto proved = air_quotient::AirQuotientProve<
        gf::Fp3, air_recurse::DualAlgB3>(
        cs, columns, fs_seed, {});
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "dual_interval:prove:" + proved.note);
    }
    out = proved.proof;
    if (!air_quotient::AirQuotientVerify<
            gf::Fp3, air_recurse::DualAlgB3>(
            cs, out, fs_seed, why)) {
        out = {};
        return Fail(why, "dual_interval:self_verify");
    }
    return true;
}

bool VerifyRCStage3CoupledBankStreamDualIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>&
        children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    const uint256& fs_seed,
    const RCStage3CoupledBankStreamDualIntervalAirProof& proof,
    std::string* why)
{
    air_quotient::AirConstraintSystem<gf::Fp3> cs;
    if (fs_seed.IsNull() ||
        !BuildIntervalAir(
            manifest, children, parent, cs, nullptr, why) ||
        !air_quotient::AirQuotientVerify<
            gf::Fp3, air_recurse::DualAlgB3>(
            cs, proof, fs_seed, why)) {
        return Fail(why, "dual_interval:verify");
    }
    return true;
}

RCStage3CoupledBankFullBinaryMirrorWitness
BuildRCStage3CoupledBankFullBinaryMirrorWitness(
    const std::vector<
        air_quotient::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<air_recurse::DualAlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    const std::vector<uint32_t>& child_output_column_bases)
{
    RCStage3CoupledBankFullBinaryMirrorWitness out;
    out.child_constraint_systems = child_css;
    out.child_fs_seeds = child_fs_seeds;
    out.child_output_column_bases =
        child_output_column_bases;
    if (child_css.size() != 2 || children.size() != 2 ||
        child_fs_seeds.size() != 2 ||
        child_output_column_bases.size() != 2 ||
        child_fs_seeds[0].IsNull() ||
        child_fs_seeds[1].IsNull() ||
        child_fs_seeds[0] == child_fs_seeds[1]) {
        out.note =
            "stage3:coupled_bank_stream:binary:shape_or_seed";
        return out;
    }

    std::vector<Fri3AlgDualTranscriptWitness> transcripts(2);
    out.child_pins.resize(2);
    std::vector<
        air_quotient::AirQuotientProof<
            gf::Fp3,
            air_quotient::AirFriBackendAlg<gf::Fp3>>>
        lane_proofs;
    std::vector<
        air_quotient::AirConstraintSystem<gf::Fp3>>
        lane_css;
    std::vector<uint256> lane_seeds;
    lane_proofs.reserve(4);
    lane_css.reserve(4);
    lane_seeds.reserve(4);

    for (uint32_t child = 0; child < 2; ++child) {
        std::string why;
        if (!air_quotient::AirQuotientVerify<
                gf::Fp3, air_recurse::DualAlgB3>(
                child_css[child], children[child],
                child_fs_seeds[child], &why)) {
            out.note =
                "stage3:coupled_bank_stream:binary:child:" +
                why;
            return out;
        }
        transcripts[child] =
            BuildFri3AlgDualTranscriptWitness(
                children[child].batch.repeated,
                child_fs_seeds[child]);
        if (!transcripts[child].valid ||
            !transcripts[child].common_statement_bound ||
            !transcripts[child].ordered_lanes_bound) {
            out.note =
                "stage3:coupled_bank_stream:binary:transcript:" +
                transcripts[child].note;
            return out;
        }
        auto& pin = out.child_pins[child];
        pin.air_proof_commitment =
            air_recurse::ComputeDualV5AirProofCommitment(
                children[child]);
        pin.transcript_commitment =
            air_recurse::ComputeDualV5TranscriptCommitment(
                transcripts[child]);
        pin.master_statement_binding =
            children[child].batch.repeated
                .master_statement_binding;
        pin.lane_child_binding =
            children[child].batch.repeated
                .lane_child_binding;
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            pin.lane_row_root[lane] =
                Fri3AlgDigestToUint256(
                    children[child].batch.repeated
                        .lane[lane].row_commit.root);
            air_quotient::AirQuotientProof<
                gf::Fp3,
                air_quotient::AirFriBackendAlg<gf::Fp3>>
                view;
            view.batch =
                children[child].batch.repeated.lane[lane];
            view.trace_commit = children[child].trace_commit;
            const size_t begin =
                static_cast<size_t>(lane) *
                kRCFri3AlgDualQueriesPerLane;
            const size_t end =
                begin + kRCFri3AlgDualQueriesPerLane;
            if (end > children[child].next_openings.size()) {
                out.note =
                    "stage3:coupled_bank_stream:binary:lane_openings";
                return out;
            }
            view.next_openings.insert(
                view.next_openings.end(),
                children[child].next_openings.begin() + begin,
                children[child].next_openings.begin() + end);
            lane_proofs.push_back(std::move(view));
            lane_css.push_back(child_css[child]);
            lane_seeds.push_back(child_fs_seeds[child]);
        }
        pin.host_reports_native_air_accepted = true;
        pin.host_reports_exact_transcript_replayed = true;
        pin.host_reports_ordered_lane_binding_checked = true;
    }

    const air_recurse::VerifierAirFamilies families{};
    auto normalized =
        air_recurse::BuildAggregateWitnessHeterogeneous(
            lane_css, lane_proofs, lane_seeds, families);
    if (!normalized.ok ||
        normalized.pis.size() != 4) {
        out.note =
            "stage3:coupled_bank_stream:binary:normalized:" +
            normalized.note;
        return out;
    }
    for (uint32_t logical = 0; logical < 2; ++logical) {
        for (uint32_t lane = 0;
             lane < kRCFri3AlgDualNumLanes; ++lane) {
            auto& pi = normalized.pis[
                logical * kRCFri3AlgDualNumLanes + lane];
            const auto& coefficients =
                transcripts[logical].lane[lane]
                    .batch_coefficients;
            if (coefficients.size() != pi.child_w + 1) {
                out.note =
                    "stage3:coupled_bank_stream:binary:coefficients";
                return out;
            }
            pi.fri_batch_coefficients = coefficients;
            pi.independent_fri_batching = true;
        }
    }
    normalized.cs =
        air_recurse::BuildVerifierAIRPinned(
            4, normalized.pis, families);
    if (normalized.columns.size() !=
        normalized.cs.n_columns) {
        out.note =
            "stage3:coupled_bank_stream:binary:column_rebuild";
        return out;
    }
    for (const auto& [column, values] :
         normalized.cs.preprocessed) {
        normalized.columns[column] = values;
    }

    const auto outputs =
        air_recurse::DescribeVerifierAIRFullTranscriptOutputs(
            normalized.pis, families);
    auto find_output =
        [&](uint32_t lane_child, uint32_t item,
            uint32_t coordinate,
            air_recurse::VerifierAirTranscriptOutput& found) {
            for (const auto& output : outputs) {
                if (output.kind ==
                        air_recurse::
                            VerifierAirTranscriptOutputKind::
                                EvaluationZ1 &&
                    output.child_index == lane_child &&
                    output.item_index == item &&
                    output.coordinate == coordinate) {
                    found = output;
                    return true;
                }
            }
            return false;
        };

    std::array<std::array<uint32_t, 18>, 2> child_words{};
    std::array<
        std::array<
            air_recurse::VerifierAirTranscriptOutput, 18>,
        4> lane_sources{};
    for (uint32_t logical = 0; logical < 2; ++logical) {
        for (uint32_t word = 0; word < 18; ++word) {
            const uint32_t item =
                child_output_column_bases[logical] + word;
            for (uint32_t lane = 0;
                 lane < kRCFri3AlgDualNumLanes; ++lane) {
                const uint32_t lane_child =
                    logical * kRCFri3AlgDualNumLanes + lane;
                const auto& pi =
                    normalized.pis[lane_child];
                if (item >= pi.evals_z1.size() ||
                    item >= pi.evals_z2.size() ||
                    !gf::Eq(
                        pi.evals_z1[item],
                        pi.evals_z2[item]) ||
                    gf::Canonical(
                        pi.evals_z1[item].c1) != 0 ||
                    gf::Canonical(
                        pi.evals_z1[item].c2) != 0 ||
                    !find_output(
                        lane_child, item, 0,
                        lane_sources[lane_child][word])) {
                    out.note =
                        "stage3:coupled_bank_stream:binary:output";
                    return out;
                }
                const uint64_t value =
                    gf::Canonical(
                        pi.evals_z1[item].c0);
                if (value >
                    std::numeric_limits<uint32_t>::max()) {
                    out.note =
                        "stage3:coupled_bank_stream:binary:output_range";
                    return out;
                }
                if (lane == 0) {
                    child_words[logical][word] =
                        static_cast<uint32_t>(value);
                } else if (
                    child_words[logical][word] != value) {
                    out.note =
                        "stage3:coupled_bank_stream:binary:lane_output";
                    return out;
                }
            }
        }
    }
    if (uint64_t{child_words[0][0]} +
            child_words[0][1] !=
            child_words[1][0]) {
        out.note =
            "stage3:coupled_bank_stream:binary:not_contiguous";
        return out;
    }
    for (uint32_t word = 0; word < 8; ++word) {
        if (child_words[0][10 + word] !=
            child_words[1][2 + word]) {
            out.note =
                "stage3:coupled_bank_stream:binary:sha_chain";
            return out;
        }
    }
    out.parent_output_words[0] = child_words[0][0];
    out.parent_output_words[1] =
        child_words[0][1] + child_words[1][1];
    for (uint32_t word = 0; word < 8; ++word) {
        out.parent_output_words[2 + word] =
            child_words[0][2 + word];
        out.parent_output_words[10 + word] =
            child_words[1][10 + word];
    }

    out.parent_cs = std::move(normalized.cs);
    out.parent_columns = std::move(normalized.columns);
    out.parent_output_column_base =
        out.parent_cs.n_columns;
    out.parent_cs.n_columns += 18;
    for (uint32_t word = 0; word < 18; ++word) {
        const uint32_t column =
            out.parent_output_column_base + word;
        std::vector<gf::Fp3> values(
            out.parent_cs.n_rows,
            Fp3FromU64(out.parent_output_words[word]));
        out.parent_cs.preprocessed.emplace_back(
            column, values);
        out.parent_columns.push_back(std::move(values));
    }
    auto add_relation =
        [&](const char* name,
            std::function<gf::Fp3(
                const std::vector<gf::Fp3>&)> residual,
            uint32_t degree = 1) {
            AddIntervalConstraint(
                out.parent_cs, name,
                air_quotient::AirKind::kEverywhere,
                degree,
                [residual = std::move(residual)](
                    const std::vector<gf::Fp3>& cur,
                    const std::vector<gf::Fp3>&) {
                    return residual(cur);
                });
        };
    for (uint32_t logical = 0; logical < 2; ++logical) {
        for (uint32_t word = 0; word < 18; ++word) {
            const auto left =
                lane_sources[2 * logical][word];
            const auto right =
                lane_sources[2 * logical + 1][word];
            add_relation(
                "stage3.bank_binary.lane_output_equality",
                [left, right](
                    const std::vector<gf::Fp3>& cur) {
                    return gf::Sub(
                        air_recurse::
                            EvaluateVerifierAIRTranscriptOutput(
                                left, cur),
                        air_recurse::
                            EvaluateVerifierAIRTranscriptOutput(
                                right, cur));
                });
        }
    }
    const auto source =
        [&](uint32_t logical, uint32_t word,
            const std::vector<gf::Fp3>& cur) {
            return air_recurse::
                EvaluateVerifierAIRTranscriptOutput(
                    lane_sources[2 * logical][word], cur);
        };
    add_relation(
        "stage3.bank_binary.parent_first",
        [base = out.parent_output_column_base, source](
            const std::vector<gf::Fp3>& cur) {
            return gf::Sub(cur[base], source(0, 0, cur));
        });
    add_relation(
        "stage3.bank_binary.parent_count",
        [base = out.parent_output_column_base, source](
            const std::vector<gf::Fp3>& cur) {
            return gf::Sub(
                cur[base + 1],
                gf::Add(
                    source(0, 1, cur),
                    source(1, 1, cur)));
        });
    add_relation(
        "stage3.bank_binary.contiguous",
        [source](const std::vector<gf::Fp3>& cur) {
            return gf::Sub(
                source(1, 0, cur),
                gf::Add(
                    source(0, 0, cur),
                    source(0, 1, cur)));
        });
    for (uint32_t word = 0; word < 8; ++word) {
        add_relation(
            "stage3.bank_binary.parent_h_in",
            [base = out.parent_output_column_base,
             source, word](
                const std::vector<gf::Fp3>& cur) {
                return gf::Sub(
                    cur[base + 2 + word],
                    source(0, 2 + word, cur));
            });
        add_relation(
            "stage3.bank_binary.sha_chain",
            [source, word](
                const std::vector<gf::Fp3>& cur) {
                return gf::Sub(
                    source(1, 2 + word, cur),
                    source(0, 10 + word, cur));
            });
        add_relation(
            "stage3.bank_binary.parent_h_out",
            [base = out.parent_output_column_base,
             source, word](
                const std::vector<gf::Fp3>& cur) {
                return gf::Sub(
                    cur[base + 10 + word],
                    source(1, 10 + word, cur));
            });
    }

    out.lane_public_inputs =
        std::move(normalized.pis);
    out.violations =
        air_recurse::CountWitnessViolationsOnH(
            out.parent_cs, out.parent_columns);
    out.independent_child_seeds = true;
    out.both_children_executed = true;
    out.all_vcs_families_enabled = true;
    out.lane_output_equality_same_trace = true;
    out.bank_interval_join_same_trace = true;
    out.under_column_cap =
        out.parent_cs.n_columns <=
            kRCFri3AlgBatchMaxColumns;
    out.parent_proof_emitted = false;
    out.valid =
        out.violations == 0 && out.under_column_cap;
    out.note = out.valid
        ? "full binary mirror and bank interval join execute; "
          "parent proof emission remains open"
        : "full binary mirror failed: columns=" +
              std::to_string(out.parent_cs.n_columns) +
              " cap=" +
              std::to_string(kRCFri3AlgBatchMaxColumns) +
              " violations=" +
              std::to_string(out.violations);
    return out;
}

uint256 CommitRCStage3CoupledBankStreamRecursiveProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& proof)
{
    if (manifest.commitment.IsNull() ||
        proof.version != kRCStage3CoupledBankStreamVersion ||
        proof.receipt.commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << RECURSIVE_PROOF_DOMAIN;
    hash << proof.version;
    hash << manifest.commitment;
    hash << proof.receipt.commitment;
    hash << proof.receipt.level;
    if (proof.receipt.level == 0) {
        if (!proof.children.empty() ||
            proof.leaf.leaf_commitment.IsNull()) {
            return {};
        }
        hash << uint8_t{0};
        hash << proof.leaf.leaf_commitment;
    } else {
        if (proof.children.empty() ||
            proof.children.size() >
                kRCStage3CoupledBankStreamArity ||
            !proof.leaf.leaf_commitment.IsNull()) {
            return {};
        }
        const uint256 air_commitment =
            CommitIntervalAirProof(
                proof.interval_relation_proof);
        if (air_commitment.IsNull()) return {};
        hash << uint8_t{1};
        hash << static_cast<uint32_t>(proof.children.size());
        for (const auto& child : proof.children) {
            if (child.recursive_commitment.IsNull()) return {};
            hash << child.recursive_commitment;
        }
        hash << air_commitment;
    }
    return hash.GetHash();
}

bool BuildRCStage3CoupledBankStreamRecursiveLeafProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& verified_leaf,
    RCStage3CoupledBankStreamRecursiveProof& out,
    std::string* why)
{
    out = {};
    if (!BuildRCStage3CoupledBankStreamLeafReceipt(
            manifest, verified_leaf, out.receipt, why)) {
        return false;
    }
    out.leaf = verified_leaf;
    out.recursive_commitment =
        CommitRCStage3CoupledBankStreamRecursiveProof(
            manifest, out);
    if (out.recursive_commitment.IsNull()) {
        out = {};
        return Fail(why, "recursive_leaf:commitment");
    }
    return true;
}

namespace {

bool VerifyRecursiveBankProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& proof,
    uint32_t depth,
    uint64_t& visited,
    std::string* why)
{
    if (depth > manifest.aggregation_levels ||
        visited == std::numeric_limits<uint64_t>::max()) {
        return Fail(why, "recursive:depth_or_count");
    }
    ++visited;
    if (proof.version !=
        kRCStage3CoupledBankStreamVersion) {
        return Fail(why, "recursive:version");
    }
    if (proof.receipt.level == 0) {
        if (!proof.children.empty()) {
            return Fail(why, "recursive:leaf_children");
        }
        RCStage3CoupledBankStreamIntervalReceipt expected;
        if (!BuildRCStage3CoupledBankStreamLeafReceipt(
                manifest, proof.leaf, expected, why) ||
            !(proof.receipt == expected)) {
            return Fail(why, "recursive:leaf_relation");
        }
    } else {
        if (proof.children.empty() ||
            proof.children.size() >
                kRCStage3CoupledBankStreamArity ||
            !proof.leaf.leaf_commitment.IsNull()) {
            return Fail(why, "recursive:parent_shape");
        }
        std::vector<RCStage3CoupledBankStreamIntervalReceipt>
            child_receipts;
        child_receipts.reserve(proof.children.size());
        for (const auto& child : proof.children) {
            if (child.receipt.level + 1 !=
                    proof.receipt.level ||
                !VerifyRecursiveBankProof(
                    manifest, child, depth + 1,
                    visited, why)) {
                return Fail(why, "recursive:child");
            }
            child_receipts.push_back(child.receipt);
        }
        if (!VerifyRCStage3CoupledBankStreamIntervalRelation(
                manifest, child_receipts, proof.receipt,
                proof.interval_relation_proof, why)) {
            return Fail(why, "recursive:interval_relation");
        }
    }
    const uint256 commitment =
        CommitRCStage3CoupledBankStreamRecursiveProof(
            manifest, proof);
    if (commitment.IsNull() ||
        proof.recursive_commitment != commitment) {
        return Fail(why, "recursive:commitment");
    }
    return true;
}

} // namespace

bool BuildRCStage3CoupledBankStreamRecursiveParentProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamRecursiveProof>&
        children,
    RCStage3CoupledBankStreamRecursiveProof& out,
    std::string* why)
{
    out = {};
    if (children.empty() ||
        children.size() >
            kRCStage3CoupledBankStreamArity) {
        return Fail(why, "recursive_parent:children");
    }
    uint64_t visited = 0;
    std::vector<RCStage3CoupledBankStreamIntervalReceipt>
        child_receipts;
    child_receipts.reserve(children.size());
    for (const auto& child : children) {
        if (!VerifyRecursiveBankProof(
                manifest, child, 0, visited, why)) {
            return Fail(why, "recursive_parent:invalid_child");
        }
        child_receipts.push_back(child.receipt);
    }
    if (!BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, child_receipts, out.receipt, why) ||
        !ProveRCStage3CoupledBankStreamIntervalRelation(
            manifest, child_receipts, out.receipt,
            out.interval_relation_proof, why)) {
        out = {};
        return false;
    }
    out.children = children;
    out.recursive_commitment =
        CommitRCStage3CoupledBankStreamRecursiveProof(
            manifest, out);
    if (out.recursive_commitment.IsNull()) {
        out = {};
        return Fail(why, "recursive_parent:commitment");
    }
    return true;
}

bool VerifyRCStage3CoupledBankStreamRecursiveProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& proof,
    std::string* why)
{
    uint64_t visited = 0;
    return VerifyRecursiveBankProof(
        manifest, proof, 0, visited, why);
}

bool VerifyRCStage3CoupledBankStreamRecursiveRoot(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& root,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankStreamRecursiveProof(
            manifest, root, why) ||
        !ValidateRCStage3CoupledBankStreamRootReceipt(
            manifest, root.receipt, why)) {
        return Fail(why, "recursive_root");
    }
    return true;
}

RCStage3CoupledBankNormalizedVerifierStep
BuildRCStage3CoupledBankNormalizedVerifierStep(
    const air_quotient::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<air_recurse::DualAlgAirProof>& children,
    const uint256& child_fs_seed,
    const uint256& parent_fs_seed,
    const air_recurse::VerifierAirFamilies& families)
{
    RCStage3CoupledBankNormalizedVerifierStep out;
    out.logical_children =
        static_cast<uint32_t>(children.size());
    out.child_fs_seed = child_fs_seed;
    out.parent_fs_seed = parent_fs_seed;
    if (children.empty() ||
        children.size() >
            kRCStage3CoupledBankStreamArity ||
        child_fs_seed.IsNull() ||
        parent_fs_seed.IsNull()) {
        out.note =
            "stage3:coupled_bank_stream:normalized:shape";
        return out;
    }
    const auto result =
        air_recurse::ProveAggregateDualV5Checked(
            child_cs, children, child_fs_seed,
            parent_fs_seed, families);
    if (!result.ok || !result.witness_satisfies) {
        out.note =
            "stage3:coupled_bank_stream:normalized:prove:" +
            result.note;
        return out;
    }
    out.effective_fs_seed = result.effective_fs_seed;
    out.child_statement_commitment =
        result.child_statement_commitment;
    out.families = families;
    out.normalized_parent = result.proof;
    out.lane_public_inputs = result.lane_pis;
    out.child_pins = result.child_pins;
    out.normalized_parent_proof_commitment =
        air_recurse::ComputeDualV5AirProofCommitment(
            out.normalized_parent);
    out.rows = result.measurement.n_rows;
    out.columns = result.measurement.n_columns;
    out.constraints = result.measurement.n_constraints;
    out.prove_micros = result.root_prove_micros;
    out.descendant_free = true;
    out.all_available_algebraic_families =
        result.all_vcs_families_enabled;
    out.complete_child_proof_commitments =
        !out.normalized_parent_proof_commitment.IsNull() &&
        std::all_of(
            out.child_pins.begin(), out.child_pins.end(),
            [](const auto& pin) {
                return !pin.air_proof_commitment.IsNull() &&
                    !pin.transcript_commitment.IsNull();
            });
    out.fiat_shamir_replayed_on_host =
        std::all_of(
            out.child_pins.begin(), out.child_pins.end(),
            [](const auto& pin) {
                return pin.host_reports_exact_transcript_replayed &&
                    pin.host_reports_ordered_lane_binding_checked;
            });
    out.fiat_shamir_equations_in_air =
        air_recurse::kDualV5FiatShamirEquationsInAir;
    out.bank_interval_relation_same_trace = false;
    out.commitment = NormalizedStepCommitment(out);
    if (out.commitment.IsNull()) {
        out.note =
            "stage3:coupled_bank_stream:normalized:commitment";
        return out;
    }
    out.valid = true;
    std::string why;
    if (!VerifyRCStage3CoupledBankNormalizedVerifierStep(
            out, &why)) {
        out.valid = false;
        out.note =
            "stage3:coupled_bank_stream:normalized:self_verify:" +
            why;
        return out;
    }
    out.note =
        out.all_available_algebraic_families
            ? "descendant-free normalized V5 algebraic verifier; "
              "SHA Fiat-Shamir and bank interval same-trace links open"
            : "descendant-free bounded normalized verifier; selected "
              "algebraic families are incomplete";
    return out;
}

bool VerifyRCStage3CoupledBankNormalizedVerifierStep(
    const RCStage3CoupledBankNormalizedVerifierStep& step,
    std::string* why)
{
    if (!step.valid ||
        !step.descendant_free ||
        !step.complete_child_proof_commitments ||
        step.fiat_shamir_equations_in_air ||
        step.bank_interval_relation_same_trace ||
        step.normalized_parent_proof_commitment !=
            air_recurse::ComputeDualV5AirProofCommitment(
                step.normalized_parent) ||
        step.commitment.IsNull() ||
        step.commitment != NormalizedStepCommitment(step)) {
        return Fail(why, "normalized:binding");
    }
    if (!air_recurse::VerifyAggregateDualV5Diagnostic(
            step.normalized_parent,
            step.lane_public_inputs,
            step.child_pins,
            step.parent_fs_seed,
            step.families, why)) {
        return Fail(why, "normalized:parent");
    }
    return true;
}

air_quotient::AirConstraintSystem<gf::Fp3>
BuildRCStage3CoupledBankNormalizedOutputConstraintSystem(
    const RCStage3CoupledBankNormalizedVerifierStep& step)
{
    if (!step.valid ||
        step.logical_children == 0 ||
        step.lane_public_inputs.size() !=
            step.logical_children *
                kRCFri3AlgDualNumLanes) {
        return {};
    }
    return air_recurse::BuildVerifierAIRPinned(
        static_cast<uint32_t>(
            step.lane_public_inputs.size()),
        step.lane_public_inputs, step.families);
}

uint256 ComputeRCStage3CoupledBankStreamSecondPassSeed(
    const RCStage3CoupledBankStreamManifest& manifest,
    const uint256& root_receipt_commitment)
{
    if (manifest.commitment.IsNull() ||
        root_receipt_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << SECOND_SEED_DOMAIN;
    hash << kRCStage3CoupledBankStreamVersion;
    hash << manifest.commitment;
    hash << root_receipt_commitment;
    return hash.GetHash();
}

bool VerifyRCStage3CoupledBankStreamSecondPass(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& root,
    const RCStage3CoupledBankStreamSecondPassProof& second,
    std::string* why)
{
    if (!ValidateRCStage3CoupledBankStreamRootReceipt(
            manifest, root, why) ||
        second.version != kRCStage3CoupledBankStreamVersion ||
        second.first_pass_terminal != root.last_h_out ||
        second.bank_root.IsNull() ||
        second.bank_root !=
            DigestWords(second.second_pass_output)) {
        return Fail(why, "second:binding");
    }
    const std::array<uint8_t, 64> block =
        SecondPassBlock(second.first_pass_terminal);
    ha::FixedProgramBoundaryInstance boundary;
    if (!ha::BuildSha256CompressionBoundaryInstance(
            block, ha::CanonicalSha256InitialState(),
            second.second_pass_output, boundary, why)) {
        return Fail(why, "second:boundary");
    }
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    const uint256 seed =
        ComputeRCStage3CoupledBankStreamSecondPassSeed(
            manifest, root.commitment);
    if (seed.IsNull() ||
        !ha::VerifyFixedProgramProvenanceAir(
            program, boundary.external_values,
            boundary.final_words, seed,
            second.compression_proof, why)) {
        return Fail(why, "second:proof");
    }
    return true;
}

bool VerifyRCStage3CoupledBankStreamRecursiveRootAndSecondPass(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& root,
    const RCStage3CoupledBankStreamSecondPassProof& second,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankStreamRecursiveRoot(
            manifest, root, why) ||
        !VerifyRCStage3CoupledBankStreamSecondPass(
            manifest, root.receipt, second, why)) {
        return Fail(why, "recursive_root_and_second");
    }
    return true;
}

RCStage3CoupledBankStreamAudit
CurrentRCStage3CoupledBankStreamAudit()
{
    RCStage3CoupledBankStreamAudit out;
    out.production_counts_manifest_derived = true;
    out.source_chunk_openings_executable = true;
    out.byte_to_sha_word_projection_executable = true;
    out.fixed_program_leaf_proof_executable = true;
    out.exact_chaining_aggregation_schedule_executable = true;
    out.interval_relation_air_executable = true;
    out.recursive_child_tree_verifier_executable = true;
    out.second_pass_and_bank_root_executable = true;
    out.recursive_interval_proof_executable = true;
    out.normalized_descendant_free_step_executable = true;
    out.normalized_two_level_execution_tested = true;
    out.normalized_full_four_child_families_executable = false;
    out.normalized_full_binary_mirror_executable = false;
    out.normalized_binary_interval_same_trace = true;
    out.normalized_full_binary_parent_proof_executable = false;
    out.succinct_fixed_point_executable = false;
    out.strict_semantic_complete = false;
    out.remaining =
        "the executable recursive V1 carries its full child tree and is not "
        "succinct; the bounded descendant-free proof step and full binary "
        "bank-join witness are not one emitted and verified artifact; the "
        "70,974-column two-child mirror now fits the backend cap, but proof "
        "emission/verification, artifact integration, resource/performance "
        "and equivalence evidence remain open; SHA Fiat-Shamir/master-binding "
        "equations and full semantic closure remain outside AIR; "
        "CoupledBankPages must export the identical bank_page_byte_root";
    return out;
}

RCStage3CoupledBankStreamCostEstimate
EstimateRCStage3CoupledBankStreamRecursiveCost(
    const RCStage3CoupledBankStreamManifest& manifest,
    uint64_t measured_leaf_verify_micros,
    uint64_t measured_parent_verify_micros)
{
    RCStage3CoupledBankStreamCostEstimate out;
    out.leaf_proofs = manifest.first_pass_blocks;
    out.parent_proofs = manifest.aggregation_parent_sites;
    out.tree_depth = manifest.aggregation_levels;
    if (out.parent_proofs >
        std::numeric_limits<uint64_t>::max() -
            out.leaf_proofs) {
        return {};
    }
    out.total_proofs =
        out.leaf_proofs + out.parent_proofs;
    out.expanded_verify_seconds =
        (static_cast<long double>(out.leaf_proofs) *
             measured_leaf_verify_micros +
         static_cast<long double>(out.parent_proofs) *
             measured_parent_verify_micros) /
        1000000.0L;
    out.succinct = false;
    return out;
}

static_assert(kRCStage3CoupledBankStreamingScheduleExecutable);
static_assert(kRCStage3CoupledBankStreamingLeafVerifierExecutable);
static_assert(
    kRCStage3CoupledBankStreamingStructuralAggregationExecutable);
static_assert(
    kRCStage3CoupledBankStreamingRecursiveTreeVerifierExecutable);
static_assert(
    !kRCStage3CoupledBankStreamingSuccinctFixedPointExecutable);
static_assert(
    !kRCStage3CoupledBankStreamingRecursiveAuthorityReady);

} // namespace matmul::v4::rc
