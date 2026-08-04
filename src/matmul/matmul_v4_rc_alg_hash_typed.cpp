// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_alg_hash_typed.h>

#include <algorithm>

namespace matmul::v4::rc::alg_hash_typed {
namespace {

using gf::Add;
using gf::Canonical;
using gf::Fp;
using gf::Fp3;

constexpr std::array<RoleV12, kRoleCountV12> kRoles{{
    RoleV12::MerkleRowLeaf,
    RoleV12::MerkleFoldLeaf,
    RoleV12::MerkleInternalNode,
    RoleV12::TranscriptShapeCommit,
    RoleV12::TranscriptAirLambda,
    RoleV12::TranscriptFriSeed,
    RoleV12::TranscriptOodZ1,
    RoleV12::TranscriptOodZ2,
    RoleV12::TranscriptOodEvaluations,
    RoleV12::TranscriptBatchSeed,
    RoleV12::TranscriptBatchCoefficient,
    RoleV12::TranscriptDeepWeight,
    RoleV12::TranscriptFoldState,
    RoleV12::TranscriptFoldBeta,
    RoleV12::TranscriptQuerySeed,
    RoleV12::TranscriptQueryCandidate,
    RoleV12::TranscriptPadding,
    RoleV12::ReceiptCommitment,
    RoleV12::ProgramTableCommitment,
    RoleV12::ApplicationStatementCommitment,
}};

void SetError(std::string* why, const char* text)
{
    if (why != nullptr) *why = text;
}

ah::Digest DigestOf(const ah::State& state)
{
    return {state[0], state[1], state[2], state[3]};
}

} // namespace

static_assert(kCapacityMagicV1 < gf::kP,
              "typed-hash capacity magic must be canonical");
static_assert(ah::kAlgHashRate + ah::kAlgHashCapacity == ah::kAlgHashT);

const std::array<RoleV12, kRoleCountV12>& AllRolesV12()
{
    return kRoles;
}

bool IsKnownRoleV12(RoleV12 role)
{
    return std::find(kRoles.begin(), kRoles.end(), role) != kRoles.end();
}

bool IsVariableSpongeRoleV12(RoleV12 role)
{
    return IsKnownRoleV12(role) &&
        role != RoleV12::MerkleFoldLeaf &&
        role != RoleV12::MerkleInternalNode;
}

bool CapacityIvForRoleV12(
    RoleV12 role, CapacityIvV12& iv, std::string* why)
{
    iv = {};
    if (!IsKnownRoleV12(role)) {
        SetError(why, "typed hash unknown role");
        return false;
    }
    iv = {
        kCapacityMagicV1,
        gf::FromU64(static_cast<uint32_t>(role)),
        gf::FromU64(kProtocolVersionV12),
        gf::FromU64(kTypedHashVersionV1),
    };
    return true;
}

bool InitializeStateV12(
    RoleV12 role, ah::State& state, std::string* why)
{
    CapacityIvV12 iv{};
    if (!CapacityIvForRoleV12(role, iv, why)) return false;
    state = {};
    std::copy(iv.begin(), iv.end(),
              state.begin() + ah::kAlgHashRate);
    return true;
}

bool SpongeHashFpV12(
    RoleV12 role, const std::vector<Fp>& lanes,
    ah::Digest& digest, std::string* why)
{
    digest = {};
    if (!IsVariableSpongeRoleV12(role)) {
        SetError(why, IsKnownRoleV12(role)
            ? "typed hash role requires fixed-width encoding"
            : "typed hash unknown role");
        return false;
    }

    std::vector<Fp> padded;
    padded.reserve(lanes.size() + ah::kAlgHashRate);
    for (Fp lane : lanes) padded.push_back(Canonical(lane));
    padded.push_back(gf::FromU64(1));
    while (padded.size() % ah::kAlgHashRate != 0) {
        padded.push_back(gf::FromU64(0));
    }

    ah::State state{};
    if (!InitializeStateV12(role, state, why)) return false;
    for (size_t offset = 0; offset < padded.size();
         offset += ah::kAlgHashRate) {
        for (uint32_t lane = 0; lane < ah::kAlgHashRate; ++lane) {
            state[lane] = Add(state[lane], padded[offset + lane]);
        }
        ah::Permute(state);
    }
    digest = DigestOf(state);
    return true;
}

ah::Digest RowLeafV12(
    const std::vector<Fp3>& row, uint32_t index)
{
    std::vector<Fp> lanes;
    lanes.reserve(3 * row.size() + 1);
    for (const Fp3& value : row) {
        lanes.push_back(Canonical(value.c0));
        lanes.push_back(Canonical(value.c1));
        lanes.push_back(Canonical(value.c2));
    }
    lanes.push_back(gf::FromU64(index));
    ah::Digest digest{};
    const bool ok =
        SpongeHashFpV12(RoleV12::MerkleRowLeaf, lanes, digest);
    (void)ok;
    return digest;
}

ah::Digest FoldLeafV12(
    const Fp3& value, uint32_t index)
{
    ah::State state{};
    const bool ok =
        InitializeStateV12(RoleV12::MerkleFoldLeaf, state);
    (void)ok;
    state[0] = Canonical(value.c0);
    state[1] = Canonical(value.c1);
    state[2] = Canonical(value.c2);
    state[3] = gf::FromU64(index);
    ah::Permute(state);
    return DigestOf(state);
}

ah::Digest CompressV12(
    const ah::Digest& left, const ah::Digest& right)
{
    ah::State state{};
    const bool ok =
        InitializeStateV12(RoleV12::MerkleInternalNode, state);
    (void)ok;
    for (uint32_t lane = 0; lane < ah::kAlgHashDigestLen; ++lane) {
        state[lane] = Canonical(left[lane]);
        state[ah::kAlgHashDigestLen + lane] =
            Canonical(right[lane]);
    }
    ah::Permute(state);
    return DigestOf(state);
}

StreamingRowHasherV12::StreamingRowHasherV12(uint32_t n_rows)
    : m_rows(n_rows)
{
    CapacityIvV12 iv{};
    const bool ok =
        CapacityIvForRoleV12(RoleV12::MerkleRowLeaf, iv);
    (void)ok;
    for (RowState& row : m_rows) {
        std::copy(iv.begin(), iv.end(),
                  row.sponge.begin() + ah::kAlgHashRate);
    }
}

void StreamingRowHasherV12::AbsorbLane(
    RowState& row, Fp value)
{
    row.pending[row.pending_count++] = Canonical(value);
    if (row.pending_count != ah::kAlgHashRate) return;
    for (uint32_t lane = 0; lane < ah::kAlgHashRate; ++lane) {
        row.sponge[lane] =
            Add(row.sponge[lane], row.pending[lane]);
        row.pending[lane] = 0;
    }
    ah::Permute(row.sponge);
    row.pending_count = 0;
}

bool StreamingRowHasherV12::AbsorbColumn(
    const std::vector<Fp3>& column, std::string* why)
{
    if (m_finalized) {
        SetError(why, "typed streaming row hasher finalized");
        return false;
    }
    if (column.size() != m_rows.size()) {
        SetError(why, "typed streaming row hasher column height");
        return false;
    }
    for (size_t row = 0; row < m_rows.size(); ++row) {
        AbsorbLane(m_rows[row], column[row].c0);
        AbsorbLane(m_rows[row], column[row].c1);
        AbsorbLane(m_rows[row], column[row].c2);
    }
    ++m_columns;
    return true;
}

bool StreamingRowHasherV12::AbsorbColumnBlock(
    const std::vector<std::vector<Fp3>>& block,
    size_t count, std::string* why)
{
    if (m_finalized) {
        SetError(why, "typed streaming row hasher finalized");
        return false;
    }
    if (count > block.size()) {
        SetError(why, "typed streaming row hasher block count");
        return false;
    }
    for (size_t column = 0; column < count; ++column) {
        if (block[column].size() != m_rows.size()) {
            SetError(why, "typed streaming row hasher column height");
            return false;
        }
    }
    for (size_t row = 0; row < m_rows.size(); ++row) {
        for (size_t column = 0; column < count; ++column) {
            const Fp3& value = block[column][row];
            AbsorbLane(m_rows[row], value.c0);
            AbsorbLane(m_rows[row], value.c1);
            AbsorbLane(m_rows[row], value.c2);
        }
    }
    m_columns += static_cast<uint32_t>(count);
    return true;
}

bool StreamingRowHasherV12::Finalize(
    std::vector<ah::Digest>& digests, std::string* why)
{
    digests.clear();
    if (m_finalized || m_rows.empty() || m_columns == 0) {
        SetError(why, "typed streaming row hasher finalization state");
        return false;
    }
    digests.resize(m_rows.size());
    for (uint32_t index = 0; index < m_rows.size(); ++index) {
        RowState& row = m_rows[index];
        AbsorbLane(row, gf::FromU64(index));
        AbsorbLane(row, gf::FromU64(1));
        while (row.pending_count != 0) {
            AbsorbLane(row, gf::FromU64(0));
        }
        digests[index] = DigestOf(row.sponge);
    }
    m_finalized = true;
    return true;
}

uint32_t StreamingRowHasherV12::Rows() const
{
    return static_cast<uint32_t>(m_rows.size());
}

uint32_t StreamingRowHasherV12::Columns() const
{
    return m_columns;
}

uint64_t StreamingRowHasherV12::WorkingSetBytes() const
{
    return static_cast<uint64_t>(m_rows.capacity()) *
        sizeof(RowState);
}

uint64_t StreamingRowHasherV12::WorkingSetBytesForRows(
    uint32_t n_rows)
{
    return static_cast<uint64_t>(n_rows) * sizeof(RowState);
}

} // namespace matmul::v4::rc::alg_hash_typed
