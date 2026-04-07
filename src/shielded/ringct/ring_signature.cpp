// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/ring_signature.h>

#include <crypto/timing_safe.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/sampling.h>
#include <streams.h>
#include <support/cleanse.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace shielded::ringct {
namespace {

using ChallengeType = lattice::Poly256;

struct DerivedRingMember {
    lattice::PolyVec public_key;
    lattice::Poly256 link_generator;
    lattice::Poly256 link_generator_ntt;
};

struct ChallengeContext {
    DataStream prefix;
    DataStream suffix;
};

using TranscriptChunks = std::vector<std::vector<DataStream>>;

static constexpr int32_t RESPONSE_SERIALIZATION_BOUND{(1 << 23) - 1};
// Masking bound: alpha sampled uniformly from [-MASKING_BOUND, MASKING_BOUND].
// Must equal GAMMA_RESPONSE so the acceptance region masks the c*s shift.
static constexpr int32_t MASKING_BOUND{lattice::GAMMA_RESPONSE};
// Acceptance bound: accept z iff ||z||_inf <= gamma - beta*eta (Lyubashevsky).
static constexpr int32_t RESPONSE_NORM_BOUND{
    lattice::GAMMA_RESPONSE - lattice::BETA_CHALLENGE * lattice::SECRET_SMALL_ETA};
static constexpr int MAX_REJECTION_ATTEMPTS{512};
static_assert(MASKING_BOUND <= RESPONSE_SERIALIZATION_BOUND,
              "Signed24 serialization must accommodate MASKING_BOUND");
static_assert(RESPONSE_NORM_BOUND > 0, "RESPONSE_NORM_BOUND must be positive");
static_assert(RESPONSE_NORM_BOUND < MASKING_BOUND,
              "acceptance bound must be strictly less than masking bound for rejection sampling");
static_assert(lattice::SECRET_SMALL_ETA * lattice::BETA_CHALLENGE < RESPONSE_NORM_BOUND,
              "secret/challenge bounds must permit bounded real responses");
// R7-106 (F6): PolyVecAddCentered overflow safety — the sum of a masking
// vector (inf-norm <= MASKING_BOUND) and a centered polynomial product
// (inf-norm < POLY_Q/2 after Reduce()) must fit int32_t.
static_assert(static_cast<int64_t>(MASKING_BOUND) + lattice::POLY_Q / 2 <
              static_cast<int64_t>(std::numeric_limits<int32_t>::max()),
              "PolyVecAddCentered: sum of masking bound and q/2 must fit int32_t");

[[nodiscard]] ChallengeType ChallengeFromDigest(const uint256& challenge_digest)
{
    return lattice::SampleChallenge(
        Span<const unsigned char>{challenge_digest.begin(), uint256::size()});
}

[[nodiscard]] lattice::Poly256 SampleBoundedPoly(FastRandomContext& rng, int32_t bound)
{
    // NOTE: Uses randrange() deliberately to preserve deterministic RNG progression.
    // The timing of randrange()'s rejection loop depends on the RNG output (ChaCha20),
    // not on any secret value, so no secret-dependent timing leak occurs.
    if (bound <= 0) return lattice::Poly256{};
    // R7-102: Widen to uint64_t before multiply to prevent int32 overflow for large bounds.
    const uint32_t span = static_cast<uint32_t>(static_cast<uint64_t>(bound) * 2 + 1);
    lattice::Poly256 out;
    for (size_t i = 0; i < lattice::POLY_N; ++i) {
        out.coeffs[i] = static_cast<int32_t>(rng.randrange(span)) - bound;
    }
    return out;
}

[[nodiscard]] lattice::PolyVec SampleBoundedVec(FastRandomContext& rng, size_t len, int32_t bound)
{
    lattice::PolyVec out(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = SampleBoundedPoly(rng, bound);
    }
    return out;
}

[[nodiscard]] lattice::PolyVec SampleMaskingVec(FastRandomContext& rng)
{
    return SampleBoundedVec(rng, lattice::MODULE_RANK, MASKING_BOUND);
}

// R6-107 analysis: Simulated responses are uniform over [-RESPONSE_NORM_BOUND,
// RESPONSE_NORM_BOUND].  Real accepted responses z = y + c*s (with y uniform
// in [-MASKING_BOUND, MASKING_BOUND]) are also uniform over this range after
// rejection (since ||c*s||_inf <= beta*eta ensures y = z-c*s stays in
// [-MASKING_BOUND, MASKING_BOUND] whenever ||z||_inf <= RESPONSE_NORM_BOUND).
// Therefore the simulated and real distributions are identical: no ZK gap.
[[nodiscard]] lattice::PolyVec SampleSimulatedResponse(FastRandomContext& rng)
{
    return SampleBoundedVec(rng, lattice::MODULE_RANK, RESPONSE_NORM_BOUND);
}

[[nodiscard]] uint256 ComputeSigningRngSeed(const std::vector<std::vector<uint256>>& ring_members,
                                            const std::vector<size_t>& real_indices,
                                            const std::vector<lattice::PolyVec>& input_secrets,
                                            const uint256& message_hash,
                                            Span<const unsigned char> rng_entropy)
{
    std::vector<uint32_t> real_index_u32;
    real_index_u32.reserve(real_indices.size());
    for (const size_t idx : real_indices) {
        real_index_u32.push_back(static_cast<uint32_t>(idx));
    }

    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_RNGSeed_V2"};
    hw << message_hash;
    hw << ring_members;
    hw << real_index_u32;
    hw << input_secrets;
    const bool has_entropy = !rng_entropy.empty();
    hw << has_entropy;
    if (has_entropy) {
        hw.write(AsBytes(rng_entropy));
    }
    return hw.GetSHA256();
}

[[nodiscard]] uint256 DeriveInputSecretSeedFromNote(Span<const unsigned char> spending_key,
                                                    const ShieldedNote& note)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_SecretFromNote_V1"};
    hw.write(AsBytes(spending_key));
    hw << note.GetCommitment();
    hw << note.GetNullifier(spending_key);
    return hw.GetSHA256();
}

[[nodiscard]] uint256 InputSecretFingerprint(const lattice::PolyVec& input_secret)
{
    return CommitmentHash(Commit(/*value=*/0, input_secret));
}

[[nodiscard]] lattice::PolyVec DerivePublicKey(const uint256& ring_member, size_t member_index)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_Public_V5"};
    hw << ring_member;
    hw << static_cast<uint32_t>(member_index);
    const uint256 seed = hw.GetSHA256();
    return lattice::ExpandUniformVec(
        Span<const unsigned char>{seed.begin(), uint256::size()},
        lattice::MODULE_RANK,
        24576);
}

[[nodiscard]] lattice::Poly256 DeriveLinkGenerator(const uint256& ring_member)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_LinkBase_V4"};
    hw << ring_member;
    const uint256 seed = hw.GetSHA256();
    return lattice::ExpandUniformPoly(
        Span<const unsigned char>{seed.begin(), uint256::size()},
        28672);
}

using DerivedRingMemberCacheKey = std::pair<uint256, uint32_t>;
using DerivedRingMemberCache = std::map<DerivedRingMemberCacheKey, DerivedRingMember>;
using DerivedRingMemberRefs = std::vector<const DerivedRingMember*>;

void CleansePolyVec(lattice::PolyVec& vec)
{
    if (vec.empty()) return;
    memory_cleanse(vec.data(), vec.size() * sizeof(lattice::Poly256));
}

void CleanseResponses(std::vector<lattice::PolyVec>& responses)
{
    for (auto& response : responses) {
        CleansePolyVec(response);
    }
}

[[nodiscard]] lattice::PolyVec SamplePublicKeyOffsetVec(FastRandomContext& rng)
{
    const uint256 seed = rng.rand256();
    return lattice::ExpandUniformVec(
        Span<const unsigned char>{seed.begin(), uint256::size()},
        lattice::MODULE_RANK,
        32768 + static_cast<uint32_t>(rng.randrange(4096)));
}

[[nodiscard]] const DerivedRingMember& GetOrCreateDerivedRingMember(const uint256& ring_member,
                                                                    size_t member_index,
                                                                    DerivedRingMemberCache& cache)
{
    const auto key = std::make_pair(ring_member, static_cast<uint32_t>(member_index));
    const auto [it, inserted] = cache.emplace(key, DerivedRingMember{});
    if (inserted) {
        it->second.public_key = DerivePublicKey(ring_member, member_index);
        it->second.link_generator = DeriveLinkGenerator(ring_member);
        it->second.link_generator_ntt = it->second.link_generator;
        it->second.link_generator_ntt.NTT();
    }
    return it->second;
}

[[nodiscard]] DerivedRingMemberRefs BuildDerivedRingMembers(const std::vector<uint256>& ring_members,
                                                            DerivedRingMemberCache& cache)
{
    DerivedRingMemberRefs out;
    out.reserve(ring_members.size());
    for (size_t member_idx = 0; member_idx < ring_members.size(); ++member_idx) {
        out.push_back(&GetOrCreateDerivedRingMember(ring_members[member_idx], member_idx, cache));
    }
    return out;
}

[[nodiscard]] bool HasInvalidRingMembers(const std::vector<uint256>& ring_members,
                                         bool allow_duplicates)
{
    std::set<uint256> unique_members;
    for (const uint256& member : ring_members) {
        if (member.IsNull()) return true;
        if (!allow_duplicates && !unique_members.insert(member).second) return true;
    }
    return false;
}

[[nodiscard]] lattice::PolyVec PreparePolyVecNTT(const lattice::PolyVec& vec)
{
    lattice::PolyVec out = vec;
    for (size_t i = 0; i < vec.size(); ++i) {
        out[i].NTT();
    }
    return out;
}

[[nodiscard]] lattice::PolyMat BuildCommitmentMatrixNTT()
{
    lattice::PolyMat mat_ntt = CommitmentMatrix();
    for (auto& row : mat_ntt) {
        for (auto& poly : row) {
            poly.NTT();
        }
    }
    return mat_ntt;
}

[[nodiscard]] const lattice::PolyMat& CommitmentMatrixNTT()
{
    static const lattice::PolyMat g_matrix_ntt = BuildCommitmentMatrixNTT();
    return g_matrix_ntt;
}

[[nodiscard]] lattice::PolyVec MatVecMulPreparedNTT(const lattice::PolyVec& vec_ntt)
{
    if (vec_ntt.size() != lattice::MODULE_RANK) return {};
    const lattice::PolyMat& mat_ntt = CommitmentMatrixNTT();
    lattice::PolyVec out(mat_ntt.size());
    for (size_t row = 0; row < mat_ntt.size(); ++row) {
        lattice::Poly256 acc_ntt{};
        for (size_t col = 0; col < vec_ntt.size(); ++col) {
            const lattice::Poly256 term = lattice::Poly256::PointwiseMul(mat_ntt[row][col], vec_ntt[col]);
            acc_ntt = acc_ntt + term;
        }
        acc_ntt.InverseNTT();
        acc_ntt.Reduce();
        acc_ntt.CAddQ();
        out[row] = acc_ntt;
    }
    return out;
}

[[nodiscard]] lattice::PolyVec PolyVecMulPolyPreparedNTT(const lattice::PolyVec& vec_ntt, const lattice::Poly256& poly_ntt)
{
    lattice::PolyVec out(vec_ntt.size());
    for (size_t i = 0; i < vec_ntt.size(); ++i) {
        out[i] = lattice::Poly256::PointwiseMul(vec_ntt[i], poly_ntt);
        out[i].InverseNTT();
        out[i].Reduce();
        out[i].CAddQ();
    }
    return out;
}

[[nodiscard]] lattice::PolyVec PolyVecMulPoly(const lattice::PolyVec& vec, const lattice::Poly256& poly)
{
    const lattice::PolyVec vec_ntt = PreparePolyVecNTT(vec);
    lattice::Poly256 poly_ntt = poly;
    poly_ntt.NTT();
    return PolyVecMulPolyPreparedNTT(vec_ntt, poly_ntt);
}

[[nodiscard]] lattice::PolyVec PolyVecMulPolyCentered(const lattice::PolyVec& vec, const ChallengeType& poly)
{
    // NTT-based polynomial multiplication that preserves centered (signed) coefficients.
    // The challenge polynomial has small ternary coefficients so the product stays bounded.
    const lattice::PolyVec vec_ntt = PreparePolyVecNTT(vec);
    lattice::Poly256 poly_ntt = poly;
    poly_ntt.NTT();
    lattice::PolyVec out(vec_ntt.size());
    for (size_t i = 0; i < vec_ntt.size(); ++i) {
        out[i] = lattice::Poly256::PointwiseMul(vec_ntt[i], poly_ntt);
        out[i].InverseNTT();
        out[i].Reduce();
        // Do NOT call CAddQ here — we need centered (possibly negative) coefficients
        // so the rejection sampling norm check works correctly.
    }
    return out;
}

// R7-106: Document overflow safety for PolyVecAddCentered.
// Input 'a' has coefficients in [-MASKING_BOUND, MASKING_BOUND] = [-131072, 131072].
// Input 'b' comes from PolyVecMulPolyCentered followed by Reduce(), giving
// coefficients in (-q/2, q/2) = (-4190209, 4190209). The sum is bounded by
// 4190209 + 131072 = 4321281, well within int32_t range (max 2147483647).
// The int64_t intermediate prevents any transient overflow.
[[nodiscard]] lattice::PolyVec PolyVecAddCentered(const lattice::PolyVec& a, const lattice::PolyVec& b)
{
    if (a.size() != b.size()) return {};
    lattice::PolyVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < lattice::POLY_N; ++j) {
            out[i].coeffs[j] = static_cast<int32_t>(static_cast<int64_t>(a[i].coeffs[j]) + b[i].coeffs[j]);
        }
    }
    return out;
}

[[nodiscard]] lattice::PolyVec ComputeW(const lattice::PolyVec& response_ntt,
                                        const ChallengeType& challenge,
                                        const lattice::PolyVec& public_key)
{
    const lattice::PolyVec az = MatVecMulPreparedNTT(response_ntt);
    const lattice::PolyVec cpk = PolyVecMulPoly(public_key, challenge);
    return lattice::PolyVecSub(az, cpk);
}

[[nodiscard]] lattice::PolyVec ComputeEffectivePublicKey(const lattice::PolyVec& public_key,
                                                         const lattice::PolyVec& public_key_offset)
{
    if (public_key.size() != public_key_offset.size()) return {};
    return lattice::PolyVecAdd(public_key, public_key_offset);
}

[[nodiscard]] uint256 HashPolyVec(const lattice::PolyVec& vec)
{
    HashWriter hw;
    hw << vec;
    return hw.GetSHA256();
}

[[nodiscard]] bool ValidateEffectivePublicKeysUnique(
    const DerivedRingMemberRefs& derived_members,
    const std::vector<lattice::PolyVec>& member_public_key_offsets)
{
    if (derived_members.empty() || derived_members.size() != member_public_key_offsets.size()) return false;

    std::set<uint256> seen_effective_public_keys;
    for (size_t member_idx = 0; member_idx < derived_members.size(); ++member_idx) {
        const lattice::PolyVec effective_public_key = ComputeEffectivePublicKey(
            derived_members[member_idx]->public_key,
            member_public_key_offsets[member_idx]);
        if (effective_public_key.empty()) return false;
        if (!lattice::IsValidPolyVec(effective_public_key)) return false;

        const uint256 effective_pk_hash = HashPolyVec(effective_public_key);
        if (effective_pk_hash.IsNull()) return false;
        if (!seen_effective_public_keys.insert(effective_pk_hash).second) return false;
    }
    return true;
}

[[nodiscard]] lattice::PolyVec ComputeU(const lattice::PolyVec& response_ntt,
                                        const ChallengeType& challenge,
                                        const lattice::PolyVec& key_image,
                                        const lattice::Poly256& link_generator_ntt)
{
    const lattice::PolyVec hz = PolyVecMulPolyPreparedNTT(response_ntt, link_generator_ntt);
    const lattice::PolyVec cki = PolyVecMulPoly(key_image, challenge);
    return lattice::PolyVecSub(hz, cki);
}

void WriteStreamBytes(HashWriter& hw, const DataStream& stream)
{
    if (stream.empty()) return;
    hw.write(Span<const std::byte>{stream.data(), stream.size()});
}

[[nodiscard]] ChallengeContext BuildChallengeContext(const std::vector<uint256>& ring_members,
                                                     const lattice::PolyVec& key_image,
                                                     const std::vector<lattice::PolyVec>& member_public_key_offsets,
                                                     size_t input_index,
                                                     const uint256& message_hash)
{
    ChallengeContext context;
    context.prefix << std::string{"BTX_MatRiCT_RingSig_Challenge_V4"};
    context.prefix << message_hash;
    context.prefix << static_cast<uint32_t>(input_index);
    context.suffix << ring_members;
    context.suffix << key_image;
    context.suffix << member_public_key_offsets;
    return context;
}

[[nodiscard]] uint256 ComputeNextChallengeDigest(const ChallengeContext& challenge_context,
                                                 size_t member_index,
                                                 const lattice::PolyVec& w,
                                                 const lattice::PolyVec& u)
{
    HashWriter hw;
    WriteStreamBytes(hw, challenge_context.prefix);
    hw << static_cast<uint32_t>(member_index);
    WriteStreamBytes(hw, challenge_context.suffix);
    hw << w;
    hw << u;
    return hw.GetSHA256();
}

void RunRingSignaturePaddingIterations(const ChallengeContext& challenge_context,
                                       const DerivedRingMemberRefs& derived_input_ring,
                                       const std::vector<lattice::PolyVec>& member_offsets,
                                       const lattice::PolyVec& key_image,
                                       size_t ring_size,
                                       int accepted_attempt,
                                       const uint256& message_hash)
{
    if (accepted_attempt < 0 || accepted_attempt >= (MAX_REJECTION_ATTEMPTS - 1)) return;
    if (!lattice::IsSupportedRingSize(ring_size) ||
        derived_input_ring.size() != ring_size ||
        member_offsets.size() != ring_size) {
        return;
    }

    HashWriter seed_hw;
    seed_hw << std::string{"BTX_MatRiCT_RingSig_Padding_V1"};
    seed_hw << message_hash;
    seed_hw << key_image;
    seed_hw << accepted_attempt;
    FastRandomContext padding_rng(seed_hw.GetSHA256());

    for (int pad = accepted_attempt + 1; pad < MAX_REJECTION_ATTEMPTS; ++pad) {
        // R7-105: Use constant-time sampling in padding to prevent timing
        // side-channel leakage of accepted_attempt via RNG-dependent rejection.
        lattice::PolyVec pad_alpha = lattice::SampleBoundedVecCT(padding_rng, lattice::MODULE_RANK, MASKING_BOUND);
        if (!lattice::IsValidPolyVec(pad_alpha)) {
            CleansePolyVec(pad_alpha);
            continue;
        }
        const lattice::PolyVec pad_alpha_ntt = PreparePolyVecNTT(pad_alpha);
        const size_t member_idx = static_cast<size_t>(padding_rng.randrange(ring_size));
        const lattice::PolyVec effective_public_key = ComputeEffectivePublicKey(
            derived_input_ring[member_idx]->public_key,
            member_offsets[member_idx]);
        if (effective_public_key.empty()) {
            CleansePolyVec(pad_alpha);
            continue;
        }
        uint256 digest_seed = padding_rng.rand256();
        if (digest_seed.IsNull()) digest_seed = uint256::ONE;
        const ChallengeType challenge_poly = ChallengeFromDigest(digest_seed);
        const lattice::PolyVec pad_w = ComputeW(pad_alpha_ntt, challenge_poly, effective_public_key);
        const lattice::PolyVec pad_u = ComputeU(pad_alpha_ntt,
                                                challenge_poly,
                                                key_image,
                                                derived_input_ring[member_idx]->link_generator_ntt);
        (void)ComputeNextChallengeDigest(challenge_context, member_idx, pad_w, pad_u);
        CleansePolyVec(pad_alpha);
    }
}

[[nodiscard]] bool VerifyInputChallengeChain(const RingInputProof& input_proof,
                                             const std::vector<uint256>& ring_members,
                                             const DerivedRingMemberRefs& derived_members,
                                             const lattice::PolyVec& key_image,
                                             const std::vector<lattice::PolyVec>& member_public_key_offsets,
                                             const ChallengeContext& challenge_context,
                                             bool prevalidated_responses)
{
    const size_t ring_size = ring_members.size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;
    if (derived_members.size() != ring_size) return false;
    if (input_proof.responses.size() != ring_size) return false;
    if (input_proof.challenges.size() != ring_size) return false;
    if (member_public_key_offsets.size() != ring_size) return false;
    if (!ValidateEffectivePublicKeysUnique(derived_members, member_public_key_offsets)) return false;

    for (size_t member_idx = 0; member_idx < ring_size; ++member_idx) {
        const uint256& challenge_digest = input_proof.challenges[member_idx];
        if (challenge_digest.IsNull()) return false;

        const ChallengeType challenge = ChallengeFromDigest(challenge_digest);
        const lattice::PolyVec& response = input_proof.responses[member_idx];
        if (!prevalidated_responses) {
            if (!lattice::IsValidPolyVec(response)) return false;
            if (lattice::PolyVecInfNorm(response) > RESPONSE_NORM_BOUND) return false;
        }
        const lattice::PolyVec response_ntt = PreparePolyVecNTT(response);

        const lattice::PolyVec effective_public_key = ComputeEffectivePublicKey(derived_members[member_idx]->public_key,
                                                                                member_public_key_offsets[member_idx]);
        if (effective_public_key.empty()) return false;
        const lattice::PolyVec w = ComputeW(response_ntt, challenge, effective_public_key);
        const lattice::PolyVec u = ComputeU(response_ntt, challenge, key_image, derived_members[member_idx]->link_generator_ntt);
        const uint256 expected_next = ComputeNextChallengeDigest(challenge_context, member_idx, w, u);
        const size_t next_idx = (member_idx + 1) % ring_size;
        if (!TimingSafeEqual(input_proof.challenges[next_idx], expected_next)) return false;
    }
    return true;
}

void WriteTranscriptChunk(DataStream& chunk,
                          size_t input_index,
                          size_t member_index,
                          const uint256& challenge_digest,
                          const lattice::PolyVec& w,
                          const lattice::PolyVec& u)
{
    chunk.clear();
    chunk << static_cast<uint32_t>(input_index);
    chunk << static_cast<uint32_t>(member_index);
    chunk << challenge_digest;
    chunk << w;
    chunk << u;
}

[[nodiscard]] uint256 ComputeTranscriptChallengeFromChunks(const RingSignature& signature,
                                                           const std::vector<std::vector<uint256>>& ring_members,
                                                           const TranscriptChunks& input_chunks,
                                                           const uint256& message_hash)
{
    if (input_chunks.size() != signature.input_proofs.size()) return uint256{};
    if (signature.member_public_key_offsets.size() != signature.input_proofs.size()) return uint256{};
    if (ring_members.empty() || ring_members.size() != signature.input_proofs.size()) return uint256{};

    const size_t ring_size = ring_members.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) return uint256{};
    for (const auto& ring : ring_members) {
        if (ring.size() != ring_size) return uint256{};
    }

    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_FS_V3"};
    // R5-105: Bind static lattice parameters into transcript to prevent
    // parameter-confusion attacks across different parameter sets.
    hw << static_cast<uint32_t>(lattice::POLY_N);
    hw << static_cast<int32_t>(lattice::POLY_Q);
    hw << static_cast<uint32_t>(lattice::MODULE_RANK);
    hw << static_cast<uint32_t>(ring_size);
    hw << message_hash;
    hw << ring_members;
    hw << signature.key_images;
    hw << signature.member_public_key_offsets;

    for (size_t input_idx = 0; input_idx < input_chunks.size(); ++input_idx) {
        if (input_chunks[input_idx].size() != ring_size) return uint256{};
        for (size_t member_idx = 0; member_idx < ring_size; ++member_idx) {
            if (input_chunks[input_idx][member_idx].empty()) return uint256{};
            WriteStreamBytes(hw, input_chunks[input_idx][member_idx]);
        }
    }
    return hw.GetSHA256();
}

[[nodiscard]] bool BuildInputTranscriptChunks(const RingInputProof& input_proof,
                                              const DerivedRingMemberRefs& derived_members,
                                              const lattice::PolyVec& key_image,
                                              const std::vector<lattice::PolyVec>& member_public_key_offsets,
                                              const ChallengeContext& challenge_context,
                                              size_t input_index,
                                              std::vector<DataStream>& out_chunks,
                                              bool prevalidated_responses)
{
    const size_t ring_size = derived_members.size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;
    if (input_proof.responses.size() != ring_size) return false;
    if (input_proof.challenges.size() != ring_size) return false;
    if (member_public_key_offsets.size() != ring_size) return false;

    out_chunks.assign(ring_size, DataStream{});
    for (size_t member_idx = 0; member_idx < ring_size; ++member_idx) {
        const uint256& challenge_digest = input_proof.challenges[member_idx];
        if (challenge_digest.IsNull()) return false;
        const ChallengeType challenge = ChallengeFromDigest(challenge_digest);
        const lattice::PolyVec& response = input_proof.responses[member_idx];
        if (!prevalidated_responses) {
            if (!lattice::IsValidPolyVec(response)) return false;
            if (lattice::PolyVecInfNorm(response) > RESPONSE_NORM_BOUND) return false;
        }
        const lattice::PolyVec response_ntt = PreparePolyVecNTT(response);
        const lattice::PolyVec effective_public_key = ComputeEffectivePublicKey(derived_members[member_idx]->public_key,
                                                                                member_public_key_offsets[member_idx]);
        if (effective_public_key.empty()) return false;
        const lattice::PolyVec w = ComputeW(response_ntt, challenge, effective_public_key);
        const lattice::PolyVec u = ComputeU(response_ntt, challenge, key_image, derived_members[member_idx]->link_generator_ntt);
        const uint256 expected_next = ComputeNextChallengeDigest(challenge_context, member_idx, w, u);
        if (expected_next.IsNull()) return false;
        const size_t next_idx = (member_idx + 1) % ring_size;
        if (!TimingSafeEqual(input_proof.challenges[next_idx], expected_next)) return false;
        WriteTranscriptChunk(out_chunks[member_idx], input_index, member_idx, challenge_digest, w, u);
    }
    return true;
}

} // namespace

bool RingInputProof::IsValid(size_t expected_ring_size) const
{
    if (!lattice::IsSupportedRingSize(expected_ring_size)) return false;
    if (responses.size() != expected_ring_size) return false;
    if (challenges.size() != expected_ring_size) return false;

    for (size_t i = 0; i < expected_ring_size; ++i) {
        if (!lattice::IsValidPolyVec(responses[i])) return false;
        if (lattice::PolyVecInfNorm(responses[i]) > RESPONSE_NORM_BOUND) return false;
        if (challenges[i].IsNull()) return false;
    }
    return true;
}

size_t RingInputProof::GetSerializedSize() const
{
    size_t total{0};
    for (const auto& response : responses) {
        total += response.size() * lattice::POLY_N * 3U;
    }
    total += challenges.size() * uint256::size();
    return total;
}

bool RingSignature::IsValid(size_t expected_inputs, size_t expected_ring_size) const
{
    if (challenge_seed.IsNull()) return false;
    if (input_proofs.size() != expected_inputs) return false;
    if (key_images.size() != expected_inputs) return false;
    if (member_public_key_offsets.size() != expected_inputs) return false;

    std::set<uint256> seen_images;
    for (size_t i = 0; i < expected_inputs; ++i) {
        if (!input_proofs[i].IsValid(expected_ring_size)) return false;
        if (!lattice::IsValidPolyVec(key_images[i])) return false;
        if (member_public_key_offsets[i].size() != expected_ring_size) return false;
        for (const auto& offset : member_public_key_offsets[i]) {
            if (!lattice::IsValidPolyVec(offset)) return false;
        }
        if (lattice::PolyVecInfNorm(key_images[i]) == 0) return false;
        const uint256 image_hash = CommitmentHash(Commit(/*value=*/0, key_images[i]));
        if (!seen_images.insert(image_hash).second) return false;
    }
    return true;
}

size_t RingSignature::GetSerializedSize() const
{
    size_t total{uint256::size()}; // challenge_seed
    for (const auto& input_proof : input_proofs) {
        total += input_proof.GetSerializedSize();
    }
    for (size_t i = 0; i < key_images.size(); ++i) {
        total += POLYVEC_MODQ23_PACKED_SIZE;
    }
    for (const auto& input_offsets : member_public_key_offsets) {
        total += sizeof(uint64_t);
        for (const auto& offset : input_offsets) {
            (void)offset;
            total += POLYVEC_MODQ23_PACKED_SIZE;
        }
    }
    return total;
}

uint256 RingSignatureMessageHash(const std::vector<Commitment>& input_commitments,
                                 const std::vector<Commitment>& output_commitments,
                                 CAmount fee,
                                 const std::vector<Nullifier>& input_nullifiers,
                                 const uint256& tx_binding_hash)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_Msg_V1"};
    hw << input_commitments;
    hw << output_commitments;
    hw << fee;
    hw << input_nullifiers;
    hw << tx_binding_hash;
    return hw.GetSHA256();
}

Nullifier ComputeNullifierFromKeyImage(const lattice::PolyVec& key_image)
{
    if (!lattice::IsValidPolyVec(key_image)) return uint256{};
    if (lattice::PolyVecInfNorm(key_image) == 0) return uint256{};

    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RingSig_Nullifier_V1"};
    hw << key_image;
    return hw.GetSHA256();
}

bool DeriveInputSecretFromNote(lattice::PolyVec& out_secret,
                               Span<const unsigned char> spending_key,
                               const ShieldedNote& note)
{
    out_secret.clear();
    if (spending_key.size() < 32 || !note.IsValid()) return false;
    const uint256 seed = DeriveInputSecretSeedFromNote(spending_key, note);
    FastRandomContext rng(seed);
    out_secret = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, lattice::SECRET_SMALL_ETA);
    if (!lattice::IsValidPolyVec(out_secret)) {
        CleansePolyVec(out_secret);
        out_secret.clear();
        return false;
    }
    if (lattice::PolyVecInfNorm(out_secret) == 0) {
        CleansePolyVec(out_secret);
        out_secret.clear();
        return false;
    }
    return true;
}

bool DeriveInputNullifierFromSecret(Nullifier& out_nullifier,
                                    const lattice::PolyVec& input_secret,
                                    const uint256& ring_member_commitment)
{
    if (!lattice::IsValidPolyVec(input_secret) || ring_member_commitment.IsNull()) return false;
    const lattice::Poly256 link_generator = DeriveLinkGenerator(ring_member_commitment);
    const lattice::PolyVec key_image = PolyVecMulPoly(input_secret, link_generator);
    out_nullifier = ComputeNullifierFromKeyImage(key_image);
    return !out_nullifier.IsNull();
}

bool DeriveInputNullifierForNote(Nullifier& out_nullifier,
                                 Span<const unsigned char> spending_key,
                                 const ShieldedNote& note,
                                 const uint256& ring_member_commitment)
{
    lattice::PolyVec secret;
    if (!DeriveInputSecretFromNote(secret, spending_key, note)) return false;
    const bool ok = DeriveInputNullifierFromSecret(out_nullifier, secret, ring_member_commitment);
    CleansePolyVec(secret);
    return ok;
}

bool VerifyRingSignatureNullifierBinding(const RingSignature& signature,
                                         const std::vector<Nullifier>& input_nullifiers)
{
    if (signature.key_images.size() != input_nullifiers.size()) return false;
    std::set<Nullifier> seen;
    for (size_t i = 0; i < signature.key_images.size(); ++i) {
        const Nullifier expected = ComputeNullifierFromKeyImage(signature.key_images[i]);
        if (expected.IsNull()) return false;
        // SideChannel F3 fix: use constant-time comparison for defense-in-depth.
        if (!TimingSafeEqual(input_nullifiers[i], expected)) return false;
        if (!seen.insert(expected).second) return false;
    }
    return true;
}

bool CreateRingSignature(RingSignature& signature,
                         const std::vector<std::vector<uint256>>& ring_members,
                         const std::vector<size_t>& real_indices,
                         const std::vector<lattice::PolyVec>& input_secrets,
                         const uint256& message_hash,
                         Span<const unsigned char> rng_entropy,
                         bool allow_duplicate_ring_members)
{
    const size_t input_count = ring_members.size();
    if (input_count == 0 || real_indices.size() != input_count || input_secrets.size() != input_count) return false;
    if (input_count > MAX_RING_SIGNATURE_INPUTS) return false;

    const size_t ring_size = ring_members.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;

    std::set<uint256> seen_input_secret_fingerprints;
    for (size_t i = 0; i < input_count; ++i) {
        if (ring_members[i].size() != ring_size) return false;
        if (real_indices[i] >= ring_members[i].size()) return false;
        if (HasInvalidRingMembers(ring_members[i], allow_duplicate_ring_members)) return false;
        if (!lattice::IsValidPolyVec(input_secrets[i])) return false;
        if (input_secrets[i].size() != lattice::MODULE_RANK) return false;
        if (lattice::PolyVecInfNorm(input_secrets[i]) > lattice::SECRET_SMALL_ETA) return false;
        if (lattice::PolyVecInfNorm(input_secrets[i]) == 0) return false;
        const uint256 secret_fingerprint = InputSecretFingerprint(input_secrets[i]);
        if (secret_fingerprint.IsNull()) return false;
        if (!seen_input_secret_fingerprints.insert(secret_fingerprint).second) return false;
    }

    FastRandomContext rng(ComputeSigningRngSeed(ring_members, real_indices, input_secrets, message_hash, rng_entropy));
    std::vector<DerivedRingMemberRefs> derived_ring_members;
    derived_ring_members.reserve(input_count);
    DerivedRingMemberCache derived_member_cache;
    for (const auto& ring : ring_members) {
        derived_ring_members.push_back(BuildDerivedRingMembers(ring, derived_member_cache));
    }

    signature.input_proofs.assign(input_count, RingInputProof{});
    signature.key_images.assign(input_count, lattice::PolyVec{});
    signature.member_public_key_offsets.assign(input_count, {});
    signature.challenge_seed = uint256{};
    TranscriptChunks transcript_chunks(input_count, std::vector<DataStream>(ring_size));
    std::set<uint256> seen_key_images;

    for (size_t input_idx = 0; input_idx < input_count; ++input_idx) {
        RingInputProof& input_proof = signature.input_proofs[input_idx];
        const auto& derived_input_ring = derived_ring_members[input_idx];

        const size_t real_index = real_indices[input_idx];
        lattice::PolyVec secret = input_secrets[input_idx];
        lattice::PolyVec secret_ntt = PreparePolyVecNTT(secret);
        const lattice::PolyVec signer_public_key = MatVecMulPreparedNTT(secret_ntt);
        if (!lattice::IsValidPolyVec(signer_public_key)) {
            CleansePolyVec(secret);
            CleansePolyVec(secret_ntt);
            return false;
        }
        std::vector<lattice::PolyVec> member_offsets(ring_size);
        for (size_t member_idx = 0; member_idx < ring_size; ++member_idx) {
            if (member_idx == real_index) {
                member_offsets[member_idx] = lattice::PolyVecSub(signer_public_key,
                                                                 derived_input_ring[real_index]->public_key);
            } else {
                member_offsets[member_idx] = SamplePublicKeyOffsetVec(rng);
            }
            if (!lattice::IsValidPolyVec(member_offsets[member_idx])) {
                CleansePolyVec(secret);
                CleansePolyVec(secret_ntt);
                return false;
            }
        }
        if (!ValidateEffectivePublicKeysUnique(derived_input_ring, member_offsets)) {
            CleansePolyVec(secret);
            CleansePolyVec(secret_ntt);
            return false;
        }
        signature.member_public_key_offsets[input_idx] = member_offsets;
        const lattice::Poly256& link_generator_real = derived_input_ring[real_index]->link_generator;
        const lattice::Poly256& link_generator_real_ntt = derived_input_ring[real_index]->link_generator_ntt;
        signature.key_images[input_idx] = PolyVecMulPoly(secret, link_generator_real);
        if (!lattice::IsValidPolyVec(signature.key_images[input_idx])) {
            CleansePolyVec(secret);
            CleansePolyVec(secret_ntt);
            return false;
        }
        const uint256 key_image_hash = CommitmentHash(Commit(/*value=*/0, signature.key_images[input_idx]));
        if (key_image_hash.IsNull() || !seen_key_images.insert(key_image_hash).second) {
            CleansePolyVec(secret);
            CleansePolyVec(secret_ntt);
            return false;
        }
        const ChallengeContext challenge_context = BuildChallengeContext(ring_members[input_idx],
                                                                         signature.key_images[input_idx],
                                                                         member_offsets,
                                                                         input_idx,
                                                                         message_hash);
        RingInputProof candidate;
        candidate.responses.assign(ring_size, lattice::PolyVec{});
        candidate.challenges.assign(ring_size, uint256{});

        bool accepted{false};
        int accepted_attempt{-1};
        const auto reset_candidate = [&candidate]() {
            CleanseResponses(candidate.responses);
            std::fill(candidate.challenges.begin(), candidate.challenges.end(), uint256{});
        };
        for (int attempts = 0; attempts < MAX_REJECTION_ATTEMPTS; ++attempts) {
            reset_candidate();

            lattice::PolyVec alpha = SampleMaskingVec(rng);
            if (!lattice::IsValidPolyVec(alpha)) {
                CleansePolyVec(alpha);
                continue;
            }
            const lattice::PolyVec alpha_ntt = PreparePolyVecNTT(alpha);

            const lattice::PolyVec w_real = MatVecMulPreparedNTT(alpha_ntt);
            const lattice::PolyVec u_real = PolyVecMulPolyPreparedNTT(alpha_ntt, link_generator_real_ntt);
            uint256 next_challenge = ComputeNextChallengeDigest(challenge_context, real_index, w_real, u_real);
            if (next_challenge.IsNull()) {
                CleansePolyVec(alpha);
                continue;
            }

            bool chain_ok{true};
            size_t member_idx = (real_index + 1) % ring_size;
            while (member_idx != real_index) {
                candidate.challenges[member_idx] = next_challenge;
                const ChallengeType challenge_poly = ChallengeFromDigest(next_challenge);

                candidate.responses[member_idx] = SampleSimulatedResponse(rng);
                if (!lattice::IsValidPolyVec(candidate.responses[member_idx])) {
                    chain_ok = false;
                    break;
                }
                const lattice::PolyVec response_ntt = PreparePolyVecNTT(candidate.responses[member_idx]);
                const lattice::PolyVec effective_public_key = ComputeEffectivePublicKey(
                    derived_input_ring[member_idx]->public_key,
                    member_offsets[member_idx]);
                if (effective_public_key.empty()) {
                    chain_ok = false;
                    break;
                }

                const lattice::PolyVec w = ComputeW(response_ntt,
                                                    challenge_poly,
                                                    effective_public_key);
                const lattice::PolyVec u = ComputeU(response_ntt,
                                                    challenge_poly,
                                                    signature.key_images[input_idx],
                                                    derived_input_ring[member_idx]->link_generator_ntt);
                next_challenge = ComputeNextChallengeDigest(challenge_context, member_idx, w, u);
                if (next_challenge.IsNull()) {
                    chain_ok = false;
                    break;
                }
                member_idx = (member_idx + 1) % ring_size;
            }
            if (!chain_ok) {
                CleansePolyVec(alpha);
                continue;
            }

            candidate.challenges[real_index] = next_challenge;
            const ChallengeType challenge_real = ChallengeFromDigest(next_challenge);
            // R6-211: Compute c*s into a named temporary so it can be cleansed.
            lattice::PolyVec cs_product = PolyVecMulPolyCentered(secret, challenge_real);
            lattice::PolyVec z_real = PolyVecAddCentered(alpha, cs_product);
            CleansePolyVec(cs_product);
            if (!lattice::IsValidPolyVec(z_real)) {
                CleansePolyVec(z_real);
                CleansePolyVec(alpha);
                continue;
            }
            if (lattice::PolyVecInfNorm(z_real) > RESPONSE_NORM_BOUND) {
                CleansePolyVec(z_real);
                CleansePolyVec(alpha);
                continue;
            }
            const lattice::PolyVec z_real_ntt = PreparePolyVecNTT(z_real);
            const lattice::PolyVec effective_public_key_real = ComputeEffectivePublicKey(
                derived_input_ring[real_index]->public_key,
                member_offsets[real_index]);
            if (effective_public_key_real.empty()) {
                CleansePolyVec(z_real);
                CleansePolyVec(alpha);
                continue;
            }
            const lattice::PolyVec w_real_final = ComputeW(z_real_ntt,
                                                           challenge_real,
                                                           effective_public_key_real);
            const lattice::PolyVec u_real_final = ComputeU(z_real_ntt,
                                                           challenge_real,
                                                           signature.key_images[input_idx],
                                                           link_generator_real_ntt);
            const size_t next_real_idx = (real_index + 1) % ring_size;
            const uint256 expected_next_real = ComputeNextChallengeDigest(challenge_context,
                                                                          real_index,
                                                                          w_real_final,
                                                                          u_real_final);
            if (expected_next_real != candidate.challenges[next_real_idx]) {
                CleansePolyVec(z_real);
                CleansePolyVec(alpha);
                continue;
            }
            candidate.responses[real_index] = std::move(z_real);
            CleansePolyVec(alpha);

            if (!VerifyInputChallengeChain(candidate,
                                           ring_members[input_idx],
                                           derived_input_ring,
                                           signature.key_images[input_idx],
                                           member_offsets,
                                           challenge_context,
                                           /*prevalidated_responses=*/false)) {
                continue;
            }
            if (!candidate.IsValid(ring_size)) continue;
            if (!BuildInputTranscriptChunks(candidate,
                                           derived_input_ring,
                                           signature.key_images[input_idx],
                                           member_offsets,
                                           challenge_context,
                                           input_idx,
                                           transcript_chunks[input_idx],
                                           /*prevalidated_responses=*/true)) {
                continue;
            }
            input_proof = std::move(candidate);
            accepted = true;
            accepted_attempt = attempts;
            break;
        }
        RunRingSignaturePaddingIterations(challenge_context,
                                          derived_input_ring,
                                          member_offsets,
                                          signature.key_images[input_idx],
                                          ring_size,
                                          accepted_attempt,
                                          message_hash);
        CleansePolyVec(secret);
        CleansePolyVec(secret_ntt);
        if (!accepted) {
            CleanseResponses(candidate.responses);
            return false;
        }
    }

    signature.challenge_seed = ComputeTranscriptChallengeFromChunks(signature,
                                                                    ring_members,
                                                                    transcript_chunks,
                                                                    message_hash);
    if (signature.challenge_seed.IsNull()) return false;
    if (!signature.IsValid(input_count, ring_size)) return false;
    if (!VerifyRingSignature(signature, ring_members, message_hash)) return false;
    return true;
}

bool VerifyRingSignature(const RingSignature& signature,
                         const std::vector<std::vector<uint256>>& ring_members,
                         const uint256& message_hash)
{
    const size_t input_count = ring_members.size();
    if (input_count == 0) return false;
    if (input_count > MAX_RING_SIGNATURE_INPUTS) return false;

    const size_t ring_size = ring_members.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;

    for (const auto& ring : ring_members) {
        if (ring.size() != ring_size) return false;
        // MatRiCT audit F1 fix: crypto verification layer independently rejects
        // duplicate ring members as defense-in-depth. Consensus validation also
        // enforces diversity, but the cryptographic layer should not rely on it.
        if (HasInvalidRingMembers(ring, /*allow_duplicates=*/false)) return false;
    }
    std::vector<DerivedRingMemberRefs> derived_ring_members;
    derived_ring_members.reserve(input_count);
    DerivedRingMemberCache derived_member_cache;
    for (const auto& ring : ring_members) {
        derived_ring_members.push_back(BuildDerivedRingMembers(ring, derived_member_cache));
    }

    if (!signature.IsValid(input_count, ring_size)) return false;

    TranscriptChunks transcript_chunks(input_count);
    for (size_t input_idx = 0; input_idx < input_count; ++input_idx) {
        const RingInputProof& input_proof = signature.input_proofs[input_idx];
        const ChallengeContext challenge_context = BuildChallengeContext(ring_members[input_idx],
                                                                         signature.key_images[input_idx],
                                                                         signature.member_public_key_offsets[input_idx],
                                                                         input_idx,
                                                                         message_hash);
        if (!BuildInputTranscriptChunks(input_proof,
                                        derived_ring_members[input_idx],
                                        signature.key_images[input_idx],
                                        signature.member_public_key_offsets[input_idx],
                                        challenge_context,
                                        input_idx,
                                        transcript_chunks[input_idx],
                                        /*prevalidated_responses=*/true)) {
            return false;
        }
    }

    const uint256 expected = ComputeTranscriptChallengeFromChunks(signature,
                                                                  ring_members,
                                                                  transcript_chunks,
                                                                  message_hash);
    if (expected.IsNull()) return false;
    return TimingSafeEqual(expected, signature.challenge_seed);
}

bool ExportRingSignatureTranscriptChunks(
    std::vector<std::vector<std::vector<unsigned char>>>& out_chunks,
    const RingSignature& signature,
    const std::vector<std::vector<uint256>>& ring_members,
    const uint256& message_hash)
{
    out_chunks.clear();
    const size_t input_count = ring_members.size();
    if (input_count == 0) return false;
    if (input_count > MAX_RING_SIGNATURE_INPUTS) return false;

    const size_t ring_size = ring_members.front().size();
    if (!lattice::IsSupportedRingSize(ring_size)) return false;

    for (const auto& ring : ring_members) {
        if (ring.size() != ring_size) return false;
        if (HasInvalidRingMembers(ring, /*allow_duplicates=*/false)) return false;
    }

    std::vector<DerivedRingMemberRefs> derived_ring_members;
    derived_ring_members.reserve(input_count);
    DerivedRingMemberCache derived_member_cache;
    for (const auto& ring : ring_members) {
        derived_ring_members.push_back(BuildDerivedRingMembers(ring, derived_member_cache));
    }

    if (!signature.IsValid(input_count, ring_size)) return false;

    TranscriptChunks transcript_chunks(input_count);
    out_chunks.assign(input_count, {});
    for (size_t input_idx = 0; input_idx < input_count; ++input_idx) {
        const RingInputProof& input_proof = signature.input_proofs[input_idx];
        const ChallengeContext challenge_context = BuildChallengeContext(ring_members[input_idx],
                                                                         signature.key_images[input_idx],
                                                                         signature.member_public_key_offsets[input_idx],
                                                                         input_idx,
                                                                         message_hash);
        if (!BuildInputTranscriptChunks(input_proof,
                                        derived_ring_members[input_idx],
                                        signature.key_images[input_idx],
                                        signature.member_public_key_offsets[input_idx],
                                        challenge_context,
                                        input_idx,
                                        transcript_chunks[input_idx],
                                        /*prevalidated_responses=*/true)) {
            out_chunks.clear();
            return false;
        }

        auto& exported_input_chunks = out_chunks[input_idx];
        exported_input_chunks.reserve(transcript_chunks[input_idx].size());
        for (const DataStream& chunk : transcript_chunks[input_idx]) {
            std::vector<unsigned char> encoded;
            encoded.reserve(chunk.size());
            for (const std::byte byte : chunk) {
                encoded.push_back(std::to_integer<unsigned char>(byte));
            }
            exported_input_chunks.push_back(std::move(encoded));
        }
    }

    return true;
}

} // namespace shielded::ringct
