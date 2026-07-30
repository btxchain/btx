// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_hash_air.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_hash_domain_sep.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <iterator>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_hash_air {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
constexpr uint32_t CARRY_COL = 3 * kWordColumns;
constexpr std::array<uint32_t, 8> SHA_H0{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
constexpr std::array<uint32_t, 64> SHA_K{
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};

Fp3 U(uint64_t v) { return Fp3::FromFp(gf::FromU64(v)); }

bool Fail(std::string* why, const std::string& message)
{
    if (why) *why = "stage3:hash_air:" + message;
    return false;
}

bool IsPowerOfTwo(uint32_t n) { return n >= 2 && (n & (n - 1)) == 0; }

Fp3 Bool(const Fp3& b)
{
    return gf::Mul(b, gf::Sub(b, Fp3::One()));
}

Fp3 Xor2(const Fp3& a, const Fp3& b)
{
    return gf::Sub(gf::Add(a, b), gf::Mul(U(2), gf::Mul(a, b)));
}

Fp3 Xor3(const Fp3& a, const Fp3& b, const Fp3& c)
{
    return Xor2(Xor2(a, b), c);
}

Fp3 Choice(const Fp3& a, const Fp3& b, const Fp3& c)
{
    return gf::Add(c, gf::Mul(a, gf::Sub(b, c)));
}

Fp3 Majority(const Fp3& a, const Fp3& b, const Fp3& c)
{
    const Fp3 ab = gf::Mul(a, b);
    return gf::Sub(gf::Add(gf::Add(ab, gf::Mul(a, c)), gf::Mul(b, c)),
                   gf::Mul(U(2), gf::Mul(ab, c)));
}

void Add(aq::AirConstraintSystem<Fp3>& cs, const char* name, uint32_t degree,
         std::function<Fp3(const std::vector<Fp3>&,
                           const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> c;
    c.name = name;
    c.kind = aq::AirKind::kEverywhere;
    c.alg_degree = degree;
    c.eval = std::move(eval);
    cs.constraints.push_back(std::move(c));
}

void AddWord(aq::AirConstraintSystem<Fp3>& cs, uint32_t word)
{
    for (uint32_t bit = 0; bit < 32; ++bit) {
        Add(cs, "stage3.hash.word.bit_boolean", 2,
            [word, bit](const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
                return Bool(cur[BitColumn(word, bit)]);
            });
    }
    Add(cs, "stage3.hash.word.recompose", 1,
        [word](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = gf::Add(sum, gf::Mul(U(uint64_t{1} << bit),
                                          cur[BitColumn(word, bit)]));
            }
            return gf::Sub(sum, cur[ValueColumn(word)]);
        });
}

bool Validate(const Spec& spec, std::string* why)
{
    if (spec.registry_version != kRegistryVersion) return Fail(why, "bad_registry_version");
    if (!IsPowerOfTwo(spec.n_rows) || spec.n_rows > kRCFriMaxCoeffsHard) {
        return Fail(why, "bad_row_count");
    }
    if (NumWords(spec.family) == 0) return Fail(why, "unknown_family");
    if (spec.family == Family::XorRot32) {
        if (spec.rotate_left == 0 || spec.rotate_left >= 32) {
            return Fail(why, "bad_rotate_left");
        }
    } else if (spec.rotate_left != 0) {
        return Fail(why, "unused_rotate_left");
    }
    if (spec.family == Family::ShaXor3Transform32) {
        for (const auto& t : spec.transforms) {
            if (t.amount == 0 || t.amount >= 32) return Fail(why, "bad_transform_amount");
            if (t.kind != BitTransformKind::RotateRight &&
                t.kind != BitTransformKind::ShiftRight) {
                return Fail(why, "bad_transform_kind");
            }
        }
    } else {
        for (const auto& t : spec.transforms) {
            if (t.amount != 0) return Fail(why, "unused_transform");
        }
    }
    return true;
}

uint32_t Rotl32(uint32_t v, uint8_t n) { return (v << n) | (v >> (32 - n)); }
uint32_t Rotr32(uint32_t v, uint8_t n) { return (v >> n) | (v << (32 - n)); }

uint32_t Transform(uint32_t v, const BitTransform& t)
{
    return t.kind == BitTransformKind::RotateRight ? Rotr32(v, t.amount) : v >> t.amount;
}

Fp3 TransformBit(const std::vector<Fp3>& cur, uint32_t out,
                 const BitTransform& t)
{
    if (t.kind == BitTransformKind::RotateRight) {
        return cur[BitColumn(0, (out + t.amount) & 31U)];
    }
    const uint32_t source = out + t.amount;
    return source < 32 ? cur[BitColumn(0, source)] : Fp3::Zero();
}

void PutWord(std::vector<std::vector<Fp3>>& cols, uint32_t word,
             uint32_t row, uint32_t value)
{
    cols[ValueColumn(word)][row] = U(value);
    for (uint32_t bit = 0; bit < 32; ++bit) {
        cols[BitColumn(word, bit)][row] = U((value >> bit) & 1U);
    }
}

std::vector<Family> ShaFamilies()
{
    return {Family::Add32, Family::ShaChoice32, Family::ShaMajority32,
            Family::ShaXor3Transform32};
}

std::vector<Gap> ShaGaps(bool xof, bool stream)
{
    std::vector<Gap> gaps{
        {GapCode::CopyAndCtlWiring, "the two-epoch provenance proof closes internal SSA copies, but its external/final boundary cells are not yet equality-linked to the producer and consumer role-proof columns at the recursive root"},
        {GapCode::RecursiveAggregation, "boundary-pinned instruction proofs and their CTL children are not folded into the normalized recursive root"},
    };
    // XofCounter / CompleteStream manifest gaps are CLOSED by the recursive
    // bindings (Build/Verify{XofCounter,CompleteStream}ManifestRecursiveBinding):
    // the ordered committed-column stream is now Merkle-folded and bound to the
    // committed manifest root, so a wrong value or reordering fails closed. Only
    // CopyAndCtlWiring + RecursiveAggregation remain open for these relations.
    if (xof && !kHashXofCounterManifestBindingExecutable) {
        gaps.push_back({GapCode::XofCounterManifest,
                        "the exact minimal counter/rejection manifest maps to executable SHA boundary instances but is not recursively bound to the builder output root"});
    }
    if (stream && !kHashCompleteStreamManifestBindingExecutable) {
        gaps.push_back({GapCode::CompleteStreamManifest,
                        "the exact leaf/node or digest stream manifest maps to executable SHA boundary instances but is not recursively bound to its producer columns"});
    }
    return gaps;
}

void AppendU32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) out.push_back(value >> (8 * i));
}

void AppendU64(std::vector<uint8_t>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) out.push_back(value >> (8 * i));
}

uint256 Sha256dTagged(const char* domain, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> bytes;
    bytes.insert(bytes.end(), domain, domain + std::strlen(domain));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    uint8_t first[32];
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(first);
    CSHA256().Write(first, sizeof(first)).Finalize(out.data());
    return out;
}

std::array<uint8_t, 32> DigestBytes(const std::array<uint32_t, 8>& words)
{
    std::array<uint8_t, 32> out{};
    for (uint32_t i = 0; i < 8; ++i) {
        out[4 * i] = words[i] >> 24;
        out[4 * i + 1] = words[i] >> 16;
        out[4 * i + 2] = words[i] >> 8;
        out[4 * i + 3] = words[i];
    }
    return out;
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{digest.data(), digest.size()}};
}

std::vector<std::array<uint8_t, 64>> PadSha256(
    const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> padded = message;
    padded.push_back(0x80);
    while (padded.size() % 64 != 56) padded.push_back(0);
    const uint64_t bits = static_cast<uint64_t>(message.size()) * 8;
    for (int shift = 7; shift >= 0; --shift) {
        padded.push_back(bits >> (8 * shift));
    }
    std::vector<std::array<uint8_t, 64>> blocks(padded.size() / 64);
    for (uint32_t i = 0; i < blocks.size(); ++i) {
        std::copy_n(padded.begin() + 64 * i, 64, blocks[i].begin());
    }
    return blocks;
}

std::array<uint32_t, 16> MessageWords(
    const std::array<uint8_t, 64>& block)
{
    std::array<uint32_t, 16> out{};
    for (uint32_t i = 0; i < 16; ++i) {
        out[i] = (uint32_t{block[4 * i]} << 24) |
                 (uint32_t{block[4 * i + 1]} << 16) |
                 (uint32_t{block[4 * i + 2]} << 8) |
                 uint32_t{block[4 * i + 3]};
    }
    return out;
}

bool BuildShaPass(const std::vector<uint8_t>& message,
                  ShaPassManifest& out, std::string* why)
{
    out = {};
    out.message_size = message.size();
    out.padded_blocks = PadSha256(message);
    std::array<uint32_t, 8> state = SHA_H0;
    const FixedProgram program =
        BuildCanonicalProgram(ProgramKind::Sha256Compression);
    for (const auto& block : out.padded_blocks) {
        out.h_in.push_back(state);
        const auto words = MessageWords(block);
        std::vector<uint32_t> external;
        external.reserve(88);
        external.insert(external.end(), words.begin(), words.end());
        external.insert(external.end(), state.begin(), state.end());
        external.insert(external.end(), SHA_K.begin(), SHA_K.end());
        ProgramWitness witness;
        if (!BuildProgramWitness(program, external, witness, why) ||
            witness.final_words.size() != 8) {
            return Fail(why, "sha_pass_program");
        }
        std::copy_n(witness.final_words.begin(), 8, state.begin());
        out.h_out.push_back(state);
    }
    return true;
}

void AppendShaPass(std::vector<uint8_t>& bytes, const ShaPassManifest& pass)
{
    AppendU64(bytes, pass.message_size);
    AppendU32(bytes, pass.padded_blocks.size());
    for (const auto& block : pass.padded_blocks) {
        bytes.insert(bytes.end(), block.begin(), block.end());
    }
    AppendU32(bytes, pass.h_in.size());
    for (const auto& state : pass.h_in) {
        for (uint32_t word : state) AppendU32(bytes, word);
    }
    AppendU32(bytes, pass.h_out.size());
    for (const auto& state : pass.h_out) {
        for (uint32_t word : state) AppendU32(bytes, word);
    }
}

void AppendHash(std::vector<uint8_t>& bytes, const uint256& hash)
{
    bytes.insert(bytes.end(), hash.data(), hash.data() + hash.size());
}

void AppendShaCommitments(std::vector<uint8_t>& bytes,
                          const std::vector<ShaManifest>& manifests)
{
    AppendU32(bytes, manifests.size());
    for (const auto& manifest : manifests) AppendHash(bytes, manifest.commitment);
}

} // namespace

const char* FamilyName(Family f)
{
    switch (f) {
    case Family::Add32: return "add32";
    case Family::XorRot32: return "xor_rot32";
    case Family::ShaChoice32: return "sha_choice32";
    case Family::ShaMajority32: return "sha_majority32";
    case Family::ShaXor3Transform32: return "sha_xor3_transform32";
    }
    return "unknown";
}

uint32_t NumWords(Family f)
{
    switch (f) {
    case Family::Add32:
    case Family::XorRot32: return 3;
    case Family::ShaChoice32:
    case Family::ShaMajority32: return 4;
    case Family::ShaXor3Transform32: return 2;
    }
    return 0;
}

uint32_t NumColumns(Family f)
{
    const uint32_t words = NumWords(f);
    return words == 0 ? 0 : words * kWordColumns + (f == Family::Add32 ? 1 : 0);
}

uint32_t ValueColumn(uint32_t word) { return word * kWordColumns; }
uint32_t BitColumn(uint32_t word, uint32_t bit) { return ValueColumn(word) + 1 + bit; }
uint32_t AddCarryColumn() { return CARRY_COL; }

bool BuildConstraintSystem(const Spec& spec, aq::AirConstraintSystem<Fp3>& out,
                           std::string* why)
{
    out = {};
    if (!Validate(spec, why)) return false;
    out.n_rows = spec.n_rows;
    out.n_columns = NumColumns(spec.family);
    for (uint32_t word = 0; word < NumWords(spec.family); ++word) AddWord(out, word);

    switch (spec.family) {
    case Family::Add32:
        Add(out, "stage3.hash.add32.carry_boolean", 2,
            [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                return Bool(cur[CARRY_COL]);
            });
        Add(out, "stage3.hash.add32.identity", 1,
            [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                return gf::Sub(
                    gf::Sub(gf::Add(cur[ValueColumn(0)], cur[ValueColumn(1)]),
                            cur[ValueColumn(2)]),
                    gf::Mul(U(uint64_t{1} << 32), cur[CARRY_COL]));
            });
        break;
    case Family::XorRot32:
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.xor_rot32.bit", 2,
                [bit, rot = spec.rotate_left](const std::vector<Fp3>& cur,
                                               const std::vector<Fp3>&) {
                    const uint32_t source = (bit + 32U - rot) & 31U;
                    return gf::Sub(cur[BitColumn(2, bit)],
                                   Xor2(cur[BitColumn(0, source)],
                                        cur[BitColumn(1, source)]));
                });
        }
        break;
    case Family::ShaChoice32:
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.sha_choice32.bit", 2,
                [bit](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                    return gf::Sub(cur[BitColumn(3, bit)],
                                   Choice(cur[BitColumn(0, bit)],
                                          cur[BitColumn(1, bit)],
                                          cur[BitColumn(2, bit)]));
                });
        }
        break;
    case Family::ShaMajority32:
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.sha_majority32.bit", 3,
                [bit](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
                    return gf::Sub(cur[BitColumn(3, bit)],
                                   Majority(cur[BitColumn(0, bit)],
                                            cur[BitColumn(1, bit)],
                                            cur[BitColumn(2, bit)]));
                });
        }
        break;
    case Family::ShaXor3Transform32:
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.sha_xor3_transform32.bit", 3,
                [bit, transforms = spec.transforms](const std::vector<Fp3>& cur,
                                                     const std::vector<Fp3>&) {
                    return gf::Sub(cur[BitColumn(1, bit)],
                                   Xor3(TransformBit(cur, bit, transforms[0]),
                                        TransformBit(cur, bit, transforms[1]),
                                        TransformBit(cur, bit, transforms[2])));
                });
        }
        break;
    }
    return true;
}

bool BuildWitness(const Spec& spec, const Inputs& in, Witness& out, std::string* why)
{
    out = {};
    if (!Validate(spec, why)) return false;
    auto size_ok = [&](const std::vector<uint32_t>& v, const char* name) {
        return v.size() == spec.n_rows || Fail(why, std::string{name} + "_length");
    };
    if (!size_ok(in.a, "a")) return false;
    if (spec.family != Family::ShaXor3Transform32 && !size_ok(in.b, "b")) return false;
    if ((spec.family == Family::ShaChoice32 || spec.family == Family::ShaMajority32) &&
        !size_ok(in.c, "c")) return false;

    out.columns.assign(NumColumns(spec.family),
                       std::vector<Fp3>(spec.n_rows, Fp3::Zero()));
    out.output.resize(spec.n_rows);
    for (uint32_t row = 0; row < spec.n_rows; ++row) {
        PutWord(out.columns, 0, row, in.a[row]);
        uint32_t r = 0;
        switch (spec.family) {
        case Family::Add32: {
            PutWord(out.columns, 1, row, in.b[row]);
            const uint64_t sum = uint64_t{in.a[row]} + in.b[row];
            r = static_cast<uint32_t>(sum);
            out.columns[CARRY_COL][row] = U(sum >> 32);
            PutWord(out.columns, 2, row, r);
            break;
        }
        case Family::XorRot32:
            PutWord(out.columns, 1, row, in.b[row]);
            r = Rotl32(in.a[row] ^ in.b[row], spec.rotate_left);
            PutWord(out.columns, 2, row, r);
            break;
        case Family::ShaChoice32:
            PutWord(out.columns, 1, row, in.b[row]);
            PutWord(out.columns, 2, row, in.c[row]);
            r = (in.a[row] & in.b[row]) ^ (~in.a[row] & in.c[row]);
            PutWord(out.columns, 3, row, r);
            break;
        case Family::ShaMajority32:
            PutWord(out.columns, 1, row, in.b[row]);
            PutWord(out.columns, 2, row, in.c[row]);
            r = (in.a[row] & in.b[row]) ^ (in.a[row] & in.c[row]) ^
                (in.b[row] & in.c[row]);
            PutWord(out.columns, 3, row, r);
            break;
        case Family::ShaXor3Transform32:
            r = Transform(in.a[row], spec.transforms[0]) ^
                Transform(in.a[row], spec.transforms[1]) ^
                Transform(in.a[row], spec.transforms[2]);
            PutWord(out.columns, 1, row, r);
            break;
        }
        out.output[row] = r;
    }
    return true;
}

bool VerifyShard(const Spec& spec, const aq::AirQuotientProof<Fp3>& proof,
                 const uint256& seed, std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    return BuildConstraintSystem(spec, cs, why) &&
           aq::AirQuotientVerify<Fp3>(cs, proof, seed, why);
}

FixedProgram BuildCanonicalProgram(ProgramKind kind)
{
    FixedProgram out;
    out.kind = kind;
    uint32_t next_address = 1;
    auto external = [&]() { return next_address++; };
    auto push = [&](ProgramOpcode opcode, uint32_t round, uint32_t step,
                    std::initializer_list<uint32_t> inputs,
                    uint8_t rotate = 0) {
        ProgramRow row;
        row.opcode = opcode;
        row.round = static_cast<uint16_t>(round);
        row.step = static_cast<uint16_t>(step);
        row.rotate_left = rotate;
        row.input_count = static_cast<uint8_t>(inputs.size());
        std::copy(inputs.begin(), inputs.end(), row.input_address.begin());
        row.output_address = next_address++;
        out.rows.push_back(row);
        return row.output_address;
    };

    if (kind == ProgramKind::Sha256Compression) {
        std::array<uint32_t, 64> w{};
        for (uint32_t i = 0; i < 16; ++i) w[i] = external();
        std::array<uint32_t, 8> initial{};
        for (auto& address : initial) address = external();
        std::array<uint32_t, 64> k{};
        for (auto& address : k) address = external();
        out.external_address_count = next_address - 1;

        for (uint32_t round = 16; round < 64; ++round) {
            const uint32_t s0 =
                push(ProgramOpcode::ShaSmallSigma0, round, 0,
                     {w[round - 15]});
            const uint32_t s1 =
                push(ProgramOpcode::ShaSmallSigma1, round, 1,
                     {w[round - 2]});
            uint32_t sum =
                push(ProgramOpcode::Add32, round, 2,
                     {w[round - 16], s0});
            sum = push(ProgramOpcode::Add32, round, 3,
                       {sum, w[round - 7]});
            w[round] = push(ProgramOpcode::Add32, round, 4, {sum, s1});
        }

        std::array<uint32_t, 8> state = initial;
        for (uint32_t round = 0; round < 64; ++round) {
            const auto old = state;
            const uint32_t s1 =
                push(ProgramOpcode::ShaBigSigma1, round, 0, {old[4]});
            const uint32_t ch =
                push(ProgramOpcode::ShaChoice32, round, 1,
                     {old[4], old[5], old[6]});
            uint32_t t1 =
                push(ProgramOpcode::Add32, round, 2, {old[7], s1});
            t1 = push(ProgramOpcode::Add32, round, 3, {t1, ch});
            t1 = push(ProgramOpcode::Add32, round, 4, {t1, k[round]});
            t1 = push(ProgramOpcode::Add32, round, 5, {t1, w[round]});
            const uint32_t s0 =
                push(ProgramOpcode::ShaBigSigma0, round, 6, {old[0]});
            const uint32_t maj =
                push(ProgramOpcode::ShaMajority32, round, 7,
                     {old[0], old[1], old[2]});
            const uint32_t t2 =
                push(ProgramOpcode::Add32, round, 8, {s0, maj});
            const uint32_t new_a =
                push(ProgramOpcode::Add32, round, 9, {t1, t2});
            const uint32_t new_e =
                push(ProgramOpcode::Add32, round, 10, {old[3], t1});
            state = {new_a, old[0], old[1], old[2],
                     new_e, old[4], old[5], old[6]};
        }
        for (uint32_t lane = 0; lane < 8; ++lane) {
            out.final_addresses.push_back(
                push(ProgramOpcode::Add32, 64, lane,
                     {initial[lane], state[lane]}));
        }
        return out;
    }

    if (kind == ProgramKind::ChaCha20Block) {
        std::array<uint32_t, 16> initial{};
        for (auto& address : initial) address = external();
        out.external_address_count = next_address - 1;
        std::array<uint32_t, 16> state = initial;
        static constexpr uint32_t COLUMN[4][4]{
            {0, 4, 8, 12}, {1, 5, 9, 13},
            {2, 6, 10, 14}, {3, 7, 11, 15}};
        static constexpr uint32_t DIAGONAL[4][4]{
            {0, 5, 10, 15}, {1, 6, 11, 12},
            {2, 7, 8, 13}, {3, 4, 9, 14}};
        auto quarter = [&](uint32_t q, const uint32_t lane[4]) {
            const uint32_t a = lane[0], b = lane[1], c = lane[2], d = lane[3];
            state[a] = push(ProgramOpcode::Add32, q, 0, {state[a], state[b]});
            state[d] = push(ProgramOpcode::XorRot32, q, 1, {state[d], state[a]}, 16);
            state[c] = push(ProgramOpcode::Add32, q, 2, {state[c], state[d]});
            state[b] = push(ProgramOpcode::XorRot32, q, 3, {state[b], state[c]}, 12);
            state[a] = push(ProgramOpcode::Add32, q, 4, {state[a], state[b]});
            state[d] = push(ProgramOpcode::XorRot32, q, 5, {state[d], state[a]}, 8);
            state[c] = push(ProgramOpcode::Add32, q, 6, {state[c], state[d]});
            state[b] = push(ProgramOpcode::XorRot32, q, 7, {state[b], state[c]}, 7);
        };
        uint32_t quarter_index = 0;
        for (uint32_t double_round = 0; double_round < 10; ++double_round) {
            for (const auto& lanes : COLUMN) quarter(quarter_index++, lanes);
            for (const auto& lanes : DIAGONAL) quarter(quarter_index++, lanes);
        }
        for (uint32_t lane = 0; lane < 16; ++lane) {
            out.final_addresses.push_back(
                push(ProgramOpcode::Add32, 80, lane,
                     {state[lane], initial[lane]}));
        }
    }
    return out;
}

bool ValidateCanonicalProgram(const FixedProgram& program, std::string* why)
{
    if (program.kind != ProgramKind::Sha256Compression &&
        program.kind != ProgramKind::ChaCha20Block) {
        return Fail(why, "unknown_program");
    }
    if (program != BuildCanonicalProgram(program.kind)) {
        return Fail(why, "noncanonical_program");
    }
    return true;
}

Spec ProgramRowSpec(const ProgramRow& row, uint32_t n_rows)
{
    Spec out;
    out.n_rows = n_rows;
    switch (row.opcode) {
    case ProgramOpcode::Add32:
        out.family = Family::Add32;
        break;
    case ProgramOpcode::XorRot32:
        out.family = Family::XorRot32;
        out.rotate_left = row.rotate_left;
        break;
    case ProgramOpcode::ShaChoice32:
        out.family = Family::ShaChoice32;
        break;
    case ProgramOpcode::ShaMajority32:
        out.family = Family::ShaMajority32;
        break;
    case ProgramOpcode::ShaSmallSigma0:
        out.family = Family::ShaXor3Transform32;
        out.transforms = {{
            {BitTransformKind::RotateRight, 7},
            {BitTransformKind::RotateRight, 18},
            {BitTransformKind::ShiftRight, 3},
        }};
        break;
    case ProgramOpcode::ShaSmallSigma1:
        out.family = Family::ShaXor3Transform32;
        out.transforms = {{
            {BitTransformKind::RotateRight, 17},
            {BitTransformKind::RotateRight, 19},
            {BitTransformKind::ShiftRight, 10},
        }};
        break;
    case ProgramOpcode::ShaBigSigma0:
        out.family = Family::ShaXor3Transform32;
        out.transforms = {{
            {BitTransformKind::RotateRight, 2},
            {BitTransformKind::RotateRight, 13},
            {BitTransformKind::RotateRight, 22},
        }};
        break;
    case ProgramOpcode::ShaBigSigma1:
        out.family = Family::ShaXor3Transform32;
        out.transforms = {{
            {BitTransformKind::RotateRight, 6},
            {BitTransformKind::RotateRight, 11},
            {BitTransformKind::RotateRight, 25},
        }};
        break;
    }
    return out;
}

RCStage3CtlSchedule BuildProgramCtlSchedule(
    const FixedProgram& program, uint32_t namespace_id)
{
    RCStage3CtlSchedule out;
    if (namespace_id == 0) return out;
    std::string ignored;
    if (!ValidateCanonicalProgram(program, &ignored)) return out;
    size_t total = 0;
    for (const auto& row : program.rows) total += 2 * row.input_count;
    out.events.reserve(total);
    for (uint32_t stage = 0; stage < program.rows.size(); ++stage) {
        const auto& row = program.rows[stage];
        for (uint32_t input = 0; input < row.input_count; ++input) {
            const uint32_t address = row.input_address[input];
            out.events.push_back({namespace_id, stage, address, 1});
            out.events.push_back({namespace_id, stage, address, -1});
        }
    }
    return out;
}

bool BuildProgramWitness(const FixedProgram& program,
                         const std::vector<uint32_t>& external_values,
                         ProgramWitness& out, std::string* why)
{
    out = {};
    if (!ValidateCanonicalProgram(program, why)) return false;
    if (external_values.size() != program.external_address_count) {
        return Fail(why, "external_value_count");
    }
    const uint32_t max_address =
        program.rows.empty() ? program.external_address_count
                             : program.rows.back().output_address;
    out.address_values.assign(max_address + 1, 0);
    for (uint32_t i = 0; i < external_values.size(); ++i) {
        out.address_values[i + 1] = external_values[i];
    }
    out.instruction_outputs.reserve(program.rows.size());
    size_t ctl_count = 0;
    for (const auto& row : program.rows) ctl_count += 2 * row.input_count;
    out.ctl_values.reserve(ctl_count);

    for (const auto& row : program.rows) {
        std::array<uint32_t, 3> in{};
        for (uint32_t i = 0; i < row.input_count; ++i) {
            if (row.input_address[i] == 0 ||
                row.input_address[i] >= out.address_values.size() ||
                row.input_address[i] >= row.output_address) {
                return Fail(why, "non_ssa_input");
            }
            in[i] = out.address_values[row.input_address[i]];
            const Fp3 value = U(in[i]);
            out.ctl_values.push_back(value);
            out.ctl_values.push_back(value);
        }

        uint32_t value = 0;
        switch (row.opcode) {
        case ProgramOpcode::Add32:
            value = in[0] + in[1];
            break;
        case ProgramOpcode::XorRot32:
            value = Rotl32(in[0] ^ in[1], row.rotate_left);
            break;
        case ProgramOpcode::ShaChoice32:
            value = (in[0] & in[1]) ^ (~in[0] & in[2]);
            break;
        case ProgramOpcode::ShaMajority32:
            value = (in[0] & in[1]) ^ (in[0] & in[2]) ^
                    (in[1] & in[2]);
            break;
        case ProgramOpcode::ShaSmallSigma0:
        case ProgramOpcode::ShaSmallSigma1:
        case ProgramOpcode::ShaBigSigma0:
        case ProgramOpcode::ShaBigSigma1: {
            const Spec spec = ProgramRowSpec(row, 2);
            value = Transform(in[0], spec.transforms[0]) ^
                    Transform(in[0], spec.transforms[1]) ^
                    Transform(in[0], spec.transforms[2]);
            break;
        }
        }
        if (row.output_address == 0 ||
            row.output_address >= out.address_values.size()) {
            return Fail(why, "bad_output_address");
        }
        out.address_values[row.output_address] = value;
        out.instruction_outputs.push_back(value);
    }
    out.final_words.reserve(program.final_addresses.size());
    for (const uint32_t address : program.final_addresses) {
        if (address == 0 || address >= out.address_values.size()) {
            return Fail(why, "bad_final_address");
        }
        out.final_words.push_back(out.address_values[address]);
    }
    return true;
}

bool BuildProgramInstructionShards(
    const FixedProgram& program, const ProgramWitness& witness,
    std::vector<ProgramInstructionShard>& out, std::string* why)
{
    out.clear();
    if (!ValidateCanonicalProgram(program, why)) return false;
    if (witness.instruction_outputs.size() != program.rows.size() ||
        witness.address_values.empty()) {
        return Fail(why, "program_witness_shape");
    }
    auto same = [](const Spec& a, const Spec& b) {
        return a.family == b.family &&
               a.rotate_left == b.rotate_left &&
               a.transforms == b.transforms;
    };
    for (uint32_t row_index = 0; row_index < program.rows.size(); ++row_index) {
        Spec key = ProgramRowSpec(program.rows[row_index], 2);
        auto it = std::find_if(
            out.begin(), out.end(),
            [&](const ProgramInstructionShard& shard) {
                return same(shard.spec, key);
            });
        if (it == out.end()) {
            ProgramInstructionShard shard;
            shard.spec = key;
            out.push_back(std::move(shard));
            it = std::prev(out.end());
        }
        it->program_rows.push_back(row_index);
    }

    for (auto& shard : out) {
        uint32_t n_rows = 2;
        while (n_rows < shard.program_rows.size()) n_rows <<= 1;
        shard.spec.n_rows = n_rows;
        Inputs inputs;
        inputs.a.assign(n_rows, 0);
        inputs.b.assign(n_rows, 0);
        inputs.c.assign(n_rows, 0);
        for (uint32_t local = 0; local < shard.program_rows.size(); ++local) {
            const uint32_t program_row = shard.program_rows[local];
            const auto& row = program.rows[program_row];
            const auto get = [&](uint32_t operand) {
                const uint32_t address = row.input_address[operand];
                return address < witness.address_values.size()
                    ? witness.address_values[address] : 0U;
            };
            inputs.a[local] = get(0);
            if (row.input_count > 1) inputs.b[local] = get(1);
            if (row.input_count > 2) inputs.c[local] = get(2);
        }
        if (!BuildWitness(shard.spec, inputs, shard.witness, why)) return false;
        for (uint32_t local = 0; local < shard.program_rows.size(); ++local) {
            if (shard.witness.output[local] !=
                witness.instruction_outputs[shard.program_rows[local]]) {
                return Fail(why, "instruction_output_mismatch");
            }
        }
    }
    return true;
}

namespace {

uint32_t OpcodeSelector(const ProgramRow& row)
{
    switch (row.opcode) {
    case ProgramOpcode::Add32: return 0;
    case ProgramOpcode::XorRot32:
        switch (row.rotate_left) {
        case 16: return 1;
        case 12: return 2;
        case 8: return 3;
        case 7: return 4;
        default: return kFixedProgramOpcodeCount;
        }
    case ProgramOpcode::ShaChoice32: return 5;
    case ProgramOpcode::ShaMajority32: return 6;
    case ProgramOpcode::ShaSmallSigma0: return 7;
    case ProgramOpcode::ShaSmallSigma1: return 8;
    case ProgramOpcode::ShaBigSigma0: return 9;
    case ProgramOpcode::ShaBigSigma1: return 10;
    }
    return kFixedProgramOpcodeCount;
}

uint32_t OutputWordSlot(const ProgramRow& row)
{
    switch (row.opcode) {
    case ProgramOpcode::ShaChoice32:
    case ProgramOpcode::ShaMajority32:
        return 3;
    case ProgramOpcode::ShaSmallSigma0:
    case ProgramOpcode::ShaSmallSigma1:
    case ProgramOpcode::ShaBigSigma0:
    case ProgramOpcode::ShaBigSigma1:
        return 1;
    default:
        return 2;
    }
}

std::array<BitTransform, 3> SelectorTransforms(uint32_t selector)
{
    switch (selector) {
    case 7:
        return {{{BitTransformKind::RotateRight, 7},
                 {BitTransformKind::RotateRight, 18},
                 {BitTransformKind::ShiftRight, 3}}};
    case 8:
        return {{{BitTransformKind::RotateRight, 17},
                 {BitTransformKind::RotateRight, 19},
                 {BitTransformKind::ShiftRight, 10}}};
    case 9:
        return {{{BitTransformKind::RotateRight, 2},
                 {BitTransformKind::RotateRight, 13},
                 {BitTransformKind::RotateRight, 22}}};
    default:
        return {{{BitTransformKind::RotateRight, 6},
                 {BitTransformKind::RotateRight, 11},
                 {BitTransformKind::RotateRight, 25}}};
    }
}

uint32_t NextPow2(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

uint32_t LaneColumn(uint32_t base, uint32_t column)
{
    return base + column;
}

Fp3 TransformBitAt(const std::vector<Fp3>& cur, uint32_t base,
                   uint32_t out, const BitTransform& transform)
{
    if (transform.kind == BitTransformKind::RotateRight) {
        return cur[LaneColumn(
            base, BitColumn(0, (out + transform.amount) & 31U))];
    }
    const uint32_t source = out + transform.amount;
    return source < 32
        ? cur[LaneColumn(base, BitColumn(0, source))]
        : Fp3::Zero();
}

void AddFixedProgramWordAt(
    aq::AirConstraintSystem<Fp3>& out, uint32_t base, uint32_t word)
{
    for (uint32_t bit = 0; bit < 32; ++bit) {
        Add(out, "stage3.hash.program.packed.word.bit_boolean", 2,
            [base, word, bit](const std::vector<Fp3>& cur,
                              const std::vector<Fp3>&) {
                return Bool(cur[LaneColumn(base, BitColumn(word, bit))]);
            });
    }
    Add(out, "stage3.hash.program.packed.word.recompose", 1,
        [base, word](const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = gf::Add(
                    sum,
                    gf::Mul(
                        U(uint64_t{1} << bit),
                        cur[LaneColumn(base, BitColumn(word, bit))]));
            }
            return gf::Sub(
                sum, cur[LaneColumn(base, ValueColumn(word))]);
        });
}

void AddFixedProgramCoreAt(
    const FixedProgram& program, aq::AirConstraintSystem<Fp3>& out,
    uint32_t base)
{
    for (uint32_t word = 0; word < 4; ++word) {
        AddFixedProgramWordAt(out, base, word);
    }
    for (uint32_t selector = 0; selector < kFixedProgramOpcodeCount;
         ++selector) {
        std::vector<Fp3> values(out.n_rows, Fp3::Zero());
        for (uint32_t row = 0; row < program.rows.size(); ++row) {
            if (OpcodeSelector(program.rows[row]) == selector) {
                values[row] = Fp3::One();
            }
        }
        out.preprocessed.push_back(
            {LaneColumn(base, kFixedProgramSelectorBase + selector),
             std::move(values)});
    }
    Add(out, "stage3.hash.program.packed.carry_boolean", 2,
        [base](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            return Bool(cur[LaneColumn(base, kFixedProgramCarryColumn)]);
        });
    Add(out, "stage3.hash.program.packed.selector_sum", 2,
        [base](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t i = 0; i < kFixedProgramOpcodeCount; ++i) {
                sum = gf::Add(
                    sum,
                    cur[LaneColumn(base, kFixedProgramSelectorBase + i)]);
            }
            return Bool(sum);
        });
    for (uint32_t word = 0; word < 4; ++word) {
        Add(out, "stage3.hash.program.packed.padding_zero", 2,
            [base, word](const std::vector<Fp3>& cur,
                         const std::vector<Fp3>&) {
                Fp3 active = Fp3::Zero();
                for (uint32_t i = 0; i < kFixedProgramOpcodeCount; ++i) {
                    active = gf::Add(
                        active,
                        cur[LaneColumn(
                            base, kFixedProgramSelectorBase + i)]);
                }
                return gf::Mul(
                    gf::Sub(Fp3::One(), active),
                    cur[LaneColumn(base, ValueColumn(word))]);
            });
    }
    Add(out, "stage3.hash.program.packed.add_carry_zero", 2,
        [base](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[LaneColumn(base, kFixedProgramSelectorBase)]),
                cur[LaneColumn(base, kFixedProgramCarryColumn)]);
        });
    Add(out, "stage3.hash.program.packed.add", 2,
        [base](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            const Fp3 residual = gf::Sub(
                gf::Sub(
                    gf::Add(
                        cur[LaneColumn(base, ValueColumn(0))],
                        cur[LaneColumn(base, ValueColumn(1))]),
                    cur[LaneColumn(base, ValueColumn(2))]),
                gf::Mul(
                    U(uint64_t{1} << 32),
                    cur[LaneColumn(base, kFixedProgramCarryColumn)]));
            return gf::Mul(
                cur[LaneColumn(base, kFixedProgramSelectorBase)],
                residual);
        });
    static constexpr uint8_t ROTS[4]{16, 12, 8, 7};
    for (uint32_t which = 0; which < 4; ++which) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.program.packed.xor_rot", 3,
                [base, which, bit](const std::vector<Fp3>& cur,
                                   const std::vector<Fp3>&) {
                    const uint32_t source =
                        (bit + 32 - ROTS[which]) & 31U;
                    const Fp3 residual = gf::Sub(
                        cur[LaneColumn(base, BitColumn(2, bit))],
                        Xor2(
                            cur[LaneColumn(
                                base, BitColumn(0, source))],
                            cur[LaneColumn(
                                base, BitColumn(1, source))]));
                    return gf::Mul(
                        cur[LaneColumn(
                            base,
                            kFixedProgramSelectorBase + 1 + which)],
                        residual);
                });
        }
    }
    for (uint32_t bit = 0; bit < 32; ++bit) {
        Add(out, "stage3.hash.program.packed.choice", 3,
            [base, bit](const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[LaneColumn(
                        base, kFixedProgramSelectorBase + 5)],
                    gf::Sub(
                        cur[LaneColumn(base, BitColumn(3, bit))],
                        Choice(
                            cur[LaneColumn(base, BitColumn(0, bit))],
                            cur[LaneColumn(base, BitColumn(1, bit))],
                            cur[LaneColumn(base, BitColumn(2, bit))])));
            });
        Add(out, "stage3.hash.program.packed.majority", 4,
            [base, bit](const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[LaneColumn(
                        base, kFixedProgramSelectorBase + 6)],
                    gf::Sub(
                        cur[LaneColumn(base, BitColumn(3, bit))],
                        Majority(
                            cur[LaneColumn(base, BitColumn(0, bit))],
                            cur[LaneColumn(base, BitColumn(1, bit))],
                            cur[LaneColumn(base, BitColumn(2, bit))])));
            });
    }
    for (uint32_t which = 0; which < 4; ++which) {
        const auto transforms = SelectorTransforms(7 + which);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.program.packed.sigma", 4,
                [base, which, bit, transforms](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 residual = gf::Sub(
                        cur[LaneColumn(base, BitColumn(1, bit))],
                        Xor3(
                            TransformBitAt(
                                cur, base, bit, transforms[0]),
                            TransformBitAt(
                                cur, base, bit, transforms[1]),
                            TransformBitAt(
                                cur, base, bit, transforms[2])));
                    return gf::Mul(
                        cur[LaneColumn(
                            base,
                            kFixedProgramSelectorBase + 7 + which)],
                        residual);
                });
        }
    }
    Add(out, "stage3.hash.program.packed.unused_word3", 2,
        [base](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            const Fp3 use_word3 = gf::Add(
                cur[LaneColumn(
                    base, kFixedProgramSelectorBase + 5)],
                cur[LaneColumn(
                    base, kFixedProgramSelectorBase + 6)]);
            return gf::Mul(
                gf::Sub(Fp3::One(), use_word3),
                cur[LaneColumn(base, ValueColumn(3))]);
        });
    Add(out, "stage3.hash.program.packed.sigma_unused_word2", 2,
        [base](const std::vector<Fp3>& cur,
               const std::vector<Fp3>&) {
            Fp3 selected = Fp3::Zero();
            for (uint32_t i = 7; i <= 10; ++i) {
                selected = gf::Add(
                    selected,
                    cur[LaneColumn(
                        base, kFixedProgramSelectorBase + i)]);
            }
            return gf::Mul(
                selected, cur[LaneColumn(base, ValueColumn(2))]);
        });
}

} // namespace

bool BuildFixedProgramConstraintSystem(
    const FixedProgram& program, aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ValidateCanonicalProgram(program, why)) return false;
    out.n_rows = NextPow2(program.rows.size());
    out.n_columns = kFixedProgramColumns;
    for (uint32_t word = 0; word < 4; ++word) AddWord(out, word);
    for (uint32_t selector = 0; selector < kFixedProgramOpcodeCount;
         ++selector) {
        std::vector<Fp3> values(out.n_rows, Fp3::Zero());
        for (uint32_t row = 0; row < program.rows.size(); ++row) {
            if (OpcodeSelector(program.rows[row]) == selector) {
                values[row] = Fp3::One();
            }
        }
        out.preprocessed.push_back(
            {kFixedProgramSelectorBase + selector, std::move(values)});
    }
    out.preprocessed_pin_ood = true;
    Add(out, "stage3.hash.program.carry_boolean", 2,
        [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return Bool(cur[kFixedProgramCarryColumn]);
        });
    Add(out, "stage3.hash.program.selector_sum", 2,
        [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t i = 0; i < kFixedProgramOpcodeCount; ++i) {
                sum = gf::Add(sum, cur[kFixedProgramSelectorBase + i]);
            }
            return Bool(sum);
        });
    for (uint32_t word = 0; word < 4; ++word) {
        Add(out, "stage3.hash.program.padding_zero", 2,
            [word](const std::vector<Fp3>& cur,
                   const std::vector<Fp3>&) {
                Fp3 active = Fp3::Zero();
                for (uint32_t i = 0; i < kFixedProgramOpcodeCount; ++i) {
                    active = gf::Add(
                        active, cur[kFixedProgramSelectorBase + i]);
                }
                return gf::Mul(
                    gf::Sub(Fp3::One(), active),
                    cur[ValueColumn(word)]);
            });
    }
    Add(out, "stage3.hash.program.add_carry_zero", 2,
        [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(Fp3::One(), cur[kFixedProgramSelectorBase]),
                cur[kFixedProgramCarryColumn]);
        });
    Add(out, "stage3.hash.program.add", 2,
        [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            const Fp3 residual = gf::Sub(
                gf::Sub(
                    gf::Add(cur[ValueColumn(0)], cur[ValueColumn(1)]),
                    cur[ValueColumn(2)]),
                gf::Mul(U(uint64_t{1} << 32),
                        cur[kFixedProgramCarryColumn]));
            return gf::Mul(cur[kFixedProgramSelectorBase], residual);
        });
    static constexpr uint8_t ROTS[4]{16, 12, 8, 7};
    for (uint32_t which = 0; which < 4; ++which) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.program.xor_rot", 3,
                [which, bit](const std::vector<Fp3>& cur,
                             const std::vector<Fp3>&) {
                    const uint32_t source =
                        (bit + 32 - ROTS[which]) & 31U;
                    const Fp3 residual = gf::Sub(
                        cur[BitColumn(2, bit)],
                        Xor2(cur[BitColumn(0, source)],
                             cur[BitColumn(1, source)]));
                    return gf::Mul(
                        cur[kFixedProgramSelectorBase + 1 + which],
                        residual);
                });
        }
    }
    for (uint32_t bit = 0; bit < 32; ++bit) {
        Add(out, "stage3.hash.program.choice", 3,
            [bit](const std::vector<Fp3>& cur,
                  const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[kFixedProgramSelectorBase + 5],
                    gf::Sub(cur[BitColumn(3, bit)],
                            Choice(cur[BitColumn(0, bit)],
                                   cur[BitColumn(1, bit)],
                                   cur[BitColumn(2, bit)])));
            });
        Add(out, "stage3.hash.program.majority", 4,
            [bit](const std::vector<Fp3>& cur,
                  const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[kFixedProgramSelectorBase + 6],
                    gf::Sub(cur[BitColumn(3, bit)],
                            Majority(cur[BitColumn(0, bit)],
                                     cur[BitColumn(1, bit)],
                                     cur[BitColumn(2, bit)])));
            });
    }
    for (uint32_t which = 0; which < 4; ++which) {
        const auto transforms = SelectorTransforms(7 + which);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            Add(out, "stage3.hash.program.sigma", 4,
                [which, bit, transforms](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 residual = gf::Sub(
                        cur[BitColumn(1, bit)],
                        Xor3(
                            TransformBit(cur, bit, transforms[0]),
                            TransformBit(cur, bit, transforms[1]),
                            TransformBit(cur, bit, transforms[2])));
                    return gf::Mul(
                        cur[kFixedProgramSelectorBase + 7 + which],
                        residual);
                });
        }
    }
    Add(out, "stage3.hash.program.unused_word3", 2,
        [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            const Fp3 use_word3 = gf::Add(
                cur[kFixedProgramSelectorBase + 5],
                cur[kFixedProgramSelectorBase + 6]);
            return gf::Mul(
                gf::Sub(Fp3::One(), use_word3),
                cur[ValueColumn(3)]);
        });
    Add(out, "stage3.hash.program.sigma_unused_word2", 2,
        [](const std::vector<Fp3>& cur, const std::vector<Fp3>&) {
            Fp3 selected = Fp3::Zero();
            for (uint32_t i = 7; i <= 10; ++i) {
                selected = gf::Add(
                    selected, cur[kFixedProgramSelectorBase + i]);
            }
            return gf::Mul(selected, cur[ValueColumn(2)]);
        });
    return true;
}

bool BuildFixedProgramAirWitness(
    const FixedProgram& program, const ProgramWitness& witness,
    std::vector<std::vector<Fp3>>& columns, std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramConstraintSystem(program, cs, why)) return false;
    if (witness.instruction_outputs.size() != program.rows.size()) {
        return Fail(why, "fixed_program_witness_shape");
    }
    columns.assign(
        cs.n_columns, std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (uint32_t row_index = 0; row_index < program.rows.size(); ++row_index) {
        const auto& row = program.rows[row_index];
        std::array<uint32_t, 4> words{};
        for (uint32_t i = 0; i < row.input_count; ++i) {
            const uint32_t address = row.input_address[i];
            if (address >= witness.address_values.size()) {
                return Fail(why, "fixed_program_bad_input");
            }
            words[i] = witness.address_values[address];
        }
        switch (row.opcode) {
        case ProgramOpcode::ShaChoice32:
        case ProgramOpcode::ShaMajority32:
            words[3] = witness.instruction_outputs[row_index];
            break;
        case ProgramOpcode::ShaSmallSigma0:
        case ProgramOpcode::ShaSmallSigma1:
        case ProgramOpcode::ShaBigSigma0:
        case ProgramOpcode::ShaBigSigma1:
            words[1] = witness.instruction_outputs[row_index];
            break;
        default:
            words[2] = witness.instruction_outputs[row_index];
            break;
        }
        for (uint32_t word = 0; word < 4; ++word) {
            columns[ValueColumn(word)][row_index] = U(words[word]);
            for (uint32_t bit = 0; bit < 32; ++bit) {
                columns[BitColumn(word, bit)][row_index] =
                    U((words[word] >> bit) & 1U);
            }
        }
        if (row.opcode == ProgramOpcode::Add32) {
            const uint64_t sum = uint64_t{words[0]} + words[1];
            columns[kFixedProgramCarryColumn][row_index] = U(sum >> 32);
        }
        const uint32_t selector = OpcodeSelector(row);
        if (selector >= kFixedProgramOpcodeCount) {
            return Fail(why, "fixed_program_opcode");
        }
        columns[kFixedProgramSelectorBase + selector][row_index] =
            Fp3::One();
    }
    return true;
}

uint256 CommitFixedProgram(const FixedProgram& program)
{
    std::string ignored;
    if (!ValidateCanonicalProgram(program, &ignored)) return {};
    std::vector<uint8_t> bytes;
    bytes.push_back(static_cast<uint8_t>(program.kind));
    AppendU32(bytes, program.external_address_count);
    AppendU32(bytes, program.rows.size());
    for (const auto& row : program.rows) {
        bytes.push_back(static_cast<uint8_t>(row.opcode));
        bytes.push_back(static_cast<uint8_t>(row.round));
        bytes.push_back(static_cast<uint8_t>(row.round >> 8));
        bytes.push_back(static_cast<uint8_t>(row.step));
        bytes.push_back(static_cast<uint8_t>(row.step >> 8));
        bytes.push_back(row.rotate_left);
        bytes.push_back(row.input_count);
        for (uint32_t address : row.input_address) {
            AppendU32(bytes, address);
        }
        AppendU32(bytes, row.output_address);
    }
    AppendU32(bytes, program.final_addresses.size());
    for (uint32_t address : program.final_addresses) {
        AppendU32(bytes, address);
    }
    return Sha256dTagged("BTX_RC_STAGE3_FIXED_HASH_PROGRAM_V1", bytes);
}

uint256 CommitFixedProgramBoundaryStatement(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words)
{
    if (external_values.size() != program.external_address_count ||
        final_words.size() != program.final_addresses.size()) {
        return {};
    }
    const uint256 program_commitment = CommitFixedProgram(program);
    if (program_commitment.IsNull()) return {};
    std::vector<uint8_t> bytes;
    AppendHash(bytes, program_commitment);
    AppendU32(bytes, external_values.size());
    for (uint32_t value : external_values) AppendU32(bytes, value);
    AppendU32(bytes, final_words.size());
    for (uint32_t value : final_words) AppendU32(bytes, value);
    return Sha256dTagged(
        "BTX_RC_STAGE3_FIXED_HASH_BOUNDARY_STATEMENT_V1", bytes);
}

bool BuildFixedProgramBoundaryConstraintSystem(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!BuildFixedProgramConstraintSystem(program, out, why)) return false;
    if (external_values.size() != program.external_address_count) {
        return Fail(why, "fixed_program_boundary_external_count");
    }
    if (final_words.size() != program.final_addresses.size()) {
        return Fail(why, "fixed_program_boundary_final_count");
    }

    out.n_columns = kFixedProgramBoundaryColumns;
    std::array<std::vector<Fp3>, 4> expected;
    std::array<std::vector<Fp3>, 4> mask;
    for (uint32_t word = 0; word < 4; ++word) {
        expected[word].assign(out.n_rows, Fp3::Zero());
        mask[word].assign(out.n_rows, Fp3::Zero());
    }

    for (uint32_t row_index = 0; row_index < program.rows.size();
         ++row_index) {
        const auto& row = program.rows[row_index];
        for (uint32_t input = 0; input < row.input_count; ++input) {
            const uint32_t address = row.input_address[input];
            if (address > 0 &&
                address <= program.external_address_count) {
                expected[input][row_index] =
                    U(external_values[address - 1]);
                mask[input][row_index] = Fp3::One();
            }
        }
        const auto final = std::find(
            program.final_addresses.begin(),
            program.final_addresses.end(), row.output_address);
        if (final != program.final_addresses.end()) {
            const uint32_t word = OutputWordSlot(row);
            const size_t index =
                static_cast<size_t>(final - program.final_addresses.begin());
            expected[word][row_index] = U(final_words[index]);
            mask[word][row_index] = Fp3::One();
        }
    }

    for (uint32_t word = 0; word < 4; ++word) {
        out.preprocessed.push_back(
            {kFixedProgramBoundaryExpectedBase + word,
             std::move(expected[word])});
        out.preprocessed.push_back(
            {kFixedProgramBoundaryMaskBase + word,
             std::move(mask[word])});
        Add(out, "stage3.hash.program.public_boundary", 2,
            [word](const std::vector<Fp3>& cur,
                   const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[kFixedProgramBoundaryMaskBase + word],
                    gf::Sub(
                        cur[ValueColumn(word)],
                        cur[kFixedProgramBoundaryExpectedBase + word]));
            });
    }
    out.preprocessed_pin_ood = true;
    return true;
}

bool BuildFixedProgramBoundaryAirWitness(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    columns.clear();
    if (witness.address_values.size() <=
        program.external_address_count) {
        return Fail(why, "fixed_program_boundary_address_shape");
    }
    for (uint32_t i = 0; i < external_values.size(); ++i) {
        if (witness.address_values[i + 1] != external_values[i]) {
            return Fail(why, "fixed_program_boundary_external_mismatch");
        }
    }
    if (witness.final_words != final_words) {
        return Fail(why, "fixed_program_boundary_final_mismatch");
    }

    if (!BuildFixedProgramAirWitness(program, witness, columns, why)) {
        return false;
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramBoundaryConstraintSystem(
            program, external_values, final_words, cs, why)) {
        return false;
    }
    columns.resize(
        cs.n_columns, std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        if (column >= kFixedProgramColumns) columns[column] = values;
    }
    return true;
}

namespace {

constexpr uint32_t kFixedProgramProvenanceBusId = 0x48505231U;

void AddKind(
    aq::AirConstraintSystem<Fp3>& cs, const char* name,
    aq::AirKind kind, uint32_t degree,
    std::function<Fp3(const std::vector<Fp3>&,
                      const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

Fp3 FixedProgramOutputValue(const std::vector<Fp3>& row)
{
    Fp3 word1_selector = Fp3::Zero();
    for (uint32_t selector = 7; selector <= 10; ++selector) {
        word1_selector = gf::Add(
            word1_selector,
            row[kFixedProgramSelectorBase + selector]);
    }
    Fp3 word2_selector = Fp3::Zero();
    for (uint32_t selector = 0; selector <= 4; ++selector) {
        word2_selector = gf::Add(
            word2_selector,
            row[kFixedProgramSelectorBase + selector]);
    }
    const Fp3 word3_selector = gf::Add(
        row[kFixedProgramSelectorBase + 5],
        row[kFixedProgramSelectorBase + 6]);
    return gf::Add(
        gf::Mul(word1_selector, row[ValueColumn(1)]),
        gf::Add(
            gf::Mul(word2_selector, row[ValueColumn(2)]),
            gf::Mul(word3_selector, row[ValueColumn(3)])));
}

uint64_t FixedProgramInternalEdgeCount(const FixedProgram& program)
{
    uint64_t edges{0};
    for (const auto& row : program.rows) {
        for (uint32_t input = 0; input < row.input_count; ++input) {
            if (row.input_address[input] >
                program.external_address_count) {
                ++edges;
            }
        }
    }
    return edges;
}

std::vector<std::vector<Fp3>> FixedProgramProvenanceMetadata(
    const FixedProgram& program, uint32_t n_rows)
{
    std::vector<std::vector<Fp3>> metadata(
        kFixedProgramProvenanceBaseColumns -
            kFixedProgramBoundaryColumns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    if (program.rows.empty()) return metadata;

    const uint32_t max_address =
        program.rows.back().output_address;
    std::vector<uint32_t> use_count(max_address + 1, 0);
    for (const auto& row : program.rows) {
        for (uint32_t input = 0; input < row.input_count; ++input) {
            const uint32_t address = row.input_address[input];
            if (address > program.external_address_count &&
                address < use_count.size()) {
                ++use_count[address];
            }
        }
    }
    const auto set =
        [&](uint32_t absolute_column, uint32_t row,
            uint64_t value) {
            metadata[
                absolute_column -
                kFixedProgramBoundaryColumns][row] = U(value);
        };
    for (uint32_t row_index = 0;
         row_index < program.rows.size(); ++row_index) {
        const auto& row = program.rows[row_index];
        const uint32_t uses =
            row.output_address < use_count.size()
            ? use_count[row.output_address] : 0;
        set(kFixedProgramProvenanceOutputAddress,
            row_index, row.output_address);
        set(kFixedProgramProvenanceOutputUseCount,
            row_index, uses);
        set(kFixedProgramProvenanceOutputHasUse,
            row_index, uses != 0);
        for (uint32_t input = 0; input < 3; ++input) {
            if (input >= row.input_count) continue;
            const uint32_t address = row.input_address[input];
            if (address <= program.external_address_count) {
                continue;
            }
            set(kFixedProgramProvenanceInputAddressBase + input,
                row_index, address);
            set(kFixedProgramProvenanceInputMaskBase + input,
                row_index, 1);
        }
    }
    return metadata;
}

uint256 FixedProgramProvenanceTraceCommitment(
    const FixedProgram& program,
    const uint256& boundary_statement,
    uint32_t n_rows, uint32_t n_coeffs,
    const std::vector<uint256>& base_roots)
{
    if (boundary_statement.IsNull() ||
        base_roots.size() !=
            kFixedProgramProvenanceBaseColumns) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_FIXED_HASH_PROVENANCE_TRACE_V1";
    hash << CommitFixedProgram(program);
    hash << boundary_statement;
    hash << n_rows;
    hash << n_coeffs;
    for (const auto& root : base_roots) hash << root;
    return hash.GetHash();
}

bool DeriveFixedProgramProvenanceChallenges(
    const FixedProgram& program,
    const uint256& boundary_statement,
    const uint256& fs_seed,
    uint32_t n_rows, uint32_t n_coeffs,
    const std::vector<uint256>& base_roots,
    RCStage3CtlChallenges& challenges,
    std::string* why)
{
    challenges = {};
    const uint64_t edges =
        FixedProgramInternalEdgeCount(program);
    const uint256 schedule_commitment =
        CommitFixedProgram(program);
    const uint256 trace_commitment =
        FixedProgramProvenanceTraceCommitment(
            program, boundary_statement, n_rows,
            n_coeffs, base_roots);
    if (edges == 0 ||
        edges > kRCStage3CtlMaxEvents / 2 ||
        fs_seed.IsNull() ||
        schedule_commitment.IsNull() ||
        trace_commitment.IsNull()) {
        return Fail(why, "provenance_challenge_context");
    }

    const RCStage3RelationRole role =
        program.kind == ProgramKind::Sha256Compression
        ? RCStage3RelationRole::EpisodeDigest
        : RCStage3RelationRole::EpisodeExtract;
    RCStage3CtlParticipantSpec participant;
    participant.role = role;
    participant.event_count = 2 * edges;
    participant.send_count = edges;
    participant.receive_count = edges;
    participant.schedule_commitment = schedule_commitment;
    RCStage3CtlManifest manifest;
    manifest.bus_id = kFixedProgramProvenanceBusId;
    manifest.transcript_seed = fs_seed;
    manifest.participants.push_back(participant);

    RCStage3CtlChildPin pin;
    pin.role = role;
    pin.bus_id = manifest.bus_id;
    pin.event_count = participant.event_count;
    pin.send_count = participant.send_count;
    pin.receive_count = participant.receive_count;
    pin.schedule_commitment = schedule_commitment;
    pin.trace_commitment = trace_commitment;
    return DeriveRCStage3CtlChallenges(
        manifest, {pin}, challenges, why);
}

Fp3 FixedProgramProvenanceContribution(
    const std::vector<Fp3>& row, uint32_t lane)
{
    const uint32_t producer_inverse =
        lane == 0
        ? kFixedProgramProvenanceProducerInverse1
        : kFixedProgramProvenanceProducerInverse2;
    const uint32_t consumer_base =
        lane == 0
        ? kFixedProgramProvenanceConsumerInverse1Base
        : kFixedProgramProvenanceConsumerInverse2Base;
    Fp3 contribution = gf::Mul(
        row[kFixedProgramProvenanceOutputUseCount],
        row[producer_inverse]);
    for (uint32_t input = 0; input < 3; ++input) {
        contribution = gf::Sub(
            contribution,
            gf::Mul(
                row[kFixedProgramProvenanceInputMaskBase + input],
                row[consumer_base + input]));
    }
    return contribution;
}

bool BuildFixedProgramProvenanceConstraintSystem(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const RCStage3CtlChallenges& challenges,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!BuildFixedProgramBoundaryConstraintSystem(
            program, external_values, final_words,
            out, why)) {
        return false;
    }
    out.n_columns = kFixedProgramProvenanceColumns;
    auto metadata =
        FixedProgramProvenanceMetadata(program, out.n_rows);
    for (uint32_t offset = 0;
         offset < metadata.size(); ++offset) {
        out.preprocessed.emplace_back(
            kFixedProgramBoundaryColumns + offset,
            std::move(metadata[offset]));
    }
    out.preprocessed_pin_ood = true;

    const std::array<Fp3, 2> gamma{
        challenges.gamma1, challenges.gamma2};
    const std::array<Fp3, 2> alpha{
        challenges.alpha1, challenges.alpha2};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t producer_inverse =
            lane == 0
            ? kFixedProgramProvenanceProducerInverse1
            : kFixedProgramProvenanceProducerInverse2;
        const uint32_t consumer_base =
            lane == 0
            ? kFixedProgramProvenanceConsumerInverse1Base
            : kFixedProgramProvenanceConsumerInverse2Base;
        const uint32_t running =
            lane == 0
            ? kFixedProgramProvenanceRunning1
            : kFixedProgramProvenanceRunning2;

        Add(out, "stage3.hash.provenance.producer_inverse",
            3, [lane, producer_inverse, gamma, alpha](
                   const std::vector<Fp3>& cur,
                   const std::vector<Fp3>&) {
                const Fp3 tuple = gf::Add(
                    cur[kFixedProgramProvenanceOutputAddress],
                    gf::Mul(gamma[lane],
                            FixedProgramOutputValue(cur)));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                return gf::Sub(
                    gf::Mul(
                        denominator, cur[producer_inverse]),
                    cur[kFixedProgramProvenanceOutputHasUse]);
            });
        Add(out, "stage3.hash.provenance.producer_padding",
            2, [producer_inverse](
                   const std::vector<Fp3>& cur,
                   const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[kFixedProgramProvenanceOutputHasUse]),
                    cur[producer_inverse]);
            });
        for (uint32_t input = 0; input < 3; ++input) {
            Add(out, "stage3.hash.provenance.consumer_inverse",
                2, [lane, input, consumer_base, gamma, alpha](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
                    const Fp3 tuple = gf::Add(
                        cur[kFixedProgramProvenanceInputAddressBase +
                            input],
                        gf::Mul(
                            gamma[lane],
                            cur[ValueColumn(input)]));
                    const Fp3 denominator =
                        gf::Sub(alpha[lane], tuple);
                    return gf::Sub(
                        gf::Mul(
                            denominator,
                            cur[consumer_base + input]),
                        cur[kFixedProgramProvenanceInputMaskBase +
                            input]);
                });
            Add(out, "stage3.hash.provenance.consumer_padding",
                2, [input, consumer_base](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[kFixedProgramProvenanceInputMaskBase +
                                input]),
                        cur[consumer_base + input]);
                });
        }
        AddKind(
            out, "stage3.hash.provenance.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const std::vector<Fp3>& cur,
                      const std::vector<Fp3>&) {
                return cur[running];
            });
        AddKind(
            out, "stage3.hash.provenance.running_transition",
            aq::AirKind::kTransition, 2,
            [lane, running](const std::vector<Fp3>& cur,
                            const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[running],
                    gf::Add(
                        cur[running],
                        FixedProgramProvenanceContribution(
                            cur, lane)));
            });
        AddKind(
            out, "stage3.hash.provenance.running_last",
            aq::AirKind::kLastRow, 2,
            [lane, running](const std::vector<Fp3>& cur,
                            const std::vector<Fp3>&) {
                return gf::Add(
                    cur[running],
                    FixedProgramProvenanceContribution(
                        cur, lane));
            });
    }
    return true;
}

std::vector<uint256> FixedProgramProvenanceBaseRoots(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs)
{
    if (columns.size() <
        kFixedProgramProvenanceBaseColumns) {
        return {};
    }
    std::vector<uint256> roots(
        kFixedProgramProvenanceBaseColumns);
    for (uint32_t column = 0;
         column < roots.size(); ++column) {
        roots[column] =
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], n_coeffs);
    }
    return roots;
}

} // namespace

FixedProgramProvenanceInstance
BuildFixedProgramProvenanceInstance(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed)
{
    FixedProgramProvenanceInstance out;
    out.boundary_statement =
        CommitFixedProgramBoundaryStatement(
            program, external_values, final_words);
    if (out.boundary_statement.IsNull() ||
        fs_seed.IsNull()) {
        out.note =
            "stage3:hash_air:provenance_statement";
        return out;
    }

    std::vector<std::vector<Fp3>> columns;
    std::string why;
    if (!BuildFixedProgramBoundaryAirWitness(
            program, witness, external_values,
            final_words, columns, &why)) {
        out.note = why;
        return out;
    }
    aq::AirConstraintSystem<Fp3> dummy;
    RCStage3CtlChallenges zero_challenges{};
    if (!BuildFixedProgramProvenanceConstraintSystem(
            program, external_values, final_words,
            zero_challenges, dummy, &why)) {
        out.note = why;
        return out;
    }
    columns.resize(
        kFixedProgramProvenanceBaseColumns,
        std::vector<Fp3>(dummy.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         dummy.preprocessed) {
        if (column >= kFixedProgramBoundaryColumns &&
            column <
                kFixedProgramProvenanceBaseColumns) {
            columns[column] = values;
        }
    }
    const uint32_t n_coeffs = FriNextPow2(
        std::max(dummy.n_rows, dummy.QuotientLen()));
    const auto base_roots =
        FixedProgramProvenanceBaseRoots(
            columns, n_coeffs);
    if (!DeriveFixedProgramProvenanceChallenges(
            program, out.boundary_statement, fs_seed,
            dummy.n_rows, n_coeffs,
            base_roots,
            out.challenges, &why) ||
        !BuildFixedProgramProvenanceConstraintSystem(
            program, external_values, final_words,
            out.challenges, out.cs, &why)) {
        out.note = why;
        return out;
    }
    columns.resize(
        out.cs.n_columns,
        std::vector<Fp3>(out.cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        if (column >= kFixedProgramBoundaryColumns) {
            columns[column] = values;
        }
    }

    std::array<Fp3, 2> running{
        Fp3::Zero(), Fp3::Zero()};
    const std::array<Fp3, 2> gamma{
        out.challenges.gamma1,
        out.challenges.gamma2};
    const std::array<Fp3, 2> alpha{
        out.challenges.alpha1,
        out.challenges.alpha2};
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        std::vector<Fp3> current(
            out.cs.n_columns, Fp3::Zero());
        for (uint32_t column = 0;
             column < out.cs.n_columns; ++column) {
            current[column] = columns[column][row];
        }
        for (uint32_t lane = 0; lane < 2; ++lane) {
            const uint32_t producer_inverse =
                lane == 0
                ? kFixedProgramProvenanceProducerInverse1
                : kFixedProgramProvenanceProducerInverse2;
            const uint32_t consumer_base =
                lane == 0
                ? kFixedProgramProvenanceConsumerInverse1Base
                : kFixedProgramProvenanceConsumerInverse2Base;
            const uint32_t running_column =
                lane == 0
                ? kFixedProgramProvenanceRunning1
                : kFixedProgramProvenanceRunning2;
            columns[running_column][row] = running[lane];

            if (!gf::IsZero(
                    current[
                        kFixedProgramProvenanceOutputHasUse])) {
                const Fp3 tuple = gf::Add(
                    current[
                        kFixedProgramProvenanceOutputAddress],
                    gf::Mul(
                        gamma[lane],
                        FixedProgramOutputValue(current)));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:"
                        "provenance_producer_pole";
                    return out;
                }
                columns[producer_inverse][row] =
                    gf::Inv(denominator);
                current[producer_inverse] =
                    columns[producer_inverse][row];
            }
            for (uint32_t input = 0;
                 input < 3; ++input) {
                if (gf::IsZero(
                        current[
                            kFixedProgramProvenanceInputMaskBase +
                            input])) {
                    continue;
                }
                const Fp3 tuple = gf::Add(
                    current[
                        kFixedProgramProvenanceInputAddressBase +
                        input],
                    gf::Mul(
                        gamma[lane],
                        current[ValueColumn(input)]));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:"
                        "provenance_consumer_pole";
                    return out;
                }
                columns[consumer_base + input][row] =
                    gf::Inv(denominator);
                current[consumer_base + input] =
                    columns[consumer_base + input][row];
            }
            running[lane] = gf::Add(
                running[lane],
                FixedProgramProvenanceContribution(
                    current, lane));
        }
    }
    if (!gf::IsZero(running[0]) ||
        !gf::IsZero(running[1])) {
        out.note =
            "stage3:hash_air:provenance_terminal";
        return out;
    }
    out.columns = std::move(columns);
    out.valid = true;
    out.note =
        "stage3:hash_air:provenance_complete_internal_ssa";
    return out;
}

bool ProveFixedProgramProvenanceAir(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed,
    FixedProgramProvenanceAirProof& out,
    std::string* why)
{
    out = {};
    const auto instance =
        BuildFixedProgramProvenanceInstance(
            program, witness, external_values,
            final_words, fs_seed);
    if (!instance.valid) {
        return Fail(why, instance.note);
    }
    const auto proved = aq::AirQuotientProve<Fp3>(
        instance.cs, instance.columns, fs_seed, {});
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "provenance_prove:" + proved.note);
    }
    out.boundary_statement =
        instance.boundary_statement;
    out.challenge_commitment =
        CommitRCStage3CtlChallenges(
            instance.challenges);
    out.quotient = proved.proof;
    out.valid = true;
    out.note =
        "stage3:hash_air:provenance_proved";
    return true;
}

bool VerifyFixedProgramProvenanceAir(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed,
    const FixedProgramProvenanceAirProof& proof,
    std::string* why)
{
    const uint256 boundary_statement =
        CommitFixedProgramBoundaryStatement(
            program, external_values, final_words);
    const auto& batch = proof.quotient.batch;
    if (proof.version != 1 || !proof.valid ||
        boundary_statement.IsNull() ||
        proof.boundary_statement != boundary_statement ||
        batch.columns.size() !=
            kFixedProgramProvenanceColumns + 1 ||
        batch.column_len.size() !=
            kFixedProgramProvenanceColumns + 1 ||
        batch.column_len.empty()) {
        return Fail(why, "provenance_verify_shape");
    }
    const uint32_t n_rows = batch.column_len[0];
    if (!IsPowerOfTwo(n_rows)) {
        return Fail(why, "provenance_verify_rows");
    }
    std::vector<uint256> base_roots(
        kFixedProgramProvenanceBaseColumns);
    for (uint32_t column = 0;
         column < base_roots.size(); ++column) {
        base_roots[column] =
            batch.columns[column].root;
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveFixedProgramProvenanceChallenges(
            program, boundary_statement, fs_seed,
            n_rows, batch.n_coeffs, base_roots,
            challenges, why) ||
        proof.challenge_commitment !=
            CommitRCStage3CtlChallenges(challenges)) {
        return Fail(why, "provenance_verify_challenges");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramProvenanceConstraintSystem(
            program, external_values, final_words,
            challenges, cs, why) ||
        cs.n_rows != n_rows) {
        return Fail(why, "provenance_verify_cs");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof.quotient, fs_seed, &air_why)) {
        return Fail(
            why, "provenance_verify_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:hash_air:"
            "provenance_complete_internal_ssa_ok";
    }
    return true;
}

namespace {

constexpr uint32_t kFixedProgramVerticalBusId = 0x48505631U;

uint256 CommitVerticalBoundaryStatement(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries)
{
    if (boundaries.empty() ||
        boundaries.size() >
            kFixedProgramVerticalSemanticInstances) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_FIXED_HASH_VERTICAL_BOUNDARY_V1";
    hash << CommitFixedProgram(program);
    hash << static_cast<uint32_t>(boundaries.size());
    for (const auto& boundary : boundaries) {
        const uint256 commitment =
            CommitFixedProgramBoundaryStatement(
                program, boundary.external_values,
                boundary.final_words);
        if (commitment.IsNull()) return {};
        hash << commitment;
    }
    return hash.GetHash();
}

bool DeriveVerticalChallenges(
    const FixedProgram& program,
    const uint256& boundary_statement,
    const uint256& fs_seed,
    uint32_t n_rows,
    uint32_t n_coeffs,
    uint32_t scheduled_instances,
    const std::vector<uint256>& base_roots,
    RCStage3CtlChallenges& challenges,
    std::string* why)
{
    challenges = {};
    const uint64_t edges =
        FixedProgramInternalEdgeCount(program) *
        scheduled_instances;
    HashWriter schedule_hash;
    schedule_hash <<
        "BTX_RC_STAGE3_FIXED_HASH_VERTICAL_SCHEDULE_V1";
    schedule_hash << CommitFixedProgram(program);
    schedule_hash << scheduled_instances;
    const uint256 schedule_commitment =
        schedule_hash.GetHash();
    HashWriter trace_hash;
    trace_hash <<
        "BTX_RC_STAGE3_FIXED_HASH_VERTICAL_TRACE_V1";
    trace_hash << schedule_commitment;
    trace_hash << boundary_statement;
    trace_hash << n_rows;
    trace_hash << n_coeffs;
    trace_hash << static_cast<uint32_t>(base_roots.size());
    for (const auto& root : base_roots) trace_hash << root;
    const uint256 trace_commitment = trace_hash.GetHash();
    if (edges == 0 || edges > kRCStage3CtlMaxEvents / 2 ||
        fs_seed.IsNull() || boundary_statement.IsNull() ||
        schedule_commitment.IsNull() ||
        trace_commitment.IsNull()) {
        return Fail(why, "vertical_challenge_context");
    }
    const RCStage3RelationRole role =
        program.kind == ProgramKind::Sha256Compression
        ? RCStage3RelationRole::EpisodeDigest
        : RCStage3RelationRole::EpisodeExtract;
    RCStage3CtlParticipantSpec participant;
    participant.role = role;
    participant.event_count = 2 * edges;
    participant.send_count = edges;
    participant.receive_count = edges;
    participant.schedule_commitment = schedule_commitment;
    RCStage3CtlManifest manifest;
    manifest.bus_id = kFixedProgramVerticalBusId;
    manifest.transcript_seed = fs_seed;
    manifest.participants.push_back(participant);
    RCStage3CtlChildPin pin;
    pin.role = role;
    pin.bus_id = manifest.bus_id;
    pin.event_count = participant.event_count;
    pin.send_count = participant.send_count;
    pin.receive_count = participant.receive_count;
    pin.schedule_commitment = schedule_commitment;
    pin.trace_commitment = trace_commitment;
    return DeriveRCStage3CtlChallenges(
        manifest, {pin}, challenges, why);
}

bool BuildVerticalConstraintSystem(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const RCStage3CtlChallenges& challenges,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why,
    uint32_t scheduled_instances =
        kFixedProgramVerticalScheduledInstances,
    const std::vector<std::vector<uint8_t>>*
        public_external_masks = nullptr,
    bool pin_finals = true)
{
    if (boundaries.empty() ||
        boundaries.size() >
            kFixedProgramVerticalSemanticInstances ||
        !BuildFixedProgramBoundaryConstraintSystem(
            program, boundaries[0].external_values,
            boundaries[0].final_words, out, why)) {
        return false;
    }
    const uint32_t lane_rows = out.n_rows;
    if (lane_rows != 1024) {
        return Fail(why, "vertical_program_rows");
    }
    if (scheduled_instances == 0 ||
        (scheduled_instances &
         (scheduled_instances - 1)) != 0 ||
        scheduled_instances >
            kFixedProgramVerticalScheduledInstances ||
        boundaries.size() > scheduled_instances ||
        (public_external_masks != nullptr &&
         public_external_masks->size() != boundaries.size())) {
        return Fail(why, "vertical_schedule_shape");
    }
    out.n_rows = lane_rows * scheduled_instances;
    out.n_columns =
        kFixedProgramVerticalProvenanceColumns;
    out.preprocessed.clear();
    out.preprocessed_pin_ood = true;

    // Boundary pins vary per instance. Rebuild their preprocessed columns by
    // concatenating the canonical one-instance schedules.
    std::vector<std::vector<Fp3>> fixed(
        out.n_columns,
        std::vector<Fp3>(out.n_rows, Fp3::Zero()));
    std::vector<bool> is_fixed(out.n_columns, false);
    for (uint32_t instance = 0;
         instance < scheduled_instances;
         ++instance) {
        const auto& boundary =
            boundaries[std::min<size_t>(
                instance, boundaries.size() - 1)];
        aq::AirConstraintSystem<Fp3> local;
        if (!BuildFixedProgramBoundaryConstraintSystem(
                program, boundary.external_values,
                boundary.final_words, local, why)) {
            return false;
        }
        for (const auto& [column, values] :
             local.preprocessed) {
            is_fixed[column] = true;
            std::copy(
                values.begin(), values.end(),
                fixed[column].begin() +
                    instance * lane_rows);
        }
        const uint32_t row_base = instance * lane_rows;
        const size_t semantic =
            std::min<size_t>(
                instance, boundaries.size() - 1);
        for (uint32_t row_index = 0;
             row_index < program.rows.size(); ++row_index) {
            const auto& row = program.rows[row_index];
            if (!pin_finals &&
                std::find(
                    program.final_addresses.begin(),
                    program.final_addresses.end(),
                    row.output_address) !=
                    program.final_addresses.end()) {
                const uint32_t word = OutputWordSlot(row);
                fixed[
                    kFixedProgramBoundaryExpectedBase + word]
                    [row_base + row_index] = Fp3::Zero();
                fixed[
                    kFixedProgramBoundaryMaskBase + word]
                    [row_base + row_index] = Fp3::Zero();
            }
            if (public_external_masks != nullptr &&
                instance < boundaries.size()) {
                const auto& mask =
                    (*public_external_masks)[semantic];
                if (mask.size() !=
                    program.external_address_count) {
                    return Fail(
                        why, "vertical_public_mask_shape");
                }
                for (uint32_t input = 0;
                     input < row.input_count; ++input) {
                    const uint32_t address =
                        row.input_address[input];
                    if (address > 0 &&
                        address <=
                            program.external_address_count &&
                        mask[address - 1] == 0) {
                        fixed[
                            kFixedProgramBoundaryExpectedBase +
                            input][row_base + row_index] =
                            Fp3::Zero();
                        fixed[
                            kFixedProgramBoundaryMaskBase +
                            input][row_base + row_index] =
                            Fp3::Zero();
                    }
                }
            }
        }
    }
    const auto metadata =
        FixedProgramProvenanceMetadata(program, lane_rows);
    for (uint32_t offset = 0;
         offset < metadata.size(); ++offset) {
        const uint32_t column =
            kFixedProgramBoundaryColumns + offset;
        is_fixed[column] = true;
        for (uint32_t instance = 0;
             instance < scheduled_instances;
             ++instance) {
            std::copy(
                metadata[offset].begin(),
                metadata[offset].end(),
                fixed[column].begin() +
                    instance * lane_rows);
        }
    }
    for (uint32_t row = 0; row < out.n_rows; ++row) {
        const uint32_t instance = row / lane_rows;
        fixed[kFixedProgramVerticalInstanceIdColumn][row] =
            U(instance);
        fixed[kFixedProgramVerticalPhaseColumn][row] =
            U(row % lane_rows);
        fixed[kFixedProgramVerticalActiveColumn][row] =
            U(instance < boundaries.size());
    }
    is_fixed[kFixedProgramVerticalInstanceIdColumn] = true;
    is_fixed[kFixedProgramVerticalPhaseColumn] = true;
    is_fixed[kFixedProgramVerticalActiveColumn] = true;
    for (uint32_t column = 0;
         column < out.n_columns; ++column) {
        if (is_fixed[column]) {
            out.preprocessed.emplace_back(
                column, std::move(fixed[column]));
        }
    }

    const uint64_t address_stride =
        static_cast<uint64_t>(
            program.rows.back().output_address) + 1;
    if (address_stride *
            scheduled_instances >=
        gf::kP) {
        return Fail(why, "vertical_address_stride");
    }
    const std::array<Fp3, 2> gamma{
        challenges.gamma1, challenges.gamma2};
    const std::array<Fp3, 2> alpha{
        challenges.alpha1, challenges.alpha2};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t producer_inverse =
            lane == 0
            ? kFixedProgramProvenanceProducerInverse1
            : kFixedProgramProvenanceProducerInverse2;
        const uint32_t consumer_base =
            lane == 0
            ? kFixedProgramProvenanceConsumerInverse1Base
            : kFixedProgramProvenanceConsumerInverse2Base;
        const uint32_t running =
            lane == 0
            ? kFixedProgramProvenanceRunning1
            : kFixedProgramProvenanceRunning2;
        Add(out, "stage3.hash.vertical.producer_inverse", 3,
            [lane, producer_inverse, gamma, alpha,
             address_stride](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 namespaced = gf::Add(
                    cur[kFixedProgramProvenanceOutputAddress],
                    gf::Mul(
                        U(address_stride),
                        cur[kFixedProgramVerticalInstanceIdColumn]));
                const Fp3 tuple = gf::Add(
                    namespaced,
                    gf::Mul(
                        gamma[lane],
                        FixedProgramOutputValue(cur)));
                return gf::Sub(
                    gf::Mul(
                        gf::Sub(alpha[lane], tuple),
                        cur[producer_inverse]),
                    cur[kFixedProgramProvenanceOutputHasUse]);
            });
        Add(out, "stage3.hash.vertical.producer_padding", 2,
            [producer_inverse](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[kFixedProgramProvenanceOutputHasUse]),
                    cur[producer_inverse]);
            });
        for (uint32_t input = 0; input < 3; ++input) {
            Add(out, "stage3.hash.vertical.consumer_inverse", 2,
                [lane, input, consumer_base, gamma, alpha,
                 address_stride](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 namespaced = gf::Add(
                        cur[
                            kFixedProgramProvenanceInputAddressBase +
                            input],
                        gf::Mul(
                            U(address_stride),
                            cur[
                                kFixedProgramVerticalInstanceIdColumn]));
                    const Fp3 tuple = gf::Add(
                        namespaced,
                        gf::Mul(
                            gamma[lane],
                            cur[ValueColumn(input)]));
                    return gf::Sub(
                        gf::Mul(
                            gf::Sub(alpha[lane], tuple),
                            cur[consumer_base + input]),
                        cur[
                            kFixedProgramProvenanceInputMaskBase +
                            input]);
                });
            Add(out, "stage3.hash.vertical.consumer_padding", 2,
                [input, consumer_base](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[
                                kFixedProgramProvenanceInputMaskBase +
                                input]),
                        cur[consumer_base + input]);
                });
        }
        AddKind(
            out, "stage3.hash.vertical.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const std::vector<Fp3>& cur,
                      const std::vector<Fp3>&) {
                return cur[running];
            });
        AddKind(
            out, "stage3.hash.vertical.running_transition",
            aq::AirKind::kTransition, 2,
            [lane, running](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[running],
                    gf::Add(
                        cur[running],
                        FixedProgramProvenanceContribution(
                            cur, lane)));
            });
        AddKind(
            out, "stage3.hash.vertical.running_last",
            aq::AirKind::kLastRow, 2,
            [lane, running](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Add(
                    cur[running],
                    FixedProgramProvenanceContribution(
                        cur, lane));
            });
    }
    return true;
}

std::vector<uint256> VerticalBaseRoots(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs)
{
    std::vector<uint32_t> indices;
    for (uint32_t column = 0;
         column < kFixedProgramProvenanceBaseColumns;
         ++column) {
        indices.push_back(column);
    }
    indices.push_back(kFixedProgramVerticalInstanceIdColumn);
    indices.push_back(kFixedProgramVerticalPhaseColumn);
    indices.push_back(kFixedProgramVerticalActiveColumn);
    std::vector<uint256> roots;
    roots.reserve(indices.size());
    for (uint32_t column : indices) {
        roots.push_back(
            aq::AirCommittedValuesRoot<Fp3>(
                columns[column], n_coeffs));
    }
    return roots;
}

} // namespace

FixedProgramVerticalProvenanceInstance
BuildFixedProgramVerticalProvenanceInstance(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const uint256& fs_seed)
{
    FixedProgramVerticalProvenanceInstance out;
    out.semantic_instances =
        static_cast<uint32_t>(boundaries.size());
    out.boundary_statement =
        CommitVerticalBoundaryStatement(program, boundaries);
    if (out.boundary_statement.IsNull() ||
        fs_seed.IsNull()) {
        out.note = "stage3:hash_air:vertical_statement";
        return out;
    }
    out.scheduled_instances = 1;
    while (out.scheduled_instances < boundaries.size()) {
        out.scheduled_instances <<= 1;
    }
    if (out.scheduled_instances < 2) {
        out.scheduled_instances = 2;
    }
    std::string why;
    RCStage3CtlChallenges zero{};
    aq::AirConstraintSystem<Fp3> dummy;
    if (!BuildVerticalConstraintSystem(
            program, boundaries, zero, dummy, &why,
            out.scheduled_instances)) {
        out.note = why;
        return out;
    }
    std::vector<std::vector<Fp3>> columns(
        dummy.n_columns,
        std::vector<Fp3>(dummy.n_rows, Fp3::Zero()));
    const uint32_t lane_rows =
        dummy.n_rows / out.scheduled_instances;
    for (uint32_t instance = 0;
         instance < out.scheduled_instances;
         ++instance) {
        const auto& boundary =
            boundaries[std::min<size_t>(
                instance, boundaries.size() - 1)];
        ProgramWitness witness;
        std::vector<std::vector<Fp3>> local;
        if (!BuildProgramWitness(
                program, boundary.external_values,
                witness, &why) ||
            witness.final_words != boundary.final_words ||
            !BuildFixedProgramBoundaryAirWitness(
                program, witness,
                boundary.external_values,
                boundary.final_words, local, &why)) {
            out.note = "stage3:hash_air:vertical_witness:" + why;
            return out;
        }
        for (uint32_t column = 0;
             column < local.size(); ++column) {
            std::copy(
                local[column].begin(), local[column].end(),
                columns[column].begin() +
                    instance * lane_rows);
        }
    }
    for (const auto& [column, values] : dummy.preprocessed) {
        columns[column] = values;
    }
    const uint32_t n_coeffs = FriNextPow2(
        std::max(dummy.n_rows, dummy.QuotientLen()));
    const auto base_roots =
        VerticalBaseRoots(columns, n_coeffs);
    out.checked_trace_root_hints.assign(
        dummy.n_columns, uint256{});
    uint32_t base_root = 0;
    for (uint32_t column = 0;
         column < kFixedProgramProvenanceBaseColumns;
         ++column) {
        out.checked_trace_root_hints[column] =
            base_roots[base_root++];
    }
    out.checked_trace_root_hints[
        kFixedProgramVerticalInstanceIdColumn] =
        base_roots[base_root++];
    out.checked_trace_root_hints[
        kFixedProgramVerticalPhaseColumn] =
        base_roots[base_root++];
    out.checked_trace_root_hints[
        kFixedProgramVerticalActiveColumn] =
        base_roots[base_root++];
    if (base_root != base_roots.size()) {
        out.note = "stage3:hash_air:vertical_base_root_shape";
        return out;
    }
    if (!DeriveVerticalChallenges(
            program, out.boundary_statement, fs_seed,
            dummy.n_rows, n_coeffs,
            out.scheduled_instances,
            base_roots,
            out.challenges, &why) ||
        !BuildVerticalConstraintSystem(
            program, boundaries, out.challenges,
            out.cs, &why, out.scheduled_instances)) {
        out.note = why;
        return out;
    }
    for (const auto& [column, values] :
         out.cs.preprocessed) {
        columns[column] = values;
    }
    const uint64_t address_stride =
        static_cast<uint64_t>(
            program.rows.back().output_address) + 1;
    std::array<Fp3, 2> running{
        Fp3::Zero(), Fp3::Zero()};
    const std::array<Fp3, 2> gamma{
        out.challenges.gamma1, out.challenges.gamma2};
    const std::array<Fp3, 2> alpha{
        out.challenges.alpha1, out.challenges.alpha2};
    std::vector<Fp3> current(
        out.cs.n_columns, Fp3::Zero());
    for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < out.cs.n_columns; ++column) {
            current[column] = columns[column][row];
        }
        for (uint32_t lane = 0; lane < 2; ++lane) {
            const uint32_t producer_inverse =
                lane == 0
                ? kFixedProgramProvenanceProducerInverse1
                : kFixedProgramProvenanceProducerInverse2;
            const uint32_t consumer_base =
                lane == 0
                ? kFixedProgramProvenanceConsumerInverse1Base
                : kFixedProgramProvenanceConsumerInverse2Base;
            const uint32_t running_column =
                lane == 0
                ? kFixedProgramProvenanceRunning1
                : kFixedProgramProvenanceRunning2;
            columns[running_column][row] = running[lane];
            const Fp3 instance_offset = gf::Mul(
                U(address_stride),
                current[kFixedProgramVerticalInstanceIdColumn]);
            if (!gf::IsZero(
                    current[
                        kFixedProgramProvenanceOutputHasUse])) {
                const Fp3 tuple = gf::Add(
                    gf::Add(
                        current[
                            kFixedProgramProvenanceOutputAddress],
                        instance_offset),
                    gf::Mul(
                        gamma[lane],
                        FixedProgramOutputValue(current)));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:vertical_producer_pole";
                    return out;
                }
                columns[producer_inverse][row] =
                    gf::Inv(denominator);
                current[producer_inverse] =
                    columns[producer_inverse][row];
            }
            for (uint32_t input = 0; input < 3; ++input) {
                if (gf::IsZero(
                        current[
                            kFixedProgramProvenanceInputMaskBase +
                            input])) {
                    continue;
                }
                const Fp3 tuple = gf::Add(
                    gf::Add(
                        current[
                            kFixedProgramProvenanceInputAddressBase +
                            input],
                        instance_offset),
                    gf::Mul(
                        gamma[lane],
                        current[ValueColumn(input)]));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:vertical_consumer_pole";
                    return out;
                }
                columns[consumer_base + input][row] =
                    gf::Inv(denominator);
                current[consumer_base + input] =
                    columns[consumer_base + input][row];
            }
            running[lane] = gf::Add(
                running[lane],
                FixedProgramProvenanceContribution(
                    current, lane));
        }
    }
    if (!gf::IsZero(running[0]) ||
        !gf::IsZero(running[1])) {
        out.note = "stage3:hash_air:vertical_terminal";
        return out;
    }
    out.columns = std::move(columns);
    out.valid = true;
    out.note =
        "stage3:hash_air:vertical_complete_internal_ssa";
    return out;
}

uint256 CommitFixedProgramVerticalWitnessBoundaryStatement(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links)
{
    if (boundaries.empty() || boundaries.size() > 64 ||
        boundaries.size() != public_masks.size()) return {};
    uint32_t scheduled = 1;
    while (scheduled < boundaries.size()) scheduled <<= 1;
    if (scheduled < 2) scheduled = 2;
    HashWriter statement;
    statement <<
        "BTX_RC_STAGE3_FIXED_HASH_WITNESS_BOUNDARY_V1";
    statement << CommitFixedProgram(program);
    statement << static_cast<uint32_t>(boundaries.size());
    statement << scheduled;
    for (uint32_t instance = 0;
         instance < boundaries.size(); ++instance) {
        if (public_masks[instance].size() !=
                program.external_address_count ||
            boundaries[instance].external_values.size() !=
                program.external_address_count ||
            boundaries[instance].final_words.size() !=
                program.final_addresses.size()) {
            return {};
        }
        statement << static_cast<uint32_t>(
            public_masks[instance].size());
        for (uint32_t external = 0;
             external < public_masks[instance].size();
             ++external) {
            statement << public_masks[instance][external];
            if (public_masks[instance][external]) {
                statement <<
                    boundaries[instance]
                        .external_values[external];
            }
        }
    }
    statement << static_cast<uint32_t>(links.size());
    for (uint32_t link_index = 0;
         link_index < links.size(); ++link_index) {
        const auto& link = links[link_index];
        const uint64_t effective_id = link.link_id != 0
            ? link.link_id
            : UINT64_C(0x100000000) + link_index + 1;
        if (link.source_instance >= boundaries.size() ||
            link.target_instance >= boundaries.size() ||
            link.source_final_word >=
                program.final_addresses.size() ||
            effective_id == 0 || effective_id >= gf::kP ||
            link.target_external_address == 0 ||
            link.target_external_address >
                program.external_address_count ||
            public_masks[link.target_instance]
                        [link.target_external_address - 1]) {
            return {};
        }
        for (uint32_t prior_index = 0;
             prior_index < link_index; ++prior_index) {
            const auto& prior = links[prior_index];
            const uint64_t prior_id = prior.link_id != 0
                ? prior.link_id
                : UINT64_C(0x100000000) +
                    prior_index + 1;
            const bool same_source =
                prior.source_instance ==
                    link.source_instance &&
                prior.source_final_word ==
                    link.source_final_word;
            if ((same_source &&
                 prior_id != effective_id) ||
                (!same_source &&
                 prior_id == effective_id) ||
                (prior.target_instance ==
                     link.target_instance &&
                 prior.target_external_address ==
                     link.target_external_address)) {
                return {};
            }
        }
        statement << link.source_instance;
        statement << link.source_final_word;
        statement << link.target_instance;
        statement << link.target_external_address;
        statement << effective_id;
    }
    return statement.GetHash();
}

static FixedProgramVerticalWitnessBoundaryInstance
BuildFixedProgramVerticalWitnessBoundaryInstanceImpl(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& precommitted_base_row,
    const RCStage3CtlChallenges* transcript_challenges)
{
    FixedProgramVerticalWitnessBoundaryInstance out;
    if (fs_seed.IsNull()) {
        out.note = "stage3:hash_air:witness_vertical_shape";
        return out;
    }
    uint32_t scheduled = 1;
    while (scheduled < boundaries.size()) scheduled <<= 1;
    if (scheduled < 2) scheduled = 2;
    out.semantic_instances =
        static_cast<uint32_t>(boundaries.size());
    out.scheduled_instances = scheduled;
    out.public_statement =
        CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, boundaries, public_masks, links);
    if (out.public_statement.IsNull()) {
        out.note = "stage3:hash_air:witness_vertical_statement";
        return out;
    }

    std::string why;
    RCStage3CtlChallenges zero{};
    aq::AirConstraintSystem<Fp3> dummy;
    if (!BuildVerticalConstraintSystem(
            program, boundaries, zero, dummy, &why,
            scheduled, &public_masks, false)) {
        out.note = why;
        return out;
    }
    std::vector<std::vector<Fp3>> columns(
        dummy.n_columns,
        std::vector<Fp3>(dummy.n_rows, Fp3::Zero()));
    constexpr uint32_t LANE_ROWS = 1024;
    for (uint32_t instance = 0;
         instance < scheduled; ++instance) {
        const auto& boundary =
            boundaries[std::min<size_t>(
                instance, boundaries.size() - 1)];
        ProgramWitness witness;
        std::vector<std::vector<Fp3>> local;
        if (!BuildProgramWitness(
                program, boundary.external_values,
                witness, &why) ||
            witness.final_words != boundary.final_words ||
            !BuildFixedProgramBoundaryAirWitness(
                program, witness, boundary.external_values,
                boundary.final_words, local, &why)) {
            out.note =
                "stage3:hash_air:witness_vertical_witness:" +
                why;
            return out;
        }
        for (uint32_t column = 0;
             column < local.size(); ++column) {
            std::copy(
                local[column].begin(), local[column].end(),
                columns[column].begin() +
                    instance * LANE_ROWS);
        }
    }
    for (const auto& [column, values] :
         dummy.preprocessed) {
        columns[column] = values;
    }

    // Chain metadata is prechallenge. One source may feed every canonical use
    // of one target external address; multiplicity balances those receives.
    const uint32_t chain_base = dummy.n_columns;
    constexpr uint32_t SRC_LINK = 0;
    constexpr uint32_t SRC_MULT = 1;
    constexpr uint32_t TGT_LINK = 2;
    constexpr uint32_t TGT_MASK = 5;
    constexpr uint32_t SRC_INV1 = 8;
    constexpr uint32_t SRC_INV2 = 9;
    constexpr uint32_t TGT_INV1 = 10;
    constexpr uint32_t TGT_INV2 = 13;
    constexpr uint32_t RUN1 = 16;
    constexpr uint32_t RUN2 = 17;
    constexpr uint32_t CHAIN_COLUMNS = 18;
    columns.resize(
        chain_base + CHAIN_COLUMNS,
        std::vector<Fp3>(dummy.n_rows, Fp3::Zero()));
    std::array<std::vector<Fp3>, 8> metadata;
    for (auto& column : metadata) {
        column.assign(dummy.n_rows, Fp3::Zero());
    }
    out.final_output_rows.assign(
        boundaries.size() * program.final_addresses.size(),
        0);
    for (uint32_t instance = 0;
         instance < boundaries.size(); ++instance) {
        for (uint32_t row = 0;
             row < program.rows.size(); ++row) {
            const auto final = std::find(
                program.final_addresses.begin(),
                program.final_addresses.end(),
                program.rows[row].output_address);
            if (final != program.final_addresses.end()) {
                out.final_output_rows[
                    instance * program.final_addresses.size() +
                    static_cast<size_t>(
                        final -
                        program.final_addresses.begin())] =
                    instance * LANE_ROWS + row;
            }
        }
    }
    for (uint32_t link_index = 0;
         link_index < links.size(); ++link_index) {
        const auto& link = links[link_index];
        const uint64_t effective_id = link.link_id != 0
            ? link.link_id
            : UINT64_C(0x100000000) + link_index + 1;
        const Fp3 id = U(effective_id);
        uint32_t uses = 0;
        for (uint32_t row = 0;
             row < program.rows.size(); ++row) {
            const auto& program_row = program.rows[row];
            for (uint32_t input = 0;
                 input < program_row.input_count; ++input) {
                if (program_row.input_address[input] ==
                    link.target_external_address) {
                    const uint32_t trace_row =
                        link.target_instance * LANE_ROWS + row;
                    if (!gf::IsZero(
                            metadata[
                                TGT_MASK - SRC_LINK + input]
                                [trace_row])) {
                        out.note =
                            "stage3:hash_air:"
                            "witness_vertical_target_collision";
                        return out;
                    }
                    metadata[TGT_LINK - SRC_LINK + input]
                            [trace_row] = id;
                    metadata[TGT_MASK - SRC_LINK + input]
                            [trace_row] = Fp3::One();
                    ++uses;
                }
            }
        }
        if (uses == 0) {
            out.note =
                "stage3:hash_air:witness_vertical_unused_link";
            return out;
        }
        const uint32_t source_row =
            out.final_output_rows[
                link.source_instance *
                    program.final_addresses.size() +
                link.source_final_word];
        if (!gf::IsZero(metadata[SRC_LINK][source_row]) &&
            !gf::Eq(metadata[SRC_LINK][source_row], id)) {
            out.note =
                "stage3:hash_air:"
                "witness_vertical_source_link_id";
            return out;
        }
        metadata[SRC_LINK][source_row] = id;
        metadata[SRC_MULT][source_row] = gf::Add(
            metadata[SRC_MULT][source_row], U(uses));
    }
    for (uint32_t offset = 0; offset < 8; ++offset) {
        dummy.preprocessed.emplace_back(
            chain_base + offset, metadata[offset]);
        columns[chain_base + offset] = metadata[offset];
    }
    dummy.n_columns = chain_base + CHAIN_COLUMNS;

    // Digest boundary columns are part of epoch R0.  They must precede every
    // LogUp/quotient challenge so a later CTL can consume the SHA bytes
    // without relying on a challenge-dependent Rdep projection.
    const uint32_t final_word_count =
        static_cast<uint32_t>(
            program.final_addresses.size());
    const bool sha_byte_exports =
        program.kind ==
        ProgramKind::Sha256Compression;
    const uint32_t export_base = dummy.n_columns;
    const uint32_t export_selector_base =
        export_base + final_word_count;
    const uint32_t output_bit_base =
        export_selector_base + final_word_count;
    const uint32_t output_byte_base =
        output_bit_base + 32U * final_word_count;
    const uint32_t input_word_base =
        output_byte_base + 4U * final_word_count;
    const uint32_t input_byte_base =
        input_word_base + 1;
    const uint32_t input_bit_base =
        input_byte_base + 4;
    const uint32_t input_active_column =
        input_bit_base + 32;
    const uint32_t input_address_column =
        input_active_column + 1;
    const uint32_t input_slot_base =
        input_address_column + 1;
    if (sha_byte_exports) {
        out.output_export_base = export_base;
        out.output_bit_base = output_bit_base;
        out.output_byte_base = output_byte_base;
        out.input_word_base = input_word_base;
        out.input_byte_base = input_byte_base;
        out.input_bit_base = input_bit_base;
        out.input_active_column =
            input_active_column;
        out.input_address_column =
            input_address_column;
        dummy.n_columns = input_slot_base + 3;
        columns.resize(
            dummy.n_columns,
            std::vector<Fp3>(
                dummy.n_rows, Fp3::Zero()));
        const uint32_t final_instance =
            static_cast<uint32_t>(
                boundaries.size() - 1);
        for (uint32_t word = 0;
             word < final_word_count; ++word) {
        const uint32_t native_word =
            boundaries.back().final_words[word];
        std::fill(
            columns[export_base + word].begin(),
            columns[export_base + word].end(),
            U(native_word));
        std::vector<Fp3> selector(
            dummy.n_rows, Fp3::Zero());
        selector[
            out.final_output_rows[
                final_instance * final_word_count +
                word]] = Fp3::One();
        dummy.preprocessed.emplace_back(
            export_selector_base + word,
            selector);
        columns[export_selector_base + word] =
            std::move(selector);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            std::fill(
                columns[
                    output_bit_base +
                    32U * word + bit].begin(),
                columns[
                    output_bit_base +
                    32U * word + bit].end(),
                U((native_word >> bit) & 1U));
        }
        // SHA serializes each u32 state word most-significant byte first.
        // The byte column itself is reconstructed below from the already
        // boolean word-bit columns, so it is not a native digest claim.
        for (uint32_t lane = 0; lane < 4; ++lane) {
            const uint32_t shift =
                8U * (3U - lane);
            std::fill(
                columns[
                    output_byte_base +
                    4U * word + lane].begin(),
                columns[
                    output_byte_base +
                    4U * word + lane].end(),
                U((native_word >> shift) & 0xffU));
        }
        }

        std::array<uint32_t, 16> first_message_row;
    std::array<uint32_t, 16> first_message_slot;
    first_message_row.fill(UINT32_MAX);
    first_message_slot.fill(UINT32_MAX);
    for (uint32_t row = 0;
         row < program.rows.size(); ++row) {
        for (uint32_t slot = 0;
             slot < program.rows[row].input_count; ++slot) {
            const uint32_t address =
                program.rows[row].input_address[slot];
            if (address >= 1 && address <= 16 &&
                first_message_row[address - 1] ==
                    UINT32_MAX) {
                first_message_row[address - 1] = row;
                first_message_slot[address - 1] = slot;
            }
        }
    }
    if (std::any_of(
            first_message_row.begin(),
            first_message_row.end(),
            [](uint32_t row) {
                return row == UINT32_MAX;
            })) {
        out.note =
            "stage3:hash_air:"
            "witness_vertical_message_schedule";
        return out;
    }
    std::vector<uint8_t> is_second_pass(
        boundaries.size(), 0);
    for (const auto& link : links) {
        // SHA256d's digest-as-message link occupies external words 1..8.
        // Ordinary first-pass chaining occupies state words 17..24.
        if (link.target_instance <
                is_second_pass.size() &&
            link.target_external_address >= 1 &&
            link.target_external_address <= 8) {
            is_second_pass[
                link.target_instance] = 1;
        }
    }
    std::vector<Fp3> input_active(
        dummy.n_rows, Fp3::Zero());
    std::vector<Fp3> input_address(
        dummy.n_rows, Fp3::Zero());
    std::array<std::vector<Fp3>, 3>
        input_slot;
    for (auto& slot : input_slot) {
        slot.assign(
            dummy.n_rows, Fp3::Zero());
    }
    // This byte-oriented R0 export is the SHA message bridge.  ChaCha can
    // consume two or more external words in one instruction row, so the
    // single-active-word SHA schedule is inapplicable.  Its complete external
    // input multiset is exported by AppendExternalInputCopyCtlV2 instead.
    if (program.kind == ProgramKind::Sha256Compression) {
        for (uint32_t instance = 0;
             instance < boundaries.size(); ++instance) {
            if (is_second_pass[instance]) {
                continue;
            }
            for (uint32_t word = 0; word < 16;
                 ++word) {
                const uint32_t row =
                    instance * LANE_ROWS +
                    first_message_row[word];
                const uint32_t slot =
                    first_message_slot[word];
                if (!gf::IsZero(input_active[row]) ||
                    slot >= input_slot.size()) {
                    out.note =
                        "stage3:hash_air:"
                        "witness_vertical_message_collision";
                    return out;
                }
                const uint32_t native_word =
                    boundaries[instance]
                        .external_values[word];
                input_active[row] = Fp3::One();
                input_address[row] =
                    U(static_cast<uint64_t>(instance) *
                          16U +
                      word);
                input_slot[slot][row] = Fp3::One();
                columns[input_word_base][row] =
                    U(native_word);
                for (uint32_t lane = 0; lane < 4;
                     ++lane) {
                    const uint32_t shift =
                        8U * (3U - lane);
                    columns[
                        input_byte_base + lane][row] =
                        U((native_word >> shift) &
                          0xffU);
                }
                for (uint32_t bit = 0; bit < 32;
                     ++bit) {
                    columns[
                        input_bit_base + bit][row] =
                        U((native_word >> bit) & 1U);
                }
            }
        }
    }
    dummy.preprocessed.emplace_back(
        input_active_column, input_active);
    dummy.preprocessed.emplace_back(
        input_address_column, input_address);
    for (uint32_t slot = 0; slot < 3;
         ++slot) {
        dummy.preprocessed.emplace_back(
            input_slot_base + slot,
            input_slot[slot]);
    }
    columns[input_active_column] =
        std::move(input_active);
    columns[input_address_column] =
        std::move(input_address);
    for (uint32_t slot = 0; slot < 3;
         ++slot) {
        columns[input_slot_base + slot] =
            std::move(input_slot[slot]);
    }
    }

    for (uint32_t column = 0;
         column < kFixedProgramProvenanceBaseColumns;
         ++column) {
        out.base_column_indices.push_back(column);
    }
    out.base_column_indices.push_back(
        kFixedProgramVerticalInstanceIdColumn);
    out.base_column_indices.push_back(
        kFixedProgramVerticalPhaseColumn);
    out.base_column_indices.push_back(
        kFixedProgramVerticalActiveColumn);
    for (uint32_t offset = 0; offset < 8; ++offset) {
        out.base_column_indices.push_back(
            chain_base + offset);
    }
    for (uint32_t column = export_base;
         column < dummy.n_columns; ++column) {
        out.base_column_indices.push_back(column);
    }
    std::sort(
        out.base_column_indices.begin(),
        out.base_column_indices.end());
    out.base_column_indices.erase(
        std::unique(
            out.base_column_indices.begin(),
            out.base_column_indices.end()),
        out.base_column_indices.end());
    std::string base_why;
    if (precommitted_base_row.IsNull()) {
        const auto session =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                dummy, columns,
                out.base_column_indices);
        if (!session.valid) {
            base_why = session.note;
        } else {
            out.base_row_commitment =
                session.base_row_commitment;
            out.base_row_tree_cache =
                session.row_tree_cache;
        }
    } else {
        if (!Fri3AlgDigestFromUint256(
                precommitted_base_row)
                 .has_value()) {
            out.note =
                "stage3:hash_air:"
                "witness_vertical_r0_encoding";
            return out;
        }
        out.base_row_commitment =
            precommitted_base_row;
    }
    const uint32_t n_coeffs = FriNextPow2(
        std::max(dummy.n_rows, dummy.QuotientLen()));
    if (out.base_row_commitment.IsNull()) {
        out.note =
            "stage3:hash_air:witness_vertical_r0:" +
            base_why;
        return out;
    }
    const bool challenge_ok =
        transcript_challenges != nullptr
        ? (!gf::IsZero(transcript_challenges->gamma1) &&
           !gf::IsZero(transcript_challenges->gamma2) &&
           !gf::IsZero(transcript_challenges->alpha1) &&
           !gf::IsZero(transcript_challenges->alpha2) &&
           !gf::Eq(
               transcript_challenges->gamma1,
               transcript_challenges->gamma2) &&
           !gf::Eq(
               transcript_challenges->alpha1,
               transcript_challenges->alpha2))
        : DeriveVerticalChallenges(
              program, out.public_statement, fs_seed,
              dummy.n_rows, n_coeffs, scheduled,
              {out.base_row_commitment},
              out.challenges, &why);
    if (transcript_challenges != nullptr && challenge_ok) {
        out.challenges = *transcript_challenges;
    }
    if (!challenge_ok) {
        out.note =
            "stage3:hash_air:"
            "witness_vertical_explicit_challenges";
        return out;
    }
    if (!BuildVerticalConstraintSystem(
            program, boundaries, out.challenges,
            out.cs, &why, scheduled, &public_masks,
            false)) {
        out.note = why;
        return out;
    }
    out.cs.n_columns = dummy.n_columns;
    for (uint32_t offset = 0; offset < 8; ++offset) {
        out.cs.preprocessed.emplace_back(
            chain_base + offset, metadata[offset]);
    }
    if (sha_byte_exports) {
        for (uint32_t word = 0;
             word < final_word_count; ++word) {
            out.cs.preprocessed.emplace_back(
                export_selector_base + word,
                columns[export_selector_base + word]);
        }
        for (uint32_t column =
                 input_active_column;
             column < input_slot_base + 3;
             ++column) {
            out.cs.preprocessed.emplace_back(
                column, columns[column]);
        }
    }
    out.cs.preprocessed_pin_ood = true;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.base_column_indices,
        .root = out.base_row_commitment,
    });

    const std::array<Fp3, 2> gamma{
        out.challenges.gamma1, out.challenges.gamma2};
    const std::array<Fp3, 2> alpha{
        out.challenges.alpha1, out.challenges.alpha2};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t src_inv =
            chain_base + (lane == 0 ? SRC_INV1 : SRC_INV2);
        const uint32_t tgt_inv =
            chain_base + (lane == 0 ? TGT_INV1 : TGT_INV2);
        const uint32_t running =
            chain_base + (lane == 0 ? RUN1 : RUN2);
        Add(out.cs, "stage3.hash.witness_chain.source_inverse",
            3, [lane, chain_base, src_inv, gamma, alpha](
                const auto& cur, const auto&) {
                const Fp3 tuple = gf::Add(
                    cur[chain_base + SRC_LINK],
                    gf::Mul(
                        gamma[lane],
                        FixedProgramOutputValue(cur)));
                return gf::Mul(
                    cur[chain_base + SRC_LINK],
                    gf::Sub(
                        gf::Mul(
                            gf::Sub(alpha[lane], tuple),
                            cur[src_inv]),
                        Fp3::One()));
            });
        for (uint32_t input = 0; input < 3; ++input) {
            Add(out.cs, "stage3.hash.witness_chain.target_inverse",
                3, [lane, input, chain_base, tgt_inv,
                    gamma, alpha](
                    const auto& cur, const auto&) {
                    const Fp3 mask =
                        cur[chain_base + TGT_MASK + input];
                    const Fp3 tuple = gf::Add(
                        cur[chain_base + TGT_LINK + input],
                        gf::Mul(
                            gamma[lane],
                            cur[ValueColumn(input)]));
                    return gf::Mul(
                        mask,
                        gf::Sub(
                            gf::Mul(
                                gf::Sub(alpha[lane], tuple),
                                cur[tgt_inv + input]),
                            Fp3::One()));
                });
        }
        AddKind(
            out.cs, "stage3.hash.witness_chain.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        AddKind(
            out.cs, "stage3.hash.witness_chain.running_transition",
            aq::AirKind::kTransition, 2,
            [chain_base, src_inv, tgt_inv, running](
                const auto& cur, const auto& next) {
                Fp3 contribution = gf::Mul(
                    cur[chain_base + SRC_MULT],
                    cur[src_inv]);
                for (uint32_t input = 0; input < 3; ++input) {
                    contribution = gf::Sub(
                        contribution,
                        gf::Mul(
                            cur[chain_base + TGT_MASK + input],
                            cur[tgt_inv + input]));
                }
                return gf::Sub(
                    next[running],
                    gf::Add(cur[running], contribution));
            });
        AddKind(
            out.cs, "stage3.hash.witness_chain.running_last",
            aq::AirKind::kLastRow, 2,
            [chain_base, src_inv, tgt_inv, running](
                const auto& cur, const auto&) {
                Fp3 contribution = gf::Mul(
                    cur[chain_base + SRC_MULT],
                    cur[src_inv]);
                for (uint32_t input = 0; input < 3; ++input) {
                    contribution = gf::Sub(
                        contribution,
                        gf::Mul(
                            cur[chain_base + TGT_MASK + input],
                            cur[tgt_inv + input]));
                }
                return gf::Add(cur[running], contribution);
            });
    }

    if (sha_byte_exports) {
      for (uint32_t word = 0;
           word < final_word_count; ++word) {
        Add(out.cs, "stage3.hash.witness_chain.export_final",
            2, [export_base, export_selector_base, word](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[export_selector_base + word],
                    gf::Sub(
                        cur[export_base + word],
                        FixedProgramOutputValue(cur)));
            });
        AddKind(
            out.cs, "stage3.hash.witness_chain.export_constant",
            aq::AirKind::kTransition, 1,
            [export_base, word](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[export_base + word],
                    cur[export_base + word]);
        });
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t bit_column =
                output_bit_base + 32U * word + bit;
            Add(out.cs, "stage3.hash.witness_chain.digest_bit_boolean",
                2, [bit_column](const auto& cur, const auto&) {
                    return gf::Mul(
                        cur[bit_column],
                        gf::Sub(
                            cur[bit_column], Fp3::One()));
                });
        }
        Add(out.cs, "stage3.hash.witness_chain.digest_word_reconstruct",
            1, [export_base, output_bit_base, word](
                const auto& cur, const auto&) {
                Fp3 reconstructed = Fp3::Zero();
                for (uint32_t bit = 0; bit < 32; ++bit) {
                    reconstructed = gf::Add(
                        reconstructed,
                        gf::Mul(
                            U(UINT64_C(1) << bit),
                            cur[
                                output_bit_base +
                                32U * word + bit]));
                }
                return gf::Sub(
                    cur[export_base + word],
                    reconstructed);
            });
        for (uint32_t lane = 0; lane < 4; ++lane) {
            const uint32_t byte_column =
                output_byte_base + 4U * word + lane;
            AddKind(
                out.cs,
                "stage3.hash.witness_chain.digest_byte_constant",
                aq::AirKind::kTransition, 1,
                [byte_column](
                    const auto& cur, const auto& next) {
                    return gf::Sub(
                        next[byte_column],
                        cur[byte_column]);
                });
            Add(out.cs,
                "stage3.hash.witness_chain.digest_byte_reconstruct",
                1,
                [output_bit_base, byte_column, word, lane](
                    const auto& cur, const auto&) {
                    Fp3 reconstructed = Fp3::Zero();
                    const uint32_t first_bit =
                        8U * (3U - lane);
                    for (uint32_t bit = 0; bit < 8; ++bit) {
                        reconstructed = gf::Add(
                            reconstructed,
                            gf::Mul(
                                U(UINT64_C(1) << bit),
                                cur[
                                    output_bit_base +
                                    32U * word +
                                    first_bit + bit]));
                    }
                    return gf::Sub(
                        cur[byte_column],
                        reconstructed);
                });
        }
      }
      Add(out.cs,
        "stage3.hash.witness_chain.first_pass_word_source",
        2,
        [input_word_base, input_slot_base](
            const auto& cur, const auto&) {
            Fp3 selected = Fp3::Zero();
            for (uint32_t slot = 0; slot < 3;
                 ++slot) {
                selected = gf::Add(
                    selected,
                    gf::Mul(
                        cur[input_slot_base + slot],
                        cur[ValueColumn(slot)]));
            }
            return gf::Sub(
                cur[input_word_base], selected);
        });
    for (uint32_t bit = 0; bit < 32;
         ++bit) {
        const uint32_t bit_column =
            input_bit_base + bit;
        Add(out.cs,
            "stage3.hash.witness_chain.first_pass_bit_boolean",
            2,
            [bit_column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[bit_column],
                    gf::Sub(
                        cur[bit_column],
                        Fp3::One()));
            });
    }
    Add(out.cs,
        "stage3.hash.witness_chain.first_pass_word_reconstruct",
        1,
        [input_word_base, input_bit_base](
            const auto& cur, const auto&) {
            Fp3 reconstructed = Fp3::Zero();
            for (uint32_t bit = 0; bit < 32;
                 ++bit) {
                reconstructed = gf::Add(
                    reconstructed,
                    gf::Mul(
                        U(UINT64_C(1) << bit),
                        cur[input_bit_base + bit]));
            }
            return gf::Sub(
                cur[input_word_base],
                reconstructed);
        });
      for (uint32_t lane = 0; lane < 4;
           ++lane) {
        const uint32_t byte_column =
            input_byte_base + lane;
        Add(out.cs,
            "stage3.hash.witness_chain.first_pass_byte_reconstruct",
            1,
            [input_bit_base, byte_column, lane](
                const auto& cur, const auto&) {
                Fp3 reconstructed = Fp3::Zero();
                const uint32_t first_bit =
                    8U * (3U - lane);
                for (uint32_t bit = 0; bit < 8;
                     ++bit) {
                    reconstructed = gf::Add(
                        reconstructed,
                        gf::Mul(
                            U(UINT64_C(1) << bit),
                            cur[
                                input_bit_base +
                                first_bit + bit]));
                }
                return gf::Sub(
                    cur[byte_column],
                    reconstructed);
            });
      }
    }

    // Fill the ordinary namespaced internal-SSA LogUp columns under the new
    // public-only statement challenges.
    const uint64_t address_stride =
        static_cast<uint64_t>(
            program.rows.back().output_address) + 1;
    std::array<Fp3, 2> internal_running{
        Fp3::Zero(), Fp3::Zero()};
    std::array<Fp3, 2> chain_running{
        Fp3::Zero(), Fp3::Zero()};
    std::vector<Fp3> current(
        out.cs.n_columns, Fp3::Zero());
    for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < out.cs.n_columns; ++column) {
            current[column] = columns[column][row];
        }
        for (uint32_t lane = 0; lane < 2; ++lane) {
            const uint32_t producer_inverse =
                lane == 0
                ? kFixedProgramProvenanceProducerInverse1
                : kFixedProgramProvenanceProducerInverse2;
            const uint32_t consumer_base =
                lane == 0
                ? kFixedProgramProvenanceConsumerInverse1Base
                : kFixedProgramProvenanceConsumerInverse2Base;
            const uint32_t internal_run =
                lane == 0
                ? kFixedProgramProvenanceRunning1
                : kFixedProgramProvenanceRunning2;
            columns[internal_run][row] =
                internal_running[lane];
            current[internal_run] = internal_running[lane];
            const Fp3 offset = gf::Mul(
                U(address_stride),
                current[kFixedProgramVerticalInstanceIdColumn]);
            if (!gf::IsZero(
                    current[
                        kFixedProgramProvenanceOutputHasUse])) {
                const Fp3 tuple = gf::Add(
                    gf::Add(
                        current[
                            kFixedProgramProvenanceOutputAddress],
                        offset),
                    gf::Mul(
                        gamma[lane],
                        FixedProgramOutputValue(current)));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:witness_internal_pole";
                    return out;
                }
                columns[producer_inverse][row] =
                    gf::Inv(denominator);
                current[producer_inverse] =
                    columns[producer_inverse][row];
            }
            for (uint32_t input = 0; input < 3; ++input) {
                if (gf::IsZero(
                        current[
                            kFixedProgramProvenanceInputMaskBase +
                            input])) continue;
                const Fp3 tuple = gf::Add(
                    gf::Add(
                        current[
                            kFixedProgramProvenanceInputAddressBase +
                            input],
                        offset),
                    gf::Mul(
                        gamma[lane],
                        current[ValueColumn(input)]));
                const Fp3 denominator =
                    gf::Sub(alpha[lane], tuple);
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:witness_internal_consumer_pole";
                    return out;
                }
                columns[consumer_base + input][row] =
                    gf::Inv(denominator);
                current[consumer_base + input] =
                    columns[consumer_base + input][row];
            }
            internal_running[lane] = gf::Add(
                internal_running[lane],
                FixedProgramProvenanceContribution(
                    current, lane));

            const uint32_t src_inv =
                chain_base + (lane == 0 ? SRC_INV1 : SRC_INV2);
            const uint32_t tgt_inv =
                chain_base + (lane == 0 ? TGT_INV1 : TGT_INV2);
            const uint32_t run =
                chain_base + (lane == 0 ? RUN1 : RUN2);
            columns[run][row] = chain_running[lane];
            current[run] = chain_running[lane];
            if (!gf::IsZero(
                    current[chain_base + SRC_LINK])) {
                const Fp3 denominator = gf::Sub(
                    alpha[lane],
                    gf::Add(
                        current[chain_base + SRC_LINK],
                        gf::Mul(
                            gamma[lane],
                            FixedProgramOutputValue(current))));
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:witness_chain_source_pole";
                    return out;
                }
                columns[src_inv][row] =
                    gf::Inv(denominator);
                current[src_inv] = columns[src_inv][row];
            }
            Fp3 contribution = gf::Mul(
                current[chain_base + SRC_MULT],
                current[src_inv]);
            for (uint32_t input = 0; input < 3; ++input) {
                if (gf::IsZero(
                        current[chain_base + TGT_MASK + input])) {
                    continue;
                }
                const Fp3 denominator = gf::Sub(
                    alpha[lane],
                    gf::Add(
                        current[chain_base + TGT_LINK + input],
                        gf::Mul(
                            gamma[lane],
                            current[ValueColumn(input)])));
                if (gf::IsZero(denominator)) {
                    out.note =
                        "stage3:hash_air:witness_chain_target_pole";
                    return out;
                }
                columns[tgt_inv + input][row] =
                    gf::Inv(denominator);
                current[tgt_inv + input] =
                    columns[tgt_inv + input][row];
                contribution = gf::Sub(
                    contribution,
                    current[tgt_inv + input]);
            }
            chain_running[lane] = gf::Add(
                chain_running[lane], contribution);
        }
    }
    if (!gf::IsZero(internal_running[0]) ||
        !gf::IsZero(internal_running[1]) ||
        !gf::IsZero(chain_running[0]) ||
        !gf::IsZero(chain_running[1])) {
        out.note =
            "stage3:hash_air:witness_vertical_terminal";
        return out;
    }
    out.columns = std::move(columns);
    out.valid = true;
    out.note =
        "stage3:hash_air:witness_vertical_complete";
    return out;
}

FixedProgramVerticalWitnessBoundaryInstance
BuildFixedProgramVerticalWitnessBoundaryInstance(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& precommitted_base_row)
{
    return BuildFixedProgramVerticalWitnessBoundaryInstanceImpl(
        program, boundaries, public_masks, links, fs_seed,
        precommitted_base_row, nullptr);
}

FixedProgramVerticalWitnessBoundaryInstance
BuildFixedProgramVerticalWitnessBoundaryInstanceWithChallengesV2(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& precommitted_base_row,
    const RCStage3CtlChallenges& transcript_challenges)
{
    return BuildFixedProgramVerticalWitnessBoundaryInstanceImpl(
        program, boundaries, public_masks, links, fs_seed,
        precommitted_base_row, &transcript_challenges);
}

static FixedProgramVerticalWitnessBoundaryVerifierInstance
BuildFixedProgramVerticalWitnessBoundaryVerifierInstanceImpl(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>&
        public_boundary_templates,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& base_row_commitment,
    const RCStage3CtlChallenges* transcript_challenges)
{
    FixedProgramVerticalWitnessBoundaryVerifierInstance
        out;
    if (public_boundary_templates.empty() ||
        public_boundary_templates.size() !=
            public_masks.size() ||
        fs_seed.IsNull() ||
        base_row_commitment.IsNull() ||
        !Fri3AlgDigestFromUint256(
            base_row_commitment)
             .has_value()) {
        out.note =
            "stage3:hash_air:"
            "witness_vertical_verifier_shape";
        return out;
    }
    std::vector<FixedProgramBoundaryInstance> dummy =
        public_boundary_templates;
    for (uint32_t instance = 0;
         instance < dummy.size(); ++instance) {
        if (dummy[instance].external_values.size() !=
                program.external_address_count ||
            dummy[instance].final_words.size() !=
                program.final_addresses.size() ||
            public_masks[instance].size() !=
                program.external_address_count) {
            out.note =
                "stage3:hash_air:"
                "witness_vertical_verifier_boundary";
            return out;
        }
        for (uint32_t external = 0;
             external <
                 program.external_address_count;
             ++external) {
            if (!public_masks[instance][external]) {
                dummy[instance]
                    .external_values[external] = 0;
            }
        }
        for (const auto& link : links) {
            if (link.target_instance != instance) {
                continue;
            }
            if (link.source_instance >= instance ||
                link.source_instance >= dummy.size() ||
                link.source_final_word >=
                    program.final_addresses.size() ||
                link.target_external_address == 0 ||
                link.target_external_address >
                    program.external_address_count ||
                public_masks[instance]
                    [link.target_external_address - 1]) {
                out.note =
                    "stage3:hash_air:"
                    "witness_vertical_verifier_link_order";
                return out;
            }
            dummy[instance].external_values[
                link.target_external_address - 1] =
                dummy[link.source_instance]
                    .final_words[
                        link.source_final_word];
        }
        ProgramWitness witness;
        std::string why;
        if (!BuildProgramWitness(
                program,
                dummy[instance].external_values,
                witness, &why)) {
            out.note =
                "stage3:hash_air:"
                "witness_vertical_verifier_dummy:" +
                why;
            return out;
        }
        dummy[instance].final_words =
            std::move(witness.final_words);
    }
    const uint256 expected_statement =
        CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, public_boundary_templates,
            public_masks, links);
    const auto reconstructed =
        transcript_challenges == nullptr
        ? BuildFixedProgramVerticalWitnessBoundaryInstance(
              program, dummy, public_masks, links,
              fs_seed, base_row_commitment)
        : BuildFixedProgramVerticalWitnessBoundaryInstanceWithChallengesV2(
              program, dummy, public_masks, links,
              fs_seed, base_row_commitment,
              *transcript_challenges);
    if (!reconstructed.valid ||
        expected_statement.IsNull() ||
        reconstructed.public_statement !=
            expected_statement ||
        reconstructed.base_row_commitment !=
            base_row_commitment ||
        reconstructed.base_row_tree_cache) {
        out.note =
            "stage3:hash_air:"
            "witness_vertical_verifier_reconstruct:" +
            reconstructed.note;
        return out;
    }
    out.semantic_instances =
        reconstructed.semantic_instances;
    out.scheduled_instances =
        reconstructed.scheduled_instances;
    out.public_statement =
        reconstructed.public_statement;
    out.base_row_commitment =
        reconstructed.base_row_commitment;
    out.base_column_indices =
        reconstructed.base_column_indices;
    out.challenges = reconstructed.challenges;
    out.cs = reconstructed.cs;
    out.final_output_rows =
        reconstructed.final_output_rows;
    out.output_export_base =
        reconstructed.output_export_base;
    out.output_bit_base =
        reconstructed.output_bit_base;
    out.output_byte_base =
        reconstructed.output_byte_base;
    out.input_word_base =
        reconstructed.input_word_base;
    out.input_byte_base =
        reconstructed.input_byte_base;
    out.input_bit_base =
        reconstructed.input_bit_base;
    out.input_active_column =
        reconstructed.input_active_column;
    out.input_address_column =
        reconstructed.input_address_column;
    out.valid = true;
    out.note =
        "stage3:hash_air:"
        "witness_vertical_verifier_public_only_cs";
    return out;
}

FixedProgramVerticalWitnessBoundaryVerifierInstance
BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>&
        public_boundary_templates,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& base_row_commitment)
{
    return BuildFixedProgramVerticalWitnessBoundaryVerifierInstanceImpl(
        program, public_boundary_templates, public_masks, links,
        fs_seed, base_row_commitment, nullptr);
}

FixedProgramVerticalWitnessBoundaryVerifierInstance
BuildFixedProgramVerticalWitnessBoundaryVerifierInstanceWithChallengesV2(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>&
        public_boundary_templates,
    const std::vector<std::vector<uint8_t>>& public_masks,
    const std::vector<FixedProgramWitnessBoundaryLink>& links,
    const uint256& fs_seed,
    const uint256& base_row_commitment,
    const RCStage3CtlChallenges& transcript_challenges)
{
    return BuildFixedProgramVerticalWitnessBoundaryVerifierInstanceImpl(
        program, public_boundary_templates, public_masks, links,
        fs_seed, base_row_commitment, &transcript_challenges);
}

bool ProveFixedProgramVerticalProvenanceAir(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const uint256& fs_seed,
    FixedProgramVerticalProvenanceAirProof& out,
    std::string* why)
{
    out = {};
    const auto instance =
        BuildFixedProgramVerticalProvenanceInstance(
            program, boundaries, fs_seed);
    if (!instance.valid) return Fail(why, instance.note);
    aq::AirProveOptions options;
    options.checked_trace_root_hints =
        instance.checked_trace_root_hints;
    const auto proved = aq::AirQuotientProve<
        Fp3, aq::AirFriBackendFp3StreamingColumns>(
            instance.cs, instance.columns, fs_seed, options);
    if (!proved.ok || !proved.division_exact) {
        return Fail(why, "vertical_prove:" + proved.note);
    }
    out.semantic_instances = instance.semantic_instances;
    out.boundary_statement = instance.boundary_statement;
    out.challenge_commitment =
        CommitRCStage3CtlChallenges(instance.challenges);
    out.quotient = proved.proof;
    out.valid = true;
    out.note = "stage3:hash_air:vertical_proved";
    return true;
}

bool VerifyFixedProgramVerticalProvenanceAir(
    const FixedProgram& program,
    const std::vector<FixedProgramBoundaryInstance>& boundaries,
    const uint256& fs_seed,
    const FixedProgramVerticalProvenanceAirProof& proof,
    std::string* why)
{
    const uint256 boundary_statement =
        CommitVerticalBoundaryStatement(program, boundaries);
    const auto& batch = proof.quotient.batch;
    if (boundary_statement.IsNull()) {
        return Fail(why, "vertical_verify_statement");
    }
    uint32_t scheduled_instances = 1;
    while (scheduled_instances < boundaries.size()) {
        scheduled_instances <<= 1;
    }
    if (scheduled_instances < 2) {
        scheduled_instances = 2;
    }
    if (proof.version != 1 || !proof.valid ||
        proof.semantic_instances != boundaries.size() ||
        proof.boundary_statement != boundary_statement ||
        batch.columns.size() !=
            kFixedProgramVerticalProvenanceColumns + 1 ||
        batch.column_len.size() !=
            kFixedProgramVerticalProvenanceColumns + 1 ||
        batch.column_len.empty() ||
        batch.column_len[0] !=
            1024 * scheduled_instances) {
        return Fail(why, "vertical_verify_shape");
    }
    std::vector<uint256> base_roots;
    for (uint32_t column = 0;
         column < kFixedProgramProvenanceBaseColumns;
         ++column) {
        base_roots.push_back(batch.columns[column].root);
    }
    base_roots.push_back(
        batch.columns[
            kFixedProgramVerticalInstanceIdColumn].root);
    base_roots.push_back(
        batch.columns[
            kFixedProgramVerticalPhaseColumn].root);
    base_roots.push_back(
        batch.columns[
            kFixedProgramVerticalActiveColumn].root);
    RCStage3CtlChallenges challenges;
    if (!DeriveVerticalChallenges(
            program, boundary_statement, fs_seed,
            batch.column_len[0], batch.n_coeffs,
            scheduled_instances,
            base_roots, challenges, why) ||
        proof.challenge_commitment !=
            CommitRCStage3CtlChallenges(challenges)) {
        return Fail(why, "vertical_verify_challenges");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildVerticalConstraintSystem(
            program, boundaries, challenges, cs, why,
            scheduled_instances)) {
        return Fail(why, "vertical_verify_cs");
    }
    std::string air_why;
    if (!aq::AirQuotientVerify<
            Fp3, aq::AirFriBackendFp3StreamingColumns>(
            cs, proof.quotient, fs_seed, &air_why)) {
        return Fail(
            why, "vertical_verify_air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:hash_air:vertical_complete_internal_ssa_ok";
    }
    return true;
}

uint32_t FixedProgramPackedColumn(
    uint32_t lane, uint32_t lane_column)
{
    if (lane >= kFixedProgramPackedLanes ||
        lane_column >= kFixedProgramBoundaryColumns) {
        return kFixedProgramPackedBoundaryColumns;
    }
    return lane * kFixedProgramBoundaryColumns + lane_column;
}

namespace {

bool ValidateParallelBoundaryInstances(
    const FixedProgram& program,
    const std::vector<FixedProgramPackedBoundaryInstance>& instances,
    std::string* why)
{
    if (instances.size() < 2 ||
        instances.size() > kFixedProgramMaxPackedLanes ||
        instances.size() * kFixedProgramBoundaryColumns >
            kFixedProgramRecursiveWidthCap) {
        return Fail(why, "parallel_boundary_lane_count");
    }
    for (uint32_t lane = 0; lane < instances.size(); ++lane) {
        if (instances[lane].external_values.size() !=
            program.external_address_count) {
            return Fail(why, "packed_boundary_external_count");
        }
        if (instances[lane].final_words.size() !=
            program.final_addresses.size()) {
            return Fail(why, "packed_boundary_final_count");
        }
        for (uint32_t previous = 0; previous < lane; ++previous) {
            if (instances[previous].ctl_namespace_id ==
                instances[lane].ctl_namespace_id) {
                return Fail(why, "packed_boundary_ctl_namespace_alias");
            }
        }
    }
    return true;
}

bool ValidatePackedBoundaryInstances(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    std::string* why)
{
    return ValidateParallelBoundaryInstances(
        program,
        std::vector<FixedProgramPackedBoundaryInstance>(
            instances.begin(), instances.end()),
        why);
}

void AddFixedProgramBoundaryAt(
    const FixedProgram& program,
    const FixedProgramPackedBoundaryInstance& instance,
    aq::AirConstraintSystem<Fp3>& out,
    uint32_t base)
{
    std::array<std::vector<Fp3>, 4> expected;
    std::array<std::vector<Fp3>, 4> mask;
    for (uint32_t word = 0; word < 4; ++word) {
        expected[word].assign(out.n_rows, Fp3::Zero());
        mask[word].assign(out.n_rows, Fp3::Zero());
    }
    for (uint32_t row_index = 0; row_index < program.rows.size();
         ++row_index) {
        const auto& row = program.rows[row_index];
        for (uint32_t input = 0; input < row.input_count; ++input) {
            const uint32_t address = row.input_address[input];
            if (address > 0 &&
                address <= program.external_address_count) {
                expected[input][row_index] =
                    U(instance.external_values[address - 1]);
                mask[input][row_index] = Fp3::One();
            }
        }
        const auto final = std::find(
            program.final_addresses.begin(),
            program.final_addresses.end(), row.output_address);
        if (final != program.final_addresses.end()) {
            const uint32_t word = OutputWordSlot(row);
            const size_t index =
                static_cast<size_t>(
                    final - program.final_addresses.begin());
            expected[word][row_index] =
                U(instance.final_words[index]);
            mask[word][row_index] = Fp3::One();
        }
    }
    for (uint32_t word = 0; word < 4; ++word) {
        out.preprocessed.push_back(
            {LaneColumn(
                 base, kFixedProgramBoundaryExpectedBase + word),
             std::move(expected[word])});
        out.preprocessed.push_back(
            {LaneColumn(
                 base, kFixedProgramBoundaryMaskBase + word),
             std::move(mask[word])});
        Add(out, "stage3.hash.program.packed.public_boundary", 2,
            [base, word](const std::vector<Fp3>& cur,
                         const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[LaneColumn(
                        base, kFixedProgramBoundaryMaskBase + word)],
                    gf::Sub(
                        cur[LaneColumn(base, ValueColumn(word))],
                        cur[LaneColumn(
                            base,
                            kFixedProgramBoundaryExpectedBase + word)]));
            });
    }
}

} // namespace

bool BuildFixedProgramParallelBoundaryConstraintSystem(
    const FixedProgram& program,
    const std::vector<FixedProgramPackedBoundaryInstance>& instances,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ValidateCanonicalProgram(program, why) ||
        !ValidateParallelBoundaryInstances(program, instances, why)) {
        return false;
    }
    out.n_rows = NextPow2(program.rows.size());
    out.n_columns =
        instances.size() * kFixedProgramBoundaryColumns;
    for (uint32_t lane = 0; lane < instances.size(); ++lane) {
        const uint32_t base =
            lane * kFixedProgramBoundaryColumns;
        AddFixedProgramCoreAt(program, out, base);
        AddFixedProgramBoundaryAt(
            program, instances[lane], out, base);
    }
    out.preprocessed_pin_ood = true;
    return true;
}

bool BuildFixedProgramParallelBoundaryAirWitness(
    const FixedProgram& program,
    const std::vector<ProgramWitness>& witnesses,
    const std::vector<FixedProgramPackedBoundaryInstance>& instances,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    columns.clear();
    if (witnesses.size() != instances.size()) {
        return Fail(why, "parallel_boundary_witness_count");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramParallelBoundaryConstraintSystem(
            program, instances, cs, why)) {
        return false;
    }
    columns.assign(
        cs.n_columns, std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0; lane < instances.size(); ++lane) {
        std::vector<std::vector<Fp3>> lane_columns;
        if (!BuildFixedProgramBoundaryAirWitness(
                program, witnesses[lane],
                instances[lane].external_values,
                instances[lane].final_words,
                lane_columns, why)) {
            return false;
        }
        if (lane_columns.size() != kFixedProgramBoundaryColumns) {
            return Fail(why, "parallel_boundary_lane_width");
        }
        for (uint32_t column = 0;
             column < kFixedProgramBoundaryColumns; ++column) {
            columns[lane * kFixedProgramBoundaryColumns + column] =
                std::move(lane_columns[column]);
        }
    }
    return true;
}

bool BuildFixedProgramPackedBoundaryConstraintSystem(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ValidateCanonicalProgram(program, why) ||
        !ValidatePackedBoundaryInstances(program, instances, why)) {
        return false;
    }
    out.n_rows = NextPow2(program.rows.size());
    out.n_columns = kFixedProgramPackedBoundaryColumns;
    for (uint32_t lane = 0; lane < kFixedProgramPackedLanes; ++lane) {
        const uint32_t base =
            lane * kFixedProgramBoundaryColumns;
        AddFixedProgramCoreAt(program, out, base);
        AddFixedProgramBoundaryAt(
            program, instances[lane], out, base);
    }
    out.preprocessed_pin_ood = true;
    return true;
}

bool BuildFixedProgramPackedBoundaryAirWitness(
    const FixedProgram& program,
    const std::array<ProgramWitness, kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    columns.clear();
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramPackedBoundaryConstraintSystem(
            program, instances, cs, why)) {
        return false;
    }
    columns.assign(
        cs.n_columns, std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0; lane < kFixedProgramPackedLanes; ++lane) {
        std::vector<std::vector<Fp3>> lane_columns;
        if (!BuildFixedProgramBoundaryAirWitness(
                program, witnesses[lane],
                instances[lane].external_values,
                instances[lane].final_words,
                lane_columns, why)) {
            return false;
        }
        if (lane_columns.size() != kFixedProgramBoundaryColumns) {
            return Fail(why, "packed_boundary_lane_width");
        }
        for (uint32_t column = 0;
             column < kFixedProgramBoundaryColumns; ++column) {
            columns[FixedProgramPackedColumn(lane, column)] =
                std::move(lane_columns[column]);
        }
    }
    return true;
}

bool BuildFixedProgramPackedCtlSchedules(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    std::array<RCStage3CtlSchedule, kFixedProgramPackedLanes>& out,
    std::string* why)
{
    out = {};
    if (!ValidateCanonicalProgram(program, why) ||
        !ValidatePackedBoundaryInstances(program, instances, why)) {
        return false;
    }
    for (uint32_t lane = 0; lane < kFixedProgramPackedLanes; ++lane) {
        out[lane] = BuildProgramCtlSchedule(
            program, instances[lane].ctl_namespace_id);
        if (!ValidateRCStage3CtlSchedule(out[lane], why)) {
            return Fail(why, "packed_boundary_ctl_schedule");
        }
    }
    return true;
}

uint256 CommitFixedProgramPackedBoundaryStatement(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances)
{
    std::string ignored;
    if (!ValidateCanonicalProgram(program, &ignored) ||
        !ValidatePackedBoundaryInstances(program, instances, &ignored)) {
        return {};
    }
    const uint256 program_commitment = CommitFixedProgram(program);
    if (program_commitment.IsNull()) return {};
    std::vector<uint8_t> bytes;
    AppendHash(bytes, program_commitment);
    AppendU32(bytes, kFixedProgramPackedLanes);
    for (const auto& instance : instances) {
        const uint256 boundary =
            CommitFixedProgramBoundaryStatement(
                program, instance.external_values,
                instance.final_words);
        if (boundary.IsNull()) return {};
        AppendU32(bytes, instance.ctl_namespace_id);
        AppendHash(bytes, boundary);
    }
    return Sha256dTagged(
        "BTX_RC_STAGE3_FIXED_HASH_PACKED_BOUNDARY_STATEMENT_V1",
        bytes);
}

namespace {

Fp3 FixedProgramOutputValueAt(
    const std::vector<Fp3>& row, uint32_t base)
{
    Fp3 word1_selector = Fp3::Zero();
    for (uint32_t selector = 7; selector <= 10; ++selector) {
        word1_selector = gf::Add(
            word1_selector,
            row[LaneColumn(
                base, kFixedProgramSelectorBase + selector)]);
    }
    Fp3 word2_selector = Fp3::Zero();
    for (uint32_t selector = 0; selector <= 4; ++selector) {
        word2_selector = gf::Add(
            word2_selector,
            row[LaneColumn(
                base, kFixedProgramSelectorBase + selector)]);
    }
    const Fp3 word3_selector = gf::Add(
        row[LaneColumn(base, kFixedProgramSelectorBase + 5)],
        row[LaneColumn(base, kFixedProgramSelectorBase + 6)]);
    return gf::Add(
        gf::Mul(
            word1_selector,
            row[LaneColumn(base, ValueColumn(1))]),
        gf::Add(
            gf::Mul(
                word2_selector,
                row[LaneColumn(base, ValueColumn(2))]),
            gf::Mul(
                word3_selector,
                row[LaneColumn(base, ValueColumn(3))])));
}

Fp3 FixedProgramProvenanceContributionAt(
    const std::vector<Fp3>& row, uint32_t base,
    uint32_t challenge_lane)
{
    const uint32_t producer_inverse =
        challenge_lane == 0
        ? kFixedProgramProvenanceProducerInverse1
        : kFixedProgramProvenanceProducerInverse2;
    const uint32_t consumer_base =
        challenge_lane == 0
        ? kFixedProgramProvenanceConsumerInverse1Base
        : kFixedProgramProvenanceConsumerInverse2Base;
    Fp3 contribution = gf::Mul(
        row[LaneColumn(
            base, kFixedProgramProvenanceOutputUseCount)],
        row[LaneColumn(base, producer_inverse)]);
    for (uint32_t input = 0; input < 3; ++input) {
        contribution = gf::Sub(
            contribution,
            gf::Mul(
                row[LaneColumn(
                    base,
                    kFixedProgramProvenanceInputMaskBase + input)],
                row[LaneColumn(
                    base, consumer_base + input)]));
    }
    return contribution;
}

void AddFixedProgramProvenanceAt(
    const FixedProgram& program,
    const FixedProgramPackedBoundaryInstance& instance,
    const RCStage3CtlChallenges& challenges,
    aq::AirConstraintSystem<Fp3>& out,
    uint32_t base)
{
    auto metadata =
        FixedProgramProvenanceMetadata(program, out.n_rows);
    for (uint32_t offset = 0;
         offset < metadata.size(); ++offset) {
        out.preprocessed.emplace_back(
            LaneColumn(
                base,
                kFixedProgramBoundaryColumns + offset),
            std::move(metadata[offset]));
    }

    const Fp3 namespace_domain =
        U(instance.ctl_namespace_id);
    const std::array<Fp3, 2> gamma{
        challenges.gamma1, challenges.gamma2};
    const std::array<Fp3, 2> alpha{
        challenges.alpha1, challenges.alpha2};
    for (uint32_t challenge_lane = 0;
         challenge_lane < 2; ++challenge_lane) {
        const uint32_t producer_inverse =
            challenge_lane == 0
            ? kFixedProgramProvenanceProducerInverse1
            : kFixedProgramProvenanceProducerInverse2;
        const uint32_t consumer_base =
            challenge_lane == 0
            ? kFixedProgramProvenanceConsumerInverse1Base
            : kFixedProgramProvenanceConsumerInverse2Base;
        const uint32_t running =
            challenge_lane == 0
            ? kFixedProgramProvenanceRunning1
            : kFixedProgramProvenanceRunning2;

        Add(out,
            "stage3.hash.packed_provenance.producer_inverse",
            3,
            [base, challenge_lane, producer_inverse,
             namespace_domain, gamma, alpha](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                const Fp3 tuple = gf::Add(
                    namespace_domain,
                    gf::Add(
                        cur[LaneColumn(
                            base,
                            kFixedProgramProvenanceOutputAddress)],
                        gf::Mul(
                            gamma[challenge_lane],
                            FixedProgramOutputValueAt(cur, base))));
                return gf::Sub(
                    gf::Mul(
                        gf::Sub(alpha[challenge_lane], tuple),
                        cur[LaneColumn(base, producer_inverse)]),
                    cur[LaneColumn(
                        base,
                        kFixedProgramProvenanceOutputHasUse)]);
            });
        Add(out,
            "stage3.hash.packed_provenance.producer_padding",
            2,
            [base, producer_inverse](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[LaneColumn(
                            base,
                            kFixedProgramProvenanceOutputHasUse)]),
                    cur[LaneColumn(base, producer_inverse)]);
            });
        for (uint32_t input = 0; input < 3; ++input) {
            Add(out,
                "stage3.hash.packed_provenance.consumer_inverse",
                2,
                [base, challenge_lane, input, consumer_base,
                 namespace_domain, gamma, alpha](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 tuple = gf::Add(
                        namespace_domain,
                        gf::Add(
                            cur[LaneColumn(
                                base,
                                kFixedProgramProvenanceInputAddressBase +
                                    input)],
                            gf::Mul(
                                gamma[challenge_lane],
                                cur[LaneColumn(
                                    base, ValueColumn(input))])));
                    return gf::Sub(
                        gf::Mul(
                            gf::Sub(
                                alpha[challenge_lane], tuple),
                            cur[LaneColumn(
                                base, consumer_base + input)]),
                        cur[LaneColumn(
                            base,
                            kFixedProgramProvenanceInputMaskBase +
                                input)]);
                });
            Add(out,
                "stage3.hash.packed_provenance.consumer_padding",
                2,
                [base, input, consumer_base](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[LaneColumn(
                                base,
                                kFixedProgramProvenanceInputMaskBase +
                                    input)]),
                        cur[LaneColumn(
                            base, consumer_base + input)]);
                });
        }
        AddKind(
            out,
            "stage3.hash.packed_provenance.running_first",
            aq::AirKind::kFirstRow, 1,
            [base, running](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[LaneColumn(base, running)];
            });
        AddKind(
            out,
            "stage3.hash.packed_provenance.running_transition",
            aq::AirKind::kTransition, 2,
            [base, challenge_lane, running](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Sub(
                    next[LaneColumn(base, running)],
                    gf::Add(
                        cur[LaneColumn(base, running)],
                        FixedProgramProvenanceContributionAt(
                            cur, base, challenge_lane)));
            });
        AddKind(
            out,
            "stage3.hash.packed_provenance.running_last",
            aq::AirKind::kLastRow, 2,
            [base, challenge_lane, running](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Add(
                    cur[LaneColumn(base, running)],
                    FixedProgramProvenanceContributionAt(
                        cur, base, challenge_lane));
            });
    }
}

bool BuildFixedProgramPackedProvenanceConstraintSystem(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const std::array<RCStage3CtlChallenges,
                     kFixedProgramPackedLanes>& challenges,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!ValidateCanonicalProgram(program, why) ||
        !ValidatePackedBoundaryInstances(program, instances, why)) {
        return false;
    }
    out.n_rows = NextPow2(program.rows.size());
    out.n_columns = kFixedProgramPackedProvenanceColumns;
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        const uint32_t base =
            lane * kFixedProgramProvenanceColumns;
        AddFixedProgramCoreAt(program, out, base);
        AddFixedProgramBoundaryAt(
            program, instances[lane], out, base);
        AddFixedProgramProvenanceAt(
            program, instances[lane],
            challenges[lane], out, base);
    }
    out.preprocessed_pin_ood = true;
    return true;
}

using PackedProvenanceBaseRoots =
    std::array<std::vector<uint256>,
               kFixedProgramPackedLanes>;

PackedProvenanceBaseRoots
FixedProgramPackedProvenanceBaseRoots(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t n_coeffs)
{
    PackedProvenanceBaseRoots roots;
    if (columns.size() <
        kFixedProgramPackedProvenanceColumns) {
        return {};
    }
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        roots[lane].resize(
            kFixedProgramProvenanceBaseColumns);
        const uint32_t base =
            lane * kFixedProgramProvenanceColumns;
        for (uint32_t column = 0;
             column <
                 kFixedProgramProvenanceBaseColumns;
             ++column) {
            roots[lane][column] =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[base + column], n_coeffs);
        }
    }
    return roots;
}

uint256 FixedProgramPackedProvenanceTraceCommitment(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& statement_commitment,
    uint32_t n_rows, uint32_t n_coeffs,
    const PackedProvenanceBaseRoots& roots)
{
    if (statement_commitment.IsNull()) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_FIXED_HASH_PACKED_PROVENANCE_TRACE_V1";
    hash << CommitFixedProgram(program);
    hash << statement_commitment;
    hash << n_rows;
    hash << n_coeffs;
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        if (roots[lane].size() !=
            kFixedProgramProvenanceBaseColumns) {
            return {};
        }
        hash << lane;
        hash << instances[lane].ctl_namespace_id;
        for (const auto& root : roots[lane]) hash << root;
    }
    return hash.GetHash();
}

bool DeriveFixedProgramPackedProvenanceChallenges(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& statement_commitment,
    const uint256& fs_seed,
    uint32_t n_rows, uint32_t n_coeffs,
    const PackedProvenanceBaseRoots& roots,
    uint256& trace_commitment,
    std::array<RCStage3CtlChallenges,
               kFixedProgramPackedLanes>& challenges,
    std::string* why)
{
    challenges = {};
    trace_commitment =
        FixedProgramPackedProvenanceTraceCommitment(
            program, instances, statement_commitment,
            n_rows, n_coeffs, roots);
    if (trace_commitment.IsNull() || fs_seed.IsNull()) {
        return Fail(
            why, "packed_provenance_trace_commitment");
    }
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        const uint256 boundary =
            CommitFixedProgramBoundaryStatement(
                program, instances[lane].external_values,
                instances[lane].final_words);
        HashWriter lane_hash;
        lane_hash <<
            "BTX_RC_STAGE3_FIXED_HASH_PACKED_PROVENANCE_LANE_V1";
        lane_hash << fs_seed;
        lane_hash << trace_commitment;
        lane_hash << lane;
        lane_hash << instances[lane].ctl_namespace_id;
        const uint256 lane_seed = lane_hash.GetHash();
        if (boundary.IsNull() ||
            !DeriveFixedProgramProvenanceChallenges(
                program, boundary, lane_seed,
                n_rows, n_coeffs, roots[lane],
                challenges[lane], why)) {
            return Fail(
                why, "packed_provenance_lane_challenge");
        }
    }
    return true;
}

uint256 FixedProgramPackedProvenanceAirSeed(
    const uint256& fs_seed,
    const uint256& program_commitment,
    const uint256& statement_commitment,
    const uint256& trace_commitment,
    const std::array<uint256,
                     kFixedProgramPackedLanes>&
        challenge_commitments)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_FIXED_HASH_PACKED_PROVENANCE_AIR_SEED_V1";
    hash << fs_seed;
    hash << program_commitment;
    hash << statement_commitment;
    hash << trace_commitment;
    for (const auto& commitment :
         challenge_commitments) {
        hash << commitment;
    }
    return hash.GetHash();
}

uint256 FixedProgramBoundaryAirSeed(
    const uint256& fs_seed,
    const uint256& program_commitment,
    const uint256& statement_commitment)
{
    std::vector<uint8_t> bytes;
    AppendHash(bytes, fs_seed);
    AppendHash(bytes, program_commitment);
    AppendHash(bytes, statement_commitment);
    return Sha256dTagged(
        "BTX_RC_STAGE3_FIXED_HASH_BOUNDARY_AIR_SEED_V1", bytes);
}

uint256 FixedProgramPackedBoundaryAirSeed(
    const uint256& fs_seed,
    const uint256& program_commitment,
    const uint256& statement_commitment)
{
    std::vector<uint8_t> bytes;
    AppendHash(bytes, fs_seed);
    AppendHash(bytes, program_commitment);
    AppendHash(bytes, statement_commitment);
    return Sha256dTagged(
        "BTX_RC_STAGE3_FIXED_HASH_PACKED_BOUNDARY_AIR_SEED_V1",
        bytes);
}

} // namespace

FixedProgramPackedProvenanceInstance
BuildFixedProgramPackedProvenanceInstance(
    const FixedProgram& program,
    const std::array<ProgramWitness,
                     kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed)
{
    FixedProgramPackedProvenanceInstance out;
    out.statement_commitment =
        CommitFixedProgramPackedBoundaryStatement(
            program, instances);
    if (out.statement_commitment.IsNull() ||
        fs_seed.IsNull()) {
        out.note =
            "stage3:hash_air:"
            "packed_provenance_statement";
        return out;
    }

    std::array<RCStage3CtlChallenges,
               kFixedProgramPackedLanes> zero_challenges{};
    aq::AirConstraintSystem<Fp3> dummy;
    std::string why;
    if (!BuildFixedProgramPackedProvenanceConstraintSystem(
            program, instances, zero_challenges,
            dummy, &why)) {
        out.note = why;
        return out;
    }
    std::vector<std::vector<Fp3>> columns(
        dummy.n_columns,
        std::vector<Fp3>(
            dummy.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        std::vector<std::vector<Fp3>> lane_columns;
        if (!BuildFixedProgramBoundaryAirWitness(
                program, witnesses[lane],
                instances[lane].external_values,
                instances[lane].final_words,
                lane_columns, &why) ||
            lane_columns.size() !=
                kFixedProgramBoundaryColumns) {
            out.note = why.empty()
                ? "stage3:hash_air:"
                  "packed_provenance_boundary_witness"
                : why;
            return out;
        }
        const uint32_t base =
            lane * kFixedProgramProvenanceColumns;
        for (uint32_t column = 0;
             column <
                 kFixedProgramBoundaryColumns;
             ++column) {
            columns[base + column] =
                std::move(lane_columns[column]);
        }
        auto metadata =
            FixedProgramProvenanceMetadata(
                program, dummy.n_rows);
        for (uint32_t offset = 0;
             offset < metadata.size(); ++offset) {
            columns[
                base +
                kFixedProgramBoundaryColumns +
                offset] =
                std::move(metadata[offset]);
        }
    }

    const uint32_t n_coeffs = FriNextPow2(
        std::max(dummy.n_rows, dummy.QuotientLen()));
    const auto roots =
        FixedProgramPackedProvenanceBaseRoots(
            columns, n_coeffs);
    if (!DeriveFixedProgramPackedProvenanceChallenges(
            program, instances,
            out.statement_commitment, fs_seed,
            dummy.n_rows, n_coeffs, roots,
            out.trace_commitment,
            out.challenges, &why) ||
        !BuildFixedProgramPackedProvenanceConstraintSystem(
            program, instances, out.challenges,
            out.cs, &why)) {
        out.note = why;
        return out;
    }

    std::array<std::array<Fp3, 2>,
               kFixedProgramPackedLanes> running{};
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        running[lane] = {
            Fp3::Zero(), Fp3::Zero()};
    }
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        std::vector<Fp3> current(
            out.cs.n_columns, Fp3::Zero());
        for (uint32_t column = 0;
             column < out.cs.n_columns; ++column) {
            current[column] = columns[column][row];
        }
        for (uint32_t lane = 0;
             lane < kFixedProgramPackedLanes; ++lane) {
            const uint32_t base =
                lane * kFixedProgramProvenanceColumns;
            const Fp3 namespace_domain =
                U(instances[lane].ctl_namespace_id);
            const std::array<Fp3, 2> gamma{
                out.challenges[lane].gamma1,
                out.challenges[lane].gamma2};
            const std::array<Fp3, 2> alpha{
                out.challenges[lane].alpha1,
                out.challenges[lane].alpha2};
            for (uint32_t challenge_lane = 0;
                 challenge_lane < 2;
                 ++challenge_lane) {
                const uint32_t producer_inverse =
                    challenge_lane == 0
                    ? kFixedProgramProvenanceProducerInverse1
                    : kFixedProgramProvenanceProducerInverse2;
                const uint32_t consumer_base =
                    challenge_lane == 0
                    ? kFixedProgramProvenanceConsumerInverse1Base
                    : kFixedProgramProvenanceConsumerInverse2Base;
                const uint32_t running_column =
                    challenge_lane == 0
                    ? kFixedProgramProvenanceRunning1
                    : kFixedProgramProvenanceRunning2;
                columns[
                    base + running_column][row] =
                    running[lane][challenge_lane];
                current[
                    base + running_column] =
                    running[lane][challenge_lane];

                if (!gf::IsZero(
                        current[
                            base +
                            kFixedProgramProvenanceOutputHasUse])) {
                    const Fp3 tuple = gf::Add(
                        namespace_domain,
                        gf::Add(
                            current[
                                base +
                                kFixedProgramProvenanceOutputAddress],
                            gf::Mul(
                                gamma[challenge_lane],
                                FixedProgramOutputValueAt(
                                    current, base))));
                    const Fp3 denominator =
                        gf::Sub(
                            alpha[challenge_lane], tuple);
                    if (gf::IsZero(denominator)) {
                        out.note =
                            "stage3:hash_air:"
                            "packed_provenance_producer_pole";
                        return out;
                    }
                    columns[
                        base + producer_inverse][row] =
                        gf::Inv(denominator);
                    current[
                        base + producer_inverse] =
                        columns[
                            base + producer_inverse][row];
                }
                for (uint32_t input = 0;
                     input < 3; ++input) {
                    if (gf::IsZero(
                            current[
                                base +
                                kFixedProgramProvenanceInputMaskBase +
                                input])) {
                        continue;
                    }
                    const Fp3 tuple = gf::Add(
                        namespace_domain,
                        gf::Add(
                            current[
                                base +
                                kFixedProgramProvenanceInputAddressBase +
                                input],
                            gf::Mul(
                                gamma[challenge_lane],
                                current[
                                    base +
                                    ValueColumn(input)])));
                    const Fp3 denominator =
                        gf::Sub(
                            alpha[challenge_lane], tuple);
                    if (gf::IsZero(denominator)) {
                        out.note =
                            "stage3:hash_air:"
                            "packed_provenance_consumer_pole";
                        return out;
                    }
                    columns[
                        base + consumer_base + input][row] =
                        gf::Inv(denominator);
                    current[
                        base + consumer_base + input] =
                        columns[
                            base + consumer_base + input][row];
                }
                running[lane][challenge_lane] =
                    gf::Add(
                        running[lane][challenge_lane],
                        FixedProgramProvenanceContributionAt(
                            current, base,
                            challenge_lane));
            }
        }
    }
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        if (!gf::IsZero(running[lane][0]) ||
            !gf::IsZero(running[lane][1])) {
            out.note =
                "stage3:hash_air:"
                "packed_provenance_terminal";
            return out;
        }
    }
    out.columns = std::move(columns);
    out.valid = true;
    out.note =
        "stage3:hash_air:"
        "packed_provenance_complete_internal_ssa";
    return out;
}

bool ProveFixedProgramPackedProvenanceAir(
    const FixedProgram& program,
    const std::array<ProgramWitness,
                     kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed,
    FixedProgramPackedProvenanceAirProof& out,
    std::string* why)
{
    out = {};
    const auto instance =
        BuildFixedProgramPackedProvenanceInstance(
            program, witnesses, instances, fs_seed);
    if (!instance.valid) {
        return Fail(why, instance.note);
    }
    const uint256 program_commitment =
        CommitFixedProgram(program);
    std::array<uint256,
               kFixedProgramPackedLanes>
        challenge_commitments{};
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        challenge_commitments[lane] =
            CommitRCStage3CtlChallenges(
                instance.challenges[lane]);
    }
    const uint256 proof_seed =
        FixedProgramPackedProvenanceAirSeed(
            fs_seed, program_commitment,
            instance.statement_commitment,
            instance.trace_commitment,
            challenge_commitments);
    const auto proved =
        aq::AirQuotientProve<Fp3>(
            instance.cs, instance.columns,
            proof_seed, {});
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why,
            "packed_provenance_prove:" +
                proved.note);
    }
    out.registry_version = kRegistryVersion;
    out.kind = program.kind;
    out.program_commitment =
        program_commitment;
    out.statement_commitment =
        instance.statement_commitment;
    out.trace_commitment =
        instance.trace_commitment;
    out.challenge_commitments =
        challenge_commitments;
    out.quotient = proved.proof;
    out.valid = true;
    return true;
}

bool VerifyFixedProgramPackedProvenanceAir(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed,
    const FixedProgramPackedProvenanceAirProof& proof,
    std::string* why)
{
    const uint256 program_commitment =
        CommitFixedProgram(program);
    const uint256 statement_commitment =
        CommitFixedProgramPackedBoundaryStatement(
            program, instances);
    const auto& batch = proof.quotient.batch;
    if (!proof.valid ||
        proof.registry_version != kRegistryVersion ||
        proof.kind != program.kind ||
        program_commitment.IsNull() ||
        proof.program_commitment !=
            program_commitment ||
        statement_commitment.IsNull() ||
        proof.statement_commitment !=
            statement_commitment ||
        batch.columns.size() !=
            kFixedProgramPackedProvenanceColumns + 1 ||
        batch.column_len.size() !=
            kFixedProgramPackedProvenanceColumns + 1 ||
        batch.column_len.empty()) {
        return Fail(
            why, "packed_provenance_verify_shape");
    }
    const uint32_t n_rows =
        batch.column_len[0];
    if (!IsPowerOfTwo(n_rows)) {
        return Fail(
            why, "packed_provenance_verify_rows");
    }
    PackedProvenanceBaseRoots roots;
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        roots[lane].resize(
            kFixedProgramProvenanceBaseColumns);
        const uint32_t base =
            lane * kFixedProgramProvenanceColumns;
        for (uint32_t column = 0;
             column <
                 kFixedProgramProvenanceBaseColumns;
             ++column) {
            if (batch.column_len[base + column] !=
                n_rows) {
                return Fail(
                    why,
                    "packed_provenance_verify_lane_rows");
            }
            roots[lane][column] =
                batch.columns[
                    base + column].root;
        }
    }
    uint256 trace_commitment;
    std::array<RCStage3CtlChallenges,
               kFixedProgramPackedLanes> challenges{};
    if (!DeriveFixedProgramPackedProvenanceChallenges(
            program, instances,
            statement_commitment, fs_seed,
            n_rows, batch.n_coeffs, roots,
            trace_commitment, challenges,
            why) ||
        trace_commitment !=
            proof.trace_commitment) {
        return Fail(
            why,
            "packed_provenance_verify_challenges");
    }
    std::array<uint256,
               kFixedProgramPackedLanes>
        challenge_commitments{};
    for (uint32_t lane = 0;
         lane < kFixedProgramPackedLanes; ++lane) {
        challenge_commitments[lane] =
            CommitRCStage3CtlChallenges(
                challenges[lane]);
        if (challenge_commitments[lane] !=
            proof.challenge_commitments[lane]) {
            return Fail(
                why,
                "packed_provenance_verify_lane_challenge");
        }
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramPackedProvenanceConstraintSystem(
            program, instances, challenges,
            cs, why) ||
        cs.n_rows != n_rows) {
        return Fail(
            why, "packed_provenance_verify_cs");
    }
    const uint256 proof_seed =
        FixedProgramPackedProvenanceAirSeed(
            fs_seed, program_commitment,
            statement_commitment,
            trace_commitment,
            challenge_commitments);
    std::string air_why;
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof.quotient,
            proof_seed, &air_why)) {
        return Fail(
            why,
            "packed_provenance_verify_air:" +
                air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:hash_air:"
            "packed_provenance_complete_internal_ssa_ok";
    }
    return true;
}

bool ProveFixedProgramBoundaryAir(
    const FixedProgram& program,
    const ProgramWitness& witness,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const uint256& fs_seed,
    FixedProgramBoundaryAirProof& out,
    std::string* why)
{
    out = {};
    const uint256 program_commitment = CommitFixedProgram(program);
    const uint256 statement_commitment =
        CommitFixedProgramBoundaryStatement(
            program, external_values, final_words);
    if (program_commitment.IsNull() || statement_commitment.IsNull()) {
        return Fail(why, "fixed_program_boundary_statement");
    }
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    if (!BuildFixedProgramBoundaryConstraintSystem(
            program, external_values, final_words, cs, why) ||
        !BuildFixedProgramBoundaryAirWitness(
            program, witness, external_values, final_words, columns, why)) {
        return false;
    }
    const uint256 seed = FixedProgramBoundaryAirSeed(
        fs_seed, program_commitment, statement_commitment);
    auto proved = aq::AirQuotientProve<Fp3>(cs, columns, seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, proved.note.empty()
                ? "fixed_program_boundary_air_prove"
                : proved.note);
    }
    out.registry_version = kRegistryVersion;
    out.kind = program.kind;
    out.program_commitment = program_commitment;
    out.statement_commitment = statement_commitment;
    out.quotient = std::move(proved.proof);
    return true;
}

bool VerifyFixedProgramBoundaryAir(
    const FixedProgram& program,
    const std::vector<uint32_t>& external_values,
    const std::vector<uint32_t>& final_words,
    const FixedProgramBoundaryAirProof& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (proof.registry_version != kRegistryVersion) {
        return Fail(why, "fixed_program_boundary_bad_version");
    }
    if (proof.kind != program.kind) {
        return Fail(why, "fixed_program_boundary_kind");
    }
    const uint256 program_commitment = CommitFixedProgram(program);
    const uint256 statement_commitment =
        CommitFixedProgramBoundaryStatement(
            program, external_values, final_words);
    if (program_commitment.IsNull() ||
        proof.program_commitment != program_commitment) {
        return Fail(why, "fixed_program_boundary_program_commitment");
    }
    if (statement_commitment.IsNull() ||
        proof.statement_commitment != statement_commitment) {
        return Fail(why, "fixed_program_boundary_statement_commitment");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramBoundaryConstraintSystem(
            program, external_values, final_words, cs, why)) {
        return false;
    }
    const uint256 seed = FixedProgramBoundaryAirSeed(
        fs_seed, program_commitment, statement_commitment);
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof.quotient, seed, why)) {
        return Fail(why, why && !why->empty()
            ? *why : "fixed_program_boundary_air_verify");
    }
    return true;
}

bool ProveFixedProgramPackedBoundaryAir(
    const FixedProgram& program,
    const std::array<ProgramWitness, kFixedProgramPackedLanes>& witnesses,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const uint256& fs_seed,
    FixedProgramPackedBoundaryAirProof& out,
    std::string* why)
{
    out = {};
    const uint256 program_commitment = CommitFixedProgram(program);
    const uint256 statement_commitment =
        CommitFixedProgramPackedBoundaryStatement(program, instances);
    if (program_commitment.IsNull() || statement_commitment.IsNull()) {
        return Fail(why, "packed_boundary_statement");
    }
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    if (!BuildFixedProgramPackedBoundaryConstraintSystem(
            program, instances, cs, why) ||
        !BuildFixedProgramPackedBoundaryAirWitness(
            program, witnesses, instances, columns, why)) {
        return false;
    }
    const uint256 seed = FixedProgramPackedBoundaryAirSeed(
        fs_seed, program_commitment, statement_commitment);
    auto proved = aq::AirQuotientProve<Fp3>(
        cs, columns, seed);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, proved.note.empty()
                ? "packed_boundary_air_prove"
                : proved.note);
    }
    out.registry_version = kRegistryVersion;
    out.kind = program.kind;
    out.program_commitment = program_commitment;
    out.statement_commitment = statement_commitment;
    out.quotient = std::move(proved.proof);
    return true;
}

bool VerifyFixedProgramPackedBoundaryAir(
    const FixedProgram& program,
    const std::array<FixedProgramPackedBoundaryInstance,
                     kFixedProgramPackedLanes>& instances,
    const FixedProgramPackedBoundaryAirProof& proof,
    const uint256& fs_seed,
    std::string* why)
{
    if (proof.registry_version != kRegistryVersion) {
        return Fail(why, "packed_boundary_bad_version");
    }
    if (proof.kind != program.kind) {
        return Fail(why, "packed_boundary_kind");
    }
    const uint256 program_commitment = CommitFixedProgram(program);
    const uint256 statement_commitment =
        CommitFixedProgramPackedBoundaryStatement(program, instances);
    if (program_commitment.IsNull() ||
        proof.program_commitment != program_commitment) {
        return Fail(
            why, "packed_boundary_program_commitment");
    }
    if (statement_commitment.IsNull() ||
        proof.statement_commitment != statement_commitment) {
        return Fail(
            why, "packed_boundary_statement_commitment");
    }
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildFixedProgramPackedBoundaryConstraintSystem(
            program, instances, cs, why)) {
        return false;
    }
    const uint256 seed = FixedProgramPackedBoundaryAirSeed(
        fs_seed, program_commitment, statement_commitment);
    if (!aq::AirQuotientVerify<Fp3>(
            cs, proof.quotient, seed, why)) {
        return Fail(
            why, why && !why->empty()
                ? *why : "packed_boundary_air_verify");
    }
    return true;
}

uint256 CommitShaManifest(const ShaManifest& manifest)
{
    std::vector<uint8_t> bytes;
    bytes.push_back(static_cast<uint8_t>(manifest.mode));
    AppendU64(bytes, manifest.preimage.size());
    bytes.insert(bytes.end(), manifest.preimage.begin(), manifest.preimage.end());
    AppendShaPass(bytes, manifest.first);
    AppendShaPass(bytes, manifest.second);
    bytes.insert(bytes.end(), manifest.digest.begin(), manifest.digest.end());
    // O-ENC production routing: D_BIND ASCII commitment. Under the default
    // (un-scoped) legacy model this is byte-identical to the shipped
    // Sha256dTagged; a V8 proof session prepends the 0xB1 role byte.
    namespace ds = matmul::v4::rc::stage3::domain_sep;
    return ds::Sha256dAsciiCommitment(ds::ActiveHashModel(),
                                      "BTX_RC_STAGE3_SHA_MANIFEST_V1", bytes);
}

bool BuildShaManifest(const std::vector<uint8_t>& preimage, ShaMode mode,
                      ShaManifest& out, std::string* why)
{
    out = {};
    if (mode != ShaMode::Single && mode != ShaMode::Double) {
        return Fail(why, "sha_manifest_mode");
    }
    if (preimage.size() > kMaxHashManifestPreimage ||
        preimage.size() > (std::numeric_limits<uint64_t>::max() / 8)) {
        return Fail(why, "sha_manifest_preimage_size");
    }
    out.mode = mode;
    out.preimage = preimage;
    if (!BuildShaPass(preimage, out.first, why) ||
        out.first.h_out.empty()) {
        return Fail(why, "sha_manifest_first_pass");
    }
    const auto first_digest = DigestBytes(out.first.h_out.back());
    if (mode == ShaMode::Double) {
        const std::vector<uint8_t> second_message(
            first_digest.begin(), first_digest.end());
        if (!BuildShaPass(second_message, out.second, why) ||
            out.second.h_out.size() != 1) {
            return Fail(why, "sha_manifest_second_pass");
        }
        out.digest = DigestBytes(out.second.h_out.back());
    } else {
        out.digest = first_digest;
    }
    out.commitment = CommitShaManifest(out);
    if (out.commitment.IsNull()) return Fail(why, "sha_manifest_null_commitment");
    return true;
}

bool ValidateShaManifest(const ShaManifest& manifest, std::string* why)
{
    ShaManifest expected;
    if (!BuildShaManifest(
            manifest.preimage, manifest.mode, expected, why)) {
        return false;
    }
    if (manifest != expected) return Fail(why, "sha_manifest_noncanonical");
    return true;
}

uint256 CommitCounterXofManifest(const CounterXofManifest& manifest)
{
    std::vector<uint8_t> bytes;
    AppendHash(bytes, manifest.seed);
    bytes.push_back(manifest.domain);
    bytes.push_back(static_cast<uint8_t>(manifest.mode));
    AppendU64(bytes, manifest.output_count);
    AppendShaCommitments(bytes, manifest.counter_hashes);
    AppendU64(bytes, manifest.output.size());
    bytes.insert(bytes.end(), manifest.output.begin(), manifest.output.end());
    return Sha256dTagged("BTX_RC_STAGE3_COUNTER_XOF_MANIFEST_V1", bytes);
}

bool BuildCounterXofManifest(
    const uint256& seed, uint8_t domain, CounterXofMode mode,
    uint64_t output_count, CounterXofManifest& out, std::string* why)
{
    out = {};
    if (domain == 0) return Fail(why, "xof_zero_domain");
    if (mode != CounterXofMode::RawBytes &&
        mode != CounterXofMode::MantissaE2M1 &&
        mode != CounterXofMode::Scale2Bit) {
        return Fail(why, "xof_mode");
    }
    if (output_count > kMaxHashManifestPreimage) {
        return Fail(why, "xof_output_count");
    }
    out.seed = seed;
    out.domain = domain;
    out.mode = mode;
    out.output_count = output_count;

    std::array<uint8_t, 32> seed_bytes{};
    for (uint32_t i = 0; i < 32; ++i) {
        seed_bytes[i] = seed.data()[31 - i];
    }
    uint64_t counter = 0;
    const uint64_t rejection_block_cap =
        mode == CounterXofMode::MantissaE2M1 && output_count != 0
            ? ((output_count + kRCMxBlockLen - 1) /
               kRCMxBlockLen) *
                  kRCStage3V1MaxRejectionBlocksPer32
            : (uint64_t{1} << 20);
    while (out.output.size() < output_count) {
        if (counter >= rejection_block_cap) {
            return Fail(
                why,
                mode == CounterXofMode::MantissaE2M1
                    ? "xof_rejection_block_cap"
                    : "xof_block_count");
        }
        std::vector<uint8_t> message(seed_bytes.begin(), seed_bytes.end());
        message.push_back(domain);
        for (uint32_t i = 0; i < 8; ++i) message.push_back(counter >> (8 * i));
        ShaManifest hash;
        if (!BuildShaManifest(message, ShaMode::Single, hash, why)) return false;
        const auto& digest = hash.digest;
        out.counter_hashes.push_back(std::move(hash));

        if (mode == CounterXofMode::RawBytes) {
            for (uint8_t byte : digest) {
                if (out.output.size() == output_count) break;
                out.output.push_back(byte);
            }
        } else if (mode == CounterXofMode::MantissaE2M1) {
            for (uint8_t byte : digest) {
                for (uint8_t nibble :
                     {static_cast<uint8_t>(byte & 0x0f),
                      static_cast<uint8_t>(byte >> 4)}) {
                    bool accepted{false};
                    const int8_t value =
                        bmx4::SampleMantissaNibble(nibble, accepted);
                    if (accepted) {
                        out.output.push_back(static_cast<uint8_t>(value));
                        if (out.output.size() == output_count) break;
                    }
                }
                if (out.output.size() == output_count) break;
            }
        } else {
            for (uint8_t byte : digest) {
                for (uint32_t shift = 0; shift < 8; shift += 2) {
                    out.output.push_back((byte >> shift) & 3U);
                    if (out.output.size() == output_count) break;
                }
                if (out.output.size() == output_count) break;
            }
        }
        ++counter;
    }
    // Zero output consumes no counter blocks; positive output consumes the
    // minimal prefix because the loop stops immediately after the last code.
    out.commitment = CommitCounterXofManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "xof_null_commitment");
}

bool ValidateCounterXofManifest(
    const CounterXofManifest& manifest, std::string* why)
{
    CounterXofManifest expected;
    if (!BuildCounterXofManifest(
            manifest.seed, manifest.domain, manifest.mode,
            manifest.output_count, expected, why)) {
        return false;
    }
    if (manifest != expected) return Fail(why, "xof_noncanonical");
    return true;
}

bool BuildCounterXofManifestBoundaryInstances(
    const CounterXofManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why)
{
    out.clear();
    if (manifest.domain == 0 ||
        (manifest.mode != CounterXofMode::RawBytes &&
         manifest.mode != CounterXofMode::MantissaE2M1 &&
         manifest.mode != CounterXofMode::Scale2Bit) ||
        manifest.output_count > kMaxHashManifestPreimage ||
        manifest.output.size() != manifest.output_count ||
        manifest.counter_hashes.size() > (1U << 20) ||
        manifest.commitment != CommitCounterXofManifest(manifest)) {
        return Fail(why, "xof_boundary_shape");
    }
    if ((manifest.output_count == 0) !=
        manifest.counter_hashes.empty()) {
        return Fail(why, "xof_boundary_minimal_count");
    }

    std::array<uint8_t, 32> seed_bytes{};
    for (uint32_t i = 0; i < seed_bytes.size(); ++i) {
        seed_bytes[i] = manifest.seed.data()[31 - i];
    }
    std::vector<uint8_t> expected_output;
    expected_output.reserve(manifest.output_count);
    for (size_t counter = 0;
         counter < manifest.counter_hashes.size(); ++counter) {
        const auto& hash = manifest.counter_hashes[counter];
        std::vector<uint8_t> expected_preimage(
            seed_bytes.begin(), seed_bytes.end());
        expected_preimage.push_back(manifest.domain);
        for (uint32_t byte = 0; byte < 8; ++byte) {
            expected_preimage.push_back(
                static_cast<uint64_t>(counter) >> (8 * byte));
        }
        if (hash.mode != ShaMode::Single ||
            hash.preimage != expected_preimage) {
            return Fail(why, "xof_boundary_counter_preimage");
        }
        std::vector<FixedProgramBoundaryInstance> instances;
        if (!BuildShaManifestBoundaryInstances(
                hash, instances, why) ||
            instances.size() != 1) {
            return Fail(why, "xof_boundary_counter_sha");
        }
        out.push_back(std::move(instances.front()));

        if (manifest.mode == CounterXofMode::RawBytes) {
            for (uint8_t byte : hash.digest) {
                if (expected_output.size() == manifest.output_count) break;
                expected_output.push_back(byte);
            }
        } else if (manifest.mode == CounterXofMode::MantissaE2M1) {
            for (uint8_t byte : hash.digest) {
                for (uint8_t nibble :
                     {static_cast<uint8_t>(byte & 0x0f),
                      static_cast<uint8_t>(byte >> 4)}) {
                    bool accepted{false};
                    const int8_t value =
                        bmx4::SampleMantissaNibble(nibble, accepted);
                    if (accepted) {
                        expected_output.push_back(
                            static_cast<uint8_t>(value));
                        if (expected_output.size() ==
                            manifest.output_count) {
                            break;
                        }
                    }
                }
                if (expected_output.size() ==
                    manifest.output_count) {
                    break;
                }
            }
        } else {
            for (uint8_t byte : hash.digest) {
                for (uint32_t shift = 0; shift < 8; shift += 2) {
                    expected_output.push_back((byte >> shift) & 3U);
                    if (expected_output.size() ==
                        manifest.output_count) {
                        break;
                    }
                }
                if (expected_output.size() ==
                    manifest.output_count) {
                    break;
                }
            }
        }
        if (expected_output.size() == manifest.output_count &&
            counter + 1 != manifest.counter_hashes.size()) {
            return Fail(why, "xof_boundary_trailing_counter");
        }
    }
    if (expected_output != manifest.output) {
        return Fail(why, "xof_boundary_output");
    }
    return true;
}

uint256 CommitChaChaConsumptionManifest(
    const ChaChaConsumptionManifest& manifest)
{
    std::vector<uint8_t> bytes(manifest.key.begin(), manifest.key.end());
    AppendU32(bytes, manifest.nonce_first);
    AppendU64(bytes, manifest.nonce_second);
    AppendU32(bytes, manifest.first_counter);
    AppendU64(bytes, manifest.output_bytes);
    AppendU32(bytes, manifest.blocks.size());
    for (const auto& block : manifest.blocks) {
        bytes.insert(bytes.end(), block.begin(), block.end());
    }
    AppendU64(bytes, manifest.output.size());
    bytes.insert(bytes.end(), manifest.output.begin(), manifest.output.end());
    return Sha256dTagged("BTX_RC_STAGE3_CHACHA_CONSUMPTION_V1", bytes);
}

bool BuildChaChaConsumptionManifest(
    const std::array<uint8_t, 32>& key, uint32_t nonce_first,
    uint64_t nonce_second, uint32_t first_counter, uint64_t output_bytes,
    ChaChaConsumptionManifest& out, std::string* why)
{
    out = {};
    if (output_bytes > kMaxHashManifestPreimage) {
        return Fail(why, "chacha_output_bytes");
    }
    const uint64_t block_count = output_bytes / 64 + (output_bytes % 64 != 0);
    if (block_count != 0 &&
        block_count - 1 > std::numeric_limits<uint32_t>::max() - first_counter) {
        return Fail(why, "chacha_counter_overflow");
    }
    out.key = key;
    out.nonce_first = nonce_first;
    out.nonce_second = nonce_second;
    out.first_counter = first_counter;
    out.output_bytes = output_bytes;
    const FixedProgram program =
        BuildCanonicalProgram(ProgramKind::ChaCha20Block);
    for (uint64_t block = 0; block < block_count; ++block) {
        std::vector<uint32_t> external(16);
        external[0] = 0x61707865U;
        external[1] = 0x3320646eU;
        external[2] = 0x79622d32U;
        external[3] = 0x6b206574U;
        for (uint32_t word = 0; word < 8; ++word) {
            external[4 + word] =
                uint32_t{key[4 * word]} |
                (uint32_t{key[4 * word + 1]} << 8) |
                (uint32_t{key[4 * word + 2]} << 16) |
                (uint32_t{key[4 * word + 3]} << 24);
        }
        external[12] = first_counter + block;
        external[13] = nonce_first;
        external[14] = static_cast<uint32_t>(nonce_second);
        external[15] = static_cast<uint32_t>(nonce_second >> 32);
        ProgramWitness witness;
        if (!BuildProgramWitness(program, external, witness, why) ||
            witness.final_words.size() != 16) {
            return Fail(why, "chacha_program");
        }
        std::array<uint8_t, 64> bytes{};
        for (uint32_t word = 0; word < 16; ++word) {
            const uint32_t value = witness.final_words[word];
            for (uint32_t byte = 0; byte < 4; ++byte) {
                bytes[4 * word + byte] = value >> (8 * byte);
            }
        }
        out.blocks.push_back(bytes);
        for (uint8_t byte : bytes) {
            if (out.output.size() == output_bytes) break;
            out.output.push_back(byte);
        }
    }
    out.commitment = CommitChaChaConsumptionManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "chacha_null_commitment");
}

bool ValidateChaChaConsumptionManifest(
    const ChaChaConsumptionManifest& manifest, std::string* why)
{
    ChaChaConsumptionManifest expected;
    if (!BuildChaChaConsumptionManifest(
            manifest.key, manifest.nonce_first, manifest.nonce_second,
            manifest.first_counter, manifest.output_bytes, expected, why)) {
        return false;
    }
    if (manifest != expected) return Fail(why, "chacha_noncanonical");
    return true;
}

bool BuildShaManifestBoundaryInstances(
    const ShaManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why)
{
    out.clear();
    if (manifest.mode != ShaMode::Single &&
        manifest.mode != ShaMode::Double) {
        return Fail(why, "sha_boundary_mode");
    }
    if (manifest.preimage.size() > kMaxHashManifestPreimage ||
        manifest.commitment != CommitShaManifest(manifest)) {
        return Fail(why, "sha_boundary_commitment");
    }

    const auto validate_pass =
        [&](const ShaPassManifest& pass,
            const std::vector<uint8_t>& message) {
            const auto padded = PadSha256(message);
            if (pass.message_size != message.size() ||
                pass.padded_blocks != padded ||
                pass.h_in.size() != padded.size() ||
                pass.h_out.size() != padded.size() ||
                pass.h_in.empty() ||
                pass.h_in.front() != SHA_H0) {
                return false;
            }
            for (size_t block = 1; block < pass.h_in.size(); ++block) {
                if (pass.h_in[block] != pass.h_out[block - 1]) {
                    return false;
                }
            }
            return true;
        };
    if (!validate_pass(manifest.first, manifest.preimage)) {
        return Fail(why, "sha_boundary_first_pass");
    }
    const auto first_digest =
        DigestBytes(manifest.first.h_out.back());
    const std::vector<uint8_t> second_message(
        first_digest.begin(), first_digest.end());
    if (manifest.mode == ShaMode::Single) {
        if (manifest.second != ShaPassManifest{} ||
            manifest.digest != first_digest) {
            return Fail(why, "sha_boundary_single_shape");
        }
    } else {
        if (!validate_pass(manifest.second, second_message) ||
            manifest.digest !=
                DigestBytes(manifest.second.h_out.back())) {
            return Fail(why, "sha_boundary_second_pass");
        }
    }

    const auto append_pass =
        [&](const ShaPassManifest& pass) {
            for (size_t block = 0;
                 block < pass.padded_blocks.size(); ++block) {
                FixedProgramBoundaryInstance instance;
                const auto words =
                    MessageWords(pass.padded_blocks[block]);
                instance.external_values.reserve(88);
                instance.external_values.insert(
                    instance.external_values.end(),
                    words.begin(), words.end());
                instance.external_values.insert(
                    instance.external_values.end(),
                    pass.h_in[block].begin(), pass.h_in[block].end());
                instance.external_values.insert(
                    instance.external_values.end(),
                    SHA_K.begin(), SHA_K.end());
                instance.final_words.assign(
                    pass.h_out[block].begin(), pass.h_out[block].end());
                out.push_back(std::move(instance));
            }
        };
    append_pass(manifest.first);
    if (manifest.mode == ShaMode::Double) append_pass(manifest.second);
    return true;
}

std::array<uint32_t, 8> CanonicalSha256InitialState()
{
    return SHA_H0;
}

bool BuildSha256CompressionBoundaryInstance(
    const std::array<uint8_t, 64>& padded_block,
    const std::array<uint32_t, 8>& h_in,
    const std::array<uint32_t, 8>& h_out,
    FixedProgramBoundaryInstance& out,
    std::string* why)
{
    out = {};
    const auto words = MessageWords(padded_block);
    out.external_values.reserve(88);
    out.external_values.insert(
        out.external_values.end(), words.begin(), words.end());
    out.external_values.insert(
        out.external_values.end(), h_in.begin(), h_in.end());
    out.external_values.insert(
        out.external_values.end(), SHA_K.begin(), SHA_K.end());
    out.final_words.assign(h_out.begin(), h_out.end());
    if (out.external_values.size() != 88 ||
        out.final_words.size() != 8) {
        out = {};
        return Fail(why, "sha_compression_boundary_adapter");
    }
    return true;
}

bool BuildChaChaManifestBoundaryInstances(
    const ChaChaConsumptionManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why)
{
    out.clear();
    if (manifest.output_bytes > kMaxHashManifestPreimage ||
        manifest.commitment !=
            CommitChaChaConsumptionManifest(manifest)) {
        return Fail(why, "chacha_boundary_commitment");
    }
    const uint64_t block_count =
        (manifest.output_bytes + 63) / 64;
    if (manifest.blocks.size() != block_count ||
        manifest.output.size() != manifest.output_bytes ||
        (block_count != 0 &&
         uint64_t{manifest.first_counter} + block_count - 1 >
             std::numeric_limits<uint32_t>::max())) {
        return Fail(why, "chacha_boundary_shape");
    }
    for (uint64_t byte = 0; byte < manifest.output_bytes; ++byte) {
        if (manifest.output[byte] !=
            manifest.blocks[byte / 64][byte % 64]) {
            return Fail(why, "chacha_boundary_stream");
        }
    }

    const auto read_le32 = [](const uint8_t* p) {
        return uint32_t{p[0]} | (uint32_t{p[1]} << 8) |
               (uint32_t{p[2]} << 16) | (uint32_t{p[3]} << 24);
    };
    out.reserve(block_count);
    for (uint64_t block = 0; block < block_count; ++block) {
        FixedProgramBoundaryInstance instance;
        instance.external_values.resize(16);
        instance.external_values[0] = 0x61707865U;
        instance.external_values[1] = 0x3320646eU;
        instance.external_values[2] = 0x79622d32U;
        instance.external_values[3] = 0x6b206574U;
        for (uint32_t word = 0; word < 8; ++word) {
            instance.external_values[4 + word] =
                read_le32(manifest.key.data() + 4 * word);
        }
        instance.external_values[12] =
            manifest.first_counter + static_cast<uint32_t>(block);
        instance.external_values[13] = manifest.nonce_first;
        instance.external_values[14] =
            static_cast<uint32_t>(manifest.nonce_second);
        instance.external_values[15] =
            static_cast<uint32_t>(manifest.nonce_second >> 32);
        instance.final_words.resize(16);
        for (uint32_t word = 0; word < 16; ++word) {
            instance.final_words[word] =
                read_le32(manifest.blocks[block].data() + 4 * word);
        }
        out.push_back(std::move(instance));
    }
    return true;
}

uint256 CommitDirectSha256dManifest(
    const DirectSha256dManifest& manifest)
{
    std::vector<uint8_t> bytes;
    bytes.push_back(static_cast<uint8_t>(manifest.relation));
    AppendU64(bytes, manifest.preimage.size());
    bytes.insert(bytes.end(), manifest.preimage.begin(), manifest.preimage.end());
    AppendHash(bytes, manifest.sha256d.commitment);
    AppendHash(bytes, manifest.digest);
    return Sha256dTagged("BTX_RC_STAGE3_DIRECT_SHA256D_V1", bytes);
}

bool BuildDirectSha256dManifest(
    DirectHashRelation relation, const std::vector<uint8_t>& preimage,
    DirectSha256dManifest& out, std::string* why)
{
    out = {};
    if (relation != DirectHashRelation::CoupledBarrier &&
        relation != DirectHashRelation::EpisodeDigest &&
        relation != DirectHashRelation::CoupledDigest &&
        relation != DirectHashRelation::FinalDigest) {
        return Fail(why, "direct_hash_relation");
    }
    out.relation = relation;
    out.preimage = preimage;
    if (!BuildShaManifest(preimage, ShaMode::Double, out.sha256d, why)) {
        return false;
    }
    out.digest = DigestUint(out.sha256d.digest);
    out.commitment = CommitDirectSha256dManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "direct_hash_null_commitment");
}

bool ValidateDirectSha256dManifest(
    const DirectSha256dManifest& manifest, std::string* why)
{
    DirectSha256dManifest expected;
    if (!BuildDirectSha256dManifest(
            manifest.relation, manifest.preimage, expected, why)) {
        return false;
    }
    if (manifest != expected) return Fail(why, "direct_hash_noncanonical");
    return true;
}

bool BuildDirectSha256dManifestBoundaryInstances(
    const DirectSha256dManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why)
{
    out.clear();
    if (manifest.relation != DirectHashRelation::CoupledBarrier &&
        manifest.relation != DirectHashRelation::EpisodeDigest &&
        manifest.relation != DirectHashRelation::CoupledDigest &&
        manifest.relation != DirectHashRelation::FinalDigest) {
        return Fail(why, "direct_hash_boundary_relation");
    }
    if (manifest.preimage.size() > kMaxHashManifestPreimage ||
        manifest.sha256d.mode != ShaMode::Double ||
        manifest.sha256d.preimage != manifest.preimage ||
        manifest.digest != DigestUint(manifest.sha256d.digest) ||
        manifest.commitment !=
            CommitDirectSha256dManifest(manifest)) {
        return Fail(why, "direct_hash_boundary_shape");
    }
    if (!BuildShaManifestBoundaryInstances(
            manifest.sha256d, out, why)) {
        return Fail(why, "direct_hash_boundary_sha");
    }
    return true;
}

uint256 CommitTileTreeManifest(const TileTreeManifest& manifest)
{
    std::vector<uint8_t> bytes;
    AppendU32(bytes, manifest.t_leaf);
    AppendU64(bytes, manifest.stream.size());
    bytes.insert(bytes.end(), manifest.stream.begin(), manifest.stream.end());
    AppendU64(bytes, manifest.logical_leaf_count);
    AppendU64(bytes, manifest.padded_leaf_count);
    AppendU32(bytes, manifest.leaf_hashes.size());
    for (const auto& hash : manifest.leaf_hashes) AppendHash(bytes, hash);
    AppendU32(bytes, manifest.hash_nodes.size());
    for (const auto& node : manifest.hash_nodes) {
        bytes.push_back(static_cast<uint8_t>(node.kind));
        AppendU32(bytes, node.level);
        AppendU64(bytes, node.index);
        AppendHash(bytes, node.sha256d.commitment);
        AppendHash(bytes, node.digest);
    }
    AppendHash(bytes, manifest.root);
    return Sha256dTagged("BTX_RC_STAGE3_TILE_TREE_MANIFEST_V1", bytes);
}

bool BuildTileTreeManifest(
    const std::vector<uint8_t>& stream, uint32_t t_leaf,
    TileTreeManifest& out, std::string* why)
{
    out = {};
    if (t_leaf == 0 || t_leaf > kMaxHashManifestPreimage ||
        stream.size() > kMaxHashManifestPreimage) {
        return Fail(why, "tile_tree_shape");
    }
    out.t_leaf = t_leaf;
    out.stream = stream;
    out.logical_leaf_count =
        stream.empty() ? 1 : stream.size() / t_leaf +
                              (stream.size() % t_leaf != 0);
    out.padded_leaf_count = 1;
    while (out.padded_leaf_count < out.logical_leaf_count) {
        if (out.padded_leaf_count > (uint64_t{1} << 31)) {
            return Fail(why, "tile_tree_leaf_overflow");
        }
        out.padded_leaf_count <<= 1;
    }
    out.leaf_hashes.reserve(out.padded_leaf_count);

    for (uint64_t leaf_index = 0;
         leaf_index < out.logical_leaf_count; ++leaf_index) {
        std::vector<uint8_t> preimage;
        preimage.reserve(1 + t_leaf);
        preimage.push_back(kRCLeafTag);
        const uint64_t offset = leaf_index * t_leaf;
        for (uint32_t i = 0; i < t_leaf; ++i) {
            preimage.push_back(
                offset + i < stream.size() ? stream[offset + i] : 0);
        }
        TileTreeHashNode node;
        node.kind = TileTreeNodeKind::Leaf;
        node.level = 0;
        node.index = leaf_index;
        if (!BuildShaManifest(preimage, ShaMode::Double, node.sha256d, why)) {
            return false;
        }
        node.digest = DigestUint(node.sha256d.digest);
        out.leaf_hashes.push_back(node.digest);
        out.hash_nodes.push_back(std::move(node));
    }

    if (out.logical_leaf_count < out.padded_leaf_count) {
        std::vector<uint8_t> preimage;
        preimage.push_back(kRCPadLeafTag);
        preimage.insert(
            preimage.end(),
            reinterpret_cast<const uint8_t*>(kRCPadTag),
            reinterpret_cast<const uint8_t*>(kRCPadTag) +
                sizeof(kRCPadTag) - 1);
        TileTreeHashNode pad;
        pad.kind = TileTreeNodeKind::PadLeaf;
        pad.level = 0;
        pad.index = out.logical_leaf_count;
        if (!BuildShaManifest(preimage, ShaMode::Double, pad.sha256d, why)) {
            return false;
        }
        pad.digest = DigestUint(pad.sha256d.digest);
        while (out.leaf_hashes.size() < out.padded_leaf_count) {
            out.leaf_hashes.push_back(pad.digest);
        }
        out.hash_nodes.push_back(std::move(pad));
    }

    std::vector<uint256> layer = out.leaf_hashes;
    uint32_t level = 1;
    while (layer.size() > 1) {
        std::vector<uint256> parent;
        parent.reserve(layer.size() / 2);
        for (uint64_t index = 0; index < layer.size() / 2; ++index) {
            std::vector<uint8_t> preimage;
            preimage.reserve(65);
            preimage.push_back(kRCNodeTag);
            preimage.insert(preimage.end(),
                            layer[2 * index].data(),
                            layer[2 * index].data() + 32);
            preimage.insert(preimage.end(),
                            layer[2 * index + 1].data(),
                            layer[2 * index + 1].data() + 32);
            TileTreeHashNode node;
            node.kind = TileTreeNodeKind::Internal;
            node.level = level;
            node.index = index;
            if (!BuildShaManifest(
                    preimage, ShaMode::Double, node.sha256d, why)) {
                return false;
            }
            node.digest = DigestUint(node.sha256d.digest);
            parent.push_back(node.digest);
            out.hash_nodes.push_back(std::move(node));
        }
        layer = std::move(parent);
        ++level;
    }
    out.root = layer.front();
    out.commitment = CommitTileTreeManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "tile_tree_null_commitment");
}

bool ValidateTileTreeManifest(
    const TileTreeManifest& manifest, std::string* why)
{
    TileTreeManifest expected;
    if (!BuildTileTreeManifest(
            manifest.stream, manifest.t_leaf, expected, why)) {
        return false;
    }
    if (manifest != expected) return Fail(why, "tile_tree_noncanonical");
    return true;
}

bool BuildTileTreeManifestBoundaryInstances(
    const TileTreeManifest& manifest,
    std::vector<FixedProgramBoundaryInstance>& out,
    std::string* why)
{
    out.clear();
    if (manifest.t_leaf == 0 ||
        manifest.t_leaf > kMaxHashManifestPreimage ||
        manifest.stream.size() > kMaxHashManifestPreimage ||
        manifest.commitment != CommitTileTreeManifest(manifest)) {
        return Fail(why, "tile_tree_boundary_shape");
    }
    const uint64_t logical =
        manifest.stream.empty()
            ? 1
            : manifest.stream.size() / manifest.t_leaf +
                  (manifest.stream.size() % manifest.t_leaf != 0);
    uint64_t padded = 1;
    while (padded < logical) {
        if (padded > (uint64_t{1} << 31)) {
            return Fail(why, "tile_tree_boundary_overflow");
        }
        padded <<= 1;
    }
    if (manifest.logical_leaf_count != logical ||
        manifest.padded_leaf_count != padded ||
        manifest.leaf_hashes.size() != padded ||
        manifest.hash_nodes.empty()) {
        return Fail(why, "tile_tree_boundary_counts");
    }

    size_t cursor = 0;
    std::vector<uint256> expected_leaves;
    expected_leaves.reserve(padded);
    const auto consume_node =
        [&](TileTreeNodeKind kind, uint32_t level, uint64_t index,
            const std::vector<uint8_t>& preimage,
            uint256& digest) {
            if (cursor >= manifest.hash_nodes.size()) return false;
            const auto& node = manifest.hash_nodes[cursor++];
            if (node.kind != kind || node.level != level ||
                node.index != index ||
                node.sha256d.mode != ShaMode::Double ||
                node.sha256d.preimage != preimage ||
                node.digest != DigestUint(node.sha256d.digest)) {
                return false;
            }
            std::vector<FixedProgramBoundaryInstance> instances;
            if (!BuildShaManifestBoundaryInstances(
                    node.sha256d, instances, why)) {
                return false;
            }
            out.insert(
                out.end(),
                std::make_move_iterator(instances.begin()),
                std::make_move_iterator(instances.end()));
            digest = node.digest;
            return true;
        };

    for (uint64_t index = 0; index < logical; ++index) {
        std::vector<uint8_t> preimage;
        preimage.reserve(1 + manifest.t_leaf);
        preimage.push_back(kRCLeafTag);
        const uint64_t offset = index * manifest.t_leaf;
        for (uint32_t byte = 0; byte < manifest.t_leaf; ++byte) {
            preimage.push_back(
                offset + byte < manifest.stream.size()
                    ? manifest.stream[offset + byte]
                    : 0);
        }
        uint256 digest;
        if (!consume_node(
                TileTreeNodeKind::Leaf, 0, index,
                preimage, digest)) {
            return Fail(why, "tile_tree_boundary_leaf");
        }
        expected_leaves.push_back(digest);
    }
    if (logical < padded) {
        std::vector<uint8_t> preimage;
        preimage.push_back(kRCPadLeafTag);
        preimage.insert(
            preimage.end(),
            reinterpret_cast<const uint8_t*>(kRCPadTag),
            reinterpret_cast<const uint8_t*>(kRCPadTag) +
                sizeof(kRCPadTag) - 1);
        uint256 digest;
        if (!consume_node(
                TileTreeNodeKind::PadLeaf, 0, logical,
                preimage, digest)) {
            return Fail(why, "tile_tree_boundary_pad");
        }
        expected_leaves.resize(padded, digest);
    }
    if (manifest.leaf_hashes != expected_leaves) {
        return Fail(why, "tile_tree_boundary_leaf_hashes");
    }

    std::vector<uint256> layer = expected_leaves;
    uint32_t level = 1;
    while (layer.size() > 1) {
        std::vector<uint256> parent;
        parent.reserve(layer.size() / 2);
        for (uint64_t index = 0; index < layer.size() / 2; ++index) {
            std::vector<uint8_t> preimage;
            preimage.reserve(65);
            preimage.push_back(kRCNodeTag);
            preimage.insert(
                preimage.end(), layer[2 * index].data(),
                layer[2 * index].data() + 32);
            preimage.insert(
                preimage.end(), layer[2 * index + 1].data(),
                layer[2 * index + 1].data() + 32);
            uint256 digest;
            if (!consume_node(
                    TileTreeNodeKind::Internal, level, index,
                    preimage, digest)) {
                return Fail(why, "tile_tree_boundary_internal");
            }
            parent.push_back(digest);
        }
        layer = std::move(parent);
        ++level;
    }
    if (cursor != manifest.hash_nodes.size() ||
        layer.empty() || manifest.root != layer.front()) {
        return Fail(why, "tile_tree_boundary_root");
    }
    return true;
}

uint256 CommitEpisodeDigestManifest(
    const EpisodeDigestManifest& manifest)
{
    std::vector<uint8_t> bytes;
    AppendU32(bytes, manifest.expected_rounds);
    AppendU32(bytes, manifest.round_roots.size());
    for (const uint256& root : manifest.round_roots) {
        AppendHash(bytes, root);
    }
    AppendHash(bytes, manifest.direct.commitment);
    return Sha256dTagged(
        "BTX_RC_STAGE3_EPISODE_DIGEST_MANIFEST_V1", bytes);
}

bool BuildEpisodeDigestManifest(
    uint32_t expected_rounds, const std::vector<uint256>& round_roots,
    EpisodeDigestManifest& out, std::string* why)
{
    out = {};
    if (expected_rounds == 0 ||
        expected_rounds > kMaxHashManifestPreimage / 32 ||
        round_roots.size() != expected_rounds) {
        return Fail(why, "episode_digest_shape");
    }

    std::vector<uint8_t> preimage;
    preimage.reserve(sizeof(kRCEpisodeTag) - 1 +
                     static_cast<size_t>(expected_rounds) * 32);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(kRCEpisodeTag),
        reinterpret_cast<const uint8_t*>(kRCEpisodeTag) +
            sizeof(kRCEpisodeTag) - 1);
    for (const uint256& root : round_roots) {
        preimage.insert(preimage.end(), root.data(), root.data() + 32);
    }

    out.expected_rounds = expected_rounds;
    out.round_roots = round_roots;
    if (!BuildDirectSha256dManifest(
            DirectHashRelation::EpisodeDigest, preimage, out.direct, why)) {
        return false;
    }
    out.commitment = CommitEpisodeDigestManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "episode_digest_null_commitment");
}

bool ValidateEpisodeDigestManifest(
    const EpisodeDigestManifest& manifest, std::string* why)
{
    EpisodeDigestManifest expected;
    if (!BuildEpisodeDigestManifest(
            manifest.expected_rounds, manifest.round_roots, expected, why)) {
        return false;
    }
    if (manifest != expected) {
        return Fail(why, "episode_digest_noncanonical");
    }
    return true;
}

uint256 CommitCoupledBarrierManifest(
    const CoupledBarrierManifest& manifest)
{
    std::vector<uint8_t> bytes;
    AppendU32(bytes, manifest.transcript_version);
    AppendU32(bytes, manifest.expected_barriers);
    AppendU32(bytes, manifest.barrier_index);
    AppendU64(bytes, manifest.state_bytes.size());
    bytes.insert(
        bytes.end(), manifest.state_bytes.begin(), manifest.state_bytes.end());
    AppendHash(bytes, manifest.direct.commitment);
    return Sha256dTagged(
        "BTX_RC_STAGE3_COUPLED_BARRIER_MANIFEST_V1", bytes);
}

bool BuildCoupledBarrierManifest(
    uint32_t transcript_version, uint32_t expected_barriers,
    uint32_t barrier_index, const std::vector<uint8_t>& state_bytes,
    CoupledBarrierManifest& out, std::string* why)
{
    out = {};
    if (transcript_version < ENC_RC_V1 ||
        transcript_version > ENC_RC_V4) {
        return Fail(why, "coupled_barrier_bad_transcript_version");
    }
    if (expected_barriers == 0 ||
        expected_barriers > kMaxHashManifestPreimage / 32 ||
        barrier_index >= expected_barriers ||
        state_bytes.empty() ||
        state_bytes.size() > kMaxHashManifestPreimage) {
        return Fail(why, "coupled_barrier_shape");
    }

    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const size_t tag_size = std::strlen(tags.barrier);
    std::vector<uint8_t> preimage;
    preimage.reserve(tag_size + 4 + state_bytes.size());
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.barrier),
        reinterpret_cast<const uint8_t*>(tags.barrier) + tag_size);
    AppendU32(preimage, barrier_index);
    preimage.insert(preimage.end(), state_bytes.begin(), state_bytes.end());

    out.transcript_version = transcript_version;
    out.expected_barriers = expected_barriers;
    out.barrier_index = barrier_index;
    out.state_bytes = state_bytes;
    if (!BuildDirectSha256dManifest(
            DirectHashRelation::CoupledBarrier, preimage, out.direct, why)) {
        return false;
    }
    out.commitment = CommitCoupledBarrierManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "coupled_barrier_null_commitment");
}

bool ValidateCoupledBarrierManifest(
    const CoupledBarrierManifest& manifest, std::string* why)
{
    CoupledBarrierManifest expected;
    if (!BuildCoupledBarrierManifest(
            manifest.transcript_version, manifest.expected_barriers,
            manifest.barrier_index, manifest.state_bytes, expected, why)) {
        return false;
    }
    if (manifest != expected) {
        return Fail(why, "coupled_barrier_noncanonical");
    }
    return true;
}

uint256 CommitCoupledDigestManifest(
    const CoupledDigestManifest& manifest)
{
    std::vector<uint8_t> bytes;
    AppendU32(bytes, manifest.transcript_version);
    AppendU32(bytes, manifest.expected_barriers);
    AppendHash(bytes, manifest.bank_root);
    AppendU32(bytes, manifest.barrier_roots.size());
    for (const uint256& root : manifest.barrier_roots) {
        AppendHash(bytes, root);
    }
    AppendHash(bytes, manifest.direct.commitment);
    return Sha256dTagged(
        "BTX_RC_STAGE3_COUPLED_DIGEST_MANIFEST_V1", bytes);
}

bool BuildCoupledDigestManifest(
    uint32_t transcript_version, uint32_t expected_barriers,
    const uint256& bank_root, const std::vector<uint256>& barrier_roots,
    CoupledDigestManifest& out, std::string* why)
{
    out = {};
    if (transcript_version < ENC_RC_V1 ||
        transcript_version > ENC_RC_V4) {
        return Fail(why, "coupled_digest_bad_transcript_version");
    }
    if (expected_barriers == 0 ||
        expected_barriers > kMaxHashManifestPreimage / 32 ||
        barrier_roots.size() != expected_barriers) {
        return Fail(why, "coupled_digest_shape");
    }

    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const size_t tag_size = std::strlen(tags.episode);
    std::vector<uint8_t> preimage;
    preimage.reserve(tag_size + 32 +
                     static_cast<size_t>(expected_barriers) * 32);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(tags.episode),
        reinterpret_cast<const uint8_t*>(tags.episode) + tag_size);
    preimage.insert(
        preimage.end(), bank_root.data(), bank_root.data() + 32);
    for (const uint256& root : barrier_roots) {
        preimage.insert(preimage.end(), root.data(), root.data() + 32);
    }

    out.transcript_version = transcript_version;
    out.expected_barriers = expected_barriers;
    out.bank_root = bank_root;
    out.barrier_roots = barrier_roots;
    if (!BuildDirectSha256dManifest(
            DirectHashRelation::CoupledDigest, preimage, out.direct, why)) {
        return false;
    }
    out.commitment = CommitCoupledDigestManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "coupled_digest_null_commitment");
}

bool ValidateCoupledDigestManifest(
    const CoupledDigestManifest& manifest, std::string* why)
{
    CoupledDigestManifest expected;
    if (!BuildCoupledDigestManifest(
            manifest.transcript_version, manifest.expected_barriers,
            manifest.bank_root, manifest.barrier_roots, expected, why)) {
        return false;
    }
    if (manifest != expected) {
        return Fail(why, "coupled_digest_noncanonical");
    }
    return true;
}

uint256 CommitComposedFinalDigestManifest(
    const ComposedFinalDigestManifest& manifest)
{
    std::vector<uint8_t> bytes;
    bytes.push_back(static_cast<uint8_t>(manifest.proof_version));
    bytes.push_back(static_cast<uint8_t>(manifest.proof_version >> 8));
    AppendU32(bytes, static_cast<uint32_t>(manifest.height));
    AppendHash(bytes, manifest.header_commitment);
    AppendHash(bytes, manifest.params_commitment);
    AppendU32(bytes, manifest.episode_profile);
    AppendU32(bytes, manifest.coupled_profile);
    AppendU32(bytes, manifest.transcript_version);
    AppendHash(bytes, manifest.episode_digest);
    AppendHash(bytes, manifest.coupled_digest);
    AppendHash(bytes, manifest.direct.commitment);
    return Sha256dTagged(
        "BTX_RC_STAGE3_COMPOSED_FINAL_MANIFEST_V1", bytes);
}

bool BuildComposedFinalDigestManifest(
    uint16_t proof_version, int32_t height,
    const uint256& header_commitment, const uint256& params_commitment,
    uint32_t episode_profile, uint32_t coupled_profile,
    uint32_t transcript_version, const uint256& episode_digest,
    const uint256& coupled_digest, ComposedFinalDigestManifest& out,
    std::string* why)
{
    out = {};
    if (proof_version != kRCStage3ProofVersion) {
        return Fail(why, "composed_final_bad_proof_version");
    }
    if (height < 0 || header_commitment.IsNull() ||
        params_commitment.IsNull() || episode_profile == 0 ||
        coupled_profile == 0 || transcript_version < ENC_RC_V1 ||
        transcript_version > ENC_RC_V4 || episode_digest.IsNull() ||
        coupled_digest.IsNull()) {
        return Fail(why, "composed_final_shape");
    }

    // HashWriter serializes a fixed char array including its trailing NUL,
    // then integral fields little-endian and uint256 values as raw 32 bytes.
    static constexpr char COMPOSED_DIGEST_DOMAIN[] =
        "BTX_RC_STAGE3_COMPOSED_DIGEST_V1";
    std::vector<uint8_t> preimage;
    preimage.reserve(
        sizeof(COMPOSED_DIGEST_DOMAIN) + 2 + 4 + 32 + 32 +
        4 + 4 + 4 + 32 + 32);
    preimage.insert(
        preimage.end(),
        reinterpret_cast<const uint8_t*>(COMPOSED_DIGEST_DOMAIN),
        reinterpret_cast<const uint8_t*>(COMPOSED_DIGEST_DOMAIN) +
            sizeof(COMPOSED_DIGEST_DOMAIN));
    preimage.push_back(static_cast<uint8_t>(proof_version));
    preimage.push_back(static_cast<uint8_t>(proof_version >> 8));
    AppendU32(preimage, static_cast<uint32_t>(height));
    AppendHash(preimage, header_commitment);
    AppendHash(preimage, params_commitment);
    AppendU32(preimage, episode_profile);
    AppendU32(preimage, coupled_profile);
    AppendU32(preimage, transcript_version);
    AppendHash(preimage, episode_digest);
    AppendHash(preimage, coupled_digest);

    out.proof_version = proof_version;
    out.height = height;
    out.header_commitment = header_commitment;
    out.params_commitment = params_commitment;
    out.episode_profile = episode_profile;
    out.coupled_profile = coupled_profile;
    out.transcript_version = transcript_version;
    out.episode_digest = episode_digest;
    out.coupled_digest = coupled_digest;
    if (!BuildDirectSha256dManifest(
            DirectHashRelation::FinalDigest, preimage, out.direct, why)) {
        return false;
    }
    out.commitment = CommitComposedFinalDigestManifest(out);
    return !out.commitment.IsNull() ||
           Fail(why, "composed_final_null_commitment");
}

bool ValidateComposedFinalDigestManifest(
    const ComposedFinalDigestManifest& manifest, std::string* why)
{
    ComposedFinalDigestManifest expected;
    if (!BuildComposedFinalDigestManifest(
            manifest.proof_version, manifest.height,
            manifest.header_commitment, manifest.params_commitment,
            manifest.episode_profile, manifest.coupled_profile,
            manifest.transcript_version, manifest.episode_digest,
            manifest.coupled_digest, expected, why)) {
        return false;
    }
    if (manifest != expected) {
        return Fail(why, "composed_final_noncanonical");
    }
    return true;
}

namespace {

// Manifest-family domain separators for the recursive bindings.
constexpr char kXofCounterManifestBindDomain[] =
    "BTX_RC_STAGE3_XOF_COUNTER_MANIFEST_BIND_V1";
constexpr char kChaChaInitBlockManifestBindDomain[] =
    "BTX_RC_STAGE3_CHACHA_INIT_BLOCK_MANIFEST_BIND_V1";
constexpr char kCompleteStreamManifestBindDomain[] =
    "BTX_RC_STAGE3_COMPLETE_STREAM_MANIFEST_BIND_V1";

void AppendCStr(std::vector<uint8_t>& bytes, const char* s)
{
    for (const char* p = s; *p != '\0'; ++p) {
        bytes.push_back(static_cast<uint8_t>(*p));
    }
    bytes.push_back(0);
}

// Leaf i of the committed-column stream: binds the family, the stream index i,
// and the full public boundary column block (external inputs + final words).
uint256 ManifestBindLeaf(const char* family_domain, uint64_t index,
                         const FixedProgramBoundaryInstance& inst)
{
    std::vector<uint8_t> bytes;
    AppendCStr(bytes, family_domain);
    AppendU64(bytes, index);
    AppendU32(bytes, static_cast<uint32_t>(inst.external_values.size()));
    for (uint32_t v : inst.external_values) AppendU32(bytes, v);
    AppendU32(bytes, static_cast<uint32_t>(inst.final_words.size()));
    for (uint32_t v : inst.final_words) AppendU32(bytes, v);
    return Sha256dTagged(
        "BTX_RC_STAGE3_HASH_MANIFEST_BIND_LEAF_V1", bytes);
}

// In-AIR SHA256d 2->1 Merkle compression, the same primitive that commits
// every manifest.
uint256 ManifestBindNode(const uint256& left, const uint256& right)
{
    std::vector<uint8_t> bytes;
    AppendHash(bytes, left);
    AppendHash(bytes, right);
    return Sha256dTagged(
        "BTX_RC_STAGE3_HASH_MANIFEST_BIND_NODE_V1", bytes);
}

// Fold the ordered committed-column stream into one Merkle root. Odd levels
// duplicate the last node; the total instance_count is separately bound into
// binding_commitment, so that duplication is not a length ambiguity.
uint256 ManifestStreamColumnRoot(
    const char* family_domain,
    const std::vector<FixedProgramBoundaryInstance>& stream)
{
    if (stream.empty()) {
        std::vector<uint8_t> bytes;
        AppendCStr(bytes, family_domain);
        AppendU64(bytes, 0);
        return Sha256dTagged(
            "BTX_RC_STAGE3_HASH_MANIFEST_BIND_ROOT_V1", bytes);
    }
    std::vector<uint256> level;
    level.reserve(stream.size());
    for (uint64_t i = 0; i < stream.size(); ++i) {
        level.push_back(ManifestBindLeaf(family_domain, i, stream[i]));
    }
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const uint256& l = level[i];
            const uint256& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(ManifestBindNode(l, r));
        }
        level = std::move(next);
    }
    return level.front();
}

} // namespace

bool BuildHashManifestRecursiveBinding(
    const char* family_domain, const uint256& manifest_commitment,
    const std::vector<FixedProgramBoundaryInstance>& stream,
    HashManifestRecursiveBinding& out, std::string* why)
{
    out = {};
    if (stream.size() > kMaxHashManifestPreimage) {
        return Fail(why, "manifest_bind_stream_size");
    }
    if (manifest_commitment.IsNull()) {
        return Fail(why, "manifest_bind_null_commitment");
    }
    out.manifest_commitment = manifest_commitment;
    out.instance_count = stream.size();
    out.stream_column_root =
        ManifestStreamColumnRoot(family_domain, stream);
    std::vector<uint8_t> bytes;
    AppendCStr(bytes, family_domain);
    AppendHash(bytes, out.manifest_commitment);
    AppendHash(bytes, out.stream_column_root);
    AppendU64(bytes, out.instance_count);
    out.binding_commitment = Sha256dTagged(
        "BTX_RC_STAGE3_HASH_MANIFEST_BIND_COMMIT_V1", bytes);
    return true;
}

bool VerifyHashManifestRecursiveBinding(
    const char* family_domain, const uint256& manifest_commitment,
    const std::vector<FixedProgramBoundaryInstance>& stream,
    const HashManifestRecursiveBinding& binding, std::string* why)
{
    HashManifestRecursiveBinding expected;
    if (!BuildHashManifestRecursiveBinding(
            family_domain, manifest_commitment, stream, expected, why)) {
        return false;
    }
    if (binding.manifest_commitment != expected.manifest_commitment) {
        return Fail(why, "manifest_bind_commitment_mismatch");
    }
    if (binding.instance_count != expected.instance_count) {
        return Fail(why, "manifest_bind_count_mismatch");
    }
    if (binding.stream_column_root != expected.stream_column_root) {
        return Fail(why, "manifest_bind_stream_root_mismatch");
    }
    if (binding.binding_commitment != expected.binding_commitment) {
        return Fail(why, "manifest_bind_binding_value_mismatch");
    }
    return true;
}

bool BuildXofCounterManifestRecursiveBinding(
    const CounterXofManifest& manifest, HashManifestRecursiveBinding& out,
    std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildCounterXofManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return BuildHashManifestRecursiveBinding(
        kXofCounterManifestBindDomain,
        CommitCounterXofManifest(manifest), stream, out, why);
}

bool VerifyXofCounterManifestRecursiveBinding(
    const CounterXofManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildCounterXofManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return VerifyHashManifestRecursiveBinding(
        kXofCounterManifestBindDomain,
        CommitCounterXofManifest(manifest), stream, binding, why);
}

bool BuildChaChaInitAndBlockManifestRecursiveBinding(
    const ChaChaConsumptionManifest& manifest,
    HashManifestRecursiveBinding& out, std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildChaChaManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return BuildHashManifestRecursiveBinding(
        kChaChaInitBlockManifestBindDomain,
        CommitChaChaConsumptionManifest(manifest), stream, out, why);
}

bool VerifyChaChaInitAndBlockManifestRecursiveBinding(
    const ChaChaConsumptionManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildChaChaManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return VerifyHashManifestRecursiveBinding(
        kChaChaInitBlockManifestBindDomain,
        CommitChaChaConsumptionManifest(manifest), stream, binding, why);
}

bool BuildCompleteStreamManifestRecursiveBinding(
    const TileTreeManifest& manifest, HashManifestRecursiveBinding& out,
    std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildTileTreeManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return BuildHashManifestRecursiveBinding(
        kCompleteStreamManifestBindDomain,
        CommitTileTreeManifest(manifest), stream, out, why);
}

bool VerifyCompleteStreamManifestRecursiveBinding(
    const TileTreeManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildTileTreeManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return VerifyHashManifestRecursiveBinding(
        kCompleteStreamManifestBindDomain,
        CommitTileTreeManifest(manifest), stream, binding, why);
}

bool BuildCompleteStreamManifestRecursiveBinding(
    const DirectSha256dManifest& manifest, HashManifestRecursiveBinding& out,
    std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildDirectSha256dManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return BuildHashManifestRecursiveBinding(
        kCompleteStreamManifestBindDomain,
        CommitDirectSha256dManifest(manifest), stream, out, why);
}

bool VerifyCompleteStreamManifestRecursiveBinding(
    const DirectSha256dManifest& manifest,
    const HashManifestRecursiveBinding& binding, std::string* why)
{
    std::vector<FixedProgramBoundaryInstance> stream;
    if (!BuildDirectSha256dManifestBoundaryInstances(manifest, stream, why)) {
        return false;
    }
    return VerifyHashManifestRecursiveBinding(
        kCompleteStreamManifestBindDomain,
        CommitDirectSha256dManifest(manifest), stream, binding, why);
}

std::vector<RelationReadiness> CurrentRelationReadiness()
{
    std::vector<RelationReadiness> out;
    out.push_back({Relation::BuilderShaCounterXof, true, false, ShaFamilies(), ShaGaps(true, false)});
    // ChaChaInitAndBlockManifest gap is CLOSED by
    // Build/VerifyChaChaInitAndBlockManifestRecursiveBinding: the ordered
    // init+block committed columns are Merkle-folded and bound to the committed
    // ChaCha manifest root. CopyAndCtlWiring + RecursiveAggregation remain open.
    std::vector<Gap> chacha_gaps{
        {GapCode::CopyAndCtlWiring, "the two-epoch provenance proof closes internal SSA copies, but its external/final boundary cells are not yet equality-linked to the producer and consumer role-proof columns at the recursive root"},
        {GapCode::RecursiveAggregation, "boundary-pinned instruction proofs and their CTL children are not folded into the normalized recursive root"}};
    if (!kHashChaChaInitAndBlockManifestBindingExecutable) {
        chacha_gaps.insert(
            chacha_gaps.begin() + 1,
            {GapCode::ChaChaInitAndBlockManifest, "the exact key/nonce/minimal counter-prefix manifest maps to executable block boundary instances but is not recursively bound to the consumer stream"});
    }
    out.push_back({Relation::BuilderChaCha20, true, false,
                   {Family::Add32, Family::XorRot32}, chacha_gaps});
    RelationReadiness extract = out.back();
    extract.relation = Relation::ExtractChaCha20;
    out.push_back(std::move(extract));
    out.push_back({Relation::TileTreeSha256d, true, false, ShaFamilies(), ShaGaps(false, true)});
    out.push_back({Relation::CoupledBarrierSha256d, true, false, ShaFamilies(), ShaGaps(false, true)});
    out.push_back({Relation::FinalDigestSha256d, true, false, ShaFamilies(), ShaGaps(false, true)});
    return out;
}

} // namespace matmul::v4::rc::stage3_hash_air
