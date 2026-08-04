// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v15_superprogram.h>

#include <matmul/matmul_v4_rc_alg_hash_typed.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_safe_v15_superprogram {
namespace {

using Fp3 = gf::Fp3;
namespace typed = alg_hash_typed;
namespace safe = safe_v12;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:safe_v15_superprogram:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

void Add(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

bool BaseOnly(const Fp3& value)
{
    return value.c1 == 0 && value.c2 == 0;
}

uint32_t Word(const Fp3& value)
{
    return static_cast<uint32_t>(
        gf::Canonical(value.c0));
}

Fp3 Compress(
    const Fp3& address,
    const Fp3& byte_index,
    const Fp3& value,
    const Fp3& gamma)
{
    return gf::Add(
        address,
        gf::Add(
            gf::Mul(gamma, byte_index),
            gf::Mul(gf::Mul(gamma, gamma), value)));
}

bool DigestEq(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t lane = 0; lane < a.size(); ++lane) {
        if (a[lane] != b[lane]) return false;
    }
    return true;
}

alg_hash::Digest CommitSchedule(
    const bridge::TypedSafeDirectParentProductV14& v14,
    const std::vector<CanonicalSourceV15>& sources,
    const std::vector<CanonicalSourceConsumerRecordV15>& records)
{
    std::vector<gf::Fp> lanes{
        gf::FromU64(UINT64_C(0x4254585631354354)), // "BTXV15CT"
        gf::FromU64(kVersionV15),
        gf::FromU64(v14.trace_rows),
        gf::FromU64(v14.cs.n_columns),
        gf::FromU64(sources.size()),
        gf::FromU64(records.size()),
    };
    lanes.insert(
        lanes.end(),
        v14.program_root.begin(),
        v14.program_root.end());
    lanes.insert(
        lanes.end(),
        v14.transcript_commitment.begin(),
        v14.transcript_commitment.end());
    for (const auto& source : sources) {
        lanes.push_back(gf::FromU64(source.decoded.address));
        lanes.push_back(gf::FromU64(
            static_cast<uint16_t>(source.decoded.key.kind)));
        lanes.push_back(gf::FromU64(source.decoded.key.a));
        lanes.push_back(gf::FromU64(source.decoded.key.b));
        lanes.push_back(gf::FromU64(source.decoded.key.c));
        lanes.push_back(gf::FromU64(source.decoded.key.d));
        lanes.push_back(gf::FromU64(source.decoded.key.limb));
        lanes.push_back(gf::FromU64(
            static_cast<uint8_t>(source.decoded.ownership)));
        lanes.push_back(gf::FromU64(source.producer_row));
        lanes.push_back(gf::FromU64(source.producer_slot));
        for (uint32_t multiplicity :
             source.use_multiplicity) {
            lanes.push_back(gf::FromU64(multiplicity));
        }
    }
    for (const auto& record : records) {
        lanes.push_back(gf::FromU64(record.source_address));
        lanes.push_back(gf::FromU64(record.source_byte));
        lanes.push_back(gf::FromU64(record.child_event));
        lanes.push_back(gf::FromU64(record.message_ordinal));
        lanes.push_back(gf::FromU64(record.message_byte));
        lanes.push_back(gf::FromU64(record.v14_row));
        lanes.push_back(gf::FromU64(record.v14_column));
        lanes.push_back(gf::FromU64(record.consumer_port));
    }
    alg_hash::Digest digest{};
    if (!typed::SpongeHashFpV12(
            typed::RoleV12::ProgramTableCommitment,
            lanes, digest, nullptr)) {
        return {};
    }
    return digest;
}

bool DeriveOne(
    typed::RoleV12 role,
    const char* label,
    uint32_t lane,
    const uint256& r0,
    const alg_hash::Digest& schedule,
    const alg_hash::Digest& program,
    uint32_t records,
    Fp3& out)
{
    std::vector<uint8_t> domain;
    const std::string prefix{
        "BTX_RC_STAGE3_SAFE_V15_CTL_"};
    domain.insert(domain.end(), prefix.begin(), prefix.end());
    domain.insert(
        domain.end(),
        label, label + std::char_traits<char>::length(label));
    domain.push_back(static_cast<uint8_t>(lane));
    std::vector<gf::Fp> message;
    message.reserve(19);
    for (uint32_t word = 0; word < 8; ++word) {
        uint32_t value = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            value |= uint32_t{r0.data()[4 * word + byte]}
                << (8 * byte);
        }
        message.push_back(gf::FromU64(value));
    }
    message.insert(
        message.end(), schedule.begin(), schedule.end());
    message.insert(
        message.end(), program.begin(), program.end());
    message.push_back(gf::FromU64(records));
    message.push_back(gf::FromU64(lane));
    alg_hash::Digest digest{};
    if (!safe::SafeCoreDigestV12(
            role, domain, message, digest, nullptr, nullptr)) {
        return false;
    }
    const uint256 bytes =
        Fri3AlgDigestToUint256(digest);
    out = gf::FromChallengeBytes3(bytes.data());
    return true;
}

bool DeriveChallenges(
    const uint256& r0,
    const alg_hash::Digest& schedule,
    const alg_hash::Digest& program,
    uint32_t records,
    DualCtlChallengesV15& out)
{
    out = {};
    if (r0.IsNull() ||
        !DeriveOne(
            typed::RoleV12::TranscriptAirLambda,
            "ALPHA", 1, r0, schedule, program,
            records, out.alpha1) ||
        !DeriveOne(
            typed::RoleV12::TranscriptFoldBeta,
            "GAMMA", 1, r0, schedule, program,
            records, out.gamma1) ||
        !DeriveOne(
            typed::RoleV12::TranscriptAirLambda,
            "ALPHA", 2, r0, schedule, program,
            records, out.alpha2) ||
        !DeriveOne(
            typed::RoleV12::TranscriptFoldBeta,
            "GAMMA", 2, r0, schedule, program,
            records, out.gamma2)) {
        out = {};
        return false;
    }
    return !gf::IsZero(out.gamma1) &&
        !gf::IsZero(out.gamma2) &&
        !gf::Eq(out.gamma1, out.gamma2) &&
        !gf::Eq(out.alpha1, out.alpha2);
}

void Pin(
    aq::AirConstraintSystem<Fp3>& cs,
    uint32_t column,
    const std::vector<std::vector<Fp3>>& columns)
{
    cs.preprocessed.emplace_back(
        column, columns[column]);
}

void AddDecompositionConstraints(
    aq::AirConstraintSystem<Fp3>& cs,
    const LayoutV15& l)
{
    for (uint32_t slot = 0;
         slot < kProducerSlotsV15; ++slot) {
        const uint32_t active = l.ProducerActive(slot);
        Add(
            cs, "v15.source.active_boolean",
            aq::AirKind::kEverywhere, 2,
            [active](const auto& row, const auto&) {
                return gf::Mul(
                    row[active],
                    gf::Sub(row[active], Fp3::One()));
            });
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t b = l.ProducerBit(slot, bit);
            Add(
                cs, "v15.source.bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [b](const auto& row, const auto&) {
                    return gf::Mul(
                        row[b],
                        gf::Sub(row[b], Fp3::One()));
                });
            Add(
                cs, "v15.source.inactive_bit_zero",
                aq::AirKind::kEverywhere, 2,
                [active, b](const auto& row, const auto&) {
                    return gf::Mul(
                        gf::Sub(Fp3::One(), row[active]),
                        row[b]);
                });
        }
        for (uint32_t byte = 0; byte < 4; ++byte) {
            const uint32_t bcol =
                l.ProducerByte(slot, byte);
            Add(
                cs, "v15.source.byte_recompose",
                aq::AirKind::kEverywhere, 1,
                [l, slot, byte, bcol](
                    const auto& row, const auto&) {
                    Fp3 value = Fp3::Zero();
                    uint64_t weight = 1;
                    for (uint32_t bit = 0;
                         bit < 8; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                U(weight),
                                row[l.ProducerBit(
                                    slot,
                                    8 * byte + bit)]));
                        weight <<= 1;
                    }
                    return gf::Sub(row[bcol], value);
                });
        }
        Add(
            cs, "v15.source.word_recompose",
            aq::AirKind::kEverywhere, 1,
            [l, slot](const auto& row, const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(weight),
                            row[l.ProducerByte(
                                slot, byte)]));
                    weight <<= 8;
                }
                return gf::Sub(
                    row[l.ProducerValue(slot)], value);
            });
    }

    for (uint32_t lane = 0;
         lane < kConsumerWordLanesV15; ++lane) {
        const uint32_t active =
            l.consumer_word_active_base + lane;
        Add(
            cs, "v15.consumer.word_active_boolean",
            aq::AirKind::kEverywhere, 2,
            [active](const auto& row, const auto&) {
                return gf::Mul(
                    row[active],
                    gf::Sub(row[active], Fp3::One()));
            });
        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t b =
                l.ConsumerBit(lane, bit);
            Add(
                cs, "v15.consumer.bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [b](const auto& row, const auto&) {
                    return gf::Mul(
                        row[b],
                        gf::Sub(row[b], Fp3::One()));
                });
            Add(
                cs, "v15.consumer.inactive_bit_zero",
                aq::AirKind::kEverywhere, 2,
                [active, b](const auto& row, const auto&) {
                    return gf::Mul(
                        gf::Sub(Fp3::One(), row[active]),
                        row[b]);
                });
        }
        for (uint32_t byte = 0; byte < 4; ++byte) {
            const uint32_t port = 4 * lane + byte;
            Add(
                cs, "v15.consumer.byte_recompose",
                aq::AirKind::kEverywhere, 1,
                [l, lane, byte, port](
                    const auto& row, const auto&) {
                    Fp3 value = Fp3::Zero();
                    uint64_t weight = 1;
                    for (uint32_t bit = 0;
                         bit < 8; ++bit) {
                        value = gf::Add(
                            value,
                            gf::Mul(
                                U(weight),
                                row[l.ConsumerBit(
                                    lane,
                                    8 * byte + bit)]));
                        weight <<= 1;
                    }
                    return gf::Sub(
                        row[l.ConsumerByte(port)], value);
                });
        }
        Add(
            cs, "v15.consumer.word_recompose",
            aq::AirKind::kEverywhere, 2,
            [l, lane, active](
                const auto& row, const auto&) {
                Fp3 value = Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    value = gf::Add(
                        value,
                        gf::Mul(
                            U(weight),
                            row[l.ConsumerByte(
                                4 * lane + byte)]));
                    weight <<= 8;
                }
                return gf::Mul(
                    row[active],
                    gf::Sub(
                        row[
                            bridge::
                                TypedSafeDirectParentLayoutV14{}
                                    .Message(lane)],
                        value));
            });
    }
}

void AddCtlConstraints(
    aq::AirConstraintSystem<Fp3>& cs,
    const LayoutV15& l,
    const DualCtlChallengesV15& ch)
{
    for (uint32_t slot = 0;
         slot < kProducerSlotsV15; ++slot) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            const uint32_t address =
                l.ProducerAddress(slot);
            const uint32_t active =
                l.ProducerActive(slot);
            const uint32_t value =
                l.ProducerByte(slot, byte);
            const uint32_t i1 =
                l.producer_inverse1_base +
                4 * slot + byte;
            const uint32_t i2 =
                l.producer_inverse2_base +
                4 * slot + byte;
            Add(
                cs, "v15.ctl.producer_inverse1",
                aq::AirKind::kEverywhere, 2,
                [address, active, value, i1, byte, ch](
                    const auto& row, const auto&) {
                    const Fp3 denom = gf::Sub(
                        ch.alpha1,
                        Compress(
                            row[address], U(byte),
                            row[value], ch.gamma1));
                    return gf::Sub(
                        gf::Mul(row[i1], denom),
                        row[active]);
                });
            Add(
                cs, "v15.ctl.producer_inverse2",
                aq::AirKind::kEverywhere, 2,
                [address, active, value, i2, byte, ch](
                    const auto& row, const auto&) {
                    const Fp3 denom = gf::Sub(
                        ch.alpha2,
                        Compress(
                            row[address], U(byte),
                            row[value], ch.gamma2));
                    return gf::Sub(
                        gf::Mul(row[i2], denom),
                        row[active]);
                });
        }
    }
    for (uint32_t port = 0;
         port < kConsumerBytePortsV15; ++port) {
        const uint32_t active =
            l.consumer_active_base + port;
        const uint32_t address =
            l.consumer_address_base + port;
        const uint32_t source_byte =
            l.consumer_source_byte_base + port;
        const uint32_t value =
            l.ConsumerByte(port);
        const uint32_t i1 =
            l.consumer_inverse1_base + port;
        const uint32_t i2 =
            l.consumer_inverse2_base + port;
        Add(
            cs, "v15.ctl.consumer_inverse1",
            aq::AirKind::kEverywhere, 2,
            [active, address, source_byte, value, i1, ch](
                const auto& row, const auto&) {
                const Fp3 denom = gf::Sub(
                    ch.alpha1,
                    Compress(
                        row[address],
                        row[source_byte],
                        row[value], ch.gamma1));
                return gf::Sub(
                    gf::Mul(row[i1], denom),
                    row[active]);
            });
        Add(
            cs, "v15.ctl.consumer_inverse2",
            aq::AirKind::kEverywhere, 2,
            [active, address, source_byte, value, i2, ch](
                const auto& row, const auto&) {
                const Fp3 denom = gf::Sub(
                    ch.alpha2,
                    Compress(
                        row[address],
                        row[source_byte],
                        row[value], ch.gamma2));
                return gf::Sub(
                    gf::Mul(row[i2], denom),
                    row[active]);
            });
    }

    Add(
        cs, "v15.ctl.running1.first",
        aq::AirKind::kFirstRow, 1,
        [l](const auto& row, const auto&) {
            return row[l.running1];
        });
    Add(
        cs, "v15.ctl.running2.first",
        aq::AirKind::kFirstRow, 1,
        [l](const auto& row, const auto&) {
            return row[l.running2];
        });
    const auto delta =
        [l](const auto& row, bool lane) {
            Fp3 out = Fp3::Zero();
            for (uint32_t slot = 0;
                 slot < kProducerSlotsV15; ++slot) {
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    const uint32_t inverse =
                        (lane
                             ? l.producer_inverse2_base
                             : l.producer_inverse1_base) +
                        4 * slot + byte;
                    out = gf::Add(
                        out,
                        gf::Mul(
                            row[l.ProducerMultiplicity(
                                slot, byte)],
                            row[inverse]));
                }
            }
            for (uint32_t port = 0;
                 port < kConsumerBytePortsV15; ++port) {
                const uint32_t inverse =
                    (lane
                         ? l.consumer_inverse2_base
                         : l.consumer_inverse1_base) +
                    port;
                out = gf::Sub(
                    out,
                    gf::Mul(
                        row[l.consumer_active_base + port],
                        row[inverse]));
            }
            return out;
        };
    Add(
        cs, "v15.ctl.running1.transition",
        aq::AirKind::kTransition, 2,
        [l, delta](const auto& row, const auto& next) {
            return gf::Sub(
                next[l.running1],
                gf::Add(row[l.running1], delta(row, false)));
        });
    Add(
        cs, "v15.ctl.running2.transition",
        aq::AirKind::kTransition, 2,
        [l, delta](const auto& row, const auto& next) {
            return gf::Sub(
                next[l.running2],
                gf::Add(row[l.running2], delta(row, true)));
        });
    Add(
        cs, "v15.ctl.running1.last",
        aq::AirKind::kLastRow, 2,
        [l, delta](const auto& row, const auto&) {
            return gf::Add(
                row[l.running1], delta(row, false));
        });
    Add(
        cs, "v15.ctl.running2.last",
        aq::AirKind::kLastRow, 2,
        [l, delta](const auto& row, const auto&) {
            return gf::Add(
                row[l.running2], delta(row, true));
        });
}

} // namespace

bool BuildCanonicalSourceToV14V15(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const std::vector<uint32_t>& child_base_column_indices,
    const uint256& child_public_fs_seed,
    ProductV15& out,
    std::string* why)
{
    out = {};
    if (!bridge::BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
            child_cs, child_proof,
            child_base_column_indices,
            child_public_fs_seed,
            out.native_schedule, why) ||
        !bridge::BuildTypedSafeDirectParentV14(
            out.native_schedule.program,
            out.native_schedule.witness,
            out.v14, why)) {
        out = {};
        return Fail(why, "native_schedule_or_v14");
    }
    out.host_decoder_reconstructed_external_child =
        out.native_schedule.canonical_v13_proof_decoded;
    out.external_child_proof_required = true;
    out.child_proof_tape_in_v15 = false;
    out.no_free_source_vector = true;
    out.canonical_source_values_preprocessed = true;

    std::map<uint32_t, std::array<uint32_t, 4>>
        multiplicities;
    std::set<std::pair<uint32_t, uint32_t>>
        occupied_consumers;
    for (const auto& binding :
         out.native_schedule.child.transcript_word_bindings) {
        const uint32_t global_event =
            static_cast<uint32_t>(
                out.native_schedule.outer.program.size()) +
            binding.event;
        const auto alias = std::find_if(
            out.v14.proof_cell_aliases.begin(),
            out.v14.proof_cell_aliases.end(),
            [&](const auto& candidate) {
                return candidate.event == global_event &&
                    candidate.message_ordinal ==
                        binding.message_ordinal;
            });
        if (alias == out.v14.proof_cell_aliases.end()) {
            return Fail(why, "missing_v14_message_alias");
        }
        if (alias->event_column <
                out.v14.layout.message_base ||
            alias->event_column >=
                out.v14.layout.message_base +
                    kConsumerWordLanesV15) {
            return Fail(why, "v14_message_alias_column");
        }
        const uint32_t lane =
            alias->event_column -
            out.v14.layout.message_base;
        for (uint32_t byte = 0;
             byte < binding.bytes_present; ++byte) {
            const auto& source =
                binding.source_bytes[byte];
            if (!source.canonical_abi_source) continue;
            if (source.abi_source_address >=
                    out.native_schedule
                        .canonical_v13_sources.size() ||
                source.byte_in_abi_word >= 4) {
                return Fail(why, "canonical_source_address");
            }
            const uint32_t port = 4 * lane + byte;
            if (port >= kConsumerBytePortsV15 ||
                !occupied_consumers.emplace(
                    alias->event_row, port).second) {
                return Fail(why, "consumer_port_collision");
            }
            out.records.push_back({
                source.abi_source_address,
                source.byte_in_abi_word,
                binding.event,
                binding.message_ordinal,
                static_cast<uint8_t>(byte),
                alias->event_row,
                alias->event_column,
                static_cast<uint8_t>(port),
            });
            ++multiplicities[
                source.abi_source_address][
                    source.byte_in_abi_word];
        }
    }
    if (out.records.empty() ||
        out.records.size() !=
            out.native_schedule
                .canonical_v13_source_byte_occurrences ||
        multiplicities.size() >
            out.v14.trace_rows * kProducerSlotsV15) {
        return Fail(why, "canonical_schedule_shape");
    }
    uint32_t ordinal = 0;
    for (const auto& [address, uses] : multiplicities) {
        if (address >=
            out.native_schedule
                .canonical_v13_sources.size()) {
            return Fail(why, "selected_source_address");
        }
        CanonicalSourceV15 source;
        source.decoded =
            out.native_schedule.canonical_v13_sources[
                address];
        source.use_multiplicity = uses;
        source.producer_row =
            ordinal / kProducerSlotsV15;
        source.producer_slot =
            ordinal % kProducerSlotsV15;
        out.sources.push_back(std::move(source));
        ++ordinal;
    }
    out.schedule_commitment =
        CommitSchedule(out.v14, out.sources, out.records);
    if (out.schedule_commitment ==
        alg_hash::Digest{}) {
        return Fail(why, "schedule_commitment");
    }

    out.cs = out.v14.cs;
    out.cs.n_columns = out.layout.end;
    out.columns = out.v14.columns;
    out.columns.resize(
        out.layout.end,
        std::vector<Fp3>(
            out.v14.trace_rows,
            Fp3::Zero()));
    for (const auto& source : out.sources) {
        const uint32_t row = source.producer_row;
        const uint32_t slot = source.producer_slot;
        out.columns[
            out.layout.ProducerActive(slot)][row] =
                Fp3::One();
        out.columns[
            out.layout.ProducerAddress(slot)][row] =
                U(source.decoded.address);
        out.columns[
            out.layout.ProducerValue(slot)][row] =
                U(source.decoded.value);
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.columns[
                out.layout.ProducerMultiplicity(
                    slot, byte)][row] =
                U(source.use_multiplicity[byte]);
            const uint32_t value =
                (source.decoded.value >> (8 * byte)) &
                0xffU;
            out.columns[
                out.layout.ProducerByte(
                    slot, byte)][row] = U(value);
        }
        for (uint32_t bit = 0; bit < 32; ++bit) {
            out.columns[
                out.layout.ProducerBit(
                    slot, bit)][row] =
                U((source.decoded.value >> bit) & 1U);
        }
    }

    std::set<std::pair<uint32_t, uint32_t>>
        active_words;
    for (const auto& record : out.records) {
        const uint32_t lane =
            record.consumer_port / 4;
        active_words.emplace(record.v14_row, lane);
        out.columns[
            out.layout.consumer_active_base +
                record.consumer_port][record.v14_row] =
            Fp3::One();
        out.columns[
            out.layout.consumer_address_base +
                record.consumer_port][record.v14_row] =
            U(record.source_address);
        out.columns[
            out.layout.consumer_source_byte_base +
                record.consumer_port][record.v14_row] =
            U(record.source_byte);
    }
    for (const auto& [row, lane] : active_words) {
        const Fp3 value =
            out.columns[
                out.v14.layout.Message(lane)][row];
        if (!BaseOnly(value) ||
            gf::Canonical(value.c0) >
                std::numeric_limits<uint32_t>::max()) {
            return Fail(why, "consumer_not_u32");
        }
        const uint32_t word = Word(value);
        out.columns[
            out.layout.consumer_word_active_base +
                lane][row] = Fp3::One();
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.columns[
                out.layout.ConsumerByte(
                    4 * lane + byte)][row] =
                U((word >> (8 * byte)) & 0xffU);
        }
        for (uint32_t bit = 0; bit < 32; ++bit) {
            out.columns[
                out.layout.ConsumerBit(
                    lane, bit)][row] =
                U((word >> bit) & 1U);
        }
    }
    for (uint32_t lane = 0;
         lane < 4; ++lane) {
        out.columns[
            out.layout.descriptor_base + lane]
            .assign(
                out.v14.trace_rows,
                U(out.schedule_commitment[lane]));
        out.columns[
            out.layout.descriptor_base + 4 + lane]
            .assign(
                out.v14.trace_rows,
                U(out.v14.program_root[lane]));
    }

    AddDecompositionConstraints(out.cs, out.layout);
    for (uint32_t slot = 0;
         slot < kProducerSlotsV15; ++slot) {
        Pin(out.cs, out.layout.ProducerActive(slot), out.columns);
        Pin(out.cs, out.layout.ProducerAddress(slot), out.columns);
        Pin(out.cs, out.layout.ProducerValue(slot), out.columns);
        for (uint32_t byte = 0; byte < 4; ++byte) {
            Pin(
                out.cs,
                out.layout.ProducerMultiplicity(slot, byte),
                out.columns);
        }
    }
    for (uint32_t lane = 0;
         lane < kConsumerWordLanesV15; ++lane) {
        Pin(
            out.cs,
            out.layout.consumer_word_active_base + lane,
            out.columns);
    }
    for (uint32_t port = 0;
         port < kConsumerBytePortsV15; ++port) {
        Pin(
            out.cs,
            out.layout.consumer_active_base + port,
            out.columns);
        Pin(
            out.cs,
            out.layout.consumer_address_base + port,
            out.columns);
        Pin(
            out.cs,
            out.layout.consumer_source_byte_base + port,
            out.columns);
    }
    for (uint32_t lane = 0;
         lane < kDescriptorLanesV15; ++lane) {
        Pin(
            out.cs,
            out.layout.descriptor_base + lane,
            out.columns);
    }
    out.cs.preprocessed_pin_ood = true;

    out.base_column_indices.resize(
        out.layout.dependent_begin);
    for (uint32_t column = 0;
         column < out.layout.dependent_begin; ++column) {
        out.base_column_indices[column] = column;
    }
    out.retained_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.base_column_indices);
    if (!out.retained_r0.valid ||
        !DeriveChallenges(
            out.retained_r0.base_row_commitment,
            out.schedule_commitment,
            out.v14.program_root,
            static_cast<uint32_t>(out.records.size()),
            out.challenges)) {
        return Fail(why, "r0_or_ctl_challenges");
    }
    AddCtlConstraints(out.cs, out.layout, out.challenges);

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0; row < out.cs.n_rows; ++row) {
        out.columns[out.layout.running1][row] = running1;
        out.columns[out.layout.running2][row] = running2;
        Fp3 delta1 = Fp3::Zero();
        Fp3 delta2 = Fp3::Zero();
        for (uint32_t slot = 0;
             slot < kProducerSlotsV15; ++slot) {
            const bool active =
                !gf::IsZero(out.columns[
                    out.layout.ProducerActive(slot)][row]);
            for (uint32_t byte = 0; byte < 4; ++byte) {
                if (!active) continue;
                const uint32_t address = Word(
                    out.columns[
                        out.layout.ProducerAddress(slot)][row]);
                const Fp3 value =
                    out.columns[
                        out.layout.ProducerByte(slot, byte)][row];
                const Fp3 d1 = gf::Sub(
                    out.challenges.alpha1,
                    Compress(
                        U(address), U(byte), value,
                        out.challenges.gamma1));
                const Fp3 d2 = gf::Sub(
                    out.challenges.alpha2,
                    Compress(
                        U(address), U(byte), value,
                        out.challenges.gamma2));
                if (gf::IsZero(d1) || gf::IsZero(d2)) {
                    return Fail(why, "producer_ctl_pole");
                }
                const Fp3 i1 = gf::Inv(d1);
                const Fp3 i2 = gf::Inv(d2);
                out.columns[
                    out.layout.producer_inverse1_base +
                        4 * slot + byte][row] = i1;
                out.columns[
                    out.layout.producer_inverse2_base +
                        4 * slot + byte][row] = i2;
                const Fp3 multiplicity =
                    out.columns[
                        out.layout.ProducerMultiplicity(
                            slot, byte)][row];
                delta1 = gf::Add(
                    delta1, gf::Mul(multiplicity, i1));
                delta2 = gf::Add(
                    delta2, gf::Mul(multiplicity, i2));
            }
        }
        for (uint32_t port = 0;
             port < kConsumerBytePortsV15; ++port) {
            if (gf::IsZero(
                    out.columns[
                        out.layout.consumer_active_base +
                            port][row])) {
                continue;
            }
            const uint32_t address = Word(
                out.columns[
                    out.layout.consumer_address_base +
                        port][row]);
            const uint32_t byte_index = Word(
                out.columns[
                    out.layout.consumer_source_byte_base +
                        port][row]);
            const Fp3 value =
                out.columns[
                    out.layout.ConsumerByte(port)][row];
            const Fp3 d1 = gf::Sub(
                out.challenges.alpha1,
                Compress(
                    U(address), U(byte_index), value,
                    out.challenges.gamma1));
            const Fp3 d2 = gf::Sub(
                out.challenges.alpha2,
                Compress(
                    U(address), U(byte_index), value,
                    out.challenges.gamma2));
            if (gf::IsZero(d1) || gf::IsZero(d2)) {
                return Fail(why, "consumer_ctl_pole");
            }
            const Fp3 i1 = gf::Inv(d1);
            const Fp3 i2 = gf::Inv(d2);
            out.columns[
                out.layout.consumer_inverse1_base +
                    port][row] = i1;
            out.columns[
                out.layout.consumer_inverse2_base +
                    port][row] = i2;
            delta1 = gf::Sub(delta1, i1);
            delta2 = gf::Sub(delta2, i2);
        }
        running1 = gf::Add(running1, delta1);
        running2 = gf::Add(running2, delta2);
    }

    out.canonical_source_occurrences =
        static_cast<uint32_t>(out.records.size());
    out.producer_terms =
        out.canonical_source_occurrences;
    out.consumer_terms =
        out.canonical_source_occurrences;
    out.exact_public_schedule = true;
    out.source_and_consumer_values_in_r0 =
        out.base_column_indices.size() ==
            out.layout.dependent_begin;
    out.dual_ctl_challenges_after_r0 = true;
    out.dual_fp3_terminal_zero =
        gf::IsZero(running1) &&
        gf::IsZero(running2);
    out.canonical_source_subset_complete =
        out.records.size() ==
            out.native_schedule
                .canonical_v13_source_byte_occurrences;
    out.prior_event_sources_complete = false;
    out.derived_hash_sources_complete = false;
    out.v14_outputs_to_verifier_consumers = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.violations =
        bridge::CountViolationsV12(
            out.cs, out.columns);
    out.valid =
        out.external_child_proof_required &&
        !out.child_proof_tape_in_v15 &&
        out.host_decoder_reconstructed_external_child &&
        out.no_free_source_vector &&
        out.canonical_source_values_preprocessed &&
        out.exact_public_schedule &&
        out.source_and_consumer_values_in_r0 &&
        out.dual_ctl_challenges_after_r0 &&
        out.dual_fp3_terminal_zero &&
        out.canonical_source_subset_complete &&
        out.violations == 0 &&
        !out.prior_event_sources_complete &&
        !out.derived_hash_sources_complete &&
        !out.v14_outputs_to_verifier_consumers &&
        !out.recursively_consumed &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "externally supplied native child is host-decoded into public "
          "source pins with no free source vector, and its canonical ABI "
          "sources are joined to "
          "actual V14 ProofOwned message cells; child proof tape, residual "
          "sources, verifier outputs and recursion remain fail-closed"
        : "canonical-source V15 superprogram invalid";
    if (!out.valid) {
        std::string first{"none"};
        std::vector<Fp3> cur(out.cs.n_columns);
        std::vector<Fp3> next(out.cs.n_columns);
        for (uint32_t row = 0;
             row < out.cs.n_rows && first == "none";
             ++row) {
            for (uint32_t column = 0;
                 column < out.cs.n_columns; ++column) {
                cur[column] = out.columns[column][row];
                next[column] = out.columns[column][
                    (row + 1) % out.cs.n_rows];
            }
            for (const auto& constraint :
                 out.cs.constraints) {
                const bool applies =
                    constraint.kind ==
                        aq::AirKind::kEverywhere ||
                    (constraint.kind ==
                         aq::AirKind::kTransition &&
                     row + 1 < out.cs.n_rows) ||
                    (constraint.kind ==
                         aq::AirKind::kFirstRow &&
                     row == 0) ||
                    (constraint.kind ==
                         aq::AirKind::kLastRow &&
                     row + 1 == out.cs.n_rows);
                if (applies &&
                    !gf::IsZero(
                        constraint.eval(cur, next))) {
                    first =
                        std::string{constraint.name} +
                        "@" + std::to_string(row);
                    break;
                }
            }
        }
        return Fail(
            why,
            "invalid_product:violations=" +
                std::to_string(out.violations) +
                ":terminal=" +
                std::to_string(
                    out.dual_fp3_terminal_zero) +
                ":records=" +
                std::to_string(out.records.size()) +
                ":native_occurrences=" +
                std::to_string(
                    out.native_schedule
                        .canonical_v13_source_byte_occurrences) +
                ":first=" + first);
    }
    return true;
}

bool ProveCanonicalSourceToV14V15(
    const ProductV15& product,
    const uint256& public_fs_seed,
    ProofV15& out,
    std::string* why)
{
    out = {};
    if (!product.valid ||
        product.recursive_authority_ready ||
        product.violations != 0 ||
        public_fs_seed.IsNull()) {
        return Fail(why, "invalid_product_for_prove");
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs, product.columns,
            product.base_column_indices,
            public_fs_seed, {},
            &product.retained_r0);
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "air_prove:" + proved.note);
    }
    out.schedule_commitment =
        product.schedule_commitment;
    out.v14_program_root =
        product.v14.program_root;
    out.v14_transcript_commitment =
        product.v14.transcript_commitment;
    out.r0_commitment =
        product.retained_r0.base_row_commitment;
    out.proof = proved.proof;
    out.trace_rows = product.cs.n_rows;
    out.trace_columns = product.cs.n_columns;
    out.record_count =
        static_cast<uint32_t>(product.records.size());
    std::vector<unsigned char> encoded;
    out.serialized_proof_bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            out.proof, encoded);
    if (out.serialized_proof_bytes == 0 ||
        out.serialized_proof_bytes != encoded.size() ||
        out.serialized_proof_bytes >
            kRCFriMaxProofBytesHard) {
        out = {};
        return Fail(why, "proof_serialize");
    }
    out.proof_level_verified = false;
    out.child_proof_tape_in_v15 = false;
    out.recursively_consumed = false;
    out.recursive_authority_ready = false;
    out.note =
        "V15 proof built; normalized recursive consumption remains open";
    return true;
}

bool VerifyCanonicalSourceToV14V15(
    const ProductV15& expected_product,
    const ProofV15& proof,
    const uint256& public_fs_seed,
    std::string* why)
{
    if (proof.serialized_proof_bytes == 0 ||
        proof.serialized_proof_bytes >
            kRCFriMaxProofBytesHard) {
        return Fail(why, "proof_size_bound");
    }
    std::vector<unsigned char> encoded;
    const size_t encoded_size =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof.proof, encoded);
    if (!expected_product.valid ||
        proof.version != kVersionV15 ||
        proof.trace_rows != expected_product.cs.n_rows ||
        proof.trace_columns != expected_product.cs.n_columns ||
        proof.record_count != expected_product.records.size() ||
        proof.serialized_proof_bytes != encoded_size ||
        encoded_size != encoded.size() ||
        encoded_size > kRCFriMaxProofBytesHard ||
        proof.r0_commitment !=
            expected_product.retained_r0.base_row_commitment ||
        !DigestEq(
            proof.schedule_commitment,
            expected_product.schedule_commitment) ||
        !DigestEq(
            proof.v14_program_root,
            expected_product.v14.program_root) ||
        !DigestEq(
            proof.v14_transcript_commitment,
            expected_product.v14.transcript_commitment) ||
        proof.child_proof_tape_in_v15 ||
        proof.recursively_consumed ||
        proof.recursive_authority_ready ||
        proof.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.proof.batch.groups[0]
                .row_commit.root) !=
            proof.r0_commitment) {
        return Fail(why, "proof_public_binding");
    }
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            expected_product.cs,
            proof.proof,
            expected_product.base_column_indices,
            public_fs_seed, why)) {
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:safe_v15_superprogram:proof_verified;"
            "recursive_consumption_open";
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_safe_v15_superprogram
