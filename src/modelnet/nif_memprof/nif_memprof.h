// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_MEMPROF_NIF_MEMPROF_H
#define BITCOIN_MODELNET_NIF_MEMPROF_NIF_MEMPROF_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty profile, or the profile is not stored. Nothing is stored. */
inline constexpr char NIF_MEMPROF_PROFILE[] = "PROFILE";

/** model_bytes below 1, or transient_bytes below 0. Nothing is stored. */
inline constexpr char NIF_MEMPROF_BYTES[] = "BYTES";

/**
 * model_bytes + transient_bytes overflows int64, or the sum exceeds the
 * remaining capacity. Nothing is stored.
 */
inline constexpr char NIF_MEMPROF_CAPACITY[] = "CAPACITY";

/** Release ran before Quiesce. physical_bytes() stays unchanged. */
inline constexpr char NIF_MEMPROF_PINNED[] = "PINNED";

/** Quiesce ran before Cancel. physical_bytes() stays unchanged. */
inline constexpr char NIF_MEMPROF_ORDER[] = "ORDER";

/** Accounted capacity of one memory profile engine, in bytes. */
inline constexpr std::int64_t NIF_MEMPROF_CAPACITY_BYTES{100};

/**
 * NIF-PROF-006. Accounted model bytes and transient bytes.
 * Capacity is 100 bytes. A stored reservation is an account of bytes.
 * advertised() stays false. hardware_qualified() stays false. A GPU
 * reservation is absent from this engine.
 *
 * Reserve stores one profile. An empty profile is PROFILE and stores
 * nothing. A profile that is already stored is NIFDT_REPLAY and the first
 * model_bytes and transient_bytes stay. model_bytes below 1, or
 * transient_bytes below 0, is BYTES and stores nothing. A sum that
 * overflows int64, or that exceeds the remaining capacity, is CAPACITY
 * and stores nothing. A successful Reserve adds model_bytes and
 * transient_bytes to physical_bytes().
 *
 * Cancel marks that profile canceled. physical_bytes() stays unchanged.
 * An unknown profile is PROFILE.
 *
 * Quiesce succeeds for a canceled profile and leaves physical_bytes()
 * unchanged. Quiesce before Cancel is ORDER. Release before Quiesce is
 * PINNED and leaves physical_bytes() unchanged. Release after Quiesce
 * subtracts that profile's bytes from physical_bytes(). A second Release
 * is NIFDT_REPLAY.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and leaves physical_bytes()
 * unchanged. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 */
class NifMemProf {
public:
    bool Reserve(const std::string& profile, std::int64_t model_bytes, std::int64_t transient_bytes, std::string& err);
    bool Cancel(const std::string& profile, std::string& err);
    bool Quiesce(const std::string& profile, std::string& err);
    bool Release(const std::string& profile, std::string& err);
    bool Gpu(std::string& err);

    std::int64_t physical_bytes() const { return m_physical; }
    /** Stored model bytes, or 0 when this profile is absent. */
    std::int64_t model_bytes(const std::string& profile) const;
    /** Stored transient bytes, or 0 when this profile is absent. */
    std::int64_t transient_bytes(const std::string& profile) const;

    bool advertised() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::int64_t bytes_moved() const { return static_cast<std::int64_t>(0); }

private:
    struct Row {
        std::int64_t model_bytes{0};
        std::int64_t transient_bytes{0};
        bool canceled{false};
        bool quiesced{false};
        bool released{false};
    };

    const Row* Find(const std::string& profile) const;
    Row* Find(const std::string& profile);
    /** Empty or unknown profile is PROFILE. Returns true when the caller must stop. */
    bool Missing(const std::string& profile, std::string& err) const;

    std::map<std::string, Row> m_rows;
    std::int64_t m_physical{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_MEMPROF_NIF_MEMPROF_H
