// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_NUMPROF_DT_NUMPROF_H
#define BITCOIN_MODELNET_DT_NUMPROF_DT_NUMPROF_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** The only profile names this engine records. */
inline constexpr char DT_NUMPROF_CED[] = "ced";
inline constexpr char DT_NUMPROF_CSA2[] = "csa2";
inline constexpr char DT_NUMPROF_ENGRAM[] = "engram";
inline constexpr char DT_NUMPROF_MHC[] = "mhc";

/** The name is not one of the four profile names. Nothing is stored. */
inline constexpr char DT_NUMPROF_NAME[] = "NAME";

/** hidden, layers, or heads is below 1. Nothing is stored. */
inline constexpr char DT_NUMPROF_SHAPE[] = "SHAPE";

/** The profile name is known and has no stored shape. */
inline constexpr char DT_NUMPROF_INCOMPLETE[] = "INCOMPLETE";

/**
 * DT-GRD-008. Records a caller-supplied shape for ced, csa2, engram, or mhc.
 * A stored shape is not an advertisement and is not a hardware qualification.
 * These records are not trained weights.
 *
 * Define accepts only those four names. Any other name is NAME and stores
 * nothing. hidden, layers, or heads below 1 is SHAPE and stores nothing.
 * A successful Define stores those three sizes and defined(name) becomes
 * true. A second Define of the same name, with every size at least 1, is
 * NIFDT_REPLAY and keeps the first shape.
 *
 * Advertise of an unknown name is NAME. Advertise of a known name that was
 * not defined is INCOMPLETE. Advertise of a defined name is
 * NIFDT_UNQUALIFIED. advertised(), qualified(), and hardware_qualified()
 * stay false.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and does not set advertised().
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0. hosts() stays 1. No process
 * is spawned and no socket is opened.
 */
class DtNumProf {
public:
    bool Define(const std::string& name, std::int64_t hidden, std::int64_t layers, std::int64_t heads, std::string& err);
    bool Advertise(const std::string& name, std::string& err);
    bool Gpu(std::string& err);

    bool defined(const std::string& name) const;
    /** Stored hidden size, or 0 when this name has no shape. */
    std::int64_t hidden(const std::string& name) const;
    /** Stored layer count, or 0 when this name has no shape. */
    std::int64_t layers(const std::string& name) const;
    /** Stored head count, or 0 when this name has no shape. */
    std::int64_t heads(const std::string& name) const;

    bool advertised() const { return false; }
    bool qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::int64_t bytes_moved() const { return static_cast<std::int64_t>(0); }
    std::int64_t hosts() const { return static_cast<std::int64_t>(1); }

private:
    struct Shape {
        std::int64_t hidden{0};
        std::int64_t layers{0};
        std::int64_t heads{0};
    };

    static bool Known(const std::string& name);
    const Shape* Find(const std::string& name) const;

    std::map<std::string, Shape> m_shapes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_NUMPROF_DT_NUMPROF_H
