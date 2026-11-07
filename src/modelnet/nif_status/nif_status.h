// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_STATUS_NIF_STATUS_H
#define BITCOIN_MODELNET_NIF_STATUS_NIF_STATUS_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Record refused a kind outside the evidence classes. Nothing is stored. */
inline constexpr char NIF_STATUS_CLASS[] = "CLASS";

/** Record refused an empty name. Nothing is stored. */
inline constexpr char NIF_STATUS_NAME[] = "NAME";

/**
 * Separated evidence classes for one node.
 *
 * Record stores one name in one class. kind is component, native, hardware,
 * or release. Any other kind is CLASS and stores nothing. An empty name is
 * NAME and stores nothing. A second record of the same kind and the same
 * name is NIFDT_REPLAY and the first name stays. The same name may be stored
 * once in each class. component_count(), native_count(), hardware_count(),
 * and release_count() count distinct names in that class only.
 *
 * A hardware record is evidence that a measurement was logged.
 * hardware_qualified() stays false. A release record is evidence that a
 * name was logged in the release class. release_qualified() stays false.
 * This class does not report release qualification.
 *
 * Release returns false with NIFDT_UNQUALIFIED. It does not store the name
 * and it does not increment release_count(). Promote returns false with
 * NIFDT_UNQUALIFIED. It does not copy a component name into the release
 * class and it does not set release_qualified().
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND ("0"). This class opens no socket and holds no
 * spend key.
 */
class NifStatus {
public:
    bool Record(const std::string& kind, const std::string& name, std::string& err);
    bool Release(const std::string& name, std::string& err);
    bool Promote(const std::string& name, std::string& err);

    int64_t component_count() const { return static_cast<int64_t>(m_component.size()); }
    int64_t native_count() const { return static_cast<int64_t>(m_native.size()); }
    int64_t hardware_count() const { return static_cast<int64_t>(m_hardware.size()); }
    int64_t release_count() const { return static_cast<int64_t>(m_release.size()); }

    bool component_stored(const std::string& name) const;
    bool native_stored(const std::string& name) const;
    bool hardware_stored(const std::string& name) const;
    bool release_stored(const std::string& name) const;

    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::vector<std::string>* Find(const std::string& kind);

    std::vector<std::string> m_component;
    std::vector<std::string> m_native;
    std::vector<std::string> m_hardware;
    std::vector<std::string> m_release;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_STATUS_NIF_STATUS_H
