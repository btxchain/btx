// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_IMAGE_NIF_IMAGE_H
#define BITCOIN_MODELNET_NIF_IMAGE_NIF_IMAGE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Bind refused a digest that is not 64 lowercase hex characters. Nothing is stored. */
inline constexpr char NIF_IMAGE_DIGEST[] = "DIGEST";

/** Bind refused an empty software authority, or a software authority equal to the model authority. Nothing is stored. */
inline constexpr char NIF_IMAGE_AUTHORITY[] = "AUTHORITY";

/** Rollback has only the current pin, or no pin. current() stays. */
inline constexpr char NIF_IMAGE_EMPTY[] = "EMPTY";

/** Download is refused. No bytes are written and no socket is opened. */
inline constexpr char NIF_IMAGE_DOWNLOAD[] = "DOWNLOAD";

/**
 * Offline image pin.
 *
 * Bind stores a digest only when it is 64 lowercase hex characters, the
 * software authority is non-empty, and the software authority differs from
 * the model authority. Any other digest is DIGEST and stores nothing. An
 * empty software authority, or a software authority equal to the model
 * authority, is AUTHORITY and stores nothing. A successful Bind makes that
 * digest current().
 *
 * Rollback restores the previous successful digest. With fewer than two
 * stored digests, Rollback is EMPTY and current() stays. After a second
 * Bind, Rollback returns to the first digest and leaves that first digest
 * stored.
 *
 * Download returns false with DOWNLOAD. It writes nothing and leaves
 * startup_downloads() at 0.
 *
 * Execute returns false with NIFDT_ENGINE_ABSENT. No runtime image is
 * linked, so bytes_moved() stays 0.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND ("0"). image_qualified() stays false. This class
 * does not report a production image, opens no socket, and holds no spend key.
 */
class NifImage {
public:
    bool Bind(const std::string& digest, const std::string& software_authority, const std::string& model_authority, std::string& err);
    bool Rollback(std::string& err);
    bool Download(const std::string& url, std::string& err);
    bool Execute(std::string& err);

    const std::string& current() const { return m_current; }
    int64_t startup_downloads() const { return m_startup_downloads; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    bool image_qualified() const { return false; }

private:
    std::vector<std::string> m_pins;
    std::string m_current;
    int64_t m_startup_downloads{0};
    int64_t m_bytes_moved{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_IMAGE_NIF_IMAGE_H
