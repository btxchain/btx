// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_MEDIA_NIF_MEDIA_H
#define BITCOIN_MODELNET_NIF_MEDIA_NIF_MEDIA_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Bind refused a purpose other than inference or training. Nothing is stored. */
inline constexpr char NIF_MEDIA_PURPOSE[] = "PURPOSE";

/** Acquire refused an empty id. Nothing is stored. */
inline constexpr char NIF_MEDIA_MEDIA[] = "MEDIA";

/** Acquire refused a body that is not a local file. Nothing is written. */
inline constexpr char NIF_MEDIA_DOWNLOAD[] = "DOWNLOAD";

/** Acquire refused a body that is not authorized. Nothing is written. */
inline constexpr char NIF_MEDIA_DENIED[] = "DENIED";

/** Acquire refused an ELF image or a PYTHON_PICKLE body. Nothing is written. */
inline constexpr char NIF_MEDIA_CODE[] = "CODE";

/**
 * Local media acquisition for requirement NIF-DATA-004.
 *
 * Bind accepts the purpose only when it is exactly "inference" or exactly
 * "training". Any other purpose is PURPOSE and stores nothing. A later
 * valid Bind replaces the purpose. A refused Bind leaves the purpose that
 * was already stored.
 *
 * Acquire stores one body for one id. With no Bind yet the result is
 * PURPOSE and nothing is stored. An empty id is MEDIA and nothing is
 * stored. A second Acquire of an id that is already stored is
 * NIFDT_REPLAY, checked after the empty-id check and before the download
 * and code checks. The first body stays, including when the second call
 * would have been DOWNLOAD or CODE. A call that fails does not store its
 * id, so a later valid Acquire of that id can still store.
 *
 * local_file false is DOWNLOAD. authorized false is DENIED. A body of at
 * least four bytes beginning 0x7f ELF, or a body that contains the ASCII
 * bytes PYTHON_PICKLE, is CODE. Those refusals write nothing and leave
 * acquired() unchanged. Any other body is stored once. acquired() counts
 * stored ids. stored_bytes() is the sum of stored body sizes, so one
 * stored body reports that body's size. executable() stays false.
 *
 * bytes_moved() stays 0. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND ("0"). qualified() stays
 * false. This class opens no socket, downloads nothing, and starts no
 * process.
 */
class NifMedia {
public:
    bool Bind(const std::string& purpose, std::string& err);
    bool Acquire(const std::string& id, const std::vector<unsigned char>& body, bool authorized, bool local_file, std::string& err);

    const std::string& purpose() const { return m_purpose; }
    bool stored(const std::string& id) const;
    const std::vector<unsigned char>& body(const std::string& id) const;
    int64_t acquired() const { return static_cast<int64_t>(m_items.size()); }
    int64_t stored_bytes() const;
    bool executable() const { return false; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    bool qualified() const { return false; }

private:
    struct MediaItem {
        std::string id;
        std::vector<unsigned char> body;
    };

    const MediaItem* Find(const std::string& id) const;

    std::string m_purpose;
    std::vector<MediaItem> m_items;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_MEDIA_NIF_MEDIA_H
