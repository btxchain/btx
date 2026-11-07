// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTENANT_H
#define BTX_MODELNET_SWARM_NOTNOTENANT_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. other_tenant marks the page as
 * belonging to another tenant. want_read asks this note to read it.
 *
 * A lookup for another tenant reads nothing and moves no bytes.
 * read and bytes_moved stay false on every path.
 */
struct SwarmNotNoTenant {
    std::string page_id;
    bool other_tenant{false};
    bool want_read{false};
};

/**
 * Outcome of noting a page. read and bytes_moved stay false on every
 * path. A lookup for another tenant reads nothing and moves no bytes.
 */
struct SwarmNotNoTenantResult {
    std::string code;
    bool read{false};
    bool bytes_moved{false};
};

/**
 * Note a page without reading or moving bytes. Order, first match
 * wins: an empty page_id is PAGE. other_tenant is TENANT even when
 * want_read is false. want_read is HELD. Otherwise the note is NOTED
 * and err is clear. read and bytes_moved stay false on every path.
 * A lookup for another tenant reads nothing and moves no bytes.
 */
SwarmNotNoTenantResult SwarmNoteNotNoTenant(const SwarmNotNoTenant& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTENANT_H
