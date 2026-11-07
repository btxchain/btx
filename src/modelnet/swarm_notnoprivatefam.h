// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPRIVATEFAM_H
#define BTX_MODELNET_SWARM_NOTNOPRIVATEFAM_H

#include <string>

namespace modelnet {

/**
 * A local note about one family. family_id names the family.
 * private_family records that the family is private. want_publish asks
 * this note to publish.
 *
 * Discovery does not publish a private family and moves no bytes.
 * published and bytes_moved stay false on every path.
 */
struct SwarmNotNoPrivateFam {
    std::string family_id;
    bool private_family{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a family. published and bytes_moved stay false on
 * every path. Discovery does not publish a private family and moves no
 * bytes.
 */
struct SwarmNotNoPrivateFamResult {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note a family without publishing it or moving bytes.
 * Order, first match wins: an empty family_id is FAMILY. private_family
 * true is REFUSED, even when want_publish is false. want_publish is
 * REFUSED. Otherwise the note is NOTED and err is cleared.
 * published and bytes_moved stay false on every path.
 * Discovery does not publish a private family and moves no bytes.
 */
SwarmNotNoPrivateFamResult SwarmNoteNotNoPrivateFam(const SwarmNotNoPrivateFam& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPRIVATEFAM_H
