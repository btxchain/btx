// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PROTOCOL_VERSION_H
#define BITCOIN_NODE_PROTOCOL_VERSION_H

/**
 * network protocol versioning
 */

//! Bumped to 800002 for MatMul v4.7 Epoch-A (RC ExactReplay). Nodes that do not
//! enforce the Epoch-A work transition extend a legacy chain that sealed nodes
//! reject, so they need to be distinguishable at the handshake.
static const int PROTOCOL_VERSION = 800002;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = 800001;

//! Minimum protocol version required to follow the MatMul v4.7 Epoch-A chain.
//! Peers below this version are disconnected once the tip passes
//! MATMUL_RC_ENFORCEMENT_HEIGHT. Non-updated nodes extend the legacy chain and
//! their headers violate the Epoch-A work transition; keeping them connected
//! wastes peer slots and confuses pool operators reading peer heights.
static const int MIN_MATMUL_RC_PROTOCOL_VERSION = 800002;

//! Chain height at which Epoch-A protocol version enforcement activates.
//! Default is INT32_MAX (disabled): every peer on the network still advertises
//! 800001 today, so shipping an early enforcement height would partition any
//! upgraded node from the rest of the network. Operators may lower this via
//! -matmulrcenforcementheight once upgrades are coordinated.
static const int MATMUL_RC_ENFORCEMENT_HEIGHT = 2147483647; // INT32_MAX

//! Minimum protocol version required for SMILE v2 shielded transactions.
//! Peers below this version are disconnected after SMILE_V2_ENFORCEMENT_HEIGHT
//! to prevent chain splits from nodes that reject valid SMILE v2 transactions.
static const int MIN_SMILE_V2_PROTOCOL_VERSION = 800001;

//! Chain height at which SMILE v2 protocol version enforcement activates.
//! Before this height, old-version peers are tolerated for IBD compatibility.
static const int SMILE_V2_ENFORCEMENT_HEIGHT = 51000;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "sendheaders" command and announcing blocks with headers starts with this version
static const int SENDHEADERS_VERSION = 70012;

//! "feefilter" tells peers to filter invs to you by fee starts with this version
static const int FEEFILTER_VERSION = 70013;

//! short-id-based block download starts with this version
static const int SHORT_IDS_BLOCKS_VERSION = 70014;

//! not banning for invalid compact blocks starts with this version
static const int INVALID_CB_NO_BAN_VERSION = 70015;

//! "wtxidrelay" command for wtxid-based relay starts with this version
static const int WTXID_RELAY_VERSION = 70016;

#endif // BITCOIN_NODE_PROTOCOL_VERSION_H
