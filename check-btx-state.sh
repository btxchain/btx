#!/usr/bin/env bash
set -u
CLI=/home/eldian/btx-node/bin/btx-cli
DD=/home/eldian/.btx
CONF=/home/eldian/.btx/faststart/faststart.conf
HASH=bee000e92d6b64ceb6ad9a3759fb38c1d6752713240e76bde3617f073b9cbe74
echo manifest_hash=$HASH
echo getblockheader
$CLI -datadir=$DD -conf=$CONF -rpcclienttimeout=10 getblockheader $HASH 2>&1 | head -80 || true
echo chainstates
$CLI -datadir=$DD -conf=$CONF -rpcclienttimeout=10 getchainstates 2>&1 || true
echo blockchain_short
$CLI -datadir=$DD -conf=$CONF -rpcclienttimeout=10 getblockchaininfo 2>&1 | sed -n '1,45p' || true
