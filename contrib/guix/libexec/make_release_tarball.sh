#!/bin/sh
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# A helper script to generate source release tarball

export LC_ALL=C
set -ex

[ "$#" -ge 2 ]
[ -n "${REFERENCE_DATETIME}" ]

GIT_ARCHIVE="$1"
DISTNAME="$2"

git archive --prefix="${DISTNAME}/" HEAD |
 tar -xp \
  --exclude .cirrus.yml \
  --exclude '.git*' \
  --exclude ci \
  --exclude '*minisketch*' \
  --exclude 'doc/release-notes' \
 # end of tar options

# Generate correct build info file from git, before we lose git
GIT_BUILD_INFO="$(cmake -P cmake/script/GenerateBuildInfo.cmake)"
GIT_BUILD_INFO="${GIT_BUILD_INFO}" perl -0777 -pi -e \
  's{// No build information available}{$ENV{GIT_BUILD_INFO}}' \
  "${DISTNAME}/cmake/script/GenerateBuildInfo.cmake"

tar \
  --format=ustar \
  --sort=name \
  --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 \
  --mtime="${REFERENCE_DATETIME}" \
  -c "${DISTNAME}" | \
  gzip -9n \
  >"${GIT_ARCHIVE}"

rm -rf "${DISTNAME}"
