# BTX Seed Server Spec

This file is a bundled public reference for operators who need the current
seed-node role definition when running BTX audit, red-team, or launch-readiness
procedures.

## Purpose

- Describe the minimum responsibilities of a BTX seed node.
- Provide a stable in-repo path for bundle generators and test fixtures.
- Avoid depending on an external sibling workspace to assemble review packets.

## Baseline Expectations

- Seed nodes should run a current `btxd` build from the canonical public tree.
- Seed nodes should expose the network's expected P2P listener and maintain
  persistent reachability.
- Seed nodes should serve headers and blocks for initial peer bootstrap.
- Operators should keep clock sync, disk headroom, and log retention under
  active monitoring.

## Operational Notes

- This document is intentionally lightweight. Deployment-specific inventories,
  addresses, and credentials must not be committed here.
- Review bundles may include this file as an operator-facing reference, but
  environment-specific values should be maintained outside the repository.
