BTX Shielded-State Startup and Recovery
=======================================

This is an operator runbook for what happens when `btxd` rebuilds its
node-level shielded validation state at startup, how to tell a slow-but-healthy
rebuild from a stuck one, and how to repair a damaged shielded state with the
`-resetshieldedstate` flag.

It is operator-focused. You do not need to understand the shielded pool
internals to follow it.

What shielded-state init/rebuild is
-----------------------------------
BTX keeps node-level shielded validation state (the commitment tree, the
nullifier set, and the account registry) on disk under the datadir in
`shielded_state/` (notably `shielded_state/nullifiers` and
`shielded_state/account_registry`).

At startup `btxd` runs `EnsureShieldedStateInitialized`. If that on-disk state
is missing, stale, or inconsistent with the chain tip, the node rebuilds it by
replaying every block from genesis to the tip in `RebuildShieldedState`,
re-deriving the shielded state from the blocks themselves.

A rebuild is expected and normal in these cases:

- **First start after an upgrade.** A new release that changes the shielded
  state format (or simply has no persisted state yet) will rebuild once.
- **After an unclean shutdown** (kill, crash, power loss, OOM).
- **After an interrupted earlier rebuild** (see "Do not keep restarting"
  below).

During a rebuild, RPC calls return:

```
error code: -28
error message:
Verifying blocks...
```

This is the node telling you it is still verifying / replaying and is not ready
to serve RPC yet. It is not an error you need to fix; it just means "wait".

Why it can take a while
-----------------------
The replay walks the entire chain from genesis to tip and reads every block
from disk. On a large chain or a slow disk this can take a long time. CPU and
disk will be busy the whole time.

### Do not keep restarting

Restarting in the middle of a rebuild makes things **worse**, not better.

Before the rebuild completes, the node writes an in-flight mutation marker and
wipes `shielded_state/nullifiers` and `shielded_state/account_registry`. That
marker is only cleared after a successful persist of the new state. So if you
kill `btxd` mid-rebuild, the next launch finds the marker and **starts the
rebuild over from scratch**. You will see a log line like:

```
EnsureShieldedStateInitialized: found in-flight mutation marker target_height=<H> target_hash=<hash>; rebuilding full shielded state from chain
```

Every restart resets the progress bar. Be patient and let one rebuild finish.

### Watch the progress lines

The rebuild logs periodic progress so you can confirm it is advancing. Look in
`debug.log` (or stdout) for lines like:

```
RebuildShieldedState: replaying shielded state <N>/<TOTAL> (height=<H>, <P>%)
```

`N`/`TOTAL` and the `height=` value should keep climbing and the percentage
should keep rising. As long as that is happening, the node is healthy. Tail it
with, for example:

```
tail -f ~/.btx/debug.log | grep RebuildShieldedState
```

**Only worry if** the height/percentage stops advancing for a long time **and**
there is no disk or CPU activity (check `iostat`, `top`/`htop`, or your disk
LED). A rebuild that is still reading blocks is fine even if it is slow.

Repair flow: `-resetshieldedstate`
----------------------------------
If the shielded state is damaged, or you simply want to force exactly one clean
rebuild from chain, use the `-resetshieldedstate` startup flag. It wipes the
`shielded_state` directory at startup and rebuilds it once from the chain. This
is the supported replacement for the old manual workaround of moving
`shielded_state` aside by hand.

Procedure:

1. **Stop `btxd`** cleanly (`btx-cli stop`, or stop your service unit). Wait
   for the process to exit.
2. **Back up the datadir** (at minimum copy `shielded_state/` aside, ideally
   snapshot the whole datadir) so you can roll back if needed.
3. **Start once with the flag:**

   ```
   btxd -resetshieldedstate
   ```

   or add `resetshieldedstate=1` to `btx.conf` for the single run.
4. **Let the one rebuild finish.** Watch the `RebuildShieldedState: replaying
   ...` progress lines as above and wait until the node finishes initializing
   and RPC stops returning `-28`.
5. **Remove the flag** for normal operation. `-resetshieldedstate` is a
   one-shot repair flag; leaving it on would wipe and rebuild on every start.

When to escalate
----------------
If `-resetshieldedstate` does not produce a clean, stable node, the problem is
likely below the shielded layer (block files or chainstate), and you should
escalate:

- **Local block files intact:** run a full `-reindex`. This re-reads and
  re-validates the block files and rebuilds chainstate and shielded state from
  them. Use the full `-reindex`, **not** `-reindex-chainstate` — the latter
  does not re-read the block files and will not help if those are the problem.
- **Blocks pruned or corrupt:** a reindex cannot recover data you no longer
  have. Recover from a trusted snapshot or start from a fresh datadir and
  re-sync. See the snapshot/fast-start runbooks in the docs index.

Tuning and environment notes
----------------------------
### `retainshieldedcommitmentindex` (default `1`)

`retainshieldedcommitmentindex=1` (the default) keeps the shielded commitment-
position index in the on-disk LevelDB store across restarts and snapshot
recovery, so restarts are faster. Setting `retainshieldedcommitmentindex=0`
selects the slower "externalized" posture that rebuilds that index in memory
after restart in exchange for lower retained shielded-state growth on disk.
Keep the default unless you specifically need the smaller on-disk footprint and
can accept slower restarts.

### WSL / slow-filesystem caveat

Keep the datadir on a **native Linux ext4** filesystem (e.g. `~/.btx`). Do
**not** point the datadir at a Windows-mounted path under `/mnt/c` (or any
`9p`/DrvFs mount) when running under WSL. The full-chain block reads during a
rebuild hammer that filesystem, and on Windows-mounted paths this triggers
kernel I/O stalls (you will see tasks blocked in `folio_wait_bit_common`),
which can make a rebuild appear hung when it is really starving on I/O. Native
ext4 avoids this.

See also
--------
- [BTX Shielded Pool Guide](btx-shielded-pool-guide.md)
- [BTX Mining Node Snapshot Runbook](btx-mining-node-snapshot-runbook.md)
- [btx.conf Configuration File](btx-conf.md)
- [Reduce Memory](reduce-memory.md)
