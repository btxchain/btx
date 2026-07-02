"""BTX Mining Control Panel — update, run, guard, and stop D:\\BTX pool mining."""
import json
import os
import re
import subprocess
import threading
import time
import tkinter as tk
import urllib.request
from tkinter import ttk

WSL_DIST = "Ubuntu"
CLI = "/home/eldian/btx-node/bin/btx-cli"
BTXD = "/home/eldian/btx-node/bin/btxd"
DATADIR = "/home/eldian/.btx"
MINER_BIN = "/home/eldian/.local/bin/dexbtx-miner"
MINER_CFG = "/home/eldian/.dexbtx-miner/config.yaml"
WALLET = "my-wallet"
MINING_ADDR = "btx1zkht84nwz8mxk2ln20krjr4lcn5e65gsmssk8m48qtlsl5m97awds6d9m35"
GUARD = "/mnt/d/BTX/btx-pool-guard.sh"
SOLO_GUARD = "/mnt/d/BTX/btx-solo-guard.sh"
MODE_SWITCH = "/mnt/d/BTX/btx-mining-mode.sh"
UPDATE = "/mnt/d/BTX/btx-update-latest.sh"
RESTORE = "/mnt/d/BTX/btx-restore-snapshot.sh"
GUARD_LOG = "/mnt/d/BTX/btx-pool-guard.log"
SOLO_LOG = "/mnt/d/BTX/btx-solo-guard.log"
RESTORE_LOG = "/mnt/d/BTX/btx-restore-snapshot.log"
MINER_LOG = "/mnt/d/BTX/dexbtx-miner.log"
POOL_LABEL = "minebtx.com:3333 (PPLNS)"
EXPLORER_ADDR_API = "https://explorer.minebtx.com/api/address/"
# Start the saved mining mode (and its node, for solo) when the GUI opens.
AUTO_START = True

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def wsl_run(cmd, timeout=10):
    """Run a bash command in WSL and return (stdout, stderr, rc)."""
    try:
        r = subprocess.run(
            ["wsl", "-d", WSL_DIST, "--", "/bin/bash", "-lc", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"timeout after {timeout}s", 124
    except Exception as e:
        return "", str(e), 1


def wsl_detached(cmd):
    """Start a detached long-running WSL process."""
    return subprocess.Popen(
        ["wsl", "-d", WSL_DIST, "--", "/bin/bash", "-lc", cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
    )


def explorer_balance_text(address=MINING_ADDR, timeout=6):
    """Return confirmed+mempool balance for the payout address via BTXplorer."""
    try:
        req = urllib.request.Request(
            EXPLORER_ADDR_API + address,
            headers={"User-Agent": "BTX-Control/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        chain = data.get("chain_stats", {})
        mempool = data.get("mempool_stats", {})
        confirmed_sat = int(chain.get("funded_txo_sum", 0)) - int(chain.get("spent_txo_sum", 0))
        mempool_sat = int(mempool.get("funded_txo_sum", 0)) - int(mempool.get("spent_txo_sum", 0))
        total_sat = confirmed_sat + mempool_sat
        txt = f"{total_sat / 100_000_000:.8f} BTX (payout addr)"
        if mempool_sat:
            txt += f" · mempool {mempool_sat / 100_000_000:+.8f}"
        return txt
    except Exception as e:
        return f"unavailable ({e.__class__.__name__})"


class BTXControl:
    def __init__(self, root):
        self.root = root
        self.root.title("BTX Miner Control")
        self.root.geometry("720x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#1a1a2e")
        self.running = True
        self.updating = False
        self.restoring = False

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("BTX.Horizontal.TProgressbar", troughcolor="#0f1226", background="#2aa84a", bordercolor="#16213e", lightcolor="#2aa84a", darkcolor="#0b7a53")
        style.configure("BTXWarn.Horizontal.TProgressbar", troughcolor="#0f1226", background="#f0a500", bordercolor="#16213e", lightcolor="#f0a500", darkcolor="#b97800")

        tk.Label(
            root,
            text="⛏ BTX Miner Control",
            font=("Segoe UI", 18, "bold"),
            fg="#e94560",
            bg="#1a1a2e",
        ).pack(pady=(15, 5))

        sf = tk.Frame(root, bg="#16213e", bd=1, relief="solid")
        sf.pack(padx=20, pady=10, fill="x")

        self.labels = {}
        rows = [
            ("version", "BTX Version"),
            ("mode", "Mode"),
            ("node", "Node"),
            ("blocks", "Blocks"),
            ("wallet", "Wallet Balance"),
            ("guard", "Guard"),
            ("mining", "Miner"),
            ("hashrate", "Hashrate"),
            ("gpu", "GPU"),
            ("pool", "Pool / Solo"),
        ]
        for i, (key, label) in enumerate(rows):
            tk.Label(
                sf,
                text=label,
                font=("Segoe UI", 10),
                fg="#8899aa",
                bg="#16213e",
                anchor="w",
                width=15,
            ).grid(row=i, column=0, padx=(15, 5), pady=4, sticky="w")
            val = tk.Label(
                sf,
                text="—",
                font=("Segoe UI", 10, "bold"),
                fg="#ffffff",
                bg="#16213e",
                anchor="w",
                justify="left",
            )
            val.grid(row=i, column=1, padx=(5, 15), pady=4, sticky="w")
            self.labels[key] = val

        syncf = tk.Frame(root, bg="#16213e", bd=1, relief="solid")
        syncf.pack(padx=20, pady=(0, 10), fill="x")
        tk.Label(syncf, text="Sync Progress", font=("Segoe UI", 10, "bold"), fg="#8899aa", bg="#16213e", anchor="w").pack(anchor="w", padx=15, pady=(8, 2))
        self.sync_text = tk.Label(syncf, text="Chain: —", font=("Segoe UI", 9, "bold"), fg="#ffffff", bg="#16213e", anchor="w")
        self.sync_text.pack(anchor="w", padx=15)
        self.sync_bar = ttk.Progressbar(syncf, orient="horizontal", mode="determinate", maximum=100, style="BTX.Horizontal.TProgressbar")
        self.sync_bar.pack(fill="x", padx=15, pady=(2, 8))
        self.snapshot_text = tk.Label(syncf, text="Snapshot validation: —", font=("Segoe UI", 9), fg="#d7e3ff", bg="#16213e", anchor="w")
        self.snapshot_text.pack(anchor="w", padx=15)
        self.snapshot_bar = ttk.Progressbar(syncf, orient="horizontal", mode="determinate", maximum=100, style="BTXWarn.Horizontal.TProgressbar")
        self.snapshot_bar.pack(fill="x", padx=15, pady=(2, 10))

        bf = tk.Frame(root, bg="#1a1a2e")
        bf.pack(pady=10)

        self.btn_run = tk.Button(
            bf,
            text="▶  START MODE",
            font=("Segoe UI", 12, "bold"),
            fg="white",
            bg="#0f3460",
            activebackground="#1a508b",
            width=18,
            height=2,
            bd=0,
            cursor="hand2",
            command=self.start_guard,
        )
        self.btn_run.grid(row=0, column=0, padx=6, pady=5)

        self.btn_pool = tk.Button(
            bf,
            text="POOL MODE",
            font=("Segoe UI", 11, "bold"),
            fg="white",
            bg="#0b7a53",
            activebackground="#139a6b",
            width=12,
            height=2,
            bd=0,
            cursor="hand2",
            command=lambda: self.switch_mode("pool"),
        )
        self.btn_pool.grid(row=0, column=1, padx=6, pady=5)

        self.btn_solo = tk.Button(
            bf,
            text="SOLO MODE",
            font=("Segoe UI", 11, "bold"),
            fg="white",
            bg="#7d4cc2",
            activebackground="#9466d8",
            width=12,
            height=2,
            bd=0,
            cursor="hand2",
            command=lambda: self.switch_mode("solo"),
        )
        self.btn_solo.grid(row=0, column=2, padx=6, pady=5)

        self.btn_stop = tk.Button(
            bf,
            text="⏹  STOP",
            font=("Segoe UI", 12, "bold"),
            fg="white",
            bg="#e94560",
            activebackground="#c0392b",
            width=12,
            height=2,
            bd=0,
            cursor="hand2",
            command=self.stop_guard,
        )
        self.btn_stop.grid(row=1, column=0, padx=6, pady=5)

        self.btn_update = tk.Button(
            bf,
            text="⬆  UPDATE BTX",
            font=("Segoe UI", 12, "bold"),
            fg="white",
            bg="#248232",
            activebackground="#2aa84a",
            width=16,
            height=2,
            bd=0,
            cursor="hand2",
            command=self.update_btx,
        )
        self.btn_update.grid(row=1, column=1, padx=6, pady=5)

        self.btn_restore = tk.Button(
            bf,
            text="🛠 RESTORE SNAPSHOT",
            font=("Segoe UI", 12, "bold"),
            fg="white",
            bg="#7d4cc2",
            activebackground="#9466d8",
            width=18,
            height=2,
            bd=0,
            cursor="hand2",
            command=self.restore_snapshot,
        )
        self.btn_restore.grid(row=1, column=2, padx=6, pady=5)

        self.log = tk.Text(root, height=7, width=72, bg="#0f1226", fg="#d7e3ff", bd=0, font=("Consolas", 8))
        self.log.pack(padx=20, pady=(5, 8))
        self.log.insert("end", "Logs: D:\\BTX\\btx-pool-guard.log and D:\\BTX\\dexbtx-miner.log\n")
        self.log.config(state="disabled")

        tk.Label(
            root,
            text=f"Payout: {MINING_ADDR[:20]}...{MINING_ADDR[-8:]}",
            font=("Consolas", 8),
            fg="#555577",
            bg="#1a1a2e",
        ).pack(pady=(2, 1))
        tk.Label(root, text=f"Pool: {POOL_LABEL}", font=("Consolas", 8), fg="#555577", bg="#1a1a2e").pack()

        threading.Thread(target=self.poll_status, daemon=True).start()
        if AUTO_START:
            threading.Thread(target=self.autostart_mode, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def set_label(self, key, text):
        self.root.after(0, lambda: self.labels[key].config(text=text))

    def append_log(self, text):
        def _append():
            self.log.config(state="normal")
            self.log.insert("end", text.rstrip() + "\n")
            self.log.see("end")
            self.log.config(state="disabled")
        self.root.after(0, _append)

    def guarded_status(self):
        out, err, rc = wsl_run(f"chmod +x {MODE_SWITCH}; bash {MODE_SWITCH} status", timeout=30)
        data = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
        return data

    def update_sync_progress(self, chain_pct, chain_text, snapshot_pct=None, snapshot_text="Snapshot validation: —"):
        def _update():
            self.sync_bar["value"] = max(0, min(100, chain_pct or 0))
            self.sync_text.config(text=chain_text)
            if snapshot_pct is None:
                self.snapshot_bar["value"] = 0
            else:
                self.snapshot_bar["value"] = max(0, min(100, snapshot_pct))
            self.snapshot_text.config(text=snapshot_text)
        self.root.after(0, _update)

    def sync_progress_from_chainstates(self, chainstates_out, snapshot_base_height):
        try:
            cdata = json.loads(chainstates_out) if chainstates_out else {}
            states = cdata.get("chainstates", [])
            if not states:
                return None, "Snapshot validation: —"
            # Background validation state is the chainstate without snapshot_blockhash.
            validated_states = [s for s in states if not s.get("snapshot_blockhash")]
            active_snapshot_states = [s for s in states if s.get("snapshot_blockhash")]
            base = snapshot_base_height or max((int(s.get("blocks", 0)) for s in active_snapshot_states), default=0)
            if not base:
                return None, "Snapshot validation: —"
            validated_blocks = max((int(s.get("blocks", 0)) for s in validated_states), default=0)
            pct = validated_blocks / base * 100.0 if base else 0.0
            done = not active_snapshot_states or all(bool(s.get("validated")) for s in active_snapshot_states)
            if done or validated_blocks >= base:
                return 100.0, "Snapshot validation: complete"
            return pct, f"Snapshot validation: {validated_blocks:,} / {base:,} ({pct:.1f}%)"
        except Exception:
            return None, "Snapshot validation: —"

    def poll_status(self):
        while self.running:
            try:
                version, _, _ = wsl_run(f"{BTXD} --version 2>/dev/null | head -1", timeout=6)
                self.set_label("version", version.replace("BTX daemon version ", "") if version else "not installed")

                restore_tail, _, _ = wsl_run(f"tail -80 {RESTORE_LOG} 2>/dev/null", timeout=6)
                fast_match = None
                if restore_tail and "Fast snapshot restore complete" not in restore_tail:
                    matches = re.findall(r"waiting for snapshot anchor header: headers=(\d+)/(\d+)", restore_tail)
                    if matches:
                        fast_match = matches[-1]

                info, _, _ = wsl_run(f"{CLI} -datadir={DATADIR} getblockchaininfo", timeout=8)
                if fast_match:
                    h, target = map(int, fast_match)
                    pct = (h / target * 100.0) if target else 0.0
                    self.set_label("node", "⚡ Faststart headers")
                    self.set_label("blocks", f"headers {h:,} / {target:,} ({pct:.1f}%) — snapshot loads next")
                    self.update_sync_progress(pct, f"Chain headers: {h:,} / {target:,} ({pct:.1f}%) — waiting for snapshot anchor")
                elif info:
                    data = json.loads(info)
                    blocks = data.get("blocks", "?")
                    headers = data.get("headers", "?")
                    ibd = data.get("initialblockdownload", True)
                    self.set_label("node", "✅ Running" if not ibd else "⏳ Syncing")
                    self.set_label("blocks", f"{blocks:,} / {headers:,}" if isinstance(blocks, int) else f"{blocks} / {headers}")
                    if isinstance(blocks, int) and isinstance(headers, int) and headers > 0:
                        chain_pct = min(100.0, blocks / headers * 100.0)
                        chain_text = f"Chain sync: {blocks:,} / {headers:,} ({chain_pct:.2f}%)"
                        if not ibd:
                            chain_text += " — tip ready"
                    else:
                        chain_pct = 0.0
                        chain_text = "Chain sync: unknown"
                    snapshot_pct = None
                    snapshot_text = "Snapshot validation: —"
                    snapshot = data.get("snapshot_sync", {}) if isinstance(data, dict) else {}
                    if snapshot.get("active"):
                        chainstates, _, _ = wsl_run(f"{CLI} -datadir={DATADIR} getchainstates", timeout=8)
                        snapshot_pct, snapshot_text = self.sync_progress_from_chainstates(chainstates, snapshot.get("base_height"))
                        if snapshot.get("background_validation_in_progress"):
                            snapshot_text += " — background check"
                    self.update_sync_progress(chain_pct, chain_text, snapshot_pct, snapshot_text)
                else:
                    self.set_label("node", "❌ Offline")
                    self.set_label("blocks", "—")
                    self.update_sync_progress(0, "Chain sync: node offline", None, "Snapshot validation: —")

                wallet_txt = None
                if info:
                    bal, _, _ = wsl_run(f"{CLI} -datadir={DATADIR} -rpcwallet={WALLET} getbalances", timeout=3)
                    if bal:
                        try:
                            bdata = json.loads(bal)
                            mine = bdata.get("mine", {})
                            trusted = mine.get("trusted", 0)
                            immature = mine.get("immature", 0)
                            wallet_txt = f"{trusted:.4f} BTX local"
                            if immature > 0:
                                wallet_txt += f"  (+{immature:.2f} immature)"
                        except Exception:
                            wallet_txt = None
                # In pool mode btxd is normally not required/running, so local
                # wallet RPC can be offline. Always fall back to the public
                # BTXplorer balance for the configured payout address.
                if wallet_txt:
                    self.set_label("wallet", wallet_txt)
                else:
                    self.set_label("wallet", explorer_balance_text())

                status = self.guarded_status()
                mode = status.get("mode", "pool")
                guard_running = status.get("guard_running") == "yes" if mode == "pool" else status.get("solo_guard_running") == "yes"
                miner_running = status.get("miner_running") == "yes" if mode == "pool" else status.get("solo_miner_running") == "yes"
                self.set_label("mode", "POOL" if mode == "pool" else "SOLO")
                self.set_label("guard", "🛡 Running" if guard_running else "Stopped")
                self.set_label("mining", ("⛏ Pool mining active" if mode == "pool" else "⛏ Solo loop active") if miner_running else "⏸ Stopped")
                if mode == "pool":
                    self.set_label("hashrate", status.get("hashrate", "—"))
                else:
                    solo_hr = status.get("solo_hashrate", "—")
                    share = status.get("solo_share_pct")
                    blocks_day = status.get("solo_est_blocks_per_day")
                    if share and blocks_day:
                        solo_hr += f"  ·  ~{share}% of net  ·  ~{blocks_day} blocks/day"
                    self.set_label("hashrate", solo_hr)
                if guard_running or miner_running:
                    self.root.after(0, lambda: self.btn_run.config(text="🛡  MODE ACTIVE", bg="#0b7a53"))
                else:
                    self.root.after(0, lambda: self.btn_run.config(text="▶  START MODE", bg="#0f3460"))

                gpu, _, _ = wsl_run("nvidia-smi --query-gpu=utilization.gpu,temperature.gpu,power.draw --format=csv,noheader,nounits | head -1", timeout=6)
                if gpu:
                    parts = [p.strip() for p in gpu.split(",")]
                    if len(parts) >= 3:
                        self.set_label("gpu", f"RTX 3090 — {parts[0]}% · {parts[1]}°C · {parts[2]}W")
                    else:
                        self.set_label("gpu", gpu)
                else:
                    self.set_label("gpu", "—")
                if mode == "pool":
                    self.set_label("pool", "minebtx.com — PPLNS" if miner_running else "Disconnected")
                else:
                    blocks_24h = status.get("solo_blocks_24h")
                    rewards_24h = status.get("solo_rewards_24h")
                    last_win = status.get("solo_last_win")
                    if blocks_24h is not None:
                        solo_txt = f"⛏ {blocks_24h} blocks / {rewards_24h or 0} BTX (24h)"
                        if last_win and last_win != "none in window":
                            solo_txt += f"  ·  last: {last_win}"
                        self.set_label("pool", solo_txt)
                    else:
                        self.set_label("pool", "Solo local node")

                log_path = RESTORE_LOG if self.restoring else (SOLO_LOG if mode == "solo" else GUARD_LOG)
                tail, _, _ = wsl_run(f"tail -12 {log_path} 2>/dev/null", timeout=6)
                if tail:
                    self.root.after(0, lambda t=tail: (self.log.config(state="normal"), self.log.delete("2.0", "end"), self.log.insert("end", t + "\n"), self.log.config(state="disabled")))
            except Exception as e:
                self.append_log(f"status error: {e}")
            time.sleep(5)

    def autostart_mode(self):
        """On GUI launch, start the saved mode (pool/solo + its node) if its guard is not already running."""
        status = self.guarded_status()
        mode = status.get("mode", "pool")
        running_key = "guard_running" if mode == "pool" else "solo_guard_running"
        if status.get(running_key) == "yes":
            self.append_log(f"Auto-start: {mode} guard already running.")
            return
        self.append_log(f"Auto-start: launching saved mode '{mode}'...")
        self.root.after(0, self.start_guard)

    def start_guard(self):
        self.btn_run.config(text="⏳ Starting...", state="disabled")
        threading.Thread(target=self._start_guard, daemon=True).start()

    def _start_guard(self):
        # Read the mode straight from the mode file: running the full status
        # query here can exceed the timeout when the node is busy (e.g. during
        # snapshot background validation), killing the command before the
        # guard is ever launched.
        cmd = (
            f"chmod +x {MODE_SWITCH} {GUARD} {SOLO_GUARD} {UPDATE}; "
            f"mode=$(. /mnt/d/BTX/btx-mining-mode.conf 2>/dev/null; echo \"${{BTX_MINING_MODE:-pool}}\"); "
            f"echo \"Starting selected BTX mining mode: $mode\"; "
            f"bash {MODE_SWITCH} $mode 2>&1"
        )
        out, err, rc = wsl_run(cmd, timeout=90)
        if rc == 0:
            self.append_log(out or "Mining mode start requested; no status output yet.")
        else:
            self.append_log(f"Start failed with exit {rc}:\n{err or out}")
        self.root.after(0, lambda: self.btn_run.config(state="normal"))

    def stop_guard(self):
        self.btn_stop.config(text="⏳ Stopping...", state="disabled")
        threading.Thread(target=self._stop_guard, daemon=True).start()

    def _stop_guard(self):
        out, err, rc = wsl_run(f"chmod +x {MODE_SWITCH}; bash {MODE_SWITCH} stop", timeout=60)
        self.append_log(out or err or "Stop requested.")
        self.root.after(0, lambda: self.btn_stop.config(text="⏹  STOP", state="normal"))

    def switch_mode(self, mode):
        self.btn_pool.config(state="disabled")
        self.btn_solo.config(state="disabled")
        threading.Thread(target=lambda: self._switch_mode(mode), daemon=True).start()

    def _switch_mode(self, mode):
        out, err, rc = wsl_run(f"chmod +x {MODE_SWITCH}; bash {MODE_SWITCH} {mode}", timeout=90)
        if rc == 0:
            self.append_log(out or f"Switched to {mode} mode.")
        else:
            self.append_log(f"Switch to {mode} failed with exit {rc}:\n{err or out}")
        self.root.after(0, lambda: (self.btn_pool.config(state="normal"), self.btn_solo.config(state="normal")))

    def update_btx(self):
        if self.updating:
            return
        self.updating = True
        self.btn_update.config(text="⏳ Updating...", state="disabled")
        threading.Thread(target=self._update_btx, daemon=True).start()

    def _update_btx(self):
        self.append_log("Updating BTX to the latest GitHub release...")
        out, err, rc = wsl_run(f"chmod +x {UPDATE}; bash {UPDATE}", timeout=900)
        self.append_log(out[-1800:] if out else err or "Update finished.")
        if rc == 0:
            self.append_log("BTX update complete. Press RUN + GUARD to mine with the updated node.")
        else:
            self.append_log(f"BTX update failed with exit {rc}.")
        self.updating = False
        self.root.after(0, lambda: self.btn_update.config(text="⬆  UPDATE BTX", state="normal"))

    def restore_snapshot(self):
        if self.restoring:
            return
        self.restoring = True
        self.btn_restore.config(text="⏳ Faststarting...", state="disabled")
        self.append_log("Fast-start restoring with the latest BTX release snapshot, using the EasyBTX/BTX faststart flow. Watch this box for header/download/load progress...")
        threading.Thread(target=self._restore_snapshot, daemon=True).start()

    def _restore_snapshot(self):
        out, err, rc = wsl_run(f"chmod +x {RESTORE}; bash {RESTORE}", timeout=7200)
        self.append_log(out[-2500:] if out else err or "Restore finished.")
        if rc == 0:
            self.append_log("Fast snapshot restore complete. Now press RUN + GUARD to start pool mining.")
        else:
            self.append_log(f"Fast snapshot restore failed with exit {rc}. See D:\\BTX\\btx-restore-snapshot.log")
        self.restoring = False
        self.root.after(0, lambda: self.btn_restore.config(text="🛠 RESTORE SNAPSHOT", state="normal"))

    def on_close(self):
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = BTXControl(root)
    root.mainloop()
