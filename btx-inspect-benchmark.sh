#!/usr/bin/env bash
D=/home/eldian/.local/lib/python3.12/site-packages/dexbtx_miner
echo "=== __main__: how to invoke (subcommands/args) ==="
grep -nE 'add_parser|add_argument|benchmark|set_defaults|argv|def main|ArgumentParser' "$D/__main__.py" | head -30
echo "=== benchmark.py sweep ranges + measurement ==="
grep -nE 'def run_benchmark|def run|def main|def _solve|range\(|BATCHES|THREADS|WORKERS|PREFETCH|candidates|getblocktemplate|seed_a|--max-seconds|max_seconds|elapsed|hashes|rate|nonces' "$D/benchmark.py" | head -50
echo "=== benchmark.py top (imports + how it gets a job) ==="
sed -n '1,60p' "$D/benchmark.py"
