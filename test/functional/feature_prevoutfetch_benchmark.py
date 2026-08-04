#!/usr/bin/env python3
"""End-to-end benchmark for persisted prevout fetching.

This is intentionally not part of the functional test runner. It creates a
funding block with many independent UTXOs, restarts serial and parallel nodes
to clear their coins and LevelDB caches, and submits identical spend-heavy
blocks to each node. The operating system page cache is not cleared.
"""

import json
import re
import statistics
import time
from pathlib import Path

from test_framework.blocktools import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


CONNECT_RE = re.compile(r"- Connect total: ([0-9.]+)ms")


class PrevoutFetchBenchmark(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--trials", type=int, default=6)
        parser.add_argument("--inputs-per-block", type=int, default=50_000)
        parser.add_argument("--dbcache", type=int, default=4)
        parser.add_argument("--fetch-threads", type=int, default=8)
        parser.add_argument(
            "--scatter-prevouts",
            action="store_true",
            help="Fan funding outputs into distinct transaction IDs before benchmarking",
        )
        parser.add_argument("--output", type=Path)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            self.node_args(0),
            self.node_args(self.options.fetch_threads),
            self.node_args(0),
        ]

    @staticmethod
    def log_size(node):
        return node.debug_log_path.stat().st_size

    @staticmethod
    def connect_ms_since(node, offset):
        with node.debug_log_path.open("r", encoding="utf-8", errors="replace") as log:
            log.seek(offset)
            matches = CONNECT_RE.findall(log.read())
        if not matches:
            raise AssertionError(f"No Connect total benchmark line for node {node.index}")
        return float(matches[-1])

    def node_args(self, threads):
        return [
            f"-dbcache={self.options.dbcache}",
            "-par=1",
            "-debug=bench",
            "-persistmempool=0",
            f"-prevoutfetchthreads={threads}",
        ]

    def restart_target(self, index, threads):
        self.restart_node(index, extra_args=self.node_args(threads))

    def run_test(self):
        trials = self.options.trials
        inputs_per_block = self.options.inputs_per_block
        fetch_threads = self.options.fetch_threads
        if trials <= 0 or inputs_per_block <= 0 or fetch_threads <= 0:
            raise ValueError("trials, inputs-per-block, and fetch-threads must be positive")
        total_outputs = trials * inputs_per_block
        generator, parallel, serial = self.nodes

        wallet = MiniWallet(generator, mode=MiniWalletMode.RAW_OP_TRUE)
        self.log.info("Generating mature funding chain")
        self.generatetodescriptor(generator, 101, wallet.get_descriptor())
        wallet.rescan_utxos()

        funding = wallet.create_self_transfer_multi(
            utxos_to_spend=[wallet.get_utxo(confirmed_only=True)],
            num_outputs=total_outputs,
            amount_per_output=1000,
        )
        self.log.info(f"Mining {total_outputs} persisted benchmark UTXOs")
        funding_result = self.generateblock(generator, wallet.get_descriptor(), [funding["hex"]])
        assert_equal(generator.getbestblockhash(), funding_result["hash"])

        benchmark_utxos = [
            {
                "txid": funding["txid"],
                "vout": output_index,
                "value": 1000 / COIN,
            }
            for output_index in range(total_outputs)
        ]
        if self.options.scatter_prevouts:
            self.log.info(f"Scattering {total_outputs} prevouts across distinct transaction IDs")
            scatter_hexes = []
            scattered_utxos = []
            for utxo in benchmark_utxos:
                scatter = wallet.create_self_transfer_multi(
                    utxos_to_spend=[utxo],
                    num_outputs=1,
                    amount_per_output=999,
                )
                scatter_hexes.append(scatter["hex"])
                scattered_utxos.append({
                    "txid": scatter["txid"],
                    "vout": 0,
                    "value": 999 / COIN,
                })
            scatter_result = self.generateblock(generator, wallet.get_descriptor(), scatter_hexes)
            assert_equal(generator.getbestblockhash(), scatter_result["hash"])
            benchmark_utxos = scattered_utxos

        self.disconnect_nodes(1, 0)
        self.disconnect_nodes(2, 1)

        serial_connect = []
        parallel_connect = []
        serial_rpc = []
        parallel_rpc = []

        for trial in range(trials):
            self.log.info(f"Building spend-heavy block {trial + 1}/{trials}")
            start = trial * inputs_per_block
            tx_hexes = []
            for utxo in benchmark_utxos[start:start + inputs_per_block]:
                spend = wallet.create_self_transfer_multi(
                    utxos_to_spend=[utxo],
                    num_outputs=1,
                    amount_per_output=int(round(utxo["value"] * COIN)) - 1,
                )
                tx_hexes.append(spend["hex"])

            generated = self.generateblock(generator, wallet.get_descriptor(), tx_hexes, sync_fun=self.no_op)
            block_hash = generated["hash"]
            block_hex = generator.getblock(block_hash, 0)

            # Restart immediately before submission so CCoinsViewCache and the
            # LevelDB block cache begin empty on both target nodes.
            self.restart_target(1, fetch_threads)
            self.restart_target(2, 0)
            parallel_offset = self.log_size(parallel)
            serial_offset = self.log_size(serial)

            # Alternate ordering to avoid consistently favoring one mode.
            order = [(parallel, parallel_rpc), (serial, serial_rpc)]
            if trial % 2:
                order.reverse()
            for node, samples in order:
                before = time.perf_counter()
                result = node.submitblock(block_hex)
                samples.append((time.perf_counter() - before) * 1000)
                assert_equal(result, None)
                assert_equal(node.getbestblockhash(), block_hash)

            parallel_connect.append(self.connect_ms_since(parallel, parallel_offset))
            serial_connect.append(self.connect_ms_since(serial, serial_offset))
            self.log.info(
                f"trial={trial + 1} connect_ms serial={serial_connect[-1]:.2f} "
                f"parallel={parallel_connect[-1]:.2f}"
            )

        result = {
            "trials": trials,
            "inputs_per_block": inputs_per_block,
            "dbcache_mib": self.options.dbcache,
            "script_threads": 1,
            "parallel_fetch_threads": fetch_threads,
            "scattered_prevouts": self.options.scatter_prevouts,
            "serial_connect_ms": serial_connect,
            "parallel_connect_ms": parallel_connect,
            "serial_rpc_ms": serial_rpc,
            "parallel_rpc_ms": parallel_rpc,
            "serial_connect_median_ms": statistics.median(serial_connect),
            "parallel_connect_median_ms": statistics.median(parallel_connect),
            "connect_speedup": statistics.median(serial_connect) / statistics.median(parallel_connect),
            "identical_tip": parallel.getbestblockhash() == serial.getbestblockhash() == generator.getbestblockhash(),
        }
        result_json = json.dumps(result, indent=2, sort_keys=True)
        self.log.info("RESULT " + result_json)
        if self.options.output:
            self.options.output.write_text(result_json + "\n", encoding="utf-8")


if __name__ == "__main__":
    PrevoutFetchBenchmark(__file__).main()
