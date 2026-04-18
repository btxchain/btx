#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Strip MatMul matrix payloads from v1 block files.

In BTX v1, matrices are derived from seeds stored in the header (64 bytes).
However, early versions incorrectly stored the full 512x512 matrices in each
block body (~2MB per block). This tool strips that redundant data to reduce
blockchain storage by ~99%.

Usage:
    1. Stop the btxd node
    2. Back up your blocks directory
    3. Run: python3 strip-matmul-payloads.py /path/to/datadir/blocks
    4. Restart the node with -reindex

The tool creates new stripped block files in a 'stripped' subdirectory.
After verification, replace the original files with the stripped versions.
"""

import os
import sys
import struct
import hashlib
from pathlib import Path
from typing import BinaryIO, Tuple, Optional

# BTX network magic bytes (mainnet)
NETWORK_MAGIC = bytes.fromhex("d9b4bef9")  # Bitcoin mainnet magic; adjust for BTX

# Block header size for BTX MatMul PoW
BTX_HEADER_SIZE = 182


def read_varint(f: BinaryIO) -> Tuple[int, int]:
    """Read a Bitcoin-style variable-length integer. Returns (value, bytes_read)."""
    first_byte = f.read(1)
    if not first_byte:
        raise EOFError("Unexpected end of file reading varint")
    n = first_byte[0]
    if n < 0xFD:
        return n, 1
    elif n == 0xFD:
        return struct.unpack('<H', f.read(2))[0], 3
    elif n == 0xFE:
        return struct.unpack('<I', f.read(4))[0], 5
    else:
        return struct.unpack('<Q', f.read(8))[0], 9


def write_varint(value: int) -> bytes:
    """Encode a Bitcoin-style variable-length integer."""
    if value < 0xFD:
        return bytes([value])
    elif value <= 0xFFFF:
        return bytes([0xFD]) + struct.pack('<H', value)
    elif value <= 0xFFFFFFFF:
        return bytes([0xFE]) + struct.pack('<I', value)
    else:
        return bytes([0xFF]) + struct.pack('<Q', value)


def read_vector(f: BinaryIO) -> Tuple[bytes, int]:
    """Read a serialized vector (length-prefixed). Returns (data, total_bytes_read)."""
    length, varint_size = read_varint(f)
    data = f.read(length)
    if len(data) != length:
        raise EOFError(f"Expected {length} bytes, got {len(data)}")
    return data, varint_size + length


def skip_transaction(f: BinaryIO) -> int:
    """Skip over a serialized transaction. Returns bytes skipped."""
    start_pos = f.tell()

    # Version (4 bytes)
    version_data = f.read(4)
    if len(version_data) < 4:
        raise EOFError("Unexpected end of file in transaction")

    # Check for witness marker
    marker = f.read(1)
    if not marker:
        raise EOFError("Unexpected end of file in transaction")

    has_witness = False
    if marker[0] == 0x00:
        flag = f.read(1)
        if flag and flag[0] != 0x00:
            has_witness = True
        else:
            # Not a witness tx, rewind
            f.seek(-2, 1)
    else:
        f.seek(-1, 1)

    # Input count
    input_count, _ = read_varint(f)

    # Skip inputs
    for _ in range(input_count):
        f.read(32)  # prev txid
        f.read(4)   # prev vout
        script_len, _ = read_varint(f)
        f.read(script_len)  # scriptSig
        f.read(4)   # sequence

    # Output count
    output_count, _ = read_varint(f)

    # Skip outputs
    for _ in range(output_count):
        f.read(8)  # value
        script_len, _ = read_varint(f)
        f.read(script_len)  # scriptPubKey

    # Skip witness data if present
    if has_witness:
        for _ in range(input_count):
            witness_count, _ = read_varint(f)
            for _ in range(witness_count):
                witness_len, _ = read_varint(f)
                f.read(witness_len)

    # Locktime
    f.read(4)

    return f.tell() - start_pos


def process_block_file(input_path: Path, output_path: Path) -> Tuple[int, int, int]:
    """
    Process a single block file, stripping matrix payloads.
    Returns (blocks_processed, bytes_saved, errors).
    """
    blocks_processed = 0
    bytes_saved = 0
    errors = 0

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        while True:
            # Read magic bytes
            magic = f_in.read(4)
            if len(magic) == 0:
                break  # EOF
            if len(magic) < 4:
                print(f"  Warning: Truncated magic bytes at end of file")
                break

            # Read block size
            size_data = f_in.read(4)
            if len(size_data) < 4:
                print(f"  Warning: Truncated size at end of file")
                break
            block_size = struct.unpack('<I', size_data)[0]

            # Read entire block
            block_data = f_in.read(block_size)
            if len(block_data) < block_size:
                print(f"  Warning: Truncated block data at end of file")
                break

            try:
                # Parse and strip the block
                stripped_block = strip_matrix_payload(block_data)
                new_size = len(stripped_block)

                # Write stripped block
                f_out.write(magic)
                f_out.write(struct.pack('<I', new_size))
                f_out.write(stripped_block)

                bytes_saved += block_size - new_size
                blocks_processed += 1

            except Exception as e:
                # On error, write original block unchanged
                print(f"  Warning: Error processing block {blocks_processed}: {e}")
                f_out.write(magic)
                f_out.write(size_data)
                f_out.write(block_data)
                errors += 1
                blocks_processed += 1

    return blocks_processed, bytes_saved, errors


def strip_matrix_payload(block_data: bytes) -> bytes:
    """
    Strip matrix_a_data and matrix_b_data from a serialized block.
    Returns the stripped block data.
    """
    # Block structure:
    # - CBlockHeader (182 bytes)
    # - vtx (vector of transactions)
    # - matrix_a_data (vector<uint32_t>) -- only if vtx non-empty
    # - matrix_b_data (vector<uint32_t>) -- only if vtx non-empty

    if len(block_data) < BTX_HEADER_SIZE:
        raise ValueError(f"Block too small: {len(block_data)} bytes")

    # Extract header
    header = block_data[:BTX_HEADER_SIZE]

    # Parse transactions
    pos = BTX_HEADER_SIZE
    tx_count, varint_size = parse_varint(block_data, pos)
    pos += varint_size

    if tx_count == 0:
        # No transactions = header-only relay, no matrix payload
        return block_data

    # Skip over all transactions
    for _ in range(tx_count):
        tx_size = get_transaction_size(block_data, pos)
        pos += tx_size

    # Everything from header to end of transactions is kept
    core_data = block_data[:pos]

    # Remaining bytes are matrix_a_data and matrix_b_data vectors.
    # We replace them with two empty vectors (each encoded as varint 0).
    remaining = block_data[pos:]

    # Already stripped or no trailing payload at all -- return unchanged.
    if remaining == b'\x00\x00' or len(remaining) == 0:
        if len(remaining) == 0:
            # Block is missing trailing vectors entirely; append empty ones
            # so the serialized format matches what C++ expects.
            return core_data + b'\x00\x00'
        return block_data

    # Parse and validate the two vectors to determine bytes to strip.
    try:
        vec_a_len, va_size = parse_varint(block_data, pos)
        vec_a_bytes = va_size + vec_a_len * 4  # uint32_t = 4 bytes each

        pos2 = pos + vec_a_bytes
        if pos2 > len(block_data):
            raise ValueError(f"matrix_a vector extends past block boundary "
                             f"(need {vec_a_bytes} bytes at offset {pos}, "
                             f"block is {len(block_data)} bytes)")

        if pos2 < len(block_data):
            vec_b_len, vb_size = parse_varint(block_data, pos2)
            vec_b_bytes = vb_size + vec_b_len * 4
            if pos2 + vec_b_bytes > len(block_data):
                raise ValueError(f"matrix_b vector extends past block boundary")
        else:
            vec_b_bytes = 0
    except (ValueError, struct.error) as e:
        raise ValueError(f"Failed to parse matrix payload vectors: {e}") from e

    # Return core data + two empty vectors
    return core_data + b'\x00\x00'


def parse_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Parse a varint from bytes at position. Returns (value, bytes_consumed)."""
    if pos >= len(data):
        return 0, 0
    n = data[pos]
    if n < 0xFD:
        return n, 1
    elif n == 0xFD:
        return struct.unpack('<H', data[pos+1:pos+3])[0], 3
    elif n == 0xFE:
        return struct.unpack('<I', data[pos+1:pos+5])[0], 5
    else:
        return struct.unpack('<Q', data[pos+1:pos+9])[0], 9


def get_transaction_size(data: bytes, start: int) -> int:
    """Calculate the size of a serialized transaction starting at position."""
    pos = start

    # Version (4 bytes)
    pos += 4

    # Check for witness marker
    has_witness = False
    if data[pos] == 0x00 and pos + 1 < len(data) and data[pos + 1] != 0x00:
        has_witness = True
        pos += 2  # Skip marker and flag

    # Input count
    input_count, varint_size = parse_varint(data, pos)
    pos += varint_size

    # Skip inputs
    for _ in range(input_count):
        pos += 32  # prev txid
        pos += 4   # prev vout
        script_len, vs = parse_varint(data, pos)
        pos += vs + script_len  # scriptSig
        pos += 4   # sequence

    # Output count
    output_count, varint_size = parse_varint(data, pos)
    pos += varint_size

    # Skip outputs
    for _ in range(output_count):
        pos += 8  # value
        script_len, vs = parse_varint(data, pos)
        pos += vs + script_len  # scriptPubKey

    # Skip witness data if present
    if has_witness:
        for _ in range(input_count):
            witness_count, vs = parse_varint(data, pos)
            pos += vs
            for _ in range(witness_count):
                witness_len, vs = parse_varint(data, pos)
                pos += vs + witness_len

    # Locktime
    pos += 4

    return pos - start


def main():
    if len(sys.argv) < 2:
        print("Usage: strip-matmul-payloads.py <blocks_directory>")
        print("")
        print("This tool strips redundant matrix payload data from BTX v1 blocks.")
        print("It creates stripped files in a 'stripped' subdirectory.")
        print("")
        print("IMPORTANT: Stop the node before running this tool!")
        sys.exit(1)

    blocks_dir = Path(sys.argv[1])
    if not blocks_dir.is_dir():
        print(f"Error: {blocks_dir} is not a directory")
        sys.exit(1)

    # Create output directory
    output_dir = blocks_dir / "stripped"
    output_dir.mkdir(exist_ok=True)

    # Find all blk*.dat files
    blk_files = sorted(blocks_dir.glob("blk*.dat"))
    if not blk_files:
        print(f"No blk*.dat files found in {blocks_dir}")
        sys.exit(1)

    print(f"Found {len(blk_files)} block files")
    print(f"Output directory: {output_dir}")
    print("")

    total_blocks = 0
    total_saved = 0
    total_errors = 0

    for blk_file in blk_files:
        output_file = output_dir / blk_file.name
        print(f"Processing {blk_file.name}...")

        blocks, saved, errors = process_block_file(blk_file, output_file)
        total_blocks += blocks
        total_saved += saved
        total_errors += errors

        saved_mb = saved / (1024 * 1024)
        print(f"  {blocks} blocks, {saved_mb:.2f} MB saved, {errors} errors")

    print("")
    print("=" * 60)
    print(f"Total blocks processed: {total_blocks}")
    print(f"Total space saved: {total_saved / (1024**3):.2f} GB")
    print(f"Total errors: {total_errors}")
    print("")
    print("Next steps:")
    print(f"  1. Verify the stripped files in {output_dir}")
    print(f"  2. Back up your original blocks directory")
    print(f"  3. Replace original blk*.dat files with stripped versions")
    print(f"  4. Delete the rev*.dat files (they will be regenerated)")
    print(f"  5. Restart btxd with -reindex")


if __name__ == "__main__":
    main()
