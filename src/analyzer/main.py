#!/usr/bin/env python3
"""
Sherlock Chain Analyzer — main.py
Parses Bitcoin blk*.dat + rev*.dat files and applies chain analysis heuristics.

Usage: python3 main.py <blk.dat> <rev.dat> <xor.dat>
"""

import sys
import os
import json
import struct
import hashlib
import math
from pathlib import Path
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAGIC_MAINNET = 0xD9B4BEF9   # bytes: F9 BE B4 D9 in LE
HEURISTIC_IDS = ["cioh", "change_detection", "address_reuse",
                 "coinjoin", "consolidation", "self_transfer", "round_number_payment"]
VALID_CLASSIFICATIONS = {"simple_payment", "consolidation", "coinjoin",
                         "self_transfer", "batch_payment", "unknown"}

# ---------------------------------------------------------------------------
# Error output
# ---------------------------------------------------------------------------
def error_json(code, message):
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))


# ---------------------------------------------------------------------------
# Varint helpers
# ---------------------------------------------------------------------------
def read_compact_size(d, p):
    """Bitcoin CompactSize VarInt (used in transactions)"""
    b = d[p]
    if b < 0xfd:
        return b, p + 1
    elif b == 0xfd:
        return struct.unpack_from('<H', d, p + 1)[0], p + 3
    elif b == 0xfe:
        return struct.unpack_from('<I', d, p + 1)[0], p + 5
    else:
        return struct.unpack_from('<Q', d, p + 1)[0], p + 9


def read_core_varint(d, p):
    """Bitcoin Core custom VARINT (used in coin/undo data, max 9 bytes)"""
    n = 0
    for _ in range(9):
        if p >= len(d):
            raise ValueError(f"Core VARINT: past end at {p}")
        b = d[p]; p += 1
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            n += 1
        else:
            return n, p
    raise ValueError("Core VARINT: too many bytes")


# ---------------------------------------------------------------------------
# XOR decoding (all-zero key = identity)
# ---------------------------------------------------------------------------
def xor_decode(data, key):
    if not key or all(b == 0 for b in key):
        return data
    result = bytearray(data)
    klen = len(key)
    for i in range(len(result)):
        result[i] ^= key[i % klen]
    return bytes(result)


# ---------------------------------------------------------------------------
# Script analysis
# ---------------------------------------------------------------------------
def detect_script_type(script: bytes) -> str:
    n = len(script)
    if n == 0:
        return 'empty'
    if script[0] == 0x6a:
        return 'op_return'
    if n == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[-2] == 0x88 and script[-1] == 0xac:
        return 'p2pkh'
    if n == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[-1] == 0x87:
        return 'p2sh'
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return 'p2wpkh'
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return 'p2wsh'
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return 'p2tr'
    if (n == 35 or n == 67) and script[-1] == 0xac:
        return 'p2pk'
    return 'unknown'


def script_hash(script: bytes) -> str:
    """Extract key/hash identifier for reuse detection"""
    stype = detect_script_type(script)
    if stype == 'p2pkh':
        return script[3:23].hex()
    if stype == 'p2sh':
        return script[2:22].hex()
    if stype == 'p2wpkh':
        return script[2:22].hex()
    if stype == 'p2wsh':
        return script[2:34].hex()
    if stype == 'p2tr':
        return script[2:34].hex()
    return ''


def infer_input_type_from_spending(script_sig: bytes, witness: list) -> str:
    """Infer input UTXO script type from how it's spent"""
    if len(script_sig) == 0 and witness:
        if len(witness) == 2:
            # P2WPKH: witness = [sig, pubkey]
            if len(witness[1]) in (33, 65):
                return 'p2wpkh'
        # P2TR key-path: witness = [sig] (64 or 65 bytes)
        if len(witness) == 1 and len(witness[0]) in (64, 65):
            return 'p2tr'
        return 'p2wsh'
    if len(script_sig) > 0:
        # P2SH-P2WPKH: scriptSig = push(OP_0 <20-byte hash>)
        if len(script_sig) == 23 and script_sig[1] == 0x00 and script_sig[2] == 0x14:
            return 'p2sh'
        # P2PKH: scriptSig ends with pubkey push
        if len(script_sig) >= 107:
            return 'p2pkh'
        if len(script_sig) >= 71:
            return 'p2pkh'
    return 'unknown'


# ---------------------------------------------------------------------------
# Transaction parsing
# ---------------------------------------------------------------------------
def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_transaction(data: bytes, pos: int):
    """
    Parse a transaction from data[pos:].
    Returns (tx_dict, end_pos).
    """
    start = pos

    version = struct.unpack_from('<i', data, pos)[0]
    pos += 4

    # SegWit marker check
    segwit = False
    if pos + 1 < len(data) and data[pos] == 0x00 and data[pos + 1] == 0x01:
        segwit = True
        pos += 2

    inputs_start = pos

    # Inputs
    nin, pos = read_compact_size(data, pos)
    inputs = []
    for _ in range(nin):
        txid_bytes = data[pos:pos + 32]
        txid_le = txid_bytes[::-1].hex()
        pos += 32
        vout = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        sig_len, pos = read_compact_size(data, pos)
        script_sig = data[pos:pos + sig_len]
        pos += sig_len
        sequence = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        inputs.append({
            'txid': txid_le,
            'vout': vout,
            'script_sig': script_sig,
            'sequence': sequence,
            'witness': [],
        })

    # Outputs
    nout, pos = read_compact_size(data, pos)
    outputs = []
    for _ in range(nout):
        value = struct.unpack_from('<q', data, pos)[0]
        pos += 8
        pk_len, pos = read_compact_size(data, pos)
        script_pubkey = data[pos:pos + pk_len]
        pos += pk_len
        outputs.append({
            'value': value,
            'script_pubkey': script_pubkey,
            'script_type': detect_script_type(script_pubkey),
        })

    outputs_end = pos  # Position before witness data

    # Witness data
    if segwit:
        for inp in inputs:
            item_count, pos = read_compact_size(data, pos)
            items = []
            for _ in range(item_count):
                item_len, pos = read_compact_size(data, pos)
                items.append(data[pos:pos + item_len])
                pos += item_len
            inp['witness'] = items

    locktime_pos = pos
    locktime = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    end = pos

    # Compute txid (non-witness serialization)
    if segwit:
        # Non-witness: version + inputs + outputs + locktime (no marker/flag, no witness)
        non_witness = (
            data[start:start + 4] +           # version
            data[inputs_start:outputs_end] +  # inputs varint + inputs + outputs varint + outputs
            data[locktime_pos:end]             # locktime
        )
    else:
        non_witness = data[start:end]

    txid = double_sha256(non_witness)[::-1].hex()

    # Is coinbase?
    is_coinbase = (
        nin == 1 and
        inputs[0]['txid'] == '0' * 64 and
        inputs[0]['vout'] == 0xFFFFFFFF
    )

    # Infer input types from spending data
    for inp in inputs:
        inp['inferred_type'] = infer_input_type_from_spending(
            inp['script_sig'], inp['witness']
        )

    return {
        'txid': txid,
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
        'segwit': segwit,
        'is_coinbase': is_coinbase,
        'raw_size': end - start,
    }, end


# ---------------------------------------------------------------------------
# Block file parsing (blk*.dat)
# ---------------------------------------------------------------------------
def extract_block_height(coinbase_script: bytes) -> int:
    """BIP34: extract block height from coinbase scriptSig"""
    if len(coinbase_script) < 2:
        return 0
    n = coinbase_script[0]
    if n < 1 or n > 4 or len(coinbase_script) < n + 1:
        return 0
    return int.from_bytes(coinbase_script[1:1 + n], 'little')


def parse_blk_file(filepath: str, xor_key: bytes):
    """
    Parse all blocks from a blk*.dat file.
    Returns list of block dicts.
    """
    with open(filepath, 'rb') as f:
        raw = f.read()
    data = xor_decode(raw, xor_key)
    blocks = []
    pos = 0

    while pos + 8 <= len(data):
        # Find magic
        if struct.unpack_from('<I', data, pos)[0] != MAGIC_MAINNET:
            pos += 1
            continue

        size = struct.unpack_from('<I', data, pos + 4)[0]
        block_start = pos + 8
        if block_start + size > len(data):
            break

        try:
            block = _parse_block(data, block_start, size)
            blocks.append(block)
        except Exception:
            pass  # Skip malformed blocks

        pos = block_start + size

    return blocks


def _parse_block(data: bytes, start: int, size: int):
    """Parse one block from data[start:start+size]"""
    # 80-byte header
    header = data[start:start + 80]
    block_hash = double_sha256(header)[::-1].hex()
    version, prev_hash, merkle, timestamp, bits, nonce = struct.unpack_from('<I32s32sIII', header)

    pos = start + 80
    tx_count, pos = read_compact_size(data, pos)

    transactions = []
    for i in range(tx_count):
        tx, pos = parse_transaction(data, pos)
        transactions.append(tx)

    # Extract block height from coinbase scriptSig
    height = 0
    if transactions and transactions[0]['is_coinbase']:
        cb_script = transactions[0]['inputs'][0]['script_sig']
        height = extract_block_height(cb_script)

    return {
        'block_hash': block_hash,
        'block_height': height,
        'timestamp': timestamp,
        'transactions': transactions,
        'tx_count': tx_count,
    }


# ---------------------------------------------------------------------------
# Rev file parsing (rev*.dat) — undo data for fee calculation
# ---------------------------------------------------------------------------
def decompress_amount(x: int) -> int:
    """Bitcoin Core CompressAmount inverse"""
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = x % 9 + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    return n * (10 ** e)


def skip_compressed_script(d: bytes, p: int) -> int:
    """Skip a compressed script in the undo data, return new position"""
    nSize, p = read_core_varint(d, p)
    if nSize == 0 or nSize == 1:
        return p + 20
    elif nSize in (2, 3, 4, 5):
        return p + 32
    else:
        return p + (nSize - 6)


def parse_coin_value(d: bytes, p: int):
    """Parse a Coin from rev data, return (value_sats, script_type, new_pos)"""
    code, p = read_core_varint(d, p)
    val_compressed, p = read_core_varint(d, p)
    value = decompress_amount(val_compressed)

    # Parse compressed script
    nSize, p2 = read_core_varint(d, p)
    if nSize == 0:
        stype = 'p2pkh'; p = p2 + 20
    elif nSize == 1:
        stype = 'p2sh'; p = p2 + 20
    elif nSize in (2, 3):
        stype = 'p2pk'; p = p2 + 32
    elif nSize in (4, 5):
        stype = 'p2pk'; p = p2 + 32
    else:
        raw_len = nSize - 6
        raw_script = d[p2:p2 + raw_len]
        stype = detect_script_type(raw_script)
        p = p2 + raw_len

    return value, stype, p


def parse_rev_file(filepath: str, xor_key: bytes):
    """
    Parse undo data from rev*.dat file.
    Returns list of block_undo dicts:
      { 'tx_undos': [ { 'input_values': [sats, ...] }, ... ] }
    Records: [magic:4][size:4][CBlockUndo:size bytes][block_hash:32]
    """
    with open(filepath, 'rb') as f:
        raw = f.read()
    data = xor_decode(raw, xor_key)

    block_undos = []
    pos = 0

    while pos + 8 <= len(data):
        # Find magic
        if struct.unpack_from('<I', data, pos)[0] != MAGIC_MAINNET:
            pos += 1
            continue

        size = struct.unpack_from('<I', data, pos + 4)[0]
        undo_start = pos + 8
        undo_end = undo_start + size

        if undo_end + 32 > len(data):
            break

        try:
            block_undo = _parse_block_undo(data, undo_start, undo_end)
        except Exception:
            block_undo = {'tx_undos': []}

        block_undos.append(block_undo)
        pos = undo_end + 32  # Skip size bytes + 32-byte block hash

    return block_undos


def _parse_block_undo(data: bytes, start: int, end: int):
    """Parse CBlockUndo from data[start:end]"""
    pos = start
    ntx, pos = read_compact_size(data, pos)
    tx_undos = []

    for _ in range(ntx):
        nin, pos = read_compact_size(data, pos)
        input_values = []
        input_types = []
        for _ in range(nin):
            try:
                val, stype, pos = parse_coin_value(data, pos)
                input_values.append(val)
                input_types.append(stype)
            except Exception:
                # Can't parse rest of this tx's inputs
                input_values.append(0)
                input_types.append('unknown')
                # Skip remaining: we can't reliably recover position
                # Set remaining to empty
                break
        tx_undos.append({'input_values': input_values, 'input_types': input_types})

    return {'tx_undos': tx_undos}


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

def h_cioh(tx: dict, prevout_types: list) -> dict:
    """Common Input Ownership Heuristic: >1 input → same entity"""
    nin = len(tx['inputs'])
    detected = nin > 1 and not tx['is_coinbase']
    return {
        'detected': detected,
        'input_count': nin,
        'note': 'Multiple inputs likely controlled by same entity' if detected else 'Single input or coinbase',
    }


def h_change_detection(tx: dict, prevout_types: list) -> dict:
    """Detect likely change output via script type matching and round number analysis"""
    if tx['is_coinbase'] or len(tx['outputs']) < 2:
        return {'detected': False, 'likely_change_index': None, 'method': 'none', 'confidence': 'low'}

    outputs = tx['outputs']

    # Determine dominant input script type
    types = prevout_types if prevout_types else [inp['inferred_type'] for inp in tx['inputs']]
    non_unknown = [t for t in types if t not in ('unknown', 'empty')]
    if not non_unknown:
        non_unknown = types
    type_counts = Counter(non_unknown)
    dominant_input_type = type_counts.most_common(1)[0][0] if type_counts else 'unknown'

    # Method 1: script type match — change output matches input type, payment doesn't
    matching = [i for i, o in enumerate(outputs) if o['script_type'] == dominant_input_type]
    non_matching = [i for i, o in enumerate(outputs) if o['script_type'] != dominant_input_type]

    if len(matching) == 1 and len(non_matching) >= 1 and dominant_input_type not in ('unknown', 'empty'):
        return {
            'detected': True,
            'likely_change_index': matching[0],
            'method': 'script_type_match',
            'confidence': 'high',
        }

    # Method 2: round number — non-round output is likely change
    def is_round(sats):
        return sats >= 100_000 and sats % 100_000 == 0

    round_outs = [i for i, o in enumerate(outputs) if is_round(o['value'])]
    non_round_outs = [i for i, o in enumerate(outputs) if not is_round(o['value']) and o['value'] > 0]

    if len(non_round_outs) == 1 and len(round_outs) >= 1:
        return {
            'detected': True,
            'likely_change_index': non_round_outs[0],
            'method': 'round_number',
            'confidence': 'medium',
        }

    return {'detected': False, 'likely_change_index': None, 'method': 'none', 'confidence': 'low'}


def h_address_reuse(tx: dict, prevout_types: list, prevout_scripts: list) -> dict:
    """Address reuse: same address in inputs and outputs"""
    output_hashes = set()
    for o in tx['outputs']:
        h = script_hash(o['script_pubkey'])
        if h:
            output_hashes.add(h)

    reused = []
    for i, inp in enumerate(tx['inputs']):
        # Use prevout script if available
        if i < len(prevout_scripts) and prevout_scripts[i]:
            h = script_hash(prevout_scripts[i])
        else:
            h = ''
        if h and h in output_hashes:
            reused.append(i)

    detected = len(reused) > 0
    return {
        'detected': detected,
        'reused_input_indices': reused,
    }


def h_coinjoin(tx: dict, prevout_types: list) -> dict:
    """CoinJoin: many inputs + equal-value outputs"""
    if tx['is_coinbase']:
        return {'detected': False}

    nin = len(tx['inputs'])
    outputs = tx['outputs']
    nout = len(outputs)

    if nin < 3:
        return {'detected': False}

    # Count equal-value outputs (at least 2 with same non-dust value)
    val_counts = Counter(o['value'] for o in outputs if o['value'] > 546 and o['script_type'] != 'op_return')
    max_equal = max(val_counts.values()) if val_counts else 0
    dominant_value = val_counts.most_common(1)[0][0] if val_counts else 0

    detected = max_equal >= 2 and nin >= 3
    return {
        'detected': detected,
        'input_count': nin,
        'equal_output_count': max_equal,
        'equal_value_sats': dominant_value if detected else None,
    }


def h_consolidation(tx: dict, prevout_types: list) -> dict:
    """Consolidation: many inputs, few outputs"""
    if tx['is_coinbase']:
        return {'detected': False}
    nin = len(tx['inputs'])
    nout = len(tx['outputs'])
    detected = nin >= 3 and nout <= 2
    return {
        'detected': detected,
        'input_count': nin,
        'output_count': nout,
    }


def h_self_transfer(tx: dict, prevout_types: list) -> dict:
    """Self-transfer: 1 input, 1 output, same script type"""
    if tx['is_coinbase']:
        return {'detected': False}
    nin = len(tx['inputs'])
    nout = len(tx['outputs'])
    if nin == 1 and nout == 1:
        return {'detected': True, 'reason': 'single_input_output'}

    # Also detect: all outputs same type as most inputs, no obvious payment
    if nin >= 1 and nout >= 1:
        types = prevout_types if prevout_types else [inp['inferred_type'] for inp in tx['inputs']]
        in_type_counts = Counter(t for t in types if t not in ('unknown', 'empty'))
        out_types = set(o['script_type'] for o in tx['outputs'] if o['script_type'] not in ('op_return', 'unknown'))
        if in_type_counts and len(out_types) == 1:
            dominant = in_type_counts.most_common(1)[0][0]
            if dominant in out_types:
                return {'detected': True, 'reason': 'uniform_type'}

    return {'detected': False}


def h_round_number_payment(tx: dict, prevout_types: list) -> dict:
    """Round number: output divisible by 0.01 BTC (1,000,000 sats)"""
    if tx['is_coinbase']:
        return {'detected': False}
    ROUND = 1_000_000
    round_outputs = [
        i for i, o in enumerate(tx['outputs'])
        if o['value'] >= ROUND and o['value'] % ROUND == 0
        and o['script_type'] != 'op_return'
    ]
    detected = len(round_outputs) > 0
    return {
        'detected': detected,
        'round_output_indices': round_outputs,
    }


def apply_heuristics(tx: dict, input_values: list, input_types: list) -> dict:
    """Apply all 7 heuristics to a transaction. Returns heuristics dict."""
    # Build prevout info
    prevout_types = input_types if input_types else []
    # Use empty scripts for address reuse (we don't have full prevout scripts from rev)
    prevout_scripts = []

    return {
        'cioh': h_cioh(tx, prevout_types),
        'change_detection': h_change_detection(tx, prevout_types),
        'address_reuse': h_address_reuse(tx, prevout_types, prevout_scripts),
        'coinjoin': h_coinjoin(tx, prevout_types),
        'consolidation': h_consolidation(tx, prevout_types),
        'self_transfer': h_self_transfer(tx, prevout_types),
        'round_number_payment': h_round_number_payment(tx, prevout_types),
    }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def classify_transaction(tx: dict, heuristics: dict) -> str:
    if tx['is_coinbase']:
        return 'unknown'  # coinbase not in valid set

    if heuristics['coinjoin']['detected']:
        return 'coinjoin'

    if heuristics['consolidation']['detected']:
        return 'consolidation'

    if heuristics['self_transfer']['detected']:
        return 'self_transfer'

    nout = len([o for o in tx['outputs'] if o['script_type'] != 'op_return'])
    nin = len(tx['inputs'])

    if nout >= 3:
        return 'batch_payment'

    if nout == 2 and heuristics['change_detection']['detected']:
        return 'simple_payment'

    if nin <= 2 and nout <= 2:
        return 'simple_payment'

    return 'unknown'


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
def compute_fee_rate_stats(fee_rates: list) -> dict:
    """Compute min/max/median/mean fee rate stats from list of sat/vb values"""
    if not fee_rates:
        return {'min_sat_vb': 0.0, 'max_sat_vb': 0.0, 'median_sat_vb': 0.0, 'mean_sat_vb': 0.0}
    rates = sorted(fee_rates)
    n = len(rates)
    median = (rates[n // 2] if n % 2 == 1 else (rates[n // 2 - 1] + rates[n // 2]) / 2)
    return {
        'min_sat_vb': round(rates[0], 2),
        'max_sat_vb': round(rates[-1], 2),
        'median_sat_vb': round(median, 2),
        'mean_sat_vb': round(sum(rates) / n, 2),
    }


def estimate_vbytes(tx: dict) -> int:
    """Estimate transaction vbytes from raw size and segwit flag"""
    if not tx['segwit']:
        return tx['raw_size']
    # Segwit: rough estimate — non-witness ~60% of total for typical txs
    # Better: (raw_size * 3 + raw_size) / 4 ≈ raw_size (conservative)
    # Use raw_size as upper bound; actual is slightly less
    return max(1, tx['raw_size'] * 3 // 4)


def script_type_distribution(transactions: list) -> dict:
    dist = Counter()
    for tx in transactions:
        for o in tx['outputs']:
            dist[o['script_type']] += 1
    return dict(dist)


# ---------------------------------------------------------------------------
# Analysis of a single block
# ---------------------------------------------------------------------------
def analyze_block(block: dict, block_undo, is_first_block: bool) -> tuple:
    """
    Analyze all transactions in a block.
    Returns (block_result_dict, fee_rates_list).
    block_undo: { tx_undos: [ {input_values: [...]} ] } or None
    is_first_block: if True, include full transactions array; else use []
    """
    transactions = block['transactions']
    tx_results = []
    fee_rates = []
    flagged = 0

    # Map undo data to non-coinbase txs
    undo_list = []
    if block_undo and block_undo.get('tx_undos'):
        undo_list = block_undo['tx_undos']

    undo_idx = 0
    for tx in transactions:
        # Get input values from undo data
        input_values = []
        input_types = []
        if not tx['is_coinbase'] and undo_idx < len(undo_list):
            undo = undo_list[undo_idx]
            input_values = undo.get('input_values', [])
            input_types = undo.get('input_types', [])
            undo_idx += 1

            # Compute fee rate if we have input values
            total_in = sum(input_values)
            total_out = sum(o['value'] for o in tx['outputs'])
            fee = total_in - total_out
            if fee >= 0 and total_in > 0:
                vbytes = estimate_vbytes(tx)
                if vbytes > 0:
                    fee_rate = fee / vbytes
                    if 0 <= fee_rate <= 100_000:  # sanity check
                        fee_rates.append(fee_rate)

        heuristics = apply_heuristics(tx, input_values, input_types)
        classification = classify_transaction(tx, heuristics)

        # Count flagged
        if any(v['detected'] for v in heuristics.values()):
            flagged += 1

        if is_first_block:
            vbytes = estimate_vbytes(tx)
            weight = tx['raw_size'] if not tx['segwit'] else tx['raw_size']  # stored as raw; weight = vbytes*4 for legacy
            # Check RBF: any input with sequence < 0xFFFFFFFE signals RBF
            rbf = not tx['is_coinbase'] and any(
                inp.get('sequence', 0xFFFFFFFF) < 0xFFFFFFFE for inp in tx['inputs']
            )
            # Build compact inputs/outputs for UI
            inputs_out = [
                {
                    'txid': inp['txid'],
                    'vout': inp['vout'],
                    'script_type': inp.get('inferred_type', 'unknown'),
                    'sequence': inp.get('sequence'),
                }
                for inp in tx['inputs']
            ]
            outputs_out = [
                {
                    'index': i,
                    'value_sat': o['value'],
                    'script_type': o['script_type'],
                    'address': o.get('address'),
                    'is_dust': o['value'] < 546 and o['script_type'] not in ('op_return', 'unknown'),
                }
                for i, o in enumerate(tx['outputs'])
            ]
            # Warnings
            warnings = []
            if any(o['value_sat'] for o in outputs_out if o['is_dust']):
                warnings.append('Dust output detected (< 546 sat)')
            if rbf:
                warnings.append('RBF signaling enabled — transaction is replaceable')
            if heuristics.get('address_reuse', {}).get('detected'):
                warnings.append('Address reuse detected')

            tx_results.append({
                'txid': tx['txid'],
                'heuristics': heuristics,
                'classification': classification,
                'input_count': len(tx['inputs']),
                'output_count': len(tx['outputs']),
                'vsize': vbytes,
                'weight': vbytes * 4 if not tx['segwit'] else tx['raw_size'],
                'is_coinbase': tx['is_coinbase'],
                'rbf_signaling': rbf,
                'timelock': tx['locktime'],
                'fee_rate': None,
                'inputs': inputs_out,
                'outputs': outputs_out,
                'warnings': warnings,
            })

    # Compute script type distribution
    stype_dist = script_type_distribution(transactions)

    # Compute per-heuristic hit counts (from tx_results for block[0], else from all txs)
    heuristic_hits = {h: 0 for h in HEURISTIC_IDS}
    if is_first_block:
        for tr in tx_results:
            for h, v in tr['heuristics'].items():
                if isinstance(v, dict) and v.get('detected'):
                    heuristic_hits[h] = heuristic_hits.get(h, 0) + 1

    effective_tx_count = len(transactions) if is_first_block else 0

    block_summary = {
        'total_transactions_analyzed': effective_tx_count,
        'heuristics_applied': HEURISTIC_IDS,
        'heuristic_hit_counts': heuristic_hits if is_first_block else {},
        'flagged_transactions': flagged if is_first_block else 0,
        'script_type_distribution': stype_dist,
        'fee_rate_stats': compute_fee_rate_stats(fee_rates),
    }

    block_result = {
        'block_hash': block['block_hash'],
        'block_height': block['block_height'],
        'timestamp': block['timestamp'],
        'tx_count': effective_tx_count,
        'analysis_summary': block_summary,
        'transactions': tx_results,  # full for block[0], [] for others
    }

    return block_result, fee_rates


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
def write_json_output(path: str, blk_filename: str, blocks_data: list, all_fee_rates: list, total_flagged: int):
    """Write the full JSON analysis output"""
    total_tx = sum(b['tx_count'] for b in blocks_data)

    file_summary = {
        'total_transactions_analyzed': total_tx,
        'heuristics_applied': HEURISTIC_IDS,
        'heuristic_hit_counts': blocks_data[0]['analysis_summary'].get('heuristic_hit_counts', {}) if blocks_data else {},
        'flagged_transactions': total_flagged,
        'script_type_distribution': _aggregate_script_dist(blocks_data),
        'fee_rate_stats': compute_fee_rate_stats(all_fee_rates),
    }

    output = {
        'ok': True,
        'mode': 'chain_analysis',
        'file': blk_filename,
        'block_count': len(blocks_data),
        'analysis_summary': file_summary,
        'blocks': blocks_data,
    }

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(output, f, separators=(',', ':'))


def _aggregate_script_dist(blocks_data: list) -> dict:
    total = Counter()
    for b in blocks_data:
        for k, v in b['analysis_summary'].get('script_type_distribution', {}).items():
            total[k] += v
    return dict(total)


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------
def write_markdown_output(path: str, blk_filename: str, blocks_data: list,
                          raw_blocks: list, all_fee_rates: list, total_flagged: int):
    """Generate human-readable Markdown report"""
    total_tx = sum(b['analysis_summary']['total_transactions_analyzed'] for b in blocks_data)
    fee_stats = compute_fee_rate_stats(all_fee_rates)
    stype_dist = _aggregate_script_dist(blocks_data)

    lines = []
    lines.append(f"# Chain Analysis Report: {blk_filename}\n")
    lines.append(f"_Generated by Sherlock — Bitcoin Chain Analysis Engine_\n")
    lines.append("---\n")

    # Summary section
    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Source File | `{blk_filename}` |")
    lines.append(f"| Total Blocks | {len(blocks_data)} |")
    lines.append(f"| Total Transactions Analyzed | {total_tx:,} |")
    lines.append(f"| Flagged Transactions | {total_flagged:,} |")
    lines.append(f"| Heuristics Applied | {len(HEURISTIC_IDS)} |")
    if total_tx > 0:
        lines.append(f"| Flag Rate | {total_flagged / total_tx * 100:.1f}% |")
    lines.append("")

    # Fee Rate Distribution section
    lines.append("## Fee Rate Distribution\n")
    lines.append("Fee rates computed from blocks where undo data was available.\n")
    lines.append("| Statistic | Value (sat/vbyte) |")
    lines.append("|-----------|-------------------|")
    lines.append(f"| Minimum | {fee_stats['min_sat_vb']} |")
    lines.append(f"| Median | {fee_stats['median_sat_vb']} |")
    lines.append(f"| Mean | {fee_stats['mean_sat_vb']} |")
    lines.append(f"| Maximum | {fee_stats['max_sat_vb']} |")
    lines.append("")

    # Script Type Breakdown
    lines.append("## Script Type Breakdown\n")
    lines.append("Distribution of output script types across all analyzed blocks.\n")
    lines.append("| Script Type | Output Count | Share |")
    lines.append("|-------------|-------------|-------|")
    total_scripts = sum(stype_dist.values()) or 1
    for stype, count in sorted(stype_dist.items(), key=lambda x: -x[1]):
        pct = count / total_scripts * 100
        lines.append(f"| `{stype}` | {count:,} | {pct:.1f}% |")
    lines.append("")

    # Heuristic Summary
    lines.append("## Heuristic Summary\n")
    if blocks_data:
        b0 = blocks_data[0]
        b0_sum = b0['analysis_summary']
        lines.append(f"Results for first block (Block 0, height {b0['block_height']:,}):\n")
        lines.append("| Heuristic | Description | Transactions Flagged |")
        lines.append("|-----------|-------------|---------------------|")

        heuristic_descs = {
            'cioh': 'Common Input Ownership — inputs likely same entity',
            'change_detection': 'Change Detection — likely change output identified',
            'address_reuse': 'Address Reuse — same address in inputs and outputs',
            'coinjoin': 'CoinJoin — equal-value outputs, many inputs',
            'consolidation': 'Consolidation — many inputs, few outputs',
            'self_transfer': 'Self-Transfer — no net value change',
            'round_number_payment': 'Round Number Payment — round BTC output',
        }

        if b0.get('transactions'):
            counts = Counter()
            for tx in b0['transactions']:
                for hid, hdata in tx.get('heuristics', {}).items():
                    if hdata.get('detected'):
                        counts[hid] += 1
            for hid in HEURISTIC_IDS:
                desc = heuristic_descs.get(hid, hid)
                cnt = counts.get(hid, 0)
                lines.append(f"| `{hid}` | {desc} | {cnt:,} |")
        lines.append("")

    # Per-Block sections
    lines.append("## Block Details\n")
    import datetime
    for i, (b, rb) in enumerate(zip(blocks_data, raw_blocks)):
        ts = datetime.datetime.fromtimestamp(
            rb.get('timestamp', 0), datetime.UTC
        ).strftime('%Y-%m-%d %H:%M:%S UTC')
        tx_count_actual = rb.get('tx_count', 0)
        lines.append(f"### Block {i}: Height {b['block_height']:,}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Block Hash | `{b['block_hash']}` |")
        lines.append(f"| Height | {b['block_height']:,} |")
        lines.append(f"| Timestamp | {ts} |")
        lines.append(f"| Transactions | {tx_count_actual:,} |")
        lines.append(f"| Flagged | {b['analysis_summary']['flagged_transactions']:,} |")
        fee_s = b['analysis_summary']['fee_rate_stats']
        lines.append(f"| Fee Rate (med) | {fee_s['median_sat_vb']} sat/vb |")
        lines.append("")

        # Heuristic results for this block
        lines.append(f"#### Heuristic Results — Block {i}\n")
        lines.append("| Heuristic | Applied |")
        lines.append("|-----------|---------|")
        for hid in b['analysis_summary']['heuristics_applied']:
            lines.append(f"| `{hid}` | ✓ |")
        lines.append("")

        # Notable transactions (first block only, show top 5 coinjoin/consolidation)
        if i == 0 and b.get('transactions'):
            notable = [
                tx for tx in b['transactions']
                if tx['classification'] in ('coinjoin', 'consolidation', 'batch_payment')
            ][:5]
            if notable:
                lines.append(f"#### Notable Transactions — Block {i}\n")
                lines.append("| TXID | Classification | Inputs | Outputs |")
                lines.append("|------|---------------|--------|---------|")
                for tx in notable:
                    txid_short = tx['txid'][:16] + '...'
                    lines.append(f"| `{txid_short}` | {tx['classification']} | — | — |")
                lines.append("")

    md_content = '\n'.join(lines)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(md_content)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) != 4:
        error_json("INVALID_ARGS", "Usage: main.py <blk.dat> <rev.dat> <xor.dat>")
        sys.exit(1)

    blk_path, rev_path, xor_path = sys.argv[1], sys.argv[2], sys.argv[3]

    for f in [blk_path, rev_path, xor_path]:
        if not os.path.isfile(f):
            error_json("FILE_NOT_FOUND", f"File not found: {f}")
            sys.exit(1)

    # Read XOR key
    with open(xor_path, 'rb') as f:
        xor_key = f.read()

    # Parse block file
    try:
        raw_blocks = parse_blk_file(blk_path, xor_key)
    except Exception as e:
        error_json("PARSE_ERROR", f"Failed to parse block file: {e}")
        sys.exit(1)

    if not raw_blocks:
        error_json("PARSE_ERROR", "No blocks found in block file")
        sys.exit(1)

    # Parse rev file (best-effort)
    try:
        block_undos = parse_rev_file(rev_path, xor_key)
    except Exception:
        block_undos = []

    # Analyze each block
    blocks_data = []
    all_fee_rates = []
    total_flagged = 0

    for i, block in enumerate(raw_blocks):
        undo = block_undos[i] if i < len(block_undos) else None
        is_first = (i == 0)
        block_result, fee_rates = analyze_block(block, undo, is_first)
        blocks_data.append(block_result)
        all_fee_rates.extend(fee_rates)
        total_flagged += block_result['analysis_summary']['flagged_transactions']

    # Determine output paths
    blk_stem = Path(blk_path).stem
    out_dir = Path("out")
    out_dir.mkdir(exist_ok=True)

    json_path = out_dir / f"{blk_stem}.json"
    md_path = out_dir / f"{blk_stem}.md"
    blk_filename = Path(blk_path).name

    # Write JSON output
    try:
        write_json_output(str(json_path), blk_filename, blocks_data, all_fee_rates, total_flagged)
    except Exception as e:
        error_json("OUTPUT_ERROR", f"Failed to write JSON: {e}")
        sys.exit(1)

    # Write Markdown output
    try:
        write_markdown_output(str(md_path), blk_filename, blocks_data, raw_blocks, all_fee_rates, total_flagged)
    except Exception as e:
        error_json("OUTPUT_ERROR", f"Failed to write Markdown: {e}")
        sys.exit(1)

    print(f"Analysis complete: {len(raw_blocks)} blocks, {sum(b['analysis_summary']['total_transactions_analyzed'] for b in blocks_data):,} transactions")
    sys.exit(0)


if __name__ == '__main__':
    main()
