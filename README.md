# Sherlock

Sherlock is a Bitcoin chain-analysis engine and local web visualizer for exploring transaction patterns directly from Bitcoin Core block data. It parses raw `blk*.dat` files, reads matching undo data from `rev*.dat`, applies privacy and wallet-behavior heuristics, and produces both machine-readable JSON and human-readable Markdown reports.

Built as part of the Summer of Bitcoin 2026 Developer Challenge.

## What It Does

- Parses Bitcoin mainnet block records from local `blk*.dat` files, including SegWit transactions.
- Decodes block metadata such as block hash, timestamp, transaction count, and BIP34 coinbase height.
- Uses undo data from `rev*.dat` files to recover prevout values and script-type context where available.
- Applies chain-analysis heuristics to classify transactions and flag notable behavior.
- Writes reproducible analysis reports to `out/<block-file>.json` and `out/<block-file>.md`.
- Serves a local web UI for inspecting block summaries, heuristic hits, transaction classifications, inputs, and outputs.

## Why This Exists

Bitcoin transactions are public, but understanding wallet behavior from raw block files is still difficult. Sherlock turns low-level block data into structured observations that make common chain-analysis questions easier to explore:

- Which transactions look like simple payments, consolidations, CoinJoins, self-transfers, or batch payments?
- Which heuristics were triggered for each transaction?
- How are output script types distributed across a block?
- Which transactions are worth manual review?

The project is intentionally local-first: it does not require a Bitcoin node, indexer, or external API once block fixtures are available.

## Heuristics

Sherlock currently applies seven heuristics:

| ID | Purpose |
| --- | --- |
| `cioh` | Flags multi-input transactions using the common-input-ownership assumption. |
| `change_detection` | Attempts to identify likely change outputs using script-type and round-number signals. |
| `address_reuse` | Detects reuse signals when prevout script context is available. |
| `coinjoin` | Looks for multi-input transactions with repeated equal-value outputs. |
| `consolidation` | Flags many-input, few-output transactions that look like UTXO consolidation. |
| `self_transfer` | Identifies simple internal movement patterns such as one-input/one-output transfers. |
| `round_number_payment` | Flags outputs that look like human-denominated BTC payments. |

Heuristics are probabilistic, not proof of ownership or intent. See [APPROACH.md](APPROACH.md) for the confidence model, limitations, architecture, and references.

## Repository Layout

```text
.
├── cli.sh                    # CLI wrapper around the Python analyzer
├── setup.sh                  # Decompresses fixtures and prepares optional web assets
├── web.sh                    # Starts the local visualizer
├── src/analyzer/main.py      # Block parser, undo parser, heuristics, report writer
├── src/web/server.js         # Minimal Node.js HTTP server
├── src/web/public/index.html # Browser UI
├── fixtures/                 # Compressed sample blk/rev data and xor key
├── out/                      # Example JSON and Markdown analysis outputs
├── docs/                     # Supporting diagrams
└── APPROACH.md               # Technical approach and trade-offs
```

## Quick Start

Run setup once:

```bash
./setup.sh
```

Analyze a fixture block file:

```bash
./cli.sh --block fixtures/blk04330.dat fixtures/rev04330.dat fixtures/xor.dat
```

The analyzer writes:

```text
out/blk04330.json
out/blk04330.md
```

Start the visualizer:

```bash
./web.sh
```

Then open the URL printed by the command, usually:

```text
http://127.0.0.1:3000
```

The server also exposes:

```text
GET /api/health
GET /api/analysis
GET /api/analysis/<stem>
```

## CLI Interface

```bash
./cli.sh --block <blk.dat> <rev.dat> <xor.dat>
```

Arguments:

- `<blk.dat>`: Bitcoin Core block file.
- `<rev.dat>`: Matching undo file used for prevout values and script-type hints.
- `<xor.dat>`: Bitcoin Core XOR key file. An all-zero key is treated as identity.

On success, the command exits with `0` and writes JSON/Markdown reports under `out/`. On argument or runtime errors, it prints structured JSON:

```json
{"ok":false,"error":{"code":"INVALID_ARGS","message":"Usage: cli.sh --block <blk.dat> <rev.dat> <xor.dat>"}}
```

## JSON Output

Each JSON report has this top-level shape:

```json
{
  "ok": true,
  "mode": "chain_analysis",
  "file": "blk04330.dat",
  "block_count": 1,
  "analysis_summary": {
    "total_transactions_analyzed": 1683,
    "heuristics_applied": ["cioh", "change_detection"],
    "flagged_transactions": 714,
    "script_type_distribution": {},
    "fee_rate_stats": {
      "min_sat_vb": 0.0,
      "max_sat_vb": 0.0,
      "median_sat_vb": 0.0,
      "mean_sat_vb": 0.0
    }
  },
  "blocks": []
}
```

Per-block objects include `block_hash`, `block_height`, `timestamp`, `tx_count`, `analysis_summary`, and `transactions`.

Why we did this: array of per-transaction analysis results. Required for the first block (blocks[0]): the grader validates that the array exists and its length equals tx_count. Optional for subsequent blocks — you may omit it or use an empty array to reduce JSON size and speed up grading.

In this implementation, the first parsed block includes full transaction-level records for the web UI. Later blocks may contain only aggregate summaries to keep reports smaller and faster to load.

## Web Visualizer

The browser UI reads JSON reports from `out/` and provides:

- File-level summary cards.
- Fee-rate and script-type distributions.
- Heuristic hit counts.
- Block list and block detail modal.
- Transaction detail view for the first block, including fired heuristics, classification, inputs, outputs, RBF signaling, dust warnings, and locktime.

No build system is required for the current UI. The server uses Node.js standard libraries only.

## Example Outputs

This repository includes generated reports for the bundled fixtures:

- [out/blk04330.md](out/blk04330.md)
- [out/blk05051.md](out/blk05051.md)
- `out/blk04330.json`
- `out/blk05051.json`

These are useful for exploring the visualizer immediately after cloning.

## Requirements

- Python 3.9+
- Node.js 18+ for the local web UI
- Bash-compatible shell

The analyzer itself uses Python standard-library modules only.

## Notes

Sherlock is an analysis aid, not a deanonymization oracle. The results should be read as explainable signals with known false positives and false negatives, especially around CoinJoin, exchange batching, wallet maintenance, and self-transfer patterns.

## Projcet Overview

https://drive.google.com/file/d/1fEg1JrYBYCKC6qrM_AtIQwVEpLH3ViA9/view?usp=sharing