# addrforge

Bitcoin vanity address generator. Find addresses that start or end with a pattern you choose, or match a regular expression. Supports all four Bitcoin address types, all networks, MuSig2 n-of-n key aggregation, and BIP-39 mnemonic export.

```
bc1pcat     bc1qfat     1Dad     3Shop
```

![Address Mode](assets/screen1.png)
![Type Picker](assets/screen2.png)
![Setup](assets/screen3.png)
![Inspector](assets/screen4.png)

---

## Build

```bash
cargo build --release
```

The binary is at `./target/release/addrforge`. Requires Rust 1.66+. Tested on Linux and macOS.

---

## TUI

Launch with no arguments to open the interactive terminal interface. Minimum terminal size: 72×24.

```bash
./target/release/addrforge
```

**Flow:**

```
Address Mode → Type Picker → Setup → Running → Results
                   ↓
              MuSig2 Setup → MuSig2 Result
```

| Key                 | Action                                 |
| ------------------- | -------------------------------------- |
| `↑↓` or `j/k`       | Navigate / scroll results              |
| `Tab` / `Shift-Tab` | Next / previous field                  |
| `Space` / `←→`      | Cycle value on NETWORK or MODE field   |
| `Enter`             | Confirm / start search                 |
| `Esc`               | Back                                   |
| `S`                 | Save results to file                   |
| `I`                 | Inspect selected address               |
| `N`                 | New search (resets to start)           |
| `F2`                | Open address inspector from any screen |
| `Ctrl-C`            | Quit                                   |

Settings (address type, network, mode, thread count) are saved to `~/.config/addrforge/config.toml` on exit and restored on next launch.

---

## Address types

| Type                      | Mainnet prefix | Format  | Derivation  |
| ------------------------- | -------------- | ------- | ----------- |
| Taproot P2TR              | `bc1p`         | bech32m | m/86'/0'/0' |
| Native SegWit P2WPKH      | `bc1q`         | bech32  | m/84'/0'/0' |
| Nested SegWit P2SH-P2WPKH | `3`            | base58  | m/49'/0'/0' |
| Legacy P2PKH              | `1`            | base58  | m/44'/0'/0' |

Bech32 addresses (Taproot, Native SegWit) are lowercase only. Base58 addresses (Legacy, Nested) are case-sensitive — `1ABC` and `1abc` are different patterns.

---

## Networks

addrforge supports all four Bitcoin networks. Switch networks in the Setup screen (SPACE on the NETWORK field) or via the `--network` CLI flag.

| Network | Taproot prefix | Legacy prefix |
| ------- | -------------- | ------------- |
| Mainnet | `bc1p`         | `1`           |
| Testnet | `tb1p`         | `m` / `n`     |
| Signet  | `tb1p`         | `m` / `n`     |
| Regtest | `bcrt1p`       | `m` / `n`     |

Prefix validation and difficulty estimates are network-aware. Testnet and regtest are useful for wallet integration testing without risking real funds.

---

## Search modes

**PREFIX** — address starts with your pattern (after the fixed type prefix).

```
Pattern: bc1pface
Finds:   bc1pface8qx3...
```

**SUFFIX** — address ends with your pattern.

```
Pattern: dead
Finds:   bc1p...dead
```

**REGEX** — full regular expression match against the complete address string.

```
Pattern: ^bc1p[0-9]{4}
Finds:   bc1p1337...
```

Difficulty scales exponentially with pattern length. Each extra character multiplies search time by 32 (bech32) or 58 (base58). A 4-character Taproot vanity suffix takes ~1 million attempts on average; 8 characters takes ~1 trillion.

Use `--bench` to measure your machine's generation rate before committing to a long search.

---

## MuSig2

MuSig2 mode derives an n-of-n aggregate Taproot address from 2 to 16 compressed public keys (BIP-327). All parties must co-sign to spend. The resulting address is indistinguishable from a single-key Taproot address on-chain.

**Input format:** 33-byte compressed public keys, 66 hex characters, with `02` or `03` prefix.

In the TUI, add keys one at a time — type 66 hex chars and press `Enter` to confirm each key. Once two or more keys are added, press `Enter` on an empty input to derive the aggregate address. `Backspace` on an empty input removes the last confirmed key.

**Important:** The key shown on the singlesig results screen labeled _OUTPUT KEY (TWEAKED X-ONLY PUBKEY)_ is **not** the right format for MuSig2. Use the _COMPRESSED PUBKEY_ row shown below it, or provide keys generated externally by your wallet software.

**This is not a signing tool.** addrforge derives the address only. To actually spend from a MuSig2 address you need a BIP-327 compatible signing library or wallet.

---

## CLI (no TUI)

```bash
# Find one Taproot prefix address
./target/release/addrforge --no-tui --pattern bc1pface

# Find 5 legacy addresses ending in 'cafe'
./target/release/addrforge --no-tui --addr-type legacy --mode suffix --pattern cafe --count 5

# Regex search, 8 threads
./target/release/addrforge --no-tui --mode regex --pattern "^bc1p[0-9]{3}" --threads 8

# Testnet address
./target/release/addrforge --no-tui --network testnet --pattern tb1pface

# Save results to a specific directory
./target/release/addrforge --no-tui --pattern bc1ptest --output-dir ~/keys
```

**Flags:**

| Flag           | Default   | Description                                      |
| -------------- | --------- | ------------------------------------------------ |
| `--no-tui`     | —         | Print results to stdout instead of TUI           |
| `--addr-type`  | `taproot` | `legacy`, `nested`, `native`, `taproot`          |
| `--network`    | `mainnet` | `mainnet`, `testnet`, `signet`, `regtest`        |
| `--mode`       | `prefix`  | `prefix`, `suffix`, `regex`                      |
| `--pattern`    | —         | Pattern to search for (required with `--no-tui`) |
| `--count`      | `1`       | Number of matches to find (max 1000)             |
| `--threads`    | all CPUs  | Number of worker threads (max 256)               |
| `--output-dir` | `.`       | Directory for saved result files                 |
| `--bench`      | —         | Benchmark generation speed and exit              |

---

## Benchmark

```bash
# Taproot speed on all CPUs
./target/release/addrforge --bench

# Testnet legacy speed on 4 threads
./target/release/addrforge --bench --addr-type legacy --network testnet --threads 4
```

Prints addresses/sec and estimated average search time per prefix length. Runs for 5 seconds then exits.

---

## Output files

Saved results are written to `addrforge-<timestamp>.txt` in the output directory. MuSig2 derivations are saved as `addrforge-musig2-<timestamp>.txt`.

Example singlesig result file:

```
ADDRFORGE V0.9.0 -- RESULTS
TYPE    : TAPROOT (P2TR)
NETWORK : MAINNET
MODE    : PREFIX
PATTERN : bc1pface
THREADS : 8  COUNT : 1
ELAPSED : 4.2S  ATTEMPTS : 3,847,201

MATCH 1
  ADDRESS    : bc1pface8qx3...
  PUBKEY     : <x-only output key>
  COMPRESSED : 02<compressed pubkey — use this for MuSig2>
  WIF KEY    : <private key in WIF format>
  MNEMONIC   : word1 word2 word3 ... word24
```

The mnemonic is a standard BIP-39 24-word seed phrase derived directly from the private key entropy. It encodes the same key as the WIF and can be used to import into any BIP-39 compatible wallet.

---

## Importing keys into a wallet

**Via WIF** — works with any wallet that supports raw key import.

**Sparrow Wallet** — recommended for all address types, especially Taproot.

1. File → New Wallet → Private Key
2. Paste the WIF key
3. Select the script type (P2TR for Taproot, P2WPKH for Native SegWit, etc.)

Sparrow also supports descriptor import:

```
tr(KwDiB...)
```

**Bitcoin Core** — works via the console with descriptors:

```
importdescriptors [{"desc":"tr(KwDiB...)#checksum","timestamp":"now"}]
```

Run `getdescriptorinfo "tr(KwDiB...)"` first to get the checksum.

**Electrum** — requires a script-type prefix when importing:

| Prefix                 | Address type         |
| ---------------------- | -------------------- |
| `p2wpkh:KwDiB...`      | Native SegWit (bc1q) |
| `p2wpkh-p2sh:KwDiB...` | Nested SegWit (3)    |
| `p2pkh:KwDiB...`       | Legacy (1)           |

Without a prefix, Electrum defaults to Legacy. Taproot WIF import is not supported by Electrum.

**Via BIP-39 mnemonic** — import the 24-word phrase into any BIP-39 compatible wallet (Sparrow, Ledger, Trezor, etc.). Note that BIP-39 wallets derive keys via a full HD path — the address you get will only match the addrforge result if the wallet derives at the correct path (m/86'/0'/0'/0/0 for Taproot).

**Wallets that do NOT support Taproot WIF import:** BlueWallet, Trust Wallet, Exodus, and Wasabi (expects seed phrases only) generally cannot import raw Taproot keys even if they support Taproot addresses.

---

> **⚠ Notice:** addrforge is an independent open-source tool and has not been formally audited by a third party. Read the [Security](#security) section before using with real funds.

## Security

**The WIF private key and mnemonic in the output file control the funds.** Anyone with access to this file can spend from the address.

- Store result files in an encrypted location immediately after saving
- Never share WIF keys or mnemonics, or commit them to version control
- For significant funds, generate keys on an air-gapped machine
- addrforge generates keys using the OS cryptographic RNG (`thread_rng` backed by the system entropy source)
- Vanity prefixes do not meaningfully reduce security — even an 8-character Taproot prefix leaves 216 bits of key space, far beyond any feasible attack

---

## Taproot Merkle root

In the TUI setup screen, Taproot prefix and suffix searches expose an optional **MERKLE** field. If you provide a 32-byte (64 hex char) Taproot script tree root, the address will commit to that script tree. Leave blank for a standard key-path-only address.

---

## Address inspector

Press `F2` from any main screen, or `I` on the results screen, to open the address inspector. Type any Bitcoin address and press `Enter` to decode its type, network, encoding, key hash, and spend type. Works with mainnet, testnet, signet, and regtest addresses. The inspector detects provably unspendable addresses using the BIP-341 NUMS point.

All inspection is done locally — no network requests are made. The inspector decodes only what is encoded in the address string itself (the key hash or output key). It cannot show balance, transaction history, or the original public key behind a hash.
