<!-- Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work -->
# punchcrypt

Encrypt data onto IBM 80-column punched cards.

The ciphertext **is** a deck of cards. Every column is a valid 12-bit punch, so
a real keypunch could have produced the output. The format is not a curiosity
wrapper around a byte stream — the card is the block.

```
     0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 ...
     1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 ...
    +----------------------------------------------------------------...
 12 |                                                                  ...
 11 |                                                                  ...
  0 |  []  [][]            []          []  []  []  []    [][]  [][]  ...
  1 |  []        []  []  [][]    [][]  []      [][][][][][][][][][[] ...
  2 |                      []  [][][]  [][]  []  [][]    [][]    []  ...
  3 |            []        []  []  []  [][]    []  []  []  [][][]  [ ...
  4 |[]  [][]                      [][][]  []        [][][]  [][][]  ...
  5 |    [][]    []      [][]    []                  [][]      [][][ ...
  6 |[][]                      []  []    [][]  []  []  []      []   ...
  7 |                      [][]  []        []  []        []    []   ...
  8 |                                                                  ...
  9 |                                                                  ...
    +----------------------------------------------------------------...
```

## Install

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python cryptography pytest
.venv/bin/python -m pytest tests/ -q      # 30 tests
```

## Use

```bash
# encrypt a file into a deck
punchcrypt encode secret.txt -o deck.json -e MY_PASSPHRASE_ENV

# decrypt it back
punchcrypt decode deck.json -e MY_PASSPHRASE_ENV

# draw the deck as punched cards
punchcrypt render deck.json

# show the Hollerith code table this build implements
punchcrypt table
```

The passphrase is read interactively by default, or from a file (`-p`) or an
environment variable (`-e`). There is no `--passphrase` flag on purpose: command
lines leak into `ps` and shell history.

## What is actually cryptographic here

Everything security-bearing is a standard primitive from `cryptography`:

| property | primitive |
|---|---|
| key derivation | HKDF-SHA256, separate keys for encryption and MAC |
| confidentiality | ChaCha20 keystream, per-deck random nonce |
| integrity | HMAC-SHA256, 16-byte tag over the whole punched image |

The card format is **framing, not a cipher**. A card is 960 bits (80 columns ×
12 bits), and 12 does not divide 8, 16 or 32, so the usual "treat it as bytes"
shortcut does not apply — the column is the unit.

## Design decisions worth knowing

**The naive version was rejected on purpose.** XOR-ing a card against a
repeating key stream is the obvious approach, and it is broken: with a 960-bit
card and a keystream that repeats, an attacker holding two ciphertexts cancels
the keystream and recovers the XOR of the plaintexts. The keystream here is
generated per deck from a random nonce, so that attack does not apply.
`test_keystream_reuse_attack_does_not_apply` asserts it.

**One MAC covers the whole deck**, computed over the punched card image with
the MAC field zeroed. Reordering cards, dropping one, substituting one from
another deck, or flipping any single punched hole invalidates the deck. There is
no per-card tag, because a per-card tag would let cards be shuffled between
decks that share a passphrase.

**Header on card 0 only.** 50 columns of header plus 30 payload columns on card
0; 80 payload columns on every card after it. That keeps the overhead to one
card for the whole deck rather than taxing every card.

## Hollerith layer

`punchcrypt/hollerith.py` implements the real IBM code, not an invented one:

- digits: a single punch in rows 0–9
- letters: **two** punches, a zone plus a digit
  - `12 + 1..9` → A–I
  - `11 + 1..9` → J–R
  - `0 + 2..9` → S–Z
- space: no punch at all

Punctuation is deliberately **not** claimed. Keypunch models (IBM 026, 029, and
the EBCDIC-era 129) assigned the leftover two- and three-punch combinations
differently, so any table would be a guess. Arbitrary characters travel through
an explicit escape sequence instead, so text still round-trips without inventing
history.

This layer is for reading and writing **plaintext** cards. An encrypted deck is
random bits and is not Hollerith-readable — that is the point.

## Limits

- One deck holds at most 65,535 bytes (the header's uint16 length field).
- Text mode carries UTF-8 bytes, not Hollerith column masks. Those masks are
  12-bit values and the cipher's column payload is 8 bits, so passing them
  through would truncate zone punches and turn `A` into a digit.
- There is no key stretching on the passphrase beyond HKDF. A low-entropy
  passphrase is a low-entropy key; use a real one.
- `render` output is 160+ characters wide.

## Tests

30 tests, grouped by what they defend: the Hollerith table is the real one and
round-trips; the cipher round-trips and every column is a valid 12-bit punch;
and the attacks that were considered must fail.

```bash
.venv/bin/python -m pytest tests/ -q
```
