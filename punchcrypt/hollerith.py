# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
"""
Hollerith character layer for 12-row x 80-column punched cards.

Historical basis (IBM 80-column format, introduced 1928; the two extra rows
added 1930 for alphabetic coding):

  - 12 rows. Top three positions are the ZONE punches: 12 (top), 11, and 0.
    Row 0 is also a digit punch, so it does double duty.
  - Digits are a single punch in rows 0-9.
  - The 26 letters are TWO punches: a zone (12, 11 or 0) plus a digit 1-9.
        12 + 1..9 -> A..I
        11 + 1..9 -> J..R
         0 + 2..9 -> S..Z
  - Space is the absence of any punch.

Punctuation is deliberately NOT claimed here. Keypunch models (IBM 026, 029,
and the EBCDIC-era 129) assigned the leftover two- and three-punch combinations
differently, so any table would be a guess. Instead this layer supports the
parts that are unambiguous and standard, plus an explicit escape for everything
else, so arbitrary text still round-trips without inventing history.

Binary mode is also provided, because real installations punched binary data
onto cards (IBM shipped "binary punched cards"): 6 bits per column in rows 0-5,
which packs bytes without needing any character table at all. The cipher works
on raw columns, so it never depends on the text layer.
"""

from __future__ import annotations

ROWS = 12          # row labels, top to bottom: 12, 11, 0, 1, ..., 9
COLS = 80
ROW_LABELS = [12, 11] + list(range(0, 10))

# bit position -> row label. bit 0 = row 0 ... bit 9 = row 9,
# bit 10 = row 11, bit 11 = row 12.
ROW_TO_BIT = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9,
              11: 10, 12: 11}
BIT_TO_ROW = {v: k for k, v in ROW_TO_BIT.items()}

COLUMN_MASK = 0xFFF  # 12 bits


def rows_to_mask(rows) -> int:
    """Turn a list of row labels into a 12-bit column mask."""
    mask = 0
    for r in rows:
        if r not in ROW_TO_BIT:
            raise ValueError(f"no such row: {r!r}")
        mask |= 1 << ROW_TO_BIT[r]
    return mask & COLUMN_MASK


def mask_to_rows(mask: int) -> list:
    """Turn a 12-bit column mask back into row labels, top to bottom."""
    return [label for label in ROW_LABELS if mask & (1 << ROW_TO_BIT[label])]


# --------------------------------------------------------------------------
# Text layer: digits, letters, space. Standard Hollerith.
# --------------------------------------------------------------------------

DIGIT_CODES = {str(d): rows_to_mask([d]) for d in range(10)}

LETTER_CODES = {}
for i, ch in enumerate("ABCDEFGHI"):
    LETTER_CODES[ch] = rows_to_mask([12, i + 1])
for i, ch in enumerate("JKLMNOPQR"):
    LETTER_CODES[ch] = rows_to_mask([11, i + 1])
for i, ch in enumerate("STUVWXYZ"):
    LETTER_CODES[ch] = rows_to_mask([0, i + 2])

SPACE_CODE = 0

# Escape marker: 11-0 is unused by digits and letters, so it can introduce a
# byte written as two columns of 6-bit binary. This keeps arbitrary text
# round-tripping without pretending to know a punctuation table.
ESCAPE_CODE = rows_to_mask([11, 0])

CHAR_TO_MASK = {}
CHAR_TO_MASK.update(DIGIT_CODES)
CHAR_TO_MASK.update(LETTER_CODES)
CHAR_TO_MASK[" "] = SPACE_CODE

MASK_TO_CHAR = {}
for _ch, _m in CHAR_TO_MASK.items():
    MASK_TO_CHAR.setdefault(_m, _ch)


class EncodeError(ValueError):
    pass


def text_to_columns(text: str) -> list:
    """Encode text to a list of 12-bit column masks (not padded to 80)."""
    cols = []
    for ch in text.upper():
        if ch in CHAR_TO_MASK:
            cols.append(CHAR_TO_MASK[ch])
        else:
            # escape: ESCAPE_CODE, then the byte as two 6-bit columns
            b = ord(ch) & 0xFF
            cols.append(ESCAPE_CODE)
            cols.append(b & 0x3F)
            cols.append((b >> 6) & 0x3F)
    return cols


def columns_to_text(cols) -> str:
    """Decode column masks back to text."""
    out = []
    i = 0
    while i < len(cols):
        m = cols[i] & COLUMN_MASK
        if m == ESCAPE_CODE:
            if i + 2 >= len(cols):
                raise EncodeError("truncated escape sequence")
            b = (cols[i + 1] & 0x3F) | ((cols[i + 2] & 0x3F) << 6)
            out.append(chr(b))
            i += 3
            continue
        ch = MASK_TO_CHAR.get(m)
        if ch is None:
            raise EncodeError(
                f"column {i} is not a valid character punch: "
                f"{mask_to_rows(m)} (this is encrypted or binary data)"
            )
        out.append(ch)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# Binary layer: 6 bits per column in rows 0-5.
# --------------------------------------------------------------------------

BINARY_ROW_BITS = [ROW_TO_BIT[r] for r in range(6)]  # rows 0..5


def bytes_to_columns(data: bytes) -> list:
    """Pack bytes 6 bits per column, two bits of the next byte per column.

    Bit order: column n carries bits 6n..6n+5 of the bit stream, LSB first.
    """
    cols = []
    bitpos = 0
    total_bits = len(data) * 8
    while bitpos < total_bits:
        mask = 0
        for k in range(6):
            p = bitpos + k
            if p >= total_bits:
                break
            byte = data[p // 8]
            bit = (byte >> (p % 8)) & 1
            if bit:
                mask |= 1 << BINARY_ROW_BITS[k]
        cols.append(mask)
        bitpos += 6
    return cols


def columns_to_bytes(cols, nbytes: int) -> bytes:
    """Inverse of bytes_to_columns."""
    out = bytearray(nbytes)
    bitpos = 0
    for mask in cols:
        for k in range(6):
            p = bitpos + k
            if p >= nbytes * 8:
                break
            if (mask >> BINARY_ROW_BITS[k]) & 1:
                out[p // 8] |= 1 << (p % 8)
        bitpos += 6
    return bytes(out)


def is_binary_columns(cols) -> bool:
    """True if every column only uses rows 0-5 (i.e. binary, not text)."""
    allowed = 0
    for bit in BINARY_ROW_BITS:
        allowed |= 1 << bit
    return all((c & ~allowed) == 0 for c in cols)
