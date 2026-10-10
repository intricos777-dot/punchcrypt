"""
Card-level encryption.

Design, and why it is shaped this way:

The cipher operates on 80-column cards, not on bytes. Each column is 12 bits,
which is a genuinely awkward width (12 does not divide 8, 16 or 32), so the
usual "treat it as a byte stream" shortcut does not apply. A card is instead a
960-bit block.

Everything security-bearing is a standard primitive, from `cryptography`:

  - key derivation  : HKDF-SHA256, separate keys for encryption and MAC
  - confidentiality : ChaCha20 keystream, per-deck random nonce
  - integrity       : HMAC-SHA256, truncated to a 16-byte tag

The card format is framing, not a cryptographic primitive. The point of the
framing is that the output is a legitimate punch card: every column is a valid
12-bit punch, so a real keypunch could have produced the deck.

Deck layout
-----------
Card 0 carries the header (46 columns) plus the first 34 payload columns.
Cards 1..n-1 hold 80 payload columns each. Keeping the header on a single card
means the overhead is one card for the whole deck instead of a tax on every
card.

The naive version of this idea (XOR the card with a repeating key stream) was
rejected deliberately: with a 960-bit card and a keystream that repeats, an
attacker holding two ciphertexts can cancel the keystream and recover the XOR
of the plaintexts. The keystream here is generated per deck from a random
nonce, so that attack does not apply, and the MAC catches tampering.

One MAC covers the whole deck, so reordering, dropping or substituting a card
invalidates it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import hollerith

MAGIC = b"PC01"          # punchcrypt, format version 1
SALT_LEN = 8
NONCE_LEN = 16           # cryptography's ChaCha20 requires a 128-bit nonce
MAC_LEN = 16
KEY_LEN = 32

# Header layout, in card columns (card 0 only):
#   0-3   magic "PC01"
#   4     format byte (1)
#   5-6   payload length in bytes, big-endian uint16
#   7-8   total cards, big-endian uint16
#   9     flags
#   10-17 salt (8 bytes)
#   18-33 nonce (16 bytes)
#   34-49 MAC (16 bytes)
_OFF_MAGIC = 0
_OFF_FORMAT = 4
_OFF_LEN = 5
_OFF_CARDS = 7
_OFF_FLAGS = 9
_OFF_SALT = 10
_OFF_NONCE = 18
_OFF_MAC = 34
HEADER_COLS = 50

PAYLOAD_CARD0 = hollerith.COLS - HEADER_COLS   # 30
PAYLOAD_REST = hollerith.COLS                  # 80

FLAG_TEXT = 0x01
MAX_PAYLOAD = 0xFFFF


class PunchcryptError(Exception):
    pass


class IntegrityError(PunchcryptError):
    pass


class FormatError(PunchcryptError):
    pass


def _pack_bytes(data: bytes, ncols: int) -> list:
    """Bytes -> ncols column masks, 8 bits per column, zero padded."""
    padded = data.ljust(ncols, b"\x00")
    return [padded[i] for i in range(ncols)]


def _unpack_bytes(cols) -> bytes:
    return bytes(c & 0xFF for c in cols)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt,
                info=b"punchcrypt/v1/enc")
    return hkdf.derive(passphrase.encode("utf-8"))


def derive_mac_key(passphrase: str, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt,
                info=b"punchcrypt/v1/mac")
    return hkdf.derive(passphrase.encode("utf-8"))


def _keystream(key: bytes, nonce: bytes, ncols: int) -> bytes:
    """ChaCha20 keystream, one byte per column."""
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    return cipher.encryptor().update(b"\x00" * ncols)


@dataclass
class Card:
    """One punched card: 80 columns of 12-bit masks."""
    columns: list

    def __post_init__(self):
        if len(self.columns) != hollerith.COLS:
            raise FormatError(
                f"a card has {hollerith.COLS} columns, got {len(self.columns)}")
        for i, c in enumerate(self.columns):
            if c & ~hollerith.COLUMN_MASK:
                raise FormatError(f"column {i} exceeds 12 bits: {c:#x}")

    def to_rows(self) -> list:
        return [hollerith.mask_to_rows(c) for c in self.columns]

    def render(self) -> str:
        """Text-art rendering of the card, as it would look punched.

        Each column is drawn as two characters, so the column ruler above the
        card is spaced the same way -- otherwise the digits do not line up with
        the columns they label.
        """
        tens = "     " + "".join(str((i // 10) % 10) + " " for i in range(1, 81))
        ones = "     " + "".join(str(i % 10) + " " for i in range(1, 81))
        lines = [tens, ones,
                 "    +" + "-" * 160 + "+"]
        for label in hollerith.ROW_LABELS:
            bit = hollerith.ROW_TO_BIT[label]
            row = "".join("[]" if (col & (1 << bit)) else "  "
                          for col in self.columns)
            lines.append(f"{label:>3} |{row}|")
        lines.append("    +" + "-" * 160 + "+")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"columns": [f"{c:03x}" for c in self.columns]}

    @classmethod
    def from_dict(cls, d: dict) -> "Card":
        return cls([int(c, 16) for c in d["columns"]])


def _capacity(ncards: int) -> int:
    return PAYLOAD_CARD0 + PAYLOAD_REST * (ncards - 1)


def _split_message(data: bytes) -> list:
    """Split payload across cards: 34 columns on card 0, 80 on the rest."""
    if len(data) <= PAYLOAD_CARD0:
        return [data]
    chunks = [data[:PAYLOAD_CARD0]]
    rest = data[PAYLOAD_CARD0:]
    for i in range(0, len(rest), PAYLOAD_REST):
        chunks.append(rest[i:i + PAYLOAD_REST])
    return chunks


def encrypt(data: bytes, passphrase: str, *, text_mode: bool = False) -> list:
    """Encrypt bytes into a deck of Cards."""
    if not passphrase:
        raise PunchcryptError("empty passphrase")
    if len(data) > MAX_PAYLOAD:
        raise PunchcryptError(
            f"payload is {len(data)} bytes; the header length field caps a "
            f"deck at {MAX_PAYLOAD}")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)
    mac_key = derive_mac_key(passphrase, salt)

    chunks = _split_message(data)
    ncards = len(chunks)

    total_cols = sum(len(c) for c in chunks)
    ks = _keystream(key, nonce, total_cols)

    enc_chunks = []
    off = 0
    for chunk in chunks:
        enc_chunks.append([chunk[i] ^ ks[off + i] for i in range(len(chunk))])
        off += len(chunk)

    header = bytearray(HEADER_COLS)
    header[_OFF_MAGIC:_OFF_MAGIC + 4] = MAGIC
    header[_OFF_FORMAT] = 1
    struct.pack_into(">H", header, _OFF_LEN, len(data))
    struct.pack_into(">H", header, _OFF_CARDS, ncards)
    header[_OFF_FLAGS] = FLAG_TEXT if text_mode else 0
    header[_OFF_SALT:_OFF_SALT + SALT_LEN] = salt
    header[_OFF_NONCE:_OFF_NONCE + NONCE_LEN] = nonce

    # Lay the cards out first, padded to a full 80 columns, so the tag covers
    # exactly the bytes that appear on the punch cards. Computing it over the
    # unpadded chunks instead would make encrypt and decrypt disagree about the
    # final card's zero padding.
    card_cols = []
    for i, enc in enumerate(enc_chunks):
        cols = (_pack_bytes(bytes(header), HEADER_COLS) + enc) if i == 0 else list(enc)
        cols = cols + [0] * (hollerith.COLS - len(cols))
        card_cols.append(cols)

    flat = [c for cols in card_cols for c in cols]
    mac = hmac.new(mac_key, bytes(flat), hashlib.sha256).digest()[:MAC_LEN]
    for k in range(MAC_LEN):
        card_cols[0][_OFF_MAC + k] = mac[k]

    return [Card(cols) for cols in card_cols]


def decrypt(cards: list, passphrase: str) -> bytes:
    """Decrypt a deck of Cards back to bytes."""
    if not cards:
        raise FormatError("no cards")
    if not passphrase:
        raise PunchcryptError("empty passphrase")

    header = _unpack_bytes(cards[0].columns[:HEADER_COLS])
    if header[_OFF_MAGIC:_OFF_MAGIC + 4] != MAGIC:
        raise FormatError("not a punchcrypt card (bad magic)")
    if header[_OFF_FORMAT] != 1:
        raise FormatError(f"unsupported format version {header[_OFF_FORMAT]}")

    length = struct.unpack_from(">H", header, _OFF_LEN)[0]
    ncards = struct.unpack_from(">H", header, _OFF_CARDS)[0]
    if ncards != len(cards):
        raise FormatError(f"deck is {len(cards)} cards, header says {ncards}")
    if length > _capacity(ncards):
        raise FormatError(
            f"header claims {length} payload bytes but {ncards} card(s) hold "
            f"at most {_capacity(ncards)}")

    salt = header[_OFF_SALT:_OFF_SALT + SALT_LEN]
    nonce = header[_OFF_NONCE:_OFF_NONCE + NONCE_LEN]
    mac_expected = bytes(header[_OFF_MAC:_OFF_MAC + MAC_LEN])

    # The tag covers the punched card image: every column of every card, with
    # the MAC field itself zeroed. Rebuild exactly that and compare.
    flat = [c for card in cards for c in card.columns]
    for k in range(MAC_LEN):
        flat[_OFF_MAC + k] = 0

    mac_key = derive_mac_key(passphrase, salt)
    mac_actual = hmac.new(mac_key, bytes(flat), hashlib.sha256).digest()[:MAC_LEN]
    if not hmac.compare_digest(mac_expected, mac_actual):
        raise IntegrityError(
            "MAC mismatch — wrong passphrase, or the deck was altered")

    # Ciphertext columns: card 0's payload starts after the header.
    payload = []
    for i, card in enumerate(cards):
        payload.extend(card.columns[HEADER_COLS:] if i == 0 else card.columns)

    key = derive_key(passphrase, salt)
    ks = _keystream(key, nonce, len(payload))
    return bytes((payload[i] ^ ks[i]) & 0xFF for i in range(length))


def encrypt_text(text: str, passphrase: str) -> list:
    """Encrypt a string.

    The payload is the UTF-8 bytes, not Hollerith column masks. Those masks are
    12-bit values and this cipher's column payload is 8 bits, so passing them
    through would truncate the zone punches (A = rows 12+1 = 0x802 would lose
    its zone and come back as a digit). The encrypted deck is random bits in any
    case, so it is not Hollerith-readable; the hollerith module remains the way
    to render or read *plaintext* cards.
    """
    return encrypt(text.encode("utf-8"), passphrase, text_mode=True)


def decrypt_text(cards: list, passphrase: str) -> str:
    return decrypt(cards, passphrase).decode("utf-8")
