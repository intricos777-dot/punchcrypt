# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
"""Tests for punchcrypt.

Grouped by what they defend:
  - Hollerith layer: the character table is the real one, and round-trips.
  - Cipher: round-trips, every card is a valid 12-bit punch, integrity holds.
  - Attacks that were considered and must fail.
"""
import os
import struct

import pytest

from punchcrypt import cipher, hollerith


# --------------------------------------------------------------------------
# Hollerith layer
# --------------------------------------------------------------------------

def test_row_bit_mapping_is_12_bits():
    assert len(hollerith.ROW_TO_BIT) == 12
    assert len(set(hollerith.ROW_TO_BIT.values())) == 12
    assert sorted(hollerith.ROW_TO_BIT.values()) == list(range(12))


def test_digits_are_single_punches():
    for d in range(10):
        mask = hollerith.CHAR_TO_MASK[str(d)]
        assert mask.bit_count() == 1, f"digit {d} should be one punch"
        assert hollerith.mask_to_rows(mask) == [d]


def test_letters_are_two_punches():
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        mask = hollerith.CHAR_TO_MASK[ch]
        assert mask.bit_count() == 2, f"letter {ch} should be zone + digit"


def test_known_hollerith_letter_codes():
    # A = 12+1, I = 12+9, J = 11+1, R = 11+9, S = 0+2, Z = 0+9
    assert hollerith.mask_to_rows(hollerith.CHAR_TO_MASK["A"]) == [12, 1]
    assert hollerith.mask_to_rows(hollerith.CHAR_TO_MASK["I"]) == [12, 9]
    assert hollerith.mask_to_rows(hollerith.CHAR_TO_MASK["J"]) == [11, 1]
    assert hollerith.mask_to_rows(hollerith.CHAR_TO_MASK["R"]) == [11, 9]
    assert hollerith.mask_to_rows(hollerith.CHAR_TO_MASK["S"]) == [0, 2]
    assert hollerith.mask_to_rows(hollerith.CHAR_TO_MASK["Z"]) == [0, 9]


def test_space_is_no_punch():
    assert hollerith.CHAR_TO_MASK[" "] == 0


def test_text_roundtrip_uppercase():
    text = "HELLO WORLD 123 ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cols = hollerith.text_to_columns(text)
    assert hollerith.columns_to_text(cols) == text


def test_text_roundtrip_with_punctuation_via_escape():
    text = "HELLO, WORLD! 100% *SAFE*"
    cols = hollerith.text_to_columns(text)
    assert hollerith.columns_to_text(cols) == text.upper()


def test_escape_marker_is_not_used_by_any_character():
    # ESCAPE_CODE must not collide with a real character, or decoding is
    # ambiguous.
    assert hollerith.ESCAPE_CODE not in hollerith.MASK_TO_CHAR


def test_binary_roundtrip():
    data = os.urandom(97)
    cols = hollerith.bytes_to_columns(data)
    assert hollerith.columns_to_bytes(cols, len(data)) == data


def test_binary_uses_only_rows_0_to_5():
    cols = hollerith.bytes_to_columns(b"\xff\xff\xff")
    assert hollerith.is_binary_columns(cols)


# --------------------------------------------------------------------------
# Cipher
# --------------------------------------------------------------------------

PW = "correct horse battery staple"


def test_roundtrip_empty():
    cards = cipher.encrypt(b"", PW)
    assert cipher.decrypt(cards, PW) == b""


def test_roundtrip_short():
    for n in (1, 5, 9, 10, 11, 79, 80, 81):
        data = os.urandom(n)
        assert cipher.decrypt(cipher.encrypt(data, PW), PW) == data, f"n={n}"


def test_roundtrip_multi_card():
    data = os.urandom(1000)
    cards = cipher.encrypt(data, PW)
    assert len(cards) > 1
    assert cipher.decrypt(cards, PW) == data


def test_every_column_is_a_valid_12_bit_punch():
    cards = cipher.encrypt(os.urandom(500), PW)
    for card in cards:
        assert len(card.columns) == 80
        for col in card.columns:
            assert 0 <= col <= 0xFFF, f"column out of range: {col:#x}"


def test_header_lands_in_valid_punches():
    # The magic must survive the 8-bits-per-column packing.
    cards = cipher.encrypt(b"x", PW)
    header = cipher._unpack_bytes(cards[0].columns[:cipher.HEADER_COLS])
    assert header[:4] == cipher.MAGIC


def test_wrong_passphrase_is_refused_not_garbage():
    cards = cipher.encrypt(b"secret payload", PW)
    with pytest.raises(cipher.IntegrityError):
        cipher.decrypt(cards, "wrong passphrase")


def test_empty_passphrase_rejected():
    with pytest.raises(cipher.PunchcryptError):
        cipher.encrypt(b"x", "")
    cards = cipher.encrypt(b"x", PW)
    with pytest.raises(cipher.PunchcryptError):
        cipher.decrypt(cards, "")


def test_same_plaintext_twice_gives_different_cards():
    a = cipher.encrypt(b"same message", PW)
    b = cipher.encrypt(b"same message", PW)
    assert [c.columns for c in a] != [c.columns for c in b]


# --------------------------------------------------------------------------
# Attacks that must fail
# --------------------------------------------------------------------------

def test_keystream_reuse_attack_does_not_apply():
    """Two encryptions of the same plaintext must not share a keystream.

    The naive design (XOR with a fixed repeating key) leaks P1 XOR P2 when two
    ciphertexts are compared. With a per-card random nonce, the difference of
    two payloads must not equal the difference of the plaintexts.
    """
    msg = b"A" * 200
    c1 = cipher.encrypt(msg, PW)[0].columns[cipher.HEADER_COLS:cipher.HEADER_COLS + 100]
    c2 = cipher.encrypt(msg, PW)[0].columns[cipher.HEADER_COLS:cipher.HEADER_COLS + 100]
    assert c1 != c2
    # If a keystream were shared, c1 XOR c2 would be 0 for identical plaintext.
    assert any(a ^ b for a, b in zip(c1, c2))


def test_bit_flip_in_ciphertext_is_detected():
    cards = cipher.encrypt(b"payload to protect", PW)
    col = cipher.HEADER_COLS + 2
    cards[0].columns[col] ^= 0x01
    with pytest.raises(cipher.IntegrityError):
        cipher.decrypt(cards, PW)


def test_bit_flip_in_header_is_detected():
    cards = cipher.encrypt(b"payload to protect", PW)
    cards[0].columns[cipher._OFF_FLAGS] ^= 0x01
    with pytest.raises((cipher.IntegrityError, cipher.FormatError)):
        cipher.decrypt(cards, PW)


def test_card_reordering_is_detected():
    data = os.urandom(400)
    cards = cipher.encrypt(data, PW)
    assert len(cards) >= 2
    swapped = [cards[1], cards[0]] + cards[2:]
    with pytest.raises(cipher.FormatError):
        cipher.decrypt(swapped, PW)


def test_card_substitution_between_decks_is_detected():
    a = cipher.encrypt(os.urandom(400), PW)
    b = cipher.encrypt(os.urandom(400), PW)
    mixed = [a[0], b[1]]
    with pytest.raises((cipher.FormatError, cipher.IntegrityError)):
        cipher.decrypt(mixed, PW)


def test_truncated_deck_is_detected():
    cards = cipher.encrypt(os.urandom(400), PW)
    with pytest.raises(cipher.FormatError):
        cipher.decrypt(cards[:1], PW)


def test_non_punchcrypt_card_is_rejected():
    junk = cipher.Card([0] * 80)
    with pytest.raises(cipher.FormatError):
        cipher.decrypt([junk], PW)


def test_card_rejects_out_of_range_column():
    with pytest.raises(cipher.FormatError):
        cipher.Card([0x1000] + [0] * 79)


def test_card_rejects_wrong_width():
    with pytest.raises(cipher.FormatError):
        cipher.Card([0] * 79)


# --------------------------------------------------------------------------
# Text mode end to end
# --------------------------------------------------------------------------

def test_text_mode_roundtrip():
    text = "ATTACK AT DAWN"
    cards = cipher.encrypt_text(text, PW)
    assert cipher.decrypt_text(cards, PW) == text


def test_text_mode_preserves_punctuation():
    text = "MEET ME AT 5PM, BRING $100."
    cards = cipher.encrypt_text(text, PW)
    assert cipher.decrypt_text(cards, PW) == text


def test_render_produces_80_columns_per_row():
    cards = cipher.encrypt(b"x", PW)
    art = cards[0].render()
    lines = art.splitlines()
    body = [ln for ln in lines if ln.startswith((" 12", " 11")) or
            (len(ln) > 4 and ln[4] == "|")]
    assert body, "no card rows rendered"
    for ln in body:
        assert len(ln.split("|")[1]) == 160  # 80 columns of two chars
