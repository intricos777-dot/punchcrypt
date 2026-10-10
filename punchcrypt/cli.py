#!/usr/bin/env python3
"""punchcrypt — encrypt data onto IBM 80-column punched cards.

A deck of cards is the ciphertext. Every column is a valid 12-bit punch, so the
output is a card a real keypunch could have produced.

Crypto is standard: HKDF-SHA256 key derivation, ChaCha20 keystream,
encrypt-then-MAC with HMAC-SHA256. The card format is framing, not a cipher.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import cipher, hollerith


def _passphrase(args) -> str:
    if args.passphrase_file:
        return Path(args.passphrase_file).read_text().strip()
    if args.passphrase_env:
        import os
        val = os.environ.get(args.passphrase_env)
        if not val:
            sys.exit(f"environment variable {args.passphrase_env} is empty")
        return val
    first = getpass.getpass("passphrase: ")
    if not first:
        sys.exit("empty passphrase")
    again = getpass.getpass("again: ")
    if first != again:
        sys.exit("passphrases do not match")
    return first


def _deck_json(cards) -> str:
    return json.dumps({"format": "punchcrypt/1",
                       "cards": [c.to_dict() for c in cards]}, indent=2)


def _load_deck(path: str):
    data = json.loads(Path(path).read_text())
    if data.get("format") != "punchcrypt/1":
        sys.exit(f"{path}: not a punchcrypt deck")
    return [cipher.Card.from_dict(d) for d in data["cards"]]


def cmd_encode(args):
    raw = Path(args.input).read_bytes() if args.input else sys.stdin.buffer.read()
    cards = cipher.encrypt(raw, _passphrase(args))
    out = _deck_json(cards)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"wrote {len(cards)} card(s) to {args.output}")
    else:
        print(out)


def cmd_decode(args):
    cards = _load_deck(args.deck)
    try:
        raw = cipher.decrypt(cards, _passphrase(args))
    except cipher.PunchcryptError as exc:
        sys.exit(f"refused: {exc}")
    if args.output:
        Path(args.output).write_bytes(raw)
        print(f"wrote {len(raw)} bytes to {args.output}")
    else:
        sys.stdout.buffer.write(raw)


def cmd_text_encode(args):
    text = args.text if args.text is not None else sys.stdin.read()
    cards = cipher.encrypt_text(text, _passphrase(args))
    out = _deck_json(cards)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"wrote {len(cards)} card(s) to {args.output}")
    else:
        print(out)


def cmd_text_decode(args):
    cards = _load_deck(args.deck)
    try:
        print(cipher.decrypt_text(cards, _passphrase(args)))
    except cipher.PunchcryptError as exc:
        sys.exit(f"refused: {exc}")


def cmd_render(args):
    cards = _load_deck(args.deck)
    for i, card in enumerate(cards):
        if len(cards) > 1:
            print(f"=== card {i + 1} of {len(cards)} ===")
        print(card.render())
        if i + 1 < len(cards):
            print()


def cmd_table(args):
    """Show the Hollerith character table this build implements."""
    print("Hollerith code, as implemented (12-row IBM card)")
    print()
    print(f"{'char':<6}{'punches':<16}{'rows':<12}{'mask':<8}")
    print("-" * 44)
    items = sorted(hollerith.CHAR_TO_MASK.items(),
                   key=lambda kv: (kv[1].bit_count(), kv[1]))
    for ch, mask in items:
        rows = hollerith.mask_to_rows(mask)
        shown = "space" if ch == " " else ch
        print(f"{shown!r:<6}{mask.bit_count():<16}{str(rows):<12}{mask:#06x}")
    print()
    print("Letters use two punches (zone + digit): 12+1..9 = A..I,")
    print("11+1..9 = J..R, 0+2..9 = S..Z. Space is no punch at all.")
    print("Punctuation is not claimed: keypunch models disagreed, so arbitrary")
    print("characters travel through an escape sequence instead.")


def cmd_selftest(args):
    import subprocess
    here = Path(__file__).resolve().parent.parent
    test = here / "tests" / "test_punchcrypt.py"
    if not test.exists():
        sys.exit(f"no test file at {test}")
    return subprocess.call([sys.executable, "-m", "pytest", str(test), "-q"])


def build_parser():
    p = argparse.ArgumentParser(
        prog="punchcrypt",
        description="Encrypt data onto IBM 80-column punched cards.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-o", "--output", help="write here instead of stdout")
        sp.add_argument("-p", "--passphrase-file",
                        help="read the passphrase from this file")
        sp.add_argument("-e", "--passphrase-env",
                        help="read the passphrase from this environment variable")

    sp = sub.add_parser("encode", help="encrypt a file (or stdin) into a card deck")
    sp.add_argument("input", nargs="?", help="file to encrypt; omit for stdin")
    common(sp)
    sp.set_defaults(func=cmd_encode)

    sp = sub.add_parser("decode", help="decrypt a card deck")
    sp.add_argument("deck")
    common(sp)
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("text-encode", help="encrypt text as Hollerith punches")
    sp.add_argument("-t", "--text", help="the text; omit for stdin")
    common(sp)
    sp.set_defaults(func=cmd_text_encode)

    sp = sub.add_parser("text-decode", help="decrypt a Hollerith card deck")
    sp.add_argument("deck")
    common(sp)
    sp.set_defaults(func=cmd_text_decode)

    sp = sub.add_parser("render", help="draw a deck as punched cards")
    sp.add_argument("deck")
    sp.set_defaults(func=cmd_render)

    sp = sub.add_parser("table", help="show the Hollerith code table")
    sp.set_defaults(func=cmd_table)

    sp = sub.add_parser("selftest", help="run the test suite")
    sp.set_defaults(func=cmd_selftest)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
