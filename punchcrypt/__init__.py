# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
"""punchcrypt — encrypt data onto IBM 80-column punched cards."""
from . import cipher, hollerith

__version__ = "1.0.0"
__all__ = ["cipher", "hollerith", "Card", "encrypt", "decrypt"]

Card = cipher.Card
encrypt = cipher.encrypt
decrypt = cipher.decrypt
