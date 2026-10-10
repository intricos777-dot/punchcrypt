"""punchcrypt — encrypt data onto IBM 80-column punched cards."""
from . import cipher, hollerith

__version__ = "1.0.0"
__all__ = ["cipher", "hollerith", "Card", "encrypt", "decrypt"]

Card = cipher.Card
encrypt = cipher.encrypt
decrypt = cipher.decrypt
