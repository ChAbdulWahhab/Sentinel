"""Veylance utility package.

  - logger.py      -> setup_logger() (file + stderr)
  - validators.py  -> is_url(), is_valid_host()
  - colors.py      -> SEV_HEX severity color map
  - wordlists.py   -> load() bundled wordlists from data/
"""

from veylance.utils.logger import setup_logger
from veylance.utils.validators import is_url, is_valid_host
from veylance.utils.colors import SEV_HEX
from veylance.utils.wordlists import load as load_wordlist

__all__ = [
    "setup_logger",
    "is_url",
    "is_valid_host",
    "SEV_HEX",
    "load_wordlist",
]