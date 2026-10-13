"""SentinelScan utility package.

  - logger.py      -> setup_logger() (file + stderr)
  - validators.py  -> is_url(), is_valid_host()
  - colors.py      -> SEV_HEX severity color map
  - wordlists.py   -> load() bundled wordlists from data/
"""

from sentinelscan.utils.logger import setup_logger
from sentinelscan.utils.validators import is_url, is_valid_host
from sentinelscan.utils.colors import SEV_HEX
from sentinelscan.utils.wordlists import load as load_wordlist

__all__ = [
    "setup_logger",
    "is_url",
    "is_valid_host",
    "SEV_HEX",
    "load_wordlist",
]