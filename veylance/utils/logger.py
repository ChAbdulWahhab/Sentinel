"""Logging setup."""
from __future__ import annotations
import logging
import sys
from pathlib import Path
from veylance.config import CONFIG_DIR


def setup_logger(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    log_file = CONFIG_DIR / "veylance.log"
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    logger = logging.getLogger("veylance")
    logger.setLevel(level)
    logger.handlers.clear()

    # stderr (when verbose)
    if verbose:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(logging.Formatter(fmt))
        logger.addHandler(sh)

    # file always
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt))
    logger.addHandler(fh)
    return logger