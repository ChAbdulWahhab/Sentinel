"""Logging setup."""
from __future__ import annotations
import logging
import sys
from pathlib import Path
from veylance.config import DEBUG_LOG_FILE


def setup_logger(verbose: bool = False, quiet: bool = False, debug: bool = False) -> logging.Logger:
    level = logging.DEBUG if (debug or verbose) else (logging.WARNING if quiet else logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    logger = logging.getLogger("veylance")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # stderr handler
    if debug or verbose:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(logging.Formatter(fmt))
        logger.addHandler(sh)
    elif not quiet:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.WARNING)
        sh.setFormatter(logging.Formatter(fmt))
        logger.addHandler(sh)

    # file handler: all debug output always goes to ~/.veylance/debug.log
    try:
        DEBUG_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(DEBUG_LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt))
        logger.addHandler(fh)
    except Exception:
        pass

    return logger