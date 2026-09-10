"""
Structured logging module for LPE-AutoScan.
"""

import logging
import sys
from typing import Optional


def setup_logger(verbose: bool = False, quiet: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("lpe_autoscan")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    if quiet:
        console_level = logging.ERROR
    elif verbose:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger
