"""
OmniSight-OSINT Structured Logging
==================================
Configures centralized, structured logging leveraging Python's standard `logging`
subsystem combined with `rich.logging.RichHandler` for clean visual output.
"""

import logging
import sys
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler

_LOGGER_INITIALIZED = False


def setup_logger(
    name: str = "OmniSight",
    level: int = logging.INFO,
    console: Optional[Console] = None
) -> logging.Logger:
    """Set up and configure a structured logger instance with RichHandler.

    Args:
        name: Logger identifier name.
        level: Logging level (e.g. logging.DEBUG, logging.INFO).
        console: Optional existing Rich console instance to avoid duplicate handles.

    Returns:
        Configured logging.Logger instance.
    """
    global _LOGGER_INITIALIZED
    logger = logging.getLogger(name)

    if not _LOGGER_INITIALIZED:
        logger.setLevel(level)

        # Clear existing handlers to prevent duplicate output
        while logger.handlers:
            logger.handlers.pop()

        rich_handler = RichHandler(
            console=console or Console(stderr=True),
            show_time=True,
            show_level=True,
            show_path=False,
            rich_tracebacks=True,
            markup=True
        )
        rich_handler.setLevel(level)

        formatter = logging.Formatter(
            fmt="[%(name)s] %(message)s",
            datefmt="%X"
        )
        rich_handler.setFormatter(formatter)
        logger.addHandler(rich_handler)

        logger.propagate = False
        _LOGGER_INITIALIZED = True
    else:
        logger.setLevel(level)
        for h in logger.handlers:
            h.setLevel(level)

    return logger


def get_logger(name: str = "OmniSight") -> logging.Logger:
    """Retrieve the shared logger instance."""
    return logging.getLogger(name)
