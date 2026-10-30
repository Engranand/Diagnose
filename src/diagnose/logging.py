"""Structured logging configuration using *structlog*.

In **development** output is pretty-printed to the console.
In **production** output is machine-readable JSON (one object per line).

The correlation-ID middleware binds ``correlation_id``, ``method``, and
``path`` into the structlog context-vars so every log line emitted during
a request automatically includes them.
"""

from __future__ import annotations

import logging
import sys

import structlog

from diagnose.settings import Settings


def setup_logging(settings: Settings) -> None:
    """Configure structlog and the standard-library root logger."""

    log_level = logging.DEBUG if settings.DEBUG else logging.INFO

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.format_exc_info,
    ]

    if settings.ENVIRONMENT == "development":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Standard-library root logger
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=log_level)

    # Quieten noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.DATABASE_ECHO else logging.WARNING
    )
