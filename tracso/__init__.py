"""tracso - trace shared-object origins of a running process."""

import sys as _sys
from importlib.metadata import version

__author__ = "Leinier Orama"
__copyright__ = "Copyright 2026, Leinier Orama"
__credits__ = ["Leinier Orama"]
__maintainer__ = "Leinier Orama"
__email__ = "lof310w@gmail.com"
__version__ = "1.0.0"

_sys.setrecursionlimit(10000)

try:
    from loguru import logger  # type: ignore
except ImportError:

    class NewLogger:  # Fallback Logger
        """Minimal loguru-compatible shim backed by print()."""

        def _emit(self, level, message, *args, **kwargs):
            try:
                text = message.format(*args, **kwargs) if (args or kwargs) else message
            except Exception:
                text = message
            print(f"[{level}] {text}", file=_sys.stderr)

        def trace(self, m, *a, **kw):
            self._emit("TRACE", m, *a, **kw)

        def debug(self, m, *a, **kw):
            self._emit("DEBUG", m, *a, **kw)

        def info(self, m, *a, **kw):
            self._emit("INFO", m, *a, **kw)

        def success(self, m, *a, **kw):
            self._emit("SUCCESS", m, *a, **kw)

        def warning(self, m, *a, **kw):
            self._emit("WARNING", m, *a, **kw)

        def error(self, m, *a, **kw):
            self._emit("ERROR", m, *a, **kw)

        def critical(self, m, *a, **kw):
            self._emit("CRITICAL", m, *a, **kw)

    logger = NewLogger()

__all__ = ["__version__", "__author__", "__license__", "logger"]
