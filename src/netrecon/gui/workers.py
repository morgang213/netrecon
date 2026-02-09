"""Background worker thread for running tool operations."""

import re

from PySide6.QtCore import QThread, Signal


def strip_rich_tags(text: str) -> str:
    """Remove Rich markup tags like [red]...[/red] from text."""
    return re.sub(r"\[/?[a-z/ ]+\]", "", text)


class ToolWorker(QThread):
    """Runs a tool's core function in a background thread.

    Signals:
        finished(object): Emitted with the result on success.
        error(str): Emitted with an error message on failure.
    """

    finished = Signal(object)
    error = Signal(str)

    def __init__(self, func, inputs):
        super().__init__()
        self.func = func
        self.inputs = inputs

    def run(self):
        try:
            result = self.func(self.inputs)
            self.finished.emit(result)
        except SystemExit as e:
            msg = str(e)
            if not msg or msg in ("0", "1"):
                msg = "Operation failed — check your input parameters."
            self.error.emit(strip_rich_tags(msg))
        except Exception as e:
            self.error.emit(strip_rich_tags(f"{type(e).__name__}: {e}"))
