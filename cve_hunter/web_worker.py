"""Isolated CVE process. Cancellation unwinds workflow cleanup when possible."""
from __future__ import annotations

import os
import signal
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path


class RunCancelled(BaseException):
    pass


def execute(connection, cancelled, cve: str, options: dict) -> None:
    if os.name != "nt":
        os.setsid()
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(RunCancelled()))

    def progress(event):
        if cancelled.is_set():
            raise RunCancelled()
        connection.send({"event": "progress", "data": event})

    directory = Path(options["output_dir"]) / cve
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with (directory / "worker.log").open("a", encoding="utf-8") as log, redirect_stdout(log), redirect_stderr(log):
            from main import run_cve
            if cancelled.is_set():
                raise RunCancelled()
            result = run_cve(cve, show_details=False, generate_report=True, on_progress=progress, **options)
            connection.send({"event": "result", "data": result})
    except RunCancelled:
        connection.send({"event": "cancelled"})
    except Exception as exc:
        connection.send({"event": "error", "data": str(exc)})
    finally:
        connection.close()
