"""Protocol executors for HTTP and non-HTTP reproduction."""

from cve_hunter.executors.base import (
    PROTOCOL_DATABASE,
    PROTOCOL_HTTP,
    PROTOCOL_KERNEL,
    PROTOCOL_TCP,
    PROTOCOL_UNSUPPORTED,
    build_execution_spec,
    execute_spec,
    infer_protocol,
)
from cve_hunter.executors.database import execute_database_spec

__all__ = [
    "PROTOCOL_DATABASE",
    "PROTOCOL_HTTP",
    "PROTOCOL_KERNEL",
    "PROTOCOL_TCP",
    "PROTOCOL_UNSUPPORTED",
    "build_execution_spec",
    "execute_database_spec",
    "execute_spec",
    "infer_protocol",
]
