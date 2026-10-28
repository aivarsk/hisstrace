"""Hisstrace: programmable syscall interception and fault injection in Python.

strace, with fangs.
"""

from importlib.metadata import PackageNotFoundError, version

from .arch import current
from .scenario import CompletedCall, IOVec, Matcher, Sockaddr, Timespec, any_of, arg_names, on, post, pre, run, tracer
from .trace import Child, Event, TraceeExited, Tracer, Trap

try:
    __version__ = version("hisstrace")  # from the installed package metadata
except PackageNotFoundError:  # running from a source checkout
    __version__ = "dev"

__all__ = [
    "Child",
    "CompletedCall",
    "Event",
    "IOVec",
    "Matcher",
    "Sockaddr",
    "Timespec",
    "TraceeExited",
    "Tracer",
    "Trap",
    "any_of",
    "arg_names",
    "current",
    "on",
    "post",
    "pre",
    "run",
    "tracer",
    "__version__",
]
