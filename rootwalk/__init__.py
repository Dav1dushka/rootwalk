"""rootwalk: a small iterative DNS resolver written from scratch."""
from .message import DNSFormatError, Message, Question, Record, build_query, decode, encode
from .resolver import ResolveError, Resolver, Result

__version__ = "0.1.0"
__all__ = ["DNSFormatError", "Message", "Question", "Record", "ResolveError", "Resolver", "Result",
           "build_query", "decode", "encode"]
