"""Iterative DNS resolution, the way a recursive resolver does it.

Start at a root server, ask the question, and follow referrals
(root → TLD servers → the domain's own name servers) until someone answers
authoritatively. Every hop is recorded so the CLI can show the path.
"""
from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass, field

from .message import TYPES, DNSFormatError, Message, Record, build_query, decode, normalize, type_name

# IANA root hints (named.root). IPv4 only, which works on every network.
ROOT_HINTS: list[tuple[str, str]] = [
    ("a.root-servers.net.", "198.41.0.4"), ("b.root-servers.net.", "170.247.170.2"),
    ("c.root-servers.net.", "192.33.4.12"), ("d.root-servers.net.", "199.7.91.13"),
    ("e.root-servers.net.", "192.203.230.10"), ("f.root-servers.net.", "192.5.5.241"),
    ("g.root-servers.net.", "192.112.36.4"), ("h.root-servers.net.", "198.97.190.53"),
    ("i.root-servers.net.", "192.36.148.17"), ("j.root-servers.net.", "192.58.128.30"),
    ("k.root-servers.net.", "193.0.14.129"), ("l.root-servers.net.", "199.7.83.42"),
    ("m.root-servers.net.", "202.12.27.33"),
]


class ResolveError(RuntimeError):
    pass


@dataclass
class Step:
    """One question sent to one server, for the trace."""
    depth: int
    server: str
    address: str
    question: str
    outcome: str
    ms: float


@dataclass
class Result:
    name: str
    qtype: int
    rcode: str = "NOERROR"
    records: list[Record] = field(default_factory=list)
    trace: list[Step] = field(default_factory=list)
    from_cache: bool = False


class Cache:
    """Records keyed by (name, type), dropped when their TTL runs out."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._data: dict[tuple[str, int], tuple[float, list[Record]]] = {}

    def get(self, name: str, qtype: int) -> list[Record] | None:
        hit = self._data.get((name, qtype))
        if not hit:
            return None
        expires, records = hit
        if self.clock() >= expires:
            del self._data[(name, qtype)]
            return None
        return records

    def put(self, name: str, qtype: int, records: list[Record]) -> None:
        if records:
            ttl = min(r.ttl for r in records)
            if ttl > 0:
                self._data[(name, qtype)] = (self.clock() + ttl, records)


class Resolver:
    def __init__(self, roots: list[tuple[str, str]] | None = None, port: int = 53, timeout: float = 2.0,
                 retries: int = 1, max_hops: int = 24, cache: Cache | None = None):
        self.roots = roots or ROOT_HINTS
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.max_hops = max_hops
        self.cache = cache if cache is not None else Cache()

    # -- public ------------------------------------------------------------
    def resolve(self, name: str, qtype: int | str = "A") -> Result:
        qtype = TYPES[qtype.upper()] if isinstance(qtype, str) else qtype
        result = Result(normalize(name), qtype)
        self._resolve(result.name, qtype, result, depth=0)
        return result

    # -- iterative algorithm ---------------------------------------------------
    def _resolve(self, name: str, qtype: int, result: Result, depth: int) -> list[Record]:
        if depth > 8:
            raise ResolveError("too many nested lookups (CNAME or name-server loop?)")
        cached = self.cache.get(name, qtype)
        if cached is not None:
            if depth == 0:
                result.records, result.from_cache = cached, True
            return cached

        servers = list(self.roots)
        random.shuffle(servers)  # spread load across root servers, as real resolvers do
        for _ in range(self.max_hops):
            resp, (ns_name, ns_ip), ms = self._ask_any(servers, name, qtype)
            question = f"{name} {type_name(qtype)}"

            if resp.rcode != 0:
                result.trace.append(Step(depth, ns_name, ns_ip, question, resp.rcode_name, ms))
                if depth == 0:
                    result.rcode = resp.rcode_name
                return []

            exact = [r for r in resp.answers if r.name == name and r.rtype == qtype]
            if exact:
                result.trace.append(Step(depth, ns_name, ns_ip, question, f"answer ({len(exact)})", ms))
                self.cache.put(name, qtype, exact)
                if depth == 0:
                    result.records = exact
                return exact

            cname = next((r for r in resp.answers if r.name == name and r.rtype == TYPES["CNAME"]), None)
            if cname:
                target = cname.data
                result.trace.append(Step(depth, ns_name, ns_ip, question, f"CNAME → {target}", ms))
                in_packet = [r for r in resp.answers if r.name == target and r.rtype == qtype]
                rest = in_packet or self._resolve(target, qtype, result, depth + 1)
                chain = [cname, *rest]
                if depth == 0:
                    result.records = chain
                return chain

            referral = [r for r in resp.authorities if r.rtype == TYPES["NS"]]
            if referral:
                zone = referral[0].name
                count = f"{len(referral)} name server{'s' if len(referral) != 1 else ''}"
                result.trace.append(Step(depth, ns_name, ns_ip, question, f"referral → {zone} ({count})", ms))
                servers = self._next_servers(referral, resp.additionals, result, depth)
                if not servers:
                    raise ResolveError(f"no reachable name server for {zone}")
                continue

            # Authoritative "this name exists but has no such record" (NODATA).
            result.trace.append(Step(depth, ns_name, ns_ip, question, "no data", ms))
            return []
        raise ResolveError(f"gave up after {self.max_hops} referrals")

    def _next_servers(self, ns_records: list[Record], additionals: list[Record], result: Result,
                      depth: int) -> list[tuple[str, str]]:
        names = [r.data for r in ns_records]
        glue = [(r.name, r.data) for r in additionals if r.rtype == TYPES["A"] and r.name in names]
        if glue:
            random.shuffle(glue)
            return glue
        # No glue (the name servers live in another zone): resolve one of them first.
        for ns in random.sample(names, len(names)):
            try:
                addrs = self._resolve(ns, TYPES["A"], result, depth + 1)
            except ResolveError:
                continue
            ips = [(ns, r.data) for r in addrs if r.rtype == TYPES["A"]]
            if ips:
                return ips
        return []

    # -- transport -------------------------------------------------------------
    def _ask_any(self, servers, name, qtype) -> tuple[Message, tuple[str, str], float]:
        errors = []
        for ns_name, ip in servers[:4]:  # a few servers per zone is plenty
            for _ in range(self.retries + 1):
                start = time.perf_counter()
                try:
                    resp = self.query(ip, name, qtype)
                    return resp, (ns_name, ip), (time.perf_counter() - start) * 1000
                except (OSError, DNSFormatError, ResolveError) as exc:
                    errors.append(f"{ip}: {exc}")
        raise ResolveError("no server answered: " + "; ".join(errors[-3:]))

    def query(self, ip: str, name: str, qtype: int) -> Message:
        """One UDP question, with a TCP retry if the answer was truncated."""
        qid = random.randint(0, 0xFFFF)
        packet = build_query(name, qtype, qid)
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, (ip, self.port))
            while True:
                data, addr = s.recvfrom(4096)
                if addr[0] != ip:
                    continue  # ignore packets from anyone else
                resp = decode(data)
                if resp.id == qid:
                    break     # wrong id = stray or spoofed packet: keep waiting
        self._check(resp, name, qtype)
        if resp.tc:
            resp = self._query_tcp(ip, packet, qid)
            self._check(resp, name, qtype)
        return resp

    def _query_tcp(self, ip: str, packet: bytes, qid: int) -> Message:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((ip, self.port))
            s.sendall(struct.pack("!H", len(packet)) + packet)
            (length,) = struct.unpack("!H", _recv_exact(s, 2))
            resp = decode(_recv_exact(s, length))
        if resp.id != qid:
            raise ResolveError("TCP answer has the wrong id")
        return resp

    @staticmethod
    def _check(resp: Message, name: str, qtype: int) -> None:
        if not resp.qr:
            raise ResolveError("server sent a query, not a response")
        if resp.questions and (resp.questions[0].name != name or resp.questions[0].qtype != qtype):
            raise ResolveError("answer is for a different question")


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ResolveError("connection closed early")
        buf += chunk
    return buf


def reverse_name(ip: str) -> str:
    """192.0.2.7 -> 7.2.0.192.in-addr.arpa. (and the nibble form for IPv6)."""
    return ipaddress.ip_address(ip).reverse_pointer + "."
