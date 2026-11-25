"""A tiny DNS hierarchy on loopback addresses for end-to-end tests.

Each FakeServer listens on its own 127.0.0.x address (UDP and TCP) and
answers with whatever its handler returns, so the resolver talks to real
sockets exactly as it would on the internet.
"""
from __future__ import annotations

import socket
import struct
import threading
from typing import Callable

from rootwalk.message import TYPES, Message, Question, Record, decode, encode

Handler = Callable[[Question], Message | None]


class FakeServer:
    def __init__(self, ip: str, port: int, handler: Handler, tcp_handler: Handler | None = None,
                 send_decoy_first: bool = False):
        self.ip, self.port, self.handler = ip, port, handler
        self.tcp_handler = tcp_handler or handler
        self.send_decoy_first = send_decoy_first
        self.queries: list[Question] = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((ip, port))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((ip, port))
        self.tcp.listen()
        self._stop = False
        for target in (self._serve_udp, self._serve_tcp):
            threading.Thread(target=target, daemon=True).start()

    def _reply(self, data: bytes, handler: Handler) -> bytes | None:
        query = decode(data)
        q = query.questions[0]
        self.queries.append(q)
        resp = handler(q)
        if resp is None:
            return None  # simulate a dead server
        resp.id, resp.qr, resp.questions = query.id, True, [q]
        return encode(resp)

    def _serve_udp(self):
        while not self._stop:
            try:
                data, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            out = self._reply(data, self.handler)
            if out is None:
                continue
            if self.send_decoy_first:  # same packet with a different id, like a spoofing attempt
                decoy = bytearray(out)
                decoy[0] ^= 0xFF
                self.udp.sendto(bytes(decoy), addr)
            self.udp.sendto(out, addr)

    def _serve_tcp(self):
        while not self._stop:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            with conn:
                (length,) = struct.unpack("!H", conn.recv(2))
                out = self._reply(conn.recv(length), self.tcp_handler)
                if out:
                    conn.sendall(struct.pack("!H", len(out)) + out)

    def close(self):
        self._stop = True
        self.udp.close()
        self.tcp.close()


# --- helpers to write zone handlers briefly ------------------------------------------

def rr(name: str, rtype: str, data, ttl: int = 300) -> Record:
    return Record(name, TYPES[rtype], ttl, data)


def answer(*records: Record, aa: bool = True) -> Message:
    return Message(id=0, aa=aa, answers=list(records))


def referral(zone: str, ns: dict[str, str | None]) -> Message:
    """Delegate `zone` to name servers; a None address means no glue."""
    return Message(id=0, authorities=[rr(zone, "NS", n, 86400) for n in ns],
                   additionals=[rr(n, "A", ip, 86400) for n, ip in ns.items() if ip])


def nxdomain(zone: str) -> Message:
    soa = {"mname": "ns1." + zone, "rname": "hostmaster." + zone, "serial": 1, "refresh": 3600,
           "retry": 600, "expire": 86400, "minimum": 60}
    return Message(id=0, aa=True, rcode=3, authorities=[rr(zone, "SOA", soa, 60)])


def nodata(zone: str) -> Message:
    m = nxdomain(zone)
    m.rcode = 0
    return m
