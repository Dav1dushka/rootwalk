"""DNS wire format (RFC 1035): build queries, parse responses.

A DNS message is a 12-byte header followed by four sections: questions,
answers, authority and additional records. Names are stored as length-prefixed
labels (``3www7example3com0``) and may be *compressed*: a two-byte pointer
(top bits ``11``) jumps back to a name that appeared earlier in the packet.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
CLASS_IN = 1
MAX_POINTER_JUMPS = 32


class DNSFormatError(ValueError):
    """The bytes are not a valid DNS message."""


def type_name(code: int) -> str:
    return TYPE_NAMES.get(code, f"TYPE{code}")


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN


@dataclass
class Record:
    name: str
    rtype: int
    ttl: int
    data: object          # str for A/AAAA/NS/CNAME/PTR, tuple for MX, list for TXT, dict for SOA
    rclass: int = CLASS_IN

    def text(self) -> str:
        """Value as dig would print it."""
        if self.rtype == TYPES["MX"]:
            pref, host = self.data
            return f"{pref} {host}"
        if self.rtype == TYPES["TXT"]:
            return " ".join(f'"{s}"' for s in self.data)
        if self.rtype == TYPES["SOA"]:
            d = self.data
            return f"{d['mname']} {d['rname']} {d['serial']} {d['refresh']} {d['retry']} {d['expire']} {d['minimum']}"
        return str(self.data)


@dataclass
class Message:
    id: int
    qr: bool = False          # False = query, True = response
    opcode: int = 0
    aa: bool = False          # authoritative answer
    tc: bool = False          # truncated: retry over TCP
    rd: bool = False          # recursion desired
    ra: bool = False          # recursion available
    rcode: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")


# --- names ----------------------------------------------------------------------

def normalize(name: str) -> str:
    """Lower-case, fully qualified (trailing dot) form used for comparisons."""
    name = name.strip().lower()
    return name if name.endswith(".") else name + "."


def encode_name(name: str) -> bytes:
    name = normalize(name)
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name[:-1].split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        if not 0 < len(raw) <= 63:
            raise ValueError(f"label {label!r} must be 1-63 bytes")
        out += bytes([len(raw)]) + raw
    out += b"\x00"
    if len(out) > 255:
        raise ValueError("name longer than 255 bytes")
    return bytes(out)


def decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly compressed name. Returns (name, offset after the name in the original position)."""
    labels: list[str] = []
    end = None
    jumps = 0
    while True:
        if offset >= len(buf):
            raise DNSFormatError("name runs past end of message")
        length = buf[offset]
        if length & 0xC0 == 0xC0:                       # compression pointer
            if offset + 1 >= len(buf):
                raise DNSFormatError("truncated pointer")
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DNSFormatError("compression loop")
            offset = ((length & 0x3F) << 8) | buf[offset + 1]
            continue
        if length & 0xC0:
            raise DNSFormatError("unsupported label type")
        offset += 1
        if length == 0:
            break
        label = buf[offset:offset + length]
        if len(label) < length:
            raise DNSFormatError("truncated label")
        labels.append(label.decode("ascii", errors="replace").lower())
        offset += length
    return (".".join(labels) + ".") if labels else ".", end if end is not None else offset


# --- encoding ---------------------------------------------------------------------

def _flags(m: Message) -> int:
    return ((m.qr << 15) | (m.opcode << 11) | (m.aa << 10) | (m.tc << 9) | (m.rd << 8) | (m.ra << 7) | m.rcode)


def _rdata(r: Record) -> bytes:
    t = r.rtype
    if t == TYPES["A"]:
        return ipaddress.IPv4Address(r.data).packed
    if t == TYPES["AAAA"]:
        return ipaddress.IPv6Address(r.data).packed
    if t in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"]):
        return encode_name(r.data)
    if t == TYPES["MX"]:
        pref, host = r.data
        return struct.pack("!H", pref) + encode_name(host)
    if t == TYPES["TXT"]:
        return b"".join(bytes([len(s.encode())]) + s.encode() for s in r.data)
    if t == TYPES["SOA"]:
        d = r.data
        return (encode_name(d["mname"]) + encode_name(d["rname"])
                + struct.pack("!IIIII", d["serial"], d["refresh"], d["retry"], d["expire"], d["minimum"]))
    if isinstance(r.data, bytes):
        return r.data
    raise ValueError(f"cannot encode {type_name(t)}")


def encode(m: Message) -> bytes:
    """Serialise a message (no name compression: simple and always valid)."""
    out = bytearray(struct.pack("!HHHHHH", m.id, _flags(m), len(m.questions), len(m.answers),
                                len(m.authorities), len(m.additionals)))
    for q in m.questions:
        out += encode_name(q.name) + struct.pack("!HH", q.qtype, q.qclass)
    for r in (*m.answers, *m.authorities, *m.additionals):
        rdata = _rdata(r)
        out += encode_name(r.name) + struct.pack("!HHIH", r.rtype, r.rclass, r.ttl, len(rdata)) + rdata
    return bytes(out)


def build_query(name: str, qtype: int, query_id: int, recursion_desired: bool = False) -> bytes:
    return encode(Message(id=query_id, rd=recursion_desired, questions=[Question(normalize(name), qtype)]))


# --- decoding ---------------------------------------------------------------------

def _parse_rdata(buf: bytes, rtype: int, start: int, length: int) -> object:
    end = start + length
    rd = buf[start:end]
    if rtype == TYPES["A"]:
        if length != 4:
            raise DNSFormatError("bad A record length")
        return str(ipaddress.IPv4Address(rd))
    if rtype == TYPES["AAAA"]:
        if length != 16:
            raise DNSFormatError("bad AAAA record length")
        return str(ipaddress.IPv6Address(rd))
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"]):
        return decode_name(buf, start)[0]          # may point anywhere in the packet
    if rtype == TYPES["MX"]:
        (pref,) = struct.unpack_from("!H", buf, start)
        return pref, decode_name(buf, start + 2)[0]
    if rtype == TYPES["TXT"]:
        parts, i = [], 0
        while i < length:
            n = rd[i]
            parts.append(rd[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
            i += 1 + n
        return parts
    if rtype == TYPES["SOA"]:
        mname, off = decode_name(buf, start)
        rname, off = decode_name(buf, off)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", buf, off)
        return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum}
    return rd.hex()


def _parse_record(buf: bytes, offset: int) -> tuple[Record, int]:
    name, offset = decode_name(buf, offset)
    if offset + 10 > len(buf):
        raise DNSFormatError("truncated record header")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    if offset + rdlength > len(buf):
        raise DNSFormatError("truncated record data")
    data = _parse_rdata(buf, rtype, offset, rdlength)
    return Record(name, rtype, ttl, data, rclass), offset + rdlength


def decode(buf: bytes) -> Message:
    if len(buf) < 12:
        raise DNSFormatError("message shorter than the 12-byte header")
    mid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", buf, 0)
    m = Message(id=mid, qr=bool(flags >> 15), opcode=(flags >> 11) & 0xF, aa=bool(flags >> 10 & 1),
                tc=bool(flags >> 9 & 1), rd=bool(flags >> 8 & 1), ra=bool(flags >> 7 & 1), rcode=flags & 0xF)
    offset = 12
    try:
        for _ in range(qd):
            name, offset = decode_name(buf, offset)
            qtype, qclass = struct.unpack_from("!HH", buf, offset)
            offset += 4
            m.questions.append(Question(name, qtype, qclass))
        for count, section in ((an, m.answers), (ns, m.authorities), (ar, m.additionals)):
            for _ in range(count):
                record, offset = _parse_record(buf, offset)
                section.append(record)
    except struct.error as exc:
        raise DNSFormatError(f"truncated message: {exc}") from None
    return m
