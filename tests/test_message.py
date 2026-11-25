import pytest

from rootwalk.message import (
    TYPES,
    DNSFormatError,
    Message,
    Question,
    Record,
    build_query,
    decode,
    decode_name,
    encode,
    encode_name,
)

# A real-world style response for "example.com A" whose answer name is a
# compression pointer (0xC00C) back to the question at offset 12.
COMPRESSED = bytes.fromhex(
    "1234" "8180" "0001" "0001" "0000" "0000"
    "076578616d706c6503636f6d00" "0001" "0001"
    "c00c" "0001" "0001" "00000e10" "0004" "5db8d70e"
)


def test_decode_compressed_response():
    m = decode(COMPRESSED)
    assert (m.id, m.qr, m.rd, m.ra, m.rcode) == (0x1234, True, True, True, 0)
    assert m.questions == [Question("example.com.", TYPES["A"])]
    assert m.answers == [Record("example.com.", TYPES["A"], 3600, "93.184.215.14")]


def test_build_query_layout():
    q = build_query("Example.COM", TYPES["MX"], 0xBEEF)
    assert q[:4] == b"\xbe\xef\x00\x00"                    # id, flags: plain iterative query
    assert q[4:12] == b"\x00\x01\x00\x00\x00\x00\x00\x00"  # one question, nothing else
    assert q[12:] == b"\x07example\x03com\x00\x00\x0f\x00\x01"


@pytest.mark.parametrize("rtype, data", [
    ("A", "192.0.2.1"), ("AAAA", "2001:db8::1"), ("NS", "ns1.example.test."), ("CNAME", "www.example.test."),
    ("PTR", "host.example.test."), ("MX", (10, "mail.example.test.")), ("TXT", ["v=spf1 -all", "hello"]),
    ("SOA", {"mname": "ns1.example.test.", "rname": "hostmaster.example.test.", "serial": 2026112501,
             "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300}),
])
def test_record_roundtrip(rtype, data):
    original = Message(id=7, qr=True, aa=True, answers=[Record("x.example.test.", TYPES[rtype], 60, data)])
    back = decode(encode(original))
    assert back.answers[0].data == data and back.aa and back.qr


def test_names_are_normalised():
    assert decode_name(encode_name("WWW.Example.Test"), 0) == ("www.example.test.", 18)
    assert encode_name(".") == b"\x00"


def test_name_limits():
    with pytest.raises(ValueError):
        encode_name("a" * 64 + ".test")
    with pytest.raises(ValueError):
        encode_name(".".join(["abcdefghi"] * 30))


@pytest.mark.parametrize("raw, message", [
    (b"\x00" * 5, "header"),
    (COMPRESSED[:-3], "truncated"),
    (COMPRESSED[:12] + b"\xc0\x0c", "loop"),                 # pointer to itself
    (COMPRESSED[:12] + b"\x05abc", "truncated label"),
])
def test_malformed_input_raises(raw, message):
    data = raw if message != "loop" else raw[:4] + b"\x00\x01" + raw[6:]
    with pytest.raises(DNSFormatError, match=message):
        decode(data)


def test_record_text_like_dig():
    assert Record("a.", TYPES["MX"], 1, (5, "mx.a.")).text() == "5 mx.a."
    assert Record("a.", TYPES["TXT"], 1, ["x", "y"]).text() == '"x" "y"'
