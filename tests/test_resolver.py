"""End-to-end resolution against a fake DNS hierarchy on 127.0.0.x.

    root (127.0.0.10)  →  test. (127.0.0.11)  →  example.test. (127.0.0.12)
                                              →  other.test.   (127.0.0.14, NS has no glue)
    root               →  net.  (127.0.0.13)     knows ns.provider.net = 127.0.0.14
"""
import random

import pytest

from rootwalk.message import TYPES, Message
from rootwalk.resolver import Cache, ResolveError, Resolver, reverse_name

from .fakedns import FakeServer, answer, nodata, nxdomain, referral, rr

BIG_TXT = ["x" * 200] * 25  # ~5 KB: does not fit in a UDP answer


def root(q):
    if q.name.endswith(".test."):
        return referral("test.", {"ns.nic.test.": "127.0.0.11"})
    if q.name.endswith(".net."):
        return referral("net.", {"ns.nic.net.": "127.0.0.13"})
    return nxdomain(".")


def tld_test(q):
    if q.name.endswith("example.test."):
        return referral("example.test.", {"ns1.example.test.": "127.0.0.12"})
    if q.name.endswith("other.test."):
        return referral("other.test.", {"ns.provider.net.": None})
    return nxdomain("test.")


def tld_net(q):
    if q.name == "ns.provider.net." and q.qtype == TYPES["A"]:
        return answer(rr("ns.provider.net.", "A", "127.0.0.14"))
    return nxdomain("net.")


def example_test(q):
    z = "example.test."
    name, t = q.name, q.qtype
    if name == "www." + z and t == TYPES["A"]:
        return answer(rr(name, "A", "192.0.2.80"))
    if name == "alias." + z:  # CNAME with the target in the same answer
        return answer(rr(name, "CNAME", "www." + z), rr("www." + z, "A", "192.0.2.80"))
    if name == "ext." + z:    # CNAME into another zone: must be resolved separately
        return answer(rr(name, "CNAME", "api.other.test."))
    if name == z and t == TYPES["MX"]:
        return answer(rr(name, "MX", (10, "mail." + z)))
    if name == "big." + z and t == TYPES["TXT"]:
        m = Message(id=0, aa=True, tc=True)      # UDP: truncated, answer omitted
        return m
    if name in ("www." + z,):
        return nodata(z)                         # www exists, but not with this type
    return nxdomain(z)


def example_test_tcp(q):
    if q.name == "big.example.test.":
        return answer(rr(q.name, "TXT", BIG_TXT))
    return example_test(q)


def other_test(q):
    if q.name == "api.other.test." and q.qtype == TYPES["A"]:
        return answer(rr(q.name, "A", "198.51.100.7", ttl=120))
    return nxdomain("other.test.")


@pytest.fixture(scope="module")
def net():
    port = random.randint(20000, 60000)
    servers = {
        "root": FakeServer("127.0.0.10", port, root),
        "test": FakeServer("127.0.0.11", port, tld_test, send_decoy_first=True),
        "example": FakeServer("127.0.0.12", port, example_test, tcp_handler=example_test_tcp),
        "net": FakeServer("127.0.0.13", port, tld_net),
        "other": FakeServer("127.0.0.14", port, other_test),
        "dead": FakeServer("127.0.0.9", port, lambda q: None),
    }
    yield port, servers
    for s in servers.values():
        s.close()


def make(port, roots=(("root.fake.", "127.0.0.10"),), **kw):
    return Resolver(roots=list(roots), port=port, timeout=0.3, retries=0, **kw)


def test_follows_referrals_to_the_answer(net):
    port, _ = net
    r = make(port).resolve("www.example.test", "A")
    assert [x.data for x in r.records] == ["192.0.2.80"]
    assert [s.address for s in r.trace] == ["127.0.0.10", "127.0.0.11", "127.0.0.12"]
    assert r.trace[0].outcome.startswith("referral → test.")
    assert r.trace[-1].outcome == "answer (1)"


def test_cname_inside_the_same_zone(net):
    port, _ = net
    r = make(port).resolve("alias.example.test")
    assert [(x.rtype, x.data) for x in r.records] == [(TYPES["CNAME"], "www.example.test."), (TYPES["A"], "192.0.2.80")]


def test_cname_to_another_zone_without_glue(net):
    port, _ = net
    r = make(port).resolve("ext.example.test")
    assert r.records[-1].data == "198.51.100.7"
    # the resolver had to look up ns.provider.net. itself (a nested lookup, depth 2)
    assert any(s.question == "ns.provider.net. A" and s.depth == 2 for s in r.trace)


def test_nxdomain_and_nodata(net):
    port, _ = net
    missing = make(port).resolve("nope.example.test")
    assert missing.rcode == "NXDOMAIN" and missing.records == []
    empty = make(port).resolve("www.example.test", "AAAA")
    assert empty.rcode == "NOERROR" and empty.records == [] and empty.trace[-1].outcome == "no data"


def test_mx_record(net):
    port, _ = net
    assert make(port).resolve("example.test", "MX").records[0].data == (10, "mail.example.test.")


def test_truncated_udp_answer_is_retried_over_tcp(net):
    port, _ = net
    r = make(port).resolve("big.example.test", "TXT")
    assert r.records[0].data == BIG_TXT


def test_spoofed_reply_with_wrong_id_is_ignored(net):
    port, servers = net
    assert servers["test"].send_decoy_first
    assert make(port).resolve("www.example.test").records[0].data == "192.0.2.80"


def test_dead_server_is_skipped_and_all_dead_fails(net):
    port, _ = net
    both = (("dead.fake.", "127.0.0.9"), ("root.fake.", "127.0.0.10"))
    assert make(port, roots=both).resolve("www.example.test").records
    with pytest.raises(ResolveError, match="no server answered"):
        make(port, roots=(("dead.fake.", "127.0.0.9"),)).resolve("www.example.test")


def test_cache_answers_without_network_until_ttl_expires(net):
    port, servers = net
    now = [1000.0]
    res = make(port, cache=Cache(clock=lambda: now[0]))
    res.resolve("api.other.test")  # ttl 120
    before = len(servers["other"].queries)
    again = res.resolve("api.other.test")
    assert again.from_cache and len(servers["other"].queries) == before
    now[0] += 121
    assert not res.resolve("api.other.test").from_cache


def test_reverse_name():
    assert reverse_name("192.0.2.7") == "7.2.0.192.in-addr.arpa."
    assert reverse_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.ip6.arpa.")
