# rootwalk

A small DNS resolver written from scratch in Python, with no dependencies. It builds DNS packets by hand, sends them over UDP (and TCP when needed) and walks the DNS tree the way a real recursive resolver does: **root server → TLD servers → the domain's own name servers**, showing every hop.

```
$ rootwalk github.com
$ rootwalk gmail.com MX
$ rootwalk 1.1.1.1            # reverse lookup (PTR)
$ rootwalk example.com --json
```

Output from the test network in this repo (see *Tests*), resolving a CNAME that points into another zone whose name server has no glue record:

```
$ rootwalk ext.example.test
;; rootwalk ext.example.test. A
 1  ext.example.test. A     root-1 (127.0.0.10)             referral → test. (1 name server)             1 ms
 2  ext.example.test. A     ns.nic.test. (127.0.0.11)       referral → example.test. (1 name server)     0 ms
 3  ext.example.test. A     ns1.example.test. (127.0.0.12)  CNAME → api.other.test.                      0 ms
 4    api.other.test. A     root-1 (127.0.0.10)             referral → test. (1 name server)             0 ms
 5    api.other.test. A     ns.nic.test. (127.0.0.11)       referral → other.test. (1 name server)       0 ms
 6      ns.provider.net. A  root-1 (127.0.0.10)             referral → net. (1 name server)              0 ms
 7      ns.provider.net. A  ns.nic.net. (127.0.0.13)        answer (1)                                   0 ms
 8    api.other.test. A     ns.provider.net. (127.0.0.14)   answer (1)                                   0 ms

ext.example.test.                   300  CNAME  api.other.test.
api.other.test.                     120  A      198.51.100.7
```

Indentation shows nested lookups: to follow the CNAME, rootwalk starts a new search for `api.other.test`, and to reach that zone it first has to find the address of its name server, `ns.provider.net`.

## Install

```bash
pip install git+https://github.com/Dav1dushka/rootwalk
rootwalk example.com
```

or run it from a clone with `python -m rootwalk example.com`. Python 3.10+.

## How it works

**1. Building the question** (`rootwalk/message.py`). A DNS message is a 12-byte header (id, flags, four section counts) followed by questions and records. Names are written as length-prefixed labels: `example.com` becomes `\x07example\x03com\x00`. Queries are sent with *recursion desired* off, because rootwalk does the recursion itself.

**2. Reading the answer.** Responses use *name compression*: instead of repeating `example.com`, a record can contain a two-byte pointer (top two bits set) to where that name already appeared. The parser follows pointers, and refuses loops and pointers past the end of the packet, so a malicious response cannot hang or crash it.

**3. Walking the tree** (`rootwalk/resolver.py`). Ask a root server; it does not know `www.example.com` but *refers* us to the `com.` servers, often with their addresses attached (*glue* records). Ask those, get referred to `example.com.`'s servers, ask them, get the answer. Along the way the resolver handles:

- **CNAMEs**, including targets in other zones (a new search from the root);
- **referrals without glue**, by resolving the name server's own address first;
- **NXDOMAIN** (name does not exist) and **NODATA** (name exists, but not with that record type);
- **truncated answers** (TC flag): the same question is repeated over TCP;
- **dead servers**: short timeouts, then the next server for the zone;
- **spoofing basics**: answers must come from the server that was asked, carry the random query id and match the question;
- **a TTL cache**, so repeated lookups do not touch the network.

## Tests

```bash
pip install pytest
pytest -q
```

The resolver tests start a whole fake DNS hierarchy on loopback addresses (`127.0.0.10` is the "root", `127.0.0.11` serves `test.`, and so on) and resolve names through real sockets: referrals, glueless delegation, cross-zone CNAMEs, NXDOMAIN, TCP fallback for a 5 KB TXT record, a server that sends a decoy reply with the wrong id, a dead server, and cache expiry. Parser tests cover every supported record type, compression pointers and malformed packets.

## Supported record types

A, AAAA, NS, CNAME, SOA, PTR, MX, TXT. Unknown types are shown as hex.

## Limits

rootwalk is a learning tool, not a replacement for a production resolver: no DNSSEC validation, no EDNS(0), IPv4 transport only, and the cache lives only for one run of the program.

## License

MIT
