# rootwalk

🇷🇺 [Русская версия ниже](#ru)

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

---

<a id="ru"></a>

# rootwalk — по-русски

Небольшой DNS-резолвер, написанный с нуля на Python, без зависимостей. Он сам собирает DNS-пакеты, отправляет их по UDP (а при необходимости по TCP) и проходит дерево DNS так же, как настоящий рекурсивный резолвер: **корневой сервер → серверы TLD → собственные серверы имён домена**. Каждый шаг выводится на экран.

```
$ rootwalk github.com
$ rootwalk gmail.com MX
$ rootwalk 1.1.1.1            # обратный запрос (PTR)
$ rootwalk example.com --json
```

Пример вывода выше снят в тестовой сети из этого репозитория: CNAME указывает в другую зону, а у сервера имён той зоны нет glue-записи. Отступы показывают вложенные запросы. Чтобы пройти по CNAME, rootwalk начинает новый поиск `api.other.test`, а чтобы добраться до этой зоны, сначала узнаёт адрес её сервера имён `ns.provider.net`.

## Установка

```bash
pip install git+https://github.com/Dav1dushka/rootwalk
rootwalk example.com
```

Или из клона репозитория: `python -m rootwalk example.com`. Нужен Python 3.10+.

## Как это работает

**1. Запрос** (`rootwalk/message.py`). DNS-сообщение — это заголовок из 12 байт (id, флаги, четыре счётчика секций), за ним вопросы и записи. Имена записываются метками с байтом длины: `example.com` превращается в `\x07example\x03com\x00`. Флаг *recursion desired* выключен, потому что рекурсию rootwalk выполняет сам.

**2. Разбор ответа.** В ответах используется *сжатие имён*: вместо повтора `example.com` запись может содержать двухбайтовый указатель (два старших бита равны 1) на место, где это имя уже встречалось. Парсер следует по указателям, но отвергает циклы и указатели за пределы пакета, поэтому вредоносный ответ не может его повесить или уронить.

**3. Обход дерева** (`rootwalk/resolver.py`). Спрашиваем корневой сервер. Он не знает `www.example.com`, но *отсылает* к серверам `com.` и часто сразу прикладывает их адреса (*glue*-записи). Спрашиваем их, получаем отсылку к серверам `example.com.`, спрашиваем их и получаем ответ. По пути резолвер обрабатывает:

- **CNAME**, в том числе с целью в другой зоне (новый поиск от корня);
- **отсылки без glue** — сначала узнаёт адрес самого сервера имён;
- **NXDOMAIN** (имени не существует) и **NODATA** (имя есть, но записи такого типа нет);
- **усечённые ответы** (флаг TC) — тот же вопрос повторяется по TCP;
- **недоступные серверы** — короткие таймауты, затем следующий сервер зоны;
- **базовую защиту от подмены** — ответ должен прийти от того сервера, которого спрашивали, с тем же случайным id и на тот же вопрос;
- **кэш с учётом TTL**, чтобы повторные запросы не шли в сеть.

## Тесты

```bash
pip install pytest
pytest -q
```

Тесты резолвера поднимают целую фальшивую иерархию DNS на loopback-адресах (`127.0.0.10` — «корень», `127.0.0.11` обслуживает `test.` и так далее) и резолвят имена через настоящие сокеты. Проверяются отсылки, делегирование без glue, CNAME между зонами, NXDOMAIN, переход на TCP для TXT-записи на 5 КБ, сервер, который присылает подставной ответ с чужим id, недоступный сервер и истечение кэша. Тесты парсера покрывают все поддерживаемые типы записей, указатели сжатия и битые пакеты.

## Поддерживаемые типы записей

A, AAAA, NS, CNAME, SOA, PTR, MX, TXT. Неизвестные типы выводятся в hex.

## Ограничения

rootwalk — учебный инструмент, а не замена промышленному резолверу: нет проверки DNSSEC, нет EDNS(0), транспорт только IPv4, кэш живёт только в пределах одного запуска.

## Лицензия

MIT
