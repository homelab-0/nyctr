# Security model and release boundaries

## What the initial application protects

The API authenticates users, enforces administrator/member permissions and checks
CSRF on authenticated mutations. Sessions are revocable server-side records.
Provider credentials are server environment secrets referenced by a restricted
name; arbitrary environment variables are not available as credential sources.
The web client receives evidence and sanitized configuration, not credentials.

The model's key follows the same rule with its own name. An administrator
connects the model in the console by naming a server secret that matches
`NYCTR_MODEL_SECRET_*`; a source's secret name is refused there and a model's is
refused for a source. The endpoint is where Nyctr sends that key and the
redacted evidence pack, so the operator, not the administrator, says which
servers it may be on: `NYCTR_MODEL_HOSTS`, plus the server in the server's own
`NYCTR_AI_BASE_URL`. A server is a scheme, a host and a port. A bare name in the
list means HTTPS on port 443 and nothing else, so listing a host never lets the
key go in clear text or to another port of it; plain HTTP or another port is
allowed only where the operator wrote it in full. The list exists so that a
stolen administrator session cannot send a key to another server, aim Nyctr at
an internal address, or probe the ports of a listed host. The key set directly
on the server (`NYCTR_AI_API_KEY`) goes only to the server set beside it, on
that scheme and port. A cloud metadata or link-local address is refused for a
connection made in the console, listed or not; the server's own
`NYCTR_AI_BASE_URL` is the operator's choice and is not checked that way. No
redirect is followed, and both checks run again before every call. A saved value that cannot be read turns the model off: it never
falls back to the server's own endpoint and key. The key is never in an API
answer, an audit record or a log, and a refusal never repeats what was typed.
See [the model](model.md).

Collectors only read. They send GET requests, with one stated exception: a source
that offers only session sign-in (Pi-hole) is sent one sign-in and one sign-out
request for the collection's own session. There are no firewall mutations and no
AI tool calls.

Nyctr can change a provider in three narrow ways, all in
`nyctr/integrations/actions.py`: add or remove one NextDNS allowlist entry,
create or delete one UniFi hotspot voucher, and authorise or unauthorise one UniFi
guest client. Each function refuses to run before any network call unless the
operator named the provider in `NYCTR_PROVIDER_WRITES`, and validates its
inputs: the NextDNS functions accept a plain domain name, never a URL or
wildcard, and the UniFi functions accept only well-formed identifiers. The
NextDNS functions and the guest authorise/unauthorise function read the provider
state back after the change. Creating a voucher relies on the voucher UniFi
returns, and deleting one relies on the provider accepting the request; neither
is read back at the time. The next collection mirrors the voucher list, which is
when a difference would show. Demo mode simulates every change and never
contacts a provider.

Every decision records what happened at the provider: `simulated`, `applied`,
`not_applied` or `failed`. A decision is never displayed as restored or removed
connectivity unless it was applied. With writes disabled, an approval is stored
as not applied and the administrator is told to make the change by hand.

Nyctr acts without a person only under two administrator-written rules, both off
until switched on:

- The access rule may open a request when the score is at or below the written
  limit (which the code caps at 60), the block came from a privacy list, the
  member is under the daily cap, and no administrator denied that address before.
  An unknown score, a security or content-rule block, a source whose integration cannot open addresses, a missing DNS source, disabled
  writes or a provider failure all leave the request waiting for a person.
- The guest cut-off rule unauthorises a guest device after a written number of
  threat-list lookups within a written number of minutes. It counts stored
  observations. No model output is an input to either rule.

## Two addresses

Nyctr can be served on one address or two. `NYCTR_PUBLIC_URL` is the console.
`NYCTR_PORTAL_URL`, when set, is a second origin for members, for example
`https://blocked.example.org`.

- **Portal address.** Every session has member rights, whatever the account's
  role. An administrator who signs in there sees their own devices' blocks and
  can ask for access like anyone else; none of the console's reads or changes
  answer on that address. The account itself is not changed, and the page
  offers the way to the console.
- **Console address.** For administrators. A member who signs in there gets no
  session: single sign-on restarts on the portal address, and local sign-in
  answers with the portal's address, after the password has been checked.
- **Sign-in.** The redirect sent to the identity provider is the configured
  origin of the address the person started on. It is never built from the
  request's Host header, and an unrecognised Host is treated as the console.
  Session cookies belong to one host, so each address has its own session.
- **Changes.** A changing request must carry the origin of the address it
  arrives on. A page on one address cannot change anything through the other.

What this is not: the application tells the addresses apart by the Host header,
so the split limits what a session can do on each name, and keeps the console's
surface off the name members use. It becomes a network boundary only when the
operator also routes the two hostnames separately, for example by publishing
only the portal's hostname to a wider network. A caller who can reach the
application under the console's hostname is on the console address.

The proxy in front of Nyctr must pass the original Host header through. The two
addresses must be different hostnames: browsers share cookies between ports of
one hostname, so two ports would share a session. Both addresses are stored the
way a browser sends an origin, lower-case and without the scheme's default port.

Without `NYCTR_PORTAL_URL` there is one address and roles alone decide what a
session can do, as before.

## Where a request came from

Nyctr works out a request's address in one place (`nyctr/peer.py`), and the web
server's own forwarded-header handling is off in the image, the chart, Compose
and the documented commands. The list of proxies is kept under a name the web
server does not read (`NYCTR_TRUSTED_PROXIES`), so a server started by hand with
that handling left on believes only `127.0.0.1`. That is not enough when a proxy
runs on the server's own host: the web server then rewrites the peer to an entry
the client chose, and Nyctr cannot see that it did. A list that covers every
address is refused at start. Nyctr reads no header
about the scheme. A peer that is not one of the
operator's listed proxies is the client and its headers are ignored. Behind a
listed proxy Nyctr reads `X-Forwarded-For` from the right and takes the entry
that proxy wrote, at position `NYCTR_PROXY_HOPS`; entries to its left came from
the client and are never read. With more than one proxy every proxy must be
listed: an entry to the right of the one read that is not a listed proxy means
the request did not pass them all. That, or a missing or malformed entry, gives
no address. The sign-in limit counts by that address, and requests with none share
one quota. The address is evidence of where a request came from. It grants
nothing by itself.

This holds only as far as the operator's set-up does. A peer that can connect
under a listed address is believed. With more than one proxy, a client whose own
address is inside a listed range and which can reach an inner proxy directly
passes for a proxy and can name any address; Nyctr cannot tell the two apart.

## Threats considered

| Threat | Required boundary |
| --- | --- |
| Member requests another person's event by ID | Server authorization, including event-time ownership and current access |
| Shared upstream resolver is mistaken for a person | Unattributed events remain administrator-only |
| Signing in on a device shows a member what someone else did on it | Off until an administrator switches it on. A tie is made only for a signed-in person, on the one device the gateway says holds the request's address, never on infrastructure, on another person's device or on a device another person is tied to unless it is shared. It reaches back a set time before the first sign-in (two hours unless set otherwise, 24 at most) and assumes the person signing in was the one using the device in that time, but never past the last time an administrator said whose the device is, nor, on a device that is not shared, past the end of another person's tie on it. That is the one place a member sees events from before Nyctr knew who was on the device. When the gateway does not answer, the stored inventory stands in while the last collection is under 15 minutes old; an address can change hands in that time, so such a tie could name the wrong device, and it therefore reaches back to nothing before its own first sign-in. An administrator finds these ties by `basis: stored` in `GET /api/presence`. A client inside a listed proxy range that reaches the server directly can name any address, and is then tied to the device at the address it names |
| Everyone arrives from one address because a proxy hides theirs | A listed proxy's address is tied to nobody and administrators are told. An address outside every collected network, held by no device or by two, is tied to nobody |
| A total, a filter count or where a page ends gives away another person's event | The list of blocked lookups applies member rights in the database query, before the page is cut and before anything is counted |
| Stale block becomes an access grant | Reject stale requests. An approval is refused once the blocked lookup behind it has expired; refusing or noting a request needs no fresh evidence |
| Provider redirects leak an API key | No redirected credential-bearing requests |
| Configured endpoint targets internal metadata | Explicit console host allowlist, HTTPS validation, reserved-address restrictions |
| Provider returns misleading successful HTTP status | Parse provider-level errors; never treat missing/error data as safe |
| Log text or domain is used as prompt instructions | Future AI treats source text as untrusted evidence and cannot execute |
| Model invents confidence or permissions | Unknown risk remains unknown; external authorization owns decisions |
| Temporary exception survives restart | Leases are database rows; a background task and every lease read close what has expired, and a failed removal stays open, visible and retried |
| Expiry removes a rule Nyctr did not create | A pre-existing allowlist entry is recorded as not owned and never removed; overlapping leases keep the entry until the last one ends |
| A guest is cut off on a guessed identity | DNS lookups are tied to a guest only by an administrator link or a unique name match, which is labelled inferred and shown in the guest's timeline |
| A guest device attacks the system that polices it | Nyctr is never the captive portal and nothing on the guest network needs to reach it; a guard test fails if any API route answers without a session ([guest Wi-Fi design](guest-wifi.md)) |
| A client claims another address in a forwarded header | Only a listed proxy is believed, and only about the entry it wrote itself; entries the client sent are never read |
| Someone forges the collection nudge | It needs a shared secret, reads nothing from the request, only starts a read-only collection, and runs at most once every 30 seconds |
| A stolen administrator session points the model somewhere else to collect its key | The endpoint must be on a server the operator allowed, by scheme, host and port; the key is named by a secret with the model's own pattern; an address holding a sign-in name or password is refused; no redirect is followed |
| A listed model host is reached in clear text, or on another of its ports | A bare name in the list is HTTPS on port 443 only; anything else must be written in full by the operator |
| A saved model setting cannot be read after an upgrade or a rollback | The model is off and says so; the server's own endpoint and key, which an administrator replaced, are not used in its place |
| A trace of a model call says who asked or which device it was about | Trace fields are fixed words, versions, a new random id and a digest of the subject's id keyed with 32 random bytes only this installation holds (never the model's key, never sent or shown), so the digest cannot be matched against guessed ids; the `user` field is never sent |
| SQL statement logging is on, and its log is read by someone who also reads the traces | That log then holds the trace key, like every other stored value, and a reader with the key could test guessed ids against a session. Statement logging is off by default and cannot be turned on from the console; leave it off, or treat its output as a secret |
| Model is told to act by text in a log or request | The model has no tools or credentials; evidence is passed as data in a bounded pack with addresses, emails, codes and identifiers removed |
| Model cites something it was not shown | Citations are resolved against the pack on the server and dropped when they do not match |
| Graph query exhausts the server | Administrator-only, query-only, with length, depth and returned-object limits |

## Deployment responsibilities

Use HTTPS, retain secure cookies in live deployments, keep the service behind
appropriate network controls, and protect database backups. Set a strong initial
administrator password or configure OIDC. Configure narrowly scoped provider
credentials where their APIs support it. Never disable TLS verification to make
a console connection succeed; configure a valid trust chain instead.

Leave SQL statement logging off, as it is by default, or treat its output as a
secret. Nyctr writes no stored secret to its own logs, but statement logging
writes stored values as they are saved, and the settings table holds one: the
key Nyctr makes to name what a traced model call is about.

Demo and live databases must be separate. Demo is for evaluation using known
accounts and synthetic events. Do not expose demo to an untrusted network.

## Limitations to resolve before a production release

- Complete independent review of authentication, OIDC mappings, SSRF boundaries,
  source parsing and member visibility.
- End-to-end validation against supported real provider versions, including
  missing telemetry and asymmetric routing.
- Backup/restore exercises, and retention of anything but lookups and
  inventory. Blocked lookups are deleted when their time is up, and items a
  source has stopped reporting are dropped as docs/architecture/overview.md
  describes; requests, exceptions and the audit table are kept without limit.
- Multi-process-safe throttling and job concurrency if scaling beyond one process.
  Lease reconciliation, scheduled collection and the assistant's rate limit run
  inside the API process. A scheduled run, and each retry of a source that
  failed it, is claimed in the database so two copies do not both perform it;
  a restart may drop a claimed retry, and the next run covers the source. Expired
  exceptions are ended on every tick, separately from collection, and an entry
  is claimed in the database before it is read, added or removed, so two copies,
  or the tick and a person, remove and record it once, and an opening and a
  removal of one address cannot cross. Each change at a source ends within 60
  seconds, as failed if it has not finished. An opening that fails after its add
  may have been sent leaves a record, and Nyctr removes the entry itself. A
  source can apply an add after Nyctr stopped waiting for it (Nyctr waits 20
  seconds for a request and 60 for a change), so the record is not settled on
  one read that shows nothing: for five minutes after the attempt Nyctr reads
  the source again on every tick, removes the entry if it appears, and takes
  an entry found there by a new opening of that address to be its own. Five
  minutes is five times the longest Nyctr itself waits for a change and the
  time after which a claim counts as abandoned; after it the record is settled
  with how long Nyctr looked. Known limits. A source that applies an add more
  than five minutes late leaves an entry nothing on record removes. From the
  moment a record is listed as not confirmed until it is
  settled, Nyctr takes an entry for that address at that source to be its own
  and removes it: an administrator must not add the address there by hand while
  Open now lists it as not confirmed (at least five minutes after such an
  attempt), and the row says so, with until when. An entry added by
  hand meanwhile may also be handed to another open exception for that address
  and removed later, when that exception ends, after the row is gone. Nyctr keeps no such
  record when the add itself reports that nothing was sent. It does keep one
  when it cannot know: after a copy is killed between storing the record and
  the add's answer, the record lives five minutes, and an entry a person adds
  in those five minutes is removed; and for as long as a source keeps failing
  after an add that may have been sent. If the address was there when Nyctr
  asked, a person removes it in that second, Nyctr's add is sent and that copy
  is killed before it records the add's answer, the entry stays with nothing on
  record (a failure short of a kill is recorded and the entry removed). An
  entry is passed on to another exception only after the source says it is
  there; a source that offers no such read is never passed an entry. An
  opening that stands still for more than five minutes after its add cannot
  know what became of its entry: Nyctr removes nothing on its word and asks an
  administrator to check at the source, so an entry of Nyctr's can stay there
  until a person ends it. After a copy is killed during an approval, that
  request can be decided again only once its claim is five minutes old. The
  nudge and the assistant's limit are still per process.
- Scheduled collection is on by default and only an administrator can change it
  (`PUT /api/collection`); every change is audited with the old and new
  value. Collection only reads, but the guest cut-off rule and lock-out act at
  every collection, so with the schedule on a rule an administrator wrote and
  switched on acts with nobody at the console.
- The NextDNS allowlist calls follow the documented rule for nested array
  endpoints and the UniFi calls follow the 11.0.97 contract. Neither has been
  exercised against the live service.
- A guest "lock out" re-cuts the device at each collection. It is not a
  UniFi-side block and a device that changes its hardware address evades it.
- The risk score reads only the block reason and the shape of the name. It is
  not a reputation service and must not be presented as one.
- Device recognition in the member portal matches the connecting address to
  inventory among devices the caller may already see. With "Recognise members'
  devices when they sign in" switched on (Setup, off by default), Nyctr also
  asks the gateway which device holds the address and ties the signed-in person
  to it: a record of its own that never changes whose a device is, ends 30 days
  after the last sign-in from it or when the member or an administrator ends
  it, and is kept 90 days after that. When an administrator changes whose a
  device is or who shares it, every tie on it held by anyone the new
  assignment does not name ends at once. A device that is dropped after it
  has left its source, or whose source is removed, takes its ties with it.
  Every ending is audited with whose tie it was: by the member, by an
  administrator, by an assignment, by switching recognition off, by the 30
  days running out and by the device going. The worker keeps these records,
  so they are closed and deleted on time with nobody opening a page. A new
  tie reaches back no further than the last time an administrator set whose
  the device is (saved again unchanged counts too) and, on a device that is
  not shared, no further than the end of the last tie another person held on
  it. A tie that an assignment keeps starts again at that assignment, so it
  shows nothing the new assignment does not cover. Making a tie and switching
  recognition off take one lock on the stored setting, so no tie is committed
  after the switch. When the gateway does not answer, Nyctr falls back to
  the stored inventory while the last collection is under 15 minutes old.
  An address can change hands in that time, and the tie would then name the
  wrong device. Such a tie has `basis: stored` in `GET /api/presence`, which
  is how an administrator finds it, and it does not reach back before its
  own first sign-in, so a wrong match shows nothing from before. Only a
  source whose integration declares the lookup takes part at all. A tie or
  conflict record holds the address the request came from
  and the device's hardware address. Only administrators are shown them, and
  they go when the record does, 90 days after a tie ends or after a
  conflict's last attempt. Neither works through NAT, or through a
  proxy that is not listed or does not pass the member's LAN address on. A
  router or address translator that is not a listed proxy and is itself in the
  inventory would be tied to the first person who signs in through it: check
  the address Nyctr sees for you before switching recognition on. A request
  that reaches Nyctr over IPv6 is never tied, by rule and whatever ranges a
  source collects, and the portal tells the member so. An address is looked
  up only in the site whose network holds it; where two sites, or two
  sources, use the same range, nothing says which one a request came from
  and nobody is tied. The gateway lookup has been run only against
  fabricated answers.
- Audit export and tamper-evidence. A database audit table is not an immutable log.
- Explicit schema upgrade and rollback testing beyond the initial schema.
- Image signing/SBOM publication, pinned release images and upgrade policy.

## Change authorization

An approval binds to one domain on one DNS source for a stated time. The lease
records the attempted provider operation, its outcome and whether Nyctr owns the
entry. Still to do: bind approvals to an immutable plan digest, separate the
execution service from the API process, and invalidate approvals on detected
configuration drift.

A profile-wide DNS exception may affect more than one person. That effective
scope must be shown before approval. Never silently convert a domain request
into a broad shared-CDN IP allow rule.

No block reason, no reputation hit, or a low numeric risk score is insufficient
to prove safety. An automatic temporary grant must satisfy the explicit
administrator rule and fails closed on missing evidence.
