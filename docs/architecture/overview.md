# Architecture

## Product scope

Nyctr connects network inventory, policy configuration, observed behavior and
identity to explain posture and access. The current alpha workspace includes
read-only inventory and configured-policy collection, relationship exploration,
resource and finding views, recent DNS observations, member access requests,
integration health, and audited administrator review. Demo findings illustrate
the investigation flow; the live collectors do not yet generate posture findings.

A first version of risk scoring, an evidence-bound assistant and controlled,
gated provider changes is implemented; see the sections below for its limits.
Port posture, firewall-event investigations and reputation-based risk evaluation
are planned.

## Initial runtime

The application has a React/TypeScript web client, a FastAPI backend and a
PostgreSQL database. One application image contains the compiled frontend and
Python service. SQLite supports local development and isolated tests. Provider
adapters are independent Python modules, not separate microservices.

The API owns identity, authorization and persistence. The frontend cannot choose
its role or widen a query's member scope. Read-only collection is
initiated by an administrator and bounded per request, or run on the schedule an
administrator sets with `PUT /api/collection` (on by default, every 15 minutes), by an
upkeep loop inside the API process. The schedule and the time of its last run
are stored in the database, so a change applies within one upkeep pass on every
running copy, a restart does not reset the clock, and only one copy performs a
given run. A source whose scheduled collection fails for a reason that may pass
(a broken connection, a timeout, a rate limit, a server error at the source) is
tried again after about 1, 2 and 4 minutes, never at or after the next run, and
keeps its previous status until the last retry fails. A refused key or a rejected
setting is shown at once, and so is a source whose retries end without a
collection (the schedule switched off, its secret gone); the audit says why. Each pending retry is a row in the settings table that
one copy claims the same way as a run. A Collect pressed by a person and a
connection test are not retried. Moving scheduled collection and background
analysis to a separate worker process is future work.

Reading a source is network work on the server's loop, and so is turning its
answer into a snapshot. Storing what was read is blocking database work and
runs on a worker thread, in a database session of its own, so the API goes on
answering meanwhile. The analysis after a collection runs the same way, whether
the schedule, a person or a nudge started it, and one analysis runs at a time
in a process. After the analysis the guest rule is applied on the loop, one
call to the source per device it acts on, each committed as it is made. The
refresh of findings that ends it, and the one after an administrator's guest
action, run on a worker thread in a session of their own and take their turn
behind any analysis that is running, so the loop does not wait for either. A
guest action is committed before that refresh, so it is on record whatever the
refresh meets.

A store is one transaction that begins by checking the lease on the source: it
is stored whole or not at all. A scheduled pass or a person's Collect that is
stopped during a store waits for the store to end, however often it is
cancelled. A collection started by the nudge address is not waited for when the
server stops: it ends as if killed, with nothing stored and its lease left to
run out, whether or not its store had begun. A store reads what is already stored in a fixed number of statements
plus one per 500 new identifiers, never one per item. On SQLite, which allows
one writer, a request that writes waits for a store in progress and fails if
the wait passes five seconds. On PostgreSQL a request waits only if it locks
the row of the source being stored, as opening or ending an exception at that
source does, and then for at most that one store.

Each collection writes two log lines, at its start and at its end: the source's
name as saved, who started it (`schedule`, `person` or `nudge`), which retry it
is, how long it took and how long the store took, items and lookups read and
new, requests sent to the source, seconds spent waiting for a turn at a request
limit, and the outcome (`stored`, `partial`, `failed` with its category,
`replaced`, or `stopped` for a run that was cancelled, with whether its store
was finished). No key, address or lookup is logged.

The upkeep loop ticks every 30 seconds, and a tick never waits for a provider.
It starts ending the exceptions whose time is up, and it starts a collection
pass (the scheduled run if one is due, then the retries that are due) unless
this copy's previous pass is still going. So an exception is ended within one
tick of its expiry plus its own call to the source, and the calls for
exceptions ahead of it at that same source, however long a collection takes. A
run or retry that comes due during a pass is not claimed until the pass ends;
it stays due in the database for the next tick, or for another copy.

The tick also clears out what Nyctr no longer needs, without calling a source
and on a worker thread, so the server goes on answering meanwhile. Blocked
lookups whose time is up are removed at every tick; a request keeps its own
copy of what it asked about. Once an hour it looks for what has left each
source (`nyctr/retention.py`):

- A collection that listed a kind of item in full marks every stored item of
  that kind it did not list as missing, with the time, and notes the day. A
  missing item is kept, stays in Inventory with its mark, and is not counted
  as present or drawn on the Map. When its source lists it again it is the
  same item, with its owner, its assignment and its label links.
- A missing item is dropped when whole reads of its kind on at least 7
  separate days, the last of them 7 days after the first, all left it out and
  no read in between listed it. One read says only that the item was not
  there at that moment, so a source that was down, or is collected by hand
  now and then, drops nothing until it has been read on 7 days. The number is
  `KEEP_DAYS` in `nyctr/retention.py`. A day on which the kind was in doubt
  neither counts nor starts the count again: nobody knows whether the item
  was there that day, so the days before it still stand and the day itself
  adds nothing. An item that comes back later is a new item.
- What a person attached something to is never dropped by itself: a device
  assigned to someone or filed by an administrator, and an item with a DNS
  label link on either side. It stays, marked missing and not counted, until
  an administrator removes the assignment or the link, or removes the source.
  Setup's table says how long it has been missing.
- A blocked address is kept by its lookups instead of the 7 days: it goes when
  no stored lookup from its source names it.
- A collection that read a log only from where the last one ended counts what
  earlier reads took from the log, and is still inside the window, as listed,
  and takes any mark off it. It vouches only for the stretch it read: while
  the stored log is not whole from the window's start (a read before it kept
  only part, or hit a gap) it is in doubt for the same kinds, and marks and
  counts nothing of them. Each collection records what it left in doubt
  (`unread`) and from when nothing is in doubt (`unread_from`), beside how
  far back the stored log has no hole (`whole_from`), which a gap does not
  move.
- Not knowing is not the same as gone. Nothing is marked, and no day is
  counted, on a collection that kept only its most recent rows, did not list
  the kind in full, or recorded a gap that could have hidden items (the
  integration declares which gaps cannot, see the integration contract).
  Nothing is dropped while a source's latest collection failed, while it is
  being collected, after an edit that sent it back to be tested, or before a
  collection has recorded what it read in full.
- Each source is gone through once an hour, counted from when it last was. A
  source that a collection has at that moment is tried again at the next
  tick, so a collection that falls on the same tick every hour cannot keep a
  source from being cleared.
- What may go is read once a run, with no lock held: the source's blocked
  addresses and the addresses its stored lookups name are each read through
  the index on their source and compared, so the cost grows with their sum.
  The drop then works in batches of 500 items, each in its own transaction
  that locks the source's row first, as the store step of a collection does.
  Lookups are stored only by that step, so a batch that finds a collection
  has stored since the read stops, and the run starts again at the next
  tick. So a drop and a store of one
  source never work at once: a collection waits for one batch at most, and a
  collection that has taken the source stops the run until the next tick.
  SQLite has one write lock for the whole database, so there a batch keeps
  every other write waiting; the run pauses between batches to let them in.
- An item Nyctr still holds something on is kept, marked missing, until that
  ends: a blocked address with an open or unconfirmed exception or a waiting
  request; a device a stored lookup is tied to; a guest Nyctr cut off or
  locked out, or whose access at the source has not run out. Guest passes are
  not items and are never dropped here. No lookup, request or audit record
  goes with a dropped item.
- Each run writes one audit record for each source that lost something, with
  how many of each kind went; Activity shows it. A run that drops nothing
  records nothing, and one source that fails does not stop the others.

An exception is ended at the source once, whoever asks: the tick, someone
opening the list of exceptions, an administrator ending it, or another copy.
Before Nyctr reads or changes an entry at a source, to open an exception or
to remove one, it takes a claim on that source and address (a row in the
settings table, as for a run) and saves it, so no database lock is held
during the provider call. Openings and endings of one address at one source
therefore go one at a time: an entry is never removed under an exception
that is being opened, and two openings at once share one entry that goes
with the last of them. An ending that finds the claim taken sends and records
nothing and is tried again at the next tick; an administrator is told the
exception is already being ended. An opening waits up to ten seconds for the
claim, because nobody tries it again on the person's behalf, and is then
refused in plain words with nothing sent. With the claim held the exception
is read again, and its row is locked and read once more before the ending is
recorded. The claim is given back with the record, at once when the change
fails, or when Nyctr is stopped mid-call, and only by the attempt that holds
it. One left by a copy that was killed can be taken over after five minutes.

An opening that fails never leaves an entry at the source that nothing on
record points at. With the claim held and before any add, Nyctr asks the
source whether the address is already allowed there, and puts the attempt on
record with the answer: a lease with status `unconfirmed`, which is never
access and is counted nowhere as an open exception. An address that was
already there is never removed, unless the add itself then finds it gone and
sends its own add: the add's answer wins over the first one, also when the
add fails afterwards. A stored exception replaces the record. If the
opening fails after its add may have been sent, or Nyctr is killed, the
record stays: Nyctr reads the source, removes the entry if it is there and
checks that it is gone, once before the opening answers and then on every
tick (after a kill, once the claim can be taken over). Until then
administrators see it under Open now in plain words, the person who asked is
told nothing was opened, the source cannot be removed, and a new opening of
that address first settles it or is refused. A source that offers no such
read gets a record Nyctr never acts on: it says Nyctr cannot tell whether it
put the entry there, and an administrator checks and ends it.

An entry Nyctr added has an exception or a record that will remove it, within
the known limits listed in docs/security-model.md. An opening that comes back
to find its claim taken over (it stood still for more than five minutes)
stores nothing, and cannot know what became of its entry meanwhile: its
record says so, Nyctr never acts on it, and an administrator is asked to
check at the source and end it. When an exception
of Nyctr's own ends while another open exception uses the entry, the duty to
remove it passes to that one, whatever it was recorded as. Nyctr tells its
own entry from a person's by the add's own read: the entry is Nyctr's if the
address was absent when Nyctr added it. Where a source cannot say, Nyctr
removes nothing and asks an administrator to check there.

A decision on a request holds nothing unsaved while a source is called. It
first takes a claim on the request (the same kind of row, always before the
entry's claim), and so does the access rule when it opens one by itself. A
second decision meanwhile is answered at once that the request is being
approved, and never waits on a database lock. The decision,
the exception and both claims are stored together; every failure gives the
claims back and leaves the request waiting with a note. A claim left by a
killed copy is cleared by the tick after five minutes. Automatic openings for
one person go one at a time, so the daily limit holds for requests sent at
the same moment.

Every change at a source (opening or removing an exception, issuing or ending
a pass, letting a guest on or cutting one off, and each undo) has an overall
limit of 60 seconds for all its requests together. A source that keeps an
answer trickling in is cut off at that limit: the change is recorded as
failed, never as done, and its claim is given back, so one stuck source holds
up the next ending there by a minute at most. The limit is well under the
five-minute hold, so a claim does not outlive its call. A collection locks
its source's row and then the rows it stores, only while storing, so
collections and endings never wait on each other.
Stopping Nyctr cancels a pass in progress: the source being read stays marked
as collecting until its lease is five minutes old, and the next run then takes
it over.

Saved-integration diagnostics reuse the bounded, verified read transport under
the collection lease. They return an ephemeral report of checked capabilities
and evidence gaps without importing the examined snapshot or changing the last
successful collection. A successful probe proves only the reported read scope.

## Core data

| Entity | Responsibility |
| --- | --- |
| Resource | Provider-namespaced site, network, device, workload, destination or policy |
| Relationship | Typed edge with source, collection time and evidence kind |
| Observation | Event, destination, reason, source time and expiry |
| Device assignment | Identity authorization with time-valid attribution |
| Sign-in tie | A signed-in person was on a device at a time, or a conflict where no tie was made. Never an assignment |
| Finding | Explanation, affected resources, supporting evidence and uncertainty |
| Access request | Durable user intent linked to a specific eligible observation |
| Integration | Provider, validated configuration, secret reference and collection health |
| Audit record | Actor, action, target, time and sanitized outcome |

Resources use provider/integration namespaces. Similar names and IP addresses do
not merge identities. Provider keys, device labels and addresses can change; a
future reconciliation layer must preserve evidence before joining records.

Each graph edge is **observed**, **configured**, or **inferred**. Physical
attachment, VLAN membership, hosting, policy application and DNS resolution are
different relationships. Unknown or stale evidence stays visible, and an item its
source has stopped reporting is marked and counted apart until it is dropped
(see the upkeep loop above). There is no
claim of a proven end-to-end traffic path merely because nodes are connected.

## Integration contract

Each adapter validates its configuration and returns a normalized snapshot with
resources, relationships, observations and capabilities. The API persists the
snapshot transactionally and records collection status. Source IDs are stable
within an integration. Collection uses verified HTTPS, bounded requests and
pagination, sanitized failures and no credential forwarding across redirects.

Provider capability reporting is explicit. A configured API credential does not
prove that event logs are available. UniFi Network's future event receiver will
be a channel within that integration. An optional generic receiver can later
support other sources without creating a duplicate UniFi provider.

The diagnostics report distinguishes adapter implementation from reads verified
during that check. Connectivity, certificate validation, credential acceptance,
response contracts, logging availability, and attribution gaps are separate
results; absent evidence remains unknown. Provider-controlled error text and
resolved credentials never appear in this report.

UniFi Fabric will group Site Manager connection/setup in the UI. Its API endpoint,
credentials and collection coverage remain separately modeled. The supplied
Carrier/ISP Fabric subscriber contract does not establish support for
organizational Blueprint/Canvas controls.

## Analysis and execution

The intended flow is collection → normalized evidence → analysis → proposal →
authorization → execution → verification. Each step has an explicit owner.

- Integrations: `nyctr/integrations/registry.py` holds the contract. Each kind of
  source is one module that declares what it reads, which capabilities it adds
  and what it can change. Everything below asks the registry for a capability and
  never names a vendor; see [the integration contract](../integration-contract.md).
- Collection: `nyctr/integrations/*` adapters and `nyctr/collection.py`. Read only.
- Analysis: `nyctr/risk.py` (block scoring), `nyctr/analysis.py` (rule-based
  findings) and `nyctr/links.py` (inferred links between sources). No model.
- Authorization: an administrator's decision, or a rule in `nyctr/policy.py`.
- Execution: `nyctr/integrations/actions.py`, gated by `NYCTR_PROVIDER_WRITES`,
  called from `nyctr/access.py` (leases) and `nyctr/guests.py`.
- Verification: DNS exceptions and guest authorisation read back the provider
  state (voucher create and delete are confirmed at the next collection); `nyctr/worker.py`
  and every lease read reconcile expired leases.
- Explanation: `nyctr/assistant.py` and the read-only `nyctr/query.py`. Every
  call to the model goes through `nyctr/model.py`, which holds where the model
  is, the limits on where its key may go and the trace fields of each call.

Execution still runs inside the API process. Separating it, and binding
approvals to an immutable plan digest, remain to be done.

Deterministic analysis should establish facts and policy semantics before AI
summarizes them. AI responses must refer to authorized evidence, identify gaps
and return structured proposals. Provider credentials stay outside model context.
The model is one chat-completions endpoint, connected by an administrator in the
console or set on the server ([the model](../model.md)); a proxy in front of it
can route to any provider and trace the calls. An external MCP surface is a separate, authenticated read interface;
it does not give external agents ambient mutation privileges.

Execution exists in a first form: an approval or the administrator's written
rule opens a lease, the gated action changes the provider and reads the change
back, and the outcome is recorded separately from the decision. An approval is
refused when the evidence behind it has expired. Not yet implemented: binding an
approval to an exact normalized plan (target, provider operation, object/scope,
duration, preconditions and plan digest), an executor that independently
verifies identity, policy and drift, and renewed approval for a changed plan. A
successful provider response and verified restoration of user access remain
separate outcomes.

Preauthorized temporary grants require the deterministic administrator rule with
its limits. AI cannot author or broaden that rule. Leases are durable, track
whether Nyctr owns the provider entry, tolerate overlapping requests, are
reconciled after restart, and stay open and visible when a removal fails.

## Identity and member privacy

Local authentication and optional OIDC create server sessions. OIDC provider
subjects are authoritative; display names and email claims alone cannot grant
administrator rights. Explicit trusted group mapping determines roles.

A member sees only observations associated with an eligible personal/shared
device, attributed at event time and still authorized at read time. An upstream
DNS profile or gateway address often represents multiple people, so unidentified
events remain administrator-visible. Infrastructure devices are excluded from
the member workflow unless intentionally classified and assigned.

With recognition at sign-in switched on, a member also sees the device they
signed in on. On the first portal request after signing in (never inside
sign-in) `nyctr/presence.py` takes the request's address from `nyctr/peer.py`,
requires it to lie inside a network a source collected and not to be a listed
proxy's, and asks that source's integration, through its `devices.lookup`
capability, which client holds it now: one read with a five-second limit,
paced, its answer remembered for a minute. If the read fails, the stored
inventory stands in while the last collection is under 15 minutes old.
Exactly one client must hold the address. The tie reaches back a set time
before the first sign-in and assumes the person signing in was the one using
the device in that time; `nyctr/deps.py` alone turns a tie or an assignment
into what a member may see.

Inbox freshness and durable history are separate. Expired entries disappear
from the requestable inbox; existing requests retain their evidence snapshot and
audit trail. New requests and future execution revalidate the source evidence.

## Operational scope

This first version is one workspace and one application process. It is not a
multi-tenant SaaS. Start with one replica for migration/bootstrap and collection.
Future horizontal scaling needs migration coordination, distributed throttling,
job leases and stronger audit retention controls. See the roadmap for the gates
before production and write-capable operation.
