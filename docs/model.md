# The model

Nyctr's assistant answers an administrator's questions and explains findings
through one chat endpoint that speaks the common chat-completions interface
(`POST <endpoint>/chat/completions`). The model sees only the bounded, redacted
evidence pack, has no credentials and no tools, and cannot change anything. With
no model connected the assistant is off; the list of what needs a person is
rule-based and always works.

## Connecting it

An administrator connects the model in the console: **Setup, This installation,
Model**. The card takes the endpoint, the model's name, the name of the secret
that holds the key, how calls are traced and a time limit of 5 to 120 seconds.
**Test** sends one tiny fixed question and says how it went: the model answered,
the endpoint refused (with the HTTP status), it could not be reached, something
answered in the wrong shape, or no answer came in time. Nothing the endpoint
said is repeated.

The server's own settings keep working. `NYCTR_AI_BASE_URL`, `NYCTR_AI_MODEL`
and `NYCTR_AI_API_KEY` are the starting value; once an administrator saves in
the console, the console's value is the one in force, and the card says which
of the two it is. An installation with only the server's settings sends what it
always sent: no trace header, unless the operator sets `NYCTR_AI_TRACE`. Every save is audited with the old and new settings. The demo
workspace cannot connect a model.

## Where the key may be sent

Whoever runs the server decides this, not the administrator in the browser:

| Server setting | Effect |
| --- | --- |
| `NYCTR_MODEL_HOSTS` | Comma-separated servers an endpoint may be on. A bare name, `llm.example.org`, allows HTTPS on port 443 only. Any other port, or plain HTTP, must be written in full with no path: `https://llm.example.org:8443`, `http://proxy.internal:4000`. A name is a plain server name in either form: no wildcard and no trailing dot. The server in `NYCTR_AI_BASE_URL` is always allowed, on its own scheme and port only. Empty allows no other server. |
| `NYCTR_MODEL_SECRET_<NAME>` | One key the console can name. The console takes the name, never the key. |

- The secret's name must match `NYCTR_MODEL_SECRET_*` and be set on the server.
  A source's secret (`NYCTR_CONNECTOR_SECRET_*`) is refused here, and a model's
  is refused for a source.
- `NYCTR_AI_API_KEY` is sent only to the server in `NYCTR_AI_BASE_URL` (same
  scheme, host and port). An endpoint saved in the console on any other server
  gets a key only by naming a `NYCTR_MODEL_SECRET_*`.
- A listed name is never trusted in clear text or on another port. Listing
  `llm.example.org` does not allow `http://llm.example.org` or
  `https://llm.example.org:8443`: each of those is another entry, and the
  operator writes it only if it is meant. So a proxy inside the same cluster or
  Compose network on plain HTTP is listed as, say, `http://proxy.internal:4000`,
  and that traffic should stay off any shared network.
- The same holds for the server's own endpoint: its scheme and port are part
  of where `NYCTR_AI_API_KEY` may go, and of what the console may save without
  a list entry.
- An endpoint saved in the console with a sign-in name, a password, a question
  mark or a `#` is refused, and so is a cloud metadata or link-local address,
  listed or not. That refusal applies to connections made in the console. The
  server's own `NYCTR_AI_BASE_URL` is the operator's choice and is not checked
  that way.
- No redirect is followed. An endpoint that answers with one is reported as
  refused, and the key goes nowhere else.
- Both lists are checked when a value is saved and again before every call, so
  taking a server or a secret away on the server stops the calls. The assistant
  is then off, and the list of what needs a person says why.
- A server address that cannot be used (`NYCTR_AI_BASE_URL` with no server name,
  or a port that is not a number from 1 to 65535) does not stop the server. The
  model is off, and the card and the list of what needs a person say that the
  server's setting must be corrected.
- A saved value that a version of Nyctr cannot read (after a rollback, for
  example) never falls back to the server's own endpoint and key. The model is
  off, the card and the list of what needs a person say the setting must be
  saved again, and nothing is sent until it is.

In the Helm chart these are `assistant.hosts` and `assistant.secrets`; in
Compose, `NYCTR_MODEL_HOSTS` and one `NYCTR_MODEL_SECRET_<NAME>` line per key.

## Putting a tracing proxy in front

To see every call the model receives, point the endpoint at a proxy that speaks
the same chat-completions interface and records what passes through it, and let
the proxy hold the real provider's key. Allow the proxy in
`NYCTR_MODEL_HOSTS` (in full if it is on plain HTTP or its own port), give Nyctr the proxy's own key as a `NYCTR_MODEL_SECRET_*`,
and connect it in the console.

Nyctr describes each call in request headers, never in the body by default,
because an endpoint ignores a header it does not know. The card's **Tracing**
choice sets how much. A connection saved in the console is traced for a tracing
proxy unless the administrator picks otherwise. The server's own settings are
not traced unless `NYCTR_AI_TRACE` is set to `standard`, `proxy` or `proxy_body`
(`assistant.trace` in the Helm chart); the default there is `off`:

| Choice | What is sent |
| --- | --- |
| Off | No trace header. |
| A trace number only | `traceparent`, the W3C header, with a new 32-hex trace id per call. |
| For a tracing proxy (offered when saving in the console) | `traceparent`, and the fields below as the headers one common open-source proxy reads. |
| Also inside the request | The same, and the same fields in the body's `metadata` object, for a proxy that reads only the body. Some endpoints reject a body field they do not know, so use it only with a proxy that takes it. |

| Field | Header | Value |
| --- | --- | --- |
| Trace id | `langfuse_trace_id` | The trace id in `traceparent`. |
| What the call is for | `langfuse_trace_name` | `nyctr.question`, `nyctr.explanation` or `nyctr.test`. `nyctr.analysis` is reserved. |
| What it is about | `langfuse_session_id` | `finding:` and 16 hex characters of a keyed digest of the finding's id, so calls about one finding group together. Absent when a call is about nothing in particular. |
| The rest | `langfuse_trace_metadata` | JSON: `nyctr_version`, `prompt_version`, `purpose`, `subject_kind`, `mode`. |
| Version | `langfuse_trace_release` | The Nyctr version. |

The header names are that proxy's and sit in one table in `nyctr/model.py`;
Nyctr does not know or care which proxy is there. Nothing about a person or a
device is in a trace: no name, email, device name, hardware or network address,
and never the key. An id is sent as a keyed digest (HMAC-SHA256) because ids
of findings are built from device ids, and a plain digest could be matched
against guessed ids by anyone who knows how an id begins. The key is 32 random
bytes this installation makes the first time it sends a session and keeps in
its own database. It is not the model's key, it is in no request, answer or
audit record and in no log line Nyctr writes, and two installations give the
same finding different sessions. SQL statement logging, which is off unless
whoever runs the server turns it on, writes stored values as they are saved,
this key included. Replacing it only splits old and new traces into separate
groups.
The request's `user` field is never sent. The proxy still sees
the request itself, which holds the redacted evidence pack and the
administrator's question, so run it where that may be kept.

Known limits: some web servers in front of a proxy drop headers that hold an
underscore, in which case calls still work and traces are not grouped. Whether
a given proxy version turns the metadata header's JSON text back into fields
has not been checked against a running proxy.
