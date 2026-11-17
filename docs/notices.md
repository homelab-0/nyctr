# Notices

Nyctr can tell an administrator when a member is waiting, or when an opening could not be removed, without the administrator opening the console. Setup holds the address. A background tick sends the notice. The message cannot approve anything.

## What is sent

The body is JSON, version 1. It names the notice, the kind, the time, the Nyctr version, a title, up to three short lines, and the request: its id, the blocked name, the device's name, the person's name, the block's reason and score, and the minutes asked. It also carries a link to that request in the console. The link works only after sign-in and carries no token. Nothing in the body is a secret, a hardware address or a network address.

The kinds sent today are `request_waiting`, `lease_stuck` and `test`.

## Where it may go

The address is HTTPS. Whoever runs the server can list other servers in `NYCTR_NOTICE_HOSTS`, in the same form as `NYCTR_MODEL_HOSTS`. A bare name is HTTPS on port 443. Plain HTTP, or another port, is written in full (`http://name:4000`, `https://name:8443`).

A loopback, link-local, metadata or other address that is not public is refused unless that exact server is listed. So are multicast, `::`, and the translation prefixes `64:ff9b::/96` and `::ffff:0:0:0/96`. An IPv4 address written inside `::/96` is judged as that IPv4 address. If any answer for the name is such an address, the name is refused unless it is listed. Nyctr checks the address it actually connected to. It does not follow a redirect. The whole send, from the lookup through the last byte it reads, takes at most 10 seconds, and the database is not held while the call is open. Setup and the activity record show the server, not the rest of the address. A path that is not plain letters, numbers and ordinary marks is refused.

## How to verify the signature

When a secret is named, Nyctr sends two headers:

```
X-Nyctr-Notice-Id: <the notice id>
X-Nyctr-Signature: t=<seconds>,v1=<hex>
```

The hex is HMAC-SHA-256 of the raw body, prefixed by the seconds and a dot: the bytes of `t`, then `.`, then the body. The key is the secret whose name matches `NYCTR_NOTICE_SECRET_*`. Setup stores the name, never the secret.

To verify, split `t` and `v1`, compute that HMAC, and compare the hex in constant time. Also check that `t` is recent. A changed body or a changed `t` does not match. The same notice id means the same notice; a repeat can be dropped.

With no secret the notice is sent unsigned, and Setup says so. If the named secret is missing, nothing is sent.

Nyctr tries at once, then after 1, 5, 15 and 60 minutes. A 2xx is delivered. A 4xx other than 408 and 429 is not tried again. Any failure spends a try. Giving up is shown on the attention list, and so is a named secret that cannot be used. One running copy does not send a notice another copy is already sending. If a copy stops during a send, another copy sends that notice once the claim is a minute old. The same notice id is sent again, so the receiver can drop the repeat. A test from Setup sends a notice of the kind `test`.
