# Guest Wi-Fi design

Decided 2026-11-10. This records how guests sign in, what Nyctr does, and why.

## Decision

**UniFi serves the guest sign-in page. Nyctr never does.** Nyctr works only from
the management side, through the UniFi Network API:

1. A guest joins the guest Wi-Fi. UniFi holds the device and shows its own
   captive portal.
2. The guest types a pass code that an administrator issued in Nyctr (a UniFi
   hotspot voucher created through the API), or an administrator lets the
   waiting device on from the Nyctr console.
3. Nyctr reads UniFi to learn who is on, which access point they use and how
   much data they use, and ties blocked DNS lookups to the device.
4. Nyctr can cut a device off, by hand or under the written cut-off rule.

Nothing on the guest network needs to reach Nyctr. Block it there.

## Options considered

| | A. Nyctr is the portal | B. API only | C. UniFi portal, Nyctr on the management side (chosen) |
| --- | --- | --- | --- |
| Who serves the sign-in page | Nyctr, set as UniFi's External Portal Server | UniFi | UniFi |
| Guest devices can reach Nyctr | Yes, before they are authorised | No | No |
| Pass tied to a device | Exactly: Nyctr authorises the device itself | By matching times | Exactly when let on from the console; by matching times for a pass code |
| Guest Wi-Fi works if Nyctr is down | No new guest can sign in | Yes | Yes |
| Nyctr learns of a new guest | Immediately | At the next collection | At the next collection, or straight away with the optional nudge |
| Notice shown to guests | Nyctr's own page | UniFi's page | UniFi's page, with wording Nyctr supplies |

Option C is option B plus three things: letting a waiting device on from the
console, an optional push from UniFi so Nyctr looks straight away, and a check of
which Wi-Fi names actually sit behind the captive portal.

## Why not make Nyctr the portal

UniFi supports it. With an external portal, any web request from an
unauthorised guest is redirected to the external server with the device's
hardware address (`id`), the access point (`ap`), the Wi-Fi name (`ssid`) and
the original address (`url`) in the query string. The server then finds the
client by hardware address and sends `AUTHORIZE_GUEST_ACCESS`
([Ubiquiti: External Hotspot API](https://help.ui.com/hc/en-us/articles/31228198640023-External-Hotspot-API-for-Authorization-Clients)).

The cost is where that puts Nyctr:

- **It exposes the most sensitive system to the least trusted devices.** Nyctr
  holds a UniFi key that can authorise and cut off clients, a NextDNS key that
  can change the allowlist, and the evidence about everyone's network. An
  external portal must be reachable by devices that have not signed in, which
  are exactly the devices the cut-off rule exists for.
- **The request cannot be trusted.** The hardware address arrives as a query
  parameter from the guest's own browser. Anyone on the guest Wi-Fi could call
  the authorise endpoint for any address, so the only real control would be the
  pass code, checked on a page Nyctr would have to harden against the open
  guest network.
- **Captive portals start in plain HTTP.** The redirect has to be intercepted
  before TLS; Ubiquiti's own example uses an `http://` portal address.
- **It makes Nyctr a dependency of the Wi-Fi.** If Nyctr is down or being
  upgraded, no guest can sign in.

What option A buys is an exact link between a pass and a device, an instant
view of new guests, and a custom page. Option C recovers most of that without
the exposure: a device let on from the console is linked exactly, a one-device
pass leaves little room for a wrong match, the nudge removes most of the delay,
and UniFi's page can carry Nyctr's notice.

## What the code does

- `nyctr/guests.py` issues and ends passes, lets a waiting device on (`admit`),
  cuts off, restores and locks out, and returns `portal` in `GET /api/guests`:
  who serves the page (always `unifi`), each Wi-Fi name with whether UniFi's
  captive portal gates it, and the suggested notice.
- `nyctr/integrations/unifi.py` reads `/v1/sites/{site}/wifi/broadcasts` and
  records each name's `hotspotConfiguration.type`. The API does not say whether
  a captive portal is UniFi's own or an external server.
- `GET|POST /api/hooks/collect` is the optional nudge. It needs the shared
  secret in `NYCTR_NUDGE_TOKEN`, reads nothing from the request, starts an
  ordinary read-only collection and runs at most once every 30 seconds.
- A test (`test_nothing_is_served_to_a_device_that_has_not_signed_in`) walks
  every API route and fails if one answers without a session, apart from
  sign-in, health, the API description and the nudge. Adding a guest-facing
  page would have to change that test on purpose.

## Setting it up in UniFi

1. Create a guest network on its own VLAN and a Wi-Fi name for it.
2. Turn on Hotspot (captive portal) for that Wi-Fi name with **Vouchers** as
   the sign-in method. Leave External Portal Server off.
3. Paste the notice from Nyctr's Guests screen into the portal's terms box.
4. In the firewall, block the guest network from reaching the Nyctr host.
5. In Nyctr, connect UniFi and add `unifi_network` to `NYCTR_PROVIDER_WRITES`
   so it can issue passes and cut devices off.
6. Optional: choose how often Nyctr collects under Setup, This installation
   (every 15 minutes unless changed), and in UniFi's Alarm Manager
   (Network 9.3 or later) add a webhook on client connected and threat
   detected that calls `https://<nyctr>/api/hooks/collect/<token>`
   ([Ubiquiti: Alarm Manager](https://help.ui.com/hc/en-us/articles/27721287753239)).

Steps 2, 3 and 6 are done in UniFi's own interface; the API has no setting for
them. None of this has been run against a real console by this project.

## Known limits

- A pass code typed into UniFi's page is matched to a device by time. The API
  does not record which voucher a client used. Issue one-device passes when
  the link matters, or let the device on from the console.
- The nudge puts its token in the address when the sender cannot set headers,
  so it can appear in access logs. It can only start a read-only collection.
- Ubiquiti does not document the Alarm Manager webhook body. Nyctr ignores it.
- With the collection schedule turned off and no nudge, Nyctr sees a new guest
  only when an administrator presses Collect. With it on, the cut-off rule and
  lock-out act at every scheduled collection without anyone at the console.
- A cut-off lasts until the device gets access again. If a cut guest signs in
  with another pass, or is let on in the UniFi console, the next collection shows
  it as online and the cut-off rule looks at it again. Use lock out to keep a
  device off: Nyctr cuts a locked device again at every collection.
- UniFi's API lists connected clients only and has no flow or event feed.
  Guest activity is blocked DNS lookups; port scans are not visible.
