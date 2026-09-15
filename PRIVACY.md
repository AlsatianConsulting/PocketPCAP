# PocketPCAP — Privacy Policy

**Last updated:** 15 September 2026
**Applies to:** PocketPCAP for Android, package `dev.alsatianconsulting.pocketpcap`
**Publisher:** Alsatian Consulting, LLC — https://www.alsatian.consulting

---

## Summary

PocketPCAP has no account, no sign-in, no telemetry, no analytics, no advertising and no
crash reporting. We do not operate a server for it and we receive nothing from it.

Your captures, your analysis, your notes and your decryption keys stay on your device.

Three features do reach the internet, and only when you invoke them. They are listed in
full under [What leaves your device](#what-leaves-your-device). The most important is the
**Traffic Map**, which sends IP addresses taken from your capture to third-party lookup
services. If that matters to you, do not open the Traffic Map.

---

## What PocketPCAP stores on your device

| Data | Where | Notes |
|---|---|---|
| Capture files (PCAPNG/PCAP) | `Documents/pocketpcap` by default, or the folder you choose | Contains real network traffic, including payloads unless you captured or exported headers-only |
| Exports — filtered, merged, headers-only, annotated captures; CSV/JSON tables; KML/GeoJSON maps | Same folder | Created only when you ask for them |
| Extracted objects (HTTP, TFTP, SMB, Email, DICOM) | App-private storage | Created only when you ask for them |
| Endpoint aliases, saved and recent filters, bookmarks, packet notes | Local database `pocketpcap.db` in app-private storage | Never transmitted |
| TLS key log (`SSLKEYLOGFILE`) you import | App-private storage | Never transmitted |
| 802.11 keys — WEP key, WPA/WPA2 passphrase or PSK | App-private preferences | Never transmitted |
| Offline GeoIP database you import | App-private storage | Never transmitted |
| Settings — output directory, display mode, autostop ceilings | App-private preferences | Never transmitted |
| Diagnostic logs, when you collect them | App-private storage | Never transmitted |

None of this is sent anywhere by the app. It is yours, on your device.

## What leaves your device

This is the complete list. Nothing else in the app makes a network request.

### 1. Traffic Map and endpoint location — **third-party lookups**

When you open the **Traffic Map**, or look up the location of a single endpoint,
PocketPCAP makes these requests:

| Request | Sent to | What is disclosed |
|---|---|---|
| Your own public IP address | `https://api.ipify.org` | Your network's public IP |
| Geolocation for an endpoint | `https://ipwho.is/<address>` | That endpoint's IP address — **only** when your imported offline GeoIP database has no entry for it |
| Registration data for an endpoint | `https://rdap.org/ip/<address>` | That endpoint's IP address — only when the geolocation result did not already carry organisation/ASN detail |

The Traffic Map performs these lookups for up to **40** of the public endpoints in the
open capture, ordered by bytes.

**Only globally routable unicast addresses are ever sent.** Private (RFC 1918), loopback,
link-local, carrier-grade NAT, multicast, broadcast, documentation and test-range
addresses are all excluded before any request is made — so the mDNS, SSDP and broadcast
traffic that fills a typical LAN capture is never disclosed to anyone.

**What this means in practice:** the operators of `ipwho.is` and `rdap.org` learn which
public IP addresses appear in your capture, and `api.ipify.org` learns your public IP.
They do not receive your capture, your packets, or their contents — only the addresses
being looked up. These are independent services with their own privacy practices, which we
do not control.

**To avoid it entirely:** do not open the Traffic Map or the endpoint location screen.
Every other analysis feature works without any network access. Importing an offline GeoIP
database that carries organisation/ASN detail removes both lookups for addresses it
covers.

### 2. Check for Updates — only when you tap it

**Settings → About → Check for Updates** requests
`https://api.github.com/repos/AlsatianConsulting/PocketPCAP/releases/latest` and
compares the version there with the one installed. It sends no capture data and no
identifiers, and it never downloads or installs anything. It runs only when you tap it.

### 3. Name resolution — off by default, or local only

- **Reverse DNS** is **off by default**. If you enable *Settings → Capture → Resolve
  hostnames*, the app sends DNS queries for addresses in your capture to whatever DNS
  resolver your device is configured to use. Your DNS provider therefore sees those
  addresses.
- **Local discovery** (mDNS, NetBIOS, LLMNR) broadcasts on your local network only. It
  does not leave the network segment and reaches no third party.
- **MAC vendor lookup** uses an OUI database bundled inside the app. It is entirely
  offline.

### 4. Anything you share or export

When you use the share sheet or copy an export off the device, you choose the destination
and that destination receives the file. A capture may contain credentials, message
contents, browsing history and other sensitive material. Prefer **Share headers only (no
payloads)** when the payloads are not the point of sharing.

### 5. Rootless VPN capture is local

Rootless capture uses Android's `VpnService` to create a local tunnel on the device so
traffic can be recorded to a file. It does **not** route your traffic through any remote
server, does not modify traffic, and does not send traffic anywhere. The tunnel exists
only on your device. PocketPCAP excludes its own traffic from it.

## What PocketPCAP never does

- No account, sign-in, registration or email collection
- No analytics, telemetry, usage statistics or crash reporting
- No advertising, advertising identifiers or tracking of any kind
- No collection of device identifiers, IMEI, phone number, contacts or location
- No upload of captures, packets, keys, notes or settings
- No selling or sharing of personal information — we hold none to sell or share

## Permissions and why they are needed

| Permission | Used for |
|---|---|
| `INTERNET` | The three network features listed above. Not used for anything else. |
| `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` | Enumerating network interfaces and their state for the capability check and capture setup |
| `CHANGE_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE` | Holding a multicast lock so LLMNR/mDNS local name resolution can receive replies |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` | Keeping a capture running, with a visible notification and a stop control, while the app is in the background. Declared as `specialUse` rather than `dataSync` because nothing is synchronised — packets are written to a local file and nothing is transmitted off the device |
| `POST_NOTIFICATIONS` | The capture notification and its stop control |
| `BIND_VPN_SERVICE` (via `VpnService`) | Rootless local capture, as described above |

PocketPCAP requests **no storage permission**. Captures reach `Documents/pocketpcap`
through Android's MediaStore, which needs none.

Root access, where you grant it, is used solely to run the bundled `dumpcap` so it can
open a live network interface. Nothing else in the app requires or uses it.

## Traffic you capture belongs to other people too

A packet capture records the communications of every device on the segment you are
capturing, not only your own. Those communications may contain other people's personal
data.

You are responsible for capturing only on networks and devices you own or are authorised
to inspect, and for handling what you capture lawfully — which in many jurisdictions
includes data-protection obligations towards the people whose traffic appears in it.
PocketPCAP is a passive diagnostic tool; it does not and will not perform injection,
spoofing, deauthentication or any other active attack.

## Retention and deletion

We retain nothing, because we receive nothing. Everything lives on your device and you
control it:

- **Capture files and exports:** delete them in the app's Files screen, or with any file
  manager in `Documents/pocketpcap`.
- **Aliases, filters, bookmarks, notes:** delete individually in the app, or clear the
  app's storage in Android Settings.
- **TLS key log and 802.11 keys:** *Settings → Decryption* → Clear.
- **Offline GeoIP database:** *Settings → GeoIP* → Clear.
- **Everything at once:** uninstall the app, or use Android Settings → Apps → PocketPCAP →
  Storage → Clear storage. Note that uninstalling does not delete files already written to
  `Documents/pocketpcap`; remove those yourself if you want them gone.

Data sent to the third-party lookup services in section 1 is subject to those services'
own retention practices, not ours.

## Children

PocketPCAP is a network diagnostic tool for technical users. It is not directed at
children and collects no personal information from anyone, including children.

## Changes to this policy

If the app's data handling changes, this policy will be updated and the date at the top
changed with it. The current version is always the one published at the URL in the Google
Play listing, and its history is public in the project repository.

## Contact

- **Website:** https://www.alsatian.consulting
- **Project:** https://github.com/AlsatianConsulting
- **Email:** info@alsatian.consulting

---

*PocketPCAP is free software licensed GPL-3.0-or-later. This document describes the
behaviour of the published build and is not legal advice.*
