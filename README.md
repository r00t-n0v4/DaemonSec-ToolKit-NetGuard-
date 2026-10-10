# NetGuard

**A pocket-sized network security toolkit — VPN-based traffic observation, WiFi/BLE airspace awareness, proximity fox-hunting, and bug-bounty recon in one offline-first Android app.**

`v0.9.5` · 6 tabs · pure Android (no root, no Termux) · exports MD/JSON/PDF on-device

## What it does

NetGuard is a **self-contained, Termux-free** pentest companion. Every scan writes structured findings to an on-device Room database, everything is grouped for at-a-glance reading, and every session can be exported, viewed, or saved on the phone.

| Module | What you get | Root needed |
|---|---|---|
| **Network Recon** | ARP-table host discovery, active TCP sweep of your whole /24, mDNS + SSDP passive listen, OUI vendor lookup | No |
| **WiFi Scan** | Every visible AP recorded (SSID/BSSID/ch/security/RSSI), channel-congestion advisor, evil-twin detection, security-downgrade detection, venue-SSID rogue-AP alerts — all grouped in one view | No |
| **Traffic Observation** | `VpnService` TUN observer: real **UDP forwarding** (DNS/QUIC/HTTP3 pass through), DNS query log, **TLS SNI extraction** (what domains, without decryption), known-tracker flagging, cleartext-port flagging | No |
| **BLE Discovery** | Nearby-device scan **classified into groups** (below), AirTag/Tile/SmartTag/Chipolo tracker detection incl. Apple Find My beacons, movement heuristic | No |
| **🦊 Fox Hunt** | **Its own tab**: enter a tracker's MAC (copy it from any BLE row), Hunt, and NetGuard locks onto that device — live RSSI, warmer/colder range estimate, "walk back to where that was" best-signal guidance, packet counter; every packet logs as a hunt trail. Platform-filtered to the target MAC (battery-friendly) | No |
| **GATT Profiling** | Connect to any BLE device, walk the service/characteristic tree, flag **writable-unencrypted characteristics** (the smart-lock vuln pattern), JSON profile export | No |
| **Web Recon** | crt.sh subdomain enum, DNS-over-HTTPS record pulls, security-header audit (CSP/HSTS/cookies/CORS), directory busting with **custom-404 fingerprinting**, reflection triage, severity + OWASP tags | No |
| **OSINT** | Username presence across 12 platforms, HIBP breach lookup, Wayback CDX pull, GitHub secret-dork search, domain RDAP **+ IP intel (RDAP/AbuseIPDB) — domains not required** | No |
| **Reporting** | Markdown / JSON / **PDF** (rendered on-device), session diffing ("new since last scan"), scope declaration auto-embedded, in-app viewer, save to Downloads, share sheet, per-report delete | No |
| **Findings feed** | Every row carries a **source badge** (Bluetooth/WiFi/LAN scan/OSINT/Web recon/Traffic), collapsible radio sections, and **🛰 intel records**: recon/OSINT results group per target — one tap opens everything a target produced (TXT/A/CAA/SOA/RDAP/headers…) in one place | No |

## At a glance: the Nearby tab

One unified classifier buckets **every device** — BLE, WiFi APs, LAN neighbors — into the same groups, whether it announced a name, a Bluetooth company ID, or just a MAC:

**Red alerts (pinned on top):**
- `⚠ Possible Evil Twins` — same SSID broadcast by multiple BSSIDs with differing security, WPA→open downgrade decoys, and **venue SSIDs** (Starbucks/airports/hotels…) spoofed by a lone open/unknown AP
- `⚠ Trackers / Flipper Alerts` — AirTags/Find My, Tiles, SmartTags, Chipolos, and **Flipper Zeros** (matched by the `80:E1:26` hardware OUI, so renamed devices still classify)

**Radio sections (collapsible):**
- **BLUETOOTH** — Flipper Zero · Trackers · Meta/AR Glasses · Headphones/Audio · TV/Media · Wearables · HID/Input · Vehicle · Dev Boards (ESP32/nRF) · Phones/Computers · Other
- **WI-FI** — anomalies first, then APs grouped by the same categories (TVs/Cast devices classify from their SSIDs), then LAN neighbors

**Per-device copy:** every row (Nearby + Findings) has a copy button — long-press the row or tap the copy icon to put the MAC/BSSID/IP on the clipboard with a toast.

**The Findings feed is organized, not a dump:** collapsible `BLUETOOTH (n)` / `WI-FI (n)` / `WIFI ANOMALIES (n)` / `LAN (n)` sections plus **🛰 intel records** — recon on `example.com` or a username matrix produces ONE record per target; open it to see every DNS record type (TXT/A/AAAA/CAA/SOA/NS/MX), RDAP hits, headers, and platform results the recon produced.

## Architecture

One-directional data flow — modules never touch the database:

```
┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│ recon/*     │  │ wifi/* +    │  │ web/ osint/  │
│ hosts+ports │  │ ble/* radio │  │ HTTP recon   │
└──────┬──────┘  └──────┬──────┘  └──────┬───────┘
       │                │                │
       ▼                ▼                ▼
   ═══════════════════════════════════════════
        FindingBus  (SharedFlow, DROP_OLDEST)
   ═══════════════════════════════════════════
                       │
                       ▼
          NetGuardApp collector (single DB writer)
                       │
                       ▼
   Room (findings + sessions)  ──DAO Flows──►  Compose tabs
                       │
                       ▼
        ReportExporter ──► .md / .json / .pdf
                       ├──► in-app viewer (text | PdfRenderer)
                       ├──► MediaStore Downloads/NetGuard/
                       └──► share sheet (FileProvider)

   vpn/NetGuardVpnService ──► TUN reader ──► UDP NAT out
                              (protect()'d sockets, RFC 1071 checksums)
```

**Design choices worth stealing:**
- **Sealed `Finding` model with JSON payloads** — the Room table never churns as subtypes evolve; the type-discriminator + payload-blob pattern means adding a module touches zero migrations.
- **`SocketProtector` singleton** — the VpnService registers its `protect()` at startup and every module's sockets (HTTP recon, BLE listeners, sweeps) bypass the TUN instead of tunneling into the observer itself. `WifiPinner` additionally binds every probe socket to the WiFi `Network` — with WiFi + LTE both up, default-network routing would otherwise send LAN probes into the cellular agent (RFC1918 unroutable there), silently killing port scans.
- **Bounded UI reads + resilient writer** — the feed observes a newest-300 window (a scan burst = hundreds of inserts; re-diffing the whole session per insert stalled the tab), and the single DB writer retries failed rows instead of dying.
- **Classification-before-render** — grouping decodes the raw field; rendering formats the row. Never conflate the two.
- **Dark-only theme, terminal aesthetic** — near-black surfaces, one signal-yellow accent, red flagged rows, glitch-streak background on the control screen only (readability beats ambience under dense logs).

## Build it

**From the CLI (no Android Studio required):**

```bash
# one-time: user-space toolchain (JDK 17 + Android SDK + Gradle)
mkdir -p ~/opt && cd ~/opt
curl -fLo jdk17.tar.gz "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse"
curl -fLo cmdline-tools.zip "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
curl -fLo gradle.zip "https://services.gradle.org/distributions/gradle-8.9-bin.zip"
tar xzf jdk17.tar.gz && mv jdk-17* jdk-17 && unzip -q gradle.zip
mkdir -p android-sdk/cmdline-tools && unzip -q cmdline-tools.zip -d /tmp/clt
mv /tmp/clt/cmdline-tools android-sdk/cmdline-tools/latest
export JAVA_HOME=~/opt/jdk-17 ANDROID_HOME=~/opt/android-sdk
yes | ~/opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
~/opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
echo "sdk.dir=$HOME/opt/android-sdk" > local.properties

# build
~/opt/gradle-8.9/bin/gradle assembleDebug --console=plain --no-daemon
# → app/build/outputs/apk/debug/app-debug.apk
```

**Or just open the project in Android Studio** and hit Run — it's a standard Gradle/Compose project (AGP 8.5.2, Kotlin 1.9.24, Compose BOM 2024.06).

## Install & use

```bash
adb install -r app-debug.apk        # or sideload the APK
```

1. **Start monitoring** — grants location/BLE/notification permissions, then the Android VPN consent dialog. UDP traffic (DNS, QUIC/HTTP3) now flows through the observer; TCP is **observe-only** until the userspace-stack integration (see VPN status below) — expect HTTPS to stall while the tunnel is up.
2. Run scans from the deck: **ARP scan** (instant) · **Network scan** (whole /24 + mDNS/SSDP, port probes + banner grabs + OS guessing) · **WiFi scan** (all APs + anomaly detection, ~10s) · **BLE device scan** (~15s).
3. **OSINT** and **Web recon (bug bounty)** are one-tap dropdown sheets on the same deck — tap to expand every tool inline (username matrix, HIBP breaches, IP/domain RDAP, Wayback, GitHub dorks / crt.sh subdomains, DoH records, header audit, dir busting, reflection triage). Entering a target and running it = declaring your authorization; `.gov`/`.mil` refused.
4. Hunting a tracker? Open the **🦊 Fox Hunt** tab, paste the MAC (long-press-copy it from any BLE finding), press Hunt, and walk — the readout goes warmer/colder with a best-signal trail.
5. Watch **Nearby** for the classified group view; red groups alert on top.
6. **Reports** → open in-app / save to `Download/NetGuard/` / share / delete. The scope declaration you typed is embedded on every exported page.

OSINT extras live in **Settings** (gear icon): your HIBP API key and a GitHub token unlock breach lookup and code-search dorking. Keys stay in app-private prefs and never appear in exports.

## Changelog (recent)

**0.9.5 — live traffic logs that work under the tunnel (fixed the tunnel itself)**
- **The VPN reader finally reads more than one packet**: the tun fd netd hands out is O_NONBLOCK, and the reader treated `EAGAIN` (no packet right now) as end-of-stream and EXITED after the first packet — that was the real "the tunnel kills the internet" bug all along (DNS died one millisecond in). It now parks on EAGAIN like every VPN app does.
- **DNS works under the tunnel again** via the UDP-NAT forwarder (OpenDNS upstream): verified `ping example.com` resolving through the tunnel.
- **Traffic logs flow again while monitoring runs**: DNS rows carry real hostnames (api.github.com, www.wikipedia.org, api.ipify.org…), TLS/TCP rows carry destination IP + port; rows land in the Findings list live during the session.
- **TLS SNI capture fixed**: rows emit at each flow's first DATA packet instead of the payload-less SYN (the SYN can't carry SNI — every TLS row used to be a bare IP).
- Per-app attribution stays honest: only NetGuard's own flows get a package name (Android 10+ kernel-filters other apps' /proc/net socket rows; DNS rows attribute the querying app via the tun path when readable).

**0.9.4 — Findings type-filter slider**
- The type-filter chips (All/WEB/WIFI_AP/…/OSINT) overflowed their fixed Row and the last chips (OSINT) rendered off-screen — unreachable when several sensors ran in one session. The row is now a horizontal slider (swipe to reach every type). Verified: swipe left → OSINT chip reachable → filters to its record.

**0.9.3 — OSINT record stacking + anomaly section**
- **OSINT results stack per identifier**: a username-matrix run now lands as ONE `🛰 <username>` record — all 12 platform results (GitHub/Reddit/X/Keybase/...) expand from it with per-row OSINT badges and ⚠ flags on the record when any platform hit exists. Verified live: `huangnova (12 results)`, Reddit/X/SoundCloud/Medium/Telegram/Instagram flagged red.
- **WiFi anomalies get their own collapsible section** (`WIFI ANOMALIES (n)`, after WI-FI): mixed in, the band-wide congestion rows read as broken AP entries (bare "wifi" headline crushed under the badge). Anomaly rows now headline the kind ("Congestion") with the full detail line beneath.

**0.9.2 — Findings restructure + true dead-spot fix**
- **Recon records group by TARGET properly**: DNS-record targets ("example.com TXT"), dir-bust paths, reflection URLs, vhost probes and header rows all normalize to the base host, so one `example.com` recon = one record — expanding it shows every TXT / A / AAAA / CAA / SOA / NS / MX row in one place (verified: 13 rows).
- **WiFi/BLE/LAN/Info sections in Findings collapse too** — the feed is now headers-first (🛰 records + BLUETOOTH (n) / WI-FI (n) / LAN (n)), each folded until tapped: a full session stays at ~6 rows on screen instead of 65+.
- **Dead-spot #2 fixed:** even with the hardened writer, the tab re-queried and re-diffed the ENTIRE session (unbounded `observeForSession`) on every single insert — during a BLE burst (hundreds of rows/s) the main thread starved and the tab froze until scans ended. The UI now observes a newest-300 window; reports keep reading the full session from the DAO.
- Removed the dead "Run" button beside the Target-domain field in the web-recon sheet.

**0.9.1 — intel records, source badges, dead-spot fix**
- **Recon results are grouped per target in the Findings tab**: running OSINT/web recon on `example.com` stores every result (DNS records, RDAP, subdomains, headers, hits…) under ONE "🛰 example.com" record row — tap it to open everything from that target in a single place, folded away from the device log when closed. Public-IP rows join the intel set.
- **Findings rows now carry a source badge**: `Bluetooth` / `WiFi` / `LAN scan` / `OSINT` / `Web recon` / `Traffic` / `Network info` — glanceable origin like the Nearby tab's grouping, and the bare `[TYPE]` prefix line is gone.
- **Fixed: the "dead spot" after running BLE → OSINT → WiFi in one session.** Root cause: the single DB-writer coroutine died permanently on the first failed insert (any transient SQLite lock/error cancelled `collect{}` and every later finding was silently dropped — Findings just stopped updating). The writer now retries each row 3× with backoff and drops a bad row instead of dying; `launchSafely` blocks log crashes instead of failing silently.

**0.9.0 — Fox Hunt tab + Intel dropdown**
- **🦊 Fox Hunt is its own tab**: enter the target's MAC (copy it from a Findings BLE row — long-press), press Hunt, and the tab locks onto that device — live RSSI, a warmer/colder range estimate, best-signal-so-far ("walk back to where that was"), and a packet counter. The BLE scan is platform-filtered to the target MAC (power-efficient); press Stop to end. Verified live on a Flipper: `-60 dBm — WARM ~1.1m`, 24 packets.
- **Findings tab: OSINT/Web results collapse into one "🛰 INTEL" dropdown group** (OSINT + WEB + ATTACKER_LOOKUP), folded by default, so DNS-record spam no longer buries device findings.
- Six tabs now: Monitor · Nearby · Findings · 🦊 Fox Hunt · Reports · GATT.

**0.8.x — usability pass (dropdown tools, fox hunt, copy)**
- **OSINT and Web recon are now expandable dropdown sheets** on the Monitor deck, not dialogs: tap the row and every tool appears inline with its own input + Run button — no more multi-step popups. Each tool runs independently (username matrix, HIBP breaches, IP/domain RDAP, Wayback, GitHub dorks / subdomains, DNS, headers, dir busting, reflection triage); the OSINT/IP path was verified live on-device (1.1.1.1 → APNIC-LABS, AS13335).
- **🦊 BLE Fox hunt** — proximity hunting for trackers and alert-class BLE (AirTag/Find My, Flipper OUI...): 30 s low-latency scan, every observation logged, warmer/colder readout with a log-distance range estimate. Verified live: Flipper `Cr0w` tracked at ~1.7 m.
- **Copy MAC/BSSID/IP from Near (Nearby) or Findings**: rows show a copy button (tap) and the whole row copies on long-press, with a toast. Verified live: Flipper MAC copied and confirmed via system clipboard chip.
- Renames: "Active sweep" → **Network scan**; "Full WiFi sweep" → **WiFi scan** (deck, quick buttons, statuses, auto-opened scope label).

**0.7.x — probes connect for real + the network map**
- Scan sockets pinned to the WiFi `Network` (`Network.bindSocket`): with WiFi + LTE up simultaneously, default-network routing sent LAN-bound probes into the cellular agent where RFC1918 space is unroutable — sweeps "succeeded" with zero contact. TCP RSTs now count as proof of life; RST-only hosts appear on the map.
- Public-IP/OSINT lookups run on a dedicated dispatcher with a default-network fallback; when the router refuses new forwarded WAN TCP, the status strip says so.
- The map: this phone + gateway highlighted, per-device open ports with service descriptions + banners, OS guesses (port patterns + banner + OUI), AP-isolation detection, public IP with RDAP org/ASN.

## VPN module status (the honest version)

- **UDP: forwarded for real.** Every flow is NAT'd through a `protect()`'d `DatagramChannel`; replies are synthesized back into the TUN as hand-built IPv4/UDP packets with correct IP-header checksums (the kernel silently drops wrong ones). DNS aimed at the internal resolver is redirected upstream — QUIC/HTTP3 and DNS keep working during a session.
- **TCP: observe-and-flag only, deliberately not forwarded.** Forwarding means being a userspace TCP/IP stack (retransmission, windowing, reordering) — not something to fake with code that silently drops connections under real packet loss. The production path is [Firestack](https://github.com/celzero/firestack) (tun2socks used by RethinkDNS); wiring it in is the top roadmap item.
- **Per-app attribution:** Android 10+ kernel-filters other apps' rows in `/proc/net/{tcp,udp}` for unprivileged readers, so attribution resolves NetGuard's own flows only. The data-model field stays put for a rooted build.

## Authorized use

NetGuard is built for **defensive work on networks you own and bug-bounty targets within a program's written scope**. The app enforces part of this itself: web-recon/OSINT targets require explicit entry (= authorization declaration), `.gov`/`.mil` are hard-refused, requests are throttled, and every report embeds the scope declaration you typed before starting. Know your local laws — scanning networks you don't have permission to touch is illegal essentially everywhere.

