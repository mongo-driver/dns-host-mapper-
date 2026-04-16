# DNS Host Mapper VPN (Android)

`DNS Host Mapper VPN` is an Android app that acts like a mobile `hosts` file by intercepting DNS queries through a local `VpnService`.

It lets you:

- map custom domains to IPv4 addresses (for example `hasan.local -> 192.168.6.5`)
- use custom upstream DNS servers (for example `217.218.155.155`)
- answer local mapped domains directly
- forward non-mapped domains to upstream DNS with fallback behavior
- announce `.local` entries over mDNS on the LAN

## Why this app exists

Android does not provide a system-wide editable `hosts` file for normal apps.  
This project provides a user-space alternative by:

1. creating a local VPN tunnel
2. capturing DNS packets sent by apps
3. responding locally for mapped domains
4. forwarding other domains to configured upstream resolvers

## Key Features

- Add/Edit/Delete domain to IPv4 rules
- Rule persistence via `SharedPreferences`
- Custom DNS server management
- mDNS support for `.local` domains
- DNS response cache with TTL-aware behavior
- Upstream resolver cooldown/fallback logic
- Verbose DNS trace logging (`DNS_HOST_MAP_TRACE`)

## Project Structure

- `app/src/main/java/com/example/etc/MainActivity.kt`
: Main UI, rule/DNS management, VPN start/stop/state sync.
- `app/src/main/java/com/example/etc/data/HostRuleStore.kt`
: Stores rules, custom DNS servers, and VPN running state.
- `app/src/main/java/com/example/etc/vpn/HostsVpnService.kt`
: Core VPN tunnel loop and DNS packet handling.
- `app/src/main/java/com/example/etc/vpn/UpstreamDnsResolver.kt`
: Upstream DNS querying, candidate selection, cooldown, caching.
- `app/src/main/java/com/example/etc/vpn/MdnsLocalResponder.kt`
: mDNS listener/announcer for `.local` entries.
- `app/src/main/java/com/example/etc/vpn/DnsPacketCodec.kt`
: DNS parse/build helpers (A/AAAA/PTR/HTTPS/etc).

## Build

```bash
./gradlew :app:assembleDebug
```

## Run

1. Install and open app.
2. Add mapping (example):
: Domain: `hasan.local`
: IPv4: `192.168.6.5`
3. Optionally add custom DNS server:
: `217.218.155.155`
4. Tap `START VPN`.
5. Test from network tools/browser:
: `hasan.local`, `zarebin.ir`, `soft98.ir`

## Screenshots

<p align="center">
  <img src="docs/images/main-screen.png" alt="Main Screen" width="280" />
  <img src="docs/images/manage-dns-servers.png" alt="Manage DNS Servers" width="280" />
</p>

<p align="center">
  <img src="docs/images/ping-git-ir.png" alt="Ping git.ir" width="280" />
  <img src="docs/images/ping-hasan-local.png" alt="Ping hasan.local" width="280" />
  <img src="docs/images/ping-soft98-ir.png" alt="Ping soft98.ir" width="280" />
</p>

## Troubleshooting

- Ensure Android Private DNS is disabled if interception is bypassed.
- Keep VPN running while testing mapped domains.
- Check `logcat` tag: `DNS_HOST_MAP_TRACE`.
- If mapped `.local` fails on some clients, verify mDNS traffic on LAN and that multicast is available.

## License

No license file is currently included in this repository.
