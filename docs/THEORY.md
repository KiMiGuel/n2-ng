# N2-NG Theory

This document explains the wireless auditing concepts behind N2-NG's features. It is educational background, not an instruction manual — see `USER_GUIDE.md` for operations.

## Monitor Mode

A wireless adapter in managed mode only sees traffic addressed to it. Monitor mode (`airmon-ng`, `iw`) puts the interface into promiscuous 802.11 reception: every frame on the current channel is delivered to userspace, including beacons, probe requests, data frames, and authentication exchanges from all nearby networks. Everything N2-NG shows — access points, clients, handshakes — is parsed from this raw frame stream (`airodump-ng`).

Channel hopping cycles the interface through channels to survey the whole band; locking a target stops hopping so the radio stays on the target's channel and captures its traffic reliably.

## MAC Randomization

Before entering monitor mode, N2-NG can randomize the interface's MAC address (#4). The source MAC is visible in every injected frame (deauthentications, WEP injections), so randomization avoids tying audit traffic to the adapter's burned-in address. The original address is restored when the interface returns to managed mode.

## WPA/WPA2 Handshake Capture

WPA2 derives session keys from a 4-way handshake between access point and client. The handshake contains the ANonce, SNonce, both MAC addresses, and a MIC — everything needed to test a candidate passphrase offline:

1. `PMK = PBKDF2(passphrase, ESSID, 4096, 256)`
2. `PTK = PRF(PMK, ANonce, SNonce, AP MAC, client MAC)`
3. Recompute the MIC with the PTK and compare it to the captured MIC.

A match proves the passphrase. N2-NG detects the handshake in the capture stream and saves it for offline cracking with hashcat. Capture is opportunistic: a handshake only appears when a client (re)connects. A deauthentication attack forces connected clients to reconnect, producing a handshake on demand.

## PMKID Attack

Some access points include a PMKID in the first EAPOL message of roaming (802.11r) exchanges. The PMKID is derived from the PMK and both MAC addresses, so it enables the same offline passphrase test as a full handshake — but it can be requested directly from the AP with no client present and no deauthentication.

## Deauthentication

802.11 deauthentication frames are unauthenticated management frames. Forging one from the AP's address to a client (or broadcast) makes the client drop and reconnect. This is how handshake capture is accelerated — and why it is also a denial-of-service primitive. N2-NG sends deauths via `aireplay-ng` and stops the entire process group on Stop (#5) so no injector is left running.

## WEP Attacks

WEP's RC4 key scheduling leaks key material through weak IVs. Given enough captured IVs, statistical attacks (`aircrack-ng`) recover the key. Because passive collection is slow, active attacks generate traffic:

- **Fake authentication** (`-1`): associates with the AP so it accepts our injected frames. WEP requires the source MAC; N2-NG resolves it from sysfs (#3).
- **ARP request replay** (`-3`): reinjects captured ARP requests; each reply carries a fresh IV.
- **ChopChop** (`-4`) and **Fragmentation** (`-5`): decrypt or forge a packet byte-by-byte without the key, yielding a keystream for injection.

## WPS

Wi-Fi Protected Setup exchanges an 8-digit PIN split into two halves that are validated independently, reducing brute force to ~11,000 attempts. N2-NG's WPS scan lists APs advertising WPS in their beacons; online PIN attacks (`reaver`/`bully`) and the offline Pixie Dust attack target this weakness.

## Offline Cracking

Captured handshakes, PMKIDs, and WEP IVs are cracked offline — no further radio traffic, no rate limiting. Hashcat modes: 22000 (WPA-PBKDF2/PMKID/handshake), 2500/2501 (legacy hccapx). The security of a WPA2 network therefore reduces to passphrase entropy: the handshake exposes enough material to test guesses at GPU speed.

## Defensive Takeaways

- Use WPA2/WPA3 with a long, random passphrase — handshake capture is a matter of when, not if.
- Disable WPS.
- Prefer WPA3-SAE, which replaces the PSK exchange with Dragonfly and removes offline dictionary attacks on the handshake.
- 802.11w (management frame protection) authenticates deauth frames and defeats forced reconnection.
