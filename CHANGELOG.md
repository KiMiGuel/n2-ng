# Changelog

## 1.7.1

### Fixed
- `AttackController` never checked for root; `aireplay-ng`/`reaver` need raw-socket access and died silently (<1ms, invisible in `ps aux`) when n2-ng was launched without `sudo`, so OMNI's HANDSHAKE stage produced junk captures with no EAPOL M3. Now logs a loud warning at init and refuses to spawn with a clear message instead of a silent per-attack failure.

## 1.7.0

### Added
- OMNI Attack (All Stages): `src/n2ng/omni.py` — `OmniAttackOrchestrator`, an adaptive all-stage chain per locked target: PROFILE → PMKID (30s window) → WPS (pixie-dust first, then paced reaver with lockout-aware abort) → HANDSHAKE (directed deauth, skipped when PMF required) → EVILTWIN (stub) → ONLINE (strictly budgeted: ≤20 default PINs / ≤5 passwords, single pass, never loops) → CRACK (batches all target .22000 records, hashcat with `-r` rules + `--nonce-error-corrections`)
- First success short-circuits; Stop Attack kills the orchestrator and all stage workers; live stage indicator in the status bar; per-stage result + timing report
- `EvilTwinStage` stub (WPA3 transition-mode downgrade) — raises NotImplementedError, marked "coming v1.8"
- `wps_state()` wash-output parser (enabled / locked / unknown)
- New tests: state-machine transitions, WPS skip-when-locked, PMF skip of handshake stage, crack batch assembly/dedup, stub behavior

### Changed
- No changes to existing attacks or the capture verdict gate (invariant tests guard both)

## 1.6.0

Research-driven upgrade (see `research/`): PMKID methodology (hashcat 22000), PMF/802.11w-aware routing, WPA3 transition-mode handling, hashcat v7 capture-tolerance flags.

### Added
- PMKID Attack (Clientless) button: scapy-based clientless PMKID capture — open-system auth + RSN association request, extracts the PMKID from the AP's unprotected EAPOL M1 and writes a hashcat `-m 22000` (WPA*01) file straight into the target folder. No client required; works under PMF
- Smart Attack (Auto) button: PMF-aware adaptive attack chain — profiles the target, tries quiet PMKID first, falls back to directed deauth only when PMF is not required, and logs the correct pivot (WPA2 downgrade twin for transition mode, online SAE for pure WPA3) instead of wasting deauths that 802.11w drops
- Security profiling: WPA2/WPA3/transition/WEP/open classification with PMF status (`security_profile`, `recommend_attack`); shown as a Profile badge in the target card
- Hashcat dialog: optional rules file (`-r`) and hashcat v7 `--nonce-error-corrections` override for noisy PMKID/handshake captures
- Stop Attack now also stops PMKID/Smart Attack worker threads

### Fixed
- Capture gate: CHALLENGE-only handshakes (M1+M2, messagepair 0) again log a warning and keep capturing instead of falsely stopping auto-deauth (restores the v1.1.0 documented behavior)
- `--version` test now tracks the package version instead of a hardcoded string

## 1.1.0

### Added
- Handshake verification gate: .22000 files are classified by the EAPOL MESSAGEPAIR byte — AUTHORIZED (messagepair 1-5, AP accepted the client's proof, crackable) vs CHALLENGE (M1+M2 only, messagepair 0, possibly a failed/wrong-password auth)
- Verdict badge in the Capture Sessions action bar showing the selected session's verdict (AUTHORIZED / CHALLENGE / PMKID / NO PAIR), cached per path+mtime
- Automatic .22000 generation: captures are (re)converted in the background after the capture gate, Fix Capture, Merge, and lazily when a session without a .22000 is selected

### Changed
- Auto-deauth loop no longer stops on unverified handshakes (CHALLENGE only logs a warning and keeps capturing)
- Two-level network table sorting: PWR ties break by CH ascending, CH ties break by PWR descending

### Removed
- "Convert to 22000" button and context-menu entry — conversion is now automatic

## 1.0.0

### Added
- Randomize MAC address before entering monitor mode (#4)
- Restore managed mode on quit while keeping pre-existing monitor interfaces (#7)
- Archive merge sources after verified merge (opt-in) (#8)

### Fixed
- Stop Attack now kills entire attack process groups instead of orphaning processes (#5)
- Resolve source MAC from sysfs for WEP attacks ("cannot determine our mac address") (#3)
- Enable mouse wheel scrolling in side dialogs (#9)
- UI fits small displays down to 800x480 (#6)
