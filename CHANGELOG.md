# Changelog

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
