# Diagnostic Browser — Windows Native Acceptance (T01–T50)

**Purpose.** This is the manual acceptance that must pass on authorized Windows
hardware before a production GO. The GitHub Windows CI already proves the exe
builds, bundles Chromium + the offline model, launches on a clean VM, writes
encrypted evidence, runs the watchdog, performs real offline inference, and shuts
down gracefully. CI cannot prove the items below — they require a human, a real
enterprise environment, and signed binaries.

**Test environment to record once, at the top of every run:**

| Field | Value |
|---|---|
| Windows edition / build | e.g. Windows 11 Pro 23H2 (22631.x) |
| Hardware (CPU / RAM / disk) | |
| EXE file name | DiagnosticBrowser.exe |
| EXE SHA-256 | (from `Get-FileHash`) |
| Installer file + SHA-256 | |
| Source commit SHA | |
| Tester / date | |

**How to run.** Work top to bottom. For each test record PASS / FAIL / BLOCKED,
the observed result, and the evidence file path. A single FAIL on any
non-optional test holds the release at NO-GO. Capture evidence into a dated
folder (screenshots, copies of `*.health.json`, the exported ZIPs, Event Viewer
exports). Do not continue past a FAIL that blocks later tests until it is fixed
and the affected tests are re-run.

**Running an UNSIGNED build (expected during testing).** If the build is not yet
code-signed, Windows and some AV engines will warn — this is normal and does not
mean the app is broken:

- **SmartScreen:** launching the exe or installer shows a blue "Windows protected
  your PC" box. Click **More info**, then **Run anyway**. (An administrator can
  pre-approve the file, but click-through is fine for testing.)
- **Browser download warning:** if the exe is downloaded via a browser it may be
  flagged as "not commonly downloaded" — choose **Keep**.
- **Antivirus / EDR:** a large self-contained exe (~500 MB with bundled Chromium
  + model) can be held for scanning or quarantined. If so, add a temporary
  exclusion for the test copy, or have IT allowlist it.
- **Verify you have the right file first:** before trusting a downloaded copy,
  confirm its SHA-256 matches the hash recorded for the build
  (`Get-FileHash DiagnosticBrowser.exe -Algorithm SHA256`).

For an unsigned test build, record **T01** and **T47** as *Deferred — unsigned
build* rather than FAIL; they become applicable once signing is done per the
code-signing runbook.

**Clean-machine rule.** T01–T08 and T43–T45 must be performed on a machine with
**no** Python, Node, Chrome, Playwright, SQLCipher, or build tools installed, and
with **no developer internet dependency access** — this is the whole point of a
self-contained executable.

---

## Section A — Installation, bundling, clean machine (T01–T08)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T01 | Clean install from installer | On a clean Windows box, run the signed installer; accept defaults | Installs without requiring any prerequisite; Start-menu entry created; no error dialogs | Screenshot of install + install dir listing |
| T02 | No external runtime required | Confirm Python/Node/Chrome/SQLCipher are **not** present (`where python`, `where chrome`) then launch the app | App runs fully with none of them installed | `where` output, app running |
| T03 | Bundle integrity | Run `DiagnosticBrowser.exe --verify-bundle` | JSON shows `embedded_chromium:true`, `offline_ai_model:true`, `packaging:"ONE_FILE"`, `verified:true` | Console JSON |
| T04 | No first-run downloads | Disconnect the machine from the internet, then first-launch the app | App starts and operates; no attempt to download Chromium, model, or packages | Network monitor / screenshot |
| T05 | Temp extraction is clean | Launch, use, exit; inspect the onefile temp extraction dir | Extraction occurs and is cleaned up on exit; no orphaned multi-GB temp dirs after repeated runs | Temp dir listing before/after |
| T06 | Per-user writable data dir | Launch with default `--data-dir`; confirm evidence/config land under `%LOCALAPPDATA%\DiagnosticBrowser` | Data dir created under the user profile, not under Program Files | Path listing |
| T07 | EXE hash matches delivered | `Get-FileHash DiagnosticBrowser.exe` equals the hash recorded in the handoff for this commit | Hashes match exactly | Hash comparison |
| T08 | Uninstall is clean | Uninstall via Apps & Features | Program files removed; user may keep/clear data dir by choice; no broken services left | Screenshot |

## Section B — Launch and core browsing (T09–T16)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T09 | First launch & dashboard | Launch; note the printed local dashboard URL and login code; open the dashboard | Dashboard loads; login code required and accepted | Screenshot |
| T10 | Browser window opens | Confirm the diagnostic Chromium window opens | Real Chromium launches with the sandbox enabled | Screenshot |
| T11 | Navigate to an allowlisted site | Configure an authorized host; navigate to it | Page loads and renders normally | Screenshot |
| T12 | Arbitrary navigation within policy | Navigate to several different authorized sites | Normal browsing; not locked to a single hardcoded site | Screenshot |
| T13 | Non-allowlisted host is not captured | Navigate to a host outside the configured allowlist | Diagnostics do not capture it; no evidence rows for that host | Timeline screenshot |
| T14 | Dashboard navigation | Click through every nav item (Browser, Dashboard, Diagnostics, Flight Recorder, Evidence, Regression, Self-Diagnostics, Auto-Repair, AI Analysis, Settings, Reports, About) | Every view loads; no dead buttons; no console errors | Screenshots |
| T15 | Status accuracy | Compare header chips / health card to actual subsystem state | Indicators reflect real state (e.g. watchdog STALE shows when the heartbeat is stale) | Screenshot |
| T16 | Responsiveness during capture | Browse actively while diagnostics run | Dashboard stays responsive; no UI freeze | Observation note |

## Section C — Diagnostics and flight recorder (T17–T26)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T17 | DNS failure classification | Navigate to a host that fails DNS | Failure domain identified as DNS; presented as evidence, not a guessed root cause | Timeline / detail |
| T18 | TCP connectivity failure | Trigger a connection refused/reset | Classified as a network/connection failure | Timeline |
| T19 | TLS / certificate failure | Hit a cert error page | Classified as TLS/cert without weakening validation | Timeline |
| T20 | HTTP error capture | Cause a 4xx/5xx | HTTP error recorded with status, route metadata only | Timeline |
| T21 | JS exception capture | Trigger a page JS error (synthetic lab) | Recorded as js_exception with class/line, no raw source | Timeline |
| T22 | Timeout / slow resource | Introduce latency | Timeout/slow-resource event captured | Timeline |
| T23 | Flight recorder persistence | Record events, stop the app, relaunch | Prior approved events persist and reload | DB + screenshot |
| T24 | Bounded growth | Run long enough to exceed the retention/size cap | Recorder prunes; no unbounded disk/memory growth | Dir size over time |
| T25 | Incident preservation | Click Preserve Incident; confirm window protected | 30-min pre + 10-min post window protected; gaps reported, not reconstructed | Incidents view |
| T26 | Report generation & export | Generate each export (engineering / internal / system-health) | ZIPs produced with PDF/HTML/JSONL/CSV + SHA-256 manifest; open and verify | Exported ZIPs |

## Section D — Privacy and security (T27–T34)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T27 | No secrets persisted | On a login page, submit credentials; inspect the recorder DB and exports | No passwords, tokens, cookies, auth headers, bodies, or page text anywhere | DB/export inspection |
| T28 | Encrypted at rest | After graceful shutdown, read the first 16 bytes of `flight_recorder.sqlite` | Not `SQLite format 3\0`; SQLCipher-encrypted | Hex dump |
| T29 | Ordinary SQLite cannot open it | Try to open the DB with a plain SQLite tool | Fails without the key | Screenshot |
| T30 | Key management | Confirm the DB key is protected via Windows DPAPI (per-user) | Key not stored in plaintext; not portable to another user/machine | Note / test on 2nd profile |
| T31 | No open debug port | Scan localhost for an exposed CDP/debug port while running | No privileged browser debug interface exposed on an unprotected port | `netstat` output |
| T32 | Dashboard auth + CSRF | Call a mutating API without the login cookie / CSRF token | Rejected (401/403) | Request logs |
| T33 | Enterprise policy respected | Confirm the app does not bypass enterprise Chrome policy or weaken cert validation | No policy override; validation intact | Note |
| T34 | Logs are safe | Inspect app logs | No secrets, no raw stack traces on user-visible channels | Log sample |

## Section E — Resilience and recovery (T35–T42)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T35 | Browser process crash | Kill the Chromium process | App detects it, records the event, and recovers/reattaches without losing the session | Timeline + screenshot |
| T36 | Controller/engine crash | Kill the engine process | Supervisor restarts it; evidence preserved | Status + logs |
| T37 | Watchdog independence | Stall the collector heartbeat | Watchdog (independent of the browser process) flags STALE and acts | watchdog.health.json |
| T38 | Forced termination | Hard-kill the whole app (Task Manager End Task) | Next launch recovers; DB not corrupted; interrupted writes handled | Relaunch screenshot |
| T39 | Restart & evidence recovery | Relaunch after any crash | Prior evidence intact and readable | Timeline |
| T40 | Disk-full handling | Fill the data volume, keep recording | Fails safe; reports the condition; no corruption | Note |
| T41 | Rapid navigation / redirect loop | Navigate rapidly / hit a redirect loop | Captured and bounded; no crash | Timeline |
| T42 | Multiple consecutive launches | Launch/exit 10× in a row | Clean every time; no leaked temp dirs or orphaned processes | Process/temp listing |

## Section F — Offline AI (T43–T45)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T43 | Real inference (offline) | Disconnect internet; run `DiagnosticBrowser.exe --ai-selftest` | `{"verified":true,"status":"LOCAL_UNVERIFIED","analysis_chars">0,"sanitized_ok":true,"leak_free":true}` | Console JSON |
| T44 | AI over real evidence | From the dashboard, Analyze with AI on a real session | Returns Observations / Hypotheses / Verification; labels output as unverified hypothesis | Screenshot |
| T45 | Degrades safely | Temporarily remove/rename the model, run analysis | Reports UNAVAILABLE; browsing/diagnostics continue normally | Screenshot |

## Section G — Enterprise / vendor workflow (T46–T48)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T46 | Real vendor/Okta login | Complete a genuine SSO/Okta login to the authorized target in the diagnostic browser | Login works; no credential/token ever appears in evidence or exports | Screenshot + DB check |
| T47 | Endpoint security / AV | Run with the organization's AV/EDR active | No quarantine/block of the signed exe; app functions | AV log / note |
| T48 | No vendor branding | Inspect UI, window titles, About, installer, exports, error messages | The original enterprise vendor name appears nowhere user-facing | Screenshots |

## Section H — Longevity and shutdown (T49–T50)

| ID | Title | Steps | Expected result | Evidence |
|---|---|---|---|---|
| T49 | 24-hour soak | Leave the app recording an authorized session unattended for 24h | No crash, no memory/handle leak, bounded disk use, watchdog healthy throughout | Resource graph + final health JSON |
| T50 | Graceful shutdown | Trigger normal shutdown (and the `engine.stop` path) | Clean exit code; DB closed and intact; all child processes gone | Exit code + process listing |

---

## Sign-off

| Gate | Result |
|---|---|
| T01–T50 all PASS (no blocking FAIL) | ☐ |
| EXE and installer signed and verified (see signing runbook) | ☐ |
| Evidence archived for every test | ☐ |
| Residual risks documented and accepted | ☐ |
| **Production verdict** | ☐ GO ☐ NO-GO |

Accepted by: ________________________  Date: __________
