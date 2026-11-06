# Diagnostic Browser — Code Signing & Installer Runbook (Windows)

**Audience.** The person producing the release build on authorized Windows x64
hardware. Follow this after the T01–T50 acceptance has otherwise passed on an
unsigned build; signing is one of the final production gates.

**Why it matters.** An unsigned exe triggers SmartScreen and many EDR/AV engines,
and cannot be verified by the organization as authentic. Signing with a trusted
certificate and a timestamp makes the binary verifiable and durable past the
certificate's expiry. The repo currently emits `DiagnosticBrowser-5.0.0rc4-UNSIGNED`
from `installer/DiagnosticBrowser.iss` — signing is a deliberate, separate step.

---

## 0. Prerequisites (one-time)

| Item | Notes |
|---|---|
| Code-signing certificate | OV or (preferred) **EV**. EV gives immediate SmartScreen reputation; OV accrues reputation over time. Keep the private key on the issuing **hardware token / HSM** — never export it to disk. |
| `signtool.exe` | From the Windows SDK / Visual Studio Build Tools. Confirm with `where signtool`. |
| Inno Setup (`iscc.exe`) | To compile `installer/DiagnosticBrowser.iss`. Confirm with `where iscc`. |
| Timestamp authority URL | e.g. your CA's RFC-3161 endpoint. Timestamping is **mandatory** so signatures stay valid after the cert expires. |
| Build toolchain | Python 3.11 + the repo's `scripts\setup_windows.ps1` dependencies, for the build step only (not required on end-user machines). |

Record the certificate thumbprint, issuer, and expiry in the release record.

---

## 1. Build the one-file EXE

```powershell
# from the repo root, on authorized Windows x64
.\scripts\finish_on_windows.ps1
```

This installs build deps, builds `dist\DiagnosticBrowser.exe`, runs the clean
onefile acceptance, and runs the offline-AI inference self-test. Confirm it ends
with the "Automated Windows checks passed" line before signing.

Capture the pre-signing hash:

```powershell
Get-FileHash .\dist\DiagnosticBrowser.exe -Algorithm SHA256
```

## 2. Sign the EXE

Using the certificate on its token (selected automatically with `/a`, or pin it
with `/sha1 <thumbprint>`):

```powershell
signtool sign `
  /fd SHA256 `
  /tr http://YOUR-TIMESTAMP-AUTHORITY `
  /td SHA256 `
  /a `
  /d "Diagnostic Browser" `
  .\dist\DiagnosticBrowser.exe
```

- `/fd SHA256` — file digest algorithm.
- `/tr` + `/td SHA256` — RFC-3161 timestamp (do not use the older `/t`).
- `/d` — friendly name shown in the UAC prompt.

Verify the signature and chain:

```powershell
signtool verify /pa /v .\dist\DiagnosticBrowser.exe
```

Expect: "Successfully verified" with a valid chain and a timestamp. If it fails,
do **not** ship — fix the cert/chain and re-sign.

## 3. Build the installer

```powershell
iscc .\installer\DiagnosticBrowser.iss
```

This produces the installer under the Inno Setup output dir. Note the current
`OutputBaseFilename` is `...-UNSIGNED`; after you validate the signing flow,
update that define (and any `SignTool` directive) in the `.iss` so the filename
no longer says UNSIGNED and the installer self-signs on compile if you wire a
`SignTool` entry. Until then, sign the installer manually in step 4.

## 4. Sign the installer

```powershell
signtool sign /fd SHA256 /tr http://YOUR-TIMESTAMP-AUTHORITY /td SHA256 /a `
  /d "Diagnostic Browser Setup" `
  .\installer\Output\DiagnosticBrowser-5.0.0rc4-*.exe

signtool verify /pa /v .\installer\Output\DiagnosticBrowser-5.0.0rc4-*.exe
```

Both the inner `DiagnosticBrowser.exe` (step 2) and the installer must be signed.
If the installer bundles the exe, sign the exe **first**, then compile, then sign
the installer, so the signed exe is the one packaged.

## 5. Reputation, AV, and endpoint

- **SmartScreen:** EV certificates get reputation immediately; OV builds it as
  installs accumulate. Expect first-run SmartScreen prompts on fresh OV certs.
- **AV / EDR:** submit the signed binaries to the organization's AV/EDR vendor
  for allowlisting, and add a managed exclusion if your security team requires
  one. Re-run T47 after allowlisting.
- **Large onefile note:** the exe is ~500 MB (bundled Chromium + model); some
  scanners flag large self-extracting binaries. The signature + vendor
  allowlisting is the remedy, not disabling the scanner.

## 6. Hash, record, distribute

```powershell
Get-FileHash .\dist\DiagnosticBrowser.exe -Algorithm SHA256
Get-FileHash .\installer\Output\DiagnosticBrowser-5.0.0rc4-*.exe -Algorithm SHA256
```

Record both **post-signing** hashes, the cert thumbprint, the build commit SHA,
and the timestamp authority in the release record and the requirements
traceability matrix. Distribute only through the approved internal channel.

---

## Verification checklist (must all be ☑ before GO)

- ☐ `finish_on_windows.ps1` passed on this build (incl. onefile acceptance + AI self-test)
- ☐ EXE signed; `signtool verify /pa /v` succeeds with a valid timestamp
- ☐ Installer signed; `signtool verify /pa /v` succeeds
- ☐ Private key never left the token/HSM
- ☐ SmartScreen behavior confirmed acceptable for the chosen cert type
- ☐ Signed binaries submitted to AV/EDR; T47 re-run and PASS
- ☐ Post-signing SHA-256 of EXE and installer recorded against the commit SHA
- ☐ Installer output filename no longer contains "UNSIGNED"
- ☐ Entries added to the release record / traceability matrix

> Signing proves authenticity and integrity; it does **not** substitute for the
> T01–T50 functional acceptance, the 24-hour soak, or the real vendor/Okta
> workflow. All must pass before a production GO.
