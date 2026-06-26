# SimpleOTP

A cross-platform (Windows-first) desktop authenticator for **TOTP** two-factor codes, written in
.NET 10 + Avalonia. It looks and works like a mobile authenticator — a list of accounts, each
showing the current 6/8‑digit code with a live countdown ring, and **click a code to copy it**.

The twist: every secret is **encrypted with a key sealed to your machine's TPM 2.0 chip**. Copying
the config file to another computer is useless — the secrets can only be decrypted on the device
that sealed them.

![main window](docs/screenshot-main.png)

## Why the TPM matters

This project was inspired by [`mtausig/totpm`](https://gitlab.com/mtausig/totpm) (a Go CLI that
imports TOTP seeds into the TPM). SimpleOTP keeps that device-binding idea and improves on it:

| | `totpm` (reference) | **SimpleOTP** |
|---|---|---|
| Secret protection | Seed imported into TPM as an HMAC key | Seed AES‑256‑GCM encrypted; key (DEK) sealed to TPM |
| PIN / auth | **None** — any local process as your user can mint codes | **Optional, TPM‑enforced PIN** |
| Algorithms | SHA1 only (URI field ignored) | SHA1 / SHA256 / SHA512 honored |
| Interface | CLI | GUI (Avalonia), like a phone authenticator |
| Persistent TPM state | Transient (re-derives SRK each run) | Transient — **never writes to TPM NV storage** |

### How device-binding works

1. On first run, SimpleOTP generates a random **256‑bit data‑encryption key (DEK)**.
2. The DEK is **sealed** as a TPM keyed‑hash object under a Storage Root Key (SRK) that is
   re‑derived deterministically from the TPM's (per‑chip, non‑extractable) owner seed each run.
   The sealed public/private blobs are stored in the vault file — **nothing is left inside the TPM**.
3. Each account's TOTP secret is encrypted with **AES‑256‑GCM** under the DEK.
4. To show codes, the TPM **unseals** the DEK (optionally gated by your PIN). Only the *exact* TPM
   that sealed it can do this — so a copied `vault.json` is inert on any other machine.

> ⚠️ **There is no cloud backup and no escrow — by design.** If the TPM is cleared/reset, the
> firmware is updated in a way that resets the TPM, or the machine/motherboard changes, the sealed
> key is gone and **your stored secrets are unrecoverable**. Keep your original QR codes / recovery
> codes so you can re‑enroll. This is the price of true device binding.

The PIN, when set, is the TPM object's auth value. Wrong PINs feed the TPM's dictionary‑attack
lockout, so brute force is throttled by hardware. There is **no PIN recovery**.

### Network auto-unlock (optional)

Inspired by **BitLocker Network Unlock** (minus the certificate machinery): instead of typing your
PIN every session, the app can fetch an unlock secret from a webservice on your machine/LAN and use
it to open the vault automatically.

How it stays safe with a PIN:

- The vault key (DEK) is **sealed twice** in the TPM — once under your **PIN**, once under a separate
  **high-entropy auto-unlock key**. Either can unlock; the webservice never learns your PIN.
- The auto-unlock key is **never stored on disk** by this app. Only the second sealed blob and the
  endpoint config live in `vault.json`. The key lives only in your webservice (e.g. in its RAM).
- On launch, if auto-unlock is configured, the app calls your service; on success it unseals via the
  TPM with no prompt. **On any failure it falls back to the PIN screen.**

You build the webservice (the app is the client only). The contract:

| | |
|---|---|
| Request | `POST {url}` (GET also supported) with header `X-App-Key: {appKey}` |
| Success | `200 OK`, response **body = the auto-unlock key** (UTF-8 text; trailing whitespace trimmed) |
| Failure | any non-2xx / unreachable → app falls back to PIN |

Configure it under **⚙ Settings → Network auto-unlock**: set the URL and app key, generate the
auto-unlock key, click **Enable** (the app shows the exact body your service must return), and use
**Test** to verify your endpoint. For an `https://` URL with a self-signed/local certificate, you can
pin it by SHA-256 thumbprint (or, for local dev only, allow any cert).

![settings](docs/screenshot-settings.png)

> The device-binding guarantee is unchanged: the auto-unlock blob is still TPM-sealed, so a copied
> `vault.json` plus the app key are useless on another machine (no matching TPM). The added exposure
> is local: while your service is reachable, anything that can call it **and** read the app key from
> `vault.json` could obtain the unlock key — so run the service on loopback/your LAN and prefer
> `https` off-box.

## Requirements

- **.NET 10 SDK** (the app targets `net10.0`).
- A working **TPM 2.0** (Windows: via TBS; Linux: `/dev/tpmrm0`). The app **hard‑requires** a TPM —
  with none present it shows a "No TPM detected" screen and refuses to store anything insecurely.

## Build & run

```bash
dotnet build                       # build the whole solution
dotnet test                        # run unit tests (TPM integration tests are skipped by default)
dotnet run --project src/SimpleOtp.App
```

### Publish a self-contained Windows executable

```bash
dotnet publish src/SimpleOtp.App -r win-x64 -c Release --self-contained \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

Linux build: swap `-r win-x64` for `-r linux-x64`. (Do **not** add `PublishTrimmed` — Avalonia's
XAML/view-locator uses reflection and breaks under aggressive trimming.)

## Using it

- **+** in the header (or the empty-state button) opens **Add account**, which supports:
  - **Paste** an `otpauth://totp/...` link **or** a raw Base32 secret, then *Load*.
  - **Import a QR screenshot**: *Open image…*, *Paste image* (e.g. after `Win`+`Shift`+`S`), or
    **drag an image file** onto the window.
  - **Manual entry**: issuer, label, secret, algorithm, digits, period.
- **Click a card** to copy its current code (a "Copied" toast confirms).
- **⚙ Settings** to set / change / remove the TPM‑enforced PIN, and to configure **network
  auto-unlock** (see above).
- **🔒 Lock** to clear the unlocked key from memory until the PIN is re-entered.

By default there is **no PIN** — secrets are bound to the device + your OS account. Enable a PIN for
an extra factor.

## Data & storage

Vault file (mode `0600`):

- Windows: `%AppData%\SimpleOtp\vault.json`
- Linux/macOS: `~/.config/SimpleOtp/vault.json`

```jsonc
{
  "Version": 1,
  "Backend": "tpm2",
  "PinProtected": false,
  "Dek": { "Public": "<base64 TPM2B public>", "Private": "<base64 TPM2B private>" },
  // present only when network auto-unlock is enabled (the second sealing + endpoint config;
  // the auto-unlock key itself is NOT stored here):
  "DekAuto": { "Public": "…", "Private": "…" },
  "AutoUnlock": { "Enabled": true, "Url": "https://…/unlock", "AppKey": "…", "Method": "POST" },
  "Accounts": [
    {
      "Id": "…", "Issuer": "GitHub", "Label": "octocat",
      "Algorithm": "Sha1", "Digits": 6, "Period": 30,
      "Secret": { "Nonce": "…", "Tag": "…", "Ciphertext": "…" }   // AES-256-GCM, never plaintext
    }
  ]
}
```

## Project layout

```
SimpleOtp.slnx
├── src/
│   ├── SimpleOtp.Core/     TOTP engine, otpauth parser, envelope-encryption Vault, store,
│   │                       network auto-unlock client  (no TPM/UI deps)
│   ├── SimpleOtp.Tpm/      ISecretSealer implementation over TPM 2.0 (Microsoft.TSS)
│   ├── SimpleOtp.Import/   QR decoding (ZXing.Net + SkiaSharp)
│   └── SimpleOtp.App/      Avalonia 12 GUI (MVVM, CommunityToolkit.Mvvm)
└── tests/
    └── SimpleOtp.Tests/    xUnit: RFC 6238 vectors, URI parsing, vault round-trips, QR, view models
```

The TPM lives behind the `ISecretSealer` interface in Core, so everything except `SimpleOtp.Tpm`
is hardware-agnostic and unit-testable with an in-memory fake.

### Running the real-TPM tests

These are skipped by default so the suite never touches the chip. To run them (each seals **one
transient object** and flushes it — nothing persists in the TPM):

```bash
SIMPLEOTP_TPM_TEST=1 dotnet test --filter FullyQualifiedName~TpmIntegrationTests
```

## Key dependencies

`Microsoft.TSS` (TPM 2.0) · `Otp.NET` (RFC 6238) · `ZXing.Net` + `ZXing.Net.Bindings.SkiaSharp`
(QR) · `Avalonia` 12 + `CommunityToolkit.Mvvm` (UI).
