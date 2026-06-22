# Build & upload Logos to TestFlight (no Mac)

Logos builds and uploads to TestFlight entirely on GitHub's hosted macOS runners
via `.github/workflows/ios-release.yml`. No Mac is needed — not even for signing:
the workflow uses an App Store Connect API key, so Xcode mints a cloud-managed
distribution certificate automatically. (The Rust core is compiled into
`LogosKit.xcframework` first by `scripts/build-ios.sh`.)

## One-time setup

### 1. Repository is public
`Cole-Will-I-Am/Logos` is **permanently public**, so Actions runs without the
silent billing-block a private repo on this account hits (the job would show
`failure` with no logs) — and it fits the open-core / binary-transparency design.

### 2. App Store Connect app record
The bundle ID is **`com.colecantcode.logos`** (team **`B3DB33R8JN`**). Before the
first upload can land, an **app record must exist** in App Store Connect for that
bundle ID (the ASC API can't create new apps — this is a browser step):

1. <https://appstoreconnect.apple.com> → **Apps** → **+** → **New App**.
2. Platform **iOS**; Name e.g. `Logos`; Primary language; Bundle ID
   `com.colecantcode.logos` (register it under **Certificates, IDs & Profiles →
   Identifiers** first if it isn't listed); pick an SKU (e.g. `logos`).
3. Create. (TestFlight tab will populate after the first build is processed.)

`-allowProvisioningUpdates` + the Admin API key handle the App ID / provisioning
profile automatically during archive.

### 3. Repository secrets
Settings → Secrets and variables → Actions → **New repository secret**. These are
the **same three** the SEER repo uses (same Apple team):

| Secret | Value |
|---|---|
| `ASC_KEY_ID` | The API key ID (e.g. `CL8R428N2X`) |
| `ASC_ISSUER_ID` | The team's issuer ID (App Store Connect → Users and Access → Integrations) |
| `ASC_KEY_P8_BASE64` | `base64 -w0 AuthKey_<KEY_ID>.p8` (one line) |

The key must be an **Admin**-role team key — App Manager fails export with
"Cloud signing permission error / No profiles found."

## Running a build

Actions tab → **iOS — TestFlight Release** → **Run workflow** (input `upload`
defaults to true). Build number = the GitHub run number; `MARKETING_VERSION` is
read from `project.yml` (bump it per release — see the version-bump convention).

The build appears in TestFlight after Apple finishes processing (~5–15 min).

## Notes & caveats

- **Export compliance:** `project.yml` sets `ITSAppUsesNonExemptEncryption: false`,
  which keeps TestFlight uploads unblocked. Don't flip it to `true` casually:
  `true` requires an `ITSEncryptionExportComplianceCode`, and without that code the
  `altool` upload fails validation with `(409) Invalid Export Compliance Code` —
  App Store Connect only issues the code *after* you complete its export-compliance
  questionnaire. The by-the-book App Store path is: file a BIS/NSA mass-market
  (5D992.c) self-classification, complete the ASC questionnaire to obtain the code,
  then set the key `true` and add the code. In practice Logos ships with `false` /
  answering "no" to the encryption question, which is the common path for an app
  whose encryption is standard E2EE.
- **Relay:** the app defaults to `https://relay.manticthink.com`. A TestFlight
  build is only usable once that public HTTPS relay is live (iOS ATS blocks
  cleartext, so a localhost default can't work on device).
- **Cert cap:** `scripts/revoke_dev_certs.mjs` runs before archive to revoke stale
  cloud-managed *Development* certs (best-effort; never touches Distribution).
