# Build & upload Logos to TestFlight (no Mac)

Logos builds and uploads to TestFlight entirely on GitHub's hosted macOS runners
via `.github/workflows/ios-release.yml`. No Mac is needed — not even for signing:
the workflow uses an App Store Connect API key, so Xcode mints a cloud-managed
distribution certificate automatically. (The Rust core is compiled into
`LogosKit.xcframework` first by `scripts/build-ios.sh`.)

## One-time setup

### 1. Repository must be public (or Actions billing resolved)
A private repo on this account silently billing-blocks Actions (the job shows
`failure` with no logs). Keep `Cole-Will-I-Am/Logos` **public**, which also fits
the open-core / binary-transparency design.

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

- **Export compliance:** `project.yml` sets `ITSAppUsesNonExemptEncryption: false`
  to keep the beta upload unblocked. Logos *does* use custom E2EE, so this is a
  pragmatic beta shortcut — file a proper encryption self-classification before
  any **public App Store** release.
- **Relay:** the app defaults to `https://relay.manticthink.com`. A TestFlight
  build is only usable once that public HTTPS relay is live (iOS ATS blocks
  cleartext, so a localhost default can't work on device).
- **Cert cap:** `scripts/revoke_dev_certs.mjs` runs before archive to revoke stale
  cloud-managed *Development* certs (best-effort; never touches Distribution).
