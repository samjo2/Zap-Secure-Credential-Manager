# Zap Credential Autofill Extension

Chrome extension that autofills login forms from your local Zap vault.

Unlike v1, the extension never downloads your whole vault: it asks the server
for the single best-matching credential for the current site
(`GET /api/fill?domain=<host>`), and the server only answers while your vault
session is unlocked.

## Installation

1. Run Zap locally at `http://localhost:5000` and log in via the web UI.
2. Open `chrome://extensions`, enable **Developer mode**.
3. Click **Load unpacked** and select this `extension` folder.

## Usage

- Save credentials in Zap with the **Website** field set (e.g. `github.com`).
  Matching is by domain: `github.com` also matches `gist.github.com`.
- On a login page, click the Zap icon, then **Autofill credentials**.
- Optionally enable **Autofill automatically on this site** to fill on page
  load for that domain.

If the popup reports the vault is locked, log in to Zap again; vault sessions
expire after inactivity.

## Notes

- Credentials are only ever filled into the top-level frame, never iframes.
- The extension needs the Zap session cookie; Chrome allows this because the
  Zap origin is listed under `host_permissions`. If autofill stops working
  after logging in, verify you are logged in at exactly `localhost:5000` (not
  `127.0.0.1:5000`, which is a different cookie origin).
