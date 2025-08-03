# Zap Credential Autofill Extension

This Chrome extension retrieves credentials stored in your local Zap server and autofills login forms.

## Installation

1. Make sure the Zap application is running locally at `http://localhost:5000` and that you have logged in via the web UI.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the `extension` folder from this repository.

## Usage

- Visit a login page for a service saved in Zap.
- Click the Zap extension icon and press **Autofill Credentials**.
- Optionally check **Autofill automatically on this domain** to whitelist the current site. Whitelisted domains will autofill on page load.

The extension calls the `/get_credentials` endpoint on the Zap server using your existing session to retrieve stored usernames and passwords and injects them into detected login form fields.
