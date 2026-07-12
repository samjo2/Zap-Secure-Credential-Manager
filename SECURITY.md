# Zap security design

## Goals

1. A stolen database file, disk image, or backup must be useless without a
   user's master password.
2. One compromised account must not expose any other account's data.
3. History (the audit log) must be tamper-evident.
4. The web surface must resist the standard attacks: CSRF, XSS, session
   fixation, credential stuffing, user enumeration.

## Key hierarchy

| Material | Derived/generated | Stored? |
|---|---|---|
| Master password | chosen by user | never (scrypt verifier only) |
| Auth hash | `werkzeug` scrypt hash of master password | yes |
| KEK (key-encryption key) | `scrypt(master password, per-user 16-byte salt, N=2^14, r=8, p=1)` | never |
| DEK (data-encryption key) | random 256-bit, generated at registration | only wrapped: `AES-256-GCM(KEK, DEK)` |
| Credential plaintext | username + password + notes as JSON | only sealed: `AES-256-GCM(DEK)` |

Separate salts and domain-separated inputs keep the auth verifier and the KEK
independent: neither can be computed from the other.

Every AES-GCM sealing uses a fresh random 96-bit nonce and an associated-data
string binding the blob to its context (`zap:cred:v1:<user_id>:<credential_id>`
for credentials, a fixed label for DEK wrapping). A ciphertext copied onto
another row, credential, or user fails authentication and cannot be decrypted.

## Session and vault locking

- Login verifies the auth hash, derives the KEK, unwraps the DEK, and places
  the DEK in an **in-process memory map** keyed by a random 256-bit token.
  Only the token goes into the (signed, HttpOnly, SameSite=Lax) session
  cookie; the DEK itself never leaves the server or touches disk.
- The entry expires after a sliding idle timeout (default 15 minutes) and on
  logout, password change, reset, or process restart. A locked vault requires
  the master password again.
- `session.clear()` runs on every login before granting privileges (fixation
  defense), and the CSRF token is regenerated with the new session.
- Consequence: run Zap as a single process. A multi-worker deployment would
  need a shared encrypted session store, which is deliberately out of scope.

## Password reset vs password change

- **Change** (knows current password): the DEK is unwrapped with the old KEK
  and re-wrapped under the new one. Vault contents are preserved.
- **Reset** (forgot password): the old KEK is unrecoverable, therefore so is
  the DEK and every ciphertext under it. Zap states this in the UI, requires
  an explicit acknowledgement checkbox, erases the orphaned ciphertexts, and
  issues a fresh DEK. Reset tokens are 256-bit random values, stored only as
  SHA-256 hashes, single-use, and expire after 30 minutes.

## Login hardening

- Failures are throttled per (username, IP) pair - five failures lock that
  pair for 15 minutes - plus a wider per-IP cap across all usernames. An
  attacker hammering your username from their machine locks *their* pair,
  not your account.
- Unknown-user and wrong-password paths return the same message, and the
  unknown-user path still runs a hash verification so response timing does
  not reveal whether a username exists.

## Web surface

- CSRF: per-session random token required on every state-changing request
  (form field or `X-CSRF-Token` header), compared with `hmac.compare_digest`.
- CSP `default-src 'self'` with no inline scripts anywhere; `frame-ancestors
  'none'`, `nosniff`, `no-referrer` (reset tokens never leak via Referer).
- All credential JSON responses are `Cache-Control: no-store`.
- The vault UI builds DOM nodes with `textContent`; stored credential fields
  are never interpreted as HTML.
- The extension endpoint (`/api/fill`) returns one domain-matched credential
  and requires an unlocked vault; there is no endpoint that dumps the vault
  in plaintext.

## Audit log integrity

Each user's audit entries form a hash chain:
`entry_hash = HMAC-SHA256(audit_key, user|timestamp|action|detail|prev_hash)`,
where `audit_key` is derived from the server secret and `prev_hash` links to
the previous entry (genesis for the first). Verification recomputes the whole
chain; any edited, deleted, or reordered row breaks every subsequent link.
Entries record event types and service names only - never passwords.

Rotating `ZAP_SECRET_KEY` invalidates prior audit signatures (the page will
show a failed check); export or accept that before rotating.

## What Zap does NOT defend against

- **A live, privileged attacker on the running server** while users are
  logged in: unwrapped DEKs are in process memory by design.
- **A malicious server operator**: plaintext transits server memory during
  add/reveal. The upgrade that removes this class is client-side (WebCrypto)
  encryption where the master password never leaves the browser - the
  Bitwarden model. The storage format (wrapped DEK, per-blob AAD) was chosen
  so that migration is a client change, not a data migration.
- **Compromise of your own browser or clipboard.**
- Denial of service; TLS is assumed to be terminated in front of Zap
  (set `ZAP_HTTPS=1` so cookies are marked Secure).

## Reporting

Open a GitHub issue for non-sensitive reports, or email the address in the
README for anything that should stay private until fixed.
