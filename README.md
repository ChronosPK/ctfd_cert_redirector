# ctfd_cert_redirector

Minimal CTFd plugin that exposes a "Certificates" page to participants and
redirects them to an external certificate portal with a signed, short-lived token.

## Features

- `/certificates` (user, authenticated):
  - Shows context text and a "Claim certificate" button.
  - Only available after the CTF end time, unless early claims are enabled.
- `/certificates/claim` (user, authenticated):
  - Issues a signed token with user + team context and redirects to the external app.
- `/admin/certificates` (admin):
  - Shows status (configured / not configured).
  - Shows current external URL, TTL, audience.
  - Simple toggle to allow / disallow claims before CTF end.
  - Link to open the participant view in a new tab.

## Token format

The plugin generates a compact token:

- Body: base64url(JSON), no padding.
- Signature: base64url(HMAC-SHA256(body, shared_secret)).
- Final token: `body + "." + signature`.

Body fields:

- `aud`: audience string.
- `uid`: CTFd user id.
- `email`: user email (if present).
- `name`: user name.
- `team_id`: team id (if any).
- `team_name`: team name (if any).
- `team_score`: numeric score for the team (if any).
- `team_pos`: 1-based team rank on the public scoreboard (if any).
- `bracket_id`: bracket id (if used).
- `bracket_name`: always `null` in vanilla CTFd CE.
- `ts`: UNIX timestamp of issuance (seconds).
- `ttl`: lifetime in seconds.

The external app must:

1. Split the token on `"."` into `body` and `sig`.
2. Compute `expected_sig = base64url(HMAC-SHA256(body, shared_secret))`.
3. Compare `sig == expected_sig` in constant time.
4. Decode `body` from base64url into JSON.
5. Check `now <= ts + ttl`.
6. Check `aud` matches the expected audience.

If all checks pass, the payload can be trusted as issued by CTFd.

## Configuration

The plugin is configured entirely via environment variables on the CTFd service:

- `CTFDBRIDGE_EXTERNAL_URL` (required)  
  External certificate portal, e.g. `https://certs.example.org/claim`.

- `CTFDBRIDGE_SHARED_SECRET` (required)  
  Long random secret used for HMAC-SHA256.

- `CTFDBRIDGE_TTL` (optional, default: `600`)  
  Token lifetime in seconds.

- `CTFDBRIDGE_AUD` (optional, default: `chronos-cert`)  
  Audience string to bind tokens to your verifier.

- `CTFDBRIDGE_ALLOW_BEFORE_END` (optional, default: `false`)  
  Initial mode for allowing claims before the CTF end time.
  Can later be toggled from `/admin/certificates`.

The plugin also stores the "allow before end" flag in CTFd's config under:

- `cert_redirector:allow_before_end`

## Installation

1. Copy this directory into `CTFd/CTFd/plugins/ctfd_cert_redirector`.
2. Ensure it is importable as `CTFd.plugins.ctfd_cert_redirector`:
   - Set `config.json` accordingly if you use plugin autoloading.
3. Set environment variables on the CTFd container (e.g. in `docker-compose.yml`):
   ```yaml
   environment:
     - CTFDBRIDGE_EXTERNAL_URL=https://certs.example.org/claim
     - CTFDBRIDGE_SHARED_SECRET=change_me_to_a_long_random_value
     - CTFDBRIDGE_TTL=600
     - CTFDBRIDGE_AUD=chronos-cert
4. Restart CTFd.
After restart:
  - Admin panel: /admin/certificates
  - User panel: /certificates
  - Claim endpoint: /certificates/claim