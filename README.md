# VEXORA License System (independent)

A small independent license manager with a web admin panel, FastAPI endpoints, and SQLite storage. It is intended for software you own or are authorized to manage; it does not integrate with any game or bypass anti-cheat/security systems.

## Features
- Admin login protected by `ADMIN_PASSWORD`.
- Create licenses with any duration in hours (default 48) and device limit (default 2).
- License duration starts on first successful activation.
- Ban/unban, renew by hours, delete, and list licenses.
- API activation and periodic verification endpoints.
- UTC server-side expiry checks.

## Railway setup
1. Create a new project and deploy this folder from a GitHub repository.
2. Add these environment variables in Railway:
   - `ADMIN_PASSWORD`: long, unique admin password.
   - `SESSION_SECRET`: long random secret (at least 32 random characters).
   - `API_SHARED_SECRET`: a separate long random secret.
   - `DATABASE_PATH`: `licenses.db` (only suitable if your deployment uses persistent storage).
3. Add a Railway persistent volume and mount it where `licenses.db` is stored. Set `DATABASE_PATH` to a path on that volume, e.g. `/data/licenses.db`.
4. Deploy. Visit the generated public domain; `/health` should return `{"ok":true,...}`.

Important: SQLite data on an ephemeral filesystem can be lost during redeploys. Use a persistent volume or replace SQLite with a managed database before relying on real licenses. Review current Railway plan and pricing before deployment.

## API
Both endpoints require the header `X-API-Secret: <API_SHARED_SECRET>`. Do not expose this secret in a public client application. A real production client should use a server-side broker or an appropriate signed challenge/session design; any secret embedded in a distributed client can be extracted.

### Activate
`POST /api/v1/activate`
```json
{"key":"VEX-ABCD-EFGH-IJKL","device_id":"stable-device-identifier"}
```
First successful activation sets the expiry time to now + `duration_hours`. A new device is rejected after the limit is reached.

### Verify
`POST /api/v1/verify`
```json
{"key":"VEX-ABCD-EFGH-IJKL","device_id":"stable-device-identifier"}
```
Verifies expiry, status, and registered device.

## Local run
```bash
python -m venv .venv
# activate the environment
pip install -r requirements.txt
# set ADMIN_PASSWORD, SESSION_SECRET, API_SHARED_SECRET in your shell
uvicorn app:app --reload
```

## Security notes
- Use HTTPS and strong secrets.
- Never commit `.env` or secrets to GitHub.
- This is a starter project, not a security audit. For production, add CSRF protection, login rate limiting, audit logs, backups, and preferably PostgreSQL.
- The API shared secret is for trusted server-to-server calls. Do not embed it in a client distributed to users.
