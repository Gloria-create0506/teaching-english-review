# Teaching English Review

This project hosts interactive English review webpages for Journey to the West Chapters 1-6 and an extra Module 4 lesson page.

## Current auth model

The project now uses a simplified account system:

- email registration
- email sign-in
- signed-in password change
- optional registration domain whitelist

Because of that, the site must run through `server.js`. Pure static file mode is no longer enough for real user access.

## Main files

- `server.js`: account system and static file server
- `login.html`: static fallback page that tells users to open `/login`
- `chapters.html`: chapter hub
- `index.html`: Chapter 1
- `chapter-2.html` to `chapter-6.html`: other chapter pages
- `module-4-unit-1-body-party.html`: extra lesson page
- `render.yaml`: Render deployment settings
- `start-server.bat`: local server start script

## Required environment variables

Recommended environment variables:

- `ALLOWED_EMAIL_DOMAINS`: comma-separated registration whitelist, for example `qq.com,gmail.com,school.edu`
- `LOCKED_LESSONS`: comma-separated locked lessons, for example `module-4,chapter-6`
- `SESSION_HOURS`: default `24`

## Local run

1. Install Node.js 18 or newer.
2. If you want to limit who can register, set `ALLOWED_EMAIL_DOMAINS`.
3. If you want to lock certain lessons, set `LOCKED_LESSONS`.
4. Run:

```powershell
node server.js
```

5. Open:

```text
http://localhost:8765/login
```

You can also use:

```text
start-server.bat
```

## Render deployment

This project is ready for Render.

1. Upload the project to GitHub.
2. Connect the repo to Render as a Node web service.
3. Make sure these environment variables are set in Render:

```text
ALLOWED_EMAIL_DOMAINS=qq.com,gmail.com,school.edu
LOCKED_LESSONS=module-4,chapter-6
SESSION_HOURS=24
```

`LOCKED_LESSONS` supports either aliases or full file names. Examples:

- `module-4`
- `module-4-unit-1-body-party.html`
- `chapter-6`
- `chapter-6.html`

4. Start command:

```text
node server.js
```

## State file

User and session data are stored in:

```text
auth-state.json
```

This file is intentionally ignored by git.

If a user forgets a password in this simplified version, either:

- create a new account for that user, or
- manually edit `auth-state.json` on the server

If the user is already signed in, they can open `/account` and change the password directly.

## Packaging

Rebuild the public web upload package:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-public-web-package.ps1
```

Rebuild the Windows installer:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1
```

Rebuild the Codex handoff package:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-codex-share-package.ps1
```
