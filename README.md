# Teaching English Review

This project hosts interactive English review webpages for Journey to the West Chapters 1-6 and an extra Module 4 lesson page.

## Current auth model

The project now uses full account authentication:

- email registration
- email verification
- email sign-in
- password reset by email

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

These are required for real registration and password reset:

- `RESEND_API_KEY`: Resend API key
- `EMAIL_FROM`: verified sender email, for example `Journey Review <noreply@yourdomain.com>`

These are recommended:

- `APP_BASE_URL`: public base URL, for example `https://teaching-english-review.onrender.com`
- `ALLOWED_EMAIL_DOMAINS`: comma-separated registration whitelist, for example `qq.com,gmail.com,school.edu`
- `SESSION_HOURS`: default `24`
- `VERIFY_TOKEN_HOURS`: default `24`
- `RESET_TOKEN_MINUTES`: default `30`

## Local run

1. Install Node.js 18 or newer.
2. Set `RESEND_API_KEY` and `EMAIL_FROM`.
3. Run:

```powershell
node server.js
```

4. Open:

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
RESEND_API_KEY=your_resend_api_key
EMAIL_FROM=Journey Review <noreply@yourdomain.com>
APP_BASE_URL=https://your-public-domain
ALLOWED_EMAIL_DOMAINS=qq.com,gmail.com,school.edu
SESSION_HOURS=24
VERIFY_TOKEN_HOURS=24
RESET_TOKEN_MINUTES=30
```

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
