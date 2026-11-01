# Watch — Gujarati-first social app

Watch is a small Node.js + SQLite social app with Home, Stories, Reels, Videos, Explore, Create, and Profile screens.

## Project layout

- `server.js` — Node.js HTTP server and SQLite API (Node 22.13+).
- `public/index.html` — responsive Gujarati-first single-page app.
- `public/manifest.json`, `public/icon.svg` — PWA metadata and app icon.
- `mobile/` — Capacitor Android wrapper.
- `.github/workflows/build-apk.yml` — manually triggered Android debug APK build.
- `render.yaml`, `Dockerfile` — Render deployment configuration.

## Run locally

Install Node.js 22.13 or newer, then run:

```bash
npm start
```

Open `http://localhost:3000`. For local HTTP testing only, use `npm run dev` (this disables the Secure cookie flag; do not use this setting in production).

The server stores the SQLite database and uploads in `DATA_DIR` (default: `./data`). For a deployed server, set `DATA_DIR=/data`, provide a long random `SECRET`, and use HTTPS.

## Deploy to Render

1. Push the whole repository to GitHub.
2. In Render, create a Blueprint and select this repository.
3. Confirm that `DATA_DIR=/data`, `TRUST_PROXY=1`, and a persistent disk mounted at `/data` are configured.
4. Use the HTTPS URL Render provides.

Do not publish secrets or real user data in GitHub.

## Build Android debug APK

This workflow builds an APK that opens the deployed HTTPS Watch site inside a Capacitor Android shell. It requires an internet connection and a deployed server.

1. Deploy the web app first and copy its HTTPS URL.
2. In GitHub, open **Settings → Secrets and variables → Actions → Variables**.
3. Add repository variable `APP_URL`, e.g. `https://your-watch-app.onrender.com`.
4. Open **Actions → Build Android APK → Run workflow**.
5. When the workflow completes, download the `watch-apk` artifact and install `app-debug.apk` on your Android phone.

This is a **debug APK** for testing, not a Play Store release. A Play Store release requires signing configuration and further testing.

## Features

- Signup/login with password hashing and signed HttpOnly cookies.
- Posts, photo/video uploads, Stories, Reels and video pages.
- Likes, comments, saves, follows, blocks and reports.
- Explore ranking, search, theme toggle and profile editing.
- Upload type sniffing, request limits and basic security headers.

## Important limitations

- This is an early-stage project. Test with dummy accounts and non-sensitive content before inviting real users.
- Instagram, Facebook and YouTube are not automatically integrated by this code. Content is user-uploaded to Watch; external platform integration requires official APIs and compliance with their terms.
- No production moderation dashboard, password reset, email/phone verification, or signed Android release is included.
