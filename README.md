# Vande Mataram OTP backend (Fast2SMS)

Why this exists: the Fast2SMS key must never be inside the app (index.html / JS). Anyone can open
those files and use your key to spend your SMS credits. The app calls this server; only this server
knows the key.

## Deploy (Render / Railway / any VPS with Node 18+)
1. Upload this folder (keep `.env` PRIVATE - do NOT put it on Cloudflare Pages / a public site).
   On Render/Railway set the variables from `.env` in the dashboard instead of uploading the file.
2. Start command: `node server.js`  (no npm install needed).
3. Open `https://YOUR-SERVER/health` -> should show `{"ok":true}`.
4. In the app's `config.js` set: `window.VM_API='https://YOUR-SERVER';` and redeploy the app.
5. Set `ALLOWED_ORIGINS` to your real app URL.

## Built-in SMS-credit protection
- 60 s cooldown per number, max 5 SMS/hour per number, 10/hour per IP, hard daily cap (`DAILY_SMS_CAP`).
- OTP valid 5 min, 5 wrong tries, stored only as an HMAC hash, never logged.
- Fast2SMS "OTP" route needs your Fast2SMS account to be verified / wallet recharged.
- OTP state is in memory: run ONE instance (a restart just means users request a new OTP).

## Security note
The key was shared in a chat message, so treat it as exposed: after this works, generate a new
key in the Fast2SMS dashboard and update `FAST2SMS_API_KEY` here.
