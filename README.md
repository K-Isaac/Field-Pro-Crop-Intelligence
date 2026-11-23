# FieldLens Pro AI — Live Platform (v3)

Anyone with internet opens the site, photographs a plant, and gets an AI diagnosis
(health, nutrients, water, pests, fertilizer, harvest timing) in English, Kinyarwanda, French or Swahili.
Everything operational lives in **/admin**.

| URL | Who | What |
|---|---|---|
| `/` | Public | Scan, results, personal history, shareable result links (`/r/<id>`), installable PWA |
| `/admin` | You only | Overview, all scans, AI keys, alarm rules, limits, site text, QR poster, feedback, logs, security |
| `/healthz` | Host | Health check |

## Put it live (about 10 minutes)
1. Create a **new** OpenAI key (the one pasted in chat earlier must be revoked — see below).
2. Push this folder to a private GitHub repo.
3. Render.com → New → **Blueprint** → pick the repo (`render.yaml` does the rest).
4. In the Render dashboard set `OPENAI_API_KEY`; read the generated `ADMIN_PASSWORD`.
5. Open `https://<your-service>.onrender.com/` (public) and `/admin` (you). Add your own domain in Render → Settings → Custom Domains.

Also runs on Railway / Fly.io / any Docker host: `docker build -t fieldlens . && docker run -p 8080:8080 -e ADMIN_PASSWORD=... -e OPENAI_API_KEY=... -v fl:/data fieldlens`

## Environment variables
| Name | Purpose |
|---|---|
| `ADMIN_PASSWORD` | Required. `/admin` login is disabled without it (no default PIN). Changeable later inside /admin. |
| `OPENAI_API_KEY` / `GEMINI_API_KEY` | AI engine keys. Can instead be pasted in /admin → AI engine. |
| `SECRET_KEY` | Session signing. Auto-generated and stored in `DATA_DIR` if absent. |
| `DATA_DIR` | Where the SQLite DB and photos live. **Mount a persistent disk here.** |
| `FL_ENV=production` | Secure cookies + HSTS. |

## Built-in protection (because it's open to everyone)
- Per-visitor hourly limit and a global daily cap (both editable in /admin) so a stranger can't run up your AI bill.
- Photos validated, EXIF/GPS stripped, resized to 1280px; AI output sanitised; all page output HTML-escaped.
- Admin: hashed password, login lockout, HttpOnly/SameSite session, CSRF header, API keys never sent to the browser.
- No simulated results: if the AI is down or unconfigured, users are told so instead of getting fake diagnoses.

## Local run
```
pip install -r requirements.txt
ADMIN_PASSWORD=yourpass OPENAI_API_KEY=sk-... python app.py   # http://localhost:5000
```
