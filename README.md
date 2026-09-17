# ScamShield AI — AI-Powered Digital Scam Defense System

ScamShield AI is a **defensive, educational** tool that helps people spot possible
warning signs in suspicious links, messages, QR codes, and media. It runs entirely
on your own computer, uses **only local rule-based heuristics** (no paid APIs, no
API keys, no external AI services), and never claims to be certain.

> ScamShield AI never says a link is "definitely safe" or "definitely fraudulent."
> It only highlights **possible warning signs** so you can make your own informed decision.

---

## 1. Project overview

| | |
|---|---|
| **Type** | Local web app: FastAPI backend + single-file HTML frontend |
| **Purpose** | Defensive cybersecurity education — highlight scam warning signs |
| **Cost** | Free. No paid APIs, no API keys required |
| **Data handling** | Nothing submitted is stored permanently; uploads are processed in memory only |
| **Languages** | English (`en`) and Hindi (`hi`) |

## 2. Features

- **URL Scanner** — local heuristic analysis of a link (no request is ever made to the submitted URL).
- **Message Analyzer** — rule-based detection of scam patterns in pasted SMS/WhatsApp/email text.
- **QR Scanner** — decodes an uploaded QR code image locally and analyzes any link found inside it, without ever opening it.
- **Experimental Media Checker** — transparent, clearly-labeled experimental heuristics for text or images. This is **not** a reliable AI-content detector, and the app never claims it is.
- **Bilingual** — English and Hindi explanations throughout.
- **Text-to-speech** — uses the browser's built-in speech synthesis (nothing is sent to a third-party speech service).
- **Safety Guide** — plain-language guidance on protecting yourself from scams.

## 3. Folder structure

```
scamshield-ai/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py               # FastAPI app & routes
│   │   ├── schemas.py            # Pydantic request/response models
│   │   ├── config.py             # Settings, CORS, limits
│   │   └── services/
│   │       ├── __init__.py
│   │       ├── url_analyzer.py       # URL heuristic engine
│   │       ├── message_analyzer.py   # Message heuristic engine
│   │       ├── qr_analyzer.py        # Local QR decoding (OpenCV)
│   │       └── media_analyzer.py     # Experimental media checks
│   ├── tests/
│   │   ├── __init__.py
│   │   └── test_api.py
│   ├── requirements.txt
│   ├── .env.example
│   └── .gitignore
├── frontend/
│   └── index.html                # Entire frontend: HTML + CSS + JS in one file
├── README.md
└── .gitignore
```

## 4. Windows setup

You need **Python 3.10+** installed. Check with:

```powershell
py --version
```

Clone or copy this project folder, then open it in VS Code.

## 5. Virtual environment setup

From the project root (`scamshield-ai/`):

```powershell
py -m venv backend\venv
.\backend\venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script with an execution-policy error, you
have two options:

**Option A — allow scripts for your user (one-time):**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
Then re-run the `Activate.ps1` command above.

**Option B — skip activation entirely** and call the venv's Python directly
for every command (see the alternative commands in each section below).

## 6. Package installation

With the virtual environment active:

```powershell
py -m pip install -r backend\requirements.txt
```

**Alternative (no activation):**
```powershell
backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

> **Note on the QR scanner:** it uses `opencv-python-headless`. If that package
> ever fails to install on your machine, the app still works — the `/analyze-qr`
> endpoint will simply respond that QR decoding is unavailable, and every other
> feature keeps working normally.

## 7. Running tests

```powershell
py -m pytest backend\tests
```

**Alternative (no activation):**
```powershell
backend\venv\Scripts\python.exe -m pytest backend\tests
```

## 8. Starting the backend

```powershell
py -m uvicorn app.main:app --reload --app-dir backend
```

**Alternative (no activation):**
```powershell
backend\venv\Scripts\python.exe -m uvicorn app.main:app --reload --app-dir backend
```

The API will be available at `http://127.0.0.1:8000`. Visit
`http://127.0.0.1:8000/docs` for interactive API documentation (Swagger UI).

## 9. Starting the frontend with Live Server

1. Open `frontend/index.html` in VS Code.
2. Install the **Live Server** extension if you don't already have it.
3. Right-click `index.html` → **"Open with Live Server"**.
4. Your browser will open something like `http://127.0.0.1:5500/frontend/index.html`.
5. Make sure the backend (step 8) is running at the same time — the frontend
   calls `http://127.0.0.1:8000` directly.

If you open `index.html` by double-clicking it instead of using Live Server,
some browsers will block the requests to the backend due to CORS restrictions
on `file://` pages. Using Live Server (or any local static server) avoids this.

## 10. API endpoint documentation

### `GET /`
Returns basic project information and a disclaimer.

### `GET /health`
```json
{ "status": "healthy", "service": "scamshield-backend" }
```

### `POST /analyze-link`
**Request:**
```json
{ "url": "https://example.com", "language": "en" }
```
**Response:** risk report (`risk_level`, `risk_score`, `summary`, `red_flags`,
`safety_advice`, `technical_details`, `disclaimer`).

### `POST /analyze-message`
**Request:**
```json
{ "message": "Your account will be blocked. Send your OTP immediately.", "language": "en" }
```
**Response:** same risk-report shape as `/analyze-link`.

### `POST /analyze-qr`
**Multipart form-data:**
- `file`: image file (PNG/JPEG/WEBP, max 5MB)
- `language`: `en` or `hi`

Decodes the QR code locally. If it contains a URL, that URL is analyzed the
same way as `/analyze-link` — it is **never opened**.

### `POST /analyze-media`
**Multipart form-data:** either
- `text`: text to check, **or**
- `file`: an image to check

plus `language`. Returns an experimental, clearly-labeled result that is
**never** presented as proof of AI generation.

## 11. Security limitations

Be transparent with yourself and your users about what this project **does not** do:

- It does **not** fetch, render, or open submitted URLs — analysis is purely
  string/pattern based, so it cannot detect issues that only appear once a
  page loads (e.g. a fake login form hosted on an otherwise "clean-looking" domain).
- It does **not** use a trained machine-learning model — all detection is
  transparent, explainable, rule-based heuristics. This means it can both
  miss new scam patterns and occasionally flag legitimate content.
- The **Experimental Media Checker** cannot reliably detect AI-generated
  content. Treat its output as a discussion starter, not a verdict.
- CORS is currently open to common local development origins
  (`127.0.0.1:5500`, etc.) — **do not deploy this as-is to production.** Restrict
  `ALLOWED_ORIGINS` (see `.env.example`) to your real frontend domain first.
- There is no authentication, rate limiting, or persistent storage in this
  version. Do not use it to handle real user accounts or sensitive data.
- Uploaded QR/media files are processed only in memory for the duration of
  the request and are never written permanently to disk.

## 12. Free deployment plan

You can deploy this project for free without a paid account:

**Backend (FastAPI) — free-tier Python host** (e.g. Render, Railway, Fly.io
free tiers — check current free-tier terms, as they change over time):
1. Push the `backend/` folder to a Git repository.
2. Create a new "Web Service" pointing at that repo.
3. Set the start command to:
   ```
   uvicorn app.main:app --host 0.0.0.0 --port $PORT --app-dir backend
   ```
   (adjust `--app-dir` if your host's working directory differs)
4. Set the `ALLOWED_ORIGINS` environment variable to your deployed frontend's
   exact URL (e.g. `https://your-frontend.pages.dev`).

**Frontend — free static host** (e.g. GitHub Pages, Cloudflare Pages, Netlify
free tier):
1. Deploy the `frontend/` folder (it's just one HTML file).
2. Open `frontend/index.html` and change:
   ```js
   const API_BASE = "http://127.0.0.1:8000";
   ```
   to your deployed backend's HTTPS URL, e.g.:
   ```js
   const API_BASE = "https://your-backend.onrender.com";
   ```
3. Re-deploy the frontend.

**Production CORS:** Set the backend's `ALLOWED_ORIGINS` environment variable
(comma-separated if more than one) to the exact frontend origin(s) — never
leave it as `*` if you ever add cookies/credentials later.

**Free-tier limitations to expect:**
- Free web services often "sleep" after inactivity, causing a slow first request.
- Free tiers usually cap monthly compute hours and bandwidth.
- Uploaded files and sensitive data should **never** be stored, even
  temporarily, on a free host you don't fully control — this project already
  avoids persistent storage by design; keep it that way.

This project has **not** been deployed anywhere by default — you must follow
the steps above yourself if you want a live, public version.

## 13. Future improvements

- Add more languages beyond English and Hindi.
- Expand the heuristic keyword/pattern lists based on real-world scam reports.
- Add a browser extension version that can check links before they're clicked.
- Add optional, privacy-respecting reputation lookups (e.g. checking a domain's
  registration age) — with explicit user consent and clear disclaimers.
- Add screen-reader-optimized result summaries.
- Add a feedback mechanism so users can report false positives/negatives to
  improve the heuristics (with no personal data collected).

---

**Disclaimer:** ScamShield AI is an educational project. It provides
preliminary heuristic analysis only and is not a substitute for official
verification, professional security tools, or your own good judgment.
