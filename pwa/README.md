# Esoptron PWA

Mobile-friendly Progressive Web App for scanning Metatron cards and
enrolling on a phone or desktop browser.

## Architecture

```
pwa/                      Vite + React + TS frontend (this folder)
└── src/
    ├── lib/
    │   ├── api.ts        Typed client for /api/v1/* (REST + multipart)
    │   └── storage.ts    IndexedDB + AES-GCM passphrase-encrypted store
    ├── components/
    │   ├── CameraScanner.tsx
    │   └── MnemonicDisplay.tsx
    ├── App.tsx           Multi-step UX state machine
    └── main.tsx          React entry point

Backend (separate process):
    py scripts/serve_pwa_api.py  →  http://localhost:8765/api/v1/*
```

## Development

```bash
# 1. Start the Python REST API (with CORS for Vite)
py scripts/serve_pwa_api.py --cors http://localhost:5173

# 2. In another terminal, start the PWA dev server
cd pwa
npm install
npm run dev
# → opens http://localhost:5173
```

The Vite dev server proxies `/api/*` to the Python backend by default;
override via the `VITE_API_TARGET` env var.

## User flow

```
welcome ──▶ scan ──▶ scanning ──▶ phrase ──▶ passphrase ──▶ ready
   ▲                                                          │
   └────────────── reset (clear IndexedDB) ───────────────────┘

   unlock ──▶ ready          (returning user)
```

* `welcome`     — first-time landing, button to start camera
* `scan`        — live camera preview + manual capture button
* `scanning`    — upload to backend, await ScanResult
* `phrase`      — show 24 BIP-39 words, quiz on 3 random positions
* `passphrase`  — set passphrase for local AES-GCM store
* `ready`       — show enrollment summary
* `unlock`      — passphrase prompt for returning users

## Security model

* `device_secret` is fetched once from the backend (via
  `X-Esoptron-Reveal-Secrets: 1`) and stored locally encrypted with
  AES-GCM using a key derived from the user's passphrase via PBKDF2-SHA-256
  (600 000 iterations).
* The 24-word BIP-39 phrase is shown once and never persisted client-side.
* Backend never persists anything — it is a pure scan-and-return service.
* This MVP runs over HTTP in dev; production deployment MUST use HTTPS
  (camera access requires a secure context on most browsers).

## Build

```bash
npm run build
# Output: pwa/dist/
```

The build is a standard static bundle (Vite + service worker manifest)
ready to deploy on any HTTPS host: GitHub Pages, Netlify, Cloudflare
Pages, etc.
