# PentaForge UI (Tauri 2)

Desktop UI built with React + Vite (frontend) and Tauri 2 (desktop shell).

## Scripts

- `npm run dev` -> run desktop app with Tauri dev mode.
- `npm run build` -> build desktop app with Tauri.
- `npm run web:dev` -> run only the web frontend (Vite).
- `npm run web:build` -> build only the web frontend.

## Notes

- Tauri config lives in `src-tauri/tauri.conf.json`.
- Window controls are implemented via `@tauri-apps/api/window` in the React titlebar.
- Projects are persisted through the server API (`/api/projects`) into local SQLite.

## Run Backend API

From repo root:

```bash
python -m pip install -r server/requirements-api.txt
python -m uvicorn server.api.app:app --host 127.0.0.1 --port 8000
```

Projects data is persisted locally in:

`server/db/projects/projects.db`

Then run the desktop UI:

```bash
npm run dev
```
