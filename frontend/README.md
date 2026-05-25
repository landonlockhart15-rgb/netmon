# NetMon Frontend

The NetMon dashboard — a React + TypeScript + Vite single-page app served by the
NetMon backend.

## Layout

- `src/components/sections/` — main views: `Overview`, `Devices`, `Alerts`, `Shield`
- `src/components/layout/` — `Shell`, `Sidebar`, `TopBar`, `MobileNav`, `StatStrip`
- `src/components/shared/` — reusable pieces, including `DeviceChat` and `DeviceModal`
- `src/lib/api.ts` — typed client for the backend REST API

## Development

```bash
npm install
npm run dev     # Vite dev server with HMR (talks to the running NetMon backend)
npm run build   # production build → ../static/  (committed; this is what ships)
npm run lint    # ESLint
```

The build output is written to the repo's top-level `static/` directory, which
the FastAPI backend (`app/main.py`) serves. A regular NetMon install uses the
committed `static/` bundle and never needs Node — only UI contributors do.
