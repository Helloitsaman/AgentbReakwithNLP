# AgentBreak — Live Agent Flow

A standalone n8n-style live visualization of the AgentBreak agents working:
each step the attacker, target agent, policy guard, and oracle take becomes a
block, connected by branches that grow in real time as a run executes. Below
the flow is a live metrics section (outcomes, categories, severity, coverage).

Black + gold theme to match the main dashboard.

## Run it

```bash
npm install          # first time only
npm run dev          # http://localhost:5174
```

It runs on **port 5174** so it won't clash with the main dashboard (5173).
`vite.config.js` proxies `/api` to the backend on `http://127.0.0.1:8000`.

## Modes
- **Live Campaign** — runs every scenario via `POST /api/test-runs`, fetches
  traces, and draws one branch per scenario (deterministic or hybrid LLM).
- **Live Single Scan** — runs `POST /api/real/scan` and draws one branch.
- **Simulated (no backend)** — uses built-in sample data so it works with the
  backend off. Safe for live presenting.

Start the backend first for the live modes; use Simulated otherwise.

## Drop it into the main dashboard instead (optional)
`src/App.jsx` is self-contained. To make it a tab in the existing dashboard,
copy its body into a `LiveFlowPage` component, `npm i reactflow`, and render it
as a new view. The same `/api` calls work there (the main app already proxies
`/api`).
