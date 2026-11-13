# Dashboard frontend

Next.js + TypeScript + Tailwind CSS, built as a static export (ADR-0005).

The FastAPI app serves the compiled output from `dashboard/out/` so a single
`python -m api` entry point starts both the API and the frontend.

## Development

```bash
cd dashboard
npm install
npm run dev        # local dev server (port 3000)
npm run build      # static export → out/
```

## Security note

All attacker-supplied and LLM-generated text must be rendered as plain text.
Never use `dangerouslySetInnerHTML` with untrusted content.
See R6.9.
