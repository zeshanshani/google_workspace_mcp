# Gmail MCP

A Gmail-only MCP server, stripped down from
[taylorwilsdon/google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp)
and wired for Railway deployment.

## What it exposes

Gmail tools only. Three tool tiers (`core`, `extended`, `complete`) defined in
`core/tool_tiers.yaml`. The Railway config runs the `core` tier:

- `search_gmail_messages`
- `get_gmail_message_content`
- `get_gmail_messages_content_batch`
- `send_gmail_message`

Raise to `--tool-tier extended` or `--tool-tier complete` to expose drafts,
labels, filters, threads, and batch label operations.

## Run locally

Requires [`uv`](https://github.com/astral-sh/uv) and Python 3.10+.

```bash
uv sync --group dev
uv run main.py --transport streamable-http --tools gmail --tool-tier core
```

Set `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` first (use
`.env` or shell export). The callback URL Google needs to know about is
`http://localhost:8000/oauth2callback` by default.

## Deploy to Railway

1. Push this branch to GitHub.
2. Create a Railway project from the repo. Railway auto-detects
   `Dockerfile` and uses `railway.json` for the start command.
3. Set environment variables per `.env.railway.example`:
   - `GOOGLE_OAUTH_CLIENT_ID`
   - `GOOGLE_OAUTH_CLIENT_SECRET`
   - `WORKSPACE_MCP_HOST=0.0.0.0`
   - `MCP_ENABLE_OAUTH21=true`
   - `WORKSPACE_MCP_STATELESS_MODE=true`
   - `WORKSPACE_EXTERNAL_URL=https://<your-app>.up.railway.app`
4. Add `https://<your-app>.up.railway.app/oauth2callback` to the OAuth
   client's authorized redirect URIs in Google Cloud Console.

`$PORT` is set by Railway automatically; `main.py` reads it first before
falling back to `WORKSPACE_MCP_PORT`.

## Tests

```bash
uv run ruff check .
uv run pytest
```

## Security

See `SECURITY_AUDIT.md` for the audit that accompanied this strip.

## License

MIT. Upstream copyright remains with Taylor Wilsdon.
