# Security Audit — Gmail-only MCP Server

Audit target: Gmail-only strip of `google_workspace_mcp` on branch `gmail-only`.
Scope: `auth/`, `core/`, `gmail/`, `main.py`, `pyproject.toml`, deploy configs. Tests excluded from severity counts.

> **Status (post-fix commit):** Findings **1.2**, **1.3**, **2.2**, **2.3**, and **4.1** are fixed. 13 new regression tests in `tests/auth/test_security_hardenings.py` guard the behaviour. Other findings are left as documented trade-offs or deferred — see individual entries.

Severity legend: **Critical** (fix before deploy), **High** (fix soon), **Medium** (hardening), **Low** (hygiene), **Informational** (documented or working as intended).

Findings are grouped by domain. Each finding includes a file:line reference and a concrete remediation. Several findings surfaced by automated agents were verified by re-reading the cited code; where the agent's severity was over- or under-stated, I have adjusted it with a note.

---

## 1. Credential and token handling

### 1.1 Plaintext refresh-token storage in legacy (non-OAuth-2.1) mode — **High**
`auth/credential_store.py:178-207`

`LocalDirectoryCredentialStore` writes `refresh_token`, `token`, and `client_secret` to `~/.google_workspace_mcp/credentials/<email>.json` in plaintext. File mode is 0600 and directory mode is 0700 (line 126 / line 198), so OS-level ACLs are correct, but there is no encryption at rest. In the OAuth 2.1 path (`core/server.py:237-238, 358-430`), tokens are Fernet-encrypted with a key derived from `FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY` or the client secret.

Risk: disk-image theft, container escape, or lateral movement from another process running as the same user exposes refresh tokens. On Railway this is moot (deployment should use OAuth 2.1 + stateless mode, which skips the local store entirely), but if someone runs the server locally in stdio mode they are storing plaintext refresh tokens indefinitely.

Remediation: prefer the OAuth 2.1 + encrypted backend path for any non-ephemeral deployment. For local use, document this clearly or add Fernet wrapping to `LocalDirectoryCredentialStore`.

### 1.2 Credentials directory created without explicit mode — **Fixed** (was Medium)
`core/utils.py:275`

`check_credentials_directory_permissions()` calls `os.makedirs(credentials_dir, exist_ok=True)` with no `mode=`, relying on the process umask. On a typical umask of 0o022 the directory ends up 0o755 (world-readable). `auth/credential_store.py:126` creates the same directory later with 0o700, but if the check function runs first on a fresh host the dir is created 0o755 and never tightened.

Remediation: `os.makedirs(credentials_dir, mode=0o700, exist_ok=True)` and a post-creation `os.chmod(..., 0o700)` assertion.

**Applied:** `core/utils.py:check_credentials_directory_permissions` now passes `mode=0o700` to `makedirs`, tightens existing directories via `chmod(0o700)`, and creates the probe file via `os.open(..., 0o600)` instead of plain `open(...)` so the umask can't widen it.

### 1.3 Revoked refresh token not purged — **Fixed** (was Medium)
`auth/google_auth.py:844-856, 1032-1037`

When `RefreshError` is raised (user revoked access in Google account settings, token expired past the refresh window), the function logs and returns `None`. The stored credential file is left on disk with a dead refresh token. `delete_credential()` exists (`auth/credential_store.py:209-227`) but is never called on this path.

Remediation: on `RefreshError`, call `get_credential_store().delete_credential(user_google_email)` before returning.

**Applied:** `auth/google_auth.py:get_credentials` now deletes the stored credential for the user after a `RefreshError`, guarded by `is_stateless_mode()` so Railway/stateless deployments (which have no file to delete) are unaffected. Failure to delete is logged at WARNING and does not block the re-auth flow.

### 1.4 Encryption at rest in OAuth 2.1 mode — **Informational**
`core/server.py:237, 358-361, 363-366, 427-430`, `core/cli.py:23, 38-62`

`FernetEncryptionWrapper` is applied to both Valkey and disk backends when OAuth 2.1 is enabled. Key derivation uses the JWT signing key if present, otherwise the OAuth client secret via PBKDF2. Working as intended.

### 1.5 Tokens are not logged — **Informational**
`main.py:78-81` suppresses `httpx` and `httpcore` to WARNING (those libraries log URLs containing access tokens at INFO). Token values never appear in f-strings across `auth/`, `core/`, `gmail/`. Grep of `logger.*{.*token.*}` returns no hits inside sensitive-value positions — only token-existence / user-email log lines. Working as intended.

### 1.6 No secrets in git history — **Informational**
`git ls-files | grep -iE 'cred|secret|token|\.env|\.pem|\.key'` returns only source files (`auth/credential_store.py`, test files, `uv.lock`) plus `.env.oauth21`, which is a template with placeholder values (verified). `.gitignore` already covers `.env`, `client_secret.json`, `/.credentials`.

Minor hardening: add `oauth_states.json`, `credentials/`, `*.pem`, `*.key`, and `store_creds/` to `.gitignore` defensively.

---

## 2. OAuth 2.0 / 2.1 implementation

### 2.1 `id_token` decoded without signature verification — **Medium** (adjusted from "Critical")
`auth/google_auth.py:140-147, 1233-1244`

Both call sites use `jwt.decode(credentials.id_token, options={"verify_signature": False})` purely to extract the `email` claim. The `credentials.id_token` value was obtained inside `flow.fetch_token()` (line 677) over a TLS connection to `oauth2.googleapis.com`, so the token is effectively trusted at the point of decoding. The agent's "Critical" rating assumed the token could be attacker-controlled; in the observed call paths it cannot be.

Why it still matters: the code relies on an invariant not enforced at the decode site. If `credentials.id_token` were ever populated from an untrusted source in the future (e.g., a session-restore path), the email claim would be unsigned.

Remediation: use `google.oauth2.id_token.verify_oauth2_token(...)` against Google's JWKS, or obtain the email from the `userinfo` endpoint once after the exchange and cache it alongside the credential. Don't re-decode without verification even when today's call sites are safe.

### 2.2 `redirect_uri` not validated before starting auth flow — **Fixed** (was High)
`auth/google_auth.py:509-514`

`start_auth_flow()` accepts a `redirect_uri` argument and passes it straight to `create_oauth_flow()` with no allowlist check. `auth/oauth_config.py:219-230` defines `validate_redirect_uri()` but it is not invoked here.

This is mitigated in practice because Google enforces the redirect URI against the list registered in the OAuth client configuration, so a totally unknown redirect fails at Google. But if a second redirect URI is registered for testing and leaks into a prod deployment, or a wildcard is registered, this server won't catch it.

Remediation: call `get_oauth_config().validate_redirect_uri(redirect_uri)` before flow creation; fail closed on mismatch.

**Applied:** `start_auth_flow()` now rejects the flow with `GoogleAuthenticationError` if `validate_redirect_uri()` returns False. Covered by `TestRedirectUriAllowlistEnforced`.

### 2.3 `OAUTHLIB_INSECURE_TRANSPORT` substring check — **Fixed** (was Medium, adjusted from "High")
`auth/google_auth.py:498-504`

The check `"localhost" in redirect_uri or "127.0.0.1" in redirect_uri` uses substring matching. A misconfigured `WORKSPACE_MCP_BASE_URI=https://localhost.evil.com/...` would match. This can't bypass Google's redirect-URI check (Google still enforces the registered URI), so there is no single-step exploit, but the substring check is fragile.

Remediation: parse the redirect URI with `urlparse()` and compare `.hostname` against `{"localhost", "127.0.0.1", "::1"}` exactly. Also refuse to set the flag if `MCP_ENABLE_OAUTH21=true` or if `WORKSPACE_EXTERNAL_URL` is set.

**Applied:** a new `_redirect_uri_is_local()` helper in `auth/google_auth.py` uses `urlparse(...).hostname` against an exact allowlist, replacing both substring sites (`start_auth_flow` and `handle_auth_callback`). `http://localhost.attacker.example/cb` no longer enables insecure transport. Covered by `TestRedirectUriIsLocal`.

### 2.4 CSRF: state-missing callback fallback consumes "latest" state — **Medium** (adjusted from "High")
`auth/google_auth.py:639-658`, `auth/oauth21_session_store.py:412-427`

When a callback arrives with no `state` (Google's `prompt=select_account` path can drop it), the code consumes the latest pending state via `consume_latest_oauth_state()`. In multi-user stdio mode this could theoretically wire a callback from Bob to a pending flow started by Alice.

Severity is Medium, not High, because: (a) the callback still has to include a valid authorization `code` tied to the same OAuth client, (b) the flow's PKCE `code_verifier` is bound to the consumed state so a mismatched code fails the exchange, and (c) Railway stateless-HTTP deployments use OAuth 2.1 session binding which is not affected.

Remediation: reject the state-less path unless there is exactly one pending state on the server, or require a signed session binding in the callback URL for stdio mode.

### 2.5 Bearer-token → temporary session binding — **Medium**
`auth/oauth21_session_store.py:195-213`

A bearer token without a matching `Mcp-Session-Id` creates a synthetic session via `hashlib.sha256(token)[:8]`. This synthetic session is not registered in `_session_auth_binding`, so downstream `allow_recent_auth` paths (line ~780) can grant credentials for any user whose access token is in the store.

Remediation: on synthetic-session creation, validate the token matches an existing stored session and bind the synthetic ID to that user; reject otherwise.

### 2.6 Token expiry is lazily checked — **Low**
`auth/oauth21_session_store.py:680-696`

`Credentials` objects are reconstructed with an `expiry` value; the `google-auth` library's `valid` property is checked at tool-call time, but if a token becomes expired between retrieval and use there is no guard. In practice tokens have a 60-minute lifetime so this window is vanishingly small.

Remediation: check `credentials.expired` at retrieval time and trigger refresh proactively.

### 2.7 No JWT issuer validation when reconstructing credentials — **Low**
`auth/oauth21_session_store.py:560-572`

Issuer (`https://accounts.google.com`) is stored with the session but not re-verified when retrieving credentials. If a future code path lets a non-Google IdP populate the store, this would not catch it. Not exploitable today.

### 2.8 `GOOGLE_SERVICE_ACCOUNT_KEY_JSON` is env-loadable — **Informational** (downgraded from "High")
`auth/oauth_config.py:68`

The agent flagged this as High because the service account private key lives in an env var and could be logged. I verified `main.py:319-336`: the config-summary logger includes `GOOGLE_SERVICE_ACCOUNT_KEY_FILE` (a path) but **not** `GOOGLE_SERVICE_ACCOUNT_KEY_JSON`. No leak path observed. Prefer the file-based form on Railway anyway, since Railway env vars surface in the deploy UI.

### 2.9 No session cookies — **Informational**
No `Set-Cookie` emitted anywhere; session is tracked via the `Mcp-Session-Id` header. Avoids the entire cookie-CSRF class of issues.

---

## 3. Network egress

### 3.1 SSRF protection on Gmail attachment fetch — **Informational** (working as intended)
`core/http_utils.py:1-335`

`ssrf_safe_fetch()` and `ssrf_safe_stream()` resolve the hostname, reject non-global IPs (private ranges, loopback, link-local), pin the connection to the resolved IP with a Host header override to prevent DNS rebinding, and revalidate on every redirect (max 10 hops). This is applied to the attachment-URL path in `gmail/gmail_tools.py` (`_download_attachment_bytes` call in the attachment flow). Robust implementation.

### 3.2 Only Google domains reached from outbound calls — **Informational**
Every outbound domain observed in the code is under `googleapis.com` or `accounts.google.com` / `oauth2.googleapis.com`. `mail.google.com` and `console.cloud.google.com` appear only as link strings returned to the user, never fetched. No telemetry, analytics, or third-party SDKs (grep for `sentry`, `datadog`, `segment`, `posthog`, `analytics`, `telemetry` returns zero hits).

### 3.3 CORS allowlist includes non-Google origins — **Informational**
`auth/oauth_config.py` (referenced lines 183-186): `vscode-webview://`, `https://vscode.dev`, `https://github.dev` are allowed origins for the OAuth callback surface. Intentional (IDE integration). Worth knowing before narrowing if this server is not used from those clients.

---

## 4. Input validation and file-system safety

### 4.1 Attachment filename sanitation relies on `Path.stem` — **Fixed** (was Medium)
`core/attachment_storage.py:96-103`

Filenames returned by the Gmail API are extracted and used to build the on-disk name via `Path(filename).stem + "_" + file_id[:8] + Path(filename).suffix`. `Path.stem` collapses path separators so `../../../evil.txt` becomes `evil`, and `Path / save_name` does not permit escape into a parent directory. In practice this is safe, but the safety is an accidental property of `Path`, not an explicit assertion.

Remediation: reject filenames containing `/`, `\`, null bytes, or longer than a sensible limit (255 chars) before using them. A one-line `if any(c in filename for c in "/\\\x00"): raise ValueError(...)` makes the intent explicit and survives future refactors.

**Applied:** `AttachmentStorage.save_attachment` now raises `ValueError("... path separators or null bytes")` if the filename contains `/`, `\`, or `\x00`. Covered by four cases in `TestAttachmentFilenameSanitation`.

### 4.2 Attachment serving endpoint has no user binding — **Medium**
`core/server.py:541-563`

`GET /attachments/{file_id}` serves attachments by 128-bit UUID. UUIDs are unguessable, but they are logged, emitted in tool output, and (in HTTP mode) transmitted in URLs that may end up in proxy logs, browser history, or referer headers. If one user's UUID leaks, anyone with the UUID can fetch the attachment for the next hour (default TTL).

Remediation: bind `file_id` to the authenticated user's session in the metadata record; reject requests where the calling session does not match the owner. Alternatively, sign the file ID as a JWT (HMAC on the server secret) so possession of a raw UUID isn't sufficient.

### 4.3 `validate_file_path()` is robust — **Informational**
`core/utils.py:123-237`

Resolves symlinks via `Path.resolve()`, enforces allowlist directory via `relative_to()`, blocks `/proc`, `/sys`, `/etc/shadow`, `.ssh`, `.aws`, `.kube`, `.gnupg`, `.config/gcloud`, and common credential-file basenames. Symlink-escape and `..` traversal both blocked. Good implementation.

Gap to note: `validate_file_path()` is **not** called on the Gmail-attachment save path (`attachment_storage.save_attachment`). Saved files go to `STORAGE_DIR` which is controlled by the server, not by user input, so this is an architectural inconsistency rather than a vulnerability.

### 4.4 Gmail query parameter is safe by API contract — **Informational**
`gmail/gmail_tools.py:1253-1261`

User-provided `query` is passed as `q=` to `users().messages().list()`. The googleapiclient library URL-encodes it before transmission. Gmail's own query parser handles malformed input and returns 400. No injection pathway.

### 4.5 `ALLOWED_FILE_DIRS` enforcement — **Informational**
Enforced via `validate_file_path()` at every disk-read point where a user-supplied path enters (`send_gmail_message`'s attachment upload). Test coverage exists (`tests/core/test_validate_file_path.py`, 8 tests, all passing). Working as intended.

---

## 5. Dependencies

### 5.1 Direct dependencies all use `>=` (floating lower bound) — **Low**
`pyproject.toml`

Every dep uses `>=` rather than a pin or a compatible-release (`~=`) marker. `uv.lock` is committed (verified: `git ls-files | grep uv.lock` → `uv.lock`) so reproducibility is preserved in practice as long as callers use `uv sync --frozen` (as the Dockerfile does: line 17). Floating lower bounds are industry-normal for libraries; for this *application* I'd still suggest `~=` pins so future `uv lock` regenerations don't silently upgrade across a breaking change.

Current direct deps (13): `fastapi`, `fastmcp`, `google-api-python-client`, `google-auth-oauthlib`, `httpx`, `py-key-value-aio`, `pyjwt`, `python-dotenv`, `pyyaml`, `cryptography`, `defusedxml`, `pypdf`.

### 5.2 Resolved tree — **Informational**
`uv pip list` returns 113 packages. None are known-compromised, none are typosquats, none are third-party-service SDKs (no Sentry, Datadog, Segment, Slack, etc.). Large packages that are load-bearing: `fastmcp` (protocol), `google-api-python-client` (Gmail API), `authlib` (brought by `fastmcp`, used for JOSE). `authlib` emits a deprecation warning at runtime (`AuthlibDeprecationWarning` about `authlib.jose` → `joserfc`) which is informational only.

### 5.3 No shadow requirements.txt — **Informational**
Only `pyproject.toml` + `uv.lock`.

---

## 6. Logging discipline

### 6.1 Exception objects logged via f-string — **Low**
Multiple sites, e.g. `auth/google_auth.py:796`, `auth/auth_info_middleware.py:356, 378`, `core/server.py:694`, `auth/oauth21_session_store.py:695, 793, 1179, 1250`.

Pattern: `logger.error(f"... {e}")` or `logger.error(f"... {e}", exc_info=True)`. If a `googleapiclient.HttpError` ever stringifies with an access token in the URL (current `google-auth` uses the Authorization header, so this is defensive), the token would be logged. Low severity; modern `google-auth` does not put tokens in URLs.

Remediation: replace f-string exception logging with `logger.exception("...")` plus non-interpolated messages, so stack frames with token values are still captured but message text is clean.

### 6.2 No PII in Gmail tool logs — **Informational**
`gmail/gmail_tools.py` has only two logger calls about email content (lines 164, 182), and both log "Failed to decode body part" with the exception — no actual body content. Recipients, subjects, message bodies are never logged at INFO.

---

## 7. Code quality red flags

### 7.1 Zero hits on dangerous primitives — **Informational**
Grepped across `auth/`, `core/`, `gmail/`, `main.py`, `fastmcp_server.py`:
- `eval(` — 0
- `exec(` — 0
- `os.system(` — 0
- `os.popen(` — 0
- `pickle.load` / `pickle.loads` — 0
- `subprocess` with `shell=True` — 0
- `yaml.load(` (unsafe loader) — 0 (only `yaml.safe_load` used)
- `verify=False` / `VERIFY_NONE` / `CERT_NONE` — 0

### 7.2 Dynamic imports from static string table — **Informational**
`main.py:330` uses `import_module("gmail.gmail_tools")` with a literal string selected by keyed dict. Not user-controllable.

---

## Summary by severity (after fix pass)

| Sev | Remaining | Fixed |
|---|---:|---|
| Critical | 0 | — |
| High | 1 | ~~2.2~~ |
| Medium | 3 | ~~1.2~~, ~~1.3~~, ~~2.3~~, ~~4.1~~ |
| Low | 3 | — |
| Informational | 10 | — |

Remaining High: **1.1** (plaintext refresh tokens in legacy local store — moot on Railway because `main.py` forces `MCP_ENABLE_OAUTH21=true` + `WORKSPACE_MCP_STATELESS_MODE=true`; downgraded to Informational for the Railway deploy surface).

Remaining Medium, left as explicit trade-offs:
- **2.1** id_token re-decoded without signature verification — already a trusted-TLS value in practice; fix requires cross-cutting change to adopt `verify_oauth2_token` with JWKS caching.
- **2.4** state-less CSRF callback fallback — fix requires flow-wide changes to the state store lookup.
- **2.5** bearer-token → synth-session — fix requires refactoring `oauth21_session_store.py`.
- **4.2** attachment endpoint has no user binding — fix requires adding a user-identity column to attachment metadata and checking it on serve.

Remaining Low (**2.6** lazy expiry, **2.7** issuer revalidation, **5.1** float deps, **6.1** exception-logging idiom) are left as quality-of-life items. Informational findings are unchanged.

## Recommended remaining actions

Before a production deploy:

1. **Decide on 4.2** — the `/attachments/{file_id}` endpoint serves any known UUID for its TTL. Fine for a private single-tenant Railway deploy; hostile for a multi-tenant one. If you plan to share this URL publicly, bind `file_id` to the authenticated user in `AttachmentStorage.save_attachment` and reject mismatched sessions in the route.
2. **Monitor 2.4/2.5** — these only bite under active attack with pending OAuth flows for other users, which is out-of-scope for a small private deployment. Revisit before opening signup to untrusted users.
3. **Medium-term hygiene** — pin direct dependencies with `~=`, replace `logger.error(f"... {e}")` with `logger.exception(...)`, and if you ever run locally in legacy OAuth 2.0 mode, put the plaintext-store path behind an explicit opt-in flag.
