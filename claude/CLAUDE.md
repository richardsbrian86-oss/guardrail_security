# Security standards for everything built here

These are defaults, not suggestions. Deviating is fine when the user asks for it — but say so out loud rather than silently.

## Secrets

- Never hardcode credentials, API keys, tokens, connection strings, or private keys in source. Read them from environment variables or a secret manager.
- Never write real secret values into a file that gets committed. `.env` holds real values and is gitignored; `.env.example` holds placeholder names only.
- New project → `.gitignore` covers `.env*` (except `.env.example`), `*.pem`, `*.key`, `*.pfx`, credential files, and local database files, from the first commit.
- Never log a secret, a full auth header, a session token, or a raw request body that may contain one.

## Input and injection

- Every value that crosses a trust boundary (HTTP request, CLI arg, file, webhook, LLM output, third-party API) is untrusted until validated. Validate shape and bounds at the edge with a schema (zod, pydantic, or equivalent), not with ad-hoc `if` checks scattered downstream.
- SQL: parameterized queries or a query builder/ORM. Never string-concatenate or f-string user input into SQL — not even for a column name or `ORDER BY`; allowlist those against a fixed set.
- Shell: avoid shelling out when a library exists. When unavoidable, pass an argument array — never build a command string from user input, and never `shell=True` / `shell: true` with interpolated values.
- Never `eval`, `exec`, `new Function`, `pickle.loads`, or `yaml.load` (use `yaml.safe_load`) on data you did not produce.
- File paths from user input: resolve, then verify the result stays inside the intended base directory. Reject `..` traversal rather than stripping it.
- Web output: rely on the framework's escaping. No `innerHTML` / `dangerouslySetInnerHTML` / `v-html` with user data; sanitize with a real sanitizer (DOMPurify) if raw HTML is genuinely required.
- Outbound requests to a user-supplied URL are SSRF: allowlist hosts and block private/link-local ranges.

## Authentication and authorization

- Authorization is checked server-side on every request, per resource — not once at login, not in the UI, not by hiding a route.
- The default answer is deny. New endpoints require auth unless explicitly made public.
- Check ownership, not just identity: "is this user logged in" is not "may this user read record 42" (IDOR is the most common real bug in this class).
- Passwords: argon2id or bcrypt, never SHA/MD5, never homegrown. Compare tokens with a constant-time comparison.
- Sessions/cookies: `HttpOnly`, `Secure`, `SameSite=Lax` or stricter. Rotate session IDs on privilege change. Give tokens an expiry.

## Data handling and transport

- HTTPS/TLS everywhere; never disable certificate verification, even "temporarily" in dev.
- Return the minimum data the client needs. Don't send a whole user row because it was convenient to `SELECT *`.
- Errors to the client: a generic message plus a correlation ID. Stack traces, SQL text, and internal paths stay in server logs.
- Encrypt sensitive data at rest; use the platform's crypto library (`libsodium`, `cryptography`, Web Crypto). Never design a cipher or reuse a nonce/IV.
- Use a CSRF token for cookie-authenticated state-changing requests. Set CORS to specific origins — never `*` together with credentials.
- Rate-limit authentication, password reset, and anything expensive or enumerable.

## Dependencies and config

- Prefer the standard library or an already-present dependency over adding a package. Each new dependency is new attack surface — name it and say why when you add one.
- Pin versions and commit the lockfile. Don't add a package whose name merely looks right (typosquatting); verify it's the real one.
- Production config comes from the environment, never from defaults baked into code. No debug mode, verbose errors, default credentials, or wide-open ports in anything deployable.
- Security headers on web apps: CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, HSTS.

## While working

- When you spot an existing vulnerability in code you're touching, flag it even if fixing it wasn't the task.
- Don't disable a security control (a check, a lint rule, a type, cert verification) to make something pass. Fix the cause or say you're blocked.
- Uploaded or user-named files: validate type by content, cap size, store outside the webroot, never execute.
- Write a test for the security-relevant path (rejected input, denied access), not only the happy path.
