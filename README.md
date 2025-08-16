# Swagger Hunter — API Security Tester
**Author:** w01f

Swagger Hunter is a single-file Python tool to **discover Swagger/OpenAPI** and run **professional-grade API security tests** against systems you own or have written permission to assess.

> ⚠️ Use responsibly. Obtain written permission before testing any non-owned system.
---
> ⚠️ There has some fault positive. Just v1

---

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Options](#options)
- [Reports](#reports)
  - [Main Report](#main-report)
  - [Per-Function Reports](#per-function-reports)
- [Authorized Headers](#authorized-headers)
- [Modes & Safety](#modes--safety)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Changelog](#changelog)

---

## Features
- Broad **Swagger/OpenAPI discovery** across common paths (incl. `/schema/swagger`)
- Lightweight **endpoint enumeration** without swagger (common API paths, `robots.txt`, `sitemap.xml`)
- **Spec analysis:** security schemes, insecure HTTP, risky paths, weak validation
- **Header/cookie hygiene:** HSTS, X-Content-Type-Options, clickjacking, basic CORS checks
- **CORS preflight** test
- **Authorized token/key testing** via `--test-header` (records which header worked; redacts by default)
- **Upload testing:** safe uploads by default; optional aggressive filenames for filter-bypass probing
- **CRUD probes** from spec (GET always; POST/PUT/PATCH/DELETE gated by `--enable-destructive`)
- Extra checks: **TRACE**, **X-HTTP-Method-Override**, **GraphQL introspection**, basic **rate limiting** signal
- **Per-function reports** saved as `out/functions/<urlslug>+<function>.json|.md`
- Consolidated **main report** (JSON + Markdown)

The script prints a startup banner:
```

\===========================================
Swagger Hunter  – API Security Tester
Author: w01f
============

````

---

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install requests PyYAML PyJWT
python swagger_hunter.py --url https://api.example.com --out ./report
````

Authorized header testing:

```bash
python swagger_hunter.py \
  --url https://api.example.com \
  --token-audit \
  --test-header 'Authorization: Bearer eyJhbGciOi...' \
  --test-header 'X-API-Key: abc123' \
  --out ./report
```

Uploads (safe) + CRUD GET from spec:

```bash
python swagger_hunter.py \
  --url https://api.example.com \
  --upload-audit \
  --crud-audit \
  --out ./report
```

Destructive CRUD + aggressive upload names:

```bash
python swagger_hunter.py \
  --url https://api.example.com \
  --crud-audit --enable-destructive \
  --upload-audit --allow-aggressive-upload \
  --out ./report
```

---

## Installation

* Python **3.8+**
* Dependencies:

  ```bash
  pip install requests PyYAML PyJWT
  ```

---

## Usage Examples

CORS + TRACE + rate limit sample:

```bash
python swagger_hunter.py \
  --url https://api.example.com \
  --check-cors --trace-audit --ratelimit-audit \
  --out ./report
```

GraphQL introspection on enumerated `/graphql` endpoints:

```bash
python swagger_hunter.py \
  --url https://example.com \
  --graphql-audit \
  --out ./report
```

List successful auth trials (per-function):

```bash
jq '.worked_auth' ./report/functions/*+token-audit.json
```

---

## Options

```
--url URL                                 Target base URL (required)
--out DIR                                 Output directory (default: ./swaggerhunter-report)
--timeout SECONDS                         HTTP timeout (default: 8.0)
--header "K: V"                           Add base request header (repeatable)
--test-header "K: V"                      Add header for authorized tests (repeatable; recorded per-function)

--aggressive                              Add more spec & endpoint guesses
--wordlist FILE                           Extra paths (one per line, starting with /)
--no-bruteforce                           Skip lightweight endpoint enumeration

--check-cors                              Run CORS preflight checks
--token-audit                             Try each --test-header and record success as worked_auth
--no-redact-secrets                       Do not redact header values in reports
--upload-audit                            Probe file upload endpoints (safe filenames)
--allow-aggressive-upload                 Include bypass-style filenames (e.g., .php, semicolons, traversal)
--crud-audit                              Probe spec-defined CRUD (GET always; others need --enable-destructive)
--enable-destructive                      Allow POST/PUT/PATCH/DELETE in CRUD probes
--trace-audit                             Probe HTTP TRACE
--graphql-audit                           Probe GraphQL introspection on /graphql endpoints
--method-audit                            Probe X-HTTP-Method-Override: DELETE (requires --enable-destructive)
--ratelimit-audit                         Send a small GET burst (8) to sample for 429s
```

---

## Reports

All outputs are placed under `--out` (default `./swaggerhunter-report`).

```
<out>/
  <slug>.json                  Main consolidated JSON report
  <slug>.md                    Markdown summary
  functions/
    <urlslug>+token-audit.json
    <urlslug>+token-audit.md
    <urlslug>+upload-audit.json
    <urlslug>+crud+GET.json
    <urlslug>+trace.json
    <urlslug>+graphql-introspection.json
    ...
```

`urlslug` is a filesystem-safe slug derived from `scheme://host/path`. Per-function filenames use `url+function` format.

### Main Report

Fields:

* `target`, `timestamp`
* `summary` — counts by severity
* `findings[]` — normalized findings (target, title, detail, severity, tags, optional evidence)
* `data` — discovery outputs:

  * `specs` — discovered specs (status, content\_type, spec object)
  * `enum_endpoints` — endpoints observed via lightweight enumeration
  * `spec_findings` — per-spec finding list
  * `upload_candidates` — candidate upload endpoints
* `crud_results[]` — method/url/status from CRUD probes

Example snippet:

```json
{
  "summary": {"Critical":0,"High":2,"Medium":4,"Low":3,"Info":5},
  "crud_results": [
    {"url":"https://api.example.com/items","method":"GET","status":200},
    {"url":"https://api.example.com/items","method":"POST","status":401}
  ]
}
```

### Per-Function Reports

Each function run emits its own JSON/MD file with:

* `url`, `function`, `timestamp`
* `summary` and/or `findings[]` (specific to that function)
* `worked_auth[]` (only for `token-audit`) — which header(s) resulted in a meaningful change
* `evidence` (headers, responses, artifact fetches, etc.)

Token audit example:

```json
{
  "url": "https://api.example.com/users",
  "function": "token-audit",
  "baseline": {"status":401,"length":123},
  "worked_auth": [
    {"status":200,"length":2345,"headers_used":[{"header":"Authorization","value":"<redacted sha256:7a1c3e9dfe2f last6:...>"}]}
  ],
  "findings": [
    {"target":"https://api.example.com/users","title":"Authorized access with provided auth header(s)","detail":"Status changed 401->200 (len 123->2345).","severity":"High","tags":["auth","auth-success"]}
  ]
}
```

---

## Authorized Headers

Pass one header per `--test-header` flag. The tool tries them individually and records success.

* Bearer:

  ```
  --test-header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c...'
  ```
* API keys:

  ```
  --test-header 'X-API-Key: abc123'
  --test-header 'X-Auth-Token: abc123'
  --test-header 'Api-Key: abc123'
  ```

By default, values are redacted in reports; add `--no-redact-secrets` to show raw values.

---

## Modes & Safety

* **Safe by default.** GET probes and safe upload names.
* **Destructive actions** (POST/PUT/PATCH/DELETE, method override) require `--enable-destructive`.
* **Aggressive uploads** (bypass-style names) require `--allow-aggressive-upload`.
* **Aggressive discovery** adds more guess paths with `--aggressive`.

---

## Troubleshooting

* Install deps: `pip install requests PyYAML PyJWT`
* Some hosts block TRACE or method override — that’s expected.
* If output seems sparse, try `--aggressive` and/or provide `--wordlist`.
* To avoid enumeration noise, use `--no-bruteforce`.

---

## FAQ

**Will secrets appear in reports?**
No; header values are redacted by default. Use `--no-redact-secrets` to disable.

**Does it brute-force credentials?**
No. It only tests headers you explicitly supply via `--test-header`.

**Why do some CRUD calls show -1?**
Non-GETs are skipped unless `--enable-destructive` is set.

**Safe vs. aggressive uploads?**
Safe uses benign names; aggressive adds extension/semicolon/traversal tricks.

---

## Changelog

**1.5**

* Per-function reports under `functions/` using `url+function` format
* Records which authorized header worked (`worked_auth`) with optional redaction
* Safe/aggressive upload modes
* Console banner with app and author
* Expanded docs merged into README
