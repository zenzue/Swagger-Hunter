#!/usr/bin/env python3
from __future__ import annotations
import argparse, concurrent.futures, contextlib, hashlib, io, json, os, re, sys, time, urllib.parse
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple, Set
try:
    import yaml
except Exception:
    yaml = None
try:
    import requests
    from requests.exceptions import RequestException
except Exception:
    print("pip install requests", file=sys.stderr); sys.exit(2)
try:
    import jwt
except Exception:
    jwt = None
requests.packages.urllib3.disable_warnings()
@dataclass
class Finding:
    target: str
    title: str
    detail: str
    severity: str
    cvss_like: Optional[float] = None
    tags: Optional[List[str]] = None
    evidence: Optional[Dict[str, Any]] = None
    def key(self) -> Tuple[str, str]:
        return (self.target, self.title)
SEVERITIES = ["Critical","High","Medium","Low","Info"]
USER_AGENT = "SwaggerHunter/1.5 (author: w01f)"
DEFAULT_TIMEOUT = 8.0
SPEC_CANDIDATES = [
    "/openapi.json","/openapi.yaml","/openapi.yml","/.well-known/openapi.json",
    "/v3/api-docs","/v3/api-docs/swagger-config","/v2/api-docs",
    "/swagger.json","/swagger.yaml","/swagger/v1/swagger.json","/swagger/v2/swagger.json",
    "/api-docs","/swagger-ui.html","/swagger-ui/index.html","/swagger/index.html",
    "/docs","/redoc","/api/docs","/api/documentation","/swagger","/swagger/ui",
    "/schema/","/schema/json","/schema/openapi","/schema/openapi.json","/schema/openapi.yaml","/schema/swagger","/schema/swagger.json",
    "/swagger/docs/v1","/swagger/docs/2.0","/swagger/doc.json",
    "/openapi","/openapi/v1.json","/openapi/v2.json","/openapi/v3.json",
    "/api/swagger","/api/swagger.json","/api/spec","/docs/swagger.json","/redoc/index.html","/swagger-ui"
]
API_GUESS_PATHS = [
    "/api","/api/v1","/api/v2","/api/v3","/rest","/graphql",
    "/health","/healthz","/livez","/readyz","/metrics",
    "/admin","/actuator","/actuator/health","/actuator/info",
    "/version","/status","/users","/auth","/auth/login","/auth/token","/auth/refresh",
    "/orders","/products","/search","/schema/swagger"
]
UPLOAD_HINT_WORDS = ["upload","file","files","media","image","images","avatar","photo","attachment","attachments","document","documents","content"]
APIKEY_HEADER_CANDIDATES = ["X-API-Key","X-Api-Key","X-Auth-Token","X-Access-Token","X-Token","Api-Key","Authorization"]
def normalize_url(u: str) -> str:
    u = u.strip()
    if not u: return u
    if not re.match(r"^https?://", u, re.I): u = f"https://{u}"
    p = urllib.parse.urlsplit(u)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))
def join_url(base: str, path: str) -> str:
    return urllib.parse.urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))
def safe_json(text: str) -> Optional[Dict[str, Any]]:
    try: return json.loads(text)
    except Exception: return None
def try_yaml(text: str) -> Optional[Dict[str, Any]]:
    if not yaml: return None
    try:
        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict): return loaded
    except Exception: return None
    return None
def request(method: str, url: str, headers: Dict[str, str], timeout: float, allow_redirects=True, data=None, files=None):
    try:
        return requests.request(method, url, headers=headers, timeout=timeout, verify=False, allow_redirects=allow_redirects, data=data, files=files)
    except RequestException as e:
        return e
def ok_status(code: int) -> bool:
    return 200 <= code < 400
def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()
def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()
def looks_like_spec(text: str, content_type: str = "") -> bool:
    if "json" in (content_type or "").lower():
        js = safe_json(text)
        if isinstance(js, dict) and ("openapi" in js or "swagger" in js) and "paths" in js: return True
    if yaml:
        y = try_yaml(text)
        if isinstance(y, dict) and ("openapi" in y or "swagger" in y) and "paths" in y: return True
    if "<title>Swagger UI" in text or "SwaggerUIBundle" in text or "window.ui" in text: return True
    return False
def extract_spec(text: str, content_type: str = "") -> Optional[Dict[str, Any]]:
    if "json" in (content_type or "").lower():
        js = safe_json(text)
        if isinstance(js, dict) and ("openapi" in js or "swagger" in js): return js
    y = try_yaml(text) if yaml else None
    if isinstance(y, dict) and ("openapi" in y or "swagger" in y): return y
    return None
def redact_secret(val: str, no_redact: bool) -> str:
    if no_redact: return val
    val = str(val)
    return f"<redacted sha256:{sha256_str(val)[:12]} last6:{val[-6:] if len(val)>=6 else val}>"
def url_slug(u: str) -> str:
    p = urllib.parse.urlsplit(u)
    base = (p.netloc + p.path).strip("/")
    base = re.sub(r"[^a-zA-Z0-9]+","-", base).strip("-")
    return base or "root"
class Reporter:
    def __init__(self, outdir: str, target_root: str):
        self.outdir = outdir
        self.target_root = target_root
        os.makedirs(outdir, exist_ok=True)
        os.makedirs(os.path.join(outdir, "functions"), exist_ok=True)
    def write_function_report(self, url: str, function_name: str, payload: Dict[str, Any]):
        slug = f"{url_slug(url)}+{function_name}"
        jpath = os.path.join(self.outdir, "functions", f"{slug}.json")
        mpath = os.path.join(self.outdir, "functions", f"{slug}.md")
        payload = dict(payload or {})
        payload["url"] = url
        payload["function"] = function_name
        payload["timestamp"] = int(time.time())
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        with open(mpath, "w", encoding="utf-8") as f:
            f.write(f"# Function Report: {function_name}\n\n")
            f.write(f"- URL: `{url}`\n- Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload['timestamp']))}\n\n")
            if "summary" in payload:
                f.write("## Summary\n")
                for k, v in payload["summary"].items():
                    f.write(f"- **{k}:** {v}\n")
                f.write("\n")
            if "findings" in payload and payload["findings"]:
                f.write("## Findings\n")
                for fd in payload["findings"]:
                    tags = f" ({', '.join(fd.get('tags') or [])})" if fd.get("tags") else ""
                    f.write(f"- **{fd.get('severity','?')}**: {fd.get('title','?')}{tags}\n")
            if "evidence" in payload:
                f.write("\n## Evidence\n")
                f.write("```json\n")
                try:
                    f.write(json.dumps(payload["evidence"], indent=2)[:8000])
                except Exception:
                    f.write(str(payload["evidence"])[:8000])
                f.write("\n```\n")
        print(f"[+] per-function report -> {jpath}")
    def write_main(self, data: Dict[str, Any], findings: List[Finding], crud_results: List[Dict[str,Any]]):
        slug = re.sub(r"[^a-z0-9]+","-", urllib.parse.urlsplit(self.target_root).netloc.lower()).strip("-") or "report"
        jpath = os.path.join(self.outdir, f"{slug}.json")
        with open(jpath,"w",encoding="utf-8") as f:
            json.dump({"target": self.target_root,"timestamp": int(time.time()),
                       "summary": summarize_risk(findings),
                       "findings": [asdict(x) for x in findings],
                       "data": data,"crud_results": crud_results}, f, indent=2)
        mpath = os.path.join(self.outdir, f"{slug}.md")
        with open(mpath,"w",encoding="utf-8") as f:
            f.write(f"# Swagger Hunter Report\n\n**Target:** {self.target_root}\n\n")
            counts = summarize_risk(findings)
            f.write("## Risk Summary\n\n")
            for s in SEVERITIES: f.write(f"- **{s}:** {counts.get(s,0)}\n")
            f.write("\n## Findings\n\n")
            if not findings: f.write("_No findings._\n")
            else:
                for fd in findings:
                    tags = f" ({', '.join(fd.tags)})" if fd.tags else ""
                    f.write(f"### {fd.severity}: {fd.title}{tags}\n- Target: `{fd.target}`\n- Detail: {fd.detail}\n")
                    if fd.evidence:
                        f.write(f"- Evidence:\n")
                        for k, v in list(fd.evidence.items())[:20]: f.write(f"  - **{k}:** {json.dumps(v)[:800]}\n")
                    f.write("\n")
            if data.get("specs"):
                f.write("## Discovered Specs\n")
                for u, info in data["specs"].items(): f.write(f"- {u} — {info.get('content_type','?')} (HTTP {info.get('status')})\n")
            if data.get("enum_endpoints"):
                f.write("\n## Enumerated Endpoints (no swagger)\n")
                for u, info in data["enum_endpoints"].items(): f.write(f"- {u} — HTTP {info.get('status')}\n")
            if data.get("upload_candidates"):
                f.write("\n## Upload Candidates\n")
                for u in data["upload_candidates"]: f.write(f"- {u}\n")
            if crud_results:
                f.write("\n## CRUD Probe Results\n")
                for r in crud_results: f.write(f"- {r['method']} {r['url']} → {r['status']}\n")
            f.write("\n---\nGenerated by Swagger Hunter (author: w01f).\n")
        print(f"[+] Reports saved:\n    - {jpath}\n    - {mpath}")
def analyze_spec(url: str, spec: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    is_v3 = "openapi" in spec
    if is_v3:
        servers = spec.get("servers", [])
        if isinstance(servers, list):
            for s in servers:
                u = (s or {}).get("url", "")
                if isinstance(u, str) and u:
                    with contextlib.suppress(Exception):
                        if urllib.parse.urlsplit(u).scheme == "http":
                            out.append(Finding(url,"Non-HTTPS server in OpenAPI servers[]",f"Server '{u}' uses HTTP.","High",tags=["transport"]))
                if isinstance(s, dict) and "variables" in s:
                    out.append(Finding(url,"Server variables used","Ensure defaults enforce HTTPS and trusted hosts.","Info",tags=["configuration"]))
    else:
        schemes = spec.get("schemes", [])
        if isinstance(schemes, list) and "http" in [str(x).lower() for x in schemes]:
            out.append(Finding(url,"Swagger v2 allows HTTP scheme",f"schemes={schemes}","High",tags=["transport"]))
    sec_schemes = None
    if is_v3:
        comp = spec.get("components", {})
        sec_schemes = comp.get("securitySchemes", {})
        if not spec.get("security") and not any((spec.get("paths", {}) or {}).get(p, {}).get(m, {}).get("security") for p in (spec.get("paths", {}) or {}) for m in (spec.get("paths", {}) or {}).get(p, {})):
            out.append(Finding(url,"No security requirements defined","OpenAPI lacks global/operation-level 'security'.","High",tags=["auth"]))
    else:
        sec_def = spec.get("securityDefinitions", {})
        sec_schemes = sec_def
        if not spec.get("security") and not any((spec.get("paths", {}) or {}).get(p, {}).get(m, {}).get("security") for p in (spec.get("paths", {}) or {}) for m in (spec.get("paths", {}) or {}).get(p, {})):
            out.append(Finding(url,"No security requirements defined","Swagger v2 lacks global/operation-level 'security'.","High",tags=["auth"]))
    if isinstance(sec_schemes, dict) and sec_schemes:
        for name, sch in sec_schemes.items():
            t = (sch or {}).get("type")
            if t == "http" and (sch.get("scheme") == "basic"):
                out.append(Finding(url,"HTTP Basic authentication in use",f"securitySchemes.{name} uses Basic auth.","Medium",tags=["auth"]))
            if t == "apiKey":
                in_ = (sch.get("in") or "").lower()
                if in_ == "query":
                    out.append(Finding(url,"API key in query",f"securitySchemes.{name} passes API key via query parameter.","Medium",tags=["auth"]))
            if t == "oauth2":
                flows = sch.get("flows") or {}
                if "implicit" in flows:
                    out.append(Finding(url,"OAuth2 implicit flow present","Implicit flow is generally discouraged.","Low",tags=["auth"]))
    else:
        out.append(Finding(url,"No security schemes declared","No securitySchemes/securityDefinitions present.","Medium",tags=["auth"]))
    risky = ["/admin","/metrics","/actuator","/actuator/health","/graphql","/debug"]
    for p in (spec.get("paths", {}) or {}):
        if any(p.lower().startswith(r) for r in risky):
            ops = list((spec["paths"].get(p) or {}).keys())
            unprotected = False
            for m in ops:
                op = (spec["paths"].get(p) or {}).get(m) or {}
                if not op.get("security") and not spec.get("security"): unprotected = True
            if unprotected:
                out.append(Finding(url,"Potentially sensitive endpoint without security",f"Path '{p}' appears sensitive and lacks operation-level security.","High",tags=["exposure"]))
    for pth, methods in (spec.get("paths", {}) or {}).items():
        if not isinstance(methods, dict): continue
        for method, op in methods.items():
            if method.lower() not in ("get","post","put","patch","delete","options","head","trace"): continue
            params = []
            if isinstance(op, dict):
                params = (op.get("parameters") or [])
                if "requestBody" in op and isinstance(op["requestBody"], dict):
                    content = (op["requestBody"].get("content") or {})
                    for _, media in content.items():
                        schema = (media or {}).get("schema") or {}
                        if schema and not any(k in schema for k in ("maxLength","minLength","maximum","minimum","pattern","enum")):
                            out.append(Finding(url,"Request body lacks explicit constraints",f"{method.upper()} {pth} requestBody lacks bounds/pattern/enum.","Low",tags=["validation"]))
            for prm in params:
                if not isinstance(prm, dict): continue
                name = prm.get("name","?")
                schema = prm.get("schema") or {}
                if schema and not any(k in schema for k in ("maxLength","minLength","maximum","minimum","pattern","enum")):
                    out.append(Finding(url,"Parameter lacks explicit constraints",f"{method.upper()} {pth} parameter '{name}' has no bounds/pattern/enum.","Low",tags=["validation"]))
    pii_tokens = re.compile(r"(ssn|social[-_ ]?security|nid|passport|credit[_-]?card|cvv|cvc|iban|swift|tax|dob|birth|email|phone|address|geo)", re.I)
    def traverse(name: str, node: Any):
        if isinstance(node, dict):
            for k, v in node.items():
                field = f"{name}.{k}" if name else k
                if pii_tokens.search(k or ""): out.append(Finding(url,"Potential PII field in schema",f"{field}","Info",tags=["pii"]))
                traverse(field, v)
        elif isinstance(node, list):
            for i, v in enumerate(node): traverse(f"{name}[{i}]", v)
    comps = (spec.get("components", {}) or {}).get("schemas") if is_v3 else (spec.get("definitions") or {})
    if isinstance(comps, dict): traverse("schema", comps)
    return dedupe_findings(out)
def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    seen: Set[Tuple[str, str]] = set(); out: List[Finding] = []
    for f in findings:
        k = f.key()
        if k not in seen: out.append(f); seen.add(k)
    return out
def enumerate_without_swagger(base: str, headers: Dict[str, str], timeout: float, guesses: List[str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for path in guesses:
        url = join_url(base, path)
        resp = request("HEAD", url, headers, timeout)
        code = None; hdrs = {}
        if isinstance(resp, requests.Response):
            code = resp.status_code; hdrs = dict(resp.headers)
            if code in (405, 400, 500, None):
                resp2 = request("GET", url, headers, timeout, allow_redirects=False)
                if isinstance(resp2, requests.Response):
                    code = resp2.status_code; hdrs = dict(resp2.headers)
        results[url] = {"status": code, "headers": hdrs}
    return results
def check_cors_preflight(url: str, headers: Dict[str, str], timeout: float) -> Optional[Dict[str, str]]:
    test_headers = {"Origin":"https://example.com","Access-Control-Request-Method":"GET","Access-Control-Request-Headers":"Authorization,Content-Type",**headers}
    resp = request("OPTIONS", url, test_headers, timeout)
    if isinstance(resp, requests.Response): return {k: v for k, v in resp.headers.items() if k.lower().startswith("access-control-")}
    return None
def assess_headers(u: str, hdrs: Dict[str, str]) -> List[Finding]:
    f: List[Finding] = []; h = {k.lower(): v for k, v in hdrs.items()}
    if "strict-transport-security" not in h: f.append(Finding(u,"Missing HSTS","No Strict-Transport-Security header over HTTPS.","Low",tags=["headers"]))
    if "x-content-type-options" not in h: f.append(Finding(u,"Missing X-Content-Type-Options","No 'nosniff'.","Low",tags=["headers"]))
    if "x-frame-options" not in h and "content-security-policy" not in h: f.append(Finding(u,"Missing clickjacking protection","No X-Frame-Options or CSP frame-ancestors.","Low",tags=["headers"]))
    aco = h.get("access-control-allow-origin",""); acc = h.get("access-control-allow-credentials","")
    if aco == "*" and acc and acc.lower() == "true": f.append(Finding(u,"CORS misconfiguration","ACA-Origin='*' with credentials allowed.","High",tags=["cors"]))
    if "set-cookie" in h:
        sc = h["set-cookie"]
        if "samesite" not in sc.lower(): f.append(Finding(u,"Cookies missing SameSite","Session cookies may be vulnerable to CSRF.","Low",tags=["cookies"]))
    return f
def fetch_text(url: str, headers: Dict[str, str], timeout: float) -> Optional[str]:
    r = request("GET", url, headers, timeout)
    if isinstance(r, requests.Response) and ok_status(r.status_code):
        ct = r.headers.get("Content-Type","")
        if "text" in ct or "json" in ct or "yaml" in ct or "xml" in ct or ct == "": return r.text
    return None
def parse_robots_for_paths(txt: str) -> List[str]:
    paths: List[str] = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("user-agent") or line.lower().startswith("#"): continue
        if line.lower().startswith(("allow:","disallow:")):
            p = line.split(":",1)[1].strip()
            if p and p.startswith("/"): paths.append(p)
    return paths[:200]
def parse_sitemap_for_paths(xml: str) -> List[str]:
    locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", xml, flags=re.I); out: List[str] = []
    for u in locs:
        try:
            p = urllib.parse.urlsplit(u).path
            if p: out.append(p)
        except Exception: pass
    return list(dict.fromkeys(out))[:500]
def find_specs(base: str, headers: Dict[str, str], timeout: float, candidates: List[str]) -> Dict[str, Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(candidates) or 1)) as ex:
        futs = {}
        for path in candidates:
            url = join_url(base, path)
            futs[ex.submit(request,"GET",url,headers,timeout)] = url
        for fut in concurrent.futures.as_completed(futs):
            url = futs[fut]; resp = fut.result()
            if isinstance(resp, requests.Response) and ok_status(resp.status_code):
                ct = resp.headers.get("Content-Type",""); text = resp.text or ""
                if looks_like_spec(text, ct):
                    spec = extract_spec(text, ct)
                    found[url] = {"status": resp.status_code,"content_type": ct,"spec": spec,"raw": text[:20000]}
    return found
def crawl_home_for_swagger(base: str, headers: Dict[str, str], timeout: float) -> List[str]:
    urls: List[str] = []
    home = request("GET", base, headers, timeout)
    if isinstance(home, requests.Response) and ok_status(home.status_code):
        text = home.text or ""
        for m in re.findall(r'href=["\']([^"\']+)["\']', text, flags=re.I):
            if any(x in m for x in ("swagger","api-doc","openapi","redoc")): urls.append(urllib.parse.urljoin(base, m))
        for m in re.findall(r'src=["\']([^"\']+)["\']', text, flags=re.I):
            if any(x in m for x in ("swagger","api-doc","openapi","redoc")): urls.append(urllib.parse.urljoin(base, m))
        for m in re.findall(r'url:\s*["\']([^"\']+)["\']', text, flags=re.I):
            urls.append(urllib.parse.urljoin(base, m))
    return list(dict.fromkeys(urls))
def summarize_risk(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts: counts[f.severity] += 1
    return counts
def auth_requirement_baseline(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, int]:
    r = request("GET", url, headers, timeout, allow_redirects=False)
    if isinstance(r, requests.Response):
        clen = int(r.headers.get("Content-Length","0")) if r.headers.get("Content-Length") else len(r.content or b"")
        return (r.status_code, clen)
    return (0,0)
def try_with_headers(url: str, base_headers: Dict[str, str], test_headers: Dict[str, str], timeout: float) -> Tuple[int, int, Dict[str,str]]:
    all_headers = dict(base_headers); all_headers.update(test_headers)
    r = request("GET", url, all_headers, timeout, allow_redirects=False)
    if isinstance(r, requests.Response):
        clen = int(r.headers.get("Content-Length","0")) if r.headers.get("Content-Length") else len(r.content or b"")
        return (r.status_code, clen, dict(r.headers))
    return (0,0,{})
def meaningful_gain(base_status: int, base_len: int, new_status: int, new_len: int) -> bool:
    if base_status in (401,403) and 200 <= new_status < 300: return True
    if base_status in (404,) and 200 <= new_status < 300: return True
    if (new_status < base_status) and new_len > int(base_len * 1.5): return True
    return False
def token_audit_endpoint(url: str, base_headers: Dict[str,str], timeout: float, test_headers_list: List[Dict[str,str]], no_redact: bool) -> Dict[str, Any]:
    findings: List[Finding] = []
    successes: List[Dict[str, Any]] = []
    base_status, base_len = auth_requirement_baseline(url, base_headers, timeout)
    if base_status in (401,403):
        findings.append(Finding(url,"Endpoint requires authentication",f"Baseline response {base_status}.","Info",tags=["auth"]))
    elif base_status in (200,201,204):
        findings.append(Finding(url,"Endpoint appears accessible without token",f"Baseline response {base_status}.","Medium",tags=["auth","exposure"]))
    for hdrs in (test_headers_list or []):
        st, ln, _ = try_with_headers(url, base_headers, hdrs, timeout)
        if meaningful_gain(base_status, base_len, st, ln):
            desc = []
            for k, v in hdrs.items():
                desc.append({"header": k, "value": redact_secret(v, no_redact)})
            successes.append({"status": st, "length": ln, "headers_used": desc})
            findings.append(Finding(url,"Authorized access with provided auth header(s)",f"Status changed {base_status}->{st} (len {base_len}->{ln}).","High",tags=["auth","auth-success"],evidence={"headers_used": desc}))
            break
    return {"baseline": {"status": base_status, "length": base_len},"findings": [asdict(x) for x in findings],"worked_auth": successes}
def looks_like_file_schema(schema: Dict[str, Any]) -> bool:
    if not isinstance(schema, dict): return False
    if schema.get("type") == "string" and str(schema.get("format","")).lower() in ("binary","base64"): return True
    if "properties" in schema and isinstance(schema["properties"], dict):
        for v in schema["properties"].values():
            if looks_like_file_schema(v): return True
    return False
def spec_upload_candidates(base: str, spec: Dict[str, Any]) -> List[str]:
    cand: List[str] = []
    paths = (spec.get("paths") or {})
    for pth, methods in paths.items():
        if not isinstance(methods, dict): continue
        for method, op in methods.items():
            if method.lower() not in ("post","put","patch"): continue
            rb = (op or {}).get("requestBody"); is_upload = False
            if isinstance(rb, dict):
                content = (rb.get("content") or {})
                for ctype in content.keys():
                    if "multipart/form-data" in ctype.lower(): is_upload = True
                    schema = (content[ctype] or {}).get("schema") or {}
                    if looks_like_file_schema(schema): is_upload = True
            params = (op or {}).get("parameters") or []
            for prm in params:
                if isinstance(prm, dict):
                    if prm.get("in") == "formData" and (prm.get("type") in ("file","string")): is_upload = True
            if is_upload: cand.append(join_url(base, pth))
    return list(dict.fromkeys(cand))
def extract_urls_from_response(r: requests.Response) -> List[str]:
    urls: List[str] = []
    loc = r.headers.get("Location")
    if loc: urls.append(loc)
    txt = r.text or ""
    js = safe_json(txt) or {}
    if isinstance(js, dict):
        for k in ("url","file","file_url","path","location","href","link","download_url"):
            v = js.get(k)
            if isinstance(v, str) and v: urls.append(v)
        for k, v in js.items():
            if isinstance(v, dict):
                for kk in ("url","downloadUrl","href"):
                    vv = v.get(kk)
                    if isinstance(vv, str) and vv: urls.append(vv)
    urls += re.findall(r"https?://[^\s\"'>)]+", txt)
    return list(dict.fromkeys(urls))[:5]
def fetch_and_verify_uploaded(url: str, base_headers: Dict[str,str], timeout: float, expected_hash: str) -> Optional[Dict[str, Any]]:
    try:
        r = request("GET", url, base_headers, timeout, allow_redirects=True)
        if isinstance(r, requests.Response) and r.status_code in range(200,400):
            body = r.content or b""; h = sha256_bytes(body); preview = body[:1024]
            return {"url": url,"status": r.status_code,"hash": h,"content_type": r.headers.get("Content-Type",""),"body_preview_hex": preview.hex(),"body_preview_len": len(preview)}
    except Exception: pass
    return None
def make_test_files(safe_only: bool = True) -> List[Tuple[str, str, bytes]]:
    payload_txt = b"swagger-hunter upload probe\n"
    payload_jpg = b"\xFF\xD8\xFF\xDB\x00\x43JPEGTEST"
    if safe_only:
        return [("test.txt","text/plain",payload_txt),("test.jpg","image/jpeg",payload_jpg)]
    else:
        return [("test.txt","text/plain",payload_txt),("test.jpg","image/jpeg",payload_jpg),("test.jpg.php","image/jpeg",payload_jpg),("test.jpg;.php","image/jpeg",payload_jpg),("..%2f..%2fpoct.txt","text/plain",payload_txt)]
def upload_audit_endpoint(url: str, base_headers: Dict[str,str], timeout: float, allow_aggressive: bool) -> Dict[str, Any]:
    findings: List[Finding] = []
    evidence_all: List[Dict[str, Any]] = []
    for method in ("POST","PUT"):
        filesets = make_test_files(safe_only=not allow_aggressive)
        for fname, ctype, body in filesets:
            files = {"file": (fname, io.BytesIO(body), ctype)}
            r = request(method, url, base_headers, timeout, allow_redirects=False, files=files)
            if not isinstance(r, requests.Response):
                continue
            status = r.status_code
            ev: Dict[str, Any] = {"method": method,"request_filename": fname,"request_content_type": ctype,"upload_response_status": status,"response_headers": dict(r.headers),"response_body_snippet": (r.text or "")[:500],"request_hash": sha256_bytes(body)}
            urls = extract_urls_from_response(r)
            ev["returned_urls"] = urls
            fetched: List[Dict[str, Any]] = []
            for link in urls:
                try_url = urllib.parse.urljoin(url, link) if not link.lower().startswith("http") else link
                fv = fetch_and_verify_uploaded(try_url, base_headers, timeout, ev["request_hash"])
                if fv: fetched.append(fv)
            ev["fetched_artifacts"] = fetched
            evidence_all.append(ev)
            if status in (200,201,202,204):
                findings.append(Finding(url,"File upload accepted",f"{method} accepted '{fname}' ({ctype}).","Medium",tags=["upload"],evidence={"urls": urls}))
                break
    return {"findings": [asdict(x) for x in findings], "evidence": evidence_all}
def generate_sample(schema: Any) -> Any:
    if not isinstance(schema, dict): return {}
    t = (schema.get("type") or "").lower()
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]: return schema["enum"][0]
    if t == "string":
        fmt = (schema.get("format") or "").lower()
        if fmt in ("date-time","datetime"): return "2025-01-01T00:00:00Z"
        if fmt == "date": return "2025-01-01"
        if fmt == "email": return "test@example.com"
        if fmt == "uuid": return "00000000-0000-0000-0000-000000000000"
        return "test"
    if t in ("integer","number"): return 1
    if t == "boolean": return True
    if t == "array":
        item = generate_sample(schema.get("items") or {})
        return [item]
    if t == "object" or "properties" in schema:
        out = {}
        props = schema.get("properties") or {}
        for k, v in props.items():
            out[k] = generate_sample(v or {})
        return out or {"id":1}
    return {"id":1}
def spec_crud_candidates(base: str, spec: Dict[str, Any]) -> List[Tuple[str,str,Optional[Dict[str,Any]]]]:
    out: List[Tuple[str,str,Optional[Dict[str,Any]]]] = []
    paths = (spec.get("paths") or {})
    for pth, methods in paths.items():
        if not isinstance(methods, dict): continue
        for method, op in methods.items():
            ml = method.lower()
            if ml not in ("get","post","put","patch","delete"): continue
            url = join_url(base, pth)
            body_schema = None
            rb = (op or {}).get("requestBody")
            if isinstance(rb, dict):
                content = (rb.get("content") or {})
                app_json = None
                for k, v in content.items():
                    if "application/json" in k.lower(): app_json = v
                if not app_json and content: app_json = list(content.values())[0]
                if app_json: body_schema = (app_json or {}).get("schema") or {}
            params = (op or {}).get("parameters") or []
            if not body_schema and params:
                for prm in params:
                    if isinstance(prm, dict) and prm.get("in") == "body":
                        body_schema = prm.get("schema") or {}
                        break
            out.append((url, ml, body_schema))
    return out
def crud_call(url: str, method: str, headers: Dict[str,str], timeout: float, body_schema: Optional[Dict[str,Any]], allow_destructive: bool) -> Tuple[str,str,int]:
    try:
        if method == "get":
            r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            return (url,"GET", r.status_code if isinstance(r, requests.Response) else 0)
        if not allow_destructive: return (url,method.upper(), -1)
        if method in ("post","put","patch"):
            data = None; hdrs = dict(headers)
            if body_schema:
                data = json.dumps(generate_sample(body_schema)); hdrs["Content-Type"] = "application/json"
            r = requests.request(method.upper(), url, headers=hdrs, data=data, timeout=timeout, verify=False, allow_redirects=False)
            return (url,method.upper(), r.status_code if isinstance(r, requests.Response) else 0)
        if method == "delete":
            r = requests.delete(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            return (url,"DELETE", r.status_code if isinstance(r, requests.Response) else 0)
    except Exception:
        return (url, method.upper(), 0)
    return (url,method.upper(), -1)
def crud_audit(base_headers: Dict[str,str], timeout: float, spec_list: List[Dict[str,Any]], allow_destructive: bool) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    for sp in spec_list:
        cand = spec_crud_candidates(sp["base"], sp["spec"])
        for url, method, schema in cand:
            u,m,code = crud_call(url, method, base_headers, timeout, schema, allow_destructive)
            results.append({"url": u,"method": m,"status": code})
    return results
def method_override_audit(url: str, headers: Dict[str,str], timeout: float) -> Optional[Finding]:
    r = request("POST", url, {**headers, "X-HTTP-Method-Override":"DELETE"}, timeout, allow_redirects=False, data="{}")
    if isinstance(r, requests.Response) and r.status_code in (200,202,204):
        return Finding(url,"HTTP method override accepted",f"POST with X-HTTP-Method-Override: DELETE returned {r.status_code}.","High",tags=["method-override"])
    return None
def trace_audit(url: str, headers: Dict[str,str], timeout: float) -> Optional[Finding]:
    try:
        r = requests.request("TRACE", url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        if isinstance(r, requests.Response) and r.status_code in (200, 202):
            return Finding(url,"HTTP TRACE enabled",f"TRACE {r.status_code}.","Low",tags=["trace"])
    except Exception:
        return None
    return None
def graphql_introspection_audit(url: str, headers: Dict[str,str], timeout: float) -> Optional[Finding]:
    q = {"query":"query IntrospectionQuery { __schema { queryType { name } } }"}
    try:
        r = requests.post(url, headers={**headers, "Content-Type":"application/json"}, data=json.dumps(q), timeout=timeout, verify=False, allow_redirects=True)
        if isinstance(r, requests.Response) and 200 <= r.status_code < 300 and "__schema" in (r.text or ""):
            return Finding(url,"GraphQL introspection enabled",f"POST {url} returned {r.status_code} with __schema.","Medium",tags=["graphql"])
    except Exception:
        return None
    return None
def ratelimit_audit(url: str, headers: Dict[str,str], timeout: float, burst: int = 8) -> Optional[Finding]:
    codes = []
    for _ in range(burst):
        r = request("GET", url, headers, timeout, allow_redirects=False)
        if isinstance(r, requests.Response): codes.append(r.status_code)
        time.sleep(0.05)
    if any(c == 429 for c in codes): return None
    return Finding(url,"No visible rate limiting",f"{burst} rapid GETs without 429.","Info",tags=["rate-limit"])
def emit_per_function(reporter: Reporter, url: str, func_name: str, payload: Dict[str, Any]):
    reporter.write_function_report(url, func_name, payload or {})
def main():
    ap = argparse.ArgumentParser(description="Swagger/OpenAPI Finder + API Security Tester — author: w01f")
    ap.add_argument("--url", required=True)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--test-header", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--out", default="./swaggerhunter-report")
    ap.add_argument("--no-bruteforce", action="store_true")
    ap.add_argument("--aggressive", action="store_true")
    ap.add_argument("--wordlist")
    ap.add_argument("--check-cors", action="store_true")
    ap.add_argument("--token-audit", action="store_true")
    ap.add_argument("--upload-audit", action="store_true")
    ap.add_argument("--allow-aggressive-upload", action="store_true")
    ap.add_argument("--crud-audit", action="store_true")
    ap.add_argument("--enable-destructive", action="store_true")
    ap.add_argument("--trace-audit", action="store_true")
    ap.add_argument("--graphql-audit", action="store_true")
    ap.add_argument("--method-audit", action="store_true")
    ap.add_argument("--ratelimit-audit", action="store_true")
    ap.add_argument("--no-redact-secrets", action="store_true")
    args = ap.parse_args()
    print("===========================================")
    print("  Swagger Hunter  – API Security Tester")
    print("  Author: w01f")
    print("===========================================")
    base = normalize_url(args.url)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":",1); headers[k.strip()] = v.strip()
    test_headers_list: List[Dict[str,str]] = []
    for h in args.test_header:
        if ":" in h:
            k, v = h.split(":",1)
            test_headers_list.append({k.strip(): v.strip()})
    spec_candidates = list(SPEC_CANDIDATES); guess_paths = list(API_GUESS_PATHS)
    if args.aggressive:
        spec_candidates += ["/swagger-resources","/swagger-resources/configuration/ui","/swagger-resources/configuration/security","/_meta/openapi.json","/internal/api-docs","/api/v1/openapi.json","/api/v2/openapi.json"]
        guess_paths += ["/admin/health","/system/health","/internal/health","/.well-known/security.txt","/.well-known/ai-plugin.json"]
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist,"r",encoding="utf-8",errors="ignore") as wl:
            extra = [ln.strip() for ln in wl if ln.strip() and ln.strip().startswith("/")]
            spec_candidates += extra[:800]; guess_paths += extra[:1500]
    print(f"[*] Probing for Swagger/OpenAPI at {base} ...")
    specs = find_specs(base, headers, args.timeout, list(dict.fromkeys(spec_candidates)))
    hints = crawl_home_for_swagger(base, headers, args.timeout)
    for u in hints:
        resp = request("GET", u, headers, args.timeout)
        if isinstance(resp, requests.Response) and ok_status(resp.status_code):
            if looks_like_spec(resp.text, resp.headers.get("Content-Type","")):
                spec = extract_spec(resp.text, resp.headers.get("Content-Type",""))
                specs[u] = {"status": resp.status_code,"content_type": resp.headers.get("Content-Type",""),"spec": spec,"raw": resp.text[:20000]}
    findings: List[Finding] = []; spec_findings: Dict[str, List[Finding]] = {}
    for u, info in specs.items():
        sp = info.get("spec")
        if isinstance(sp, dict):
            fs = analyze_spec(u, sp); spec_findings[u] = fs; findings.extend(fs)
        else:
            findings.append(Finding(u,"Swagger UI exposed","Swagger UI page is reachable; ensure it does not expose private APIs.","Info",tags=["exposure"]))
    print("[*] Enumerating API endpoints without swagger (lightweight) ...")
    robots = fetch_text(join_url(base,"/robots.txt"), headers, args.timeout)
    if robots:
        rb_paths = parse_robots_for_paths(robots)
        if rb_paths:
            print(f"    [+] robots.txt contributed {len(rb_paths)} paths"); guess_paths = list(dict.fromkeys(guess_paths + rb_paths))
    sitemap = fetch_text(join_url(base,"/sitemap.xml"), headers, args.timeout)
    if sitemap and "<urlset" in sitemap:
        sm_paths = parse_sitemap_for_paths(sitemap)
        if sm_paths:
            print(f"    [+] sitemap.xml contributed {len(sm_paths)} paths"); guess_paths = list(dict.fromkeys(guess_paths + sm_paths))
    enum_targets: Dict[str, Dict[str, Any]] = {}
    if not args.no_bruteforce:
        enum_targets = enumerate_without_swagger(base, headers, args.timeout, guess_paths)
        for u, info in enum_targets.items():
            code = info.get("status"); hdrs = info.get("headers") or {}
            if code and 200 <= code < 500: findings.extend(assess_headers(u, hdrs))
    reporter = Reporter(args.out, base)
    if args.check_cors and enum_targets:
        print("[*] CORS preflight checks ...")
        for u in list(enum_targets.keys()):
            cors_hdrs = check_cors_preflight(u, headers, args.timeout)
            if cors_hdrs:
                payload = {"summary":{"cors_headers_present": True}, "evidence":{"headers": cors_hdrs}}
                emit_per_function(reporter, u, "cors-preflight", payload)
    if args.token_audit and enum_targets:
        print("[*] Running token/header audit with provided headers (authorized) ...")
        for u in list(enum_targets.keys()):
            result = token_audit_endpoint(u, headers, args.timeout, test_headers_list, args.no_redact_secrets)
            emit_per_function(reporter, u, "token-audit", result)
    upload_candidates: List[str] = []
    if args.upload_audit:
        print("[*] Discovering upload endpoints ...")
        for _, info in specs.items():
            sp = info.get("spec")
            if isinstance(sp, dict): upload_candidates += spec_upload_candidates(base, sp)
        for u in enum_targets.keys():
            p = urllib.parse.urlsplit(u).path.lower()
            if any(w in p for w in UPLOAD_HINT_WORDS): upload_candidates.append(u)
        upload_candidates = list(dict.fromkeys(upload_candidates))
        print(f"    [+] {len(upload_candidates)} candidate(s) identified")
        for u in upload_candidates:
            payload = upload_audit_endpoint(u, headers, args.timeout, allow_aggressive=args.allow_aggressive_upload)
            emit_per_function(reporter, u, "upload-audit", payload)
            for fd in payload.get("findings", []):
                findings.append(Finding(u, fd["title"], fd["detail"], fd["severity"], tags=fd.get("tags"), evidence=fd.get("evidence")))
    crud_results: List[Dict[str,Any]] = []
    if args.crud_audit:
        spec_list = []
        for _, info in specs.items():
            sp = info.get("spec")
            if isinstance(sp, dict): spec_list.append({"base": base, "spec": sp})
        crud_results = crud_audit(headers, args.timeout, spec_list, args.enable_destructive)
        if crud_results:
            print("=== CRUD Probe (method url -> status) ===")
            for r in crud_results:
                print(f"{r['method']} {r['url']} -> {r['status']}")
                emit_per_function(reporter, r["url"], f"crud+{r['method']}", {"result": r})
    if args.method_audit and args.enable_destructive and enum_targets:
        for u in list(enum_targets.keys()):
            f = method_override_audit(u, headers, args.timeout)
            if f:
                findings.append(f)
                emit_per_function(reporter, u, "method-override", {"findings":[asdict(f)]})
    if args.trace_audit and enum_targets:
        for u in list(enum_targets.keys()):
            f = trace_audit(u, headers, args.timeout)
            if f:
                findings.append(f)
                emit_per_function(reporter, u, "trace", {"findings":[asdict(f)]})
    if args.graphql_audit:
        gqls = [u for u in enum_targets.keys() if "/graphql" in urllib.parse.urlsplit(u).path.lower()]
        for u in gqls:
            f = graphql_introspection_audit(u, headers, args.timeout)
            if f:
                findings.append(f)
                emit_per_function(reporter, u, "graphql-introspection", {"findings":[asdict(f)]})
    if args.ratelimit_audit and enum_targets:
        for u in list(enum_targets.keys())[:25]:
            f = ratelimit_audit(u, headers, args.timeout, burst=8)
            if f:
                findings.append(f)
            emit_per_function(reporter, u, "ratelimit", {"findings":[asdict(f)] if f else [], "evidence":{"sample": "8 GETs burst"}})
    findings = dedupe_findings(findings)
    counts = summarize_risk(findings)
    print("\n=== Summary ===")
    for s in SEVERITIES: print(f"{s:>9}: {counts.get(s,0)}")
    if specs: print(f"Specs   : {len(specs)} discovered")
    if enum_targets:
        alive = sum(1 for v in enum_targets.values() if v.get("status") and v["status"] < 500)
        print(f"Endpoints (no swagger): {alive} observed (from {len(enum_targets)} probed)")
    data = {"specs": {u: {k: v for k, v in info.items() if k != "raw"} for u, info in specs.items()},"enum_endpoints": enum_targets,"spec_findings": {u: [asdict(x) for x in fs] for u, fs in spec_findings.items()},"upload_candidates": upload_candidates}
    reporter.write_main(data, findings, crud_results)
if __name__ == "__main__":
    main()