#!/usr/bin/env python3
# jsexposures_improved.py
import requests
import re
import concurrent.futures
import logging
import json
import argparse
import time
import signal
import sys
import base64
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from math import log2

# ---------------- Logging ----------------
def configure_logging(level):
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {level}')
    logging.basicConfig(level=numeric_level, format='%(levelname)s: %(message)s')

def signal_handler(sig, frame):
    logging.info("Exiting program gracefully...")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def print_banner():
    banner = r"""
 ▄▄▄██▀▀▀  ██████ ▓█████ ▒██   ██▒ ██▓███   ▒█████    ██████  █    ██  ██▀███  ▓█████   ██████    
   ▒██   ▒██    ▒ ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▒██▒  ██▒▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒    
   ░██   ░ ▓██▄   ▒███   ░░  █   ░▓██░ ██▓▒▒██░  ██▒░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒▒███   ░ ▓██▄      
▓██▄██▓    ▒   ██▒▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██   ██░  ▒   ██▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒   
 ▓███▒   ▒██████▒▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░ ████▓▒░▒██████▒▒▒▒█████▓ ░██▓ ▒██▒░▒████▒▒██████▒▒   
 ▒▓▒▒░   ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░   
 ▒ ░▒░   ░ ░▒  ░ ░ ░ ░  ░░░   ░▒ ░░▒ ░       ░ ▒ ▒░ ░ ░▒  ░ ░░░▒░ ░ ░   ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░   
 ░ ░ ░   ░  ░  ░     ░    ░    ░  ░░       ░ ░ ░ ▒  ░  ░  ░   ░░░ ░ ░   ░░   ░    ░   ░  ░  ░     
 ░   ░         ░     ░  ░ ░    ░               ░ ░        ░     ░        ░        ░  ░      ░     
                   jsexposures - Search for exposures in JS files
                   Author: hidalg0d
"""
    print(banner)

# ---------------- Entropy & scoring ----------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    ln = len(s)
    for v in freq.values():
        p = v / ln
        ent -= p * log2(p)
    return ent

def score_finding(description: str, match: str, runtime=False):
    score = 0
    desc = description.lower()
    if any(x in desc for x in ("key", "token", "secret", "private", "jwt")):
        score += 40
    if runtime:
        score += 10
    if len(match) > 30:
        score += 10
    if shannon_entropy(match) > 3.5:
        score += 10
    return score

# ---------------- Strict validators ----------------
PEM_BLOCK_RE = re.compile(
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+([A-Za-z0-9+/=\r\n]{200,})\s+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    re.MULTILINE
)

def is_real_pem_block(text: str) -> bool:
    m = PEM_BLOCK_RE.search(text)
    if not m:
        return False
    b64 = re.sub(r'\s+', '', m.group(1))
    try:
        raw = base64.b64decode(b64, validate=True)
        return len(raw) >= 256  # minimal plausible size for private key blob
    except Exception:
        return False

JWT_RE = re.compile(r'^[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}$')

def _b64url_pad(s: str) -> str:
    return s + '=' * (-len(s) % 4)

def is_real_jwt(s: str) -> bool:
    if not JWT_RE.match(s.strip()):
        return False
    try:
        header_b64, payload_b64, _ = s.split('.', 2)
        header = json.loads(base64.urlsafe_b64decode(_b64url_pad(header_b64)).decode('utf-8', 'ignore'))
        _ = base64.urlsafe_b64decode(_b64url_pad(payload_b64))  # payload only needs to decode
        return isinstance(header, dict) and 'alg' in header
    except Exception:
        return False

# ---------------- Third-party / artifacts heuristics ----------------
THIRD_PARTY_HINTS = (
    "ruxitagentjs", "dynatrace", "metrics/ac-analytics", "analytics.js",
    "tagmanager", "gtm.js", "hotjar", "segment", "matomo", "adobe/analytics",
    "snowplow", "/sentry", "datadog", "renderer/renderer.js",
    "jquery", "/react.", "/vue.", "/angular.", "polyfills", "vendor.", ".chunk.js",
)

def is_probably_third_party(url: str) -> bool:
    u = url.lower()
    return any(h in u for h in THIRD_PARTY_HINTS)

HEX32_RE = re.compile(r'^[0-9a-f]{32}$', re.IGNORECASE)

def is_build_artifact(candidate: str, url: str, context: str) -> bool:
    c = candidate.lower()
    path = url.lower()
    if HEX32_RE.match(c):
        if c in path:
            return True
        if re.search(r'(chunk|bundle|vendor|polyfills|renderer)', path):
            return True
        snippet = context.lower()
        if re.search(r'webpack|import\(|sourceMappingURL|__webpack_require__', snippet):
            return True
    return False

# ---------------- Patterns (tightened) ----------------
# Context-demanding patterns; avoid loose generic captures
patterns = [
    # Strong known formats / vendors
    (re.compile(r'\bAKIA[A-Z0-9]{16}\b'), "AWS Access Key ID"),
    (re.compile(r'\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*(?:"|\')?([A-Za-z0-9/+=]{20,})(?:"|\')?', re.IGNORECASE), "AWS Secret Access Key"),
    (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "Google API Key"),

    # Authorization / JWT
    (re.compile(r'(?i)\bauthorization\b\s*[:=]\s*(?:"|\')?(bearer\s+[A-Za-z0-9\-._~+/=]{20,})(?:"|\')?'), "Authorization Header"),
    (re.compile(r'([A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})'), "JWT"),

    # Secrets / passwords with separators and minimum length
    (re.compile(r'(?i)\bpassword\b\s*[:=]\s*(?:"|\')?(?!function\b)([A-Za-z0-9!@#$%^&*._\-]{10,})(?:"|\')?'), "Password"),
    (re.compile(r'(?i)\bclient[_-]?secret\b\s*[:=]\s*(?:"|\')?([A-Za-z0-9._\-]{16,})(?:"|\')?'), "Client Secret"),

    # API keys by context words
    (re.compile(r'(?i)\b(?:api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*(?:"|\')?([A-Za-z0-9_\-\.~+/]{16,})(?:"|\')?'), "API/Token by Context"),

    # PEM block (validated later)
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', re.DOTALL), "Private Key"),
]

# ---------------- HTTP session ----------------
def create_session(timeout=10, max_retries=3, backoff_factor=0.5, verify_ssl=True):
    session = requests.Session()
    retries = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS'])
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=100, pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({"User-Agent": "jsexposures/1.1 (+https://example.invalid)"})
    session.request_timeout = timeout
    session.verify_ssl = verify_ssl
    return session

# ---------------- File I/O ----------------
def load_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(urls)} URLs from {file_path}.")
        return urls
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

# ---------------- Gatekeeper ----------------
def is_probable_secret(desc: str, value: str, url: str, context: str, mode: str = "strict") -> bool:
    v = value.strip().strip('\'"')
    if len(v) < 16:
        return False

    # PEM must be real
    if "Private Key" in desc:
        if not (is_real_pem_block(v) or is_real_pem_block(context)):
            return False

    # JWT must decode
    if desc in ("JWT", "Authorization Header"):
        # extract token if "Bearer <token>"
        v2 = v.split(None, 1)[1] if v.lower().startswith("bearer ") and " " in v else v
        if JWT_RE.match(v2) and not is_real_jwt(v2):
            return False

    # Third-party libs: drop weak classes
    if is_probably_third_party(url) and desc in ("API/Token by Context", "Authorization Header", "Password"):
        if mode in ("strict", "balanced"):
            return False

    # Build artifacts (hashes near bundlers)
    if is_build_artifact(v, url, context):
        return False

    # Entropy thresholds by length and mode
    ent = shannon_entropy(v)
    if mode == "strict":
        if len(v) < 24 and ent < 3.2: return False
        if len(v) >= 24 and ent < 2.8: return False
    elif mode == "balanced":
        if len(v) < 24 and ent < 3.0: return False
        if len(v) >= 24 and ent < 2.6: return False
    else:  # loose
        if len(v) < 20 and ent < 2.8: return False

    return True

# ---------------- Core check ----------------
def check_js_for_secrets_and_comments(session: requests.Session, url: str, mode: str, timeout=None, per_file_cap=200):
    if timeout is None:
        timeout = getattr(session, 'request_timeout', 10)
    findings = []
    try:
        resp = session.get(url, timeout=timeout, verify=session.verify_ssl)
        resp.raise_for_status()
        content = resp.text

        for pattern, description in patterns:
            for m in pattern.finditer(content):
                candidate = m.group(1) if m.groups() else m.group(0)
                if not candidate:
                    continue
                cand_str = candidate.strip().strip('\'"')

                # Context window for heuristics
                start = max(0, m.start() - 120)
                end = min(len(content), m.end() + 120)
                ctx = content[start:end]

                # Gatekeeper
                if not is_probable_secret(description, cand_str, url, ctx, mode=mode):
                    continue

                lineno = content.count('\n', 0, m.start()) + 1
                score = score_finding(description, cand_str, runtime=False)
                findings.append({
                    'url': url,
                    'match': cand_str,
                    'description': description,
                    'length': len(cand_str),
                    'lineno': lineno,
                    'entropy': round(shannon_entropy(cand_str), 3),
                    'score': score,
                })

                if len(findings) >= per_file_cap:
                    logging.debug(f"Per-file cap reached at {url}")
                    break
            if len(findings) >= per_file_cap:
                break

    except requests.RequestException as e:
        logging.debug(f"Request error for {url}: {e}")
    return findings

# ---------------- Output ----------------
def log_results(results, txt_path='exposure_results.txt'):
    with open(txt_path, 'a') as f:
        for r in results:
            f.write(f'[{r["score"]}] Found: "{r["match"]}" ({r["description"]}) at {r["url"]} (line {r["lineno"]}, ent={r["entropy"]})\n')

def save_results_as_json(results, json_path='exposure_results.json'):
    try:
        try:
            with open(json_path, 'r') as jf:
                existing = json.load(jf)
        except (FileNotFoundError, json.JSONDecodeError):
            existing = []
        existing.extend(results)
        with open(json_path, 'w') as jf:
            json.dump(existing, jf, indent=2)
    except Exception as e:
        logging.error(f"Failed to write JSON results: {e}")

# ---------------- Orchestration ----------------
def process_js_files(file_path, max_workers, timeout, verify_ssl, mode: str, per_file_cap: int):
    session = create_session(timeout=timeout, max_retries=3, backoff_factor=0.5, verify_ssl=verify_ssl)
    urls = load_urls_from_file(file_path)
    if not urls:
        logging.warning("No URLs to process.")
        return

    all_results = []
    logging.info(f"Processing {len(urls)} URLs with {max_workers} workers (mode={mode}).")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(check_js_for_secrets_and_comments, session, url, mode, timeout, per_file_cap): url
            for url in urls
        }
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                res = future.result()
                if res:
                    all_results.extend(res)
                    logging.info(f"Found {len(res)} findings at {url}.")
            except Exception as e:
                logging.error(f"Error processing {url}: {e}")

    if all_results:
        all_results.sort(key=lambda x: x.get('score', 0), reverse=True)
        log_results(all_results)
        save_results_as_json(all_results)
        logging.info(f"Analysis complete. Found {len(all_results)} exposures (saved to files).")
    else:
        logging.info("No exposures found.")

# ---------------- CLI ----------------
def main():
    parser = argparse.ArgumentParser(description="JS Exposures Finder - improved (strict FP filtering)")
    parser.add_argument('--file', type=str, default='js_endpoints.txt')
    parser.add_argument('--max-workers', type=int, default=10)
    parser.add_argument('--log-level', type=str, default='INFO')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--no-verify-ssl', action='store_true', help="Don't verify SSL certificates (use with caution)")
    parser.add_argument('--mode', choices=['strict', 'balanced', 'loose'], default='strict', help='FP filtering aggressiveness')
    parser.add_argument('--per-file-cap', type=int, default=200, help='Max findings per file before short-circuit')
    args = parser.parse_args()

    configure_logging(args.log_level)
    print_banner()
    process_js_files(
        args.file,
        args.max_workers,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        mode=args.mode,
        per_file_cap=args.per_file_cap
    )

if __name__ == "__main__":
    main()

