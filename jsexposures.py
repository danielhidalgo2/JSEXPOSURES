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

# ---------------- Context Extraction ----------------
def extract_context_clues(context: str, description: str) -> str:
    """
    Extract meaningful context clues from surrounding code to identify what the credential is for.
    Looks at variable names, object properties, comments, URLs, and nearby strings.
    Works with both regular and minified JavaScript.
    """
    # Extract variable/property names from common patterns
    var_patterns = [
        r'(?:var|let|const)\s+(\w+)\s*[:=]',  # var/let/const declarations
        r'(\w+)\s*[:=]\s*["\']',  # property assignments
        r'["\'](\w+)["\']\s*:\s*["\']',  # object properties
        r'//\s*(.+?)(?:\n|$)',  # single-line comments
        r'/\*\s*(.+?)\s*\*/',  # multi-line comments
    ]
    
    clues = []
    for pattern in var_patterns:
        matches = re.findall(pattern, context, re.IGNORECASE | re.DOTALL)
        clues.extend(matches)
    
    # For minified JS: Extract nearby string literals and URLs
    # Look for API endpoints, domain names, and service identifiers
    url_patterns = [
        r'https?://([a-zA-Z0-9.-]+)',  # Domain names from URLs
        r'\.([a-zA-Z0-9-]+)\.(?:com|io|net|org|dev|app)',  # Service domains
        r'/api/([a-zA-Z0-9_-]+)',  # API endpoint paths
        r'"([a-zA-Z0-9_-]{3,20})"',  # Nearby quoted strings
    ]
    
    for pattern in url_patterns:
        matches = re.findall(pattern, context, re.IGNORECASE)
        clues.extend(matches)
    
    # Join all clues and clean up
    clue_text = ' '.join(clues).lower()
    
    # Look for service/purpose indicators in the clues
    purpose_keywords = {
        # Databases
        'database': 'Database', 'db': 'Database', 'mongodb': 'MongoDB', 'mysql': 'MySQL',
        'postgres': 'PostgreSQL', 'redis': 'Redis', 'dynamodb': 'DynamoDB',
        'supabase': 'Supabase', 'planetscale': 'PlanetScale',
        
        # Authentication/Admin
        'admin': 'Admin', 'auth': 'Authentication', 'login': 'Login', 'user': 'User Auth',
        'password': 'Password', 'username': 'Username', 'credential': 'Credentials',
        'session': 'Session', 'token': 'Token',
        
        # Payment/Commerce
        'payment': 'Payment', 'billing': 'Billing', 'checkout': 'Checkout',
        'commerce': 'Commerce', 'cart': 'Shopping Cart',
        
        # Communication
        'email': 'Email', 'smtp': 'SMTP', 'mail': 'Email', 'notification': 'Notifications',
        'sms': 'SMS', 'message': 'Messaging', 'chat': 'Chat',
        
        # Analytics/Monitoring
        'analytics': 'Analytics', 'tracking': 'Tracking', 'monitor': 'Monitoring',
        'metric': 'Metrics', 'log': 'Logging', 'telemetry': 'Telemetry',
        
        # Storage/CDN
        'storage': 'Storage', 'bucket': 'Storage', 's3': 'S3 Storage', 'cdn': 'CDN',
        'upload': 'File Upload', 'download': 'File Download', 'media': 'Media',
        
        # API/Backend
        'api': 'API', 'backend': 'Backend', 'server': 'Server', 'endpoint': 'API Endpoint',
        'webhook': 'Webhook', 'graphql': 'GraphQL', 'rest': 'REST API',
        
        # Third-party services (expanded for minified detection)
        'recaptcha': 'reCAPTCHA', 'captcha': 'CAPTCHA', 'oauth': 'OAuth',
        'firebase': 'Firebase', 'firestore': 'Firestore',
        'vercel': 'Vercel', 'netlify': 'Netlify', 'heroku': 'Heroku',
        'cloudinary': 'Cloudinary', 'imgix': 'Imgix',
        'amplitude': 'Amplitude', 'mixpanel': 'Mixpanel', 'segment': 'Segment',
        'intercom': 'Intercom', 'zendesk': 'Zendesk',
    }
    
    # Check for keywords (prioritize longer/more specific matches first)
    sorted_keywords = sorted(purpose_keywords.items(), key=lambda x: len(x[0]), reverse=True)
    for keyword, purpose in sorted_keywords:
        if keyword in clue_text:
            return purpose
    
    # For minified JS: Look for domain-based clues
    domain_services = {
        'firebase': 'Firebase',
        'firebaseio': 'Firebase',
        'googleapis': 'Google API',
        'stripe': 'Stripe',
        'twilio': 'Twilio',
        'sendgrid': 'SendGrid',
        'mailgun': 'Mailgun',
        'cloudflare': 'Cloudflare',
        'amazonaws': 'AWS',
        'azure': 'Azure',
        'digitalocean': 'DigitalOcean',
        'heroku': 'Heroku',
        'vercel': 'Vercel',
        'netlify': 'Netlify',
        'supabase': 'Supabase',
        'planetscale': 'PlanetScale',
        'railway': 'Railway',
        'render': 'Render',
    }
    
    for domain, service in domain_services.items():
        if domain in clue_text:
            return service
    
    # Extract from variable names more specifically (works for non-minified)
    if clues:
        # Get the most relevant variable name (usually the first one)
        first_var = clues[0] if clues else ''
        if first_var and len(first_var) > 2:
            # Skip single-letter variables (minified code)
            if len(first_var) == 1:
                return ""
            
            # Clean up common prefixes/suffixes
            clean_var = first_var.replace('_key', '').replace('_token', '').replace('_secret', '')
            clean_var = clean_var.replace('key', '').replace('token', '').replace('secret', '')
            clean_var = clean_var.strip('_')
            
            if clean_var and len(clean_var) > 2:
                # Capitalize and return as service name
                return clean_var.replace('_', ' ').title()
    
    return ""

# ---------------- Service Identification ----------------
def identify_service(match: str, description: str, context: str = "") -> str:
    """
    Identify which service an API key/token belongs to based on patterns and context.
    Returns the service name or "Unknown" if not identifiable.
    """
    match_upper = match.upper()
    match_lower = match.lower()
    ctx_lower = context.lower()
    
    # First, try to extract context clues for custom/internal APIs
    context_clue = extract_context_clues(context, description)
    
    # AWS patterns
    if match_upper.startswith("AKIA"):
        return "AWS"
    if "aws_secret_access_key" in ctx_lower or "AWS_SECRET_ACCESS_KEY" in context:
        return "AWS"
    
    # Google/Firebase patterns
    if match.startswith("AIza"):
        # Check context for more specific service
        if any(hint in ctx_lower for hint in ["firebase", "firebaseconfig", "firebaseapp"]):
            return "Firebase"
        elif any(hint in ctx_lower for hint in ["google", "googleapis", "gcp", "maps", "youtube"]):
            if "maps" in ctx_lower:
                return "Google Maps"
            elif "youtube" in ctx_lower:
                return "YouTube"
            else:
                return "Google Cloud"
        return "Google/Firebase"
    
    # Stripe
    if match.startswith(("sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_")):
        return "Stripe"
    
    # GitHub
    if match.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
        return "GitHub"
    
    # Slack
    if match.startswith("xox"):
        if match.startswith("xoxb-"):
            return "Slack Bot"
        elif match.startswith("xoxp-"):
            return "Slack User"
        return "Slack"
    
    # Twilio
    if match_upper.startswith("SK") and len(match) == 32:
        if "twilio" in ctx_lower:
            return "Twilio"
    if match_upper.startswith("AC") and len(match) == 34:
        if "twilio" in ctx_lower:
            return "Twilio Account"
    
    # SendGrid
    if match.startswith("SG."):
        return "SendGrid"
    
    # Mailgun
    if match.startswith("key-") and "mailgun" in ctx_lower:
        return "Mailgun"
    
    # Heroku
    if len(match) == 36 and match.count("-") == 4 and "heroku" in ctx_lower:
        return "Heroku"
    
    # Square
    if match.startswith(("sq0atp-", "sq0csp-")):
        return "Square"
    
    # Shopify
    if match.startswith("shpat_") or match.startswith("shpss_"):
        return "Shopify"
    
    # PayPal
    if "paypal" in ctx_lower and (match.startswith("A") or match.startswith("E")):
        return "PayPal"
    
    # JWT tokens
    if description in ("JWT", "Authorization Header"):
        # Try to decode and check issuer
        try:
            parts = match.split(".")
            if len(parts) == 3:
                # Decode header to check for hints
                header_b64 = parts[0]
                header_b64 += '=' * (-len(header_b64) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64).decode('utf-8', 'ignore'))
                
                # Check payload for issuer
                payload_b64 = parts[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8', 'ignore'))
                
                if 'iss' in payload:
                    issuer = payload['iss'].lower()
                    if 'google' in issuer or 'firebase' in issuer:
                        return "Firebase/Google JWT"
                    elif 'auth0' in issuer:
                        return "Auth0 JWT"
                    elif 'okta' in issuer:
                        return "Okta JWT"
                    else:
                        return f"JWT ({payload['iss']})"
        except:
            pass
        
        # Use context clue if available
        if context_clue:
            return f"JWT - {context_clue}"
        return "JWT"
    
    # Password/Username detection with context
    if description in ("Password", "Username"):
        if context_clue:
            return f"{description} - {context_clue}"
        return description
    
    # Client Secret with context
    if description == "Client Secret":
        if context_clue:
            return f"Client Secret - {context_clue}"
        return "Client Secret"
    
    # Context-based detection for generic API keys
    if description == "API/Token by Context":
        # Known third-party services
        context_hints = {
            "firebase": "Firebase",
            "google": "Google",
            "stripe": "Stripe",
            "github": "GitHub",
            "gitlab": "GitLab",
            "bitbucket": "Bitbucket",
            "aws": "AWS",
            "azure": "Azure",
            "digitalocean": "DigitalOcean",
            "cloudflare": "Cloudflare",
            "sendgrid": "SendGrid",
            "mailchimp": "Mailchimp",
            "twilio": "Twilio",
            "slack": "Slack",
            "discord": "Discord",
            "telegram": "Telegram",
            "openai": "OpenAI",
            "anthropic": "Anthropic",
            "mapbox": "Mapbox",
            "algolia": "Algolia",
            "sentry": "Sentry",
            "datadog": "Datadog",
            "newrelic": "New Relic",
            "pusher": "Pusher",
            "pubnub": "PubNub",
        }
        
        for hint, service in context_hints.items():
            if hint in ctx_lower:
                return service
        
        # If no known service, use context clue from variable names/comments
        if context_clue:
            return context_clue
    
    # Private keys
    if "Private Key" in description:
        if "rsa" in ctx_lower:
            return "RSA Private Key"
        elif "ec" in ctx_lower or "ecdsa" in ctx_lower:
            return "EC Private Key"
        elif "openssh" in ctx_lower:
            return "OpenSSH Private Key"
        return "Private Key"
    
    # Fallback to context clue if we have one
    if context_clue:
        return context_clue
    
    return "Unknown"

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

                # Context window for heuristics (larger for minified JS)
                start = max(0, m.start() - 500)
                end = min(len(content), m.end() + 500)
                ctx = content[start:end]

                # Gatekeeper
                if not is_probable_secret(description, cand_str, url, ctx, mode=mode):
                    continue

                lineno = content.count('\n', 0, m.start()) + 1
                score = score_finding(description, cand_str, runtime=False)
                service = identify_service(cand_str, description, ctx)
                findings.append({
                    'url': url,
                    'match': cand_str,
                    'description': description,
                    'service': service,
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
            service_info = f' [{r["service"]}]' if r.get("service") else ''
            f.write(f'[{r["score"]}]{service_info} Found: "{r["match"]}" ({r["description"]}) at {r["url"]} (line {r["lineno"]}, ent={r["entropy"]})\n')

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

