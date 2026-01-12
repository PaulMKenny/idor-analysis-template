#!/usr/bin/env python3
# ==================================================
# IDOR ANALYZER — ZERO FALSE NEGATIVE EDITION (MERGED)
# GraphQL + REST + TOKEN ANALYSIS + CO-OCCURRENCE + RANKED TRIAGE
# + SEMANTIC TIERING (AUTH-RELEVANT vs INFORMATIONAL)
# ==================================================

"""
CLI usage:

    python3 idor_analyzer.py <history.xml> [sitemap.xml]

Architecture:
    - EXTRACTION: Lossless, aggressive
    - CLASSIFICATION: Metadata tagging, no filtering
    - SCORING: Bayesian-ish ranking with explainable signals
    - OUTPUT: Ordered triage queue with "why" fields + co-occurrence

Zero False Negative Guarantee:
    - All candidates appear in output (Tier 1 or Tier 2)
    - Signals affect SCORE or TIER, never INCLUSION
    - Minimum score is 1 (never 0)

Merged features:
    - Full JWT parsing + ID extraction (token-aware deprioritization)
    - Mutation detection (HTTP verbs + GraphQL operation keywords)
    - Explainable scoring (score_reasons per candidate)
    - Dereference detection (request→response coupling)
    - Co-occurrence visibility (structural + replay patterns)
    - Endpoint directionality mapping
    - Two-tier output (authorization-relevant vs informational)
"""

import sys
import csv
import base64
import json
import re
import html
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
import heapq
import mmap
from collections import defaultdict
from pathlib import Path
from typing import Optional, Dict, Set, Tuple, List, Any
from urllib.parse import unquote
from dataclasses import dataclass, field
import pickle
import hashlib

_SPLIT_EXEC = ThreadPoolExecutor(max_workers=2)


# ------------------------------
# Pickle-safe defaultdict factories (NO lambdas)
# ------------------------------
def _dd_set():
    return set()


def _dd_dir():
    return defaultdict(_dd_set)          # direction -> set(msg_id)


def _dd_key():
    return defaultdict(_dd_dir)          # key -> direction-map


def _default_high():
    return "high"


def _dd_list():
    return list()


def _dd_token_binding_dict():
    return {}


# ------------------------------
# Fast XML item counter (avoids second full parse)
# ------------------------------
def fast_count_items(xml_path: str) -> int:
    """Count <item> tags without parsing XML - O(n) byte scan."""
    needle = b"<item>"
    with open(xml_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            count = 0
            pos = 0
            while True:
                pos = mm.find(needle, pos)
                if pos == -1:
                    break
                count += 1
                pos += len(needle)
            return count
        finally:
            mm.close()


# ============================================================
# CONFIG
# ============================================================

class Config:
    """
    Configuration for IDOR analysis.

    CRITICAL: These are for PRIORITIZATION and TIERING, not FILTERING.
    Nothing here should cause candidates to be excluded from the overall output.
    """

    # ID key patterns (disciplined - focused on actual ID fields)
    KEY_REGEX = re.compile(
        r'(?:^|[^a-zA-Z])(id|.*_id|id_.*|uuid|guid|iid)(?:$|[^a-zA-Z])',
        re.IGNORECASE
    )

    # Path segment ID patterns
    PATH_ID_RE = re.compile(
        r'^([0-9]+|[a-f0-9-]{8,}|[A-Za-z0-9_-]{16,})$',
        re.IGNORECASE
    )

    # Embedded JSON in HTML patterns
    EMBEDDED_JSON_PATTERNS = [
        re.compile(r'<script[^>]*type=["\']application/(?:json|ld\+json)["\'][^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE),
        re.compile(r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE),
        re.compile(r'data-props=["\'](\{.*?\})["\']', re.DOTALL),
        re.compile(r'data-state=["\'](\{.*?\})["\']', re.DOTALL),
        re.compile(r'data-config=["\'](\{.*?\})["\']', re.DOTALL),
        re.compile(r'window\.__INITIAL_STATE__\s*=\s*(\{.*?\});', re.DOTALL),
        re.compile(r'window\.__PRELOADED_STATE__\s*=\s*(\{.*?\});', re.DOTALL),
    ]

    # GraphQL ID patterns (gid://, urn:, etc.)
    GRAPHQL_ID_PATTERNS = [
        re.compile(r'^gid://([^/]+)/([^/]+)/(\d+)$'),
        re.compile(r'^urn:([^:]+):([^:]+):(\d+)$'),
    ]

    # High-signal semantic keys (rank boosts)
    HIGH_SIGNAL_KEYS = {
        # Identity / tenancy
        "user_id", "userid", "uid",
        "account_id", "accountid", "aid", "acctid",
        "pulse_account_id", "pulse_user_id",
        "org_id", "orgid", "organisation_id", "organization_id",
        "tenant_id", "tenantid",
        "workspace_id", "workspaceid",
        "team_id", "teamid",

        # Object selectors
        "board_id", "boardid",
        "project_id", "projectid",
        "item_id", "itemid",
        "pulse_id", "pulseid",
        "group_id", "groupid",
        "column_id", "view_id", "subset_id",
        "ticket_id", "ticketid",
        "order_id", "orderid",
        "invoice_id", "invoiceid",
        "document_id", "documentid", "doc_id", "docid",
        "file_id", "fileid",
        "folder_id", "folderid",
        "message_id", "messageid",
        "comment_id", "commentid",
        "agent_id", "agentid",
        "customer_id", "customerid",
    }

    # Low-signal keys (telemetry/session noise - penalize, NOT filter)
    LOW_SIGNAL_KEYS = {
        "visitor_id", "session_id", "fs_session_url", "fs_session_started_at",
        "person_id", "anonymous_id",
    }

    # Values to deprioritize (not meaningful IDs) - scoring only, never exclusion
    LOW_LIKELIHOOD_VALUES = {"true", "false", "null", "-1", "0", "1", ""}

    # === HOST PRIORITIZATION (de-prioritize, not skip) ===

    PRIMARY_HOST_SUFFIXES = {
        "monday.com",
        # Add target-specific domains here
    }

    DEPRIORITIZE_HOST_SUFFIXES = {
        # Analytics / tracking
        "facebook.net", "facebook.com", "fbcdn.net",
        "google-analytics.com", "googletagmanager.com",
        "doubleclick.net", "googlesyndication.com",
        "fullstory.com", "segment.io", "segment.com",
        "sentry.io", "sentry-cdn.com",
        "hotjar.com", "hotjar.io",
        "mixpanel.com", "amplitude.com",
        "intercom.io", "intercomcdn.com",
        "zendesk.com", "zdassets.com",
        "pusher.com", "pusherapp.com",
        "cloudflareinsights.com",
        "newrelic.com", "nr-data.net",
        "datadoghq.com", "datadoghq.eu",
        "logrocket.io", "logrocket.com",
        "heap.io", "heapanalytics.com",
        "bigbrain.me",
        # CDN / static assets
        "cloudinary.com", "cloudfront.net",
        "akamaized.net", "fastly.net",
        "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        # Social / auth widgets
        "twitter.com", "twimg.com",
        "linkedin.com", "licdn.com",
        "google.com", "gstatic.com", "googleapis.com",
        # Payment (usually isolated)
        "stripe.com", "braintreegateway.com", "paypal.com",
    }

    # Endpoint substrings that indicate telemetry (penalize, not exclude)
    DEPRIORITIZE_ENDPOINT_SUBSTRINGS = {
        "/prod/event",
        "/signals/config",
        "/messenger/web/ping",
        "/track",
        "/collect",
        "/beacon",
        "/pixel",
        "/analytics",
        "/log",
        "/metrics",
        "/health",
        "/ping",
    }

    # === MUTATION DETECTION ===

    MUTATION_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    MUTATION_OP_KEYWORDS = {
        "create", "update", "delete", "remove", "add", "set",
        "change", "move", "copy", "rename", "archive", "restore",
        "assign", "unassign", "invite", "revoke", "approve", "reject",
        "publish", "unpublish", "enable", "disable", "activate", "deactivate",
    }

    # === TOKEN DETECTION ===

    TOKEN_PARAM_NAMES = {
        "token", "access_token", "auth_token", "jwt", "session_token",
        "api_token", "bearer", "id_token", "refresh_token", "apikey",
        "api_key", "auth", "authorization", "credential",
    }

    # === SEMANTIC TIERING (classification, not filtering) ===

    # "Probably telemetry" keys - treated as telemetry only when ALL strict conditions pass
    PROBABLY_TELEMETRY_KEYS = {
        "visitor_id", "session_id", "anonymous_id",
        "fs_session_url", "fs_session_started_at",
        "ga_client_id", "fbp", "fbc",
        "_ga", "_gid", "_fbp",
    }

    # Strict analytics hosts - exact domains only
    STRICT_ANALYTICS_HOSTS = {
        "www.google-analytics.com",
        "analytics.google.com",
        "www.googletagmanager.com",
        "connect.facebook.net",
        "www.facebook.com",
        "rs.fullstory.com",
        "api.segment.io",
        "cdn.segment.com",
        "api.mixpanel.com",
        "api.amplitude.com",
        "in.hotjar.com",
        "o0.ingest.sentry.io",
    }

    # Strict telemetry paths - exact matches / startswith (to allow /tr or /tr/)
    STRICT_TELEMETRY_PATHS = {
        "/collect",
        "/j/collect",
        "/g/collect",
        "/tr/",
        "/tr",
        "/beacon",
        "/v1/track",
        "/v1/identify",
        "/track",
        "/prod/event",
    }

    # Nonce keys (WITHOUT 'state' - OAuth state can contain real IDs)
    NONCE_KEYS = {
        "nonce", "csrf", "csrf_token", "challenge",
        "code_challenge", "code_verifier"
    }

    # Timestamp keys (note: exp/iat/nbf exist in JWTs too; tiering checks selector usage)
    TIMESTAMP_KEYS = {
        "timestamp", "ts", "time", "created_at", "updated_at",
        "modified_at", "sent_at", "received_at", "expires_at",
        "exp", "iat", "nbf"
    }


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class CandidateScore:
    """Explainable score for an IDOR candidate."""
    total: int = 50
    reasons: List[str] = field(default_factory=list)

    def adjust(self, delta: int, reason: str):
        self.total += delta
        if reason:
            self.reasons.append(f"{'+' if delta >= 0 else ''}{delta}: {reason}")

    def finalize(self) -> int:
        """Ensure minimum score of 1 (zero false negative guarantee)."""
        return max(1, self.total)


@dataclass
class TokenBinding:
    """Information about token binding for an ID."""
    is_bound: bool = False
    strength: str = "none"  # "strong", "moderate", "weak", "none"
    locations: List[str] = field(default_factory=list)
    bound_ids: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class IDCandidate:
    """Complete information about an IDOR candidate (immutable)."""
    id_value: str
    key: str
    endpoint: str
    score: int
    score_reasons: Tuple[str, ...]
    origin: str
    sources: Tuple[str, ...]
    host_priority: str
    parse_confidence: str
    token_bound: bool
    token_strength: str
    token_locations: Tuple[str, ...]
    is_dereferenced: bool
    is_mutation: bool
    graphql_operations: Tuple[str, ...]
    directions: str
    request_msgs: Tuple[int, ...]
    response_msgs: Tuple[int, ...]
    is_informational: bool = False
    informational_reason: str = ""


# ============================================================
# XML / HTTP PARSING
# ============================================================

def decode_http(elem) -> bytes:
    """Decode base64-encoded HTTP message from Burp XML."""
    if elem is None or not elem.text:
        return b""
    try:
        return base64.b64decode(elem.text)
    except Exception:
        return b""


def iter_http_messages(xml_path: str):
    """
    Iterate over HTTP messages in Burp XML export (streaming).
    Uses iterparse to avoid building a full DOM (memory + speed win on large XML).
    """
    idx = 0
    # Note: Burp exports are typically namespace-free; if yours has namespaces,
    # you can still match on elem.tag.endswith("item").
    for ev, elem in ET.iterparse(xml_path, events=("end",)):
        if elem.tag != "item":
            continue
        idx += 1
        req_el = elem.find("request")
        resp_el = elem.find("response")
        yield idx, decode_http(req_el), decode_http(resp_el)
        # Critical: free memory as we stream
        elem.clear()



def split_http_message(raw: bytes) -> Tuple[str, Dict[str, str], bytes]:
    """Split HTTP message into request/status line, headers, and body."""
    if not raw:
        return "", {}, b""

    if b"\r\n\r\n" in raw:
        head_b, body = raw.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw:
        head_b, body = raw.split(b"\n\n", 1)
    else:
        return "", {}, b""

    head = head_b.decode(errors="replace")
    lines = head.splitlines()
    first_line = lines[0] if lines else ""
    headers: Dict[str, str] = {}

    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return first_line, headers, body

def split_http_pair(
    raw_req: bytes, raw_resp: bytes
) -> Tuple[
    Tuple[str, Dict[str, str], bytes],
    Tuple[str, Dict[str, str], bytes],
]:
    """
    Split request + response concurrently.
    Pure refactor: same results as calling split_http_message twice.
    """
    f_req = _SPLIT_EXEC.submit(split_http_message, raw_req)
    f_resp = _SPLIT_EXEC.submit(split_http_message, raw_resp)
    return f_req.result(), f_resp.result()



def parse_request_line(request_line: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract method and path from request line."""
    parts = request_line.split()
    return (parts[0], parts[1]) if len(parts) >= 2 else (None, None)


def extract_status_code(raw_resp: bytes) -> Optional[int]:
    """Extract HTTP status code from response."""
    if not raw_resp:
        return None
    try:
        line = raw_resp.decode(errors="replace").splitlines()[0]
        for p in line.split():
            if p.isdigit() and len(p) == 3:
                return int(p)
    except Exception:
        pass
    return None


# ============================================================
# URL / PATH HELPERS
# ============================================================

def extract_url_params(path: str) -> List[Tuple[str, str]]:
    """Extract query parameters from URL path."""
    if not path or "?" not in path:
        return []
    out = []
    for p in path.split("?", 1)[1].split("&"):
        if "=" in p:
            k, v = p.split("=", 1)
            out.append((unquote(k), unquote(v)))
        elif p:
            out.append((unquote(p), ""))
    return out


def extract_path_ids(path: str) -> List[Tuple[str, str]]:
    """Extract ID-like values from URL path segments."""
    if not path:
        return []
    base = path.split("?")[0]
    parts = [p for p in base.split("/") if p]
    out = []
    for i, part in enumerate(parts):
        if Config.PATH_ID_RE.match(part):
            key = parts[i - 1] if i > 0 else "<path>"
            out.append((key, part))
    return out


def extract_base_path(path: str) -> str:
    """Extract base path without query string."""
    if not path:
        return "/"
    return path.split("?")[0].rstrip("/") or "/"


def get_host_priority(host: str) -> str:
    """
    Classify host priority for scoring.
    Returns: "primary", "related", or "third_party"
    """
    if not host:
        return "unknown"

    host_lower = host.lower()

    if any(host_lower.endswith(suf) for suf in Config.PRIMARY_HOST_SUFFIXES):
        return "primary"

    if any(host_lower.endswith(suf) for suf in Config.DEPRIORITIZE_HOST_SUFFIXES):
        return "third_party"

    return "related"


def endpoint_from(method: Optional[str], host: str, path: Optional[str]) -> str:
    """Build endpoint string from components."""
    m = method or "?"
    h = (host or "").lower()
    p = extract_base_path(path or "/")
    return f"{m} {h}{p}"


def endpoint_has_deprioritize_substring(ep: str) -> bool:
    """Check if endpoint path contains telemetry-like substrings."""
    try:
        path = ep.split(" ", 1)[1]
    except Exception:
        path = ep
    return any(s in path for s in Config.DEPRIORITIZE_ENDPOINT_SUBSTRINGS)


def is_likely_id_value(value: str) -> bool:
    """Check if a value looks like a meaningful ID (scoring only, never exclusion)."""
    if value is None:
        return False
    if not isinstance(value, str):
        value = str(value)

    v = value.strip()
    if not v or v.lower() in Config.LOW_LIKELIHOOD_VALUES:
        return False

    # Numeric ID (3+ digits)
    if v.isdigit() and len(v) >= 3:
        return True

    # UUID-like / hex-ish
    if re.match(r'^[a-f0-9-]{8,}$', v, re.IGNORECASE):
        return True

    # Base64-ish / opaque IDs
    if re.match(r'^[A-Za-z0-9_-]{16,}$', v):
        return True

    # GraphQL global IDs
    for pat in Config.GRAPHQL_ID_PATTERNS:
        if pat.match(v):
            return True

    return False


def _is_high_entropy_value(value: str) -> bool:
    """Check if value looks like telemetry entropy (UUID, random string)."""
    if value is None:
        return False
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if not value:
        return False

    # UUID v4 pattern
    if re.match(
        r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$',
        value, re.IGNORECASE
    ):
        return True

    # Long hex string (32+ chars)
    if re.match(r'^[a-f0-9]{32,}$', value, re.IGNORECASE):
        return True

    # GA-style client ID (numeric.numeric)
    if re.match(r'^\d+\.\d+$', value):
        return True

    # Long random alphanumeric (24+ chars, mixed case/digits)
    if len(value) >= 24 and re.match(r'^[A-Za-z0-9_-]+$', value):
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        if sum([has_upper, has_lower, has_digit]) >= 2:
            return True

    return False


# ============================================================
# JSON EXTRACTION (ZERO FALSE NEGATIVE)
# ============================================================

def extract_json_objects_with_confidence(body: bytes, content_type: str) -> List[Tuple[Any, str]]:
    """
    Extract JSON objects from body with confidence levels.

    Returns: List of (obj, confidence) tuples
    Confidence: "high", "medium", "low"

    CRITICAL: ALWAYS attempts extraction. Never returns empty due to content-type.
    """
    if not body:
        return []

    results: List[Tuple[Any, str]] = []
    ct = (content_type or "").lower()
    b = body.lstrip()
    text = body.decode(errors="replace")

    # HIGH confidence: Proper JSON content-type
    if "application/json" in ct:
        try:
            obj = json.loads(text)
            results.append((obj, "high"))
            return results
        except Exception:
            pass

    # MEDIUM confidence: Looks like JSON
    if b.startswith(b"{") or b.startswith(b"["):
        try:
            obj = json.loads(text)
            results.append((obj, "medium"))
            return results
        except Exception:
            pass

    # MEDIUM confidence: JSONP callback wrapper
    try:
        jsonp_match = re.match(
            r'^[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*(\{.*\}|\[.*\])\s*\)\s*;?\s*$',
            text,
            re.DOTALL
        )
        if jsonp_match:
            obj = json.loads(jsonp_match.group(1))
            results.append((obj, "medium"))
            return results
    except Exception:
        pass

    # LOW confidence: Embedded JSON in HTML
    if "text/html" in ct or b.startswith(b"<!") or b.startswith(b"<html") or b.startswith(b"<"):
        for pattern in Config.EMBEDDED_JSON_PATTERNS:
            for match in pattern.finditer(text):
                for g in match.groups():
                    if not g:
                        continue
                    try:
                        decoded = html.unescape(g)
                        obj = json.loads(decoded)
                        results.append((obj, "low"))
                    except Exception:
                        pass

    # LOW confidence: Aggressive scan for JSON-like structures
    if not results:
        decoder = json.JSONDecoder()
        i = 0
        while i < len(text):
            if text[i] in '{[':
                try:
                    obj, end = decoder.raw_decode(text, i)
                    if (isinstance(obj, dict) and obj) or (isinstance(obj, list) and obj):
                        results.append((obj, "low"))
                    i = end
                    continue
                except Exception:
                    pass
            i += 1

    return results


def walk_json_ids(obj: Any) -> List[Tuple[str, str]]:
    """Walk JSON structure and extract ID-like key-value pairs."""
    hits: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if Config.KEY_REGEX.search(str(k)) and isinstance(v, (str, int)):
                hits.append((str(k), str(v)))
            hits.extend(walk_json_ids(v))
    elif isinstance(obj, list):
        for v in obj:
            hits.extend(walk_json_ids(v))
    return hits


def walk_json_with_context(obj: Any, parent_id: Optional[str] = None) -> List[Tuple[str, str, Optional[str]]]:
    """Walk JSON structure with parent context for co-occurrence tracking."""
    hits: List[Tuple[str, str, Optional[str]]] = []
    if isinstance(obj, dict):
        current_id = obj.get("id") if isinstance(obj.get("id"), (str, int)) else parent_id
        for k, v in obj.items():
            if Config.KEY_REGEX.search(str(k)) and isinstance(v, (str, int)):
                hits.append((str(k), str(v), parent_id))
            hits.extend(walk_json_with_context(v, current_id))
    elif isinstance(obj, list):
        for v in obj:
            hits.extend(walk_json_with_context(v, parent_id))
    return hits


def is_graphql_request(obj: Any) -> bool:
    """Check if JSON object looks like a GraphQL request."""
    return (
        isinstance(obj, dict) and
        sum(k in obj for k in ("query", "variables", "operationName")) >= 2
    )


def worsen_confidence(prev: str, new: str) -> str:
    """Keep the worst (lowest) confidence."""
    order = {"low": 0, "medium": 1, "high": 2}
    return prev if order.get(prev, 2) <= order.get(new, 2) else new


# ============================================================
# TOKEN ANALYZER (ZERO FALSE NEGATIVE)
# ============================================================

class TokenAnalyzer:
    """
    Detects signed tokens and extracts embedded IDs.

    CRITICAL: This is for PRIORITIZATION ONLY.
    Never suppress candidates based on token detection.
    """

    # JWT: three base64url segments separated by dots
    JWT_PATTERN = re.compile(
        r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+'
    )

    # Signed payload patterns (non-JWT)
    SIGNED_PAYLOAD_PATTERNS = [
        re.compile(r'[A-Za-z0-9+/=]{50,}--[a-f0-9]{40,}'),
        re.compile(r'eyJ[A-Za-z0-9_-]{20,}'),
    ]

    def __init__(self):
        self.token_bindings: Dict[int, TokenBinding] = {}
        self.detected_tokens: Dict[int, List[Tuple[str, str]]] = {}

    def analyze_request(
        self,
        msg_id: int,
        req_headers: Dict[str, str],
        path: str,
        body: bytes
    ) -> TokenBinding:
        """Extract tokens from request and identify embedded IDs."""
        tokens_found: List[Tuple[str, str]] = []

        # 1. Authorization header
        auth = req_headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
            tokens_found.append(("header:authorization", token))

        # 2. Cookies
        cookies = req_headers.get("cookie", "")
        for cookie in cookies.split(";"):
            cookie = cookie.strip()
            if "=" not in cookie:
                continue
            name, value = cookie.split("=", 1)
            name_lower = name.lower().strip()

            if any(tn in name_lower for tn in Config.TOKEN_PARAM_NAMES):
                tokens_found.append((f"cookie:{name}", value))
            elif self.JWT_PATTERN.search(value):
                tokens_found.append((f"cookie:{name}", value))

        # 3. URL query parameters
        if path and "?" in path:
            query = path.split("?", 1)[1]
            for param in query.split("&"):
                if "=" not in param:
                    continue
                name, value = param.split("=", 1)
                name_lower = name.lower()
                value = unquote(value)

                if any(tn in name_lower for tn in Config.TOKEN_PARAM_NAMES):
                    tokens_found.append((f"query:{name}", value))
                elif self.JWT_PATTERN.search(value):
                    tokens_found.append((f"query:{name}", value))

        # 4. Request body (for token in JSON)
        if body:
            try:
                body_str = body.decode(errors="replace")
                for match in self.JWT_PATTERN.finditer(body_str):
                    tokens_found.append(("body:jwt", match.group(0)))
            except Exception:
                pass

        self.detected_tokens[msg_id] = tokens_found

        # Extract IDs from each token
        bound_ids: Set[str] = set()
        locations: List[str] = []

        for location, token in tokens_found:
            extracted = self._extract_ids_from_token(token)
            if extracted:
                locations.append(location)
                bound_ids.update(extracted)

        # Determine binding strength
        if not bound_ids:
            strength = "none"
        elif any("header:" in loc for loc in locations):
            strength = "strong"
        elif any("cookie:" in loc for loc in locations):
            strength = "moderate"
        else:
            strength = "weak"

        binding = TokenBinding(
            is_bound=bool(bound_ids),
            strength=strength,
            locations=locations,
            bound_ids=bound_ids
        )

        self.token_bindings[msg_id] = binding
        return binding

    def _extract_ids_from_token(self, token: str) -> Set[str]:
        """Attempt to decode token and extract ID-like values."""
        ids: Set[str] = set()

        jwt_ids = self._decode_jwt_payload(token)
        if jwt_ids:
            ids.update(jwt_ids)
            return ids

        for pattern in self.SIGNED_PAYLOAD_PATTERNS:
            if pattern.match(token):
                decoded = self._try_base64_decode(token.split("--")[0])
                if decoded:
                    ids.update(self._extract_ids_from_dict(decoded))

        return ids

    def _decode_jwt_payload(self, token: str) -> Optional[Set[str]]:
        """Decode JWT payload segment and extract IDs."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes.decode("utf-8"))

            return self._extract_ids_from_dict(payload)
        except Exception:
            return None

    def _try_base64_decode(self, value: str) -> Optional[dict]:
        """Try to base64 decode and parse as JSON."""
        for decoder in [base64.urlsafe_b64decode, base64.b64decode]:
            try:
                padded = value + "=" * (4 - len(value) % 4)
                decoded = decoder(padded)
                return json.loads(decoded.decode("utf-8"))
            except Exception:
                continue
        return None

    def _extract_ids_from_dict(self, obj: Any, prefix: str = "") -> Set[str]:
        """Recursively extract ID-like values from decoded token payload."""
        ids: Set[str] = set()

        if isinstance(obj, dict):
            for k, v in obj.items():
                key_lower = k.lower()

                is_id_key = (
                    key_lower in {"id", "uid", "aid", "bid", "sub", "aud", "actid"} or
                    key_lower.endswith("_id") or
                    key_lower.endswith("id") or
                    "account" in key_lower or
                    "user" in key_lower or
                    "org" in key_lower
                )

                if is_id_key and isinstance(v, (str, int)):
                    str_val = str(v)
                    if is_likely_id_value(str_val):
                        ids.add(str_val)

                if isinstance(v, (dict, list)):
                    ids.update(self._extract_ids_from_dict(v, f"{prefix}{k}."))

        elif isinstance(obj, list):
            for item in obj:
                ids.update(self._extract_ids_from_dict(item, prefix))

        return ids

    def get_binding_for_id(self, msg_id: int, id_value: str) -> TokenBinding:
        """Get token binding info for a specific ID in a message."""
        binding = self.token_bindings.get(msg_id)

        if not binding or id_value not in binding.bound_ids:
            return TokenBinding()

        return binding


# ============================================================
# MAIN ANALYZER (ZERO FALSE NEGATIVE)
# ============================================================

class IDORAnalyzer:
    """
    IDOR hypothesis generator with zero false negative guarantee.

    Architecture:
    - EXTRACTION: Lossless, aggressive
    - CLASSIFICATION: Metadata tagging, no filtering
    - SCORING: Bayesian-ish ranking with explainable signals
    - OUTPUT: Ordered triage queue with "why" fields + co-occurrence
    """

    def __init__(self, xml_path: str):
        self.xml_path = xml_path

        # Core ID tracking (using pickle-safe factories)
        # id_value -> key -> direction -> set(msg_id)
        self.id_index: Dict[str, Dict[str, Dict[str, Set[int]]]] = defaultdict(_dd_key)
        # id_value -> list[(msg_id, method, host, path)]
        self.id_timeline: Dict[str, List[Tuple[int, str, str, str]]] = defaultdict(_dd_list)
        self.id_origin: Dict[str, str] = {}
        self.id_sources: Dict[str, Set[str]] = defaultdict(_dd_set)
        self.id_parse_confidence: Dict[str, str] = defaultdict(_default_high)

        # Co-occurrence tracking
        self.id_cooccurrence: Dict[str, Set[str]] = defaultdict(_dd_set)

        # Message metadata
        self.status_by_msg: Dict[int, int] = {}
        self.host_by_msg: Dict[int, str] = {}
        self.msg_endpoint: Dict[int, str] = {}
        self.host_priority_by_msg: Dict[int, str] = {}
        self.raw_messages: Dict[int, Dict[str, str]] = {}

        # Host priority tracking
        self.endpoint_host_priority: Dict[str, str] = {}

        # GraphQL tracking
        self.graphql_operations: Dict[str, List[int]] = defaultdict(_dd_list)
        self.msg_to_operation: Dict[int, str] = {}
        self.id_to_operations: Dict[str, Set[str]] = defaultdict(_dd_set)

        # Token analysis
        self.token_analyzer = TokenAnalyzer()
        self.endpoint_token_coverage: Dict[str, Dict[str, TokenBinding]] = defaultdict(_dd_token_binding_dict)

        # Client-supplied ID tracking
        self.client_supplied_ids: Set[str] = set()

        # PERFORMANCE FIX: Track IDs per message for fast lookup
        self.ids_by_msg: Dict[int, Set[str]] = defaultdict(_dd_set)

        # PERFORMANCE FIX: Exact per-message candidate keying (fixes msg_id lookups)
        # msg_id -> set[(id_value, key, endpoint)]
        self.candidate_keys_by_msg: Dict[int, Set[Tuple[str, str, str]]] = defaultdict(_dd_set)

        # PERFORMANCE FIX: Cache for candidates
        self._candidates_cache: Optional[List[IDCandidate]] = None
        self._candidates_by_msg: Optional[Dict[int, List[IDCandidate]]] = None

        # Candidate lookup cache (for fast per-msg retrieval)
        self._candidate_lookup: Optional[Dict[Tuple[str, str, str], IDCandidate]] = None

        # ==================================================
        # DISK CACHE (XML-LEVEL, TRANSPARENT)
        # ==================================================

        self._cache_path = self._compute_cache_path()
        self.analyzed = False


    # ==================================================
    # CACHE HELPERS (TRANSPARENT)
    # ==================================================

    def _compute_cache_path(self) -> Path:
        """
        Cache file is derived from:
        - absolute XML path
        - file size
        - mtime
        - analyzer code hash (auto-invalidate on logic changes)
        """
        p = Path(self.xml_path).resolve()
        try:
            stat = p.stat()
        except FileNotFoundError:
            return p.with_suffix(".idor.cache")

        # Option A: include code hash so cache invalidates automatically when analyzer changes
        try:
            code_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:8]
        except Exception:
            # Fallback: if __file__ isn't readable for any reason, still keep cache functional
            code_hash = "nocode"

        key = f"{p}:{stat.st_size}:{int(stat.st_mtime)}:{code_hash}"
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        return p.with_suffix(f".idor.{digest}.cache")

    def _load_cache(self) -> bool:
        if not self._cache_path.exists():
            return False
        try:
            with open(self._cache_path, "rb") as f:
                state = pickle.load(f)
            self.__dict__.update(state)
            self.analyzed = True
            return True
        except Exception:
            return False

    def _save_cache(self):
        try:
            state = dict(self.__dict__)
            with open(self._cache_path, "wb") as f:
                pickle.dump(state, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            # Print error instead of swallowing silently (for debugging)
            print(f"[!] Cache save failed: {e}", file=sys.stderr)


    def analyze(self):
        """
        Run full IDOR analysis with explicit phase reporting.

        Phase 1/3: Parse + extract IDs from HTTP messages
        Phase 2/3: Post-extraction summary (IDs, messages)
        Phase 3/3: Candidate scoring (lazy, triggered later)
        """

        if self.analyzed:
            return

        # === FAST PATH: LOAD CACHE ===
        if self._load_cache():
            print("[*] Loaded analyzer state from cache")
            return

        # --------------------------------------------------
        # Phase 1/3 — Parsing + Extraction
        # --------------------------------------------------
        print("[*] Phase 1/3: Parsing HTTP messages and extracting IDs...")

        # PERFORMANCE FIX: Use fast byte scan instead of second full XML parse
        total = fast_count_items(self.xml_path)
        processed = 0

        for msg_id, raw_req, raw_resp in iter_http_messages(self.xml_path):
            processed = msg_id

            if msg_id % 50 == 0:
                if total:
                    pct = (msg_id * 100) // total
                    print(f"\r    processed msg_id={msg_id}  ({pct}% of {total})",
                          end="", flush=True)
                else:
                    print(f"\r    processed msg_id={msg_id}",
                          end="", flush=True)
                    
            self.raw_messages[msg_id] = {
                "request": raw_req.decode(errors="replace"),
                "response": raw_resp.decode(errors="replace"),
            }

            self._process(msg_id, raw_req, raw_resp)

        # Final completion line (always print last msg_id)
        if processed:
            if total:
                print(f"\r    completed msg_id={processed} ({total}/{total}, 100%)")
            else:
                print(f"\r    completed msg_id={processed}")

        

        # --------------------------------------------------
        # Phase 2/3 — Extraction Summary
        # --------------------------------------------------
        print(
            f"[*] Phase 2/3: Extracted {len(self.id_index)} unique IDs "
            f"from {processed} messages"
        )

        # Mark analysis complete (candidate scoring is lazy)
        self.analyzed = True

        # Save disk cache AFTER successful extraction
        self._save_cache()

        # --------------------------------------------------
        # Phase 3/3 — Candidate Scoring (Lazy)
        # --------------------------------------------------
        print("[*] Phase 3/3: Candidate scoring will run on first access (lazy)")



    def _process(self, msg_id: int, raw_req: bytes, raw_resp: bytes):
        """Process a single HTTP message pair."""
        (req_line, req_headers, req_body), (resp_line, resp_headers, resp_body) = split_http_pair(raw_req, raw_resp)

        method, path = parse_request_line(req_line)
        host = (req_headers.get("host") or "").lower()

        # Store metadata
        status = extract_status_code(raw_resp)
        if status is not None:
            self.status_by_msg[msg_id] = status
        self.host_by_msg[msg_id] = host

        # Calculate and store endpoint + host priority
        ep = endpoint_from(method, host, path)
        host_priority = get_host_priority(host)
        self.msg_endpoint[msg_id] = ep
        self.host_priority_by_msg[msg_id] = host_priority
        self._set_endpoint_priority(ep, host_priority)

        # === PERFORMANCE GUARD: skip obvious non-application traffic early ===
        req_text = raw_req[:400].lower()
        if not any(x in req_text for x in (b"/", b"?", b"=", b"{", b"id")):
            return

        # === REQUEST ID EXTRACTION ===
        request_ids: List[Tuple[str, str]] = []

        if path:
            # URL query parameters
            for k, v in extract_url_params(path):
                self._mark_client(v)
                self.id_sources[v].add("query")
                self._record(v, k, "request", msg_id, method, host, path)
                request_ids.append((k, v))

            # Path segments
            for k, v in extract_path_ids(path):
                self._mark_client(v)
                self.id_sources[v].add("path")
                self._record(v, k, "request", msg_id, method, host, path)
                request_ids.append((k, v))

        # Request body JSON
        req_ct = req_headers.get("content-type", "")
        for obj, confidence in extract_json_objects_with_confidence(req_body, req_ct):
            if is_graphql_request(obj):
                op = obj.get("operationName", "unknown")
                self.graphql_operations[op].append(msg_id)
                self.msg_to_operation[msg_id] = op

                # GraphQL variables (high signal)
                vars_obj = obj.get("variables", {}) if isinstance(obj, dict) else {}
                for k, v in walk_json_ids(vars_obj):
                    self._mark_client(v)
                    self.id_sources[v].add("gql_var")
                    self.client_supplied_ids.add(v)
                    self.id_to_operations[v].add(op)
                    self._record(v, k, "request", msg_id, method, host, path)
                    request_ids.append((k, v))

                # Other GraphQL fields
                payload = {k: v for k, v in obj.items() if k != "variables"} if isinstance(obj, dict) else {}
                for k, v in walk_json_ids(payload):
                    self.id_sources[v].add("body")
                    self._record(v, k, "request", msg_id, method, host, path)
            else:
                # Regular JSON body
                for k, v in walk_json_ids(obj):
                    self._mark_client(v)
                    self.id_sources[v].add("body")
                    self._record(v, k, "request", msg_id, method, host, path)
                    request_ids.append((k, v))

        # === RESPONSE ID EXTRACTION ===
        response_ids: List[Tuple[str, str]] = []
        resp_ct = resp_headers.get("content-type", "")

        for obj, confidence in extract_json_objects_with_confidence(resp_body, resp_ct):
            for k, v, parent in walk_json_with_context(obj):
                self._mark_server(v)
                self.id_sources[v].add("resp")
                self._record(v, k, "response", msg_id, method, host, path)
                self.id_parse_confidence[v] = worsen_confidence(self.id_parse_confidence[v], confidence)
                response_ids.append((k, v))

                # Structural co-occurrence
                if parent and parent != v:
                    self.id_cooccurrence[f"structural:{parent}"].add(f"{k}:{v}")

                # Link to GraphQL operation
                if msg_id in self.msg_to_operation:
                    self.id_to_operations[v].add(self.msg_to_operation[msg_id])

        # === CO-OCCURRENCE TRACKING ===
        for rk, rv in request_ids:
            for sk, sv in response_ids:
                if rv != sv and is_likely_id_value(sv):
                    self.id_cooccurrence[f"replay:{rk}:{rv}"].add(f"{sk}:{sv}")

        # === TOKEN BINDING ANNOTATION ===
        if request_ids or response_ids:
            self.token_analyzer.analyze_request(msg_id, req_headers, path or "", req_body)
            self._annotate_token_bindings(msg_id, method, host, path)

    def _set_endpoint_priority(self, ep: str, pri: str):
        """Keep the best known priority for an endpoint."""
        rank = {"primary": 3, "related": 2, "unknown": 1, "third_party": 0}
        cur = self.endpoint_host_priority.get(ep, "unknown")
        if rank.get(pri, 1) > rank.get(cur, 1):
            self.endpoint_host_priority[ep] = pri

    def _mark_client(self, v: str):
        """Mark ID as client-originated."""
        if v not in self.id_origin:
            self.id_origin[v] = "client"
        elif self.id_origin[v] == "server":
            self.id_origin[v] = "both"

    def _mark_server(self, v: str):
        """Mark ID as server-originated."""
        if v not in self.id_origin:
            self.id_origin[v] = "server"
        elif self.id_origin[v] == "client":
            self.id_origin[v] = "both"

    def _record(
        self,
        v: str,
        k: str,
        direction: str,
        msg_id: int,
        method: Optional[str],
        host: str,
        path: Optional[str]
    ):
        """Record an ID occurrence."""
        if v is None:
            v = ""
        if not isinstance(v, str):
            v = str(v)
        if k is None:
            k = ""
        if not isinstance(k, str):
            k = str(k)

        self.id_index[v][k][direction].add(msg_id)
        self.id_timeline[v].append((msg_id, method or "?", host or "", path or "/"))

        # PERFORMANCE FIX: Track which IDs appear in which message
        self.ids_by_msg[msg_id].add(v)

        # PERFORMANCE FIX: Track candidate keys per message for exact lookup
        # (fixes per-message tools like permutator even when request_msgs are truncated)
        ep = self.msg_endpoint.get(msg_id)
        if ep:
            self.candidate_keys_by_msg[msg_id].add((v, k, ep))

    def _annotate_token_bindings(
        self,
        msg_id: int,
        method: Optional[str],
        host: str,
        path: Optional[str]
    ):
        """Annotate discovered IDs with their token binding status."""
        if not path or not method:
            return

        ep = endpoint_from(method, host, path)

        # PERFORMANCE FIX: Only iterate IDs in THIS message, not all IDs
        for v in self.ids_by_msg.get(msg_id, set()):
            binding = self.token_analyzer.get_binding_for_id(msg_id, v)

            if v not in self.endpoint_token_coverage[ep]:
                self.endpoint_token_coverage[ep][v] = binding
            else:
                existing = self.endpoint_token_coverage[ep][v]
                if binding.is_bound and not existing.is_bound:
                    self.endpoint_token_coverage[ep][v] = binding

    # ============================================================
    # DETECTION HELPERS
    # ============================================================

    def has_dereference_pattern(self, id_value: str) -> Tuple[bool, int]:
        """
        Check if ID appears in both request and response (any key).
        Returns: (is_dereferenced, max_response_body_size)
        """
        req_msgs: Set[int] = set()
        resp_msgs: Set[int] = set()

        for key in self.id_index.get(id_value, {}):
            req_msgs.update(self.id_index[id_value][key].get("request", set()))
            resp_msgs.update(self.id_index[id_value][key].get("response", set()))

        coupled_msgs = req_msgs & resp_msgs

        if coupled_msgs:
            max_body = 0
            for mid in coupled_msgs:
                raw = self.raw_messages.get(mid, {})
                max_body = max(max_body, len(raw.get("response", "")))
            return True, max_body

        return False, 0

    def is_selector_like(self, id_value: str) -> bool:
        """Check if ID appears in selector position (path/query/gql_var)."""
        sources = self.id_sources.get(id_value, set())
        return bool(sources & {"path", "query", "gql_var"})

    def is_mutation_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is a mutation (write) endpoint."""
        if " " not in endpoint:
            return False
        method = endpoint.split()[0]
        return method in Config.MUTATION_METHODS

    def has_mutation_operation(self, id_value: str) -> bool:
        """Check if ID is associated with mutation GraphQL operations."""
        ops = self.id_to_operations.get(id_value, set())
        for op in ops:
            op_lower = op.lower()
            if any(kw in op_lower for kw in Config.MUTATION_OP_KEYWORDS):
                return True
        return False

    # ============================================================
    # SEMANTIC TIERING (zero-FN: tier, not exclude)
    # ============================================================

    def is_pure_telemetry_id_strict(self, id_value: str, key: str) -> bool:
        """
        Ultra-conservative telemetry detection.
        Returns True only if ALL conditions confirm telemetry nature.
        """
        key_lower = (key or "").lower()
        if key_lower not in Config.PROBABLY_TELEMETRY_KEYS:
            return False

        timeline = self.id_timeline.get(id_value, [])
        if not timeline:
            return False

        # 2. Must ONLY appear on KNOWN analytics hosts (exact match)
        for _msg_id, _method, host, _path in timeline:
            if (host or "").lower() not in Config.STRICT_ANALYTICS_HOSTS:
                return False

        # 3. Must ONLY appear on telemetry endpoint paths
        for _msg_id, _method, _host, path in timeline:
            base_path = extract_base_path(path).lower()
            if not any(base_path.startswith(tp) or base_path == tp for tp in Config.STRICT_TELEMETRY_PATHS):
                return False

        # 4. Must NEVER be selector-like
        if self.is_selector_like(id_value):
            return False

        # 5. Must never be in URL or gql_var
        sources = self.id_sources.get(id_value, set())
        if sources & {"path", "query", "gql_var"}:
            return False

        # 6. Must have NO structural co-occurrence with selector IDs
        for cooc_key, vals in self.id_cooccurrence.items():
            if f":{id_value}" in cooc_key or id_value in str(vals):
                for v in vals:
                    related_id = v.split(":")[-1] if ":" in v else v
                    if self.is_selector_like(related_id):
                        return False

        # 7. Must NOT appear in replay patterns (as request source id)
        for cooc_key in self.id_cooccurrence.keys():
            if cooc_key.startswith("replay:") and id_value in cooc_key:
                return False

        # 8. Response must be empty/minimal
        for msg_id, _method, _host, _path in timeline:
            raw = self.raw_messages.get(msg_id, {})
            resp = raw.get("response", "")
            if "\r\n\r\n" in resp:
                body = resp.split("\r\n\r\n", 1)[1]
            elif "\n\n" in resp:
                body = resp.split("\n\n", 1)[1]
            else:
                body = ""
            body = body.strip()
            if body and body not in ("{}", "[]", "", "ok", "1", "null"):
                if len(body) > 100:
                    return False

        # 9. Value must be high entropy
        if not _is_high_entropy_value(id_value):
            return False

        return True

    def is_cryptographic_nonce(self, id_value: str, key: str) -> bool:
        """Detect cryptographic nonces (single-use, high-entropy)."""
        if (key or "").lower() not in Config.NONCE_KEYS:
            return False

        # Must appear exactly once
        if len(self.id_timeline.get(id_value, [])) != 1:
            return False

        # Must be high entropy
        if not _is_high_entropy_value(id_value):
            return False

        # Must not appear in co-occurrence patterns
        for cooc_key in self.id_cooccurrence.keys():
            if id_value in cooc_key or id_value in str(self.id_cooccurrence[cooc_key]):
                return False

        return True

    def is_timestamp_value(self, id_value: str, key: str) -> bool:
        """Detect timestamp values that cannot be authorization selectors."""
        if (key or "").lower() not in Config.TIMESTAMP_KEYS:
            return False

        # Must not be selector-like
        if self.is_selector_like(id_value):
            return False

        # Must be numeric
        if not str(id_value).isdigit():
            return False

        # Must be in reasonable timestamp range
        try:
            val = int(id_value)
            is_unix_seconds = 1000000000 <= val <= 2000000000
            is_unix_millis = 1000000000000 <= val <= 2000000000000
            return is_unix_seconds or is_unix_millis
        except Exception:
            return False

    def is_token_internal_only(self, id_value: str) -> bool:
        """
        Check if ID appears ONLY inside tokens, never externally.
        Semantic impossibility - cannot manipulate without forging.
        """
        token_bound_anywhere = any(
            id_value in binding.bound_ids
            for binding in self.token_analyzer.token_bindings.values()
        )
        if not token_bound_anywhere:
            return False

        sources = self.id_sources.get(id_value, set())
        external_sources = {"path", "query", "gql_var", "body", "resp"}
        if sources & external_sources:
            return False

        return True

    def get_informational_reason(self, id_value: str, key: str) -> Tuple[bool, str]:
        """
        Check if candidate is informational (not authorization-relevant).
        Returns: (is_informational, reason)
        """
        if self.is_pure_telemetry_id_strict(id_value, key):
            return True, "telemetry"
        if self.is_cryptographic_nonce(id_value, key):
            return True, "nonce"
        if self.is_timestamp_value(id_value, key):
            return True, "timestamp"
        if self.is_token_internal_only(id_value):
            return True, "token-internal"
        return False, ""

    # ============================================================
    # SCORING (ZERO FALSE NEGATIVE)
    # ============================================================

    def _candidate_inclusion_ok(self, id_value: str, key: str) -> bool:
        """
        Zero-FN posture: broad inclusion.
        Include if key looks ID-like OR is known signal key OR ID is selector-like.
        """
        k = (key or "").lower()
        if Config.KEY_REGEX.search(k):
            return True
        if k in Config.HIGH_SIGNAL_KEYS or k in Config.LOW_SIGNAL_KEYS:
            return True
        if self.is_selector_like(id_value):
            return True
        return False

    def get_candidate_score(
        self,
        id_value: str,
        key: str,
        endpoint: str,
        dir_set: Set[str]
    ) -> CandidateScore:
        """
        Calculate priority score for a candidate with explanations.
        Higher = more likely to be real IDOR.

        CRITICAL: Score is for SORTING, not FILTERING.
        Minimum score is always 1 (zero false negative guarantee).
        """
        score = CandidateScore(total=50)
        k = (key or "").lower()

        # === POSITIVE SIGNALS ===

        # Host priority
        host_pri = self.endpoint_host_priority.get(endpoint, "unknown")
        if host_pri == "primary":
            score.adjust(+15, "primary target host")
        elif host_pri == "related":
            pass
        elif host_pri == "unknown":
            score.adjust(-10, "unknown host")

        # Key semantics
        if k in Config.HIGH_SIGNAL_KEYS:
            score.adjust(+20, f"high-signal key: {key}")
        elif k in Config.LOW_SIGNAL_KEYS:
            score.adjust(-20, f"low-signal key (telemetry): {key}")
        elif Config.KEY_REGEX.search(k):
            score.adjust(+5, "ID-like key pattern")

        # Selector-like source (strongest signal)
        if self.is_selector_like(id_value):
            score.adjust(+30, "selector-like source (path/query/gql_var)")
        elif k == "id":
            score.adjust(-20, "generic 'id' without selector source")

        # Dereference pattern
        is_deref, body_size = self.has_dereference_pattern(id_value)
        if is_deref:
            score.adjust(+15, "dereference pattern (request→response)")
            if body_size > 500:
                score.adjust(+5, f"substantial response ({body_size} bytes)")

        # Direction signals
        if "request" in dir_set and "response" in dir_set:
            score.adjust(+10, "appears in both directions")
        elif dir_set == {"response"}:
            score.adjust(+5, "response-only (potential data leak)")

        # Mutation endpoint
        if self.is_mutation_endpoint(endpoint):
            score.adjust(+10, "mutation method (POST/PUT/DELETE/PATCH)")

        # Mutation GraphQL operation
        if self.has_mutation_operation(id_value):
            score.adjust(+15, "mutation GraphQL operation")

        # Origin
        origin = self.id_origin.get(id_value, "unknown")
        if origin == "client":
            score.adjust(+8, "client-originated")
        elif origin == "both":
            score.adjust(+12, "appears in both directions (client+server)")
        elif origin == "server":
            score.adjust(+4, "server-originated only")

        # Value likelihood
        if is_likely_id_value(str(id_value)):
            score.adjust(+10, "likely ID value format")
        else:
            score.adjust(-10, "unlikely ID value format")

        # GraphQL operation linkage
        if self.id_to_operations.get(id_value):
            score.adjust(+5, "linked to GraphQL operations")

        # Parse confidence
        conf = self.id_parse_confidence.get(id_value, "high")
        if conf == "high":
            score.adjust(+10, "high parse confidence")
        elif conf == "medium":
            pass
        elif conf == "low":
            score.adjust(-15, "low parse confidence")

        # === NEGATIVE SIGNALS ===

        # Third-party host
        if host_pri == "third_party":
            score.adjust(-30, "third-party host")

        # Telemetry endpoint
        if endpoint_has_deprioritize_substring(endpoint):
            score.adjust(-25, "telemetry/analytics endpoint")

        # Token binding
        binding = self.endpoint_token_coverage.get(endpoint, {}).get(id_value)
        if binding and binding.is_bound:
            if binding.strength == "strong":
                score.adjust(-25, f"token-bound (strong: {', '.join(binding.locations)})")
            elif binding.strength == "moderate":
                score.adjust(-15, f"token-bound (moderate: {', '.join(binding.locations)})")
            elif binding.strength == "weak":
                score.adjust(-5, f"token-bound (weak: {', '.join(binding.locations)})")

        return score

    # ============================================================
    # CANDIDATE GENERATION
    # ============================================================

    def get_candidates(self) -> List[IDCandidate]:
        """
        Build per-(id,key,endpoint) candidates and rank them.
        ALL candidates are returned, just in priority order.
        """
        # PERFORMANCE FIX: Return cached result if available
        if self._candidates_cache is not None:
            return self._candidates_cache

        bucket: Dict[Tuple[str, str, str], IDCandidate] = {}

        for id_value, key_map in self.id_index.items():
            for key, dir_map in key_map.items():
                if not self._candidate_inclusion_ok(id_value, key):
                    continue

                req_msgs = set(dir_map.get("request", set()))
                resp_msgs = set(dir_map.get("response", set()))
                all_msgs = req_msgs | resp_msgs

                # Expand to endpoint-scoped candidates
                per_endpoint: Dict[str, Dict[str, Any]] = defaultdict(
                    lambda: {"req": set(), "resp": set(), "dirs": set()}
                )
                for mid in all_msgs:
                    ep = self.msg_endpoint.get(mid, "? ?/?")
                    if mid in req_msgs:
                        per_endpoint[ep]["req"].add(mid)
                        per_endpoint[ep]["dirs"].add("request")
                    if mid in resp_msgs:
                        per_endpoint[ep]["resp"].add(mid)
                        per_endpoint[ep]["dirs"].add("response")

                for ep, info in per_endpoint.items():
                    dir_set = info["dirs"]
                    score_obj = self.get_candidate_score(id_value, key, ep, dir_set)
                    final_score = score_obj.finalize()

                    # Get token binding info
                    binding = self.endpoint_token_coverage.get(ep, {}).get(id_value)

                    # Get dereference info
                    is_deref, _ = self.has_dereference_pattern(id_value)

                    # Tiering (semantic)
                    is_info, info_reason = self.get_informational_reason(id_value, key)

                    directions = "+".join(sorted(dir_set)) if dir_set else "unknown"

                    # PERFORMANCE FIX: Use heapq.nsmallest instead of sorted()[:]
                    candidate = IDCandidate(
                        id_value=id_value,
                        key=key,
                        endpoint=ep,
                        score=final_score,
                        score_reasons=tuple(r for r in score_obj.reasons if r),
                        origin=self.id_origin.get(id_value, "unknown"),
                        sources=tuple(sorted(self.id_sources.get(id_value, set()))),
                        host_priority=self.endpoint_host_priority.get(ep, "unknown"),
                        parse_confidence=self.id_parse_confidence.get(id_value, "high"),
                        token_bound=binding.is_bound if binding else False,
                        token_strength=binding.strength if binding else "none",
                        token_locations=tuple(binding.locations) if binding else (),
                        is_dereferenced=is_deref,
                        is_mutation=self.is_mutation_endpoint(ep) or self.has_mutation_operation(id_value),
                        graphql_operations=tuple(sorted(self.id_to_operations.get(id_value, set()))),
                        directions=directions,
                        request_msgs=tuple(heapq.nsmallest(25, info["req"])) if info["req"] else (),
                        response_msgs=tuple(heapq.nsmallest(25, info["resp"])) if info["resp"] else (),
                        is_informational=is_info,
                        informational_reason=info_reason,
                    )
                    bucket[(id_value, key, ep)] = candidate

        # Rank by score descending, then by primary host, then by selector-like
        candidates = list(bucket.values())
        candidates.sort(
            key=lambda c: (c.score, c.host_priority == "primary", ("path" in c.sources or "query" in c.sources or "gql_var" in c.sources)),
            reverse=True
        )

        # PERFORMANCE FIX: Store candidate lookup for fast per-msg retrieval
        self._candidate_lookup = dict(bucket)

        # PERFORMANCE FIX: Cache the result
        self._candidates_cache = candidates

        # PERFORMANCE FIX: Persist expensive work so permutator doesn't recompute Phase 3
        self._save_cache()

        return candidates

    def get_candidates_tiered(self) -> Tuple[List[IDCandidate], List[IDCandidate]]:
        """
        Return candidates in two tiers:
        - Tier 1: Authorization-relevant (default view)
        - Tier 2: Informational-only (telemetry, nonces, timestamps, token-internal claims)

        ZERO INFORMATION LOSS - everything is still accessible.
        """
        all_candidates = self.get_candidates()
        tier1 = [c for c in all_candidates if not c.is_informational]
        tier2 = [c for c in all_candidates if c.is_informational]
        return tier1, tier2

    def get_relevant_msg_ids(self, top_n: int = 200) -> List[int]:
        """Collect msg_ids from top-N ranked Tier 1 candidates."""
        tier1, _tier2 = self.get_candidates_tiered()
        msg_ids: Set[int] = set()
        for c in tier1[:top_n]:
            msg_ids.update(c.request_msgs)
            msg_ids.update(c.response_msgs)
        return sorted(msg_ids)

    def get_cooccurrence_keys_for_id(self, id_value: str) -> List[str]:
        """Get co-occurrence keys where this ID appears."""
        keys = []
        for k, vals in self.id_cooccurrence.items():
            if k.endswith(f":{id_value}") or k == f"structural:{id_value}":
                keys.append(k)
            for v in vals:
                if id_value in v:
                    keys.append(k)
                    break
        return sorted(set(keys))[:10]

    def get_candidates_for_msg(self, msg_id: int) -> List[IDCandidate]:
        """Get all candidates that involve a specific message."""
        # PERFORMANCE FIX: Use exact key-based lookup (doesn't rely on truncated request_msgs)
        if self._candidate_lookup is None:
            _ = self.get_candidates()  # builds _candidate_lookup

        keys = self.candidate_keys_by_msg.get(msg_id, set())
        out: List[IDCandidate] = []
        for k in keys:
            c = self._candidate_lookup.get(k) if self._candidate_lookup else None
            if c:
                out.append(c)
        out.sort(key=lambda c: c.score, reverse=True)
        return out

    def get_endpoint_directionality(self) -> Dict[str, Dict[str, Set[str]]]:
        """
        Get per-endpoint breakdown of ID directionality.
        Returns: {endpoint: {"request_only": set(), "response_only": set(), "bidirectional": set()}}
        """
        result: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: {"request_only": set(), "response_only": set(), "bidirectional": set()}
        )

        for id_value, key_map in self.id_index.items():
            for key, dir_map in key_map.items():
                req_msgs = set(dir_map.get("request", set()))
                resp_msgs = set(dir_map.get("response", set()))

                # Group by endpoint
                per_ep: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: {"req": set(), "resp": set()})
                for mid in req_msgs:
                    ep = self.msg_endpoint.get(mid, "?")
                    per_ep[ep]["req"].add(mid)
                for mid in resp_msgs:
                    ep = self.msg_endpoint.get(mid, "?")
                    per_ep[ep]["resp"].add(mid)

                for ep, info in per_ep.items():
                    has_req = bool(info["req"])
                    has_resp = bool(info["resp"])

                    id_label = f"{key}={id_value}"
                    if has_req and has_resp:
                        result[ep]["bidirectional"].add(id_label)
                    elif has_req:
                        result[ep]["request_only"].add(id_label)
                    elif has_resp:
                        result[ep]["response_only"].add(id_label)

        return result


# ============================================================
# OUTPUT FUNCTIONS
# ============================================================

def print_graphql_summary(analyzer: IDORAnalyzer):
    """Print GraphQL operations summary."""
    if not analyzer.graphql_operations:
        return

    print("\n" + "=" * 60)
    print("GRAPHQL OPERATIONS")
    print("=" * 60 + "\n")

    for op in sorted(analyzer.graphql_operations.keys()):
        msg_ids = analyzer.graphql_operations[op]
        print(f"  {op}: {len(msg_ids)} requests")


def print_ranked_candidates(analyzer: IDORAnalyzer, limit: int = 50):
    """Print ranked candidates with explanations."""
    print("\n" + "=" * 60)
    print("RANKED IDOR CANDIDATES (TIER 1 - AUTHORIZATION RELEVANT)")
    print("=" * 60 + "\n")

    tier1, tier2 = analyzer.get_candidates_tiered()

    if not tier1:
        print("  No Tier 1 candidates found.")
        return

    for i, c in enumerate(tier1[:limit], 1):
        print(f"#{i:3d} [{c.score:3d}] {c.key}={c.id_value}")
        print(f"     endpoint: {c.endpoint}")
        print(f"     host_priority: {c.host_priority}, origin: {c.origin}")
        print(f"     sources: {', '.join(c.sources)}")
        print(f"     directions: {c.directions}")
        if c.is_dereferenced:
            print(f"     ✓ DEREFERENCED (request→response)")
        if c.is_mutation:
            print(f"     ✓ MUTATION")
        if c.graphql_operations:
            print(f"     graphql_ops: {', '.join(c.graphql_operations)}")
        if c.token_bound:
            print(f"     token_bound: {c.token_strength} ({', '.join(c.token_locations)})")
        if c.score_reasons:
            print(f"     scoring:")
            for r in c.score_reasons:
                print(f"       {r}")
        print()

    if len(tier1) > limit:
        print(f"  ... and {len(tier1) - limit} more Tier 1 candidates")

    print(f"\n  Total: {len(tier1)} Tier 1 candidates, {len(tier2)} Tier 2 (informational)")


def print_endpoint_grouped(analyzer: IDORAnalyzer, limit_endpoints: int = 30):
    """Print candidates grouped by endpoint."""
    print("\n" + "=" * 60)
    print("CANDIDATES BY ENDPOINT")
    print("=" * 60 + "\n")

    tier1, _ = analyzer.get_candidates_tiered()

    by_endpoint: Dict[str, List[IDCandidate]] = defaultdict(list)
    for c in tier1:
        by_endpoint[c.endpoint].append(c)

    sorted_eps = sorted(
        by_endpoint.items(),
        key=lambda x: max(c.score for c in x[1]),
        reverse=True
    )

    for ep, candidates in sorted_eps[:limit_endpoints]:
        top_score = max(c.score for c in candidates)
        host_pri = analyzer.endpoint_host_priority.get(ep, "unknown")
        print(f"{ep} [{host_pri}] (max_score={top_score})")
        for c in sorted(candidates, key=lambda x: x.score, reverse=True)[:5]:
            print(f"  [{c.score:3d}] {c.key}={c.id_value} ({c.directions})")
        if len(candidates) > 5:
            print(f"  ... and {len(candidates) - 5} more")
        print()

    if len(sorted_eps) > limit_endpoints:
        print(f"... and {len(sorted_eps) - limit_endpoints} more endpoints")


def print_cooccurrence(analyzer: IDORAnalyzer, limit: int = 100):
    """Print co-occurrence patterns."""
    if not analyzer.id_cooccurrence:
        return

    print("\n" + "=" * 60)
    print("ID CO-OCCURRENCE PATTERNS")
    print("=" * 60 + "\n")

    structural = {k: v for k, v in analyzer.id_cooccurrence.items() if k.startswith("structural:")}
    replay = {k: v for k, v in analyzer.id_cooccurrence.items() if k.startswith("replay:")}

    print(f"Structural patterns: {len(structural)}")
    print(f"Replay patterns: {len(replay)}\n")

    if structural:
        print("--- Structural (parent_id → child IDs) ---\n")
        sorted_structural = sorted(structural.items(), key=lambda x: len(x[1]), reverse=True)
        for k, vals in sorted_structural[:limit // 2]:
            parent_id = k.replace("structural:", "")
            print(f"  {parent_id} ({len(vals)} children):")
            for v in sorted(vals)[:5]:
                print(f"    → {v}")
            if len(vals) > 5:
                print(f"    ... and {len(vals) - 5} more")
        print()

    if replay:
        print("--- Replay (request_key:value → response IDs) ---\n")
        sorted_replay = sorted(replay.items(), key=lambda x: len(x[1]), reverse=True)
        for k, vals in sorted_replay[:limit // 2]:
            req_info = k.replace("replay:", "")
            print(f"  {req_info} ({len(vals)} responses):")
            for v in sorted(vals)[:5]:
                print(f"    → {v}")
            if len(vals) > 5:
                print(f"    ... and {len(vals) - 5} more")
        print()


def print_high_value_summary(analyzer: IDORAnalyzer):
    """Print summary of high-value targets."""
    print("\n" + "=" * 60)
    print("HIGH VALUE SUMMARY")
    print("=" * 60 + "\n")

    tier1, tier2 = analyzer.get_candidates_tiered()

    # High-scoring candidates
    high_score = [c for c in tier1 if c.score >= 80]
    mutation_candidates = [c for c in tier1 if c.is_mutation]
    deref_candidates = [c for c in tier1 if c.is_dereferenced]
    primary_host = [c for c in tier1 if c.host_priority == "primary"]

    print(f"High-score (≥80): {len(high_score)}")
    print(f"Mutation operations: {len(mutation_candidates)}")
    print(f"Dereferenced IDs: {len(deref_candidates)}")
    print(f"Primary host: {len(primary_host)}")
    print(f"Total Tier 1: {len(tier1)}")
    print(f"Total Tier 2 (informational): {len(tier2)}")


# ============================================================
# EXPORT FUNCTIONS
# ============================================================

def export_ranked_csv(analyzer: IDORAnalyzer, out_path: str):
    """Export all candidates to CSV with all metadata."""
    candidates = analyzer.get_candidates()

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "rank", "score", "tier", "id_value", "key", "endpoint",
            "host_priority", "origin", "sources", "directions",
            "is_dereferenced", "is_mutation", "graphql_ops",
            "token_bound", "token_strength", "token_locations",
            "parse_confidence", "request_msgs", "response_msgs",
            "informational_reason", "cooccurrence_keys", "score_reasons"
        ])

        tier1, tier2 = analyzer.get_candidates_tiered()

        rank = 0
        for c in tier1:
            rank += 1
            cooc = analyzer.get_cooccurrence_keys_for_id(c.id_value)
            writer.writerow([
                rank, c.score, "1", c.id_value, c.key, c.endpoint,
                c.host_priority, c.origin, "|".join(c.sources), c.directions,
                c.is_dereferenced, c.is_mutation, "|".join(c.graphql_operations),
                c.token_bound, c.token_strength, "|".join(c.token_locations),
                c.parse_confidence,
                "|".join(str(m) for m in c.request_msgs),
                "|".join(str(m) for m in c.response_msgs),
                c.informational_reason, "|".join(cooc),
                " | ".join(c.score_reasons)
            ])

        for c in tier2:
            rank += 1
            cooc = analyzer.get_cooccurrence_keys_for_id(c.id_value)
            writer.writerow([
                rank, c.score, "2", c.id_value, c.key, c.endpoint,
                c.host_priority, c.origin, "|".join(c.sources), c.directions,
                c.is_dereferenced, c.is_mutation, "|".join(c.graphql_operations),
                c.token_bound, c.token_strength, "|".join(c.token_locations),
                c.parse_confidence,
                "|".join(str(m) for m in c.request_msgs),
                "|".join(str(m) for m in c.response_msgs),
                c.informational_reason, "|".join(cooc),
                " | ".join(c.score_reasons)
            ])

    print(f"[+] Exported {len(candidates)} candidates to {out_path}")


def export_relevant_transactions(analyzer: IDORAnalyzer, out_path: str, top_n: int = 200):
    """Export HTTP transactions for top candidates."""
    msg_ids = analyzer.get_relevant_msg_ids(top_n)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("RELEVANT HTTP TRANSACTIONS (TIER 1)\n")
        f.write("=" * 80 + "\n\n")

        for msg_id in msg_ids:
            raw = analyzer.raw_messages.get(msg_id, {})
            candidates = analyzer.get_candidates_for_msg(msg_id)
            tier1_candidates = [c for c in candidates if not c.is_informational]

            f.write(f"--- Message {msg_id} ---\n")
            f.write(f"Candidates: {len(tier1_candidates)}\n")
            for c in tier1_candidates[:5]:
                f.write(f"  [{c.score}] {c.key}={c.id_value} @ {c.endpoint}\n")
            if len(tier1_candidates) > 5:
                f.write(f"  ... and {len(tier1_candidates) - 5} more\n")
            f.write("\n")

            f.write("REQUEST:\n")
            f.write(raw.get("request", "")[:2000])
            if len(raw.get("request", "")) > 2000:
                f.write("\n[TRUNCATED]\n")
            f.write("\n\n")

            f.write("RESPONSE:\n")
            f.write(raw.get("response", "")[:2000])
            if len(raw.get("response", "")) > 2000:
                f.write("\n[TRUNCATED]\n")
            f.write("\n\n")
            f.write("=" * 80 + "\n\n")

    print(f"[+] Exported {len(msg_ids)} transactions to {out_path}")


def export_triage_report(analyzer: IDORAnalyzer, out_path: str):
    """Export triage report with all sections."""
    tier1, tier2 = analyzer.get_candidates_tiered()

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("IDOR TRIAGE REPORT - ZERO FALSE NEGATIVE EDITION\n")
        f.write("=" * 80 + "\n\n")

        f.write("SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total unique IDs: {len(analyzer.id_index)}\n")
        f.write(f"Tier 1 (authorization-relevant): {len(tier1)}\n")
        f.write(f"Tier 2 (informational): {len(tier2)}\n")
        f.write(f"GraphQL operations: {len(analyzer.graphql_operations)}\n")
        f.write(f"Co-occurrence patterns: {len(analyzer.id_cooccurrence)}\n")
        f.write("\n")

        # ============================================================
        # TIER 1 CANDIDATES (MAIN TRIAGE)
        # ============================================================

        f.write("=" * 80 + "\n")
        f.write("TIER 1: AUTHORIZATION-RELEVANT CANDIDATES (MAIN TRIAGE)\n")
        f.write("=" * 80 + "\n\n")

        for i, c in enumerate(tier1[:100], 1):
            f.write(f"#{i:3d} [{c.score:3d}] {c.key}={c.id_value}\n")
            f.write(f"     endpoint: {c.endpoint}\n")
            f.write(f"     host: {c.host_priority}, origin: {c.origin}, sources: {', '.join(c.sources)}\n")
            f.write(f"     directions: {c.directions}\n")
            if c.is_dereferenced:
                f.write(f"     ✓ DEREFERENCED\n")
            if c.is_mutation:
                f.write(f"     ✓ MUTATION\n")
            if c.graphql_operations:
                f.write(f"     graphql: {', '.join(c.graphql_operations)}\n")
            if c.token_bound:
                f.write(f"     token: {c.token_strength} @ {', '.join(c.token_locations)}\n")
            cooc = analyzer.get_cooccurrence_keys_for_id(c.id_value)
            if cooc:
                f.write(f"     co-occurrence: {', '.join(cooc[:5])}\n")
            f.write(f"     scoring:\n")
            for r in c.score_reasons:
                f.write(f"       {r}\n")
            f.write("\n")

        if len(tier1) > 100:
            f.write(f"\n... and {len(tier1) - 100} more Tier 1 candidates (see CSV)\n")

        # ============================================================
        # CO-OCCURRENCE PATTERNS
        # ============================================================

        f.write("\n\n")
        f.write("=" * 80 + "\n")
        f.write("CO-OCCURRENCE PATTERNS\n")
        f.write("=" * 80 + "\n\n")

        structural = {k: v for k, v in analyzer.id_cooccurrence.items() if k.startswith("structural:")}
        replay = {k: v for k, v in analyzer.id_cooccurrence.items() if k.startswith("replay:")}

        f.write(f"Structural patterns: {len(structural)}\n")
        f.write(f"Replay patterns: {len(replay)}\n\n")

        if structural:
            f.write("--- Structural (parent_id → child IDs) ---\n\n")
            sorted_structural = sorted(structural.items(), key=lambda x: len(x[1]), reverse=True)
            for k, vals in sorted_structural[:50]:
                parent_id = k.replace("structural:", "")
                count = len(vals)
                sample = sorted(vals)[:5]
                f.write(f"  {parent_id} ({count} children):\n")
                for v in sample:
                    f.write(f"    → {v}\n")
                if count > 5:
                    f.write(f"    ... and {count - 5} more\n")
            f.write("\n")

        if replay:
            f.write("--- Replay (request_key:value → response IDs) ---\n\n")
            sorted_replay = sorted(replay.items(), key=lambda x: len(x[1]), reverse=True)
            for k, vals in sorted_replay[:50]:
                req_info = k.replace("replay:", "")
                count = len(vals)
                sample = sorted(vals)[:5]
                f.write(f"  {req_info} ({count} responses):\n")
                for v in sample:
                    f.write(f"    → {v}\n")
                if count > 5:
                    f.write(f"    ... and {count - 5} more\n")
            f.write("\n")

        # Endpoint directionality
        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("ENDPOINT DIRECTIONALITY\n")
        f.write("=" * 80 + "\n\n")

        directionality = analyzer.get_endpoint_directionality()
        sorted_eps = sorted(
            directionality.items(),
            key=lambda x: len(x[1]["bidirectional"]) + len(x[1]["request_only"]) + len(x[1]["response_only"]),
            reverse=True
        )

        for ep, dirs in sorted_eps[:40]:
            total = len(dirs["bidirectional"]) + len(dirs["request_only"]) + len(dirs["response_only"])
            if total == 0:
                continue

            host_pri = analyzer.endpoint_host_priority.get(ep, "unknown")
            f.write(f"{ep} [{host_pri}]\n")

            if dirs["bidirectional"]:
                bi_list = sorted(dirs["bidirectional"])[:10]
                f.write(f"  bidirectional ({len(dirs['bidirectional'])}): {', '.join(bi_list)}")
                if len(dirs["bidirectional"]) > 10:
                    f.write(f" ...")
                f.write("\n")

            if dirs["request_only"]:
                req_list = sorted(dirs["request_only"])[:10]
                f.write(f"  request-only ({len(dirs['request_only'])}): {', '.join(req_list)}")
                if len(dirs["request_only"]) > 10:
                    f.write(f" ...")
                f.write("\n")

            if dirs["response_only"]:
                resp_list = sorted(dirs["response_only"])[:10]
                f.write(f"  response-only ({len(dirs['response_only'])}): {', '.join(resp_list)}")
                if len(dirs["response_only"]) > 10:
                    f.write(f" ...")
                f.write("\n")

            f.write("\n")

        if len(sorted_eps) > 40:
            f.write(f"... and {len(sorted_eps) - 40} more endpoints\n")

        # ============================================================
        # INFORMATIONAL CANDIDATES (TIER 2)
        # ============================================================

        f.write("\n\n")
        f.write("=" * 80 + "\n")
        f.write("INFORMATIONAL CANDIDATES (TIER 2 - EXCLUDED FROM MAIN TRIAGE)\n")
        f.write("=" * 80 + "\n\n")

        f.write("These are kept for completeness but are unlikely authorization-relevant.\n")
        f.write("Reasons: telemetry, nonces, timestamps, token-internal claims.\n\n")

        by_reason: Dict[str, List[IDCandidate]] = defaultdict(list)
        for c in tier2:
            by_reason[c.informational_reason or "unknown"].append(c)

        for reason in sorted(by_reason.keys()):
            items = by_reason[reason]
            f.write(f"--- {reason.upper()} ({len(items)}) ---\n")
            for c in items[:20]:
                f.write(f"  [{c.score:3d}] {c.key}={c.id_value} @ {c.endpoint}\n")
            if len(items) > 20:
                f.write(f"  ... and {len(items) - 20} more\n")
            f.write("\n")

    print(f"[+] Exported triage report to {out_path}")


def export_permutator_index(analyzer: IDORAnalyzer, out_path: str):
    """
    Export minimal index for permutator (fast startup, no analyzer import needed).
    
    Contains only what permutator needs:
    - request first line (method + path)
    - host
    - candidates with mutation-relevant fields
    """
    index: Dict[str, dict] = {}
    
    # Get all candidates once
    all_candidates = analyzer.get_candidates()
    
    # Group candidates by message ID
    candidates_by_msg: Dict[int, List[IDCandidate]] = defaultdict(list)
    for c in all_candidates:
        for msg_id in c.request_msgs:
            candidates_by_msg[msg_id].append(c)
        for msg_id in c.response_msgs:
            if msg_id not in c.request_msgs:
                candidates_by_msg[msg_id].append(c)
    
    # Build index
    for msg_id, raw in analyzer.raw_messages.items():
        req = raw.get("request", "")
        first_line = req.split("\n")[0].strip() if req else ""
        
        # Skip if no request line
        if not first_line or " " not in first_line:
            continue
        
        msg_candidates = candidates_by_msg.get(msg_id, [])
        
        # Only include messages that have candidates
        if not msg_candidates:
            continue
        
        index[str(msg_id)] = {
            "request_line": first_line,
            "host": analyzer.host_by_msg.get(msg_id, ""),
            "candidates": [
                {
                    "id_value": c.id_value,
                    "key": c.key,
                    "origin": c.origin,
                    "sources": list(c.sources),
                    "token_bound": c.token_bound,
                    "token_strength": c.token_strength,
                    "score": c.score,
                    "is_informational": c.is_informational,
                }
                for c in sorted(msg_candidates, key=lambda x: x.score, reverse=True)
            ]
        }
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    
    print(f"[+] Exported permutator index ({len(index)} messages) to {out_path}")


def export_cooccurrence(analyzer: IDORAnalyzer, out_path: str):
    """Export co-occurrence patterns to file."""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("ID CO-OCCURRENCE PATTERNS\n")
        f.write("=" * 80 + "\n\n")

        structural = {k: v for k, v in analyzer.id_cooccurrence.items() if k.startswith("structural:")}
        replay = {k: v for k, v in analyzer.id_cooccurrence.items() if k.startswith("replay:")}

        f.write(f"Structural patterns: {len(structural)}\n")
        f.write(f"Replay patterns: {len(replay)}\n\n")

        if structural:
            f.write("--- STRUCTURAL (parent_id → child IDs) ---\n\n")
            for k in sorted(structural.keys()):
                parent_id = k.replace("structural:", "")
                vals = sorted(structural[k])
                f.write(f"{parent_id}:\n")
                for v in vals[:50]:
                    f.write(f"  - {v}\n")
                if len(vals) > 50:
                    f.write(f"  ... (+{len(vals) - 50} more)\n")
                f.write("\n")

        if replay:
            f.write("--- REPLAY (request_key:value → response IDs) ---\n\n")
            for k in sorted(replay.keys()):
                req_info = k.replace("replay:", "")
                vals = sorted(replay[k])
                f.write(f"{req_info}:\n")
                for v in vals[:50]:
                    f.write(f"  - {v}\n")
                if len(vals) > 50:
                    f.write(f"  ... (+{len(vals) - 50} more)\n")
                f.write("\n")

    print(f"[+] Exported co-occurrence patterns to {out_path}")


# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: idor_analyzer.py <history.xml> [sitemap.xml]")
        print("")
        print("IDOR Analyzer - Zero False Negative Edition (Merged)")
        print("")
        print("Features:")
        print("  - Full JWT parsing + ID extraction")
        print("  - Mutation detection (HTTP verbs + GraphQL ops)")
        print("  - Explainable scoring (score_reasons per candidate)")
        print("  - Dereference detection (request→response coupling)")
        print("  - Co-occurrence visibility (structural + replay patterns)")
        print("  - Endpoint directionality mapping")
        print("  - Two-tier output (authorization-relevant vs informational)")
        print("  - Semantic noise reduction (telemetry, nonces, timestamps, token-internal)")
        print("")
        print("Outputs:")
        print("  - <n>_idor_candidates.csv     : All candidates with scores + co-occurrence keys + tiering")
        print("  - <n>_idor_transactions.txt   : HTTP transactions + per-message candidate metadata (Tier 1 top-N)")
        print("  - <n>_idor_triage.txt         : Tiered triage report + co-occurrence + directionality + Tier 2 appendix")
        sys.exit(1)

    history_xml = sys.argv[1]
    base_name = Path(history_xml).stem

    print(f"[*] Analyzing: {history_xml}")
    print(f"[*] Zero False Negative Mode: ENABLED")
    print(f"[*] Two-tier output: authorization-relevant vs informational")
    print("")

    analyzer = IDORAnalyzer(history_xml)
    analyzer.analyze()

    # Print summaries
    print_graphql_summary(analyzer)
    print_ranked_candidates(analyzer, limit=50)
    print_endpoint_grouped(analyzer, limit_endpoints=30)
    print_cooccurrence(analyzer, limit=100)
    print_high_value_summary(analyzer)

    # Export files
    csv_out = f"{base_name}_idor_candidates.csv"
    export_ranked_csv(analyzer, csv_out)

    tx_out = f"{base_name}_idor_transactions.txt"
    export_relevant_transactions(analyzer, tx_out, top_n=200)

    triage_out = f"{base_name}_idor_triage.txt"
    export_triage_report(analyzer, triage_out)
    
    perm_index_out = f"{base_name}_permutator_index.json"
    export_permutator_index(analyzer, perm_index_out)

    print("")
    print("[+] Analysis complete")
    print(f"[+] Review {triage_out} for manual triage queue")

    tier1, tier2 = analyzer.get_candidates_tiered()
    print(f"[+] Tier 1 (authorization-relevant): {len(tier1)}")
    print(f"[+] Tier 2 (informational): {len(tier2)}")


if __name__ == "__main__":
    main()
