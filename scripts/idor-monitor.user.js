// ==UserScript==
// @name         Live IDOR Monitor
// @namespace    idor.monitor
// @version      0.2.0
// @description  Real-time IDOR candidate detection via fetch/XHR interception
// @match        *://*/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
  if (window.__IDOR_MONITOR__) return;
  window.__IDOR_MONITOR__ = true;

  console.log("[idor-monitor] v0.2.0 started");

  /* =====================
     CONFIG
  ===================== */

  // Matches: id, user_id, userId, userID, accountId, pk, ref, oid, etc.
  const KEY_REGEX = /(?:^|[^a-zA-Z0-9])(id|.*_id|id_.*|.*Id|.*ID|uuid|guid|iid|pk|oid|ref|key|num)(?:$|[^a-zA-Z0-9])/;

  // Path segment ID patterns
  const PATH_ID_RE = /^([0-9]+|[a-f0-9-]{8,}|[A-Za-z0-9_-]{8,})$/i;

  // Numeric ID: 1+ digits (relaxed from 3+)
  const NUMERIC_ID_RE = /^\d+$/;

  // UUID pattern
  const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

  // MongoDB ObjectID (24 hex chars)
  const OBJECTID_RE = /^[a-f0-9]{24}$/i;

  // Snowflake ID (17-19 digits)
  const SNOWFLAKE_RE = /^\d{17,19}$/;

  // Base64-ish (8+ chars)
  const BASE64_ID_RE = /^[A-Za-z0-9_-]{8,}$/;

  // High-signal keys - likely authorization selectors
  const HIGH_SIGNAL_KEYS = new Set([
    // Identity/tenancy
    "user_id", "userid", "account_id", "accountid", "org_id", "orgid",
    "tenant_id", "tenantid", "workspace_id", "workspaceid", "team_id", "teamid",
    "owner_id", "ownerid", "creator_id", "creatorid", "author_id", "authorid",
    // Objects
    "project_id", "projectid", "board_id", "boardid", "item_id", "itemid",
    "ticket_id", "ticketid", "order_id", "orderid", "invoice_id", "invoiceid",
    "document_id", "documentid", "file_id", "fileid", "folder_id", "folderid",
    "message_id", "messageid", "comment_id", "commentid", "post_id", "postid",
    "payment_id", "paymentid", "subscription_id", "subscriptionid",
    "customer_id", "customerid", "agent_id", "agentid", "group_id", "groupid",
    // Common abbreviations
    "uid", "aid", "oid", "pid", "tid", "cid", "fid", "mid",
  ]);

  // Low-signal keys - usually not IDOR targets
  const LOW_SIGNAL_KEYS = new Set([
    "visitor_id", "visitorid", "session_id", "sessionid",
    "anonymous_id", "anonymousid", "device_id", "deviceid",
    "request_id", "requestid", "trace_id", "traceid", "span_id", "spanid",
    "correlation_id", "correlationid", "transaction_id", "transactionid",
    "_ga", "_gid", "_fbp", "_gcl_au", "ajs_anonymous_id",
    "nonce", "csrf", "xsrf", "token_id",
  ]);

  // Telemetry hosts to deprioritize
  const TELEMETRY_HOSTS = new Set([
    "google-analytics.com", "analytics.google.com", "www.google-analytics.com",
    "segment.io", "api.segment.io", "cdn.segment.com",
    "mixpanel.com", "api.mixpanel.com",
    "amplitude.com", "api.amplitude.com",
    "fullstory.com", "rs.fullstory.com",
    "hotjar.com", "vars.hotjar.com",
    "sentry.io", "browser.sentry-cdn.com",
    "datadog.com", "browser-intake-datadoghq.com",
    "newrelic.com", "bam.nr-data.net",
    "intercom.io", "api-iam.intercom.io",
    "heapanalytics.com",
    "logrocket.com", "r.lr-ingest.io",
  ]);

  // Telemetry path patterns
  const TELEMETRY_PATHS = [
    /\/collect\b/, /\/track\b/, /\/analytics\b/, /\/beacon\b/,
    /\/log\b/, /\/metrics\b/, /\/events\b/, /\/pixel\b/,
    /\/j\/collect/, /\/r\/collect/, /\/__tr\b/,
  ];

  // Headers that may contain IDs
  const ID_HEADERS = [
    "x-user-id", "x-account-id", "x-org-id", "x-tenant-id",
    "x-request-id", "x-correlation-id", "x-trace-id",
    "x-customer-id", "x-client-id",
  ];

  /* =====================
     STATE
  ===================== */

  const ID_INDEX = new Map();      // id_value -> { keys, endpoints, directions, scores, ... }
  const MSG_LOG = [];              // chronological request/response log
  const CANDIDATES = new Map();    // (id,key,endpoint) -> candidate object
  const TOKEN_IDS = new Set();     // IDs extracted from JWT tokens
  let MSG_COUNTER = 0;

  /* =====================
     ID VALUE DETECTION
  ===================== */

  function isLikelyId(value) {
    if (value == null) return false;
    const v = String(value).trim();

    // Skip empty and boolean-ish
    if (!v || ["true", "false", "null", "undefined", ""].includes(v.toLowerCase())) {
      return false;
    }

    // Skip very short strings that aren't numeric
    if (v.length < 1) return false;

    // Numeric IDs (any length, but skip -1, 0 as often defaults)
    if (NUMERIC_ID_RE.test(v)) {
      // Accept any positive integer, be cautious with 0, -1
      const num = parseInt(v, 10);
      if (num > 0) return true;
      if (num === 0 || num === -1) return false; // Often defaults
      return true;
    }

    // UUID
    if (UUID_RE.test(v)) return true;

    // MongoDB ObjectID
    if (OBJECTID_RE.test(v)) return true;

    // Snowflake ID
    if (SNOWFLAKE_RE.test(v)) return true;

    // Hex ID (8+ chars, not UUID)
    if (/^[a-f0-9]{8,}$/i.test(v) && !UUID_RE.test(v)) return true;

    // Base64-ish opaque ID (8+ chars)
    if (BASE64_ID_RE.test(v) && v.length >= 8) return true;

    return false;
  }

  function getIdType(value) {
    const v = String(value).trim();
    if (UUID_RE.test(v)) return "uuid";
    if (OBJECTID_RE.test(v)) return "objectid";
    if (SNOWFLAKE_RE.test(v)) return "snowflake";
    if (NUMERIC_ID_RE.test(v)) return "numeric";
    if (/^[a-f0-9]{8,}$/i.test(v)) return "hex";
    if (BASE64_ID_RE.test(v)) return "base64";
    return "unknown";
  }

  /* =====================
     ID EXTRACTION
  ===================== */

  function extractUrlParams(url) {
    const out = [];
    try {
      const u = new URL(url);
      for (const [k, v] of u.searchParams) {
        if (isLikelyId(v) || KEY_REGEX.test(k)) {
          out.push({ key: k, value: v, source: "query" });
        }
      }
    } catch (e) {}
    return out;
  }

  function extractPathIds(url) {
    const out = [];
    try {
      const u = new URL(url);
      const parts = u.pathname.split("/").filter(Boolean);
      for (let i = 0; i < parts.length; i++) {
        const part = decodeURIComponent(parts[i]);
        if (PATH_ID_RE.test(part) && isLikelyId(part)) {
          // Use previous segment as key hint, or "path" if first
          const key = i > 0 ? parts[i - 1] : "<path>";
          out.push({ key, value: part, source: "path" });
        }
      }
    } catch (e) {}
    return out;
  }

  function walkJsonIds(obj, prefix = "", depth = 0) {
    const hits = [];
    if (depth > 15 || !obj || typeof obj !== "object") return hits;

    if (Array.isArray(obj)) {
      obj.forEach((item, idx) => {
        hits.push(...walkJsonIds(item, `${prefix}[${idx}]`, depth + 1));
      });
    } else {
      for (const [k, v] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${k}` : k;

        if (v != null && (typeof v === "string" || typeof v === "number")) {
          const strVal = String(v);
          // Check if key looks like ID field OR value looks like ID
          if (KEY_REGEX.test(k) || isLikelyId(strVal)) {
            if (isLikelyId(strVal)) {
              hits.push({ key: k, value: strVal, source: "body", path: fullKey });
            }
          }
        }

        if (v && typeof v === "object") {
          hits.push(...walkJsonIds(v, fullKey, depth + 1));
        }
      }
    }
    return hits;
  }

  function extractFormData(formData) {
    const out = [];
    if (!(formData instanceof FormData)) return out;

    for (const [k, v] of formData.entries()) {
      if (typeof v === "string" && isLikelyId(v)) {
        out.push({ key: k, value: v, source: "form" });
      }
    }
    return out;
  }

  function extractUrlSearchParams(params) {
    const out = [];
    if (!(params instanceof URLSearchParams)) return out;

    for (const [k, v] of params.entries()) {
      if (isLikelyId(v) || KEY_REGEX.test(k)) {
        out.push({ key: k, value: v, source: "form" });
      }
    }
    return out;
  }

  function extractFromHeaders(headers) {
    const out = [];
    if (!headers) return out;

    const headerObj = headers instanceof Headers
      ? Object.fromEntries(headers.entries())
      : headers;

    for (const [k, v] of Object.entries(headerObj)) {
      const lk = k.toLowerCase();

      // Check known ID headers
      if (ID_HEADERS.includes(lk) && isLikelyId(v)) {
        out.push({ key: k, value: v, source: "header" });
      }

      // Extract IDs from Authorization header (JWT)
      if (lk === "authorization" && v) {
        const tokenIds = extractJwtIds(v);
        tokenIds.forEach(id => {
          TOKEN_IDS.add(id.value);
          out.push({ ...id, source: "token" });
        });
      }
    }

    return out;
  }

  function extractJwtIds(authHeader) {
    const out = [];
    try {
      const token = authHeader.replace(/^Bearer\s+/i, "");
      const parts = token.split(".");
      if (parts.length !== 3) return out;

      // Decode payload (middle part)
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

      for (const [k, v] of Object.entries(payload)) {
        if ((KEY_REGEX.test(k) || ["sub", "aud", "uid"].includes(k)) && isLikelyId(v)) {
          out.push({ key: `jwt.${k}`, value: String(v), source: "token" });
        }
      }
    } catch (e) {}
    return out;
  }

  function extractCookieIds() {
    const out = [];
    try {
      const cookies = document.cookie.split(";");
      for (const cookie of cookies) {
        const [k, v] = cookie.trim().split("=").map(s => s.trim());
        if (k && v && (KEY_REGEX.test(k) || isLikelyId(v))) {
          if (isLikelyId(v)) {
            out.push({ key: k, value: v, source: "cookie" });
          }
        }
      }
    } catch (e) {}
    return out;
  }

  function extractGraphQLIds(body) {
    const out = [];
    try {
      const gql = typeof body === "string" ? JSON.parse(body) : body;

      // Extract from variables
      if (gql.variables && typeof gql.variables === "object") {
        out.push(...walkJsonIds(gql.variables, "gql.variables").map(id => ({
          ...id,
          source: "gql_var"
        })));
      }

      // Detect mutation vs query
      const query = gql.query || gql.mutation || "";
      const isMutation = /^\s*(mutation)\b/i.test(query) ||
        /\b(create|update|delete|remove|add|set|change|move|copy|rename|archive|restore|assign|invite|revoke|approve|reject|publish|enable|disable)\w*\s*\(/i.test(query);

      if (isMutation) {
        out.forEach(id => id.isMutation = true);
      }

    } catch (e) {}
    return out;
  }

  /* =====================
     SCORING
  ===================== */

  function calculateScore(id, key, endpoint, direction, source, opts = {}) {
    let score = 50; // Base score
    const factors = [];

    const lkey = key.toLowerCase();

    // Source bonuses
    if (["path", "query", "gql_var"].includes(source)) {
      score += 30;
      factors.push("+30 selector source");
    }

    // Key signal
    if (HIGH_SIGNAL_KEYS.has(lkey)) {
      score += 20;
      factors.push("+20 high-signal key");
    } else if (LOW_SIGNAL_KEYS.has(lkey)) {
      score -= 20;
      factors.push("-20 low-signal key");
    }

    // Generic 'id' without selector source
    if (lkey === "id" && !["path", "query", "gql_var"].includes(source)) {
      score -= 15;
      factors.push("-15 generic id in body");
    }

    // Mutation method
    if (opts.method && ["POST", "PUT", "DELETE", "PATCH"].includes(opts.method)) {
      score += 10;
      factors.push("+10 mutation method");
    }

    // GraphQL mutation
    if (opts.isMutation) {
      score += 15;
      factors.push("+15 GraphQL mutation");
    }

    // Dereference pattern (both directions)
    if (opts.isDereferenced) {
      score += 15;
      factors.push("+15 dereference pattern");
    }

    // Token-bound penalty
    if (TOKEN_IDS.has(id)) {
      score -= 25;
      factors.push("-25 token-bound");
    }

    // Telemetry penalty
    if (opts.isTelemetry) {
      score -= 25;
      factors.push("-25 telemetry endpoint");
    }

    // Third-party penalty
    if (opts.isThirdParty) {
      score -= 20;
      factors.push("-20 third-party");
    }

    // ID type bonus for well-formed IDs
    const idType = getIdType(id);
    if (["uuid", "objectid", "snowflake"].includes(idType)) {
      score += 5;
      factors.push("+5 well-formed ID");
    }

    // Ensure minimum score of 1
    score = Math.max(1, score);

    return { score, factors };
  }

  function isTelemetryEndpoint(url) {
    try {
      const u = new URL(url);

      // Check host
      if (TELEMETRY_HOSTS.has(u.host) || TELEMETRY_HOSTS.has(u.hostname)) {
        return true;
      }

      // Check path patterns
      for (const re of TELEMETRY_PATHS) {
        if (re.test(u.pathname)) return true;
      }
    } catch (e) {}
    return false;
  }

  function isThirdParty(url) {
    try {
      const u = new URL(url);
      return u.host !== location.host;
    } catch (e) {}
    return false;
  }

  /* =====================
     RECORDING
  ===================== */

  function recordId(id, key, endpoint, direction, msgId, opts = {}) {
    if (!isLikelyId(id)) return;

    if (!ID_INDEX.has(id)) {
      ID_INDEX.set(id, {
        keys: new Set(),
        endpoints: new Set(),
        directions: new Set(),
        sources: new Set(),
        requestMsgs: new Set(),
        responseMsgs: new Set(),
        scores: [],
        isTokenBound: false,
      });
    }

    const entry = ID_INDEX.get(id);
    entry.keys.add(key);
    entry.endpoints.add(endpoint);
    entry.directions.add(direction);
    if (opts.source) entry.sources.add(opts.source);

    if (direction === "request") {
      entry.requestMsgs.add(msgId);
    } else {
      entry.responseMsgs.add(msgId);
    }

    if (TOKEN_IDS.has(id)) {
      entry.isTokenBound = true;
    }

    // Build candidate key
    const candKey = `${id}::${key}::${endpoint}`;
    if (!CANDIDATES.has(candKey)) {
      CANDIDATES.set(candKey, {
        id,
        key,
        endpoint,
        directions: new Set(),
        sources: new Set(),
        firstSeen: msgId,
        scores: [],
        isMutation: false,
        isTelemetry: opts.isTelemetry || false,
        isThirdParty: opts.isThirdParty || false,
      });
    }

    const cand = CANDIDATES.get(candKey);
    cand.directions.add(direction);
    if (opts.source) cand.sources.add(opts.source);
    if (opts.isMutation) cand.isMutation = true;

    // Calculate and store score
    const isDereferenced = cand.directions.has("request") && cand.directions.has("response");
    const { score, factors } = calculateScore(id, key, endpoint, direction, opts.source, {
      ...opts,
      isDereferenced
    });
    cand.scores.push(score);
    cand.maxScore = Math.max(cand.maxScore || 0, score);
    cand.scoreFactors = factors;
  }

  function getEndpoint(method, url) {
    try {
      const u = new URL(url);
      // Normalize path: replace IDs with placeholders
      const basePath = u.pathname
        .replace(/\/\d+/g, "/{id}")
        .replace(/\/[a-f0-9-]{8,}/gi, "/{id}")
        .replace(/\/[A-Za-z0-9_-]{20,}/g, "/{id}");
      return `${method} ${u.host}${basePath}`;
    } catch (e) {
      return `${method} ${url}`;
    }
  }

  /* =====================
     FETCH INTERCEPTION
  ===================== */

  const origFetch = window.fetch;
  window.fetch = async function (input, init = {}) {
    const msgId = ++MSG_COUNTER;
    const method = (init.method || "GET").toUpperCase();
    const url = typeof input === "string" ? input : input.url;
    const endpoint = getEndpoint(method, url);

    const isTelemetry = isTelemetryEndpoint(url);
    const isThirdPartyReq = isThirdParty(url);

    // Extract request IDs from multiple sources
    const reqIds = [
      ...extractUrlParams(url),
      ...extractPathIds(url),
      ...extractFromHeaders(init.headers),
    ];

    // Body IDs based on type
    const body = init.body;
    if (body) {
      if (typeof body === "string") {
        try {
          const json = JSON.parse(body);
          // Check for GraphQL
          if (json.query || json.mutation) {
            reqIds.push(...extractGraphQLIds(json));
          }
          reqIds.push(...walkJsonIds(json));
        } catch (e) {
          // Try form-urlencoded
          try {
            const params = new URLSearchParams(body);
            reqIds.push(...extractUrlSearchParams(params));
          } catch (e2) {}
        }
      } else if (body instanceof FormData) {
        reqIds.push(...extractFormData(body));
      } else if (body instanceof URLSearchParams) {
        reqIds.push(...extractUrlSearchParams(body));
      }
    }

    reqIds.forEach(({ key, value, source, isMutation }) => {
      recordId(value, key, endpoint, "request", msgId, {
        source,
        method,
        isMutation,
        isTelemetry,
        isThirdParty: isThirdPartyReq,
      });
    });

    // Log request
    MSG_LOG.push({
      id: msgId,
      type: "request",
      method,
      url,
      endpoint,
      ids: reqIds,
      timestamp: Date.now(),
      isTelemetry,
      isThirdParty: isThirdPartyReq,
    });

    // Execute
    const response = await origFetch.call(this, input, init);

    // Clone to read body
    const clone = response.clone();

    try {
      const contentType = response.headers.get("content-type") || "";

      if (contentType.includes("application/json") || contentType.includes("text/")) {
        const text = await clone.text();
        let respIds = [];

        try {
          const json = JSON.parse(text);
          respIds = walkJsonIds(json);
        } catch (e) {}

        respIds.forEach(({ key, value, source }) => {
          recordId(value, key, endpoint, "response", msgId, {
            source: source || "body",
            method,
            isTelemetry,
            isThirdParty: isThirdPartyReq,
          });
        });

        // Check for request→response coupling (dereference pattern)
        const reqIdValues = new Set(reqIds.map(r => r.value));
        const respIdValues = new Set(respIds.map(r => r.value));
        const coupled = [...reqIdValues].filter(v => respIdValues.has(v));

        // Find response-only IDs (potential enumeration targets)
        const responseOnly = respIds.filter(r => !reqIdValues.has(r.value));

        if (coupled.length > 0 || reqIds.length > 0 || (responseOnly.length > 0 && !isTelemetry)) {
          logFlow(msgId, method, url, endpoint, reqIds, respIds, coupled, {
            isTelemetry,
            isThirdParty: isThirdPartyReq,
            responseOnly: responseOnly.slice(0, 5),
          });
        }
      }

    } catch (e) {}

    return response;
  };

  /* =====================
     XHR INTERCEPTION
  ===================== */

  const origXHROpen = XMLHttpRequest.prototype.open;
  const origXHRSend = XMLHttpRequest.prototype.send;
  const origXHRSetHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__idor_method = method;
    this.__idor_url = url;
    this.__idor_headers = {};
    return origXHROpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (this.__idor_headers) {
      this.__idor_headers[name] = value;
    }
    return origXHRSetHeader.call(this, name, value);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const msgId = ++MSG_COUNTER;
    const method = (this.__idor_method || "GET").toUpperCase();
    const url = this.__idor_url || "";
    const endpoint = getEndpoint(method, url);
    const headers = this.__idor_headers || {};

    const isTelemetry = isTelemetryEndpoint(url);
    const isThirdPartyReq = isThirdParty(url);

    const reqIds = [
      ...extractUrlParams(url),
      ...extractPathIds(url),
      ...extractFromHeaders(headers),
    ];

    if (body) {
      if (typeof body === "string") {
        try {
          const json = JSON.parse(body);
          if (json.query || json.mutation) {
            reqIds.push(...extractGraphQLIds(json));
          }
          reqIds.push(...walkJsonIds(json));
        } catch (e) {
          try {
            const params = new URLSearchParams(body);
            reqIds.push(...extractUrlSearchParams(params));
          } catch (e2) {}
        }
      } else if (body instanceof FormData) {
        reqIds.push(...extractFormData(body));
      } else if (body instanceof URLSearchParams) {
        reqIds.push(...extractUrlSearchParams(body));
      }
    }

    reqIds.forEach(({ key, value, source, isMutation }) => {
      recordId(value, key, endpoint, "request", msgId, {
        source,
        method,
        isMutation,
        isTelemetry,
        isThirdParty: isThirdPartyReq,
      });
    });

    this.addEventListener("load", function () {
      try {
        let respIds = [];
        const text = this.responseText;
        const contentType = this.getResponseHeader("content-type") || "";

        if (contentType.includes("application/json") || contentType.includes("text/")) {
          try {
            const json = JSON.parse(text);
            respIds = walkJsonIds(json);
          } catch (e) {}

          respIds.forEach(({ key, value, source }) => {
            recordId(value, key, endpoint, "response", msgId, {
              source: source || "body",
              method,
              isTelemetry,
              isThirdParty: isThirdPartyReq,
            });
          });

          const reqIdValues = new Set(reqIds.map(r => r.value));
          const coupled = respIds.filter(r => reqIdValues.has(r.value)).map(c => c.value);
          const responseOnly = respIds.filter(r => !reqIdValues.has(r.value));

          if (coupled.length > 0 || reqIds.length > 0 || (responseOnly.length > 0 && !isTelemetry)) {
            logFlow(msgId, method, url, endpoint, reqIds, respIds, coupled, {
              isTelemetry,
              isThirdParty: isThirdPartyReq,
              responseOnly: responseOnly.slice(0, 5),
            });
          }
        }

      } catch (e) {}
    });

    return origXHRSend.call(this, body);
  };

  /* =====================
     LOGGING
  ===================== */

  function logFlow(msgId, method, url, endpoint, reqIds, respIds, coupled, opts = {}) {
    // Skip telemetry unless it has high-signal keys
    if (opts.isTelemetry) {
      const hasHighSignal = reqIds.some(r => HIGH_SIGNAL_KEYS.has(r.key.toLowerCase()));
      if (!hasHighSignal) return;
    }

    const hasHighSignal = reqIds.some(r => HIGH_SIGNAL_KEYS.has(r.key.toLowerCase()));
    const hasLowSignal = reqIds.every(r => LOW_SIGNAL_KEYS.has(r.key.toLowerCase()));
    const isDeref = coupled.length > 0;
    const hasMutation = reqIds.some(r => r.isMutation);

    // Color coding based on signal
    let color, label;
    if (isDeref && hasHighSignal) {
      color = "color:#ff4444;font-weight:bold";
      label = "HIGH";
    } else if (isDeref) {
      color = "color:#ff8800;font-weight:bold";
      label = "DEREF";
    } else if (hasHighSignal) {
      color = "color:#ffaa00;font-weight:bold";
      label = "SIGNAL";
    } else if (hasMutation) {
      color = "color:#aa88ff";
      label = "MUTATION";
    } else if (hasLowSignal || opts.isTelemetry) {
      color = "color:#666";
      label = "LOW";
    } else {
      color = "color:#00cccc";
      label = "ID";
    }

    const pathOnly = new URL(url).pathname;
    console.group(`%c[${label}] ${method} ${pathOnly}`, color);
    console.log(`msg: ${msgId} | endpoint: ${endpoint}`);

    if (opts.isThirdParty) {
      console.log("%c[third-party]", "color:#888");
    }

    if (reqIds.length) {
      const reqSummary = reqIds.slice(0, 8).map(r => {
        const src = r.source !== "body" ? `[${r.source}]` : "";
        return `${r.key}=${r.value.slice(0, 20)}${src}`;
      }).join(", ");
      console.log("request IDs:", reqSummary);
      if (reqIds.length > 8) console.log(`  ... +${reqIds.length - 8} more`);
    }

    if (respIds.length) {
      console.log("response IDs:", respIds.slice(0, 5).map(r => `${r.key}=${r.value.slice(0, 20)}`).join(", "));
      if (respIds.length > 5) console.log(`  ... +${respIds.length - 5} more`);
    }

    if (isDeref) {
      console.log("%c✓ DEREFERENCE PATTERN", "color:lime;font-weight:bold", coupled);
    }

    if (opts.responseOnly && opts.responseOnly.length > 0) {
      console.log("%c→ Response-only IDs (enum targets):", "color:#88aaff",
        opts.responseOnly.map(r => `${r.key}=${r.value.slice(0, 20)}`).join(", "));
    }

    console.groupEnd();
  }

  /* =====================
     CONSOLE API
  ===================== */

  window.__IDS__ = function (filter) {
    const results = [];
    for (const [id, entry] of ID_INDEX.entries()) {
      if (filter && !id.includes(filter) && ![...entry.keys].some(k => k.includes(filter))) {
        continue;
      }
      results.push({
        id: id.slice(0, 30),
        type: getIdType(id),
        keys: [...entry.keys].slice(0, 3).join(", "),
        directions: [...entry.directions].join("+"),
        sources: [...entry.sources].slice(0, 3).join(","),
        endpoints: entry.endpoints.size,
        requests: entry.requestMsgs.size,
        responses: entry.responseMsgs.size,
        tokenBound: entry.isTokenBound ? "✓" : "",
      });
    }
    results.sort((a, b) => b.requests - a.requests);
    console.table(results.slice(0, 50));
    return results;
  };

  window.__CANDIDATES__ = function (minScore = 0) {
    const results = [];
    for (const [key, c] of CANDIDATES.entries()) {
      const maxScore = c.maxScore || Math.max(...c.scores, 0);
      if (maxScore < minScore) continue;

      const dirs = [...c.directions].join("+");
      const isClientControlled = c.directions.has("request");
      const isDereferenced = c.directions.has("request") && c.directions.has("response");
      const isResponseOnly = c.directions.has("response") && !c.directions.has("request");

      results.push({
        score: maxScore,
        id: c.id.slice(0, 20),
        key: c.key,
        endpoint: c.endpoint.slice(0, 40),
        directions: dirs,
        sources: [...c.sources].join(","),
        deref: isDereferenced ? "✓" : "",
        respOnly: isResponseOnly ? "✓" : "",
        mutation: c.isMutation ? "✓" : "",
      });
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);

    console.table(results.slice(0, 50));
    console.log(`Showing ${Math.min(50, results.length)} of ${results.length} candidates (minScore: ${minScore})`);
    return results;
  };

  window.__ENDPOINTS__ = function () {
    const byEndpoint = new Map();

    for (const [_, c] of CANDIDATES.entries()) {
      if (!byEndpoint.has(c.endpoint)) {
        byEndpoint.set(c.endpoint, {
          ids: 0,
          deref: 0,
          maxScore: 0,
          mutations: 0,
          highSignal: 0,
        });
      }
      const ep = byEndpoint.get(c.endpoint);
      ep.ids++;
      ep.maxScore = Math.max(ep.maxScore, c.maxScore || 0);

      if (c.directions.has("request") && c.directions.has("response")) {
        ep.deref++;
      }
      if (c.isMutation) ep.mutations++;
      if (HIGH_SIGNAL_KEYS.has(c.key.toLowerCase())) ep.highSignal++;
    }

    const results = [...byEndpoint.entries()]
      .map(([ep, stats]) => ({
        endpoint: ep,
        score: stats.maxScore,
        ids: stats.ids,
        deref: stats.deref,
        mutations: stats.mutations,
        highSignal: stats.highSignal,
      }))
      .sort((a, b) => b.score - a.score || b.deref - a.deref);

    console.table(results.slice(0, 30));
    return results;
  };

  window.__TOKEN_IDS__ = function () {
    const ids = [...TOKEN_IDS];
    console.log("IDs extracted from JWT tokens:", ids);
    return ids;
  };

  window.__RESPONSE_ONLY__ = function () {
    const results = [];
    for (const [key, c] of CANDIDATES.entries()) {
      if (c.directions.has("response") && !c.directions.has("request")) {
        results.push({
          id: c.id.slice(0, 20),
          key: c.key,
          endpoint: c.endpoint.slice(0, 50),
          type: getIdType(c.id),
        });
      }
    }
    console.log("%cResponse-only IDs (potential enumeration targets):", "color:orange;font-weight:bold");
    console.table(results.slice(0, 30));
    return results;
  };

  window.__EXPORT_IDOR__ = function () {
    const data = {
      url: location.href,
      timestamp: new Date().toISOString(),
      version: "0.2.0",
      ids: [...ID_INDEX.entries()].map(([id, e]) => ({
        id,
        type: getIdType(id),
        keys: [...e.keys],
        endpoints: [...e.endpoints],
        directions: [...e.directions],
        sources: [...e.sources],
        isTokenBound: e.isTokenBound,
      })),
      candidates: [...CANDIDATES.values()].map(c => ({
        ...c,
        directions: [...c.directions],
        sources: [...c.sources],
      })),
      tokenIds: [...TOKEN_IDS],
      messages: MSG_LOG.length,
    };

    const json = JSON.stringify(data, null, 2);
    console.log(json);

    try {
      navigator.clipboard.writeText(json);
      console.log("%c[EXPORTED] Copied to clipboard", "color:green");
    } catch (e) {
      console.log("%c[EXPORT] Clipboard unavailable, use copy() on returned value", "color:yellow");
    }

    return data;
  };

  window.__CLEAR_IDOR__ = function () {
    ID_INDEX.clear();
    CANDIDATES.clear();
    MSG_LOG.length = 0;
    TOKEN_IDS.clear();
    MSG_COUNTER = 0;
    console.log("[idor-monitor] State cleared");
  };

  window.__IDOR_HELP__ = function () {
    console.log(`
%c[IDOR MONITOR v0.2.0]

%cCommands:%c
  __IDS__(filter?)      - All observed IDs (optional text filter)
  __CANDIDATES__(min?)  - IDOR candidates sorted by score (optional min score)
  __ENDPOINTS__()       - Endpoints ranked by IDOR potential
  __RESPONSE_ONLY__()   - IDs only in responses (enum targets)
  __TOKEN_IDS__()       - IDs extracted from JWT tokens
  __EXPORT_IDOR__()     - Export data as JSON
  __CLEAR_IDOR__()      - Clear state

%cSignal Levels:%c
  HIGH   (red)    = Dereference + high-signal key
  DEREF  (orange) = ID in request AND response
  SIGNAL (yellow) = High-signal key (user_id, etc.)
  MUTATION (purple) = GraphQL mutation
  ID     (cyan)   = Standard ID flow
  LOW    (gray)   = Telemetry/low-signal

%cScoring Factors:%c
  +30 selector source (path/query/gql_var)
  +20 high-signal key | -20 low-signal key
  +15 dereference pattern | +15 GraphQL mutation
  +10 mutation method (POST/PUT/DELETE/PATCH)
  -25 token-bound | -25 telemetry | -20 third-party

%cWorkflow:%c
  1. Browse the app normally
  2. __CANDIDATES__(60) to see high-scoring candidates
  3. __RESPONSE_ONLY__() to find enumeration targets
  4. __ENDPOINTS__() to prioritize endpoints
  5. __EXPORT_IDOR__() to save for deeper analysis
`,
    "color:cyan;font-weight:bold",
    "color:yellow", "color:white",
    "color:lime", "color:white",
    "color:orange", "color:white",
    "color:#88aaff", "color:white"
    );
  };

  // Extract initial cookie IDs
  setTimeout(() => {
    const cookieIds = extractCookieIds();
    if (cookieIds.length > 0) {
      cookieIds.forEach(({ key, value }) => {
        recordId(value, key, "<cookie>", "request", 0, { source: "cookie" });
      });
      console.log(`[idor-monitor] Found ${cookieIds.length} IDs in cookies`);
    }
  }, 100);

  console.log("%c[idor-monitor] Ready. Type __IDOR_HELP__() for commands", "color:gray");

})();
