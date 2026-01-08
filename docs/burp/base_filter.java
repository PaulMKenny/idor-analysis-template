// Burp Base Filter
// Purpose: In-scope, response-backed traffic only
// Used for: Single-session IDOR analysis


// --------------------------------------------------
// 0. Must have a response
// --------------------------------------------------
if (requestResponse.response() == null) {
    return false;
}

// --------------------------------------------------
// 1. GitLab first-party scope
// --------------------------------------------------
String url = requestResponse.request().url().toLowerCase();
if (
 !(url.contains("gitlab.com") ||
   url.contains("gitlab.net"))
) {
    return false;
}

// --------------------------------------------------
// 2. Exclude CDN / third-party noise
// --------------------------------------------------
if (
    url.contains("cloudflare") ||
    url.contains("cloudfront") ||
    url.contains("cdn.") ||
    url.contains("gravatar") ||
    url.contains("google") ||
    url.contains("gstatic") ||
    url.contains("cookielaw") ||
    url.contains("onetrust")
) {
    return false;
}

// --------------------------------------------------
// 2.5 Exclude non-auth system endpoints
// --------------------------------------------------
if (
    url.endsWith("/-/health") ||
    url.endsWith("/-/readiness") ||
    url.contains("/-/metrics") ||
    url.contains("/-/liveness")
) {
    return false;
}

// --------------------------------------------------
// Allow GraphQL regardless of MIME
// --------------------------------------------------
if (url.contains("/api/graphql")) {
    return true;
}

// --------------------------------------------------
// 3. Exclude static by MIME
// --------------------------------------------------
String mime = requestResponse.response().mimeType().toString().toLowerCase();
if (
    mime.contains("image") ||
    mime.contains("font") ||
    mime.contains("css") ||
    mime.contains("javascript") ||
    mime.contains("audio") ||
    mime.contains("video")
) {
    return false;
}

return true;
