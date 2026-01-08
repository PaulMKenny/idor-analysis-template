// --------------------------------------------------
// 1. First-party Intercom scope
// --------------------------------------------------
String url = node.url().toLowerCase();

if (
 !(url.contains("gitlab.com") ||
   url.contains("gitlab.net"))  // Includes analytics, sentry
) {
 return false;
}

// --------------------------------------------------
// 2. Exclude static assets by extension
// --------------------------------------------------
if (
    url.endsWith(".js")   ||
    url.endsWith(".css")  ||
    url.endsWith(".png")  ||
    url.endsWith(".jpg")  ||
    url.endsWith(".jpeg") ||
    url.endsWith(".svg")  ||
    url.endsWith(".woff") ||
    url.endsWith(".woff2")||
    url.endsWith(".ttf")  ||
    url.endsWith(".map")
) {
    return false;
}

// --------------------------------------------------
// 3. Exclude obvious third-party noise
// --------------------------------------------------
if (
    url.contains("google-analytics") ||
    url.contains("googletagmanager") ||
    url.contains("facebook") ||
    url.contains("cloudfront") ||
    url.contains("cdnjs") ||
    url.contains("fonts.googleapis")
) {
    return false;
}

return true;