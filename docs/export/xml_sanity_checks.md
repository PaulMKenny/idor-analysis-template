# XML Sanity Checks (Before Running IDOR Analyzer)

This checklist ensures that a Burp XML export is suitable for
single-session IDOR analysis.

If any check fails, analysis results may be incomplete or misleading.

---

## 1. Export Source

✓ Exported from **Proxy → HTTP history**
✗ Not from Sitemap-only view
✗ Not from Logger++ export alone

Reason:

* Analyzer relies on raw request/response pairs

---

## 2. Request + Response Presence

✓ Each `<item>` contains BOTH:

* `<request>`
* `<response>`

✗ XML with missing `<response>` elements is invalid

Quick check:

```bash
grep -c "<response>" history.xml
```


````md
## 3. Single-User Session

✓ All requests originate from **one authenticated user**  
✗ No account switching mid-session  
✗ No mixed authorization headers

Reason:
- Analyzer assumes all identifiers belong to a single principal
- Mixed-user sessions invalidate origin tracking

Quick checks:
- Search for multiple Authorization headers:
  ```bash
  grep -i "authorization:" history.xml | sort | uniq -c
````

* Search for multiple session cookies:

  ```bash
  grep -i "cookie:" history.xml | sort | uniq -c
  ```

If more than one distinct value appears, the XML is invalid.

This is **non-negotiable** for your analyzer.

---

## 4. Scope Correctness

✓ Only first-party, in-scope domains included
✗ No third-party APIs, CDNs, or analytics endpoints

Reason:

* Out-of-scope traffic introduces false ID propagation
* Noise degrades replay correlation

Required:

* Burp scope configured BEFORE capture
* Scope rules documented in `docs/burp/`

Failure mode:

* IDs appear unrelated to authorization
* Co-occurrence output becomes meaningless

---

## 5. Response Content Sanity

✓ Responses contain structured data (JSON / GraphQL)
✗ Pure static responses only (CSS, images, JS)

Reason:

* Analyzer extracts identifiers from response bodies
* Static-only traffic yields false negatives

Quick check:

```bash
grep -i "content-type" history.xml | grep -E "json|graphql"
```

If no structured responses exist, analysis is not useful.

---

## 6. Encoding Integrity

✓ XML uses base64-encoded request/response bodies
✗ Truncated or malformed base64 data

Reason:

* Analyzer relies on full payload decoding
* Broken encoding causes silent data loss

Quick check:

```bash
grep -c "base64=\"true\"" history.xml
```

Count should be close to the number of <item> elements.

---

```
```
