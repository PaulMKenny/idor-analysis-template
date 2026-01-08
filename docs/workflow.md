# IDOR Analysis Workflow (Single Session)

This repository is a TEMPLATE for single-session IDOR analysis.
It is not target-specific and must never contain real target data.

---

## Intended Use

1. Capture a single authenticated user session (User A) in Burp
2. Apply strict scope filtering
3. Export HTTP history as XML
4. Run static analysis to identify:

   * client-controlled identifiers
   * authorization-relevant propagation
   * replay candidates

No exploitation or authorization assumptions are made.

---

## Inputs

* Burp HTTP history XML (single user)
* Optional sitemap XML (scope reference only)

---

## Outputs

* `idor_candidates.csv`
* `idor_relevant_transactions.txt`

Outputs are NEVER committed.

---

## Non-Goals

* No vulnerability confirmation
* No multi-user inference
* No automatic exploitation