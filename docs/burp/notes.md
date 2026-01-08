## Scope Contract

Burp scope MUST be configured before capture.

The base filter assumes:

* Only first-party domains are in scope
* Static and CDN traffic is excluded
* All entries have responses

Scope definition lives in `scope.txt`.
Filter logic lives in `base_filter.java`.

Analyzer correctness depends on this contract.