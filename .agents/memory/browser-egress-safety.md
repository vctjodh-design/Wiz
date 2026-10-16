---
name: Browser egress safety
description: Security constraint for the remote Chromium browser's outbound network traffic.
---

Every remote Chromium HTTP(S) request must pass through the local egress proxy, which resolves the destination, rejects private or reserved addresses, and connects to the checked IP. Keep browser navigation limited to public web traffic on ports 80 and 443.

**Why:** The browser runs in the hosted application environment. Unrestricted navigation could expose internal services, and validating DNS without pinning the connection leaves a DNS-rebinding gap.

**How to apply:** Preserve the proxy when changing Playwright launch settings, navigation, redirects, or request routing. Any new path to the network must enforce the same policy.
