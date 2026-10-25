---
name: Remote browser engine
description: Product expectation for the browser engine used in server-side sessions.
---

Browser testing sessions should run a system-installed Chrome/Chromium or Firefox-class browser engine on the server, rather than treating a bundled automation browser as a user's local browser. Sessions are remote and isolated; they do not inherit the user's device profile.

**Why:** The user clarified that “real browser” means using an installed browser engine on the server for browser testing.

**How to apply:** Keep the remote browser on an installed browser binary when changing session startup. Be clear that it remains server-side and headless; do not add fingerprint spoofing or anti-bot evasion.
