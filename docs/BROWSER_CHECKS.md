# Repeatable browser checks

These tests use Playwright 1.63.0 / Chromium with fictional local data. They are not real-user studies or hosted production tests. Screenshots are written to `tests/screenshots/` (ignored). Set `REVIEW_OUTPUT` to another folder if desired.

Use a separate tooling folder to avoid adding production dependencies:

```sh
npm install --prefix /tmp/project-browser-tools playwright@1.63.0
/tmp/project-browser-tools/node_modules/.bin/playwright install chromium
PLAYWRIGHT_PATH=/tmp/project-browser-tools/node_modules/playwright node tests/browser.cjs
```

On Linux CI the browser install also uses `--with-deps`. Existing GitHub workflows prepare the browser and a local fixture server. New GitHub checks have not run remotely until a push is approved.

Start `node api/tests/local-server.js`, then serve the built `client/dist` at `http://localhost:5173` (for example `python3 -m http.server 5173 --bind 127.0.0.1 --directory client/dist`). The API must be the flagged fictional harness on port 8787. Restart it between suites to avoid deliberately enforced login limits. This browser test uses the SQLite adapter; actual local Workers/D1 is separately verified by the Postman collection.

See `docs/RELEASE_REVIEW.md` for architecture and limitations. Hardware/device checks beyond Chromium viewport emulation remain manual follow-up work.
