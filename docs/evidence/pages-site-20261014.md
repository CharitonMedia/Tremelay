# GitHub Pages landing page, 2026-10-14

`gh-pages` commit 3c2572b (index.html, styles.css, .nojekyll; no JavaScript, no external requests).
Pages source `gh-pages` `/`; the build for 3c2572b reported `built`. https://charitonmedia.github.io/Tremelay/
returned the page (title "Tremelay — a local credential broker for AI agents") and styles.css returned 200.

Rendered headless at 1280px and 375px in light and dark (screenshots reviewed by the orchestrator, not
committed): single column, the SVG diagram scales, and no horizontal overflow at 375px. Every link was checked:
the repo and Discussions return 200, the 11 `blob/v1/...` targets exist on v1 (GitHub contents API),
the local stylesheet is present and the `#main` skip anchor resolves. The quickstart and doc links point at
`/blob/v1/`; switch them to `/blob/main/` at launch (marked in an HTML comment at the top of index.html).
