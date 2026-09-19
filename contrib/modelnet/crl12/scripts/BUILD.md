# Rebuilding reading editions

Markdown in docs/ is canonical. `build_documents.py` creates all six Word editions using python-docx and markdown-it-py. Install requirements-documents.txt separately from the reference validation dependencies. Inter and DejaVu Sans Mono were installed in the authoring environment; font files are not distributed. A substitute font may alter pagination.

`rebuild_figures.py` recreates three original charts from the included datasets. Market context and hypothetical commercial calculations are identified in assets/README.md and the research register.

The supplied PDFs were rendered from the final DOCX editions with LibreOffice and inspected as page images. To regenerate locally, convert with an installed office/PDF renderer, then inspect every rendered page. The package does not depend on a private conversion API.

`test_ux_prototype.py` runs selected offline browser interactions using Playwright and Chromium. Set the executable path to your local Chromium installation when different. It loads the HTML directly into a page, without contacting an external host; it does not test a live HCP service or financial adapter.
