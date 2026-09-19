# BTX — The Cognitive Reserve Layer
## Framework v1.2 · execution and reading map

Start the implementation only after the current v1.1 work has reached its coordinated handoff. Continue that tree and its evidence. This package adds neutral service roles and institutional portfolio interoperability; it does not replace the money, model or capability systems.

## Read the package

1. `docs/01_Cognitive_Reserve_Layer_Strategy.md` explains the opportunity through eight anonymous business scenarios, including a global asset manager and whole-portfolio platform.
2. `docs/02_Neutral_Provider_and_Institutional_Spec.md` is the normative implementation contract. Its operation and type appendices match the supplied schemas.
3. `docs/03_Integration_and_Launch_Guide.md` is a standalone neutral partner guide.
4. `docs/04_Whole_Portfolio_Integration_Guide.md` covers institutional asset masters, positions, valuation, AUM/AUC, look-through and draft instructions.
5. `docs/05_UX_and_Product_Playbook.md` defines the customer experience; `ux/index.html` is an offline prototype.
6. `docs/06_Acceptance_and_Journeys.md` contains 160 new native cases and 20 journeys. All begin NOT_RUN.

Word and PDF reading editions accompany all six documents. Markdown is canonical.

## Execute

Give the existing Cursor coordinator `agents/CURSOR_COORDINATOR_PROMPT.md` or the identical plaintext version. Read `agents/AGENTS.md` first. Preserve old HCP/1 and v1.1 behavior, all actual prior tests and production isolation. New operation count is 43; preserved prior contract count is 84; combined count is 127. There are 18 new signed types.

## Validate this package locally

```sh
python -m pip install -r requirements-reference.txt
python scripts/validate_package.py
python -m unittest discover -s tests -p 'test_reference.py' -v
```

These checks validate supplied reference logic, schema consistency and compatibility artifacts. They do not claim native BTX, custody, OAuth, ML-DSA, browser or external portfolio-platform execution. Native acceptance requires the actual integrated call paths.

## Source and rights discipline

Anonymous scenarios are original analysis informed by the cited business disclosures. Scenario amounts are explicitly illustrative. Full provenance, including source publisher names, is in `research/RESEARCH_REGISTER.md`. No named institution is a production profile, privileged fixture or implemented partner integration.

The new code and fixtures in this package are reference integration material. Third-party source notices in inherited compatibility assets remain unchanged. No production credentials, wallet secrets or font files are included.
