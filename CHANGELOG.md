# Changelog

## v0.6.0

- Switched the app to an editorial light theme.
- Added oversized hero typography.
- Added paper background with a subtle grid.
- Redesigned metric cards with strong borders and shadow.
- Updated buttons, sidebar and table containers.
- Replaced the README banner with a minimal product-style banner.
- Kept the neutral Risk Advisor wording.

## v0.5.2

- Renamed the advisor feature to Risk Advisor.
- Added `advisory_engine.py`.
- Added `docs/advisory-engine.md`.
- Added `tests/test_advisory_engine.py`.
- Updated app labels and export file names.
- Updated README and security notes with neutral advisor wording.

## v0.5.1

- Added safe text helper for custom Streamlit HTML cards.
- Added safe CSV export helper to reduce spreadsheet formula-injection risk.
- Updated app exports to use sanitized CSV output.
- Updated UI metric cards and custom panels to clean dynamic values before rendering.
- Added security hardening documentation.
- Added tests for safe text and safe CSV helpers.
- Updated README with security notes and v0.5.1 details.

## v0.5.0

- Added local advisory engine.
- Added Risk Advisor page to the Streamlit sidebar.
- Added summary output from scan, port and inventory results.
- Added level explanation, priority findings and suggested next steps.
- Added Markdown export for advisor notes.
- Added advisor documentation.
- Added tests for advisor logic.
- Updated README with advisor integration notes.

## v0.4.0

- Added host profiler with latency, TTL, hostname and OS hint.
- Added raw ping output support for more precise host checks.
- Added service catalog with protocol, description, common role and review guidance.
- Added response time measurement for TCP port checks.
- Added device role hint based on observed open services.
- Updated Streamlit UI to show detailed host and service information.
- Added tests for host output parsing and service catalog logic.
- Updated README with accuracy notes and v0.4.0 feature list.

## v0.3.1

- Added Docker Compose deployment file.
- Added company handover notes.
- Added demo presentation script.
- Added deployment guide.
- Added acceptance checklist.
- Added security review notes.
- Added Kali/fish run guide.
- Added GitHub issue templates for bugs and feature requests.
- Updated README with company-ready documentation section.

## v0.3.0

- Added SQLite-backed local asset inventory.
- Added Inventory page with saved devices, exposure score and open port count.
- Added Network Tools page for CIDR profile, gateway guess, netmask and broadcast address.
- Added risk engine for exposure scoring and top recommendations.
- Added standalone HTML report export.
- Added extra tests for risk scoring, reports and network helper logic.
- Updated README and project structure.

## v0.2.0

- Redesigned Streamlit dashboard with dark interface.
- Added Overview, Reports and Safety pages.
- Added local scan history CSV.
- Added Markdown report generation.
- Updated README with more natural project notes.
- Added report tests.

## v0.1.0

- Initial Streamlit dashboard.
- Added host ping checker.
- Added local CIDR scan.
- Added common port audit.
- Added defensive recommendations.
- Added basic tests and GitHub Actions workflow.
