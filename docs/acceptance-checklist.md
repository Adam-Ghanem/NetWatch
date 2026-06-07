# Acceptance Checklist

Use this checklist before presenting or handing over NetWatch.

## Repository

- [ ] README opens correctly and shows the banner.
- [ ] Installation steps are clear.
- [ ] Project structure is up to date.
- [ ] Changelog exists.
- [ ] Architecture notes exist.
- [ ] Deployment guide exists.
- [ ] Company handover notes exist.

## Local run

- [ ] Virtual environment can be created.
- [ ] Dependencies install from `requirements.txt`.
- [ ] App starts with `streamlit run app.py`.
- [ ] App opens at `http://localhost:8501`.

## Features

- [ ] Overview page loads.
- [ ] Network Tools page analyzes a private CIDR.
- [ ] Host Check works with a local IP.
- [ ] Network Scan works on an authorized local range.
- [ ] Port Audit shows risk and recommendations.
- [ ] Inventory page displays saved assets.
- [ ] Reports page exports Markdown.
- [ ] Reports page exports HTML.

## Safety

- [ ] Public IP targets are blocked.
- [ ] Large CIDR ranges are blocked.
- [ ] Scan actions require the permission checkbox.
- [ ] No exploitation or credential logic exists.

## Tests

- [ ] `pytest -q` passes.
- [ ] GitHub Actions CI passes.

## Presentation

- [ ] Demo network range is authorized.
- [ ] No sensitive real company IP map is shown publicly.
- [ ] Exported reports are reviewed before sharing.
