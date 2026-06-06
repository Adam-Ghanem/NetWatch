# Contributing

Thank you for improving NetWatch.

## Development Setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest
```

## Guidelines

- Keep the project defensive and educational.
- Do not add exploitation, brute-force, malware, stealth, or evasion features.
- Keep scan limits conservative.
- Add tests for validation and security-related logic.
- Update the README when adding features.
