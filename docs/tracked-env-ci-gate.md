# Tracked dotenv security gate

Security CI runs `python scripts/check_tracked_env_files.py` before the other checks.
It inspects tracked Git paths (including nested directories), rejects `.env`,
`.env.local`, `.env.production` and other `.env.*` variants, and allows
explicitly named `.example`, `.sample` and `.template` files. The check
does not read file contents or disclose secrets. It uses NUL-separated Git
output so paths with whitespace are handled safely.

Run locally with `python scripts/check_tracked_env_files.py`; regression
coverage lives in `tests/test_tracked_env_files.py`. This gate is separate
from Docker build-context exclusions and does not replace them.
