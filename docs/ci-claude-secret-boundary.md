# Claude API key pattern check in Security CI

The tracked-file secret boundary check now rejects strings matching
`sk-ant-[A-Za-z0-9_-]{20,}` in Git-tracked text files. It complements the
existing OpenAI key pattern and private dotenv checks. Regression coverage uses
synthetic strings only, not real credentials.

This is a deliberately narrow **pattern check**, not a full secret scanner:
other provider formats, encoded/split secrets, binary files, Git history, and
untracked files may not be detected. False positives are possible for example
strings with the same shape. Never add real keys to test fixtures. If a real key
was committed, revoke/rotate it and follow the incident procedure; removing it
from the current tree alone is insufficient.
