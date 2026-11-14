# Git ignore protection for local dotenv credentials

Git ignores root and nested `.env` and `.env.*` files by default,
including local and production overrides. Explicit `.example`, `.sample`,
and `.template` suffixes remain versionable so documented configuration
examples can be committed.

The regression test `tests/test_dotenv_gitignore.py` invokes Git's own
`check-ignore --no-index` matcher on synthetic filenames. Run it with
`python -m pytest -q tests/test_dotenv_gitignore.py`.

This is an accident-prevention layer, **not** a secret scanner. Git ignore
rules do not untrack already committed files and can be overridden with
`git add -f`. The separate Security CI tracked-file gate in PR #232 is
required to reject forced or previously tracked private dotenv files.
Review template content for secrets before committing it.
