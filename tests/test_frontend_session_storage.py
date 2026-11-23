"""Browser API-key storage stays session-only and fails soft when blocked."""

from pathlib import Path

APP_CORE = Path("frontend/app-core.js")
TLS_SCRIPT = Path("frontend/tls-investigator.js")


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _assert_storage_access_is_guarded(source: str) -> None:
    assert source.count("window.sessionStorage.getItem") == 1
    assert source.count("const storage = window.sessionStorage") == 1
    assert source.count("storage.setItem") == 1
    assert source.count("storage.removeItem") == 1
    assert source.count("window.sessionStorage.removeItem") == 1
    assert "function readSessionSecret" in source
    assert "function writeSessionSecret" in source
    assert "try {" in source
    assert "catch (_)" in source
    assert "localStorage" not in source


def test_dashboard_key_storage_is_optional_and_never_persistent() -> None:
    source = _source(APP_CORE)
    _assert_storage_access_is_guarded(source)

    assert "key: readSessionSecret('netwatchApiKey')" in source
    assert "return writeSessionSecret('netwatchApiKey', state.key)" in source
    assert "if (state.key && !persisted)" in source
    assert "the key stays in memory only until this page reloads" in source


def test_tls_investigator_key_storage_is_optional_and_never_persistent() -> None:
    source = _source(TLS_SCRIPT)
    _assert_storage_access_is_guarded(source)

    assert "const savedKeyState = readSessionSecret('netwatchApiKey')" in source
    assert "sessionStorageAvailable = writeSessionSecret('netwatchApiKey', key)" in source
    assert "the key remains in memory only until this page reloads" in source
    assert "The key is only in memory and will be lost on reload." in source
