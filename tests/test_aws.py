"""Run with Hisho's venv at the repository's top: ~/code/hisho/.venv/bin/python -m pytest -q"""
from pathlib import Path

from hisho import addon_store, addons

HERE = Path(__file__).resolve().parents[1]


def test_manifest_is_valid_and_readme_matches(addon):
    assert addons.validate_manifest(addon.manifest) == []
    assert addon_store.readme_problems(HERE) == []


def test_no_entries_is_unknown_not_an_alert(addon, ctx_for):
    assert addons.summarize(addon, ctx_for(addon))["state"] in ("unknown", "ok")
    assert addons.provider(addon).summary({}, ctx_for(addon))["state"] == "unknown"
