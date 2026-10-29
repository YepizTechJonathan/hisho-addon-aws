"""Paste from AWS CloudShell (addon.yaml connect:): the printed line becomes the entry; the pasted text is not kept.
AWS is never called: a stand-in session answers sts get_caller_identity."""
from pathlib import Path

import pytest
import yaml

from hisho import addons, connect

HERE = Path(__file__).resolve().parents[1]
KEY_ID, SECRET, ACCOUNT = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "123456789012"   # AWS's own doc examples
PRINTED = f'{{"AccessKeyId":"{KEY_ID}","SecretAccessKey":"{SECRET}","Account":"{ACCOUNT}"}}'


class Sts:
    def __init__(self, seen, fail_first=0):
        self.seen, self.fail_first = seen, fail_first

    def get_caller_identity(self):
        if self.fail_first:
            self.fail_first -= 1
            raise RuntimeError("InvalidClientTokenId: The security token included in the request is invalid")
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/hisho-readonly"}


@pytest.fixture
def mod(addon, monkeypatch):
    m = addons.provider(addon)
    seen = []
    sts = Sts(seen)

    class Session:
        def client(self, svc, region_name=None, config=None):
            return sts

    def session(entry, ctx):
        seen.append((m.key_id(entry, ctx), ctx.secret(entry["secret_access_key"])))
        return Session()
    monkeypatch.setattr(m, "session", session)
    monkeypatch.setattr(m, "_sleep", lambda s: None)
    m.seen, m.sts = seen, sts
    return m


def test_the_manifest_offers_one_paste_and_its_command_is_the_providers(addon, mod):
    assert addons.validate_manifest(addon.manifest) == []
    c = addon.manifest["connect"]
    assert c["label"] == "Paste from AWS CloudShell" and c["form"] == [] and list(c["fields"]) == ["printed_key"]
    assert c["fields"]["printed_key"]["copy"] == mod.CLOUDSHELL_COMMAND      # shown in a box with a Copy button
    assert mod.CLOUDSHELL_COMMAND in (HERE / "README.md").read_text()
    assert addon.manifest["help"]["access_key_id"]["get"] == "https://console.aws.amazon.com/cloudshell/home"
    for policy in ("SecurityAudit", "job-function/ViewOnlyAccess", "AWSBillingReadOnlyAccess"):
        assert policy in mod.CLOUDSHELL_COMMAND
    assert "delete" not in mod.CLOUDSHELL_COMMAND          # never removes anything (an old key is the owner's call)


@pytest.mark.parametrize("text", [
    PRINTED,
    f'{{\n  "AccessKey": {{\n "UserName": "hisho-readonly", "AccessKeyId": "{KEY_ID}", "Status": "Active",\n'
    f'  "SecretAccessKey": "{SECRET}"}}}}\n{ACCOUNT}',                          # the plain create-access-key output
    f"[cloudshell-user@ip ~]$ ...\n{PRINTED}\n[cloudshell-user@ip ~]$",          # with the prompt around it
    f"{KEY_ID} {SECRET} {ACCOUNT}",                                             # just the three values
])
def test_what_cloudshell_printed_is_read_in_its_usual_shapes(mod, text):
    assert mod.parse_printed(text) == {"access_key_id": KEY_ID, "secret_access_key": SECRET, "account_id": ACCOUNT}


@pytest.mark.parametrize("text", ["", "LimitExceeded: Cannot exceed quota for AccessKeysPerUser: 2", KEY_ID])
def test_no_key_says_what_to_do_and_names_the_two_key_limit(mod, text):
    out = mod.connect({"printed_key": text}, None)
    assert not out["ok"] and "LimitExceeded" in out["explain"] and "two keys" in out["explain"]
    assert SECRET not in str(out)


def test_connect_waits_for_a_brand_new_key_then_returns_the_entry(mod):
    mod.sts.fail_first = 2
    out = mod.connect({"printed_key": PRINTED}, None)
    assert out["ok"] and out["entry"] == {"access_key_id": KEY_ID, "secret_access_key": SECRET, "account_id": ACCOUNT}
    assert mod.seen[-1] == (KEY_ID, SECRET) and len(mod.seen) == 3
    assert SECRET not in out["message"] and KEY_ID not in out["message"]


def test_a_key_that_never_works_is_not_saved(mod):
    mod.sts.fail_first = 99
    out = mod.connect({"printed_key": PRINTED}, None)
    assert not out["ok"] and "wait a moment" in out["explain"] and SECRET not in str(out)


def test_through_core_the_key_becomes_local_secrets_and_the_pasted_text_is_kept_nowhere(addon, mod, fleet):
    out = connect.connect(addon, "main", {"printed_key": PRINTED})
    assert out["ok"], out
    e = addons.read_config("aws")["entries"]["main"]
    # both halves become local secrets (a key ID has no underscore, so Hisho no longer takes it for a secret's name)
    assert e == {"access_key_id": "HISHO_ADDON_AWS_MAIN_ACCESS_KEY_ID",
                 "secret_access_key": "HISHO_ADDON_AWS_MAIN_SECRET_ACCESS_KEY", "account_id": ACCOUNT}
    text = Path(addons.config_path("aws")).read_text()
    assert SECRET not in text and "printed" not in text
    assert Path(addons.LOCAL_SECRETS).read_text().count(SECRET) == 1
    assert yaml.safe_load(text)["entries"]["main"]["account_id"] == ACCOUNT


def test_an_older_entry_with_secret_names_still_resolves_both_halves(mod):
    class Ctx:
        def secret(self, name):
            return {"AWS_MAIN_READONLY_ACCESS_KEY_ID": KEY_ID}[name]
    assert mod.key_id({"access_key_id": "AWS_MAIN_READONLY_ACCESS_KEY_ID"}, Ctx()) == KEY_ID
    assert mod.key_id({"access_key_id": KEY_ID}, Ctx()) == KEY_ID
