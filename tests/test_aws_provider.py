"""addons/aws: a fake boto3 session; findings in words; the account pin; costs; the MFA unlock and changes."""
from __future__ import annotations

import datetime as dt
import time
from importlib import util
from pathlib import Path

import pytest

from hisho import addons

spec = util.spec_from_file_location("aws_provider", Path(__file__).resolve().parents[1] / "provider.py")
aws = util.module_from_spec(spec)
spec.loader.exec_module(aws)

ACCOUNT = "123456789012"
ME = f"arn:aws:iam::{ACCOUNT}:user/hisho-readonly"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/hisho-admin"
MFA = f"arn:aws:iam::{ACCOUNT}:mfa/hisho"
ENTRY = {"access_key_id": "AWS_MAIN_READONLY_ACCESS_KEY_ID", "secret_access_key": "AWS_MAIN_READONLY_SECRET_ACCESS_KEY",
         "account_id": ACCOUNT, "regions": "us-east-1,us-west-2", "admin_role_arn": ROLE, "mfa_serial": MFA}
NOW = time.time()


class ClientError(Exception):
    def __init__(self, code: str, msg: str = "no") -> None:
        super().__init__(msg)
        self.response = {"Error": {"Code": code, "Message": msg}}


def _day(days_ago: int) -> str:
    return dt.datetime.fromtimestamp(NOW - days_ago * 86400 - 3600, dt.timezone.utc).isoformat()  # an hour of slack


REPORT = ("user,arn,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,"
          "access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
          f"<root_account>,x,not_supported,{_day(40)},true,false,N/A,N/A,false,N/A,N/A\n"
          f"hisho-readonly,{ME},false,N/A,false,true,{_day(3)},{_day(0)},false,N/A,N/A\n")

TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ME}, "Action": "sts:AssumeRole",
                        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
GUARDS = {"Statement": [
    {"Sid": "NeverBlindTheWatchers", "Effect": "Deny", "Resource": "*",
     "Action": aws.GUARDRAIL_DENIES["NeverBlindTheWatchers"]},
    {"Sid": "NeverTouchBillingOrAccount", "Effect": "Deny", "Resource": "*",
     "Action": aws.GUARDRAIL_DENIES["NeverTouchBillingOrAccount"]},
    {"Sid": "NeverTouchTheCeiling", "Effect": "Deny", "Action": "budgets:ModifyBudget",
     "Resource": f"arn:aws:budgets::{ACCOUNT}:budget/hisho-ceiling"},
    {"Sid": "NeverLoosenItsOwnRules", "Effect": "Deny", "Action": "iam:*", "Resource": [ROLE, ME, MFA]}]}


def answers(over=None):
    """(service, operation) -> answer: a dict, an exception to raise, or fn(kwargs, region)."""
    a = {
        ("sts", "get_caller_identity"): {"Account": ACCOUNT, "Arn": ME},
        ("iam", "list_account_aliases"): {"AccountAliases": ["example-main"]},
        ("iam", "get_account_summary"): {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
        ("iam", "generate_credential_report"): {"State": "COMPLETE"},
        ("iam", "get_credential_report"): {"Content": REPORT.encode()},
        ("iam", "list_attached_user_policies"): {"AttachedPolicies": [{"PolicyName": p} for p in sorted(aws.READONLY_POLICIES)]},
        ("iam", "list_user_policies"): {"PolicyNames": [aws.READONLY_INLINE]},
        ("iam", "get_user_policy"): {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": ROLE}]}},
        ("iam", "list_groups_for_user"): {"Groups": []},
        ("iam", "list_mfa_devices"): {"MFADevices": [{"SerialNumber": MFA}]},
        ("iam", "get_role"): {"Role": {"AssumeRolePolicyDocument": TRUST, "MaxSessionDuration": 3600}},
        ("iam", "list_role_policies"): {"PolicyNames": [aws.GUARDRAILS]},
        ("iam", "list_attached_role_policies"): {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]},
        ("iam", "get_role_policy"): {"PolicyDocument": GUARDS},
        ("cloudtrail", "describe_trails"): {"trailList": [{"Name": "main", "TrailARN": "t1", "HomeRegion": "us-east-1",
                                                           "IsMultiRegionTrail": True, "S3BucketName": "trail-bucket"}]},
        ("cloudtrail", "get_trail_status"): {"IsLogging": True},
        ("s3", "list_buckets"): {"Buckets": [{"Name": "site"}, {"Name": "trail-bucket"}]},
        ("s3control", "get_public_access_block"): {"PublicAccessBlockConfiguration": {
            k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}},
        ("budgets", "describe_budgets"): {"Budgets": [{"BudgetName": "hisho-monthly", "BudgetType": "COST", "TimeUnit": "MONTHLY",
                                                       "BudgetLimit": {"Amount": "25.0", "Unit": "USD"},
                                                       "CalculatedSpend": {"ActualSpend": {"Amount": "3.71", "Unit": "USD"},
                                                                           "ForecastedSpend": {"Amount": "6.2", "Unit": "USD"}}},
                                                      {"BudgetName": "hisho-ceiling", "BudgetType": "COST", "TimeUnit": "MONTHLY",
                                                       "BudgetLimit": {"Amount": "100.0", "Unit": "USD"}}]},
        ("cloudwatch", "describe_alarms"): {"MetricAlarms": []},
        ("route53", "list_hosted_zones"): {"HostedZones": [{"Name": "example.com."}]},
        ("cloudfront", "list_distributions"): {"DistributionList": {"Items": []}},
        ("ec2", "describe_instances"): lambda kw, r: {"Reservations": [{"Instances": [
            {"State": {"Name": "running"}}, {"State": {"Name": "terminated"}}]}] if r == "us-west-2" else []},
        ("ec2", "describe_security_groups"): {"SecurityGroups": []},
        ("lambda", "list_functions"): {"Functions": [{}]},
        ("rds", "describe_db_instances"): {"DBInstances": []},
        ("lightsail", "get_instances"): {"instances": []},
        ("sesv2", "get_account"): {"ProductionAccessEnabled": False, "SendingEnabled": True, "SendQuota": {}},
        ("sesv2", "list_email_identities"): {"EmailIdentities": []},
        ("guardduty", "list_detectors"): {"DetectorIds": ["d1"]},
        ("guardduty", "get_detector"): {"Status": "ENABLED"},
        ("guardduty", "list_findings"): {"FindingIds": []},
        ("securityhub", "describe_hub"): ClientError("InvalidAccessException"),
        ("accessanalyzer", "list_analyzers"): {"analyzers": []},
        ("ce", "get_cost_and_usage"): {"ResultsByTime": [
            {"TimePeriod": {"Start": "2026-09-01"}, "Groups": [
                {"Keys": ["Amazon Route 53"], "Metrics": {"UnblendedCost": {"Amount": "1.02"}}},
                {"Keys": ["Tax"], "Metrics": {"UnblendedCost": {"Amount": "0.001"}}}]},
            {"TimePeriod": {"Start": "2026-10-01"}, "Groups": [
                {"Keys": ["Amazon Route 53"], "Metrics": {"UnblendedCost": {"Amount": "0.51"}}},
                {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "3.20"}}}]}]},
    }
    a.update(over or {})
    return a


class FakeClient:
    def __init__(self, svc, region, table, calls):
        self.svc, self.region, self.table, self.calls = svc, region, table, calls

    def can_paginate(self, op):
        return False

    def __getattr__(self, op):
        def call(**kw):
            self.calls.append((self.svc, op, self.region, kw))
            ans = self.table.get((self.svc, op), {})
            if isinstance(ans, Exception):
                raise ans
            return ans(kw, self.region) if callable(ans) else ans
        return call


class FakeSession:
    def __init__(self, table=None):
        self.table, self.calls = table or answers(), []

    def client(self, svc, region_name=None, config=None):
        return FakeClient(svc, region_name, self.table, self.calls)

    def get_available_regions(self, svc):
        return ["us-east-1", "us-west-2"]


def snap(table=None, entry=ENTRY):
    s = FakeSession(table)
    out = aws.collect(entry, None, s, now=NOW)
    out["cost"] = aws.collect_cost(s, dt.date(2026, 10, 20))
    return out


def keys(sn, entry=ENTRY):
    return {f["key"] for f in aws.findings("main", entry, sn)}


def test_a_healthy_account_has_no_findings_and_reads_everything():
    sn = snap()
    assert sn["errors"] == [] and sn["account"] == {"id": ACCOUNT, "alias": "example-main", "arn": ME}
    assert keys(sn) == set()
    assert sn["by_region"]["us-west-2"]["ec2"] == 1 and sn["by_region"]["us-east-1"]["securityhub"] is False
    assert aws.headline(sn) == "example-main · $3.71 this month · 5 resources"


def test_costs_come_from_one_call_and_split_by_month():
    s = FakeSession()
    c = aws.collect_cost(s, dt.date(2026, 10, 20))
    assert c["this"] == {"Amazon Route 53": 0.51, "Amazon EC2": 3.2} and c["last"] == {"Amazon Route 53": 1.02}
    [(svc, op, _r, kw)] = s.calls
    assert (svc, op) == ("ce", "get_cost_and_usage")
    assert kw["TimePeriod"] == {"Start": "2026-09-01", "End": "2026-10-20"}


def test_keys_of_another_account_are_refused():
    with pytest.raises(aws.WrongAccount, match="not 999999999999"):
        aws.collect({**ENTRY, "account_id": "999999999999"}, None, FakeSession(), now=NOW)


def test_real_problems_say_why_and_titles_have_no_numbers():
    bad_report = REPORT.replace("<root_account>,x,not_supported," + _day(40) + ",true,false",
                                "<root_account>,x,not_supported," + _day(40) + ",false,true")
    bad_report += f"bob,x,true,{_day(1)},false,true,{_day(200)},{_day(150)},false,N/A,N/A\n"
    t = answers({("iam", "get_credential_report"): {"Content": bad_report.encode()},
                   ("cloudtrail", "get_trail_status"): {"IsLogging": False},
                   ("budgets", "describe_budgets"): ClientError("NotFoundException"),
                   ("guardduty", "list_findings"): lambda kw, r: {"FindingIds": ["f1"]} if "Gte" in kw[
                       "FindingCriteria"]["Criterion"]["severity"] and kw["FindingCriteria"]["Criterion"]["severity"]["Gte"] == 7 else {},
                   ("guardduty", "get_findings"): {"Findings": [{"Title": "Bitcoin mining from an EC2 instance"}]}})
    sn = snap(t)
    found = {f["key"]: f for f in aws.findings("main", ENTRY, sn)}
    assert {"root-keys", "root-mfa", "users-mfa", "old-keys", "idle-keys", "cloudtrail", "guardduty-high",
            "no-budget"} <= set(found)
    assert found["root-keys"]["severity"] == "critical" and "bob key 1 (200 days)" in found["old-keys"]["detail"]
    assert "Bitcoin mining" in found["guardduty-high"]["detail"]
    assert not any(ch.isdigit() for f in found.values() for ch in f["title"])


def test_public_bucket_warns_until_marked_on_purpose():
    t = answers({("s3control", "get_public_access_block"): ClientError("NoSuchPublicAccessBlockConfiguration"),
                   ("s3", "get_public_access_block"): ClientError("NoSuchPublicAccessBlockConfiguration"),
                   ("s3", "get_bucket_location"): {"LocationConstraint": None},
                   ("s3", "get_bucket_policy_status"): lambda kw, r: {"PolicyStatus": {"IsPublic": kw["Bucket"] == "site"}},
                   ("s3", "get_bucket_acl"): {"Grants": []}})
    sn = snap(t)
    assert sn["s3"]["public"] == [{"name": "site", "why": "its bucket policy lets anyone read it"}]
    assert "s3-public" in keys(sn) and "s3-public" not in keys(sn, {**ENTRY, "public_ok": "site"})


def test_spending_jump_and_budget():
    sn = snap()
    sn["cost"] = {"at": NOW, "this": {"Amazon EC2": 80.0}, "last": {"Amazon EC2": 4.0}}
    assert {"cost-jump", "over-budget"} <= keys(sn, {**ENTRY, "budget_usd": 50})


def test_the_admin_role_and_the_readonly_user_are_watched():
    loose = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": [ME, "arn:aws:iam::111122223333:root"]},
                            "Action": "sts:AssumeRole"}]}
    guards = {"Statement": [s for s in GUARDS["Statement"] if s["Sid"] != "NeverBlindTheWatchers"]}
    t = answers({("iam", "get_role"): {"Role": {"AssumeRolePolicyDocument": loose, "MaxSessionDuration": 43200}},
                   ("iam", "get_role_policy"): {"PolicyDocument": guards},
                   ("iam", "list_attached_user_policies"): {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}})
    found = {f["key"]: f for f in aws.findings("main", ENTRY, snap(t))}
    assert {"admin-mfa", "admin-others", "admin-guardrails", "admin-session", "readonly-extra"} <= set(found)
    assert "statement NeverBlindTheWatchers" in found["admin-guardrails"]["detail"]
    assert "111122223333" in found["admin-others"]["detail"]
    assert "policy AdministratorAccess" in found["readonly-extra"]["detail"]
    gone = answers({("iam", "get_role"): ClientError("NoSuchEntity")})
    assert "admin-missing" in keys(snap(gone))


def test_guardrails_notice_a_dropped_action():
    doc = {"Statement": [dict(s) for s in GUARDS["Statement"]]}
    doc["Statement"][0]["Action"] = [a for a in doc["Statement"][0]["Action"] if a != "cloudtrail:StopLogging"]
    assert aws.check_guardrails(doc, [ROLE, ME, MFA]) == ["NeverBlindTheWatchers no longer denies cloudtrail:StopLogging"]
    assert aws.check_guardrails(GUARDS, [ROLE, ME, MFA]) == []


def test_summary_and_details_read_the_kept_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("HISHO_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(aws, "_cache", {})
    started = []
    monkeypatch.setattr(aws, "refresh_soon", lambda *a, **k: started.append(a[0]) or True)
    first = aws.summary({"main": ENTRY}, None)
    assert first["state"] == "unknown" and started == ["main"]
    aws._save("main", {**snap(), "at": time.time()})
    assert aws.summary({"main": ENTRY}, None)["state"] == "ok" and started == ["main"]
    titles = [s["title"] for s in aws.details({"main": ENTRY}, None)]
    assert titles == [f"example-main ({ACCOUNT})", "Security", "Changes (hisho-admin)"]
    assert (tmp_path / "addons" / "aws" / "main.json").stat().st_mode & 0o777 == 0o600


def test_a_failed_read_keeps_the_last_good_one_and_waits(tmp_path, monkeypatch):
    monkeypatch.setenv("HISHO_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(aws, "_cache", {})
    aws._save("main", {**snap(), "at": time.time() - 7 * 3600})
    t = answers({("sts", "get_caller_identity"): ClientError("InvalidClientTokenId", "bad key")})
    out = aws.refresh("main", ENTRY, None, s=FakeSession(t))
    assert "account" in out and "bad key" in out["failed"]
    assert not aws.due(ENTRY, out, time.time() + 60) and aws.due(ENTRY, out, time.time() + aws.RETRY_AFTER + 1)
    [p] = aws.summary({"main": ENTRY}, None)["problems"][:1]
    assert p["key"] == "unreadable"


def test_the_test_button_pins_the_account():
    class Ctx:
        def secret(self, name):
            return "x"
    orig = aws.session
    aws.session = lambda entry, ctx: FakeSession()
    try:
        res = aws.test({k: v for k, v in ENTRY.items() if k != "account_id"}, Ctx())
        assert res["ok"] and res["fill"] == {"account_id": ACCOUNT}
        assert not aws.test({**ENTRY, "account_id": "999999999999"}, Ctx())["ok"]
    finally:
        aws.session = orig


# ── changes ─────────────────────────────────────────────────────────────────

def _assume(kw, region):
    assert kw["SerialNumber"] == MFA and kw["DurationSeconds"] == 3600 and kw["RoleArn"] == ROLE
    if kw["TokenCode"] != "123456":
        raise ClientError("AccessDenied", "MultiFactorAuthentication failed")
    return {"Credentials": {"AccessKeyId": "ASIA", "SecretAccessKey": "s", "SessionToken": "t",
                            "Expiration": dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)},
            "AssumedRoleUser": {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/hisho-admin/hisho-main"}}


def test_unlock_needs_a_good_code_and_keeps_credentials_in_memory_only(tmp_path, monkeypatch):
    journal = []
    monkeypatch.setattr(aws, "_journal", journal.append)
    monkeypatch.setattr(aws, "_unlocked", {})
    s = FakeSession(answers({("sts", "assume_role"): _assume}))
    assert not aws.unlock("main", ENTRY, None, "12345", s)["ok"]
    assert "wrong or used code" in aws.unlock("main", ENTRY, None, "654321", s)["error"]
    assert aws.unlocked("main") is None
    res = aws.unlock("main", ENTRY, None, "123 456", s)
    assert res["ok"] and "until" in res["message"] and "ASIA" not in str(res)
    assert aws.unlocked("main") and "ASIA" not in str(journal)
    assert not list(tmp_path.iterdir())
    assert aws.lock("main")["message"] == "Locked." and aws.unlocked("main") is None


def test_unlock_refuses_a_role_in_another_account(monkeypatch):
    monkeypatch.setattr(aws, "_journal", lambda m: None)
    monkeypatch.setattr(aws, "_unlocked", {})

    def other(kw, region):
        r = _assume(kw, region)
        r["AssumedRoleUser"]["Arn"] = "arn:aws:sts::999999999999:assumed-role/hisho-admin/x"
        return r
    assert not aws.unlock("main", ENTRY, None, "123456", FakeSession(answers({("sts", "assume_role"): other})))["ok"]
    assert aws.unlocked("main") is None


def test_a_change_is_refused_while_locked_and_journaled_when_done(monkeypatch):
    journal = []
    monkeypatch.setattr(aws, "_journal", journal.append)
    monkeypatch.setattr(aws, "_unlocked", {})
    res = aws.write("main", ENTRY, "write-test", {})
    assert not res["ok"] and "locked" in res["error"] and "Nothing was changed" in res["error"]
    s = FakeSession()
    res = aws.write("main", ENTRY, "write-test", {}, s=s)
    [(svc, op, region, kw)] = s.calls
    assert res["ok"] and (svc, op, region) == ("ssm", "put_parameter", "us-west-2")
    assert kw["Name"] == "/hisho/last-unlock-test" and kw["Tier"] == "Standard" and kw["Overwrite"] and "Tags" not in kw
    assert journal[-1]["ok"] and "/hisho/last-unlock-test" in journal[-1]["plan"]


def test_the_changes_section_offers_unlock_then_lock_and_plans(monkeypatch):
    monkeypatch.setattr(aws, "_unlocked", {})
    sn = snap()
    [item] = aws.admin_section("main", ENTRY, sn)["items"]
    assert [a["id"] for a in item["actions"]] == ["unlock"] and item["actions"][0]["ask"] == aws.UNLOCK_ASK
    aws._unlocked["main"] = {"creds": {}, "until": time.time() + 1800, "arn": ""}
    [item] = aws.admin_section("main", ENTRY, sn)["items"]
    assert [a["id"] for a in item["actions"]] == ["lock", "budget-amount", "write-test"]
    assert item["actions"][-1]["confirm"].startswith("This changes AWS: Set the SSM Parameter Store parameter")
    assert item["facts"][0].startswith("unlocked until")
    assert set(aws.CORE_ACTIONS) == {"unlock", "lock", "write-test", "cloudtrail-on", "budget-amount"}


def test_unlock_through_act_hides_the_typed_code(monkeypatch):
    monkeypatch.setattr(aws, "unlock", lambda *a: {"ok": False, "error": "no"})

    class Ctx:
        input = "123456"
    assert aws.act({"main": ENTRY}, Ctx(), "main", "admin", "unlock")["hide_input"] is True



# ── CloudTrail and budget buttons ───────────────────────────────────────────

def test_cloudtrail_on_makes_a_private_bucket_and_a_trail_in_the_west():
    s = FakeSession()
    msg = aws._trail_run(s, ENTRY)
    calls = [(svc, op, region) for svc, op, region, _kw in s.calls if svc != "sts"]
    bucket = f"hisho-cloudtrail-{ACCOUNT}-us-west-2"
    assert calls == [("s3", op, "us-west-2") for op in ("create_bucket", "put_public_access_block", "put_bucket_encryption",
                                                         "put_bucket_policy", "put_bucket_lifecycle_configuration")] + [
        ("cloudtrail", "create_trail", "us-west-2"), ("cloudtrail", "start_logging", "us-west-2")]
    kw = {op: k for svc, op, _r, k in s.calls}
    assert kw["create_bucket"]["Bucket"] == bucket
    assert all(kw["put_public_access_block"]["PublicAccessBlockConfiguration"].values())
    import json as _json
    policy = _json.loads(kw["put_bucket_policy"]["Policy"])
    assert {st["Principal"]["Service"] for st in policy["Statement"]} == {"cloudtrail.amazonaws.com"}
    assert all(st["Condition"]["StringEquals"]["aws:SourceArn"] == f"arn:aws:cloudtrail:us-west-2:{ACCOUNT}:trail/hisho-trail"
               for st in policy["Statement"])
    assert kw["put_bucket_lifecycle_configuration"]["LifecycleConfiguration"]["Rules"][0]["Expiration"] == {"Days": 365}
    assert kw["create_trail"]["IsMultiRegionTrail"] and kw["create_trail"]["EnableLogFileValidation"]
    assert bucket in msg and "hisho-trail" in aws._trail_plan(ENTRY, {})


def test_cloudtrail_on_can_run_again():
    s = FakeSession(answers({("s3", "create_bucket"): ClientError("BucketAlreadyOwnedByYou"),
                             ("cloudtrail", "create_trail"): ClientError("TrailAlreadyExistsException")}))
    assert "recording" in aws._trail_run(s, ENTRY)
    assert s.calls[-1][1] == "start_logging"


def test_buttons_only_show_while_needed(monkeypatch):
    monkeypatch.setattr(aws, "_unlocked", {"main": {"creds": {}, "until": time.time() + 1800, "arn": ""}})
    sn = snap()   # a logging trail and a budget: neither button
    ids = [a["id"] for a in aws.admin_section("main", ENTRY, sn)["items"][0]["actions"]]
    assert ids == ["lock", "budget-amount", "write-test"]
    sn["trails"], sn["billing"] = [], {"budgets": [], "budget_details": [], "alarms": []}
    ids = [a["id"] for a in aws.admin_section("main", ENTRY, sn)["items"][0]["actions"]]
    assert ids == ["lock", "cloudtrail-on", "write-test"]


def test_a_change_refreshes_the_account(monkeypatch):
    started = []
    monkeypatch.setattr(aws, "write", lambda *a, **k: {"ok": True, "message": "done"})
    monkeypatch.setattr(aws, "refresh_soon", lambda *a, **k: started.append(a[0]))
    assert aws.act({"main": ENTRY}, None, "main", "admin", "cloudtrail-on")["ok"] and started == ["main"]


def test_a_copy_written_by_another_process_is_picked_up(tmp_path, monkeypatch):
    monkeypatch.setenv("HISHO_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(aws, "_cache", {})
    monkeypatch.setattr(aws, "_loaded", {})
    assert aws.cached("main") == {}   # Core looked before the first read
    path = aws.state_path("main")
    path.parent.mkdir(parents=True)
    path.write_text('{"account": {"id": "1"}}')   # the install's read lands afterwards
    assert aws.cached("main")["account"]["id"] == "1"


def test_the_page_shows_the_budget_as_aws_has_it():
    sn = snap()
    assert sn["billing"]["budgets"] == ["hisho-monthly", "hisho-ceiling"]
    items = {i["id"]: i for i in aws.security_section("main", ENTRY, sn)["items"]}
    assert items["budget"]["facts"][0].startswith("hisho-monthly: $25.00 a month · $3.71 spent · forecast $6.20; hisho-ceiling: $100.00")
    assert items["budget"]["state"] == "up"


def test_the_ceiling_budget_must_be_guarded():
    doc = {"Statement": [dict(st) for st in GUARDS["Statement"]]}
    doc["Statement"][2]["Resource"] = f"arn:aws:budgets::{ACCOUNT}:budget/hisho-monthly"
    assert aws.check_guardrails(doc, [ROLE, ME, MFA]) == ["NeverTouchTheCeiling doesn't cover budget/hisho-ceiling"]
    doc["Statement"] = [st for st in doc["Statement"] if st["Sid"] != "NeverTouchTheCeiling"]
    assert aws.check_guardrails(doc, [ROLE, ME, MFA]) == ["statement NeverTouchTheCeiling"]
    t = answers({("budgets", "describe_budgets"): {"Budgets": [{"BudgetName": "hisho-monthly"}]}})
    assert "ceiling-missing" in keys(snap(t))


def test_budget_amount_accepts_dollars_and_refuses_nonsense():
    assert aws.budget_amount("$25") == 25 and aws.budget_amount(" 1,250.5 ") == 1250.5
    for bad in ("0", "-5", "abc", "10001"):
        with pytest.raises(aws.AWSError):
            aws.budget_amount(bad)


def test_changing_the_amount_keeps_everything_else(monkeypatch):
    journal = []
    monkeypatch.setattr(aws, "_journal", journal.append)
    old = {"BudgetName": "hisho-monthly", "BudgetLimit": {"Amount": "10.0", "Unit": "USD"}, "TimeUnit": "MONTHLY",
           "BudgetType": "COST", "CostTypes": {"IncludeTax": True}, "CalculatedSpend": {"ActualSpend": {"Amount": "1"}}}
    s = FakeSession(answers({("budgets", "describe_budget"): {"Budget": old}}))
    res = aws.write("main", ENTRY, "budget-amount", snap(), s=s, typed="$25")
    assert res["ok"] and res["message"] == "hisho-monthly is now $25.00 a month (was $10.00)"
    [(_svc, _op, _r, kw)] = [c for c in s.calls if c[1] == "update_budget"]
    assert kw["NewBudget"] == {"BudgetName": "hisho-monthly", "BudgetLimit": {"Amount": "25.00", "Unit": "USD"},
                               "TimeUnit": "MONTHLY", "BudgetType": "COST", "CostTypes": {"IncludeTax": True}}
    assert "Typed: $25." in journal[-1]["plan"]


def test_a_bad_amount_changes_nothing():
    s = FakeSession()
    res = aws.write("main", ENTRY, "budget-amount", snap(), s=s, typed="lots")
    assert not res["ok"] and "Nothing was changed" in res["error"] and not s.calls


def test_the_amount_button_shows_the_plan_then_asks(monkeypatch):
    monkeypatch.setattr(aws, "_unlocked", {"main": {"creds": {}, "until": time.time() + 1800, "arn": ""}})
    acts = {a["id"]: a for a in aws.admin_section("main", ENTRY, snap())["items"][0]["actions"]}
    assert "now $25.00 a month" in acts["budget-amount"]["confirm"] and "Nothing else changes" in acts["budget-amount"]["confirm"]
    assert acts["budget-amount"]["ask"].startswith("New monthly amount for hisho-monthly")
