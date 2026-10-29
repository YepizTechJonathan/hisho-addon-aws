"""AWS integration for Hisho (see addon.yaml). Runs inside Core. Reads with read-only keys; changes only
while unlocked with an MFA code (see "changes" below).

Reading an account takes a minute or so (a few calls in every enabled region), so it runs in the
background every few hours and the result is kept in ``$HISHO_STATE_DIR/addons/aws/<entry>.json``
(no secrets in it); ``summary`` and ``details`` only read that copy. Cost Explorer charges $0.01 a
call, so costs are read in one call (this month and last, per service) on their own, slower clock.
The keys must belong to the entry's ``account_id`` (filled in by Test): any other account is refused.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

HOME_REGION = "us-east-1"   # where the global services (IAM, Cost Explorer, Budgets, billing metrics) answer
EVERY_HOURS = 6
COST_EVERY_HOURS = 12
RETRY_AFTER = 900           # after a failed read, wait this long before trying again
KEY_DAYS = 90               # an access key older than this, or unused this long, is worth replacing
GUARDDUTY_HIGH = 7          # GuardDuty severity: 7-8.9 high, 4-6.9 medium
OPEN_PORTS = {22: "SSH", 3389: "remote desktop"}
NOT_ON = ("InvalidAccessException", "ResourceNotFoundException", "SubscriptionRequiredException",
          "OptInRequired", "AccessDeniedException", "UnrecognizedClientException")


class AWSError(RuntimeError):
    pass


class WrongAccount(AWSError):
    pass


# ── talking to AWS ─────────────────────────────────────────────────────────

def key_id(entry: dict[str, Any], ctx: Any) -> str:
    """The access key ID: kept as itself when it is one (AKIA... / ASIA...; an all-capitals value is taken for a
    secret's name by Hisho, so a pasted ID stays in the entry as typed), else the secret it names. The secret
    access key is always a secret."""
    value = str(entry.get("access_key_id") or "").strip()
    return value if re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{16}", value) else ctx.secret(value).strip()


def session(entry: dict[str, Any], ctx: Any) -> Any:
    try:
        import boto3
    except ImportError:
        raise AWSError("boto3 isn't installed on Core: run .venv/bin/pip install -e '.[aws]' there")
    return boto3.session.Session(aws_access_key_id=key_id(entry, ctx),
                                 aws_secret_access_key=ctx.secret(entry["secret_access_key"]).strip(),
                                 region_name=HOME_REGION)


def client(s: Any, service: str, region: str = HOME_REGION) -> Any:
    try:
        from botocore.config import Config
        cfg = Config(connect_timeout=5, read_timeout=20, retries={"max_attempts": 3, "mode": "standard"})
    except ImportError:   # tests hand in a fake session
        cfg = None
    return s.client(service, region_name=region, config=cfg)


def code(exc: Exception) -> str:
    return str((getattr(exc, "response", None) or {}).get("Error", {}).get("Code") or type(exc).__name__)


def why(exc: Exception) -> str:
    msg = str((getattr(exc, "response", None) or {}).get("Error", {}).get("Message") or exc)
    return f"{code(exc)}: {msg}"[:200]


def attempt(errors: list[str], what: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """Run one read; a failure becomes a line in ``errors`` (shown on the page), never an exception."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{what}: {why(exc)}")
        return default


def pages(c: Any, op: str, **kw: Any) -> list[dict[str, Any]]:
    if c.can_paginate(op):
        return list(c.get_paginator(op).paginate(**kw))
    return [getattr(c, op)(**kw)]


def available(s: Any, service: str, regions: list[str]) -> list[str]:
    offered = set(s.get_available_regions(service) or [])
    return [r for r in regions if r in offered]


# ── reading an account ────────────────────────────────────────────────────

def regions_of(entry: dict[str, Any], s: Any, errors: list[str]) -> list[str]:
    chosen = [r.strip() for r in str(entry.get("regions") or "").split(",") if r.strip()]
    if chosen:
        return chosen
    found = attempt(errors, "regions", lambda: [r["RegionName"] for r in client(s, "ec2").describe_regions()["Regions"]], [])
    return sorted(found) or [HOME_REGION]


def today() -> dt.date:
    """The owner's date (Core runs on UTC: early evening in the West is already tomorrow there)."""
    try:
        from hisho import fleet_config
        return fleet_config.owner_today()
    except Exception:  # noqa: BLE001 -- an older Hisho, or no Fleet.yaml
        return dt.date.today()


def _days(stamp: Any, now: float) -> int | None:
    if not stamp or stamp in ("N/A", "no_information", "not_supported"):
        return None
    try:
        when = stamp if isinstance(stamp, dt.datetime) else dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return int((now - when.timestamp()) // 86400)


def read_iam(iam: Any, errors: list[str], now: float) -> dict[str, Any]:
    out: dict[str, Any] = {"root_mfa": None, "root_keys": None, "users": []}
    summ = attempt(errors, "IAM account summary", lambda: iam.get_account_summary()["SummaryMap"], {}) or {}
    if summ:
        out.update(root_mfa=bool(summ.get("AccountMFAEnabled")), root_keys=bool(summ.get("AccountAccessKeysPresent")))

    def report() -> str:
        for _ in range(15):
            if iam.generate_credential_report().get("State") == "COMPLETE":
                break
            time.sleep(1)
        content = iam.get_credential_report()["Content"]
        return content.decode() if isinstance(content, bytes) else str(content)
    text = attempt(errors, "IAM credential report", report, "")
    for row in csv.DictReader(io.StringIO(text or "")):
        keys = []
        for i in ("1", "2"):
            if row.get(f"access_key_{i}_active") == "true":
                keys.append({"n": int(i), "age": _days(row.get(f"access_key_{i}_last_rotated"), now),
                             "unused": _days(row.get(f"access_key_{i}_last_used_date"), now)})
        if row.get("user") == "<root_account>":
            out["root_mfa"] = row.get("mfa_active") == "true"
            out["root_keys"] = bool(keys)
            out["root_last_login"] = _days(row.get("password_last_used"), now)
            continue
        out["users"].append({"name": row.get("user"), "password": row.get("password_enabled") == "true",
                             "mfa": row.get("mfa_active") == "true", "keys": keys,
                             "last_login": _days(row.get("password_last_used"), now)})
    return out


def read_trails(s: Any, errors: list[str]) -> list[dict[str, Any]]:
    trails = attempt(errors, "CloudTrail", lambda: client(s, "cloudtrail").describe_trails(includeShadowTrails=True)["trailList"], []) or []
    out, seen = [], set()
    for t in trails:
        if t.get("TrailARN") in seen:
            continue
        seen.add(t.get("TrailARN"))
        home = t.get("HomeRegion") or HOME_REGION
        status = attempt(errors, f"CloudTrail {t.get('Name')}",
                         lambda: client(s, "cloudtrail", home).get_trail_status(Name=t["TrailARN"]), {}) or {}
        out.append({"name": t.get("Name"), "region": home, "multi_region": bool(t.get("IsMultiRegionTrail")),
                    "logging": bool(status.get("IsLogging")), "bucket": t.get("S3BucketName")})
    return out


def _bpa_on(conf: dict[str, Any] | None) -> bool:
    return bool(conf) and all(conf.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))


def read_s3(s: Any, account: str, errors: list[str]) -> dict[str, Any]:
    s3 = client(s, "s3")
    names = [b["Name"] for b in attempt(errors, "S3 buckets", lambda: s3.list_buckets().get("Buckets") or [], []) or []]

    def account_bpa() -> bool:
        try:
            return _bpa_on(client(s, "s3control").get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"])
        except Exception as exc:  # noqa: BLE001
            if code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return False
            raise
    blocked = attempt(errors, "S3 account Block Public Access", account_bpa, None)
    public = []
    for name in [] if blocked else names:
        def check(name: str = name) -> str | None:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or HOME_REGION
            c = client(s, "s3", "eu-west-1" if loc == "EU" else loc)
            try:
                if _bpa_on(c.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]):
                    return None
            except Exception as exc:  # noqa: BLE001
                if code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    raise
            try:
                if c.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic"):
                    return "its bucket policy lets anyone read it"
            except Exception as exc:  # noqa: BLE001
                if code(exc) != "NoSuchBucketPolicy":
                    raise
            grants = c.get_bucket_acl(Bucket=name).get("Grants") or []
            if any(str((g.get("Grantee") or {}).get("URI", "")).endswith(("/AllUsers", "/AuthenticatedUsers")) for g in grants):
                return "its ACL lets anyone in"
            return None
        found = attempt(errors, f"S3 bucket {name}", check, None)
        if found:
            public.append({"name": name, "why": found})
    return {"buckets": names, "account_block": blocked, "public": public}


def _usd(spend: Any) -> float | None:
    try:
        return round(float((spend or {}).get("Amount")), 2)
    except (TypeError, ValueError):
        return None


def read_billing(s: Any, account: str, errors: list[str]) -> dict[str, Any]:
    def budgets() -> list[dict[str, Any]]:
        try:
            found = client(s, "budgets").describe_budgets(AccountId=account).get("Budgets") or []
        except Exception as exc:  # noqa: BLE001
            if code(exc) == "NotFoundException":
                return []
            raise
        return [{"name": b["BudgetName"], "type": b.get("BudgetType"), "period": b.get("TimeUnit"),
                 "limit": _usd(b.get("BudgetLimit")), "spent": _usd((b.get("CalculatedSpend") or {}).get("ActualSpend")),
                 "forecast": _usd((b.get("CalculatedSpend") or {}).get("ForecastedSpend"))} for b in found]
    alarms = attempt(errors, "billing alarms", lambda: [
        a["AlarmName"] for p in pages(client(s, "cloudwatch"), "describe_alarms", AlarmTypes=["MetricAlarm"])
        for a in p.get("MetricAlarms") or [] if a.get("MetricName") == "EstimatedCharges"], None)
    found = attempt(errors, "AWS Budgets", budgets, None)
    return {"budgets": None if found is None else [b["name"] for b in found], "budget_details": found or [],
            "alarms": alarms}


def budget_line(b: dict[str, Any]) -> str:
    money = (lambda x: "?" if x is None else _money(x))
    return (f"{b['name']}: {money(b.get('limit'))} a {str(b.get('period') or 'month').lower().removesuffix('ly') or 'month'}"
            f" · {money(b.get('spent'))} spent · forecast {money(b.get('forecast'))}")


def read_region(s: Any, region: str, errors: list[str], offered: dict[str, list[str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    ec2 = client(s, "ec2", region)
    states = attempt(errors, f"EC2 {region}", lambda: [i["State"]["Name"] for p in pages(ec2, "describe_instances")
                                                       for r in p.get("Reservations") or [] for i in r.get("Instances") or []], [])
    states = [x for x in states or [] if x != "terminated"]
    out["ec2"], out["ec2_running"] = len(states), states.count("running")
    open_to_world = []
    for p in attempt(errors, f"security groups {region}", lambda: pages(ec2, "describe_security_groups"), []) or []:
        for g in p.get("SecurityGroups") or []:
            for perm in g.get("IpPermissions") or []:
                world = (any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges") or [])
                         or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges") or []))
                if not world:
                    continue
                every = perm.get("IpProtocol") == "-1"
                lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                hit = ["every port"] if every else [n for port, n in OPEN_PORTS.items() if lo <= port <= hi]
                if hit:
                    open_to_world.append({"group": f"{g.get('GroupName')} ({g.get('GroupId')})", "what": ", ".join(hit)})
    out["open_to_world"] = open_to_world
    if region in offered["lambda"]:
        out["lambda"] = sum(len(p.get("Functions") or []) for p in attempt(
            errors, f"Lambda {region}", lambda: pages(client(s, "lambda", region), "list_functions"), []) or [])
    if region in offered["rds"]:
        out["rds"] = sum(len(p.get("DBInstances") or []) for p in attempt(
            errors, f"RDS {region}", lambda: pages(client(s, "rds", region), "describe_db_instances"), []) or [])
    if region in offered["lightsail"]:
        out["lightsail"] = len(attempt(errors, f"Lightsail {region}",
                                       lambda: client(s, "lightsail", region).get_instances().get("instances") or [], []) or [])
    if region in offered["sesv2"]:
        def ses() -> dict[str, Any] | None:
            c = client(s, "sesv2", region)
            acct = c.get_account()
            quota = acct.get("SendQuota") or {}
            ids = sum(len(p.get("EmailIdentities") or []) for p in pages(c, "list_email_identities"))
            if not (ids or acct.get("ProductionAccessEnabled") or quota.get("SentLast24Hours")):
                return None
            return {"production": bool(acct.get("ProductionAccessEnabled")), "sending": bool(acct.get("SendingEnabled")),
                    "sent_24h": int(quota.get("SentLast24Hours") or 0), "max_24h": int(quota.get("Max24HourSend") or 0),
                    "identities": ids}
        out["ses"] = attempt(errors, f"SES {region}", ses, None)
    out["guardduty"] = attempt(errors, f"GuardDuty {region}", lambda: read_guardduty(client(s, "guardduty", region)), None)
    out["securityhub"] = on_or_off(errors, f"Security Hub {region}", lambda: bool(client(s, "securityhub", region).describe_hub().get("HubArn")))
    out["analyzer"] = on_or_off(errors, f"IAM Access Analyzer {region}", lambda: any(
        a.get("status") == "ACTIVE" for a in client(s, "accessanalyzer", region).list_analyzers().get("analyzers") or []))
    return out


def on_or_off(errors: list[str], what: str, fn: Callable[[], bool]) -> bool | None:
    """A service that answers "not subscribed" is off, not an error."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        if code(exc) in NOT_ON:
            return False
        errors.append(f"{what}: {why(exc)}")
        return None


def read_guardduty(gd: Any) -> dict[str, Any]:
    ids = gd.list_detectors().get("DetectorIds") or []
    if not ids or gd.get_detector(DetectorId=ids[0]).get("Status") != "ENABLED":
        return {"enabled": False}
    live = {"service.archived": {"Eq": ["false"]}}
    high = gd.list_findings(DetectorId=ids[0], MaxResults=50,
                            FindingCriteria={"Criterion": {**live, "severity": {"Gte": GUARDDUTY_HIGH}}}).get("FindingIds") or []
    medium = gd.list_findings(DetectorId=ids[0], MaxResults=50, FindingCriteria={"Criterion": {
        **live, "severity": {"Gte": 4, "Lt": GUARDDUTY_HIGH}}}).get("FindingIds") or []
    titles = [f.get("Title") for f in gd.get_findings(DetectorId=ids[0], FindingIds=high[:5]).get("Findings") or []] if high else []
    return {"enabled": True, "high": len(high), "medium": len(medium), "titles": titles}


def read_globals(s: Any, errors: list[str]) -> dict[str, Any]:
    zones = attempt(errors, "Route 53", lambda: [z["Name"].rstrip(".") for p in pages(client(s, "route53"), "list_hosted_zones")
                                                for z in p.get("HostedZones") or []], [])
    dists = attempt(errors, "CloudFront", lambda: [d.get("DomainName") for p in pages(client(s, "cloudfront"), "list_distributions")
                                                  for d in (p.get("DistributionList") or {}).get("Items") or []], [])
    return {"route53": zones or [], "cloudfront": dists or []}


# ── the admin role and the read-only user (see SOPs/AWS add-on.md) ─────────

READONLY_POLICIES = {"SecurityAudit", "ViewOnlyAccess", "AWSBillingReadOnlyAccess"}
READONLY_INLINE = "hisho-may-assume-admin"
GUARDRAILS = "hisho-guardrails"
#: statement Sid -> the actions it must deny (the setup steps' exact list)
GUARDRAIL_DENIES = {
    "NeverBlindTheWatchers": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                              "cloudtrail:PutEventSelectors", "guardduty:DeleteDetector", "guardduty:UpdateDetector",
                              "guardduty:DisassociateFromAdministratorAccount"],
    "NeverTouchBillingOrAccount": ["account:CloseAccount", "account:PutAlternateContact", "account:PutContactInformation",
                                   "aws-portal:Modify*", "billing:Put*", "billing:Update*", "payments:*",
                                   "organizations:*"],
    # Changing or deleting a budget is budgets:ModifyBudget (there is no separate delete permission), so this
    # covers one budget only: the safety net hisho-ceiling. hisho-monthly stays changeable from the page.
    "NeverTouchTheCeiling": ["budgets:ModifyBudget"],
    "NeverLoosenItsOwnRules": ["iam:*"],
}


CEILING_BUDGET = "hisho-ceiling"     # the safety-net budget only the owner can change (made in the console)
MONTHLY_BUDGET = "hisho-monthly"     # the everyday budget, its amount changeable from the page


def budget_arns(account: str) -> list[str]:
    return [f"arn:aws:budgets::{account}:budget/{CEILING_BUDGET}"]


def _doc(raw: Any) -> dict[str, Any]:
    """A policy document as a dict (boto3 decodes them; the raw API URL-encodes them)."""
    if isinstance(raw, dict):
        return raw
    import urllib.parse
    try:
        return json.loads(urllib.parse.unquote(str(raw or "{}")))
    except ValueError:
        return {}


def _list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else [] if x is None else [x]


def _statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in _list(doc.get("Statement")) if isinstance(s, dict)]


def _mfa_required(st: dict[str, Any]) -> bool:
    cond = (st.get("Condition") or {})
    for op in ("Bool", "BoolIfExists"):
        vals = _list((cond.get(op) or {}).get("aws:MultiFactorAuthPresent"))
        if op == "Bool" and vals and all(str(v).lower() == "true" for v in vals):
            return True
    return False


def check_trust(doc: dict[str, Any], user_arn: str) -> dict[str, Any]:
    """Who may take on the role, and whether every way in needs MFA."""
    others, open_ = set(), False
    for st in _statements(doc):
        if st.get("Effect") != "Allow":
            continue
        actions = {str(a).lower() for a in _list(st.get("Action"))}
        if not any(a in ("*", "sts:*") or a.startswith("sts:assumerole") for a in actions):
            continue
        principal = st.get("Principal")
        who = {"*"} if principal == "*" else {str(p) for v in (principal or {}).values() for p in _list(v)}
        others |= who - {user_arn}
        if not _mfa_required(st):
            open_ = True
    return {"mfa_required": not open_, "others": sorted(others)}


def check_guardrails(doc: dict[str, Any], own: list[str]) -> list[str]:
    """What's missing from the deny policy (empty = all there)."""
    missing = []
    by_sid = {s.get("Sid"): s for s in _statements(doc) if s.get("Effect") == "Deny"}
    for sid, want in GUARDRAIL_DENIES.items():
        st = by_sid.get(sid)
        if st is None:
            missing.append(f"statement {sid}")
            continue
        have = {str(a).lower() for a in _list(st.get("Action"))}
        gone = [a for a in want if a.lower() not in have]
        if gone:
            missing.append(f"{sid} no longer denies {', '.join(gone)}")
        res = {str(r) for r in _list(st.get("Resource"))}
        if sid in ("NeverLoosenItsOwnRules", "NeverTouchTheCeiling"):
            account = next((r.split(":")[4] for r in own if r.count(":") >= 5), "")
            needed = own if sid == "NeverLoosenItsOwnRules" else budget_arns(account)
            unguarded = [r for r in needed if r not in res and "*" not in res]
            if unguarded:
                missing.append(f"{sid} doesn't cover {', '.join(r.split(':')[-1] for r in unguarded)}")
        elif "*" not in res:
            missing.append(f"{sid} isn't on every resource")
    return missing


def read_admin(iam: Any, entry: dict[str, Any], me_arn: str, errors: list[str]) -> dict[str, Any]:
    """The read-only user (no more power than it should have) and, when set, the hisho-admin role."""
    user = me_arn.split("/")[-1] if ":user/" in me_arn else None
    out: dict[str, Any] = {"user": user, "role": None}
    if user:
        attached = attempt(errors, f"IAM user {user}", lambda: [p["PolicyName"] for p in iam.list_attached_user_policies(
            UserName=user).get("AttachedPolicies") or []], None)
        inline = attempt(errors, f"IAM user {user} inline", lambda: iam.list_user_policies(UserName=user).get("PolicyNames") or [], None)
        groups = attempt(errors, f"IAM user {user} groups", lambda: [g["GroupName"] for g in iam.list_groups_for_user(
            UserName=user).get("Groups") or []], None)
        extra = [f"policy {p}" for p in attached or [] if p not in READONLY_POLICIES]
        extra += [f"inline policy {p}" for p in inline or [] if p != READONLY_INLINE]
        extra += [f"group {g}" for g in groups or []]
        role_arn = str(entry.get("admin_role_arn") or "")
        if READONLY_INLINE in (inline or []):
            doc = _doc(attempt(errors, f"{READONLY_INLINE}", lambda: iam.get_user_policy(
                UserName=user, PolicyName=READONLY_INLINE)["PolicyDocument"], {}))
            for st in _statements(doc):
                if st.get("Effect") != "Allow":
                    continue
                acts = {str(a) for a in _list(st.get("Action"))}
                res = {str(r) for r in _list(st.get("Resource"))}
                if acts - {"sts:AssumeRole"} or (role_arn and res - {role_arn}):
                    extra.append(f"{READONLY_INLINE} allows {', '.join(sorted(acts))} on {', '.join(sorted(res))}")
        mfa = attempt(errors, f"IAM user {user} MFA", lambda: [d["SerialNumber"] for d in iam.list_mfa_devices(
            UserName=user).get("MFADevices") or []], None)
        out.update(attached=attached, inline=inline, groups=groups, extra=extra, mfa_devices=mfa)
    role_arn = str(entry.get("admin_role_arn") or "")
    if not role_arn:
        return out
    name = role_arn.split("/")[-1]

    def role() -> dict[str, Any] | None:
        try:
            r = iam.get_role(RoleName=name)["Role"]
        except Exception as exc:  # noqa: BLE001
            if code(exc) == "NoSuchEntity":
                return None
            raise
        trust = check_trust(_doc(r.get("AssumeRolePolicyDocument")), me_arn)
        inline = iam.list_role_policies(RoleName=name).get("PolicyNames") or []
        attached = [p["PolicyName"] for p in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies") or []]
        own = [role_arn, me_arn] + ([str(entry["mfa_serial"])] if entry.get("mfa_serial") else [])
        if GUARDRAILS in inline:
            missing = check_guardrails(_doc(iam.get_role_policy(RoleName=name, PolicyName=GUARDRAILS)["PolicyDocument"]), own)
        else:
            missing = [f"the {GUARDRAILS} policy"]
        return {"name": name, "max_session": int(r.get("MaxSessionDuration") or 3600), "attached": attached,
                **trust, "guardrails_missing": missing}
    out["role"] = attempt(errors, f"IAM role {name}", role, {"unreadable": True})
    out["role_configured"] = True
    return out


def collect(entry: dict[str, Any], ctx: Any, s: Any = None, now: float | None = None) -> dict[str, Any]:
    """Everything but costs, in one snapshot. Raises AWSError when the keys don't work or belong to
    another account; any single read that fails is listed in ``errors``."""
    s = s or session(entry, ctx)
    now = time.time() if now is None else now
    try:
        me = client(s, "sts").get_caller_identity()
    except Exception as exc:  # noqa: BLE001
        raise AWSError(f"AWS refused the keys ({why(exc)})")
    account = str(me.get("Account"))
    want = str(entry.get("account_id") or "").strip()
    if want and account != want:
        raise WrongAccount(f"these keys belong to AWS account {account}, not {want}")
    errors: list[str] = []
    iam = client(s, "iam")
    aliases = attempt(errors, "account alias", lambda: iam.list_account_aliases().get("AccountAliases") or [], []) or []
    regions = regions_of(entry, s, errors)
    offered = {svc: available(s, svc, regions) for svc in ("lambda", "rds", "lightsail", "sesv2")}
    snap = {"at": now, "account": {"id": account, "alias": aliases[0] if aliases else None, "arn": me.get("Arn")},
            "regions": regions, "errors": errors, "iam": read_iam(iam, errors, now), "trails": read_trails(s, errors),
            "s3": read_s3(s, account, errors), "billing": read_billing(s, account, errors), "global": read_globals(s, errors),
            "admin": read_admin(iam, entry, str(me.get("Arn") or ""), errors)}
    with ThreadPoolExecutor(max_workers=8) as pool:
        snap["by_region"] = dict(zip(regions, pool.map(lambda r: read_region(s, r, errors, offered), regions)))
    errors.sort()
    return snap


def collect_cost(s: Any, today: dt.date) -> dict[str, Any]:
    """This month so far and all of last month, per service: one Cost Explorer call ($0.01)."""
    first = today.replace(day=1)
    last_first = (first - dt.timedelta(days=1)).replace(day=1)
    ce = client(s, "ce")
    out: dict[str, Any] = {"at": time.time(), "month": first.isoformat(), "this": {}, "last": {}, "calls": 0}
    token = None
    while out["calls"] < 3:
        kw = {"NextPageToken": token} if token else {}
        res = ce.get_cost_and_usage(TimePeriod={"Start": last_first.isoformat(), "End": today.isoformat()},
                                    Granularity="MONTHLY", Metrics=["UnblendedCost"],
                                    GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}], **kw)
        out["calls"] += 1
        for period in res.get("ResultsByTime") or []:
            which = "this" if period["TimePeriod"]["Start"] == first.isoformat() else "last"
            for g in period.get("Groups") or []:
                amount = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if abs(amount) >= 0.005:
                    out[which][g["Keys"][0]] = round(out[which].get(g["Keys"][0], 0) + amount, 2)
        token = res.get("NextPageToken")
        if not token:
            break
    return out


# ── the kept copy, refreshed in the background ──────────────────────────────

_cache: dict[str, dict[str, Any]] = {}
_busy: set[str] = set()
_lock = threading.Lock()


def state_path(name: str) -> Path:
    return Path(os.environ.get("HISHO_STATE_DIR") or "~/.local/state/hisho").expanduser() / "addons" / "aws" / f"{name}.json"


_loaded: dict[str, float] = {}   # entry -> mtime of the file the cached copy came from


def cached(name: str) -> dict[str, Any]:
    """The kept copy. Re-read when the file is newer than what's in memory: another process (an install,
    the CLI) may have written it after this one first looked, which showed "Reading..." until the next read."""
    try:
        mtime = state_path(name).stat().st_mtime
    except OSError:
        mtime = 0.0
    if name not in _cache or mtime > _loaded.get(name, 0.0):
        try:
            _cache[name] = json.loads(state_path(name).read_text(encoding="utf-8"))
            _loaded[name] = mtime
        except (OSError, ValueError):
            _cache.setdefault(name, {})
    return _cache[name]


def _save(name: str, snap: dict[str, Any]) -> None:
    _cache[name] = snap
    path = state_path(name)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snap, default=str), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        _loaded[name] = path.stat().st_mtime
    except OSError:
        pass


def _hours(entry: dict[str, Any], key: str, default: int) -> float:
    try:
        return max(1.0, float(entry.get(key) or default))
    except (TypeError, ValueError):
        return float(default)


def refresh(name: str, entry: dict[str, Any], ctx: Any, cost: bool | None = None, s: Any = None) -> dict[str, Any]:
    """Read the account now (blocking). Costs too when they're due (or ``cost=True``)."""
    old = cached(name)
    try:
        s = s or session(entry, ctx)
        snap = collect(entry, ctx, s)
    except Exception as exc:  # noqa: BLE001 -- bad keys, a missing secret, no boto3: shown, retried later
        msg = str(exc) if isinstance(exc, AWSError) else f"{type(exc).__name__}: {str(exc)[:200]}"
        snap = {**old, "failed": msg, "failed_at": time.time(), "wrong_account": isinstance(exc, WrongAccount)}
        _save(name, snap)
        return snap
    old_cost = old.get("cost") if (old.get("account") or {}).get("id") == snap["account"]["id"] else None
    due = cost if cost is not None else (not old_cost or time.time() - float(old_cost.get("at") or 0)
                                         > _hours(entry, "cost_every_hours", COST_EVERY_HOURS) * 3600)
    if due:
        try:
            snap["cost"] = collect_cost(s, today())
        except Exception as exc:  # noqa: BLE001
            snap["cost"] = {**(old_cost or {}), "error": why(exc), "at": time.time()}
    else:
        snap["cost"] = old_cost
    _save(name, snap)
    return snap


def due(entry: dict[str, Any], snap: dict[str, Any], now: float) -> bool:
    if snap.get("failed_at") and float(snap["failed_at"]) > float(snap.get("at") or 0):
        return now - float(snap["failed_at"]) > RETRY_AFTER
    return now - float(snap.get("at") or 0) > _hours(entry, "every_hours", EVERY_HOURS) * 3600


def refresh_soon(name: str, entry: dict[str, Any], ctx: Any, cost: bool | None = None) -> bool:
    """Start a background read unless one is running. True when one was started."""
    with _lock:
        if name in _busy:
            return False
        _busy.add(name)

    def run() -> None:
        try:
            refresh(name, entry, ctx, cost)
        finally:
            with _lock:
                _busy.discard(name)
    threading.Thread(target=run, daemon=True, name=f"aws-{name}").start()
    return True


def current(name: str, entry: dict[str, Any], ctx: Any, now: float | None = None) -> dict[str, Any]:
    """The kept copy (starting a background read when it's old). A copy of another account is ignored."""
    snap = cached(name)
    if due(entry, snap, time.time() if now is None else now):
        refresh_soon(name, entry, ctx)
    want = str(entry.get("account_id") or "").strip()
    if want and snap.get("account") and snap["account"].get("id") != want:
        return {k: v for k, v in snap.items() if k in ("failed", "failed_at", "wrong_account")}
    return snap


# ── what it means ─────────────────────────────────────────────────────────

def _public_ok(entry: dict[str, Any]) -> set[str]:
    return {x.strip() for x in str(entry.get("public_ok") or "").split(",") if x.strip()}


def _money(x: float) -> str:
    return f"${x:,.2f}"


def totals(snap: dict[str, Any]) -> tuple[float | None, float | None]:
    c = snap.get("cost") or {}
    if "this" not in c:
        return None, None
    return round(sum(c["this"].values()), 2), round(sum(c["last"].values()), 2)


def keys_of(snap: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(u["name"], k) for u in (snap.get("iam") or {}).get("users") or [] for k in u.get("keys") or []]


def findings(name: str, entry: dict[str, Any], snap: dict[str, Any]) -> list[dict[str, Any]]:
    """Real problems only, each in words with why it matters. Titles carry no numbers, so an alert keeps
    its identity when a count changes."""
    out: list[dict[str, Any]] = []

    def add(key: str, severity: str, title: str, detail: str) -> None:
        out.append({"entry": name, "key": key, "severity": severity, "title": title, "detail": detail})
    iam = snap.get("iam") or {}
    if iam.get("root_keys"):
        add("root-keys", "critical", "the root user has access keys",
            "Whoever has them controls the whole account, billing included, and they can't be limited. "
            "Sign in as root > Security credentials > delete them (use an IAM user's key instead).")
    if iam.get("root_mfa") is False:
        add("root-mfa", "critical", "the root user has no MFA",
            "A stolen or guessed root password is enough to take the account over. "
            "Sign in as root > Security credentials > Assign MFA device.")
    no_mfa = [u["name"] for u in iam.get("users") or [] if u.get("password") and not u.get("mfa")]
    if no_mfa:
        add("users-mfa", "warn", "IAM users can sign in without MFA",
            f"{', '.join(no_mfa)}: a leaked password is enough to sign in. IAM > Users > the user > "
            "Security credentials > Assign MFA device (or remove console access if nobody uses it).")
    old = [f"{u} key {k['n']} ({k['age']} days)" for u, k in keys_of(snap) if (k.get("age") or 0) > KEY_DAYS]
    if old:
        add("old-keys", "warn", "access keys are overdue for replacing",
            f"{', '.join(old)}. The longer a key lives the more places it may have leaked to. Make a new key, "
            "switch to it, then deactivate and delete the old one.")
    idle = [f"{u} key {k['n']}" + (f" (last used {k['unused']} days ago)" if k.get("unused") is not None else " (never used)")
            for u, k in keys_of(snap) if (k.get("unused") or 0) > KEY_DAYS or (k.get("unused") is None and (k.get("age") or 0) > 7)]
    if idle:
        add("idle-keys", "warn", "access keys nobody uses are still active",
            f"{', '.join(idle)}. An unused key is all risk: deactivate it (IAM > Users > Security credentials).")
    trails = snap.get("trails")
    if trails is not None and "account" in snap and not any(t.get("logging") for t in trails):
        add("cloudtrail", "warn", "CloudTrail isn't recording",
            "There's no record of who did what in the account, which is what you need after a leaked key. "
            "CloudTrail > Create trail (all regions; the first copy of management events is free).")
    hot = [f"{r}: " + "; ".join(g.get("titles") or [f"{g['high']} high-severity findings"])
           for r, d in (snap.get("by_region") or {}).items() for g in [d.get("guardduty") or {}] if g.get("high")]
    if hot:
        add("guardduty-high", "critical", "GuardDuty found high-severity threats",
            f"{' | '.join(hot)}. These usually mean a key or server is being misused. GuardDuty > Findings.")
    public = [b for b in (snap.get("s3") or {}).get("public") or [] if b["name"] not in _public_ok(entry)]
    if public:
        add("s3-public", "warn", "S3 buckets are open to anyone",
            "; ".join(f"{b['name']}: {b['why']}" for b in public) + ". Anything in them can be read (and copied, "
            "on your bill). Turn on Block Public Access unless it's a public website, then mark it on purpose here.")
    adm = snap.get("admin") or {}
    if adm.get("extra"):
        add("readonly-extra", "critical", "Hisho's read-only AWS user has more power than it should",
            f"{adm.get('user')}: {'; '.join(adm['extra'])}. Its keys sit on Core around the clock, so anything added "
            "to it can be done by whoever steals them. Remove it in IAM > Users > the user.")
    role = adm.get("role")
    if adm.get("role_configured") and role is None:
        add("admin-missing", "warn", "the hisho-admin role is gone",
            "Unlocking for changes won't work. If you didn't delete it, someone else did: check CloudTrail.")
    elif role and not role.get("unreadable"):
        if not role.get("mfa_required"):
            add("admin-mfa", "critical", "hisho-admin can be taken on without MFA",
                "Its trust policy lost the aws:MultiFactorAuthPresent condition, so the read-only keys alone give full "
                "admin. Put the condition back (IAM > Roles > hisho-admin > Trust relationships).")
        if role.get("others"):
            add("admin-others", "critical", "someone else may take on hisho-admin",
                f"Its trust policy also lets in {', '.join(role['others'])}. Only {adm.get('user')} should be there.")
        if role.get("guardrails_missing"):
            add("admin-guardrails", "critical", "hisho-admin's guardrails are missing",
                f"{'; '.join(role['guardrails_missing'])}. Without them an unlocked Hisho could stop CloudTrail, touch "
                "billing or loosen its own rules. Put hisho-guardrails back as in SOPs/AWS add-on.")
        if role.get("max_session", 3600) > 3600:
            add("admin-session", "warn", "hisho-admin sessions can last more than an hour",
                f"Maximum session is {role['max_session'] // 60} minutes; the setup says one hour. "
                "IAM > Roles > hisho-admin > Edit > Maximum session duration.")
    bill = snap.get("billing") or {}
    if adm.get("role_configured") and bill.get("budgets") and CEILING_BUDGET not in bill["budgets"]:
        add("ceiling-missing", "warn", f"the {CEILING_BUDGET} safety-net budget is gone",
            "It emails you if spending gets past it even when hisho-monthly was raised, and Hisho itself can't "
            "change it. Make it again in the AWS console (Billing > Budgets), as in the SOP 'AWS add-on'.")
    if bill.get("budgets") == [] and bill.get("alarms") == []:
        add("no-budget", "warn", "nothing in AWS warns you about spending",
            "If a key leaks, someone can run up a large bill before you notice. Billing > Budgets > Create budget > "
            "Monthly cost budget with an email alert (two budgets are free).")
    this, last = totals(snap)
    if this is not None:
        monthly = next((b for b in bill.get("budget_details") or [] if b.get("name") == MONTHLY_BUDGET), {})
        budget = entry.get("budget_usd") or monthly.get("limit")
        if budget and this > float(budget):
            add("over-budget", "warn", "AWS spending passed your budget",
                f"{_money(this)} so far this month, budget {_money(float(budget))}. See which service on the AWS page.")
        if last is not None and this > 2 * last and this - last > 10:
            add("cost-jump", "warn", "AWS spending jumped",
                f"{_money(this)} so far this month against {_money(last)} for all of last month. Leaked keys are "
                "usually used to run servers or send mail: check which service grew.")
    return out


def headline(snap: dict[str, Any]) -> str:
    acct = snap.get("account") or {}
    who = acct.get("alias") or acct.get("id") or "AWS"
    this, _last = totals(snap)
    n = sum(d.get("ec2", 0) + d.get("lambda", 0) + d.get("rds", 0) + d.get("lightsail", 0)
            for d in (snap.get("by_region") or {}).values())
    n += len((snap.get("s3") or {}).get("buckets") or [])
    return (f"{who} · " + (f"{_money(this)} this month · " if this is not None else "")
            + f"{n} resource{'s' * (n != 1)}")


def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    problems, lines = [], []
    for name, entry in entries.items():
        snap = current(name, entry, ctx)
        if snap.get("wrong_account"):
            problems.append({"entry": name, "key": "wrong-account", "severity": "critical",
                             "title": "AWS keys belong to another account",
                             "detail": f"{snap['failed']}. Hisho stopped reading: check which keys the entry's secrets hold."})
            continue
        if snap.get("failed") and float(snap.get("failed_at") or 0) > float(snap.get("at") or 0):
            problems.append({"entry": name, "key": "unreadable", "severity": "warn", "title": "Hisho can't read AWS",
                             "detail": f"{snap['failed']}. The page shows the last good read."})
        if "account" not in snap:
            lines.append(f"{name}: reading the account (takes about a minute)")
            continue
        problems += findings(name, entry, snap)
        lines.append(headline(snap))
    has = any("account" in cached(n) for n in entries)
    return {"state": "down" if any(p["severity"] == "critical" for p in problems) else "warn" if problems
            else "ok" if has else "unknown",
            "headline": " · ".join(lines) or "no account", "problems": problems}


# ── the page ──────────────────────────────────────────────────────────────

def _ago(stamp: Any) -> str:
    try:
        mins = int((time.time() - float(stamp)) // 60)
    except (TypeError, ValueError):
        return "never"
    return "just now" if mins < 1 else f"{mins} min ago" if mins < 90 else f"{mins // 60} h ago"


def _item(id_: str, name: str, state: str, facts: list[str], actions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"id": id_, "name": name, "state": state, "facts": [f for f in facts if f], "actions": actions or []}


def account_section(name: str, entry: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    acct, cost = snap["account"], snap.get("cost") or {}
    items = [_item("refresh", "Read the account again", "off",
                   [f"read {_ago(snap.get('at'))}; again every {int(_hours(entry, 'every_hours', EVERY_HOURS))} h",
                    f"costs read {_ago(cost.get('at'))}; again every {int(_hours(entry, 'cost_every_hours', COST_EVERY_HOURS))} h"],
                   [{"id": "refresh", "label": "read now"},
                    {"id": "refresh-cost", "label": "read costs now",
                     "confirm": "Ask Cost Explorer now? AWS charges $0.01 for the call."}])]
    this, last = totals(snap)
    if cost.get("error"):
        items.append(_item("cost-error", "Costs", "unknown", [f"Cost Explorer: {cost['error']}",
                           "If it says Cost Explorer isn't enabled: open Billing > Cost Explorer once in the console."]))
    if this is not None:
        services = sorted(set(cost["this"]) | set(cost["last"]), key=lambda k: -max(cost["this"].get(k, 0), cost["last"].get(k, 0)))
        items.append(_item("cost", f"Cost: {_money(this)} this month, {_money(last or 0)} last month", "up",
                           [f"{k}: {_money(cost['this'].get(k, 0))} this month · {_money(cost['last'].get(k, 0))} last month"
                            for k in services[:20]] or ["nothing billed"]))
    names = {"ec2": "EC2 servers", "lightsail": "Lightsail servers", "lambda": "Lambda functions", "rds": "RDS databases"}
    for region, d in sorted((snap.get("by_region") or {}).items()):
        facts = [f"{names[k]}: {d[k]}" + (f" ({d['ec2_running']} running)" if k == "ec2" else "")
                 for k in names if d.get(k)]
        ses = d.get("ses")
        if ses:
            facts.append(f"SES: {'production' if ses['production'] else 'sandbox'}, sending {'on' if ses['sending'] else 'off'}, "
                         f"{ses['identities']} identities, {ses['sent_24h']} of {ses['max_24h']} mails in 24 h")
        if facts:
            items.append(_item(f"region-{region}", f"Region {region}", "up", facts))
    g, s3 = snap.get("global") or {}, snap.get("s3") or {}
    items.append(_item("global", "Global", "up", [
        f"S3 buckets: {len(s3.get('buckets') or [])}" + (f" ({', '.join(s3['buckets'][:12])})" if s3.get("buckets") else ""),
        f"Route 53 zones: {len(g.get('route53') or [])}" + (f" ({', '.join(g['route53'][:12])})" if g.get("route53") else ""),
        f"CloudFront distributions: {len(g.get('cloudfront') or [])}",
        f"IAM users: {len((snap.get('iam') or {}).get('users') or [])}"]))
    if snap.get("errors"):
        items.append(_item("errors", "Couldn't read everything", "unknown", snap["errors"][:25]))
    return {"title": f"{acct.get('alias') or name} ({acct.get('id')})", "entry": name, "state": "ok",
            "facts": [f"{len(snap.get('regions') or [])} regions read · {headline(snap)}",
                      "Read with read-only keys; changes need your MFA code (Changes, below)."] + ([entry["note"]] if entry.get("note") else []),
            "items": items}


def security_section(name: str, entry: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    iam, items = snap.get("iam") or {}, []
    bad = {f["key"] for f in findings(name, entry, snap)}

    def mark(key: str) -> str:
        return "warn" if key in bad else "up"
    items.append(_item("root", "Root user", "warn" if bad & {"root-keys", "root-mfa"} else "up", [
        "MFA on" if iam.get("root_mfa") else "MFA OFF" if iam.get("root_mfa") is False else "MFA unknown",
        "has access keys" if iam.get("root_keys") else "no access keys" if iam.get("root_keys") is False else "",
        f"last sign-in {iam['root_last_login']} days ago" if iam.get("root_last_login") is not None else ""]))
    for u in iam.get("users") or []:
        keys = [f"key {k['n']}: {k['age']} days old, " + (f"used {k['unused']} days ago" if k.get("unused") is not None else "never used")
                for k in u.get("keys") or []]
        risky = (u.get("password") and not u.get("mfa")) or any((k.get("age") or 0) > KEY_DAYS or (k.get("unused") or 0) > KEY_DAYS
                                                                 for k in u.get("keys") or [])
        items.append(_item(f"user-{u['name']}"[:60], f"IAM user {u['name']}", "warn" if risky else "up", [
            ("console sign-in, MFA " + ("on" if u.get("mfa") else "OFF")) if u.get("password") else "no console sign-in",
            *keys]))
    trails = snap.get("trails") or []
    items.append(_item("cloudtrail", "CloudTrail", mark("cloudtrail"), [
        f"{t['name']} ({t['region']}): {'recording' if t['logging'] else 'STOPPED'}, "
        f"{'all regions' if t['multi_region'] else 'one region only'}, to {t.get('bucket')}" for t in trails] or ["no trail"]))
    regions = snap.get("by_region") or {}
    gd_on = [r for r, d in regions.items() if (d.get("guardduty") or {}).get("enabled")]
    gd_facts = [f"{r}: {d['guardduty']['high']} high, {d['guardduty']['medium']} medium findings"
                + (f" ({'; '.join(d['guardduty']['titles'])})" if d['guardduty'].get('titles') else "")
                for r, d in regions.items() if (d.get("guardduty") or {}).get("high") or (d.get("guardduty") or {}).get("medium")]
    items.append(_item("guardduty", "GuardDuty", mark("guardduty-high") if gd_on else "off",
                       ([f"on in {len(gd_on)} of {len(regions)} regions"] + gd_facts) if gd_on else
                       ["off: it watches for stolen keys, miners and odd sign-ins (a few dollars a month for a small "
                        "account, 30 days free). Your call; Hisho doesn't turn it on."]))
    bill = snap.get("billing") or {}
    items.append(_item("budget", "Spending alerts", mark("no-budget"), [
        ("; ".join(budget_line(b) for b in bill.get("budget_details") or []) or
         f"budgets: {', '.join(bill['budgets']) or 'none'}") if bill.get("budgets") is not None else "budgets: couldn't read",
        f"billing alarms: {', '.join(bill['alarms']) or 'none'}" if bill.get("alarms") is not None else "billing alarms: couldn't read"]))
    s3 = snap.get("s3") or {}
    ok = _public_ok(entry)
    items.append(_item("s3-block", "S3 Block Public Access (account)", "up" if s3.get("account_block") else "off", [
        "on: no bucket can be made public" if s3.get("account_block") else
        "off: each bucket decides for itself (checked one by one below)" if s3.get("account_block") is False else "couldn't read"]))
    for b in s3.get("public") or []:
        known = b["name"] in ok
        items.append(_item(f"bucket-{b['name']}"[:60], f"public bucket {b['name']}", "off" if known else "warn",
                           [b["why"] + (". You said that's on purpose." if known else ".")],
                           [{"id": "public", "label": "not on purpose"} if known else
                            {"id": "public", "label": "on purpose",
                             "confirm": f"Stop warning about {b['name']}? It stays listed here, marked on purpose."}]))
    for r, d in sorted(regions.items()):
        for o in d.get("open_to_world") or []:
            items.append(_item(f"sg-{r}-{o['group']}"[:60], f"open to the internet: {o['group']} ({r})", "warn",
                               [f"anyone can reach {o['what']} on servers in this group. Limit it to your own address "
                                "if nothing public needs it."]))
    for label, key in (("Security Hub", "securityhub"), ("IAM Access Analyzer", "analyzer")):
        on = [r for r, d in regions.items() if d.get(key)]
        items.append(_item(key, label, "up" if on else "off", [f"on in {', '.join(on)}" if on else "off (optional)"]))
    worry = sum(1 for i in items if i["state"] == "warn")
    return {"title": "Security", "entry": name, "state": "warn" if worry else "ok",
            "facts": [f"{worry} thing{'s' * (worry != 1)} to look at" if worry else "nothing to look at"], "items": items}


# ── changes: unlocked with an MFA code, one hour at a time ──────────────────
#
# The read-only keys can take on the hisho-admin role only with an MFA code. Unlocking asks for the
# code, calls sts:AssumeRole and keeps the hour-long credentials in this process's memory, nowhere
# else (not on disk, not in the journal). Every change is a WRITES entry: its plan says in words
# exactly what will change and is the confirm question; the change is refused while locked and
# journaled (aws-change) with the plan and the outcome.

UNLOCK_SECONDS = 3600
_unlocked: dict[str, dict[str, Any]] = {}   # entry -> {"creds": {...}, "until": epoch, "arn": assumed role}


def unlocked(name: str, now: float | None = None) -> dict[str, Any] | None:
    u = _unlocked.get(name)
    if u and u["until"] - 30 > (time.time() if now is None else now):
        return u
    _unlocked.pop(name, None)
    return None


def unlock(name: str, entry: dict[str, Any], ctx: Any, code_typed: str, s: Any = None) -> dict[str, Any]:
    if not entry.get("admin_role_arn") or not entry.get("mfa_serial"):
        return {"ok": False, "error": "set admin_role_arn and mfa_serial on the entry first (see SOPs/AWS add-on)"}
    token = "".join(ch for ch in code_typed if ch.isdigit())
    if len(token) != 6:
        return {"ok": False, "error": "type the 6-digit code from your authenticator app"}
    s = s or session(entry, ctx)
    try:
        res = client(s, "sts").assume_role(RoleArn=str(entry["admin_role_arn"]), RoleSessionName=f"hisho-{name}"[:64],
                                           DurationSeconds=UNLOCK_SECONDS, SerialNumber=str(entry["mfa_serial"]),
                                           TokenCode=token)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"AWS said no ({code(exc)}): a wrong or used code, or the role's trust changed"}
    c = res["Credentials"]
    exp = c["Expiration"]
    until = exp.timestamp() if hasattr(exp, "timestamp") else time.time() + UNLOCK_SECONDS
    want = str(entry.get("account_id") or "")
    arn = str((res.get("AssumedRoleUser") or {}).get("Arn") or "")
    if want and f":{want}:" not in arn:
        return {"ok": False, "error": f"the role is in another account ({arn.split(':')[4] if arn.count(':') > 4 else '?'}); not unlocked"}
    _unlocked[name] = {"creds": {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                                 "aws_session_token": c["SessionToken"]}, "until": until, "arn": arn}
    _journal({"entry": name, "action": "unlock", "role": entry["admin_role_arn"],
              "until": dt.datetime.fromtimestamp(until).isoformat(timespec="minutes")})
    return {"ok": True, "message": f"Unlocked for changes until {_hhmm(until)}.", "hide_input": True}


def lock(name: str) -> dict[str, Any]:
    was = _unlocked.pop(name, None)
    if was:
        _journal({"entry": name, "action": "lock"})
    return {"ok": True, "message": "Locked." if was else "It was already locked."}


def admin_session(name: str) -> Any:
    u = unlocked(name)
    if u is None:
        raise AWSError("locked: unlock with your MFA code first")
    import boto3
    return boto3.session.Session(region_name=HOME_REGION, **u["creds"])


def _hhmm(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch).strftime("%H:%M")


def _journal(meta: dict[str, Any]) -> None:
    try:
        from hisho.jobs import append_event
        append_event(Path(os.environ.get("HISHO_ROOT") or "~/Hisho").expanduser(), "aws-change", {"addon": "aws", **meta})
    except Exception:  # noqa: BLE001 -- the journal never blocks
        pass


#: the demo change: a Standard-tier SSM parameter (free), outside anything the guardrails protect
TEST_PARAMETER = "/hisho/last-unlock-test"
TEST_REGION = "us-west-2"    # the owner's home side of the country; nothing else lives there yet


def _test_plan(entry: dict[str, Any], snap: dict[str, Any]) -> str:
    return (f"Set the SSM Parameter Store parameter {TEST_PARAMETER} ({TEST_REGION}, Standard tier, free) to "
            f"\"{today().isoformat()}\", creating it if it isn't there. Nothing else changes.")


def _test_run(s: Any, entry: dict[str, Any]) -> str:
    today_ = today().isoformat()
    client(s, "ssm", TEST_REGION).put_parameter(Name=TEST_PARAMETER, Value=today_, Type="String", Tier="Standard", Overwrite=True,
                                   Description="Written by Hisho's AWS add-on to test an unlocked change")
    return f"Set {TEST_PARAMETER} to {today_} ({TEST_REGION})"


def _account(entry: dict[str, Any], snap: dict[str, Any]) -> str:
    return str(entry.get("account_id") or (snap.get("account") or {}).get("id") or "")


# Turn on CloudTrail: a private bucket for its logs in the owner's region, then one trail for every region.
TRAIL_NAME = "hisho-trail"
TRAIL_REGION = TEST_REGION
TRAIL_KEEP_DAYS = 365


def trail_bucket(account: str) -> str:
    return f"hisho-cloudtrail-{account}-{TRAIL_REGION}"


def _trail_plan(entry: dict[str, Any], snap: dict[str, Any]) -> str:
    bucket = trail_bucket(_account(entry, snap))
    return (f"1) Create the private S3 bucket {bucket} in {TRAIL_REGION}: Block Public Access on, encrypted (SSE-S3), "
            f"a policy that lets only CloudTrail write to it (for this account's {TRAIL_NAME} only), and a rule that "
            f"deletes logs after {TRAIL_KEEP_DAYS} days. 2) Create the trail {TRAIL_NAME}: all regions, management "
            "events (the first copy is free), log file validation on. 3) Start it logging. Cost: a few cents a month "
            "for the stored logs. Nothing else changes.")


def _trail_run(s: Any, entry: dict[str, Any]) -> str:
    account = str(client(s, "sts").get_caller_identity()["Account"])
    bucket = trail_bucket(account)
    arn = f"arn:aws:cloudtrail:{TRAIL_REGION}:{account}:trail/{TRAIL_NAME}"
    s3 = client(s, "s3", TRAIL_REGION)
    try:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": TRAIL_REGION})
    except Exception as exc:  # noqa: BLE001
        if code(exc) != "BucketAlreadyOwnedByYou":
            raise
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
    s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    only_this_trail = {"StringEquals": {"aws:SourceArn": arn}}
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "CloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}", "Condition": only_this_trail},
        {"Sid": "CloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": arn}}}]}))
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [
        {"ID": f"expire-after-{TRAIL_KEEP_DAYS}-days", "Status": "Enabled", "Filter": {"Prefix": ""},
         "Expiration": {"Days": TRAIL_KEEP_DAYS}}]})
    ct = client(s, "cloudtrail", TRAIL_REGION)
    try:
        ct.create_trail(Name=TRAIL_NAME, S3BucketName=bucket, IsMultiRegionTrail=True,
                        IncludeGlobalServiceEvents=True, EnableLogFileValidation=True)
    except Exception as exc:  # noqa: BLE001
        if code(exc) != "TrailAlreadyExistsException":
            raise
    ct.start_logging(Name=TRAIL_NAME)
    return f"CloudTrail {TRAIL_NAME} is recording every region into {bucket} ({TRAIL_REGION})"


def _no_trail(snap: dict[str, Any]) -> bool:
    return not any(t.get("logging") for t in snap.get("trails") or [])


def _monthly(snap: dict[str, Any]) -> dict[str, Any] | None:
    return next((b for b in (snap.get("billing") or {}).get("budget_details") or [] if b.get("name") == MONTHLY_BUDGET), None)


BUDGET_MAX = 10000


def budget_amount(typed: str) -> float:
    """'25', '$25', '25.50' -> 25.5. A positive dollar amount up to BUDGET_MAX, or AWSError."""
    try:
        usd = round(float(str(typed).replace("$", "").replace(",", "").strip()), 2)
    except ValueError:
        raise AWSError(f"{typed!r} isn't a dollar amount")
    if not 0 < usd <= BUDGET_MAX:
        raise AWSError(f"the amount must be more than $0 and at most ${BUDGET_MAX:,}")
    return usd


def _amount_plan(entry: dict[str, Any], snap: dict[str, Any]) -> str:
    now = (_monthly(snap) or {}).get("limit")
    return (f"Change the AWS Budget {MONTHLY_BUDGET}'s amount (now {_money(now) if now is not None else 'unknown'} a "
            f"month) to the dollar amount you type next. Its emails (80% and 100% spent, 100% forecast) stay as they "
            f"are. Nothing else changes.")


def _amount_run(s: Any, entry: dict[str, Any], typed: str = "") -> str:
    usd = budget_amount(typed)
    account = str(client(s, "sts").get_caller_identity()["Account"])
    b = client(s, "budgets")
    old = b.describe_budget(AccountId=account, BudgetName=MONTHLY_BUDGET)["Budget"]
    keep = ("BudgetName", "CostFilters", "CostTypes", "TimeUnit", "TimePeriod", "BudgetType", "AutoAdjustData")
    new = {k: old[k] for k in keep if k in old}
    new["BudgetLimit"] = {"Amount": f"{usd:.2f}", "Unit": (old.get("BudgetLimit") or {}).get("Unit") or "USD"}
    b.update_budget(AccountId=account, NewBudget=new)
    was = _usd(old.get("BudgetLimit"))
    return f"{MONTHLY_BUDGET} is now {_money(usd)} a month (was {_money(was) if was is not None else '?'})"


#: action id -> {label, plan(entry, snap) -> words, run(admin session, entry[, typed]) -> words,
#: when(snap) -> offered?, ask: the question for a typed value (shown after the plan)}. Add jobs here.
WRITES: dict[str, dict[str, Any]] = {
    "cloudtrail-on": {"label": "turn on CloudTrail", "plan": _trail_plan, "run": _trail_run, "when": _no_trail},
    "budget-amount": {"label": "change budget amount", "plan": _amount_plan, "run": _amount_run,
                      "when": lambda snap: _monthly(snap) is not None,
                      "ask": f"New monthly amount for {MONTHLY_BUDGET}, in dollars (up to {BUDGET_MAX:,})"},
    "write-test": {"label": "test a change (SSM parameter)", "plan": _test_plan, "run": _test_run},
}
#: buttons whose state is Core's memory: `hisho addon do` sends them to Core instead of running them locally
CORE_ACTIONS = ("unlock", "lock", *WRITES)
UNLOCK_ASK = "6-digit code from the hisho MFA device in your authenticator app (unlocks changes for one hour)"
CORE_ASKS = {"unlock": UNLOCK_ASK}


def write(name: str, entry: dict[str, Any], action: str, snap: dict[str, Any], s: Any = None,
          typed: str = "") -> dict[str, Any]:
    job = WRITES[action]
    plan = job["plan"](entry, snap)
    extra: dict[str, Any] = {}
    if job.get("ask"):
        if not typed.strip():
            return {"ok": False, "error": "nothing was typed. Nothing was changed."}
        if action == "budget-amount":
            try:
                budget_amount(typed)
            except AWSError as exc:
                return {"ok": False, "error": f"{exc}. Nothing was changed."}
        plan += f" Typed: {typed.strip()[:40]}."
        extra["typed"] = typed.strip()
    try:
        s = s or admin_session(name)
    except AWSError as exc:
        return {"ok": False, "error": f"{exc}. Nothing was changed."}
    try:
        done = job["run"](s, entry, **extra)
    except Exception as exc:  # noqa: BLE001
        _journal({"entry": name, "action": action, "plan": plan, "ok": False, "error": why(exc)})
        return {"ok": False, "error": f"AWS refused: {why(exc)}"}
    _journal({"entry": name, "action": action, "plan": plan, "ok": True, "result": done})
    return {"ok": True, "message": done}


def admin_section(name: str, entry: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    adm, u = snap.get("admin") or {}, unlocked(name)
    role = adm.get("role") or {}
    ready = bool(entry.get("admin_role_arn") and entry.get("mfa_serial"))
    facts = [f"unlocked until {_hhmm(u['until'])}" if u else "locked" if ready else
             "not set up: add admin_role_arn and mfa_serial to the entry (SOPs/AWS add-on)"]
    if role and not role.get("unreadable"):
        facts.append(f"role {role.get('name')}: " + ", ".join(role.get("attached") or []) + " · MFA "
                     + ("required" if role.get("mfa_required") else "NOT required") + " · guardrails "
                     + ("in place" if not role.get("guardrails_missing") else "MISSING"))
    if adm.get("user"):
        facts.append(f"read-only user {adm['user']}: " + ", ".join(sorted(adm.get("attached") or []))
                     + (f" · MFA device {', '.join(d.split('/')[-1] for d in adm['mfa_devices'])}" if adm.get("mfa_devices") else " · no MFA device"))
    actions = []
    if ready and u:
        actions = [{"id": "lock", "label": "lock now"}] + [
            {"id": k, "label": w["label"], "confirm": "This changes AWS: " + w["plan"](entry, snap) + " Go ahead?",
             **({"ask": w["ask"]} if w.get("ask") else {})}
            for k, w in WRITES.items() if w.get("when", lambda _s: True)(snap)]
    elif ready:
        actions = [{"id": "unlock", "label": "unlock for changes",
                    "ask": UNLOCK_ASK}]
    items = [_item("admin", "Changes", "up" if u else "off", facts, actions)]
    bad = {f["key"] for f in findings(name, entry, snap)} & {"readonly-extra", "admin-missing", "admin-mfa", "admin-others",
                                                              "admin-guardrails", "admin-session"}
    return {"title": "Changes (hisho-admin)", "entry": name, "state": "warn" if bad else "ok",
            "facts": ["Hisho reads with the read-only keys. Changes need your MFA code and last at most an hour; "
                      "each shows what it will do and asks first."], "items": items}


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    out = []
    for name, entry in entries.items():
        snap = current(name, entry, ctx)
        failed = [snap["failed"]] if snap.get("failed") and float(snap.get("failed_at") or 0) > float(snap.get("at") or 0) else []
        if "account" not in snap:
            out.append({"title": name, "entry": name, "state": "down" if failed else "unknown",
                        "facts": failed or ["Reading the account; this takes about a minute. Refresh the page."], "items": []})
            continue
        acc = account_section(name, entry, snap)
        if failed:
            acc.update(state="warn", facts=[f"Last read failed: {failed[0]}"] + acc["facts"])
        out += [acc, security_section(name, entry, snap), admin_section(name, entry, snap)]
    return out


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    try:
        s = session(entry, ctx)
        me = client(s, "sts").get_caller_identity()
    except AWSError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"AWS refused the keys ({why(exc)})"}
    account, want = str(me.get("Account")), str(entry.get("account_id") or "").strip()
    if want and account != want:
        return {"ok": False, "error": f"these keys belong to AWS account {account}, not {want}"}
    return {"ok": True, "fill": {} if want else {"account_id": account},
            "message": f"Connected to AWS account {account} as {str(me.get('Arn')).split(':')[-1]}"
                       + ("" if want else "; only this account will be read") + ". The first full read takes about a minute."}



# ── one paste from AWS CloudShell (addon.yaml connect:) ─────────────────────

#: Run once in AWS CloudShell (https://console.aws.amazon.com/cloudshell/home), signed in as you. It makes (or
#: reuses) the user hisho-readonly with the three read-only policies, makes a new access key and prints one line:
#: {"AccessKeyId": ..., "SecretAccessKey": ..., "Account": ...}. AWS allows two keys per user: a third run says
#: LimitExceeded until an old key is deleted (IAM > Users > hisho-readonly > Security credentials).
CLOUDSHELL_COMMAND = (
    "U=hisho-readonly; aws iam get-user --user-name $U >/dev/null 2>&1 || aws iam create-user --user-name $U >/dev/null"
    " && for P in SecurityAudit job-function/ViewOnlyAccess AWSBillingReadOnlyAccess; do aws iam attach-user-policy"
    " --user-name $U --policy-arn arn:aws:iam::aws:policy/$P; done && A=$(aws sts get-caller-identity --query Account"
    " --output text) && aws iam create-access-key --user-name $U --query"
    " \"{AccessKeyId:AccessKey.AccessKeyId,SecretAccessKey:AccessKey.SecretAccessKey,Account:'$A'}\" --output json"
    " | tr -d ' \\n'; echo")
WAIT_TRIES, WAIT_SECONDS = 6, 3    # a brand-new key takes a few seconds to work everywhere in AWS
_sleep = time.sleep


def parse_printed(text: Any) -> dict[str, str]:
    """The key ID, secret key and account from what the command printed (its JSON line, the plain
    ``aws iam create-access-key`` output, or the three values in any order). {} when the key isn't all there."""
    raw = str(text or "").strip()
    out: dict[str, str] = {}
    try:
        data = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
    except ValueError:
        data = None
    if isinstance(data, dict):
        key = data.get("AccessKey") if isinstance(data.get("AccessKey"), dict) else data
        out = {"access_key_id": str(key.get("AccessKeyId") or ""), "secret_access_key": str(key.get("SecretAccessKey") or ""),
               "account_id": str(data.get("Account") or key.get("Account") or "")}
    if not out.get("access_key_id") or not out.get("secret_access_key"):
        kid = re.search(r"\b(AKIA[0-9A-Z]{16})\b", raw)
        sec = re.search(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])", raw)
        acct = re.search(r"(?<!\d)(\d{12})(?!\d)", raw)
        out = {"access_key_id": kid.group(1) if kid else "", "secret_access_key": sec.group(1) if sec else "",
               "account_id": acct.group(1) if acct else ""}
    if not out.get("account_id"):
        acct = re.search(r"(?<!\d)(\d{12})(?!\d)", raw)
        out["account_id"] = acct.group(1) if acct else ""
    if not re.fullmatch(r"AKIA[0-9A-Z]{16}", out["access_key_id"]) or not re.fullmatch(r"[A-Za-z0-9/+]{40}", out["secret_access_key"]):
        return {}
    if not re.fullmatch(r"\d{12}", out.get("account_id") or ""):
        out.pop("account_id", None)
    return out


class _Pasted:
    """A Context whose two key secrets are the pasted values (used only while connecting, never stored here)."""

    def __init__(self, ctx: Any, values: dict[str, str]) -> None:
        self._ctx, self._values = ctx, values

    def secret(self, name: str) -> str:
        return self._values[name] if name in self._values else self._ctx.secret(name)


def connect(values: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Paste from AWS CloudShell: the printed line becomes the entry (key ID, secret key, account). The pasted text
    itself is not kept; Core stores both key halves as local secrets. Waits for a brand-new key to start working."""
    got = parse_printed(values.get("printed_key"))
    if not got:
        return {"ok": False, "error": "no access key found in what was pasted",
                "explain": "Hisho couldn't find a new access key in that. Run the command in CloudShell again and "
                           "paste the whole line it prints, from { to }. If it said LimitExceeded, the user already "
                           "has two keys: delete the old one in IAM > Users > hisho-readonly > Security credentials, "
                           "then run it again."}
    names = {"HISHO_PASTED_ACCESS_KEY_ID": got["access_key_id"], "HISHO_PASTED_SECRET_ACCESS_KEY": got["secret_access_key"]}
    trial = {**{k: v for k, v in values.items() if k != "printed_key"}, "access_key_id": "HISHO_PASTED_ACCESS_KEY_ID",
             "secret_access_key": "HISHO_PASTED_SECRET_ACCESS_KEY", **({"account_id": got["account_id"]} if "account_id" in got else {})}
    res: dict[str, Any] = {}
    for i in range(WAIT_TRIES):
        res = test(trial, _Pasted(ctx, names))
        if res.get("ok") or "belong to AWS account" in str(res.get("error")) or "boto3" in str(res.get("error")):
            break
        if i < WAIT_TRIES - 1:
            _sleep(WAIT_SECONDS)
    if not res.get("ok"):
        return {"ok": False, "error": str(res.get("error") or "AWS refused the key"),
                "explain": "AWS didn't accept that key yet. A brand-new key can take a minute: wait a moment and "
                           "press the button again with the same text. If it still fails, run the command again for "
                           "a fresh key."}
    account = got.get("account_id") or str((res.get("fill") or {}).get("account_id") or "")
    entry = {"access_key_id": got["access_key_id"], "secret_access_key": got["secret_access_key"],
             **({"account_id": account} if account else {})}
    return {"ok": True, "entry": entry,
            "message": f"Connected to AWS account {account or '?'} as hisho-readonly (read only). The secret key is kept as a "
                       "secret on this machine; the pasted text is not kept. The first full read takes about a minute."}

def describe_secret(entry: dict[str, Any], ctx: Any) -> str:
    """The 'What:' line of the keys' Infisical comment: which user, which account, which policies."""
    s = session(entry, ctx)
    me = client(s, "sts").get_caller_identity()
    user = str(me.get("Arn")).split("/")[-1]
    iam = client(s, "iam")
    try:
        policies = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName=user).get("AttachedPolicies") or []]
    except Exception:  # noqa: BLE001
        policies = []
    return (f"AWS access key of IAM user {user}, account {me.get('Account')}."
            + (f" Policies: {', '.join(sorted(policies))}." if policies else ""))


def act(entries: dict[str, dict[str, Any]], ctx: Any, entry: str, item: str, action: str) -> dict[str, Any]:
    ent = entries.get(entry)
    if ent is None:
        return {"ok": False, "error": f"no AWS entry {entry}"}
    if action == "unlock":
        return {**unlock(entry, ent, ctx, getattr(ctx, "input", "") or ""), "hide_input": True}
    if action == "lock":
        return lock(entry)
    if action in WRITES:
        res = write(entry, ent, action, cached(entry), typed=getattr(ctx, "input", "") or "")
        if res.get("ok"):
            refresh_soon(entry, ent, ctx)   # the page shows the change at the next look
        return res
    if action in ("refresh", "refresh-cost"):
        started = refresh_soon(entry, ent, ctx, cost=True if action == "refresh-cost" else None)
        return {"ok": True, "message": "Reading the account now; reload the page in a minute." if started
                else "A read is already running; reload the page in a minute."}
    if action == "public" and item.startswith("bucket-"):
        from hisho import addons
        bucket = item.removeprefix("bucket-")
        ok = _public_ok(ent)
        ok = ok - {bucket} if bucket in ok else ok | {bucket}
        addons.set_entry(ctx.addon, entry, {"public_ok": ", ".join(sorted(ok))}, merge=True)
        return {"ok": True, "message": f"{bucket}: " + ("on purpose, no more warning" if bucket in ok else "warning again")}
    return {"ok": False, "error": f"unknown action {action}"}
