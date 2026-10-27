# AWS (Hisho add-on)

## What it does

Watches one AWS account with read-only keys, and makes changes only after you unlock them with an MFA code.

- **Inventory**, every 6 hours, across every enabled region: EC2 and Lightsail servers, Lambda functions, RDS
  databases, SES, S3 buckets, Route 53 zones, CloudFront, IAM users.
- **Costs** per service, this month and last, from one Cost Explorer call every 12 hours ($0.01 a call).
- **Security**, with alerts (Needs you and phone) only for real problems: root without MFA or with access
  keys, users signing in without MFA, keys over 90 days old or unused, CloudTrail not recording, GuardDuty
  high-severity findings, public S3 buckets, no budget or billing alarm, spending over budget or jumping.
- **Its own setup**: alerts if the `hisho-admin` role stops requiring MFA, trusts anyone else, loses its
  `hisho-guardrails` deny policy (including `NeverTouchTheCeiling`) or allows sessions over an hour, or if the read-only user gains permissions.
- **Changes**: *unlock for changes* asks for your 6-digit MFA code and takes on `hisho-admin` for at most an
  hour. The temporary keys stay in Core's memory only. Each change shows its plan and asks first, is refused
  while locked, and is journaled (`aws-change`). Changes so far: **turn on CloudTrail** (private log bucket in us-west-2,
  logs kept 365 days; offered only while no trail records) and a test change (the free SSM parameter
  `/hisho/last-unlock-test` in us-west-2). **change budget amount** sets `hisho-monthly`'s monthly amount (its emails stay).
  The guardrails keep `hisho-admin` away from `hisho-ceiling`, a safety-net budget only you change (Hisho alerts if it's gone).

The keys are pinned to one account (filled in on first save); keys from any other account are refused.
Needs boto3 on the Core machine: `.venv/bin/pip install -e '.[aws]'` in Hisho's folder.

## What it needs

- You need:
  - An AWS account you own (never a client's)
  - Ten minutes in the AWS console to make a read-only user, an MFA device and one admin role (steps under Settings)
- Runs on: the Core machine, inside Hisho Core
- One entry per AWS account, each with:
  - `access_key_id` (password, kept as a local secret, required)
  - `secret_access_key` (password, kept as a local secret, required)
  - `account_id` (str, optional)
  - `regions` (str, optional)
  - `budget_usd` (int, optional)
  - `every_hours` (int, optional)
  - `cost_every_hours` (int, optional)
  - `admin_role_arn` (str, optional)
  - `mfa_serial` (str, optional)
  - `public_ok` (str, optional)
  - `note` (str, optional)

## How to install

On the dashboard: **Add-ons > Store > AWS > Install**. Or from a terminal:

```bash
hisho addon install aws
```

Hisho takes the newest version from this repository, copies it to the machine it runs on and turns
it on. Updates show as **Update available** on its Store card; **Roll back** returns to the version
before.

## How to use

Its card shows this month's cost and any security problem. Its page (**Add-ons > AWS**) has the inventory by region, costs per service and the security checks. To change something, press **unlock for changes** under Changes and type your MFA code: Hisho can then make the listed changes (each says what it will do and asks first) for at most an hour, or until you press **lock now**.

## Settings

Set up the AWS side once, in the AWS console signed in as you. `ACCOUNT_ID` is your 12-digit account
number (top right).

1. **User `hisho-readonly`** (IAM > Users > Create user, no console access): attach `SecurityAudit`,
   `ViewOnlyAccess` and `AWSBillingReadOnlyAccess`; add an inline policy allowing `sts:AssumeRole` on
   `arn:aws:iam::ACCOUNT_ID:role/hisho-admin`; assign a virtual MFA device named `hisho`; create an access key
   ("Application running outside AWS") and save both halves as secrets:
   `hisho secret put AWS_MAIN_READONLY_ACCESS_KEY_ID` and `hisho secret put AWS_MAIN_READONLY_SECRET_ACCESS_KEY`.
2. **Role `hisho-admin`** (IAM > Roles > Create role > Custom trust policy): trust
   `arn:aws:iam::ACCOUNT_ID:user/hisho-readonly` for `sts:AssumeRole` only with `aws:MultiFactorAuthPresent` =
   `true`; attach `AdministratorAccess`; maximum session 1 hour; add an inline deny policy `hisho-guardrails` so
   even unlocked it can't stop CloudTrail or GuardDuty, touch billing or close the account, change the
   `hisho-ceiling` budget (`budgets:ModifyBudget` on it), or change itself, the read-only user or the MFA device.
3. **In Hisho** (**Add-ons > AWS > + add**, entry `main`): the two secret names, `admin_role_arn`
   (`arn:aws:iam::ACCOUNT_ID:role/hisho-admin`) and `mfa_serial` (`arn:aws:iam::ACCOUNT_ID:mfa/hisho`). Saving
   tests the keys and pins the account: keys from any other account are refused afterwards.
4. **Budgets** (Billing and Cost Management > Budgets): a `hisho-ceiling` you set by hand (Hisho can never
   change it) and an everyday `hisho-monthly` that Hisho's **change budget amount** button adjusts.

Entries are kept in `~/Hisho/System/Config/Addons/aws.yaml`. Rotate the key in IAM, then
`hisho secret put NAME --update` for both; Hisho warns when a key is over 90 days old.

## How to remove

**Add-ons > Store > AWS > Remove**, or `hisho addon remove aws`. Your settings file stays,
so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
