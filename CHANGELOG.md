# Changelog

## 0.4.1

- README says what you need (addon.yaml you_need) and how to use it; the README check requires both.

## 0.4.0

- **change budget amount** on the page (after the MFA unlock): shows the plan, asks for the new monthly amount
  ($0.01 to $10,000), changes `hisho-monthly` only; its emails stay. Journaled with what was typed.
- Guardrail `NeverTouchItsBudgets` (all `hisho-*` budgets) becomes `NeverTouchTheCeiling` (only `budget/hisho-ceiling`,
  reserved for a safety-net budget only the owner can change), so `hisho-monthly` can be changed from the page.
- Alert when the `hisho-ceiling` safety-net budget is missing.
- Hisho's over-budget alert uses `hisho-monthly`'s amount from AWS when no `budget_usd` is set.

## 0.3.0

- The guardrails now include `NeverTouchItsBudgets` (deny `budgets:ModifyBudget` on `budget/hisho-*`): an unlocked
  Hisho can't change or delete its own budgets. AWS has no separate delete permission (`budgets:DeleteBudget` doesn't
  exist), so that old line protected nothing; the watcher now checks the new statement instead.
- So the "make the monthly budget" button is gone: budgets are made or changed in the AWS console.
- The page shows each budget as AWS has it: amount, spent so far, forecast. `budget_email` setting removed.

## 0.2.1

- Dates (the cost month, the test change's value) are the owner's, not the server's UTC date.

## 0.2.0

- Two changes on the page, offered while they're needed (unlock with your MFA code, read the plan, confirm):
  **turn on CloudTrail** (private, encrypted bucket in us-west-2 that only this account's trail can write to, logs
  deleted after 365 days; multi-region trail `hisho-trail` with log file validation) and **make the monthly budget**
  (`hisho-monthly`, `budget_usd` or $10, emails `budget_email` at 80% and 100% actual and 100% forecast).
- After a change the account is read again, so the page shows it.
- Fixed: right after install the page could say "Reading the account" for a minute after the first read had finished.

## 0.1.0

- First version: inventory, costs and security checks with read-only keys; changes after an MFA unlock of hisho-admin (one test change).
