# Onboarding Gating Step 1 – Dev Note

## Migration: `b4e7f8a9c0d1_add_subscription_trial_to_tenants`

Adds to `tenants`:

- `subscription_status` (varchar, NOT NULL, default `'Trial'`)
- `trial_requirements_runs_remaining` (int, NOT NULL, default `3`)
- `trial_testplan_runs_remaining` (int, NOT NULL, default `3`)
- `trial_writeback_runs_remaining` (int, NOT NULL, default `3`)

## Apply migration

```bash
cd ai-testing-agent/backend
python3 -m flask --app app db upgrade
```

## Verify (SQL)

After upgrading, check that existing tenants have the new defaults:

```sql
SELECT id, name, slug, subscription_status,
       trial_requirements_runs_remaining,
       trial_testplan_runs_remaining,
       trial_writeback_runs_remaining
FROM tenants;
```

Expected for all rows:

- `subscription_status = 'Trial'`
- `trial_requirements_runs_remaining = 3`
- `trial_testplan_runs_remaining = 3`
- `trial_writeback_runs_remaining = 3`

## Verify via Python (dev)

From `ai-testing-agent/backend` (so `db` and `DATABASE_URL` resolve):

```bash
python3 -c "
from db import engine
from sqlalchemy import text
with engine.connect() as c:
    rows = c.execute(text('''
        SELECT id, subscription_status,
               trial_requirements_runs_remaining,
               trial_testplan_runs_remaining,
               trial_writeback_runs_remaining
        FROM tenants
        ORDER BY created_at DESC
        LIMIT 5
    '''))
    for r in rows:
        print(dict(r._mapping))
"
```

Or with `psql` (if `DATABASE_URL` is set):

```bash
psql "$DATABASE_URL" -c "SELECT id, subscription_status, trial_requirements_runs_remaining, trial_testplan_runs_remaining, trial_writeback_runs_remaining FROM tenants ORDER BY created_at DESC LIMIT 5;"
```

## Allowed `subscription_status` values

- `Trial`
- `Active`
- `Paywalled`
