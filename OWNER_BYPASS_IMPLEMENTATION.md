# Owner Run-Limit Bypass Implementation

## Summary

Implemented owner run-limit bypass across all three services. Tenant users with `role == "owner"` can now bypass run limits, but usage is still tracked for analytics and billing visibility.

## Changes Made

### 1. Flask Backend (`ai-testing-agent/backend`)

**Files Modified:**
- `services/run_limits.py`:
  - Added `is_owner_user()` helper function (queries `tenant_users` table)
  - Updated `increment_run_usage_atomic()` to accept `bypass_limit` parameter
  - Updated `check_and_increment_run_usage()` to accept `user_id` parameter and check owner role
- `app.py`:
  - Updated call site (line 10763) to pass `g.user_id` to `check_and_increment_run_usage()`

### 2. BA Requirements Agent (`ai-sr-business-req-analyst`)

**Files Modified:**
- `app/services/run_limits.py`:
  - Added `is_owner_user()` helper function (same as Flask backend)
  - Updated `increment_run_usage_atomic()` to accept `bypass_limit` parameter
  - Updated `check_and_increment_run_usage()` to accept `user_id` parameter and check owner role
- `app/api/analyze.py`:
  - Updated call site (line 381) to pass `user_id` from `X-User-ID` header

### 3. Jira Writeback Agent (`jira-writeback-agent`)

**Files Modified:**
- `services/run_limits.py`:
  - Added `is_owner_user()` helper function (same as other services)
  - Updated `increment_run_usage_atomic()` to accept `bypass_limit` parameter
  - Updated `check_and_increment_run_usage()` to accept `user_id` parameter and check owner role
- `api/rewrite.py`:
  - Updated call sites (lines 958 and 1707) to pass `user_id` from `X-User-ID` header

## Implementation Details

### Owner Check Logic

```python
def is_owner_user(db: Session, tenant_id: str, user_id: str) -> bool:
    """
    Check if a user has owner role for the given tenant.
    Queries database to ensure role is current (not from stale JWT claim).
    """
    result = db.execute(
        text("""
            SELECT role
            FROM tenant_users
            WHERE tenant_id = :tenant_id
              AND id = :user_id
              AND is_active = true
            LIMIT 1
        """),
        {"tenant_id": tenant_id, "user_id": user_id}
    ).first()
    
    return result and result.role == "owner"
```

### Bypass Behavior

1. **Owner users**: 
   - Run limits are bypassed (no `runs_used < runs_limit` check)
   - Usage is still incremented and tracked
   - Returns `run_allowed=True` with usage data
   - Logs `OWNER_BYPASS` marker

2. **Non-owner users**:
   - Normal enforcement (existing behavior preserved)
   - Blocked with 402 if limit reached

3. **Missing user_id**:
   - Defaults to normal enforcement (no bypass)
   - Logs warning if user_id expected but missing

### Security

- ✅ Role check queries database (not from JWT claim - prevents stale role data)
- ✅ `user_id` is never client-controlled (always from verified JWT or internal headers)
- ✅ Owner check is tenant-scoped (user must belong to the tenant)
- ✅ Only active users can bypass (`is_active = true` check)

## Verification Steps

### 1. Test Owner Bypass

**Setup:**
1. Create a tenant with an owner user
2. Set `runs_used >= runs_limit` for the current period
3. Attempt to run a test plan/analysis as the owner

**Expected:**
- ✅ Run succeeds (not blocked)
- ✅ `runs_used` increments (usage tracked)
- ✅ Log shows `OWNER_BYPASS` marker
- ✅ Response includes usage data

**Check logs:**
```bash
grep "OWNER_BYPASS" <log_file>
# Should show: "OWNER_BYPASS: user_id=<uuid> tenant_id=<uuid> - run limit bypassed (role=owner)"
```

### 2. Test Non-Owner Blocking

**Setup:**
1. Create a tenant with a non-owner user (admin or user role)
2. Set `runs_used >= runs_limit` for the current period
3. Attempt to run a test plan/analysis as the non-owner

**Expected:**
- ❌ Run blocked with HTTP 402
- ❌ Error message: "You've reached your monthly run limit..."
- ❌ `runs_used` does NOT increment

### 3. Test Normal Path (Below Limit)

**Setup:**
1. Any user (owner or non-owner)
2. Set `runs_used < runs_limit` for the current period
3. Attempt to run a test plan/analysis

**Expected:**
- ✅ Run succeeds
- ✅ `runs_used` increments
- ✅ No bypass logging (normal path)

### 4. Test Missing user_id

**Setup:**
1. Call endpoint without `user_id` (should not happen in normal flow, but test edge case)
2. Set `runs_used >= runs_limit`

**Expected:**
- ❌ Run blocked (normal enforcement, no bypass)
- ✅ No errors (graceful handling)

## Database Verification

### Check Owner Role

```sql
-- Verify owner user exists
SELECT id, email, role, tenant_id, is_active
FROM tenant_users
WHERE role = 'owner'
  AND is_active = true;
```

### Check Usage Tracking

```sql
-- Verify runs_used increments for owners even when over limit
SELECT tenant_id, period_key, runs_used, runs_limit
FROM tenant_usage
WHERE tenant_id = '<owner_tenant_id>'
ORDER BY period_key DESC;
```

## Logging

### Owner Bypass Logs

Look for these log entries:
```
INFO: OWNER_BYPASS: user_id=<uuid> tenant_id=<uuid> - run limit bypassed (role=owner)
```

### Usage Data Metadata

When owner bypass is used, `usage_data` includes:
```json
{
  "runs_used": 25,
  "runs_limit": 20,
  "period_start": "2026-01-01T00:00:00",
  "period_end": "2026-01-31T23:59:59",
  "bypassed_limits": true,
  "bypass_reason": "ROLE_OWNER"
}
```

## Production Deployment Checklist

- [ ] Deploy Flask backend changes
- [ ] Deploy BA agent changes
- [ ] Deploy Jira writeback agent changes
- [ ] Verify all services start without errors
- [ ] Test owner bypass with real owner user
- [ ] Test non-owner blocking still works
- [ ] Monitor logs for `OWNER_BYPASS` entries
- [ ] Verify usage tracking continues to work

## Rollback Plan

If issues occur, revert the following:
1. Remove `user_id` parameter from `check_and_increment_run_usage()` calls
2. Remove `bypass_limit` parameter from `increment_run_usage_atomic()` calls
3. Remove `is_owner_user()` function and owner check logic

All changes are backward-compatible (optional parameters), so rollback is safe.
