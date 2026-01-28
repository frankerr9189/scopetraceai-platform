# Owner Run-Limit Bypass Preflight Report

## Executive Summary

**Status**: ✅ **READY FOR IMPLEMENTATION**

All three services have access to `user_id` at the point where run limits are enforced. The `user_id` is trustworthy (derived from verified JWT tokens) and available in the request context. Minimal code changes are needed to pass `user_id` to the run limit enforcement functions.

---

## Service-by-Service Analysis

### 1. Flask Backend (`ai-testing-agent/backend`)

#### Run Limit Enforcement Location
- **File**: `app.py`
- **Function**: `generate_test_plan()` (line 10672)
- **Call Site**: Line 10763
- **Function Called**: `check_and_increment_run_usage()` from `services/run_limits.py`

#### User ID Availability
- **Status**: ✅ **YES - Available**
- **Source**: `g.user_id` (line 10680)
- **JWT Claim**: `"sub"` (extracted in `check_auth()` middleware, line 309)
- **Trust Level**: ✅ **Trustworthy** - Extracted from verified JWT token

#### Current Function Signature
```python
# services/run_limits.py:332
def check_and_increment_run_usage(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
```

#### Available Variables at Call Site
```python
# Line 10679-10680
tenant_id = getattr(g, 'tenant_id', None)  # ✅ Available
user_id = getattr(g, 'user_id', None)      # ✅ Available (NOT currently passed)
```

#### Minimal Code Change Required
1. **Update function signature** in `services/run_limits.py`:
   ```python
   def check_and_increment_run_usage(
       db: Session,
       tenant_id: str,
       plan_tier: Optional[str],
       current_period_start: Optional[datetime] = None,
       current_period_end: Optional[datetime] = None,
       user_id: Optional[str] = None  # ← ADD THIS
   ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
   ```

2. **Update call site** in `app.py` line 10763:
   ```python
   run_allowed, run_error, usage_data = check_and_increment_run_usage(
       db=db,
       tenant_id=str(tenant_id),
       plan_tier=plan_tier,
       current_period_start=current_period_start,
       current_period_end=current_period_end,
       user_id=str(user_id) if user_id else None  # ← ADD THIS
   )
   ```

3. **Add owner check logic** in `check_and_increment_run_usage()`:
   ```python
   # Before incrementing, check if user is owner
   if user_id:
       from models import TenantUser
       user = db.query(TenantUser).filter(
           TenantUser.id == user_id,
           TenantUser.tenant_id == tenant_id
       ).first()
       if user and user.role == "owner":
           # Bypass run limit for owners
           return True, None, usage_data
   ```

---

### 2. BA Requirements Agent (`ai-sr-business-req-analyst`)

#### Run Limit Enforcement Location
- **File**: `app/api/analyze.py`
- **Function**: `analyze_requirements()` (line 228)
- **Call Site**: Line 381
- **Function Called**: `check_and_increment_run_usage()` from `services/run_limits.py`

#### User ID Availability
- **Status**: ✅ **YES - Available**
- **Source**: `extract_tenant_context_for_logging(request)` (line 304)
- **Header**: `X-User-ID` (extracted in `middleware/internal_auth.py` line 95)
- **Trust Level**: ✅ **Trustworthy** - Set by Flask app from verified JWT, passed via internal service headers

#### Current Function Signature
```python
# services/run_limits.py:264
def check_and_increment_run_usage(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
```

#### Available Variables at Call Site
```python
# Line 304
tenant_id, user_id = extract_tenant_context_for_logging(request)  # ✅ Both available
# Line 381 - user_id is NOT currently passed
```

#### Minimal Code Change Required
1. **Update function signature** in `services/run_limits.py` (same as Flask backend)
2. **Update call site** in `app/api/analyze.py` line 381:
   ```python
   run_allowed, run_error, usage_data = check_and_increment_run_usage(
       db=db,
       tenant_id=str(tenant_id),
       plan_tier=plan_tier,
       current_period_start=current_period_start,
       current_period_end=current_period_end,
       user_id=user_id  # ← ADD THIS
   )
   ```
3. **Add owner check logic** (same as Flask backend)

---

### 3. Jira Writeback Agent (`jira-writeback-agent`)

#### Run Limit Enforcement Locations
- **File**: `api/rewrite.py`
- **Function 1**: `execute()` (line 830) - Line 958
- **Function 2**: `create_execute()` (line 1594) - Line 1707
- **Function Called**: `check_and_increment_run_usage()` from `services/run_limits.py`

#### User ID Availability
- **Status**: ✅ **YES - Available**
- **Source**: `extract_tenant_context_for_logging(request)` (lines 880, 1649)
- **Header**: `X-User-ID` (extracted in `middleware/internal_auth.py` line 93)
- **Trust Level**: ✅ **Trustworthy** - Set by Flask app from verified JWT, passed via internal service headers

#### Current Function Signature
```python
# services/run_limits.py:264
def check_and_increment_run_usage(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
```

#### Available Variables at Call Sites
```python
# Line 880 (execute function)
tenant_id, user_id = extract_tenant_context_for_logging(request)  # ✅ Both available

# Line 1649 (create_execute function)
tenant_id, user_id = extract_tenant_context_for_logging(request)  # ✅ Both available
```

#### Minimal Code Change Required
1. **Update function signature** in `services/run_limits.py` (same as other services)
2. **Update call site 1** in `api/rewrite.py` line 958:
   ```python
   run_allowed, run_error, usage_data = check_and_increment_run_usage(
       db=db,
       tenant_id=str(tenant_id),
       plan_tier=plan_tier,
       current_period_start=current_period_start,
       current_period_end=current_period_end,
       user_id=user_id  # ← ADD THIS
   )
   ```
3. **Update call site 2** in `api/rewrite.py` line 1707:
   ```python
   run_allowed, run_error, usage_data = check_and_increment_run_usage(
       db=db,
       tenant_id=str(tenant_id),
       plan_tier=plan_tier,
       current_period_start=current_period_start,
       current_period_end=current_period_end,
       user_id=user_id  # ← ADD THIS
   )
   ```
4. **Add owner check logic** (same as other services)

---

## Trust Boundary Analysis

### Authentication Flow

1. **Client → Flask App**:
   - Client sends JWT token in `Authorization: Bearer <token>` header
   - Flask `check_auth()` middleware (line 250) verifies JWT using `JWT_SECRET`
   - Extracts claims: `g.user_id = payload.get("sub")`, `g.tenant_id = payload.get("tenant_id")`, `g.role = payload.get("role")`
   - ✅ **Trustworthy**: JWT is cryptographically verified

2. **Flask App → Internal Agents**:
   - Flask app calls `get_internal_headers()` (agent_client.py line 31)
   - Sets `X-User-ID` header from `g.user_id` (line 63)
   - Sets `X-Tenant-ID` header from `g.tenant_id` (line 61)
   - Internal agents verify `X-Internal-Service-Key` (not JWT)
   - ✅ **Trustworthy**: Only Flask app can set headers (internal service key required)

### Security Considerations

- ✅ `user_id` is **never** client-controlled
- ✅ `user_id` is **always** derived from verified JWT tokens
- ✅ Internal service headers are **only** set by Flask app (policy authority)
- ✅ Role information (`tenant_users.role`) is stored in database (not in JWT)
- ⚠️ **Note**: Role check must query database - JWT `role` claim may be stale

---

## Implementation Recommendations

### 1. Function Signature Update (All Services)

Add `user_id` parameter to `check_and_increment_run_usage()` in all three `run_limits.py` files:

```python
def check_and_increment_run_usage(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None,
    user_id: Optional[str] = None  # ← NEW PARAMETER
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
```

### 2. Owner Bypass Logic

Add owner check **before** incrementing run usage:

```python
# Early return for owners (bypass run limits)
if user_id:
    from models import TenantUser
    user = db.query(TenantUser).filter(
        TenantUser.id == user_id,
        TenantUser.tenant_id == tenant_id,
        TenantUser.role == "owner"
    ).first()
    if user:
        # Owner bypass: return success without incrementing
        # Still compute usage_data for response
        period_key = compute_current_period_key(current_period_start, current_period_end)
        period_start, period_end = compute_usage_period(current_period_start, current_period_end)
        runs_limit = get_runs_limit_for_plan_tier(plan_tier)
        
        # Get current usage for response (don't increment)
        usage = get_tenant_usage(db, tenant_id, period_key)
        if usage:
            usage_data = {
                "runs_used": usage["runs_used"],
                "runs_limit": runs_limit,
                "period_start": usage.get("period_start") or period_start.isoformat(),
                "period_end": usage.get("period_end") or period_end.isoformat()
            }
        else:
            usage_data = {
                "runs_used": 0,
                "runs_limit": runs_limit,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat()
            }
        
        logger.info(f"OWNER_BYPASS: user_id={user_id} tenant_id={tenant_id} - run limit bypassed")
        return True, None, usage_data
```

### 3. Call Site Updates

Update all 4 call sites to pass `user_id`:
- ✅ Flask backend: `app.py` line 10763
- ✅ BA agent: `app/api/analyze.py` line 381
- ✅ Jira agent: `api/rewrite.py` line 958
- ✅ Jira agent: `api/rewrite.py` line 1707

---

## Summary Table

| Service | user_id Available? | Source | Trust Level | Call Sites | Change Required |
|---------|-------------------|--------|-------------|------------|-----------------|
| **Flask Backend** | ✅ YES | `g.user_id` (JWT "sub") | ✅ Trustworthy | 1 | Add parameter + pass `user_id` |
| **BA Agent** | ✅ YES | `X-User-ID` header | ✅ Trustworthy | 1 | Add parameter + pass `user_id` |
| **Jira Agent** | ✅ YES | `X-User-ID` header | ✅ Trustworthy | 2 | Add parameter + pass `user_id` |

---

## Conclusion

✅ **All services have trustworthy `user_id` access at run limit enforcement points.**

The implementation is straightforward:
1. Add `user_id` parameter to `check_and_increment_run_usage()` in all 3 services
2. Add owner bypass check (query `tenant_users` table) before incrementing
3. Update 4 call sites to pass `user_id`

**No UI changes required** - this is purely server-side logic.

**No breaking changes** - `user_id` parameter is optional, so existing code continues to work.
