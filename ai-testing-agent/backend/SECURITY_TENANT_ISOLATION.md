# Tenant Isolation Security Documentation

## Overview

This document describes how tenant isolation is enforced in the ScopeTraceAI backend to prevent cross-tenant data access.

## Tenant ID Derivation

**Tenant ID is ALWAYS derived server-side from authenticated JWT tokens. Client-provided tenant identifiers are NEVER trusted.**

### Authentication Flow

1. **JWT Token Creation** (`auth/jwt.py`):
   - When a user logs in or registers, a JWT token is created with:
     - `sub`: User ID (UUID)
     - `tenant_id`: Tenant ID (UUID) - **derived from database user record**
     - `role`: User role (e.g., "owner", "admin", "user")
   - The token is signed with `JWT_SECRET` (server-side only)

2. **JWT Token Verification** (`app.py:check_auth()`):
   - All protected routes require `Authorization: Bearer <token>` header
   - Token is verified using `JWT_SECRET` (prevents tampering)
   - Claims are extracted and stored in `flask.g`:
     - `g.user_id` = `payload.get("sub")`
     - `g.tenant_id` = `payload.get("tenant_id")` ← **Server-derived, not client-provided**
     - `g.role` = `payload.get("role")`
   - **Guardrail**: If `tenant_id` is missing from token, request is rejected with 401

3. **Request Context**:
   - All protected endpoints access `g.tenant_id` (never from request body/headers/params)
   - `g.tenant_id` is used for all database queries

## Tenant Scoping Enforcement

### Database Query Pattern

All queries to tenant-owned tables MUST filter by `tenant_id`:

```python
# ✅ CORRECT: Tenant-scoped query
tenant_id = g.tenant_id
runs = db.query(Run).filter(
    Run.run_id == run_id,
    Run.tenant_id == tenant_id  # ← Required filter
).first()

# ❌ WRONG: Missing tenant_id filter
runs = db.query(Run).filter(
    Run.run_id == run_id
).first()  # ← Security vulnerability!
```

### Tenant-Owned Tables

The following tables are tenant-scoped and MUST always filter by `tenant_id`:

- **`runs`**: Test plan generation runs
- **`artifacts`**: Artifact metadata (JSON files)
- **`tenant_users`**: Users within a tenant
- **`tenant_integrations`**: Integration credentials (Jira, etc.)
- **`usage_events`**: Usage tracking events

### Verified Tenant Scoping

All database queries have been audited and verified to include tenant_id filtering:

- ✅ `/api/v1/runs` - Lists runs filtered by `g.tenant_id`
- ✅ `/api/v1/runs/<run_id>` - Gets run filtered by `g.tenant_id`
- ✅ `/api/v1/runs/<run_id>/review` - Updates run filtered by `g.tenant_id`
- ✅ `/api/v1/runs/<run_id>/approve` - Updates run filtered by `g.tenant_id`
- ✅ `/api/v1/runs/<run_id>/jira` - Creates Jira ticket for run filtered by `g.tenant_id`
- ✅ `/api/v1/artifacts/<run_id>/<artifact_type>` - Gets artifact filtered by `g.tenant_id`
- ✅ `/api/v1/integrations/jira` - Gets/updates integration filtered by `g.tenant_id`
- ✅ `/api/v1/tenant/status` - Gets tenant filtered by `g.tenant_id`
- ✅ `/api/v1/tenant/bootstrap-status` - Gets tenant/integration filtered by `g.tenant_id`
- ✅ `/api/v1/jira/meta/projects` - Uses `get_jira_integration_for_current_tenant()` (tenant-scoped)
- ✅ `/api/v1/jira/meta/issue-types` - Uses `get_jira_integration_for_current_tenant()` (tenant-scoped)

### Admin Endpoints (Cross-Tenant Access)

Admin endpoints (`/api/v1/admin/*`) are the ONLY exception to tenant scoping:

- **Access Control**: Requires `owner` or `superAdmin` role (verified in `check_admin_access()`)
- **Purpose**: Allow platform administrators to manage all tenants
- **Security**: Role is verified from database (not just JWT claim)
- **Endpoints**:
  - `/api/v1/admin/tenants` - Lists all tenants (admin only)
  - `/api/v1/admin/tenants/<tenant_id>/trial/reset` - Resets trial for any tenant (admin only)
  - `/api/v1/admin/tenants/<tenant_id>/trial/set` - Sets trial/subscription for any tenant (admin only)

## Client Input Validation

**No client-provided tenant identifiers are accepted or trusted.**

### Verified: No Client Input for Tenant ID

- ✅ No endpoints accept `tenant_id` in request body
- ✅ No endpoints accept `tenant_id` in query parameters
- ✅ No endpoints accept `tenant_id` in headers (except in JWT token, which is verified)
- ✅ All tenant_id values come from `g.tenant_id` (server-derived from JWT)

### Public Endpoints (No Tenant Context)

The following endpoints do NOT require tenant context (by design):

- `/health` - Health check (no auth)
- `/` - Root endpoint (no auth)
- `/auth/login` - Login (creates tenant context)
- `/auth/register` - Registration (creates tenant context)

## Guardrails

### 1. JWT Middleware Guardrail

In `check_auth()` middleware:
```python
# Guardrail: Ensure tenant_id is present (required for tenant isolation)
if not g.tenant_id:
    logger.error("JWT token missing tenant_id claim - rejecting request")
    return jsonify({"detail": "Invalid token: missing tenant_id"}), 401
```

### 2. Helper Functions

**`utils/tenant_isolation.py`** provides helper functions:

- `require_tenant_context()`: Raises error if tenant_id not in request context
- `get_tenant_id()`: Safe getter for tenant_id (returns None if not available)
- `ensure_tenant_scoped_query()`: Helper to add tenant_id filter to queries

### 3. Service Layer Guardrails

Service functions validate tenant_id is provided:

- `services/integrations.py:get_jira_integration_for_current_tenant()`: Requires `g.tenant_id`
- `services/persistence.py`: All functions require `tenant_id` parameter
- `services/usage.py:record_usage_event()`: Requires `tenant_id` parameter (never from request)

## Testing

A tenant isolation audit was performed on [current date] with the following results:

- ✅ All database queries verified to include tenant_id filtering
- ✅ No client-provided tenant identifiers found
- ✅ JWT middleware correctly extracts tenant_id from verified token
- ✅ Admin endpoints properly restrict access to owner/superAdmin roles
- ✅ Guardrails added to prevent future mistakes

## Security Best Practices

1. **Never trust client input** for tenant identification
2. **Always filter by tenant_id** in database queries
3. **Use `g.tenant_id`** from JWT middleware (never from request body/params)
4. **Verify admin access** before allowing cross-tenant operations
5. **Log security violations** (e.g., missing tenant_id in token)

## Future Considerations

- Consider adding automated tests that verify tenant isolation
- Consider adding database-level row-level security (RLS) policies
- Consider adding audit logging for all tenant-scoped operations
