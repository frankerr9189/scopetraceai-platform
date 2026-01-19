# Centralized Entitlements Architecture

## Overview

This document describes the centralized entitlements and plan tier enforcement architecture for ScopeTraceAI. All subscription, plan tier, seat, and usage enforcement is centralized in the Flask backend (`ai-testing-agent/backend`). Agent services (`ai-sr-business-req-analyst`, `jira-writeback-agent`) are trusted internal executors that only validate internal service keys.

## Trust Boundaries

### Flask App (Policy Authority)
- **Location**: `ai-testing-agent/backend`
- **Responsibility**: Single source of truth for all policy enforcement
- **Enforces**:
  - Plan tiers (free/solo/team/business)
  - Seat caps
  - Ticket limits per run
  - Input size limits
  - Subscription status gating (Trial/Active/Paywalled)
  - Trial counters (preserves existing behavior)
- **Authenticates**: End users via Supabase JWT
- **Calls Agents**: Via HTTP with `X-Internal-Service-Key` header

### Agent Services (Execution Only)
- **Locations**: 
  - `ai-sr-business-req-analyst` (FastAPI)
  - `jira-writeback-agent` (FastAPI)
- **Responsibility**: Trusted internal executors
- **MUST NOT**:
  - Implement plan tiers
  - Enforce seat caps
  - Check trial counters
  - Check subscription_status
- **MUST**:
  - Require `X-Internal-Service-Key` header
  - Compare to `INTERNAL_SERVICE_KEY` env var
  - Reject requests with missing/invalid key (401)
- **MAY**:
  - Parse request payload
  - Perform agent logic
  - Log tenant_id and user_id (from headers)
  - Validate input schema

## Implementation Details

### Centralized Entitlements System

**File**: `ai-testing-agent/backend/services/entitlements_centralized.py`

- `enforce_entitlements()`: Comprehensive enforcement function
- `get_tenant_plan_tier()`: Determines plan tier from subscription_status
- `check_seat_cap()`: Validates seat limits
- `check_ticket_limit()`: Validates ticket count limits
- `check_input_size_limit()`: Validates input character count limits
- `check_subscription_status()`: Validates subscription status gating
- `check_trial_remaining()`: Validates trial counters (preserves existing behavior)

### Plan Tier Definitions

```python
PLAN_TIERS = {
    "free": {
        "seat_cap": 1,
        "max_tickets_per_run": 5,
        "max_input_chars": 10000,
        "trial_runs": {"requirements": 3, "testplan": 3, "writeback": 3}
    },
    "solo": {
        "seat_cap": 1,
        "max_tickets_per_run": 20,
        "max_input_chars": 50000,
        "trial_runs": None  # No trial limits for paid plans
    },
    "team": {
        "seat_cap": 10,
        "max_tickets_per_run": 50,
        "max_input_chars": 200000,
        "trial_runs": None
    },
    "business": {
        "seat_cap": 100,
        "max_tickets_per_run": 200,
        "max_input_chars": 1000000,
        "trial_runs": None
    }
}
```

### Agent HTTP Client

**File**: `ai-testing-agent/backend/services/agent_client.py`

- `call_ba_agent()`: Calls BA Requirements Agent with internal key
- `call_jira_writeback_agent()`: Calls Jira Writeback Agent with internal key
- `get_internal_headers()`: Builds headers with `X-Internal-Service-Key` and tenant context

### Internal Service Authentication

**Files**:
- `ai-sr-business-req-analyst/app/middleware/internal_auth.py`
- `jira-writeback-agent/middleware/internal_auth.py`

- `verify_internal_service_key()`: Validates `X-Internal-Service-Key` header
- `extract_tenant_context_for_logging()`: Extracts tenant/user context for logging (not enforcement)

## Environment Variables

### Required
- `INTERNAL_SERVICE_KEY`: Shared secret for agent authentication (must match in Flask and all agents)

### Optional
- `BA_AGENT_BASE_URL`: Base URL for BA agent (default: `http://localhost:8000`)
- `JIRA_WRITEBACK_AGENT_BASE_URL`: Base URL for Jira writeback agent (default: `http://localhost:8001`)
- `ENTITLEMENT_FAIL_OPEN`: If `true`, allows requests when entitlement checks fail (default: `false`)

## Trial Counter Behavior

**PRESERVED**: Existing trial counter logic remains unchanged:
- `consume_trial_run()` in `services/entitlements.py` supports agent-specific consumption
- Trial counters decrement only when `subscription_status == "Trial"`
- When all three counters reach 0, `subscription_status` is set to `"Paywalled"`
- Trial consumption happens in Flask after successful agent execution

## Migration Notes

### Breaking Changes
- Agent services no longer accept JWT tokens for authentication
- Agent services require `X-Internal-Service-Key` header
- Frontend must call Flask endpoints (not agents directly) for policy enforcement

### Backward Compatibility
- Trial counter behavior is preserved
- Existing `consume_trial_run()` function signature updated to support agent parameter (defaults to `"test_plan"` for compatibility)

## Future Work

1. **Flask Proxy Endpoints**: Create Flask endpoints that proxy requests to agents after entitlement checks
2. **Plan Tier Column**: Add explicit `plan_tier` column to `tenants` table (currently inferred from `subscription_status`)
3. **Frontend Updates**: Update frontend to call Flask endpoints instead of agents directly

## Security Considerations

- `INTERNAL_SERVICE_KEY` must be kept secret and rotated periodically
- Agents should not be directly exposed to the internet (or protected by internal key)
- All policy enforcement happens in Flask before agent calls
- Agents trust Flask as the policy authority
