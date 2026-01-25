# Pre-Production Audit Report

**Date:** 2025-01-18  
**Scope:** All three backend services (ai-testing-agent, ai-sr-business-req-analyst, jira-writeback-agent)  
**Type:** Configuration and Security Audit (No Code Changes)

---

## Executive Summary

### ✅ Strengths
- Environment variables are properly read from `os.getenv()` (not hardcoded)
- CORS origins support environment variable override via `CORS_ALLOWED_ORIGINS`
- Database URLs read from `DATABASE_URL` env var
- Stripe configuration uses env vars (`STRIPE_SECRET_KEY`, `STRIPE_PRICE_*`, `APP_BASE_URL`)
- Service URLs use env vars with localhost defaults (acceptable for dev)

### ⚠️ Risks Identified
1. **Hardcoded localhost fallbacks in error handlers** (8 instances across 2 services)
2. **Service URL defaults to localhost** (acceptable but should be documented)
3. **CORS origins include localhost in production code** (acceptable if env var override works)

---

## 1. Hardcoded localhost URLs (RISK: MEDIUM)

### Issue
Error handlers in agent services have hardcoded `"http://localhost:5173"` as fallback when CORS origin list is empty.

### Locations

#### ai-sr-business-req-analyst/app/api/analyze.py
- **Line 286:** `allowed_origin = origin if origin in allowed_origins else (allowed_origins[0] if allowed_origins else "http://localhost:5173")`
- **Line 376:** Same pattern (duplicate in error handler)
- **Line 406:** Same pattern (duplicate in error handler)

#### jira-writeback-agent/api/rewrite.py
- **Line 865:** `allowed_origin = origin if origin in allowed_origins else (allowed_origins[0] if allowed_origins else "http://localhost:5173")`
- **Line 956:** Same pattern (duplicate)
- **Line 987:** Same pattern (duplicate)
- **Line 1660:** Same pattern (duplicate)
- **Line 1751:** Same pattern (duplicate)
- **Line 1782:** Same pattern (duplicate)

### Risk Assessment
- **Severity:** MEDIUM
- **Impact:** If `ALLOWED_ORIGINS` list is empty in production, error responses will include `Access-Control-Allow-Origin: http://localhost:5173`, which could:
  - Allow unauthorized CORS requests in edge cases
  - Cause confusion in error responses
  - Potentially expose error details to wrong origin

### Proposed Fix (NOT IMPLEMENTED)
```python
# Instead of:
allowed_origin = origin if origin in allowed_origins else (allowed_origins[0] if allowed_origins else "http://localhost:5173")

# Use:
allowed_origin = origin if origin in allowed_origins else (allowed_origins[0] if allowed_origins else None)
# Then check if allowed_origin is None before setting header, or use a production-safe default from env
```

**Alternative:** Add `CORS_DEFAULT_ORIGIN` env var and use that as fallback instead of hardcoded localhost.

---

## 2. Service URLs (RISK: LOW)

### Current Implementation
**File:** `ai-testing-agent/backend/services/agent_client.py`
- **Line 22:** `BA_AGENT_BASE_URL = os.getenv("BA_AGENT_BASE_URL", "http://localhost:8000")`
- **Line 23:** `JIRA_WRITEBACK_AGENT_BASE_URL = os.getenv("JIRA_WRITEBACK_AGENT_BASE_URL", "http://localhost:8001")`

### Assessment
- ✅ **Reads from environment** (`BA_AGENT_BASE_URL`, `JIRA_WRITEBACK_AGENT_BASE_URL`)
- ✅ **Has localhost default** (acceptable for development)
- ⚠️ **No validation** that env var is set in production (will silently use localhost if missing)

### Risk Assessment
- **Severity:** LOW (but could cause production failures if env vars not set)
- **Impact:** If env vars are not set in production, service calls will fail to localhost, causing 500 errors

### Recommendation
- **Document required env vars** in deployment checklist
- **Consider:** Fail-fast if env vars not set in production (check `ENVIRONMENT` or `FLASK_ENV`)

---

## 3. CORS Configuration (RISK: LOW)

### Current Implementation

#### All Three Services
- **Base origins:** Hardcoded list includes localhost + production domains
- **Env override:** `CORS_ALLOWED_ORIGINS` env var adds additional origins
- **Production domains included:**
  - `https://app.scopetraceai.com`
  - `https://scopetraceai-platform.vercel.app`
  - `https://scopetraceai-platform.onrender.com` (only in ai-testing-agent and ai-sr-business-req-analyst)
  - `https://scopetraceai.com`
  - `https://www.scopetraceai.com`

### Assessment
- ✅ **Production domains are included** in base list
- ✅ **Supports env var override** via `CORS_ALLOWED_ORIGINS`
- ⚠️ **Localhost origins remain in production code** (acceptable if env var override works, but could be cleaner)

### Risk Assessment
- **Severity:** LOW
- **Impact:** Minimal - localhost origins won't work from production anyway, and env var override allows customization

### Recommendation
- **Verify** `CORS_ALLOWED_ORIGINS` is set in production environment
- **Consider:** Use env var for ALL origins in production (remove hardcoded list), but keep hardcoded for dev convenience

---

## 4. Environment Variables Audit

### ai-testing-agent/backend

#### Required Variables
| Variable | Usage | Location |
|----------|-------|----------|
| `DATABASE_URL` | PostgreSQL connection string | `db.py`, `app.py` (multiple) |
| `JWT_SECRET` | JWT token signing/verification | `auth/jwt.py`, `app.py` |
| `OPENAI_API_KEY` | LLM API calls | `app.py:352` |
| `INTERNAL_SERVICE_KEY` | Agent service authentication | `services/agent_client.py:26` |
| `STRIPE_SECRET_KEY` | Stripe API operations | `app.py:6243, 6394` |
| `STRIPE_PRICE_INDIVIDUAL` | Stripe price mapping | `app.py:6248`, `services/stripe_webhook_ingest.py:44` |
| `STRIPE_PRICE_TEAM` | Stripe price mapping | `app.py:6249`, `services/stripe_webhook_ingest.py:45` |
| `STRIPE_PRICE_PRO` | Stripe price mapping | `app.py:6250`, `services/stripe_webhook_ingest.py:46` |
| `APP_BASE_URL` | Stripe checkout/portal return URLs | `app.py:6244, 6395, 6417` |
| `BA_AGENT_BASE_URL` | BA agent service URL | `services/agent_client.py:22` |
| `JIRA_WRITEBACK_AGENT_BASE_URL` | Jira agent service URL | `services/agent_client.py:23` |

#### Optional Variables
| Variable | Usage | Default |
|----------|-------|---------|
| `CORS_ALLOWED_ORIGINS` | Additional CORS origins (comma-separated) | `""` |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signature verification | **REQUIRED** - `services/stripe_webhook_ingest.py:789` |
| `DEBUG_REQUIREMENTS` | Debug logging flag | `"0"` |
| `ENTITLEMENT_FAIL_OPEN` | Entitlement check fail-open mode | `"false"` |
| `ENVIRONMENT` | Environment identifier | `"development"` |
| `FLASK_ENV` | Flask environment | Not set |
| `JIRA_PROJECT_KEY` | Default Jira project | Not set |
| `JIRA_ISSUE_TYPE` | Default Jira issue type | `"Task"` |
| `INTEGRATION_SECRET_KEY` | Encryption for stored secrets | `utils/encryption.py` |

#### ⚠️ Required Variable (Previously Missing from Checklist)
- **`STRIPE_WEBHOOK_SECRET`:** **REQUIRED** - Used in `services/stripe_webhook_ingest.py:789` for signature verification. Webhook will fail if not set.

### ai-sr-business-req-analyst

#### Required Variables
| Variable | Usage | Location |
|----------|-------|----------|
| `DATABASE_URL` | PostgreSQL connection (loaded from testing agent .env) | `app/main.py:28` |
| `JWT_SECRET` | JWT (loaded from testing agent .env) | `app/main.py:28` |
| `INTERNAL_SERVICE_KEY` | Internal service authentication | `app/middleware/internal_auth.py:24` |
| `OPENAI_API_KEY` | LLM API calls | Not directly checked (should be) |

#### Optional Variables
| Variable | Usage | Default |
|----------|-------|---------|
| `CORS_ALLOWED_ORIGINS` | Additional CORS origins | `""` |
| `BA_AGENT_BASE_URL` | Self-reference (if needed) | Not used |

#### ⚠️ Risk
- **`OPENAI_API_KEY`:** Not validated at startup. Service may fail silently if missing.

### jira-writeback-agent

#### Required Variables
| Variable | Usage | Location |
|----------|-------|----------|
| `DATABASE_URL` | PostgreSQL connection (loaded from testing agent .env) | `main.py:28` |
| `JWT_SECRET` | JWT (loaded from testing agent .env) | `main.py:28` |
| `INTERNAL_SERVICE_KEY` | Internal service authentication | `middleware/internal_auth.py:24` |
| `JIRA_BASE_URL` | Jira instance URL | `src/jira_writeback_agent/config.py` |
| `JIRA_EMAIL` | Jira API email | `src/jira_writeback_agent/config.py` |
| `JIRA_API_TOKEN` | Jira API token | `src/jira_writeback_agent/config.py` |

#### Optional Variables
| Variable | Usage | Default |
|----------|-------|---------|
| `CORS_ALLOWED_ORIGINS` | Additional CORS origins | `""` |
| `JIRA_ACCEPTANCE_CRITERIA_FIELD_ID` | Custom field ID | Not set |

---

## 5. URL Configuration Audit

### ✅ Properly Configured (Read from Env)
- **Stripe return URLs:** `f"{app_base_url}/settings/billing"` (uses `APP_BASE_URL` env var)
- **Database URLs:** All services read from `DATABASE_URL`
- **Service URLs:** `BA_AGENT_BASE_URL`, `JIRA_WRITEBACK_AGENT_BASE_URL` read from env

### ⚠️ Hardcoded URLs Found
- **Error handler fallbacks:** `"http://localhost:5173"` (8 instances) - See Section 1
- **Service URL defaults:** `"http://localhost:8000"`, `"http://localhost:8001"` (acceptable for dev)

---

## 6. Production Readiness Checklist

### Environment Variables

#### ai-testing-agent/backend/.env
```bash
# REQUIRED
DATABASE_URL=postgresql://...
JWT_SECRET=...
OPENAI_API_KEY=sk-...
INTERNAL_SERVICE_KEY=...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PRICE_INDIVIDUAL=price_...
STRIPE_PRICE_TEAM=price_...
STRIPE_PRICE_PRO=price_...
APP_BASE_URL=https://app.scopetraceai.com
BA_AGENT_BASE_URL=https://ba-agent.scopetraceai.com
JIRA_WRITEBACK_AGENT_BASE_URL=https://jira-agent.scopetraceai.com

# REQUIRED
STRIPE_WEBHOOK_SECRET=whsec_...  # Required for webhook signature verification

# OPTIONAL
CORS_ALLOWED_ORIGINS=https://app.scopetraceai.com,https://www.scopetraceai.com
ENVIRONMENT=production
```

#### ai-sr-business-req-analyst/.env
```bash
# REQUIRED
OPENAI_API_KEY=sk-...
INTERNAL_SERVICE_KEY=...  # Must match testing agent

# OPTIONAL
CORS_ALLOWED_ORIGINS=https://app.scopetraceai.com
```

#### jira-writeback-agent/.env
```bash
# REQUIRED
JIRA_BASE_URL=https://your-instance.atlassian.net
JIRA_EMAIL=...
JIRA_API_TOKEN=...
INTERNAL_SERVICE_KEY=...  # Must match testing agent

# OPTIONAL
CORS_ALLOWED_ORIGINS=https://app.scopetraceai.com
JIRA_ACCEPTANCE_CRITERIA_FIELD_ID=...
```

---

## 7. Recommendations

### High Priority
1. **Set `STRIPE_WEBHOOK_SECRET`** - **REQUIRED** for webhook signature verification (will fail if missing)
2. **Verify `APP_BASE_URL`** is set correctly (used for Stripe return URLs)
3. **Set `BA_AGENT_BASE_URL` and `JIRA_WRITEBACK_AGENT_BASE_URL`** in production
4. **Set `CORS_ALLOWED_ORIGINS`** in production to restrict origins

### Medium Priority
1. **Fix hardcoded localhost fallbacks** in error handlers (see Section 1)
2. **Add validation** for required env vars at startup (fail-fast)
3. **Document** all required env vars in deployment guide

### Low Priority
1. **Consider** removing localhost from base CORS list in production builds
2. **Add** health check endpoints that verify env var configuration

---

## 8. Security Notes

### ✅ Good Practices
- JWT secrets read from env (not hardcoded)
- Database URLs read from env
- Internal service keys read from env
- Stripe keys read from env
- CORS supports env var override

### ⚠️ Areas for Improvement
- **Error handler fallbacks:** Should not default to localhost in production
- **Env var validation:** Should fail-fast if required vars missing
- **Webhook secret:** `STRIPE_WEBHOOK_SECRET` is **REQUIRED** - ensure it's set in production

---

## 9. Summary of Findings

| Category | Status | Risk Level |
|----------|--------|------------|
| Environment Variables | ✅ Read from env | LOW |
| CORS Configuration | ✅ Supports env override | LOW |
| Service URLs | ✅ Read from env (with localhost defaults) | LOW |
| Hardcoded localhost fallbacks | ⚠️ 8 instances in error handlers | MEDIUM |
| Stripe Configuration | ✅ All from env | LOW |
| Database URLs | ✅ All from env | LOW |

---

## 10. Proposed Fixes (NOT IMPLEMENTED)

### Fix 1: Remove Hardcoded localhost Fallbacks
**Files:** `ai-sr-business-req-analyst/app/api/analyze.py`, `jira-writeback-agent/api/rewrite.py`

**Change:**
```python
# Current:
allowed_origin = origin if origin in allowed_origins else (allowed_origins[0] if allowed_origins else "http://localhost:5173")

# Proposed:
default_origin = os.getenv("CORS_DEFAULT_ORIGIN", allowed_origins[0] if allowed_origins else None)
allowed_origin = origin if origin in allowed_origins else default_origin
if not allowed_origin:
    # Don't set CORS header if no valid origin
    pass
```

### Fix 2: Validate Required Env Vars at Startup
**Files:** All three services' main.py/app.py

**Add:**
```python
# At startup, validate required env vars
required_vars = {
    "DATABASE_URL": os.getenv("DATABASE_URL"),
    "JWT_SECRET": os.getenv("JWT_SECRET"),
    "INTERNAL_SERVICE_KEY": os.getenv("INTERNAL_SERVICE_KEY"),
}
missing = [k for k, v in required_vars.items() if not v]
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
```

---

**END OF AUDIT REPORT**
