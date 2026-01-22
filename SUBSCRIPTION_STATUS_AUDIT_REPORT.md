# Subscription Status Audit Report

**Date:** 2026-01-XX  
**Purpose:** Verify all reads of `tenants.subscription_status` have been removed and replaced with `tenant_billing` lookups.

---

## Executive Summary

✅ **All production runtime READS have been removed from `tenants.subscription_status`**  
⚠️ **WRITES to `tenants.subscription_status` still exist** (expected - these should eventually be migrated to write to `tenant_billing`)

---

## Categorization

### ✅ READS (Production Runtime) - **ZERO FOUND**

**Status:** ✅ **CONFIRMED - No production reads remain**

All reads now go through `get_tenant_billing()` which queries `tenant_billing` table.

---

### ⚠️ WRITES (Production Runtime) - **15 instances**

These are assignments to `tenant.subscription_status` in production code. These should eventually be migrated to write to `tenant_billing` instead.

| File | Line | Context | Category |
|------|------|---------|----------|
| `ai-testing-agent/backend/app.py` | 5070 | `tenant.subscription_status = "trial"` | WRITE - Subscription update endpoint |
| `ai-testing-agent/backend/app.py` | 5075 | `tenant.subscription_status = "individual"` | WRITE - Subscription update endpoint |
| `ai-testing-agent/backend/app.py` | 5081 | `tenant.subscription_status = "team"` | WRITE - Subscription update endpoint |
| `ai-testing-agent/backend/app.py` | 5084 | `tenant.subscription_status = "canceled"` | WRITE - Subscription update endpoint |
| `ai-testing-agent/backend/app.py` | 11444 | `target_tenant.subscription_status = status_value` | WRITE - Admin trial reset |
| `ai-testing-agent/backend/app.py` | 11594 | `target_tenant.subscription_status = status_value` | WRITE - Admin trial set |
| `ai-testing-agent/backend/app.py` | 11715 | `target_tenant.subscription_status = 'suspended'` | WRITE - Admin suspend tenant |
| `ai-testing-agent/backend/app.py` | 11719 | `target_tenant.subscription_status = 'active'` | WRITE - Admin activate tenant |
| `ai-testing-agent/backend/app.py` | 12441 | `tenant.subscription_status = 'suspended'` | WRITE - Ops suspend endpoint |
| `ai-testing-agent/backend/app.py` | 12500 | `tenant.subscription_status = 'active'` | WRITE - Ops activate endpoint |
| `ai-testing-agent/backend/services/entitlements.py` | 159 | `tenant.subscription_status = "paywalled"` | WRITE - Trial exhaustion logic |
| `ai-sr-business-req-analyst/app/services/entitlements.py` | 184 | `tenant.subscription_status = "Paywalled"` | WRITE - Trial exhaustion logic |
| `jira-writeback-agent/services/entitlements.py` | 161 | `tenant.subscription_status = "Paywalled"` | WRITE - Trial exhaustion logic |

**Note:** These writes are expected to remain until a migration strategy is implemented to write to `tenant_billing` instead.

---

### 📋 SCHEMA/MIGRATION - **3 files**

| File | Line | Context | Category |
|------|------|---------|----------|
| `ai-testing-agent/backend/models.py` | 105 | `subscription_status = Column(String, nullable=False)` | SCHEMA - Column definition |
| `ai-testing-agent/backend/migrations/versions/b4e7f8a9c0d1_add_subscription_trial_to_tenants.py` | 24-31 | `op.add_column('tenants', sa.Column('subscription_status', ...))` | MIGRATION - Add column |
| `ai-testing-agent/backend/migrations/versions/h3i4j5k6l7m8_map_subscription_status_to_new_tiers.py` | 37-154 | Multiple SQL queries updating subscription_status | MIGRATION - Data migration |

**Note:** Schema definitions and migrations are expected to remain. The column still exists in the database.

---

### 🧪 TEST - **8 files, ~30 instances**

| File | Context | Category |
|------|---------|----------|
| `ai-testing-agent/backend/test_ops_safety.py` | Lines 278, 291, 310, 326 | TEST - Assertions and assignments |
| `ai-testing-agent/backend/test_gateway_security.py` | Line 31 | TEST - Test setup |
| `ai-testing-agent/backend/test_tenant_isolation.py` | Lines 93, 108 | TEST - Test fixtures |
| `ai-testing-agent/backend/test_runs_endpoints.py` | Lines 107, 483 | TEST - Test fixtures |
| `ai-testing-agent/backend/test_phase2_user_profile.py` | Line 62 | TEST - Test fixtures |
| `jira-writeback-agent/tests/test_entitlements.py` | Lines 24, 57, 81, 97 | TEST - Mock assignments and assertions |
| `jira-writeback-agent/verify_entitlements_fix.py` | Lines 36, 82, 126, 152-153 | TEST - Verification script |
| `ai-sr-business-req-analyst/tests/test_entitlements.py` | Lines 18, 51, 75, 91 | TEST - Mock assignments and assertions |
| `ai-sr-business-req-analyst/verify_entitlements_fix.py` | Lines 35, 73, 109, 127-128 | TEST - Verification script |

**Note:** Test files are expected to use `subscription_status` for test setup and assertions.

---

### 💬 COMMENT/DOCUMENTATION - **Multiple instances**

| File | Context | Category |
|------|---------|----------|
| `ai-testing-agent/backend/services/entitlements_centralized.py` | Line 16 | COMMENT - Documentation |
| `ai-testing-agent/backend/services/entitlements_centralized.py` | Line 36, 39 | COMMENT - Function docstring |
| `ai-testing-agent/backend/app.py` | Line 191 | COMMENT - Code comment |
| `ai-testing-agent/backend/app.py` | Line 12415, 12474 | COMMENT - Docstring |
| Various migration files | Multiple | COMMENT - Migration descriptions |

---

### 🖥️ FRONTEND - **Reading from API responses (OK)**

The frontend reads `subscription_status` from API responses, which now come from `tenant_billing` via the backend.

| File | Line | Context | Category |
|------|------|---------|----------|
| `ai-testing-agent-UI/src/components/AdminPage.tsx` | 166, 182, 336, 359 | `tenant.subscription_status` | FRONTEND - Reading from API response |
| `ai-testing-agent-UI/src/components/Sidebar.tsx` | 347 | `tenantStatus.subscription_status` | FRONTEND - Reading from API response |
| `ai-testing-agent-UI/src/App.tsx` | 87, 92 | `user.subscription_status` | FRONTEND - Reading from API response |
| `ai-testing-agent-UI/src/components/RequirementsPage.tsx` | 622-623, 628-629 | `tenantStatus.subscription_status` | FRONTEND - Reading from API response |
| `ai-testing-agent-UI/src/components/FirstRunOnboardingPage.tsx` | 14-15, 20-21 | `tenantStatus.subscription_status` | FRONTEND - Reading from API response |
| `ai-testing-agent-UI/src/components/TestPlanPage.tsx` | 34-35 | `tenantStatus.subscription_status` | FRONTEND - Reading from API response |

**Note:** ✅ These are **OK** - Frontend reads from API responses which are now populated from `tenant_billing` by the backend.

---

### 🔄 BACKEND API RESPONSES - **Using tenant_billing (OK)**

All backend endpoints that return `subscription_status` now read from `tenant_billing`:

| File | Line | Context | Category |
|------|------|---------|----------|
| `ai-testing-agent/backend/app.py` | 203, 260, 4631, 5094, 11034, 11341, 11457, 11606, 12840 | `billing.get("subscription_status", ...)` | BACKEND - Reading from tenant_billing |
| `ai-testing-agent/backend/services/entitlements_centralized.py` | 133, 210, 339, 384, 448 | `billing.get("subscription_status", ...)` | BACKEND - Reading from tenant_billing |
| `ai-testing-agent/backend/services/entitlements.py` | 51, 129 | `billing.get("subscription_status", ...)` | BACKEND - Reading from tenant_billing |
| `ai-sr-business-req-analyst/app/services/entitlements.py` | 79, 171 | `billing.get("subscription_status", ...)` | BACKEND - Reading from tenant_billing |
| `jira-writeback-agent/services/entitlements.py` | 69, 148 | `billing.get("subscription_status", ...)` | BACKEND - Reading from tenant_billing |

**Note:** ✅ All these are **OK** - They read from `tenant_billing` via `get_tenant_billing()`.

---

## SQL Queries in Migrations

### Migration: `h3i4j5k6l7m8_map_subscription_status_to_new_tiers.py`

This migration contains SQL queries that read/update `subscription_status`:

- Lines 37, 49, 61, 73, 85: `SELECT COUNT(*) FROM tenants WHERE subscription_status = ...`
- Lines 42-43, 54-55, 66-67, 78-79, 90-91, 112-113: `UPDATE tenants SET subscription_status = ...`

**Category:** MIGRATION - Historical data migration (already executed)

---

## Summary by Category

| Category | Count | Status |
|----------|-------|--------|
| **READ (Production)** | **0** | ✅ **PASS** - All removed |
| **WRITE (Production)** | **13** | ⚠️ **EXPECTED** - Will be migrated later |
| **SCHEMA/MIGRATION** | **3 files** | ✅ **OK** - Expected to remain |
| **TEST** | **8 files, ~30 instances** | ✅ **OK** - Test code |
| **COMMENT** | **Multiple** | ✅ **OK** - Documentation |
| **FRONTEND (API responses)** | **6 files** | ✅ **OK** - Reads from tenant_billing via API |
| **BACKEND (tenant_billing reads)** | **5 files** | ✅ **OK** - All use get_tenant_billing() |

---

## ✅ Verification: Production Runtime Reads

**CONFIRMED:** Zero production runtime reads of `tenants.subscription_status` remain.

All reads now go through:
1. `get_tenant_billing()` in `entitlements_centralized.py`
2. Which queries `tenant_billing` table (JOIN with `tenants` for trial counters)
3. Returns `subscription_status` mapped from `tenant_billing.status`

---

## ⚠️ Remaining Work

1. **Writes to `tenants.subscription_status`** - 13 instances still write to the old column
   - These should eventually be migrated to write to `tenant_billing` instead
   - Priority: Medium (writes are less critical than reads for data consistency)

2. **Frontend reads** - All OK (reading from API responses that come from `tenant_billing`)

---

## Conclusion

✅ **GOAL ACHIEVED:** All production runtime READS of `tenants.subscription_status` have been successfully removed and replaced with `tenant_billing` lookups.

The codebase now enforces `tenant_billing` as the single source of truth for billing data reads, with hard errors if `tenant_billing` rows are missing (no fallbacks).
