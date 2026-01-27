# Welcome Email Implementation Report

## A) ONBOARDING COMPLETION ENDPOINTS IDENTIFIED

### 1. Trial Plan Selection (Primary Trigger)
**Endpoint:** `PATCH /api/v1/tenants/<tenant_id>/subscription`  
**File:** `ai-testing-agent/backend/app.py`  
**Function:** `update_tenant_subscription()`  
**Line:** ~6033-6246

**DB Commit Location:**
- Line 6178: `db.commit()` - After trial plan is set and trial counters updated
- This is the final commit for trial plan selection

**User Data Available:**
- User is authenticated (has `g.user_id` and `g.tenant_id`)
- Can query `TenantUser` table using `g.user_id` to get `email` and `first_name`
- User data available at line 6178 (after commit)

**Why This Is The Correct Trigger:**
- This is called when user clicks "Start Trial" on `/onboarding/plan` page
- DB commit happens here, marking onboarding as complete (status='trialing')
- User is authenticated and can be queried

### 2. Paid Plan Completion (Stripe Webhook)
**Endpoint:** Stripe webhook `checkout.session.completed`  
**File:** `ai-testing-agent/backend/services/stripe_webhook_ingest.py`  
**Function:** `_process_checkout_session_completed()`  
**Line:** ~72-267

**DB Commit Location:**
- Line 251: `db.commit()` - After subscription data is updated in tenant_billing

**User Data Available:**
- Have `tenant_id` from webhook metadata
- Need to query for first admin user in tenant to get email/first_name
- Can query `TenantUser` table filtering by `tenant_id` and `role='admin'`, order by `created_at ASC`, limit 1

**Why This Is The Correct Trigger:**
- This is called when Stripe checkout completes successfully
- DB commit happens here, marking subscription as active
- Onboarding is complete at this point

## B) IMPLEMENTATION PLAN

### Email Service
**File:** `ai-testing-agent/backend/services/email_service.py` (NEW)
- Function: `send_welcome_email(to_email: str, first_name: Optional[str] = None) -> bool`
- Uses Resend API
- Returns True on success, False on failure
- Logs errors but doesn't raise exceptions

### Integration Points

1. **Trial Plan** (`app.py` line ~6178):
   - After `db.commit()` for trial plan
   - Query user: `db.query(TenantUser).filter(TenantUser.id == g.user_id).first()`
   - Extract: `email`, `first_name`
   - Call: `send_welcome_email(email, first_name)`
   - Wrap in try/except, log errors, continue

2. **Paid Plan** (`stripe_webhook_ingest.py` line ~251):
   - After `db.commit()` for subscription update
   - Query first admin user: `db.query(TenantUser).filter(TenantUser.tenant_id == tenant_uuid, TenantUser.role == 'admin').order_by(TenantUser.created_at.asc()).first()`
   - Extract: `email`, `first_name`
   - Call: `send_welcome_email(email, first_name)`
   - Wrap in try/except, log errors, continue

## C) ENVIRONMENT VARIABLES REQUIRED

- `RESEND_API_KEY` - Resend API key
- `EMAIL_FROM` - Default: "ScopeTraceAI <hello@scopetraceai.com>" (or use env var)

## D) EMAIL CONTENT

**Subject:** "Welcome to ScopeTraceAI 👋"

**Body:**
```
Thanks for joining!

Here are your next steps:
1. Connect your Jira instance
2. Add tickets or specs
3. Generate your first test plan

Reply to this email if you have any questions.

- The ScopeTraceAI Team
```

**Reply-To:** hello@scopetraceai.com
