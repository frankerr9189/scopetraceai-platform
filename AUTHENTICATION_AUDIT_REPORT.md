# Authentication System Audit Report
**Date:** 2025-01-XX  
**Scope:** Complete authentication system analysis for ScopeTraceAI

## Executive Summary

**FINAL VERDICT: Custom Authentication System Only - No Supabase Auth**

The application uses **100% custom authentication** with bcrypt password hashing and custom JWT tokens. There is **NO Supabase Auth** integration. The `password_hash` column in `tenant_users` is actively used and is the single source of truth for authentication.

---

## 1. Authentication System Analysis

### 1.1 Custom Authentication (ACTIVE)

**Implementation:** Custom bcrypt-based password hashing with custom JWT tokens

**Key Files:**
- `ai-testing-agent/backend/services/auth.py` - Password hashing/verification utilities
- `ai-testing-agent/backend/auth/jwt.py` - JWT token creation/verification
- `ai-testing-agent/backend/app.py` - Authentication endpoints and middleware

**Password Hashing:**
- **Library:** `bcrypt` (version >=4.0.0)
- **Functions:**
  - `hash_password(password: str) -> str` - Hashes passwords using bcrypt
  - `verify_password(password: str, hashed: str) -> bool` - Verifies passwords
- **Storage:** `tenant_users.password_hash` column (String, NOT NULL)

**JWT Tokens:**
- **Library:** `PyJWT`
- **Secret:** `JWT_SECRET` environment variable
- **Algorithm:** HS256
- **Claims:** `sub` (user_id), `tenant_id`, `role`, `exp`, `iat`
- **Expiration:** Configurable via `JWT_EXPIRES_MINUTES` (default: 60 minutes)

### 1.2 Supabase Auth (NOT FOUND)

**Search Results:** No Supabase Auth usage found
- ❌ No `supabase.auth.signInWithPassword`
- ❌ No `supabase.auth.signUp`
- ❌ No `supabase.auth.getUser`
- ❌ No `supabase.auth.getSession`
- ❌ No `auth.users` table references
- ❌ No `auth.uid()` function calls

**Supabase References Found:**
- Only database connection string conversion (`postgres://` → `postgresql://`)
- Documentation mentions Supabase as database provider (not auth provider)
- No actual Supabase Auth SDK usage

---

## 2. Authentication Flows

### 2.1 Login Flow

**Endpoint:** `POST /auth/login`  
**File:** `ai-testing-agent/backend/app.py:4275-4458`

**Implementation:** Custom
1. Receives email + password
2. Queries `tenant_users` by email (case-insensitive)
3. Verifies password using `bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8'))`
4. Creates custom JWT token via `create_access_token()`
5. Returns JWT token + user data

**Code References:**
- Line 4351: `bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8'))`
- Line 4390: `bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8'))`
- Line 4534: `bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8'))`
- Line 4357-4361: JWT token creation

**Multi-tenant Support:**
- If user exists in multiple tenants, returns 409 with tenant list
- User selects tenant, then calls `POST /auth/login/tenant` with `tenant_id`

### 2.2 Signup/Registration Flow

**Endpoint:** `POST /api/v1/onboarding/tenant/{tenant_id}/admin`  
**File:** `ai-testing-agent/backend/app.py:5299-5449`

**Implementation:** Custom
1. Creates tenant user in `tenant_users` table
2. Hashes password using `bcrypt.gensalt()` and `bcrypt.hashpw()`
3. Stores `password_hash` in database
4. Creates custom JWT token
5. Returns JWT token + user data

**Code References:**
- Line 5401-5404: Password hashing
  ```python
  password_bytes = password.encode('utf-8')
  salt = bcrypt.gensalt()
  password_hash_bytes = bcrypt.hashpw(password_bytes, salt)
  password_hash = password_hash_bytes.decode('utf-8')
  ```
- Line 5410: `password_hash=password_hash` - Stored in database

**Note:** Legacy `/auth/register` endpoint appears to be deprecated (redirects to tenant-first onboarding)

### 2.3 Forgot Password Flow

**Endpoint:** `POST /api/v1/auth/forgot-password`  
**File:** `ai-testing-agent/backend/app.py:4844-4911`

**Implementation:** Custom
1. Finds user by email in `tenant_users`
2. Creates reset token using `create_reset_token()` (HMAC-SHA256 hashed)
3. Stores token in `password_reset_tokens` table
4. Sends reset email (currently logs to server)

**Code References:**
- Line 4897: `create_reset_token(db, str(user.id))`
- `services/auth.py:158-192` - Token creation logic

### 2.4 Reset Password Flow

**Endpoint:** `POST /api/v1/auth/reset-password`  
**File:** `ai-testing-agent/backend/app.py:4914-4973`

**Implementation:** Custom
1. Consumes reset token (one-time use)
2. Updates `user.password_hash` using `hash_password()`
3. Commits to database

**Code References:**
- Line 4964: `user.password_hash = hash_password(new_password)`

### 2.5 Change Password Flow

**Endpoint:** `POST /api/v1/users/me/change-password`  
**File:** `ai-testing-agent/backend/app.py:4783-4841`

**Implementation:** Custom
1. Verifies current password using `verify_password(current_password, user.password_hash)`
2. Updates `user.password_hash` using `hash_password(new_password)`

**Code References:**
- Line 4828: `verify_password(current_password, user.password_hash)`
- Line 4832: `user.password_hash = hash_password(new_password)`

### 2.6 Session Validation

**Middleware:** `@app.before_request check_auth()`  
**File:** `ai-testing-agent/backend/app.py:92-180`

**Implementation:** Custom JWT verification
1. Extracts `Authorization: Bearer <token>` header
2. Verifies JWT using `decode_and_verify_token(token)`
3. Extracts `user_id`, `tenant_id`, `role` from JWT claims
4. Stores on `flask.g` for downstream use
5. Enforces tenant_id requirement (tenant-first model)

**Code References:**
- Line 127: `payload, error = decode_and_verify_token(token)`
- Line 132-134: Claims extraction to `flask.g`

---

## 3. Database Access Patterns

### 3.1 `tenant_users` Table Usage

**Model:** `ai-testing-agent/backend/models.py:114-153`

**Schema:**
```python
class TenantUser(Base):
    __tablename__ = "tenant_users"
    id = Column(UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    email = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)  # ← ACTIVE COLUMN
    role = Column(String, nullable=False)
    is_active = Column(Boolean, nullable=False)
    # ... other fields
```

### 3.2 `password_hash` Column Access

**Read Operations (Password Verification):**
- `app.py:4351` - Login with tenant_slug
- `app.py:4390` - Login multi-tenant lookup
- `app.py:4534` - Login with tenant_id
- `app.py:4828` - Change password (verify current)

**Write Operations (Password Storage):**
- `app.py:4832` - Change password (update)
- `app.py:4964` - Reset password (update)
- `app.py:5410` - Admin creation (insert)

**Query Patterns:**
- `tenant_users` is queried by `email` (case-insensitive) for login
- `password_hash` is always selected when verifying credentials
- `password_hash` is updated when changing/resetting passwords
- `password_hash` is inserted when creating new users

**Conclusion:** `password_hash` is **actively used** and is the **single source of truth** for authentication.

### 3.3 `password_reset_tokens` Table

**Model:** `ai-testing-agent/backend/models.py:260-283`

**Purpose:** Stores password reset tokens (HMAC-SHA256 hashed)
- One-time use tokens
- 30-minute expiration
- Linked to `user_id`

**Usage:** Custom password reset flow (not Supabase)

---

## 4. Summary Table

| Flow | Implementation | Files Involved | Risk Level |
|------|---------------|----------------|------------|
| **Login** | Custom (bcrypt + JWT) | `app.py:4275-4458`, `auth/jwt.py`, `services/auth.py` | Low |
| **Signup** | Custom (bcrypt + JWT) | `app.py:5299-5449`, `services/auth.py` | Low |
| **Forgot Password** | Custom (HMAC tokens) | `app.py:4844-4911`, `services/auth.py:158-192` | Low |
| **Reset Password** | Custom (bcrypt) | `app.py:4914-4973`, `services/auth.py` | Low |
| **Change Password** | Custom (bcrypt) | `app.py:4783-4841`, `services/auth.py` | Low |
| **Session Validation** | Custom JWT | `app.py:92-180`, `auth/jwt.py` | Low |

---

## 5. Key Findings

### ✅ Confirmed: Custom Authentication Only

1. **No Supabase Auth Integration**
   - Zero references to Supabase Auth SDK
   - No `auth.users` table usage
   - No Supabase JWT validation

2. **Active Custom Auth System**
   - bcrypt password hashing (active)
   - Custom JWT tokens (active)
   - `password_hash` column (actively used)
   - Password reset tokens (custom implementation)

3. **Database Schema**
   - `tenant_users.password_hash` - **REQUIRED** (NOT NULL)
   - `password_reset_tokens` table - Custom implementation
   - No `auth.users` table or Supabase auth schema

4. **Security Implementation**
   - Password hashing: bcrypt (industry standard)
   - JWT signing: HS256 with `JWT_SECRET`
   - Password reset: HMAC-SHA256 hashed tokens
   - Rate limiting: In-memory (password reset)

---

## 6. Recommendations

### 6.1 Current State Assessment

**Status:** ✅ **No duplication - Single authentication system**

The application uses **only custom authentication**. There is no Supabase Auth integration, so there is no duplication to remove.

### 6.2 `password_hash` Column Status

**Status:** ✅ **ACTIVE - DO NOT DEPRECATE**

The `password_hash` column is:
- Required (NOT NULL constraint)
- Actively read for password verification
- Actively written for password updates
- Single source of truth for authentication

**Action:** Keep `password_hash` column - it is essential to the authentication system.

### 6.3 If Migrating to Supabase Auth (Future)

If you plan to migrate to Supabase Auth in the future:

1. **Phase 1:** Add Supabase Auth alongside custom auth
2. **Phase 2:** Migrate users to Supabase Auth
3. **Phase 3:** Remove custom auth code
4. **Phase 4:** Drop `password_hash` column (after all users migrated)

**Current Recommendation:** No action needed - system is working correctly with custom auth.

---

## 7. File Inventory

### Core Authentication Files

1. **`ai-testing-agent/backend/services/auth.py`**
   - Password hashing (`hash_password`, `verify_password`)
   - Password reset token management
   - Password strength validation

2. **`ai-testing-agent/backend/auth/jwt.py`**
   - JWT token creation (`create_access_token`)
   - JWT token verification (`decode_and_verify_token`)

3. **`ai-testing-agent/backend/app.py`**
   - Login endpoint (`/auth/login`)
   - Tenant login endpoint (`/auth/login/tenant`)
   - Forgot password (`/api/v1/auth/forgot-password`)
   - Reset password (`/api/v1/auth/reset-password`)
   - Change password (`/api/v1/users/me/change-password`)
   - Admin creation (`/api/v1/onboarding/tenant/{tenant_id}/admin`)
   - Auth middleware (`check_auth()`)

4. **`ai-testing-agent/backend/models.py`**
   - `TenantUser` model (includes `password_hash`)
   - `PasswordResetToken` model

### Frontend Authentication Files

1. **`ai-testing-agent-UI/src/components/LoginPage.tsx`**
   - Calls `/auth/login` endpoint
   - Handles multi-tenant selection

2. **`ai-testing-agent-UI/src/components/ForgotPasswordPage.tsx`**
   - Calls `/api/v1/auth/forgot-password`

3. **`ai-testing-agent-UI/src/components/ResetPasswordPage.tsx`**
   - Calls `/api/v1/auth/reset-password`

4. **`ai-testing-agent-UI/src/services/api.ts`**
   - API client functions for auth endpoints

---

## 8. Final Verdict

### ✅ **NO AUTHENTICATION DUPLICATION**

**Conclusion:** The application uses **100% custom authentication** with no Supabase Auth integration. There is no duplication to remove.

**Key Points:**
1. ✅ Custom bcrypt password hashing (active)
2. ✅ Custom JWT tokens (active)
3. ✅ `password_hash` column is essential (DO NOT DEPRECATE)
4. ❌ No Supabase Auth usage found
5. ❌ No `auth.users` table references
6. ❌ No Supabase JWT validation

**Recommendation:** Continue using the current custom authentication system. The `password_hash` column is actively used and should not be deprecated.

---

## 9. Appendix: Search Results Summary

### Custom Auth Keywords Found
- ✅ `password_hash` - 32 occurrences (all active usage)
- ✅ `bcrypt` - 103 occurrences (all active usage)
- ✅ `verify_password` - 8 occurrences (all active usage)
- ✅ `hash_password` - 6 occurrences (all active usage)
- ✅ `password_reset_tokens` - 5 occurrences (custom table)
- ✅ `reset_token` - 3 occurrences (custom implementation)

### Supabase Auth Keywords Found
- ❌ `supabase.auth` - 0 occurrences
- ❌ `supabaseAuth` - 0 occurrences
- ❌ `auth.users` - 0 occurrences
- ❌ `auth.uid()` - 0 occurrences
- ❌ `signInWithPassword` - 0 occurrences
- ❌ `signUp` - 0 occurrences (Supabase context)

### Supabase References (Non-Auth)
- Database connection string conversion only
- Documentation mentions (not code usage)

---

**Report Generated:** 2025-01-XX  
**Auditor:** CursorAI  
**Status:** ✅ Complete - No action required
