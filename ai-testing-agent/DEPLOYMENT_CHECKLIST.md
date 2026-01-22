# Deployment Checklist - Tenant User Management Fixes

**Date:** 2026-01-22  
**Changes:** Tenant user invite system fixes and UI improvements

## Summary of Changes

### Backend Changes (`ai-testing-agent/backend/app.py`)

1. **Fixed invite endpoint** (`POST /api/v1/tenant/users/invite`):
   - Fixed existing user check to be tenant-scoped (was checking across all tenants)
   - Ensures new users are properly inserted into `tenant_users` table
   - Added debug logging (`INVITE_CREATED`, `INVITE_REINVITED`)

2. **Fixed date formatting** in user list endpoints:
   - Added `format_datetime_utc()` helper function
   - Fixed timezone-aware datetime formatting (removed invalid `+00:00Z` format)
   - Applied to: `/api/v1/tenant/users`, `/api/v1/admin/tenants/<id>/users`, `/api/v1/admin/users`

3. **Added `has_pending_invite` field** to user list endpoints:
   - Checks for unused, non-expired invite tokens
   - Helps distinguish "Pending Activation" from "Inactive" users
   - Applied to all three user list endpoints

4. **Updated user profile endpoint** (`GET /api/v1/users/me`):
   - Added `tenant_name` field to response
   - Fetches tenant name from Tenant table

5. **Updated user profile update endpoint** (`PATCH /api/v1/users/me`):
   - Also returns `tenant_name` in response

### Database Changes

1. **Created `user_invite_tokens` table**:
   - Table already exists in production (created via script)
   - Fixed `id` column type from `bigint` to `UUID` (migration script run)
   - Table structure matches model definition

### Frontend Changes (`ai-testing-agent-UI`)

1. **ProfilePage.tsx**:
   - Fixed date parsing with `formatDate()` helper function
   - Updated Status column to show:
     - "Active" (green badge) when `is_active = true`
     - "Pending Activation" (yellow badge) when `is_active = false` AND `has_pending_invite = true`
     - "Inactive" (gray badge) when `is_active = false` AND `has_pending_invite = false`
   - Changed "Tenant ID" label to "Client Name"
   - Changed display from `tenant_id` (UUID) to `tenant_name` (readable name)

2. **api.ts**:
   - Added `has_pending_invite?: boolean` to `TenantUser` interface
   - Added `tenant_name: string | null` to `UserProfile` interface

## Pre-Deployment Checklist

### Database
- [ ] Verify `user_invite_tokens` table exists in production
- [ ] Verify `user_invite_tokens.id` is UUID type (not bigint)
- [ ] Verify all indexes exist on `user_invite_tokens` table
- [ ] Verify foreign keys are set correctly

### Backend
- [ ] Review all code changes in `app.py`
- [ ] Test invite flow locally:
  - [ ] New user invite creates record in `tenant_users`
  - [ ] Re-invite inactive user works
  - [ ] Cross-tenant email check works
- [ ] Test user list endpoints return correct date formats
- [ ] Test user list endpoints return `has_pending_invite` field
- [ ] Test profile endpoint returns `tenant_name`
- [ ] Check server logs for debug messages (`INVITE_CREATED`, `INVITE_REINVITED`)

### Frontend
- [ ] Test profile page displays:
  - [ ] "Client Name" label (not "Tenant ID")
  - [ ] Tenant name (not UUID)
  - [ ] "Pending Activation" status for invited users
  - [ ] Valid dates (not "Invalid Date")
- [ ] Test user table shows correct status badges
- [ ] Verify no console errors

## Deployment Steps

### 1. Database Verification (No Migration Needed)
```bash
# Verify table exists and has correct schema
psql $DATABASE_URL -c "\d user_invite_tokens"
psql $DATABASE_URL -c "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'user_invite_tokens' AND column_name = 'id';"
```

### 2. Backend Deployment
```bash
cd ai-testing-agent/backend

# 1. Pull latest code
git pull origin main  # or your branch

# 2. Install dependencies (if needed)
source venv/bin/activate
pip install -r requirements.txt

# 3. Restart backend service
# (Method depends on your deployment - systemd, PM2, Docker, etc.)
# Example for systemd:
sudo systemctl restart ai-testing-agent
# Or for PM2:
pm2 restart ai-testing-agent
# Or for Docker:
docker-compose restart backend
```

### 3. Frontend Deployment
```bash
cd ai-testing-agent-UI

# 1. Pull latest code
git pull origin main  # or your branch

# 2. Install dependencies (if needed)
npm install

# 3. Build
npm run build

# 4. Deploy build artifacts
# (Method depends on your deployment - Vercel, S3, etc.)
# For Vercel:
vercel --prod
# Or copy dist/ to your web server
```

## Post-Deployment Verification

### Backend API Tests
```bash
# Test invite endpoint
curl -X POST https://your-api.com/api/v1/tenant/users/invite \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "role": "user"}'

# Test user list endpoint
curl https://your-api.com/api/v1/tenant/users \
  -H "Authorization: Bearer $TOKEN"

# Verify response includes:
# - has_pending_invite field
# - Properly formatted dates (no +00:00Z)
# - tenant_name in profile endpoint
```

### Frontend Verification
- [ ] Visit profile page: `https://your-app.com/profile`
- [ ] Verify "Client Name" shows tenant name (not UUID)
- [ ] Verify user table shows "Pending Activation" for invited users
- [ ] Verify dates display correctly (not "Invalid Date")
- [ ] Check browser console for errors

## Rollback Plan

If issues occur:

### Backend Rollback
```bash
cd ai-testing-agent/backend
git checkout <previous-commit>
# Restart service
```

### Frontend Rollback
```bash
cd ai-testing-agent-UI
git checkout <previous-commit>
npm run build
# Redeploy
```

## Known Issues / Notes

1. **Migration Chain Issue**: There's a broken migration in the chain (`h3i4j5k6l7m8_map_subscription_status_to_new_tiers`) that references `subscription_status` column that doesn't exist. This doesn't affect these changes, but should be fixed separately.

2. **Debug Logging**: Added `INVITE_CREATED` and `INVITE_REINVITED` logs. These are INFO level and will appear in production logs.

3. **Date Formatting**: All datetime fields now use consistent UTC formatting with `Z` suffix (no timezone offset).

## Files Changed

### Backend
- `ai-testing-agent/backend/app.py` (multiple endpoints updated)

### Frontend
- `ai-testing-agent-UI/src/components/ProfilePage.tsx`
- `ai-testing-agent-UI/src/services/api.ts`

### Scripts (for reference, already run)
- `ai-testing-agent/backend/scripts/create_user_invite_tokens_table.py`
- `ai-testing-agent/backend/scripts/fix_user_invite_tokens_id_type.py`

## Support

If issues arise:
1. Check server logs for error messages
2. Verify database schema matches expectations
3. Test API endpoints directly with curl/Postman
4. Check browser console for frontend errors
