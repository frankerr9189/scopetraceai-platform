# Environment Variables for Tenant User Management Fixes

## Required Environment Variables

### Backend (`ai-testing-agent/backend`)

#### Database (Already Required)
```bash
DATABASE_URL=postgresql://user:password@host:port/database
# or
DATABASE_URL=postgresql+psycopg://user:password@host:port/database
```
**Status:** ✅ Already required - no change needed

#### Authentication (Already Required)
```bash
JWT_SECRET=your-secret-key-here
JWT_EXPIRES_MINUTES=60  # Optional, defaults to 60
```
**Status:** ✅ Already required - no change needed

#### Invite URL Configuration (NEW/IMPORTANT)
```bash
# Frontend base URL for invite links
APP_BASE_URL=https://app.scopetraceai.com
# OR
APP_PUBLIC_BASE_URL=https://app.scopetraceai.com
```
**Status:** ⚠️ **NEW** - Required for invite links to work correctly

**Details:**
- Used by `get_invite_url()` function in `services/auth.py`
- Invite links will be: `{APP_BASE_URL}/invite?token={token}`
- If not set, defaults to `http://localhost:5173` (development)
- **Must be set in production** to generate correct invite URLs

#### Email Service (Optional - Currently Logs Only)
```bash
# Email provider (not yet implemented, but prepared for future)
EMAIL_PROVIDER=sendgrid  # or "ses" or leave unset for logging only
SENDGRID_API_KEY=your-sendgrid-api-key  # If using SendGrid
AWS_ACCESS_KEY_ID=your-aws-key  # If using SES
AWS_SECRET_ACCESS_KEY=your-aws-secret  # If using SES
AWS_REGION=us-east-1  # If using SES
```
**Status:** ℹ️ **Optional** - Currently emails are logged to server logs only

**Current Behavior:**
- Invite emails are currently logged to server logs (WARNING level)
- Check server logs for `[USER_INVITE]` messages to get invite links
- Email integration is prepared but not yet implemented

### Frontend (`ai-testing-agent-UI`)

#### API Configuration (Already Required)
```bash
VITE_TEST_PLAN_API_BASE_URL=https://api.scopetraceai.com
# or for local development
VITE_TEST_PLAN_API_BASE_URL=http://localhost:5000
```
**Status:** ✅ Already required - no change needed

## Environment Variable Summary

### Must Set in Production

1. **`APP_BASE_URL`** or **`APP_PUBLIC_BASE_URL`** (Backend)
   - **Purpose:** Generate correct invite links
   - **Example:** `https://app.scopetraceai.com`
   - **Impact:** Without this, invite links will point to localhost

### Already Required (No Changes)

- `DATABASE_URL` - Database connection
- `JWT_SECRET` - JWT token signing
- `VITE_TEST_PLAN_API_BASE_URL` - Frontend API endpoint

### Optional (Future Enhancement)

- Email service configuration (SendGrid, SES, etc.)
- Currently invite links are logged to server logs

## Production Setup Checklist

### Backend Environment Variables
```bash
# Required
DATABASE_URL=postgresql://...
JWT_SECRET=your-secret-key
APP_BASE_URL=https://app.scopetraceai.com  # ⚠️ NEW - Must set!

# Optional (for future email integration)
# EMAIL_PROVIDER=sendgrid
# SENDGRID_API_KEY=...
```

### Frontend Environment Variables
```bash
# Required
VITE_TEST_PLAN_API_BASE_URL=https://api.scopetraceai.com
```

## Testing Invite Links

Since emails are currently logged (not sent), you can:

1. **Check server logs** for invite links:
   ```
   [USER_INVITE] Invite link for user@example.com: https://app.scopetraceai.com/invite?token=...
   ```

2. **Verify `APP_BASE_URL` is set correctly:**
   ```bash
   # In backend
   echo $APP_BASE_URL
   # Should output: https://app.scopetraceai.com
   ```

3. **Test invite flow:**
   - Create invite via UI
   - Check server logs for invite URL
   - Copy URL and test in browser

## Migration Notes

### No Database Migration Needed
- `user_invite_tokens` table already exists
- Schema is correct (verified)

### No Code Changes Needed
- All code changes are backward compatible
- Existing functionality continues to work

### Only New Environment Variable
- **`APP_BASE_URL`** - Must be set in production
- All other env vars are already required

## Troubleshooting

### Invite links point to localhost
**Problem:** `APP_BASE_URL` not set or incorrect  
**Solution:** Set `APP_BASE_URL=https://app.scopetraceai.com` in backend environment

### Can't find invite links
**Problem:** Need to check server logs  
**Solution:** Look for `[USER_INVITE]` log messages in backend logs

### Emails not being sent
**Problem:** Email service not yet implemented  
**Solution:** This is expected - emails are logged to server logs. Check logs for invite URLs.
