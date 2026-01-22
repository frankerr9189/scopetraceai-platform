# Changelog - Tenant User Management Fixes

## 2026-01-22

### Fixed
- **Invite endpoint now properly creates users in `tenant_users` table**
  - Fixed existing user check to be tenant-scoped (was incorrectly checking across all tenants)
  - Ensures `db.commit()` is called after user creation
  - Added tenant-scoped email uniqueness validation

- **Date formatting in API responses**
  - Fixed invalid datetime format (`+00:00Z` → proper UTC with `Z` suffix)
  - Applied consistent date formatting across all user list endpoints
  - Frontend now correctly parses and displays dates

- **User status display**
  - Added `has_pending_invite` field to distinguish pending invites from deactivated users
  - Frontend now shows "Pending Activation" for users with unused invite tokens
  - Frontend shows "Inactive" for deactivated users (no pending invites)

- **Profile page improvements**
  - Changed "Tenant ID" label to "Client Name"
  - Displays tenant name instead of UUID
  - Added `tenant_name` field to user profile API response

### Added
- Debug logging for invite operations (`INVITE_CREATED`, `INVITE_REINVITED`)
- `has_pending_invite` field to user list API responses
- `tenant_name` field to user profile API response
- Helper function `format_datetime_utc()` for consistent date formatting

### Database
- Verified `user_invite_tokens` table exists and has correct schema
- Fixed `user_invite_tokens.id` column type (bigint → UUID)

### Technical Details

**Backend Endpoints Updated:**
- `GET /api/v1/tenant/users` - Added `has_pending_invite`, fixed date formatting
- `GET /api/v1/admin/tenants/<id>/users` - Added `has_pending_invite`, fixed date formatting
- `GET /api/v1/admin/users` - Added `has_pending_invite`, fixed date formatting
- `POST /api/v1/tenant/users/invite` - Fixed tenant-scoped user checks
- `GET /api/v1/users/me` - Added `tenant_name` field
- `PATCH /api/v1/users/me` - Added `tenant_name` to response

**Frontend Components Updated:**
- `ProfilePage.tsx` - Status badges, date formatting, tenant name display
- `api.ts` - Updated TypeScript interfaces
