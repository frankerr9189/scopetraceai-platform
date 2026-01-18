# Leads API Documentation

## Overview

This document describes the backend API endpoints required for lead capture and management. The marketing site submits leads to the Flask backend, which persists them to Supabase and maintains Slack notifications (unchanged).

## Database Schema

See `supabase/leads.sql` for the complete table schema. Key points:
- Table: `public.leads`
- Primary key: UUID
- Email deduplication: Case-insensitive via `email_lower` generated column
- Status values: `new`, `contacted`, `qualified`, `closed`, `junk`
- RLS enabled (writes via service role only)

## Endpoints

### POST /api/v1/leads

**Public endpoint** (no authentication required) for lead submission from marketing site.

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "company": "Acme Corp",
  "role": "Engineering / Development",
  "message": "Phone: 555-1234 | Use Case: Test plan generation",
  "source": "marketing_more_info",
  "source_page": "/",
  "utm_source": "google",
  "utm_medium": "cpc",
  "utm_campaign": "summer2024",
  "utm_term": "ai testing",
  "utm_content": "ad1"
}
```

**Validation:**
- `email` (required): Must be valid email format, max 254 chars
- `name` (optional): Max 200 chars
- `company` (optional): Max 200 chars
- `role` (optional): Max 200 chars
- `message` (optional): Max 2000 chars
- `source` (optional): Max 500 chars
- `source_page` (optional): Max 500 chars
- All UTM fields (optional): Max 200 chars each
- All strings are trimmed

**Upsert Behavior:**
- If email exists (case-insensitive), update existing record
- Update: name, company, role, message, source, source_page, utm_* fields
- Preserve existing `status` (do not reset to 'new' on resubmit)
- Update `updated_at` timestamp
- Return existing lead `id` and current `status`

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "new"
}
```

**Response (400 Bad Request):**
```json
{
  "error": "Invalid email format"
}
```

**CORS:**
- Must allow: `https://scopetraceai.com`, `https://www.scopetraceai.com`
- Must allow: `https://app.scopetraceai.com` (existing)
- Do NOT use `*` with credentials

---

### GET /api/v1/admin/leads

**Admin endpoint** (authentication + admin role required) for listing leads.

**Query Parameters:**
- `status` (optional): Filter by status (`new`, `contacted`, `qualified`, `closed`, `junk`)
- `limit` (optional): Number of results (default: 50, max: 200)

**Response (200 OK):**
```json
{
  "leads": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z",
      "name": "John Doe",
      "email": "john@example.com",
      "company": "Acme Corp",
      "role": "Engineering / Development",
      "status": "new",
      "source": "marketing_more_info",
      "source_page": "/"
    }
  ],
  "total": 1
}
```

**Response (401 Unauthorized):**
```json
{
  "error": "Authentication required"
}
```

**Response (403 Forbidden):**
```json
{
  "error": "Admin role required"
}
```

---

### PATCH /api/v1/admin/leads/<lead_id>

**Admin endpoint** (authentication + admin role required) for updating lead status and notes.

**Request Body:**
```json
{
  "status": "contacted",
  "notes": "Followed up via email on 2024-01-15",
  "last_contacted_at": "2024-01-15T14:00:00Z"
}
```

**Validation:**
- `status` (optional): Must be one of: `new`, `contacted`, `qualified`, `closed`, `junk`
- `notes` (optional): Text field
- `last_contacted_at` (optional): ISO 8601 timestamp

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "contacted",
  "notes": "Followed up via email on 2024-01-15",
  "last_contacted_at": "2024-01-15T14:00:00Z",
  "updated_at": "2024-01-15T14:00:00Z"
}
```

**Response (404 Not Found):**
```json
{
  "error": "Lead not found"
}
```

---

## Testing with curl

### Submit a lead (public endpoint):
```bash
curl -X POST https://api.scopetraceai.com/api/v1/leads \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "company": "Acme Corp",
    "role": "Engineering / Development",
    "source": "marketing_more_info",
    "source_page": "/"
  }'
```

### List leads (admin endpoint):
```bash
curl -X GET "https://api.scopetraceai.com/api/v1/admin/leads?status=new&limit=10" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Update lead status (admin endpoint):
```bash
curl -X PATCH https://api.scopetraceai.com/api/v1/admin/leads/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{
    "status": "contacted",
    "notes": "Followed up"
  }'
```

---

## Important Notes

1. **Slack Notifications**: The existing Slack notification system remains unchanged. The marketing site continues to call the Next.js `/api/lead` route for Slack notifications. The Flask backend should NOT send Slack notifications - that's handled by the marketing site's Next.js API route.

2. **Email Deduplication**: Leads are deduplicated by email (case-insensitive). Resubmissions update existing records but preserve the status field.

3. **Environment Variables**: The marketing site uses `NEXT_PUBLIC_API_BASE` to point to the Flask backend. Default: `https://api.scopetraceai.com`

4. **CORS**: Ensure the Flask backend allows requests from:
   - `https://scopetraceai.com`
   - `https://www.scopetraceai.com`
   - `https://app.scopetraceai.com` (existing)
