# BA Requirements Agent - Production Environment Variables

## Required Environment Variables

The BA Requirements Agent service needs these environment variables set in production:

### 1. INTERNAL_SERVICE_KEY (CRITICAL)
```bash
INTERNAL_SERVICE_KEY=your-secret-key-here
```
**Purpose:** Authenticates requests from the testing agent backend  
**Location:** Set in `ai-sr-business-req-analyst/.env` or production environment  
**Must match:** The `INTERNAL_SERVICE_KEY` in `ai-testing-agent/backend/.env`

**If missing:** Service will return 401 Unauthorized (not 500, but check logs)

### 2. OPENAI_API_KEY (CRITICAL)
```bash
OPENAI_API_KEY=sk-...
```
**Purpose:** Required for LLM calls to analyze requirements  
**Location:** Set in `ai-sr-business-req-analyst/.env` or production environment

**If missing:** Service will return 500 Internal Server Error when trying to call OpenAI

### 3. DATABASE_URL (REQUIRED)
```bash
DATABASE_URL=postgresql://user:password@host:port/database
```
**Purpose:** 
- Save run records to database
- Record usage events
- Access Jira integration credentials (if source=jira)

**Location:** Should be loaded from `ai-testing-agent/backend/.env` (see main.py logic)

**If missing:** Service will work but won't save run records or track usage

### 4. JWT_SECRET (REQUIRED)
```bash
JWT_SECRET=your-secret-key-here
```
**Purpose:** JWT operations (if needed)  
**Location:** Should be loaded from `ai-testing-agent/backend/.env` (see main.py logic)

## Production Setup

### On Render (or similar platform)

1. **Set Environment Variables in Render Dashboard:**
   - Go to your BA Requirements Agent service
   - Navigate to Environment tab
   - Add these variables:

```bash
INTERNAL_SERVICE_KEY=<same-value-as-testing-agent-backend>
OPENAI_API_KEY=sk-...
DATABASE_URL=postgresql://...  # Same as testing agent backend
JWT_SECRET=<same-value-as-testing-agent-backend>
```

2. **Verify INTERNAL_SERVICE_KEY matches:**
   - The value in `ai-sr-business-req-analyst` must match
   - The value in `ai-testing-agent/backend`
   - They must be identical for authentication to work

## Common 500 Error Causes

### 1. Missing OPENAI_API_KEY
**Symptom:** 500 error when calling `/api/v1/analyze`  
**Fix:** Set `OPENAI_API_KEY` environment variable

### 2. Invalid OPENAI_API_KEY
**Symptom:** 500 error, check logs for OpenAI API errors  
**Fix:** Verify API key is valid and has credits

### 3. Database Connection Failure
**Symptom:** 500 error, check logs for database connection errors  
**Fix:** Verify `DATABASE_URL` is correct and database is accessible

### 4. Import Errors
**Symptom:** 500 error, check logs for ImportError or ModuleNotFoundError  
**Fix:** Ensure all dependencies are installed (`pip install -r requirements.txt`)

### 5. INTERNAL_SERVICE_KEY Mismatch
**Symptom:** 401 Unauthorized (not 500)  
**Fix:** Ensure `INTERNAL_SERVICE_KEY` matches between services

## Diagnostic Script

Run the diagnostic script to identify issues:

```bash
cd ai-sr-business-req-analyst
python3 scripts/diagnose_500_error.py
```

This will check:
- Environment variables
- Module imports
- Database connection
- OpenAI API key validity
- Internal service key

## Quick Fix Checklist

If getting 500 errors:

- [ ] Check Render logs for the actual error message
- [ ] Verify `OPENAI_API_KEY` is set and valid
- [ ] Verify `INTERNAL_SERVICE_KEY` is set and matches testing agent backend
- [ ] Verify `DATABASE_URL` is set and accessible
- [ ] Run diagnostic script: `python3 scripts/diagnose_500_error.py`
- [ ] Check that all Python dependencies are installed
- [ ] Verify the service can reach the database (network/firewall)

## Testing the Service

Test the health endpoint:
```bash
curl https://ai-sr-business-req-analyst.onrender.com/health
```

Should return: `{"status": "healthy"}`

Test the analyze endpoint (requires auth):
```bash
curl -X POST https://ai-sr-business-req-analyst.onrender.com/api/v1/analyze \
  -H "X-Internal-Service-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Test requirement", "source": ""}'
```
