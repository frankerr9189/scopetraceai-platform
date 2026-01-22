# Troubleshooting BA Agent 500 Error

## Error Message
```
{
    "detail": "500 Server Error: Internal Server Error for url: https://ai-sr-business-req-analyst.onrender.com/api/v1/analyze",
    "error": "INTERNAL_ERROR"
}
```

## Root Cause
The BA Requirements Agent service is returning a 500 Internal Server Error. This is happening **inside the BA agent**, not in the Flask gateway.

## Step 1: Check Render Logs (CRITICAL)

**Go to your Render dashboard:**
1. Navigate to your BA Requirements Agent service
2. Click on "Logs" tab
3. Look for the actual error message

The logs will show the **real error** - likely one of:
- `OpenAI API key not configured`
- `INTERNAL_SERVICE_KEY not configured`
- Database connection errors
- Import errors
- Other exceptions

## Step 2: Verify Environment Variables

In Render dashboard → Environment tab, ensure these are set:

### Required Variables

```bash
# CRITICAL - Without this, LLM calls will fail
OPENAI_API_KEY=sk-...

# CRITICAL - Must match testing agent backend
INTERNAL_SERVICE_KEY=<same-value-as-testing-agent-backend>

# REQUIRED - For database access
DATABASE_URL=postgresql://user:password@host:port/database

# REQUIRED - For JWT operations
JWT_SECRET=<same-value-as-testing-agent-backend>
```

### How to Check if Variables are Set

1. In Render dashboard, go to your BA agent service
2. Click "Environment" tab
3. Verify all 4 variables above are present
4. **Important:** `INTERNAL_SERVICE_KEY` must match exactly between:
   - BA agent service
   - Testing agent backend service

## Step 3: Common Issues and Fixes

### Issue 1: Missing OPENAI_API_KEY
**Symptom:** Logs show "OpenAI API key not configured" or "LLMClientError"  
**Fix:** Set `OPENAI_API_KEY` in Render environment variables

### Issue 2: Invalid OPENAI_API_KEY
**Symptom:** Logs show OpenAI API errors (401, 429, etc.)  
**Fix:** Verify API key is valid and has credits

### Issue 3: INTERNAL_SERVICE_KEY Mismatch
**Symptom:** Logs show "Invalid internal service key" (would be 401, not 500)  
**Fix:** Ensure `INTERNAL_SERVICE_KEY` matches between services

### Issue 4: Database Connection Failure
**Symptom:** Logs show database connection errors  
**Fix:** 
- Verify `DATABASE_URL` is correct
- Check database is accessible from Render
- Verify network/firewall allows connection

### Issue 5: Import Errors
**Symptom:** Logs show `ImportError` or `ModuleNotFoundError`  
**Fix:** 
- Check `requirements.txt` is up to date
- Verify all dependencies are installed
- Check Render build logs for installation errors

## Step 4: Test the BA Agent Directly

You can test the BA agent health endpoint:

```bash
curl https://ai-sr-business-req-analyst.onrender.com/health
```

Should return: `{"status": "healthy"}`

If this fails, the service isn't running properly.

## Step 5: Check Service Status

In Render dashboard:
1. Check if service is "Live" (not "Suspended" or "Stopped")
2. Check recent deployments - did a recent deploy fail?
3. Check resource usage (CPU, memory) - is service running out of resources?

## Step 6: Restart the Service

If environment variables are set correctly but still getting 500:
1. In Render dashboard, click "Manual Deploy" → "Deploy latest commit"
2. Or click "Restart" if available

## Diagnostic Script

If you have shell access to the BA agent server, run:

```bash
cd ai-sr-business-req-analyst
python3 scripts/diagnose_500_error.py
```

This will check:
- Environment variables
- Module imports
- Database connection
- OpenAI API key validity

## Most Common Fix

**90% of the time**, the issue is:
- Missing `OPENAI_API_KEY` in Render environment variables
- Or invalid `OPENAI_API_KEY`

**Quick fix:**
1. Go to Render dashboard → BA agent service → Environment
2. Add/update `OPENAI_API_KEY=sk-...`
3. Restart the service

## Getting Help

If you've checked all of the above and still getting 500:

1. **Copy the full error from Render logs** (not just the frontend error)
2. **Check the timestamp** - when did the error occur?
3. **Check recent deployments** - did something change?
4. **Share the actual error message** from Render logs (not the generic 500 message)

The Render logs will show the **actual exception** that's causing the 500 error.
