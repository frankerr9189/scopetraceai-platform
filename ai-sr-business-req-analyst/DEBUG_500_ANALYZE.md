# Debugging 500 Error on /api/v1/analyze

## Status
✅ BA Agent health check works: `{"status":"healthy"}`
❌ `/api/v1/analyze` endpoint returns 500 error

## Next Steps

### Step 1: Check BA Agent Logs (CRITICAL)

1. Go to Render dashboard
2. Open your **BA Requirements Agent** service
3. Click **"Logs"** tab
4. Try to analyze requirements from the UI
5. **Watch the logs in real-time** - you'll see the actual error

Look for errors like:
- `OpenAI API key not configured`
- `INTERNAL_SERVICE_KEY not configured`
- `Database connection failed`
- `ImportError` or `ModuleNotFoundError`
- Any Python traceback/exception

### Step 2: Verify Environment Variables

In Render dashboard → BA Agent service → Environment tab, verify:

```bash
# CRITICAL - Required for LLM calls
OPENAI_API_KEY=sk-...

# CRITICAL - Must match testing agent backend
INTERNAL_SERVICE_KEY=<same-value-as-testing-agent-backend>

# REQUIRED - For database access
DATABASE_URL=postgresql://user:password@host:port/database

# REQUIRED - For JWT operations
JWT_SECRET=<same-value-as-testing-agent-backend>
```

### Step 3: Verify Testing Agent Backend Configuration

In Render dashboard → Testing Agent Backend → Environment tab, verify:

```bash
# CRITICAL - Must point to BA agent
BA_AGENT_BASE_URL=https://ai-sr-business-req-analyst.onrender.com

# CRITICAL - Must match BA agent
INTERNAL_SERVICE_KEY=<same-value-as-ba-agent>
```

### Step 4: Test Analyze Endpoint Directly (with auth)

You can test the analyze endpoint directly to see the error:

```bash
# First, get a JWT token by logging in through the UI
# Then use it to test the endpoint:

curl -X POST https://scopetraceai-platform.onrender.com/api/v1/analyze \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Test requirement", "source": ""}'
```

This will show you the actual error message from the Flask gateway.

## Most Likely Causes

### 1. Missing OPENAI_API_KEY (90% of cases)
**Symptom:** Logs show "OpenAI API key not configured" or "LLMClientError"  
**Fix:** Set `OPENAI_API_KEY` in BA agent environment variables

### 2. INTERNAL_SERVICE_KEY Mismatch
**Symptom:** Logs show "Invalid internal service key" (would be 401, not 500)  
**Fix:** Ensure `INTERNAL_SERVICE_KEY` matches between both services

### 3. BA_AGENT_BASE_URL Not Set
**Symptom:** Testing agent backend can't find BA agent  
**Fix:** Set `BA_AGENT_BASE_URL` in testing agent backend

### 4. Database Connection Failure
**Symptom:** Logs show database connection errors  
**Fix:** Verify `DATABASE_URL` is correct and database is accessible

## What to Share for Help

If you need help debugging, share:

1. **The actual error from Render logs** (not just "500 Internal Server Error")
2. **Screenshot of BA agent environment variables** (hide sensitive values)
3. **Screenshot of testing agent backend environment variables** (hide sensitive values)
4. **The timestamp** when the error occurred

The Render logs will show the **exact exception** that's causing the 500 error.
