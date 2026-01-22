# BA Agent Configuration Checklist

## Issue
The BA Requirements Agent is returning 500 errors when called from the Flask gateway.

## Required Configuration

### 1. Testing Agent Backend (Flask Gateway)

**Location:** Render dashboard → Testing Agent Backend service → Environment tab

**Required Environment Variable:**
```bash
BA_AGENT_BASE_URL=https://ai-sr-business-req-analyst.onrender.com
```

**Why:** The Flask gateway needs to know where to call the BA agent service.

**How to verify:**
- Check Render dashboard → Testing Agent Backend → Environment
- Look for `BA_AGENT_BASE_URL`
- Should be set to your BA agent's Render URL

### 2. BA Requirements Agent Service

**Location:** Render dashboard → BA Requirements Agent service → Environment tab

**Required Environment Variables:**
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

**Important Notes:**
- `INTERNAL_SERVICE_KEY` must be **identical** in both services
- `DATABASE_URL` should be the same database (shared)
- `JWT_SECRET` should be the same (shared)

## Quick Fix Steps

### Step 1: Verify BA_AGENT_BASE_URL in Testing Agent Backend

1. Go to Render dashboard
2. Open your **Testing Agent Backend** service
3. Click "Environment" tab
4. Check if `BA_AGENT_BASE_URL` is set
5. If missing or wrong, add/update:
   ```
   BA_AGENT_BASE_URL=https://ai-sr-business-req-analyst.onrender.com
   ```
6. **Restart the service** after adding

### Step 2: Verify BA Agent Environment Variables

1. Go to Render dashboard
2. Open your **BA Requirements Agent** service
3. Click "Environment" tab
4. Verify all 4 variables are set:
   - `OPENAI_API_KEY` ← **Most common issue**
   - `INTERNAL_SERVICE_KEY` ← Must match backend
   - `DATABASE_URL` ← Should match backend
   - `JWT_SECRET` ← Should match backend

### Step 3: Check BA Agent Logs

1. Go to Render dashboard → BA Agent service
2. Click "Logs" tab
3. Look for error messages when you try to analyze requirements
4. Common errors:
   - `OpenAI API key not configured` → Set `OPENAI_API_KEY`
   - `INTERNAL_SERVICE_KEY not configured` → Set `INTERNAL_SERVICE_KEY`
   - Database connection errors → Check `DATABASE_URL`

### Step 4: Verify INTERNAL_SERVICE_KEY Match

**Critical:** `INTERNAL_SERVICE_KEY` must be **identical** in both services.

1. Check Testing Agent Backend → Environment → `INTERNAL_SERVICE_KEY`
2. Check BA Agent → Environment → `INTERNAL_SERVICE_KEY`
3. They must be **exactly the same** (copy-paste to ensure)

### Step 5: Restart Both Services

After making changes:
1. Restart Testing Agent Backend service
2. Restart BA Agent service
3. Wait for both to be "Live"

## Testing

### Test BA Agent Health
```bash
curl https://ai-sr-business-req-analyst.onrender.com/health
```
Should return: `{"status": "healthy"}`

### Test from Frontend
1. Log in to your production frontend
2. Go to Requirements page
3. Try to analyze requirements
4. Check browser console for errors
5. Check Render logs for both services

## Common Issues

### Issue 1: BA_AGENT_BASE_URL Not Set
**Symptom:** Flask gateway can't find BA agent  
**Fix:** Set `BA_AGENT_BASE_URL` in testing agent backend

### Issue 2: Missing OPENAI_API_KEY
**Symptom:** BA agent returns 500, logs show "OpenAI API key not configured"  
**Fix:** Set `OPENAI_API_KEY` in BA agent service

### Issue 3: INTERNAL_SERVICE_KEY Mismatch
**Symptom:** BA agent returns 401 (not 500)  
**Fix:** Ensure `INTERNAL_SERVICE_KEY` matches in both services

### Issue 4: BA Agent Not Running
**Symptom:** Connection errors, timeout  
**Fix:** Check BA agent service status in Render, ensure it's "Live"

## Verification Checklist

- [ ] `BA_AGENT_BASE_URL` is set in Testing Agent Backend
- [ ] `OPENAI_API_KEY` is set in BA Agent
- [ ] `INTERNAL_SERVICE_KEY` is set in BA Agent
- [ ] `INTERNAL_SERVICE_KEY` matches between both services
- [ ] `DATABASE_URL` is set in BA Agent
- [ ] `JWT_SECRET` is set in BA Agent
- [ ] Both services are "Live" in Render
- [ ] BA agent health endpoint returns `{"status": "healthy"}`
- [ ] Render logs show no errors when calling analyze

## Next Steps

If still getting 500 errors after checking all above:

1. **Check Render logs** for BA agent service - they will show the actual error
2. **Share the error message** from logs (not just "500 Internal Server Error")
3. **Check recent deployments** - did something change?
4. **Verify service resources** - is BA agent running out of memory/CPU?
