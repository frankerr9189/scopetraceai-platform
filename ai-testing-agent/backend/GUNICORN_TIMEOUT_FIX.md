# Fixing Gunicorn Worker Timeout for OpenAI API Calls

## Problem

The `/generate-test-plan` endpoint is timing out because:
- OpenAI API calls can take 30-60+ seconds for complex test plan generation
- Gunicorn's default timeout is 30 seconds
- Worker gets killed before the API call completes → 500 error

## Solution: Increase Gunicorn Timeout

### Option 1: Use Gunicorn Config File (Recommended)

I've created `gunicorn.conf.py` with `timeout=300` (5 minutes).

**In Render Dashboard:**
1. Go to your Testing Agent Backend service
2. Settings → Build & Deploy
3. Update the "Start Command" to:
   ```bash
   cd ai-testing-agent/backend && gunicorn -c gunicorn.conf.py app:app --bind 0.0.0.0:$PORT
   ```

### Option 2: Set Timeout in Start Command

If you can't use the config file, update the start command directly:

```bash
cd ai-testing-agent/backend && gunicorn --timeout 300 app:app --bind 0.0.0.0:$PORT
```

### Option 3: Set via Environment Variable

Add to Render environment variables:
```bash
GUNICORN_CMD_ARGS="--timeout=300"
```

Then keep your existing start command:
```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

## What Changed

1. **Created `gunicorn.conf.py`** - Config file with timeout=300 (5 minutes)
2. **Added OpenAI client timeout** - Set to 240 seconds (4 minutes) to prevent hanging
   - This gives a 60-second buffer before Gunicorn timeout

## Why 300 Seconds?

- OpenAI API calls for complex test plans can take 60-120+ seconds
- 300 seconds (5 minutes) provides a safe buffer
- Still reasonable for user experience
- Prevents worker timeouts

## After Deployment

1. Deploy the changes (commit and push)
2. Update the start command in Render (if using Option 1 or 2)
3. Restart the service
4. Test `/generate-test-plan` - it should no longer timeout

## Verify It's Working

Check Render logs - you should see:
- No more `[CRITICAL] WORKER TIMEOUT` errors
- Successful completion of `/generate-test-plan` requests
- Longer request times (30-120 seconds) are now acceptable
