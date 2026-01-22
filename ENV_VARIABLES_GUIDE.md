# Environment Variables Guide

This document explains where to set environment variables for each service in the SaaS AI Studio platform.

## Service Overview

You have **4 main services**:

1. **Frontend UI** (`ai-testing-agent-UI`) - Port 5173 (dev) / Production
2. **Testing Agent Backend** (`ai-testing-agent/backend`) - Port 5050
3. **BA Requirements Agent** (`ai-sr-business-req-analyst`) - Port 8000
4. **Jira Writeback Agent** (`jira-writeback-agent`) - Port 8001

## Frontend Environment Variables

**Location:** `ai-testing-agent-UI/.env`

**Required for Production:**
```bash
# Primary API Base URL (recommended - single URL for all services)
VITE_API_BASE=https://api.yourdomain.com

# OR separate URLs:
VITE_TEST_PLAN_API_BASE_URL=https://api.yourdomain.com
```

**Important Notes:**
- These are **Vite environment variables** (must start with `VITE_`)
- They are **embedded at build time** - you must set them before running `npm run build`
- In development, they default to `http://localhost:5050` if not set
- Copy `.env.example` to `.env` and update with your production URLs

**To set for production:**
1. Create `ai-testing-agent-UI/.env` file
2. Add `VITE_API_BASE=https://your-production-api-url.com`
3. Run `npm run build` (env vars are embedded during build)
4. Deploy the `dist` folder

## Backend Service Environment Variables

### 1. Testing Agent Backend (`ai-testing-agent/backend`)

**Location:** `ai-testing-agent/backend/.env`

**Required Variables:**
```bash
DATABASE_URL=postgresql://user:password@host:5432/dbname
JWT_SECRET=your-secret-key-here
OPENAI_API_KEY=sk-...
INTEGRATION_SECRET_KEY=your-fernet-key-here
```

**Optional:**
```bash
DEBUG_REQUIREMENTS=0  # Set to 1 for debug logging
```

### 2. BA Requirements Agent (`ai-sr-business-req-analyst`)

**Location:** `ai-sr-business-req-analyst/.env`

**Required Variables:**
```bash
OPENAI_API_KEY=sk-...
# Note: DATABASE_URL and JWT_SECRET are loaded from testing agent's .env
```

**Optional:**
```bash
JIRA_BASE_URL=https://your-jira-instance.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your-jira-api-token
```

### 3. Jira Writeback Agent (`jira-writeback-agent`)

**Location:** `jira-writeback-agent/.env`

**Required Variables:**
```bash
JIRA_BASE_URL=https://your-jira-instance.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your-jira-api-token
INTERNAL_SERVICE_KEY=your-internal-auth-key
```

## Production Deployment Checklist

### Frontend (ai-testing-agent-UI)
- [ ] Create `.env` file with `VITE_API_BASE` set to production URL
- [ ] Run `npm run build`
- [ ] Deploy `dist` folder to your hosting (Vercel, etc.)

### Backend Services
- [ ] Set `DATABASE_URL` in `ai-testing-agent/backend/.env`
- [ ] Set `JWT_SECRET` in `ai-testing-agent/backend/.env`
- [ ] Set `OPENAI_API_KEY` in both backend services
- [ ] Set `INTEGRATION_SECRET_KEY` where needed
- [ ] Configure CORS in backend to allow your frontend domain
- [ ] Deploy each backend service to your hosting platform

## Development vs Production

### Development
- Frontend defaults to `http://localhost:5050` if env vars not set
- Backend services use `.env` files in their respective directories
- All services run on localhost with different ports

### Production
- **Frontend:** Must set `VITE_API_BASE` in `.env` before building
- **Backend:** Set all required env vars in each service's `.env` file
- **CORS:** Update backend CORS settings to allow production frontend domain

## Quick Reference

| Service | Port (Dev) | Env File Location | Key Variables |
|---------|-----------|-------------------|---------------|
| Frontend UI | 5173 | `ai-testing-agent-UI/.env` | `VITE_API_BASE` |
| Testing Agent | 5050 | `ai-testing-agent/backend/.env` | `DATABASE_URL`, `JWT_SECRET`, `OPENAI_API_KEY` |
| BA Requirements | 8000 | `ai-sr-business-req-analyst/.env` | `OPENAI_API_KEY` |
| Jira Writeback | 8001 | `jira-writeback-agent/.env` | `JIRA_*`, `INTERNAL_SERVICE_KEY` |

## Troubleshooting

**"Failed to load resources" or "server could not be found"**
- Check that `VITE_API_BASE` is set correctly in frontend `.env`
- Rebuild frontend after changing env vars: `npm run build`
- Verify backend services are running and accessible

**CORS errors in production**
- Update `ALLOWED_ORIGINS` in backend services to include your production frontend URL
- Check that backend CORS configuration matches your frontend domain

**Authentication errors**
- Verify `JWT_SECRET` is the same across all services that need it
- Check that `DATABASE_URL` is correct and database is accessible
