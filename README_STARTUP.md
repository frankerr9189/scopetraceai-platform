# SaaS AI Studio - Service Startup Guide

## Quick Start

### Start All Services
```bash
./start_all_services.sh
```

This will start:
- **BA Requirements Agent** on port 8000
- **Jira Writeback Agent** on port 8001  
- **Testing Agent** on port 5050

### Stop All Services
```bash
./stop_all_services.sh
```

## Manual Startup (Alternative)

If the startup script doesn't work, you can start each service manually:

### 1. BA Requirements Agent (port 8000)
```bash
cd ai-sr-business-req-analyst
source venv/bin/activate
python3 -m uvicorn app.main:app --reload --port 8000
```

### 2. Jira Writeback Agent (port 8001)
```bash
cd jira-writeback-agent
python3 -m uvicorn main:app --reload --port 8001
```

### 3. Testing Agent (port 5050)
```bash
cd ai-testing-agent/backend
source venv/bin/activate
python3 app.py
```

### 4. UI (port 5173)
```bash
cd ai-testing-agent-UI
npm run dev
```

## Service URLs

- **BA Requirements Agent**: http://localhost:8000
- **Jira Writeback Agent**: http://localhost:8001
- **Testing Agent**: http://localhost:5050
- **UI**: http://localhost:5173

## Health Checks

- BA Agent: http://localhost:8000/health
- Jira Writeback: http://localhost:8001/health
- Testing Agent: http://localhost:5050/

## Log Files

All services write logs to `/tmp/`:
- `/tmp/ba-agent.log` - BA Requirements Agent
- `/tmp/jira-writeback.log` - Jira Writeback Agent
- `/tmp/testing-agent.log` - Testing Agent
- `/tmp/ui.log` - UI (if started separately)

## Troubleshooting

### Port Already in Use
If a port is already in use, the startup script will attempt to kill the existing process. You can also manually kill processes:
```bash
# Find process using port
lsof -i :8000

# Kill process
kill -9 <PID>
```

### Virtual Environment Issues
If you get "ModuleNotFoundError", make sure you're using the virtual environment:
```bash
# Activate venv
source venv/bin/activate

# Verify openai is installed
python3 -c "import openai; print('OK')"
```

### Environment Variables
Some services require environment variables. Check the `.env` files in each service directory:
- `ai-sr-business-req-analyst/.env`
- `jira-writeback-agent/.env`
- `ai-testing-agent/backend/.env`

Required variables:
- `OPENAI_API_KEY` - For BA Agent and Testing Agent
- `JIRA_BASE_URL` - For Jira Writeback Agent
- `JIRA_EMAIL` or `JIRA_USERNAME` - For Jira Writeback Agent
- `JIRA_API_TOKEN` - For Jira Writeback Agent
