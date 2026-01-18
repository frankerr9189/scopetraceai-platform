#!/bin/bash
# Check status of all agent services

echo "🔍 Checking service status..."
echo ""

# Check ai-sr-business-req-analyst (port 8000)
if lsof -i :8000 > /dev/null 2>&1; then
    echo "✅ ai-sr-business-req-analyst: RUNNING (port 8000)"
else
    echo "❌ ai-sr-business-req-analyst: NOT RUNNING (port 8000)"
fi

# Check UI (port 5173)
if lsof -i :5173 > /dev/null 2>&1; then
    echo "✅ UI (ai-testing-agent-UI): RUNNING (port 5173)"
else
    echo "❌ UI (ai-testing-agent-UI): NOT RUNNING (port 5173)"
fi

# Check jira-writeback-agent (would need a port - checking common ports)
if lsof -i :8001 > /dev/null 2>&1; then
    echo "✅ jira-writeback-agent: RUNNING (port 8001)"
elif lsof -i :8002 > /dev/null 2>&1; then
    echo "✅ jira-writeback-agent: RUNNING (port 8002)"
else
    echo "❌ jira-writeback-agent: NOT RUNNING (no main.py found - needs setup)"
fi

echo ""
echo "📝 To start services:"
echo "  ai-sr-business-req-analyst: cd ai-sr-business-req-analyst && uvicorn app.main:app --reload"
echo "  UI: cd ai-testing-agent-UI && npm run dev"
echo "  jira-writeback-agent: (needs main.py setup first)"
