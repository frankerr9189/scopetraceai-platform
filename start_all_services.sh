#!/bin/bash
# Startup script for all SaaS AI Studio services
# Run this script from the project root directory

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "Starting SaaS AI Studio Services"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}

# Function to wait for a service to be ready
wait_for_service() {
    local url=$1
    local name=$2
    local max_attempts=30
    local attempt=0
    
    echo -n "Waiting for $name to start..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -f "$url" > /dev/null 2>&1; then
            echo -e " ${GREEN}✓${NC}"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
        echo -n "."
    done
    echo -e " ${RED}✗${NC} (timeout)"
    return 1
}

# Kill existing processes on these ports
echo "Checking for existing processes..."
for port in 8000 8001 5050 5173; do
    if check_port $port; then
        echo -e "${YELLOW}Port $port is in use. Attempting to free it...${NC}"
        lsof -ti :$port | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
done
echo ""

# Start BA Agent (port 8000)
echo "=========================================="
echo "1. Starting BA Requirements Agent (port 8000)"
echo "=========================================="
cd "$PROJECT_ROOT/ai-sr-business-req-analyst"

if [ ! -d "venv" ]; then
    echo -e "${RED}Error: venv not found in ai-sr-business-req-analyst${NC}"
    exit 1
fi

source venv/bin/activate
python3 -m uvicorn app.main:app --reload --port 8000 > /tmp/ba-agent.log 2>&1 &
BA_PID=$!
echo "BA Agent started (PID: $BA_PID)"
echo "Logs: /tmp/ba-agent.log"
cd "$PROJECT_ROOT"
sleep 2

# Start Jira Writeback Agent (port 8001)
echo ""
echo "=========================================="
echo "2. Starting Jira Writeback Agent (port 8001)"
echo "=========================================="
cd "$PROJECT_ROOT/jira-writeback-agent"

python3 -m uvicorn main:app --reload --port 8001 > /tmp/jira-writeback.log 2>&1 &
JIRA_PID=$!
echo "Jira Writeback Agent started (PID: $JIRA_PID)"
echo "Logs: /tmp/jira-writeback.log"
cd "$PROJECT_ROOT"
sleep 2

# Start Testing Agent (port 5050)
echo ""
echo "=========================================="
echo "3. Starting Testing Agent (port 5050)"
echo "=========================================="
cd "$PROJECT_ROOT/ai-testing-agent/backend"

if [ ! -d "venv" ]; then
    echo -e "${RED}Error: venv not found in ai-testing-agent/backend${NC}"
    exit 1
fi

source venv/bin/activate
python3 app.py > /tmp/testing-agent.log 2>&1 &
TESTING_PID=$!
echo "Testing Agent started (PID: $TESTING_PID)"
echo "Logs: /tmp/testing-agent.log"
cd "$PROJECT_ROOT"
sleep 2

# Wait for services to be ready
echo ""
echo "=========================================="
echo "Waiting for services to be ready..."
echo "=========================================="

wait_for_service "http://localhost:8000/health" "BA Agent"
wait_for_service "http://localhost:8001/health" "Jira Writeback Agent"
wait_for_service "http://localhost:5050/" "Testing Agent"

# Summary
echo ""
echo "=========================================="
echo "Service Status"
echo "=========================================="
echo -e "BA Agent (8000):        ${GREEN}Running${NC} (PID: $BA_PID)"
echo -e "Jira Writeback (8001):  ${GREEN}Running${NC} (PID: $JIRA_PID)"
echo -e "Testing Agent (5050):    ${GREEN}Running${NC} (PID: $TESTING_PID)"
echo ""
echo "Log files:"
echo "  - BA Agent: /tmp/ba-agent.log"
echo "  - Jira Writeback: /tmp/jira-writeback.log"
echo "  - Testing Agent: /tmp/testing-agent.log"
echo ""
echo "To stop all services, run:"
echo "  kill $BA_PID $JIRA_PID $TESTING_PID"
echo ""
echo "=========================================="
echo "Starting UI (optional)..."
echo "=========================================="
echo "To start the UI, run in a separate terminal:"
echo "  cd ai-testing-agent-UI && npm run dev"
echo ""
echo "Or press Ctrl+C to exit (services will continue running in background)"
echo ""

# Save PIDs to file for easy cleanup
echo "$BA_PID $JIRA_PID $TESTING_PID" > /tmp/saas-ai-studio-pids.txt

# Wait for user interrupt
trap "echo ''; echo 'Stopping services...'; kill $BA_PID $JIRA_PID $TESTING_PID 2>/dev/null; exit" INT
wait
