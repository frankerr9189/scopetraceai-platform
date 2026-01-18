#!/bin/bash
# Stop script for all SaaS AI Studio services

echo "Stopping all SaaS AI Studio services..."

# Try to read PIDs from file
if [ -f /tmp/saas-ai-studio-pids.txt ]; then
    PIDS=$(cat /tmp/saas-ai-studio-pids.txt)
    for pid in $PIDS; do
        if kill -0 $pid 2>/dev/null; then
            echo "Stopping process $pid..."
            kill $pid 2>/dev/null || true
        fi
    done
    rm /tmp/saas-ai-studio-pids.txt
fi

# Also kill by port (more reliable)
for port in 8000 8001 5050; do
    if lsof -ti :$port > /dev/null 2>&1; then
        echo "Stopping service on port $port..."
        lsof -ti :$port | xargs kill -9 2>/dev/null || true
    fi
done

echo "All services stopped."
