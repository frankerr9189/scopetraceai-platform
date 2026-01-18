#!/bin/bash
# Start the Flask server for AI Testing Agent

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Start the Flask server
echo "Starting Flask server on port 5050..."
python app.py

