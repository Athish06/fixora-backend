#!/bin/bash
# Render start script for Fixora backend

# Get port from environment (Render provides this)
PORT=${PORT:-8000}

echo "Starting Fixora API on 0.0.0.0:$PORT"

# Start uvicorn with production settings
uvicorn server:app --host 0.0.0.0 --port $PORT --workers 2
