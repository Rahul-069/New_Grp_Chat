#!/bin/sh

# Start ollama server in background
ollama serve &

# Wait for server to boot
sleep 10

# Pull model
ollama pull deepseek-coder:1.3b-instruct

# Keep container alive
tail -f /dev/null
