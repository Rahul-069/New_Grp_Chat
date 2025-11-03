FROM ollama/ollama:latest

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Expose Ollama port
EXPOSE 11434

# Start Ollama and pull the model
CMD ollama serve & \
    sleep 10 && \
    ollama pull deepseek-coder:1.3b-instruct && \
    tail -f /dev/null
