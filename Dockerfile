FROM ollama/ollama:latest

# Install curl (optional for healthcheck)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Set environment variables for CORS + host binding
ENV OLLAMA_HOST "0.0.0.0:11434"
ENV OLLAMA_ORIGINS "*"

# Expose API port
EXPOSE 11434

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/bin/sh", "/start.sh"]
