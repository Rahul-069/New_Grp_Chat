FROM ollama/ollama:latest

EXPOSE 11434

CMD ["/bin/ollama", "serve"]
