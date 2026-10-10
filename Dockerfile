FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY data ./data
RUN pip install --no-cache-dir ".[dashboard,mlflow]"

COPY configs ./configs
COPY dashboard ./dashboard

# Point at the Ollama service (see docker-compose.yml) or any reachable host.
ENV OLLAMA_HOST=http://ollama:11434
ENTRYPOINT ["llm-redteam"]
CMD ["--help"]
