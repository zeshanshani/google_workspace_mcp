FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY . .

RUN uv sync --frozen --no-dev

RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8000}/health" || exit 1

ENV TOOL_TIER="core"

CMD ["sh", "-c", "uv run main.py --tool-tier \"$TOOL_TIER\""]
