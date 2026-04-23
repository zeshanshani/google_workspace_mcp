FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY . .

RUN uv sync --frozen --no-dev

RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

EXPOSE 8000

# Railway does its own healthcheck via railway.json (healthcheckPath: /health).
# Don't duplicate it here — a failing Docker HEALTHCHECK surfaces as a separate
# error and the `curl` dep adds cold-image bloat we don't otherwise need.

ENV TOOL_TIER="core"

CMD ["sh", "-c", "uv run main.py --tool-tier \"$TOOL_TIER\""]
