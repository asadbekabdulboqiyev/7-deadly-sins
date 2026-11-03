# syntax=docker/dockerfile:1
#
# SINS API + worker uchun yagona obraz.
# Og'ir tizim bog'liqliklari: WeasyPrint (PDF) uchun pango/cairo.
# nuclei va osv-scanner obrazga kirmaydi — ular alohida o'rnatiladi va
# konteynerga mount qilinadi yoki `PATH`da bo'lishi kerak (docs/RUNBOOK.md).

FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src ./src
COPY migrations ./migrations
COPY alembic.ini README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    SINS_LOG_JSON=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app /app

RUN useradd --create-home --uid 10001 sins \
    && chown -R sins:sins /app
USER sins

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["sins", "serve", "--host", "0.0.0.0", "--port", "8000"]
