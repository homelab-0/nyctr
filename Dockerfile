# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS web-build
WORKDIR /build/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="Nyctr" \
      org.opencontainers.image.description="Self-hosted network security workspace" \
      org.opencontainers.image.source="https://github.com/homelab-0/nyctr" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    NYCTR_STATIC_DIR=/app/web
WORKDIR /app
COPY services/api/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && groupadd --gid 10001 nyctr \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin nyctr
COPY services/api/nyctr/ /app/nyctr/
COPY --from=web-build /build/web/dist/ /app/web/
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)"
CMD ["uvicorn", "nyctr.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
