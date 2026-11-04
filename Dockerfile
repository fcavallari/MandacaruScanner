FROM python:3.11-slim

# All Python deps ship wheels (psycopg2-binary bundles libpq), so no compiler
# or libpq-dev is needed in the image.
WORKDIR /app

COPY requirements.txt ./pnakotic/
RUN pip install --no-cache-dir -r pnakotic/requirements.txt

# Browsers go to a shared path so the non-root runtime user can launch them.
# Chromium's own sandbox is enabled (chromium_sandbox=True in the engine).
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install chromium --with-deps \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user: the browser renders attacker-chosen pages.
RUN useradd --uid 1001 --user-group --create-home --shell /usr/sbin/nologin pnakotic

# Copy the repo AS a package so `pnakotic.src...` imports resolve
# (compose, tests and alembic all use that module path).
COPY . ./pnakotic/
# Named volumes mounted at /app/artifacts inherit this ownership on first creation.
RUN mkdir -p /app/artifacts \
    && chown -R pnakotic:pnakotic /app

ENV ARTIFACTS_DIR=/app/artifacts

USER pnakotic
