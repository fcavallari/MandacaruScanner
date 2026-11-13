FROM python:3.11-slim

# All Python deps ship wheels (psycopg2-binary bundles libpq), so no compiler
# or libpq-dev is needed in the image.
WORKDIR /app

COPY requirements.txt ./mandacaru/
RUN pip install --no-cache-dir -r mandacaru/requirements.txt

# Which browser scans run in (see SECURITY_REVIEW.md, V9). "chrome" installs Google
# Chrome stable, which gets Chrome's security builds the day Google ships them, so this
# image should be rebuilt on Chrome's cadence (weekly). Google publishes no Linux arm64
# Chrome, so an arm64 build (Apple-silicon Docker) must use "chromium": Playwright's
# bundled build, which only moves with Playwright releases.
ARG BROWSER_CHANNEL=chrome
# Browsers go to a shared path so the non-root runtime user can launch them.
# Chromium's own sandbox is enabled (chromium_sandbox=True in the engine).
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN set -eux; \
    if [ "$BROWSER_CHANNEL" = "chrome" ]; then \
        if [ "$(dpkg --print-architecture)" != "amd64" ]; then \
            echo "Google Chrome has no Linux $(dpkg --print-architecture) build; build with --build-arg BROWSER_CHANNEL=chromium" >&2; exit 1; \
        fi; \
        playwright install chrome --with-deps; \
        google-chrome --version; \
    else \
        playwright install chromium --with-deps; \
        chmod -R a+rX /ms-playwright; \
    fi; \
    rm -rf /var/lib/apt/lists/*
# Empty means Playwright's bundled Chromium; the engine reads this at launch.
ENV BROWSER_CHANNEL=${BROWSER_CHANNEL}

# Run as an unprivileged user: the browser renders attacker-chosen pages.
RUN useradd --uid 1001 --user-group --create-home --shell /usr/sbin/nologin mandacaru

# Copy the repo AS a package so `mandacaru.src...` imports resolve
# (compose, tests and alembic all use that module path).
COPY . ./mandacaru/
# Named volumes mounted at /app/artifacts inherit this ownership on first creation.
RUN mkdir -p /app/artifacts \
    && chown -R mandacaru:mandacaru /app

ENV ARTIFACTS_DIR=/app/artifacts

USER mandacaru
