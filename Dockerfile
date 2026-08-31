FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/datalox/venv \
    PATH=/opt/datalox/venv/bin:$PATH

WORKDIR /opt/datalox/source
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir uv==0.12.1 \
    && uv sync --frozen --no-dev --no-editable \
    && /usr/local/bin/python -m pip uninstall --yes uv \
    && useradd --uid 65532 --create-home datalox \
    && mkdir -p /var/lib/datalox /var/run/datalox /var/run/datalox-trust \
    && chown -R 65532:65532 /var/lib/datalox /var/run/datalox /var/run/datalox-trust \
    && rm -rf /opt/datalox/source

USER 65532:65532
WORKDIR /var/lib/datalox
ENTRYPOINT ["datalox-gate"]
