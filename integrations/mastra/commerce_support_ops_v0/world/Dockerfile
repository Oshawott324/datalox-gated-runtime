FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/datalox-venv

WORKDIR /opt/datalox
RUN python -m pip install --no-cache-dir uv==0.12.1
COPY runtime/pyproject.toml runtime/uv.lock /opt/datalox/runtime/
RUN uv sync --directory /opt/datalox/runtime --frozen --no-dev --no-install-project --no-managed-python

COPY . /opt/datalox
RUN groupadd --system datalox \
    && useradd --system --gid datalox --home-dir /nonexistent --shell /usr/sbin/nologin datalox \
    && mkdir -p /var/lib/datalox/run \
    && chown -R datalox:datalox /var/lib/datalox \
    && chmod -R a-w /opt/datalox/episode_template /opt/datalox/runtime /opt/datalox-venv

ENV PATH="/opt/datalox-venv/bin:$PATH" \
    PYTHONPATH=/opt/datalox/runtime/src \
    DATALOX_WORLD_PACKAGE_ROOT=/opt/datalox

USER datalox:datalox
VOLUME ["/var/lib/datalox/run"]
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=2s --start-period=10s --retries=12 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=1).read()" || exit 1
ENTRYPOINT ["python", "-m", "datalox_gated_runtime.world_package.entrypoint"]
