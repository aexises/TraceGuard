# Required: pass an immutable digest, e.g. python@sha256:<64 lowercase hex>.
# Docker fails before a build starts when release automation omits this argument.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never
ARG PYTHON_IMAGE
# Reject a tag or malformed digest before installing TraceGuard into the image.
RUN python -c 'import os, re; image = os.environ.get("PYTHON_IMAGE", ""); assert re.fullmatch(r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}", image), "PYTHON_IMAGE must be an immutable sha256 digest"'
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY configs ./configs
# Bootstrap only uv outside the lock; all build and application dependencies use uv.lock.
RUN pip install --no-cache-dir uv==0.13.1
RUN uv sync --locked --extra dev --no-install-project --no-cache
RUN .venv/bin/python -m build --no-isolation --wheel
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt \
    --output-file /app/requirements.txt

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /app/requirements.txt ./requirements.txt
COPY --from=builder /app/dist ./dist
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.txt \
    && pip install --no-cache-dir --no-deps dist/*.whl
USER 10001
EXPOSE 8080
CMD ["traceguard-api"]
