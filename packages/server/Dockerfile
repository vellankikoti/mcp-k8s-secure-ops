FROM python:3.11-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir uv
COPY . .
RUN uv sync --package mcp-k8s-secure-ops --no-dev && \
    uv build --package mcp-k8s-secure-ops --wheel --out-dir packages/server/dist

FROM python:3.11-slim
RUN useradd -u 10001 -r secureops && mkdir /var/lib/secureops && chown secureops /var/lib/secureops
COPY --from=build /src/packages/server/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER 10001
WORKDIR /app
ENTRYPOINT ["mcp-k8s-secure-ops"]
CMD ["serve-mcp"]
