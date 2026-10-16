# Stage 3: what is in the image. Pinned by tag and digest, no shell, no package manager,
# no pip cache, non-root user, a HEALTHCHECK that needs neither curl nor a shell.
# Digests are recorded in docker/base-images.json and checked by the tests.
FROM python:3.11.17-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89 AS build
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --target /deps -r requirements.txt

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
# The base image already runs as uid 65532, so a bare WORKDIR would create /app owned by the app
# user and let the app rewrite its own code. Let a root-owned COPY create it, then enter it.
COPY --from=build --chown=0:0 /deps /deps
COPY --chown=0:0 app/ /app/
WORKDIR /app
ENV PYTHONPATH=/deps PORT=8080
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=3 \
  CMD ["/usr/bin/python3.11", "/app/healthcheck.py"]
# The distroless python image already sets ENTRYPOINT to python3.11.
CMD ["/app/server.py"]
