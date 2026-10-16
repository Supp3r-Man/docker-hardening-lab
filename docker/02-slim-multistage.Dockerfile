# Stage 2: smaller and cache-friendly, but still runs as root and still floats on a tag.
FROM python:3.11-slim AS build
WORKDIR /build
RUN python -m venv /venv
# Dependencies first: this layer is reused until requirements.txt changes.
COPY app/requirements.txt .
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=build /venv /venv
COPY app/ /app/
ENV PATH="/venv/bin:$PATH" PORT=8080
EXPOSE 8080
CMD ["python", "server.py"]
