# Stage 1: the Dockerfile most tutorials end with. Every line here is a habit to unlearn.
FROM python:latest

WORKDIR /app
# Copies everything first, so any code edit invalidates the dependency layer below.
COPY . .
RUN pip install -r app/requirements.txt

ENV PORT=8080
EXPOSE 8080
CMD ["python", "app/server.py"]
