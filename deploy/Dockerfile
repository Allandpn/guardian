# Gateway do guardião. Contexto de build: a raiz do repositório.
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin gateway \
 && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .
USER 10001:10001
VOLUME /data
EXPOSE 8080
CMD ["python", "-m", "guardian.gateway", "serve"]
