FROM alpine:3.22

## The packages that our container will use.
RUN apk add --no-cache python3 py3-flask py3-flask-wtf py3-psutil py3-gunicorn py3-cryptography sqlite

# Unprivileged user + persistent data dir
RUN addgroup -S app && adduser -S -G app -h /app app \
    && mkdir -p /data && chown app:app /data

WORKDIR /app
COPY --chown=app:app app.py ./
COPY --chown=app:app templates ./templates
COPY --chown=app:app static ./static
COPY --chown=app:app tests ./tests

USER app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data

VOLUME /data
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:5000/healthz || exit 1

# One worker + threads: SQLite-friendly and keeps in-memory login throttling consistent.
CMD ["python3", "-m", "gunicorn", "-b", "0.0.0.0:5000", "-w", "1", "--threads", "4", \
     "--access-logfile", "-", "app:app"]
