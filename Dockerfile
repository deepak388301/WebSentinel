FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Non-root runtime user (container security: don't run as root).
RUN useradd --create-home websentinel

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x start_websentinel.sh \
    && chown -R websentinel:websentinel /app

USER websentinel

EXPOSE 8080

# The dashboard login page is public and returns 200, so it doubles as a
# lightweight liveness check (no extra curl/wget needed).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/websentinel/login', timeout=3); sys.exit(0)" || exit 1

CMD ["./start_websentinel.sh"]
