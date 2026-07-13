FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system netwatch \
    && useradd --system --gid netwatch --create-home --home-dir /home/netwatch netwatch

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=netwatch:netwatch . .
RUN mkdir -p /app/data /app/logs \
    && chown -R netwatch:netwatch /app/data /app/logs

EXPOSE 8501

USER netwatch

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
