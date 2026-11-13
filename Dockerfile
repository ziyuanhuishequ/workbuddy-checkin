FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 先装依赖，利用 Docker 层缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY run.py ./
COPY tools ./tools

RUN mkdir -p /app/data

ENV WB_DATA_DIR=/app/data \
    WB_HOST=0.0.0.0 \
    WB_PORT=8848 \
    WB_TZ_OFFSET=8

EXPOSE 8848
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8848/api/health', timeout=4).status==200 else 1)"

CMD ["python", "run.py"]
