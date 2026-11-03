# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PII_TESSDATA_DIR=/usr/share/tesseract-ocr/5/tessdata
# English OCR data for scanned PDFs (PyMuPDF has Tesseract built in and only needs the language data)
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/* && test -f "$PII_TESSDATA_DIR/eng.traineddata"
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app

# docker build --target test .   runs the test suite inside the image (OCR included)
FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY tests ./tests
RUN python -m pytest -q

FROM base AS runtime
RUN useradd --system --uid 10001 --home /srv pii && mkdir /data && chown pii /data
USER pii
ENV PII_DATABASE_URL=sqlite:////data/pii.db
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
