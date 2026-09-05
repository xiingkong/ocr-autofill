FROM python:3.11-slim

# 装 Playwright 系统依赖 + Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation libasound2 libnss3 libxss1 libgtk-3-0 libgbm1 \
    libxshmfence1 libxcomposite1 libxrandr2 libxkbcommon0 libpango-1.0-0 \
    libcairo2 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

# 装 Playwright + Chromium
RUN pip install --no-cache-dir playwright ddddocr
RUN playwright install chromium
RUN playwright install-deps chromium

WORKDIR /app
COPY ocr_server.py ./
COPY autofill-panel.html ./

# 容器内默认用 chromium（不是 Edge）
ENV BROWSER_TYPE=chromium
ENV PYTHONUNBUFFERED=1

EXPOSE 7777
CMD ["python", "ocr_server.py", "7777"]
