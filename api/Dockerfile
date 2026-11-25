FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends nftables \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY models ./models
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh && useradd -m netwatch
ENV NETWATCH_DB=/data/netwatch.db
RUN mkdir -p /data && chown netwatch /data
EXPOSE 8000
# Enforce mode needs root + NET_ADMIN to edit nftables, so the entrypoint drops privileges only in other modes.
ENTRYPOINT ["./entrypoint.sh"]
