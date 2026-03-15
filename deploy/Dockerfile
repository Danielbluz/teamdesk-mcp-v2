FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server_sse.py .
COPY td_query_checker.py .
# NOTE: Do NOT copy .env into image — use env_file in docker-compose instead

EXPOSE 8080

CMD ["uvicorn", "server_sse:app", "--host", "0.0.0.0", "--port", "8080"]
