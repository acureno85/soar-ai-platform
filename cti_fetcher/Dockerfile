FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cti_fetcher.py .

CMD ["python", "-u", "cti_fetcher.py"]
