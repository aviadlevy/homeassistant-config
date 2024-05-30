FROM python:3.11-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt


COPY secrets.py .
COPY sonarr_mgmt.py .

CMD ["python", "-u", "sonarr_mgmt.py"]

