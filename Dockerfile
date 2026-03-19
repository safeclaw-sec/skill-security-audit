FROM python:3.12-slim
RUN useradd -r -s /bin/false auditor
WORKDIR /app
COPY scripts/audit.py /app/audit.py
USER auditor
ENTRYPOINT ["python3", "/app/audit.py"]
