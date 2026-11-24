FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r shadowapi && useradd -r -g shadowapi -d /home/shadowapi -m shadowapi
WORKDIR /app

COPY --from=builder /root/.local /home/shadowapi/.local
COPY --chown=shadowapi:shadowapi . /app

ENV PATH=/home/shadowapi/.local/bin:$PATH
ENV PYTHONPATH=/app

USER shadowapi

ENTRYPOINT ["python3", "-m", "shadowapi.cli"]
CMD ["--help"]
