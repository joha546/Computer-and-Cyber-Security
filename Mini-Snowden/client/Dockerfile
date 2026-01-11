FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y python3 python3-pip net-tools iproute2 netcat netcat-openbsd && \
    pip3 install --no-cache-dir cryptography && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

CMD ["python3", "src/secure_client_with_history.py"]
