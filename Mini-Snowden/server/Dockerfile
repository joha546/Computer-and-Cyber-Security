FROM ubuntu:20.04

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# Install Python, pip, and networking tools
RUN apt-get update && \
    apt-get install -y python3 python3-pip net-tools iproute2 netcat netcat-openbsd && \
    pip3 install --no-cache-dir cryptography && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
EXPOSE 9999

CMD ["python3", "src/secure_server_with_persistence.py"]
