# Secure Chat Server with Persistence

This repository contains the **server-side code** for a secure, encrypted chat application with message persistence and backup support. The server is designed to work with a corresponding client and uses **end-to-end encryption** with **X25519/Ed25519** keys.

---

## Features

* **Secure Communication:** All messages are encrypted using `ChaCha20Poly1305` via an ephemeral key exchange (X25519).
* **Message Persistence:** Chat messages are logged securely to disk and encrypted for recovery.
* **Automatic Backups:** Periodic backups are created to prevent data loss.
* **Replay Protection:** Messages include counters to prevent replay attacks.
* **Dockerized:** Easily run in a containerized environment with Docker Compose.

---

## Folder Structure

```
server/
├── backups/                     # Backup files for chat logs
├── data/                        # Encrypted logs and master key
├── keys/                        # Server long-term Ed25519/X25519 keys
│   ├── server_ed25519_private.pem
│   ├── server_ed25519_public.pem
│   ├── server_x25519_private.pem
│   └── server_x25519_public.pem
├── logs/                        # Optional: server runtime logs
├── src/                         # Source code
│   ├── persistence.py           # Message logging and backup
│   ├── secure_server.py         # Secure server without persistence
│   ├── secure_server_with_persistence.py # Full secure server with persistence
│   └── server.py                # Optional server launcher
├── Dockerfile                   # Dockerfile to build the server container
├── README.md                    # This file
└── test_environment.py          # Scripts for testing server functionality
```

---

## Prerequisites

* Docker & Docker Compose installed
* Python 3 (inside container)
* `cryptography` Python package (installed automatically in Dockerfile)
* Generated server keys (`Ed25519` for signing, `X25519` for key exchange)

---

## Setup & Running

### 1. Generate Server Keys (if not already present)

```bash
python3 generate_keys.py
```

This creates the necessary `Ed25519` and `X25519` key pairs in the `server/keys/` directory.

### 2. Build Docker Containers

From the project root:

```bash
docker-compose build
```

### 3. Start Server Container

```bash
docker-compose up -d server
```

The server listens on **port 9999** and restores messages from backups if available.

### 4. Connect Client

Use the corresponding client container to connect:

```bash
docker-compose run --rm client
```

Follow the prompt to enter your username. All messages are encrypted end-to-end.

---

## Persistence & Backup

* Chat messages are stored in `server/data/chat_log.enc` (encrypted).
* Periodic backups are stored in `server/backups/chat_backup.enc`.
* The server automatically restores messages from the latest backup on startup.
* Configuration for backup frequency and message count thresholds is in `persistence.py`.

---

## Docker Notes

* Server Dockerfile installs:

  * Python 3, pip
  * Networking tools (`net-tools`, `iproute2`, `netcat`)
  * `cryptography` Python library
* Port `9999` is exposed for client connections.
* Persistent volumes ensure data and keys remain after container restart.

---

## Security Notes

* Server keys are **sensitive**. Never expose `server_ed25519_private.pem` or `server_x25519_private.pem`.
* All chat logs are **encrypted** using `ChaCha20Poly1305`.
* Each client performs an **ephemeral key handshake** for secure end-to-end encryption.

---

## References

* [Cryptography Library](https://cryptography.io/en/latest/)
* [ChaCha20Poly1305 AEAD](https://en.wikipedia.org/wiki/Salsa20#ChaCha20)
* [X25519 Key Exchange](https://cr.yp.to/ecdh.html)
* [Docker Compose Documentation](https://docs.docker.com/compose/)

