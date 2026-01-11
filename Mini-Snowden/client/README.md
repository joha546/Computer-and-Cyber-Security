# Secure Chat Client with History

This repository contains the **client-side code** for a secure, encrypted chat application that connects to the **Secure Chat Server**. The client supports **real-time messaging** and **retrieval of chat history** from the server.

---

## Features

* **Secure Communication:** Uses `ChaCha20Poly1305` encryption via ephemeral X25519 keys for end-to-end encryption.
* **Message History:** Retrieves the last N messages from the server on join.
* **Replay Protection:** Each message includes a counter to prevent replay attacks.
* **Dockerized:** Easily run in a containerized environment with Docker Compose.
* **Cross-Platform:** Works in any environment with Python 3 and required dependencies.

---

## Folder Structure

```
client/
├── src/
│   ├── client.py                     # Basic client implementation
│   ├── secure_client.py              # Secure client without history
│   └── secure_client_with_history.py # Full secure client with history support
├── Dockerfile                        # Dockerfile to build client container
├── README.md                          # This file
└── test_environment.py               # Optional scripts for testing client-server connection
```

---

## Prerequisites

* Docker & Docker Compose installed
* Python 3 (inside container)
* `cryptography` Python package (installed automatically in Dockerfile)
* Server must be running and accessible (port 9999 by default)
* Server's public Ed25519 key must be set in `secure_client_with_history.py`

```python
SERVER_PUBLIC_SIGNING_KEY = b"""-----BEGIN PUBLIC KEY-----
<PASTE YOUR SERVER ED25519 PUBLIC KEY HERE>
-----END PUBLIC KEY-----"""
```

---

## Setup & Running

### 1. Build Docker Containers

From the project root:

```bash
docker compose build
```

### 2. Start Client Container

```bash
docker compose run --rm client
```

You will be prompted to enter a **username**:

```text
Enter your username: joha
```

### 3. Sending & Receiving Messages

* Type your message and press Enter to send.
* Received messages are displayed in real-time.
* System messages (user joins, leaves) are displayed with `[SYSTEM]`.
* Use `quit`, `exit`, or `/q` to leave the chat.

---

## Security Notes

* **Server Verification:** The client verifies the server's Ed25519 signature during the handshake to prevent MITM attacks.
* **Encryption:** All messages are encrypted using `ChaCha20Poly1305`.
* **Replay Protection:** Each message contains a counter to detect and reject replayed messages.
* **Chat History:** Only decrypted on the client side; preserved securely on the server.

---

## Docker Notes

* Installs Python 3, pip, and networking tools (`net-tools`, `iproute2`, `netcat`).
* Installs `cryptography` Python library for secure messaging.
* Runs `secure_client_with_history.py` by default.
* Uses a mounted volume for easy local development and debugging.

---

## References

* [Cryptography Library](https://cryptography.io/en/latest/)
* [ChaCha20Poly1305 AEAD](https://en.wikipedia.org/wiki/Salsa20#ChaCha20)
* [X25519 Key Exchange](https://cr.yp.to/ecdh.html)
* [Docker Compose Documentation](https://docs.docker.com/compose/)
