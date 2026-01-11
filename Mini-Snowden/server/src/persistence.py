import os
import json
import time
import struct
import threading
from enum import Enum
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class MessageType(Enum):
    CHAT = 1
    SYSTEM = 2
    JOIN = 3
    LEAVE = 4


class ChatPersistence:
    def __init__(self, data_dir="/app/data", backup_dir="/app/backups"):
        self.data_dir = data_dir
        self.backup_dir = backup_dir

        self.log_file = os.path.join(data_dir, "chat_log.enc")
        self.state_file = os.path.join(data_dir, "server_state.json")
        self.temp_backup_file = os.path.join(backup_dir, "temp_backup.enc")
        self.backup_file = os.path.join(backup_dir, "chat_backup.enc")

        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(backup_dir, exist_ok=True)

        self.lock = threading.Lock()

        self.master_key = self._get_or_create_master_key()
        self.aead = ChaCha20Poly1305(self.master_key)

        self.message_log = []

        self.server_state = {
            "last_backup_time": 0,
            "messages_since_backup": 0
        }

        self._load_state()
        self._load_messages()

    # ---------- KEY MANAGEMENT ----------

    def _get_or_create_master_key(self):
        key_path = os.path.join(self.data_dir, "master.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                return f.read()

        key = ChaCha20Poly1305.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
        return key

    # ---------- STATE ----------

    def _load_state(self):
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r") as f:
                self.server_state = json.load(f)
        except Exception as e:
            print(f"[Persistence] Failed to load state: {e}")

    def _save_state(self):
        with open(self.state_file, "w") as f:
            json.dump(self.server_state, f)

    # ---------- LOG FORMAT ----------
    # Record = [nonce(12)][cipher_len(4)][ciphertext]

    def _load_messages(self):
        if not os.path.exists(self.log_file):
            return

        try:
            with open(self.log_file, "rb") as f:
                while True:
                    nonce = f.read(12)
                    if not nonce:
                        break

                    cipher_len_bytes = f.read(4)
                    if len(cipher_len_bytes) != 4:
                        break

                    cipher_len = struct.unpack(">I", cipher_len_bytes)[0]
                    ciphertext = f.read(cipher_len)

                    plaintext = self.aead.decrypt(nonce, ciphertext, None)

                    offset = 0
                    timestamp = struct.unpack(">d", plaintext[offset:offset+8])[0]
                    offset += 8

                    msg_type = MessageType(plaintext[offset])
                    offset += 1

                    uname_len = plaintext[offset]
                    offset += 1
                    username = plaintext[offset:offset+uname_len].decode()
                    offset += uname_len

                    msg_len = struct.unpack(">I", plaintext[offset:offset+4])[0]
                    offset += 4
                    message = plaintext[offset:offset+msg_len].decode()

                    self.message_log.append({
                        "timestamp": timestamp,
                        "type": msg_type,
                        "username": username,
                        "message": message
                    })

            print(f"[Persistence] Loaded {len(self.message_log)} messages")

        except Exception as e:
            print(f"[Persistence] Log recovery failed: {e}")

    # ---------- WRITE ----------

    def log_message(self, message_type, username, message):
        with self.lock:
            ts = time.time()

            uname_b = username.encode()
            msg_b = message.encode()

            plaintext = (
                struct.pack(">d", ts) +
                struct.pack(">B", message_type.value) +
                struct.pack(">B", len(uname_b)) +
                uname_b +
                struct.pack(">I", len(msg_b)) +
                msg_b
            )

            nonce = os.urandom(12)
            ciphertext = self.aead.encrypt(nonce, plaintext, None)

            with open(self.log_file, "ab") as f:
                f.write(nonce)
                f.write(struct.pack(">I", len(ciphertext)))
                f.write(ciphertext)

            self.message_log.append({
                "timestamp": ts,
                "type": message_type,
                "username": username,
                "message": message
            })

            self.server_state["messages_since_backup"] += 1
            self._check_backup_needed()

    # ---------- BACKUP ----------

    def _check_backup_needed(self):
        now = time.time()
        if (
            now - self.server_state["last_backup_time"] > 300 or
            self.server_state["messages_since_backup"] >= 50
        ):
            self.create_backup()

    def create_backup(self):
        with self.lock:
            if not os.path.exists(self.log_file):
                return False

            try:
                with open(self.log_file, "rb") as src, open(self.temp_backup_file, "wb") as dst:
                    dst.write(src.read())

                os.replace(self.temp_backup_file, self.backup_file)

                self.server_state["last_backup_time"] = time.time()
                self.server_state["messages_since_backup"] = 0
                self._save_state()

                print(f"[Persistence] Backup created at {datetime.now()}")
                return True

            except Exception as e:
                print(f"[Persistence] Backup failed: {e}")
                return False

    def restore_from_backup(self):
        if not os.path.exists(self.backup_file):
            print("[Persistence] No backup found")
            return False

        try:
            with open(self.backup_file, "rb") as src, open(self.log_file, "wb") as dst:
                dst.write(src.read())

            self.message_log.clear()
            self._load_messages()

            print("[Persistence] Restored from backup")
            return True

        except Exception as e:
            print(f"[Persistence] Restore failed: {e}")
            return False

    # ---------- READ ----------

    def get_recent_messages(self, count=50):
        return self.message_log[-count:]