import socket
import struct
import threading
import sys
from enum import Enum
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends import default_backend

# --- CONFIGURATION ---
SERVER_PUBLIC_SIGNING_KEY = b"""-----BEGIN PUBLIC KEY-----
PASTE YOUR ED25519 PUBLIC KEY HERE
-----END PUBLIC KEY-----"""

class HandshakeState(Enum):
    AWAITING_SERVER_HANDSHAKE = 1
    AWAITING_CLIENT_EPHEMERAL_SEND = 2
    ESTABLISHED = 3

class MessageType(Enum):
    CHAT = 1
    SYSTEM = 2
    JOIN = 3
    LEAVE = 4
    HISTORY = 5  # New message type for chat history

class SecureChatClient:
    def __init__(self, host='chat-server', port=9999):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.username = None
        self.state = HandshakeState.AWAITING_SERVER_HANDSHAKE
        
        # Cryptography state
        self.aead = None
        self.send_counter = 0
        self.recv_counter = -1

    def connect(self, username):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.username = username
            self.running = True
            
            if not self._perform_handshake():
                self.socket.close()
                return False
            
            self.send_message(MessageType.JOIN, self.username)
            
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            print(f"Securely connected to chat server as {username}")
            return True
            
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False

    def _perform_handshake(self):
        """Perform the cryptographic handshake from the client's perspective"""
        try:
            # 1. Receive server's handshake message
            # Receive lengths first
            len_ephemeral = struct.unpack('>I', self._recv_all(4))[0]
            len_signature = struct.unpack('>I', self._recv_all(4))[0]
            
            # Receive ephemeral key and signature
            server_ephemeral_pub_bytes = self._recv_all(len_ephemeral)
            signature = self._recv_all(len_signature)
            
            # 2. Verify server's signature
            server_public_signing_key = serialization.load_pem_public_key(SERVER_PUBLIC_SIGNING_KEY, backend=default_backend())
            server_public_signing_key.verify(signature, server_ephemeral_pub_bytes)
            
            # 3. Generate and send client's ephemeral key
            client_ephemeral_private_key = x25519.X25519PrivateKey.generate()
            client_ephemeral_public_key = client_ephemeral_private_key.public_key()
            
            client_ephemeral_pub_bytes = client_ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.socket.sendall(client_ephemeral_pub_bytes)
            
            # 4. Perform X25519 key exchange
            server_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(server_ephemeral_pub_bytes)
            shared_secret = client_ephemeral_private_key.exchange(server_ephemeral_public_key)
            
            # 5. Derive keys
            self._derive_keys(shared_secret)
            
            self.state = HandshakeState.ESTABLISHED
            return True
            
        except InvalidSignature:
            print("SERVER AUTHENTICATION FAILED! Signature is invalid.")
            return False
        except Exception as e:
            print(f"Handshake failed: {e}")
            return False

    def _derive_keys(self, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-chat-handshake',
        )
        key = hkdf.derive(shared_secret)
        self.aead = ChaCha20Poly1305(key)

    def send_message(self, message_type, message):
        if self.state != HandshakeState.ESTABLISHED:
            print("Cannot send message, secure channel not established.")
            return False
            
        try:
            plaintext = struct.pack('>B', message_type.value) + message.encode('utf-8')
            
            nonce = struct.pack('>Q', self.send_counter) + b'snc0'
            self.send_counter += 1
            
            ciphertext = self.aead.encrypt(nonce, plaintext, None)
            counter = self.send_counter - 1
            msg_to_send = (
                struct.pack('>Q', counter) +
                struct.pack('>I', len(ciphertext)) +
                ciphertext
            )
            self.socket.sendall(msg_to_send)
            return True
            
        except Exception as e:
            print(f"Error sending message: {e}")
            self.running = False
            return False

    def receive_messages(self):
        while self.running:
            try:
                counter_data = self._recv_all(8)
                if not counter_data: break
                counter = struct.unpack('>Q', counter_data)[0]

                if counter <= self.recv_counter:
                    print(f"\n[SYSTEM] Replay attack detected! Ignoring message.")
                    raise Exception("Replay attack detected")

                length_data = self._recv_all(4)
                if not length_data:
                    break
                
                ciphertext_len = struct.unpack('>I', length_data)[0]
                ciphertext = self._recv_all(ciphertext_len)
                
                nonce = struct.pack('>Q', counter) + b'snc0'
                
                plaintext = self.aead.decrypt(nonce, ciphertext, None)
                self.recv_counter = counter
                
                message_type = MessageType(struct.unpack('>B', plaintext[0:1])[0])
                message = plaintext[1:].decode('utf-8')
                
                if message_type == MessageType.HISTORY:
                    # Display chat history
                    print("\n--- Chat History ---")
                    print(message)
                    print("--------------------")
                elif message_type == MessageType.SYSTEM:
                    print(f"\n[SYSTEM] {message}")
                elif message_type == MessageType.CHAT:
                    print(f"\n{message}")
                
                print("> ", end="", flush=True)
                
            except InvalidTag:
                print(f"\n[SYSTEM] Message authentication failed! Disconnecting.")
                break
            except Exception as e:
                print(f"\n[SYSTEM] Error receiving message: {e}")
                break
        
        self.running = False

    def _recv_all(self, size):
        data = b''
        while len(data) < size:
            packet = self.socket.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data

    def disconnect(self):
        if self.running:
            self.send_message(MessageType.LEAVE, "")
            self.running = False
        if self.socket:
            self.socket.close()
        print("Disconnected from chat server")

    def run(self):
        while not self.username:
            username = input("Enter your username: ").strip()
            if username:
                if self.connect(username):
                    break
            else:
                print("Username cannot be empty")
        
        try:
            while self.running:
                message = input("> ")
                if not message: continue
                if message.lower() in ('quit', 'exit', '/q'):
                    break
                self.send_message(MessageType.CHAT, message)
        except KeyboardInterrupt:
            pass
        finally:
            self.disconnect()

if __name__ == "__main__":
    if len(sys.argv) > 1: host = sys.argv[1]
    else: host = 'chat-server'
    if len(sys.argv) > 2: port = int(sys.argv[2])
    else: port = 9999
        
    client = SecureChatClient(host, port)
    client.run()