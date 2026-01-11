import socket
import struct
import threading
import time
import signal
import sys
import os
import hashlib
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from persistence import ChatPersistence, MessageType

SERVER_X25519_KEY_PATH = "/app/keys/server_x25519_private.pem"
SERVER_ED25519_KEY_PATH = "/app/keys/server_ed25519_private.pem"

class HandshakeState(Enum):
    AWAITING_CLIENT_EPHEMERAL = 1
    ESTABLISHED = 2

class SecureClientHandler:
    def __init__(self, client_socket, client_address, server_static_private_key, server_static_public_key, persistence):
        self.socket = client_socket
        self.address = client_address
        self.username = None
        self.state = HandshakeState.AWAITING_CLIENT_EPHEMERAL
        
        # Load server keys
        self.server_static_private_key = server_static_private_key
        self.server_static_public_key = server_static_public_key
        
        # Reference to the persistence layer
        self.persistence = persistence
        
        # Generate server's ephemeral key for this session
        self.server_ephemeral_private_key = x25519.X25519PrivateKey.generate()
        self.server_ephemeral_public_key = self.server_ephemeral_private_key.public_key()
        
        # Cryptography state
        self.aead = None
        self.send_counter = 0
        self.recv_counter = -1

    def perform_handshake(self):
        """Perform the cryptographic handshake"""
        try:
            # 1. Send server's ephemeral public key and its signature
            ephemeral_pub_bytes = self.server_ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            signature = self.server_static_private_key.sign(ephemeral_pub_bytes)
            
            # Message format: [len(ephemeral_key)][len(signature)][ephemeral_key][signature]
            handshake_msg = struct.pack('>I', len(ephemeral_pub_bytes)) + \
                            struct.pack('>I', len(signature)) + \
                            ephemeral_pub_bytes + signature
            self.socket.sendall(handshake_msg)
            
            # 2. Receive client's ephemeral public key
            client_ephemeral_pub_bytes = self._recv_all(self.socket, 32) # X25519 raw key is 32 bytes
            if not client_ephemeral_pub_bytes:
                raise Exception("Failed to receive client ephemeral key")
                
            client_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(client_ephemeral_pub_bytes)
            
            # 3. Perform X25519 key exchange to get shared secret
            shared_secret = self.server_ephemeral_private_key.exchange(client_ephemeral_public_key)
            
            # 4. Derive encryption keys using HKDF
            self._derive_keys(shared_secret)
            
            self.state = HandshakeState.ESTABLISHED
            print(f"Secure channel established with {self.address[0]}:{self.address[1]}")
            return True
            
        except Exception as e:
            print(f"Handshake failed with {self.address[0]}:{self.address[1]}: {e}")
            return False

    def _derive_keys(self, shared_secret):
        """Derive symmetric keys from the shared secret"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # ChaCha20 key is 32 bytes
            salt=None,
            info=b'secure-chat-handshake',
        )
        key = hkdf.derive(shared_secret)
        self.aead = ChaCha20Poly1305(key)

    def send_message(self, message_type, message):
        """Send an encrypted message"""
        if self.state != HandshakeState.ESTABLISHED:
            print(f"[DEBUG] Cannot send message, client {self.username} not established.")
            return
        
        try:
            plaintext = struct.pack('>B', message_type.value) + message.encode('utf-8')
        
            # Create nonce: 8-byte counter + 4-byte fixed prefix
            nonce = struct.pack('>Q', self.send_counter) + b'snc0' # snc = secure nonce
            self.send_counter += 1
        
            ciphertext = self.aead.encrypt(nonce, plaintext, None) # No additional data
        
            # Send [counter][ciphertext]
            counter = self.send_counter - 1
            msg_to_send = (
                struct.pack('>Q', counter) +
                struct.pack('>I', len(ciphertext)) +
                ciphertext
            )

            self.socket.sendall(msg_to_send)
            print(f"[DEBUG] Sent message to {self.username}: {message_type}, {message}")
        
        except Exception as e:
            print(f"Error{e}")
            return False

    def recv_message(self):
        """Receive and decrypt a message"""
        if self.state != HandshakeState.ESTABLISHED:
            return None, None

        # Receive counter
        counter_data = self._recv_all(self.socket, 8)
        if not counter_data: return None, None
        counter = struct.unpack('>Q', counter_data)[0]

        # Replay protection check: reject old or duplicate counters
        if counter <= self.recv_counter:
            print(f"Replay attack detected! Ignoring message with counter {counter}. Expected > {self.recv_counter}")
            # Close the connection to prevent further issues
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except: pass
            return None, None
        
        # Receive ciphertext
        length_data = self._recv_all(self.socket, 4)
        if not length_data:
            return None, None

        ciphertext_len = struct.unpack('>I', length_data)[0]
        ciphertext = self._recv_all(self.socket, ciphertext_len)

        
        # Create nonce for decryption
        nonce = struct.pack('>Q', counter) + b'snc0'
        
        try:
            plaintext = self.aead.decrypt(nonce, ciphertext, None)
            self.recv_counter = counter # Update counter only on successful decryption
            
            message_type = MessageType(struct.unpack('>B', plaintext[0:1])[0])
            message = plaintext[1:].decode('utf-8')
            return message_type, message
            
        except InvalidTag:
            print("Message authentication failed! Potential tampering.")
            raise Exception("Invalid tag")

    def _recv_all(self, sock, size):
        """Helper to receive exactly size bytes"""
        data = b''
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {} # client_id -> SecureClientHandler
        self.running = False
        self.client_id_counter = 0
        
        # Initialize the persistence layer
        self.persistence = ChatPersistence()
        
        # Load long-term server keys
        try:
            with open(SERVER_X25519_KEY_PATH, "rb") as f:
                self.server_static_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            self.server_static_public_key = self.server_static_private_key.public_key()
            
            with open(SERVER_ED25519_KEY_PATH, "rb") as f:
                self.server_signing_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
        except FileNotFoundError:
            print("FATAL: Server keys not found. Did you run generate_keys.py?")
            sys.exit(1)

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"Secure server with persistence started on {self.host}:{self.port}")
            
            # Try to restore from backup if available
            self.persistence.restore_from_backup()
            
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Create a backup thread
            backup_thread = threading.Thread(target=self.backup_worker)
            backup_thread.daemon = True
            backup_thread.start()
            
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            print(f"Error starting server: {e}")
        finally:
            self.stop()

    def backup_worker(self):
        """Worker thread to handle periodic backups"""
        while self.running:
            time.sleep(300)  # Check every 5 minutes
            if self.running:
                self.persistence.create_backup()

    def accept_connections(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                self.server_socket.settimeout(None)
                
                self.client_id_counter += 1
                client_id = f"client-{self.client_id_counter}"
                
                handler = SecureClientHandler(client_socket, client_address, self.server_signing_key, self.server_static_public_key, self.persistence)
                
                if not handler.perform_handshake():
                    client_socket.close()
                    continue
                
                self.clients[client_id] = handler
                
                client_thread = threading.Thread(target=self.handle_client, args=(client_id,))
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")

    def handle_client(self, client_id):
        handler = self.clients[client_id]
        try:
            while self.running:
                message_type, message = handler.recv_message()
                if not message_type:
                    break
                
                if message_type == MessageType.JOIN:
                    handler.username = message

                    #Send recent chat history only to this client
                    recent = self.persistence.get_recent_messages()
                    for msg in recent:
                        handler.send_message(
                            msg["type"],
                            f'{msg["username"]}: {msg["message"]}'
                        )
                    
                    # Log the join message
                    self.persistence.log_message(MessageType.SYSTEM, "System", f"{message} has joined the chat")
                    self.broadcast_message(MessageType.SYSTEM, f"{message} has joined the chat", exclude_client=client_id)
                    
                
                elif message_type == MessageType.CHAT:
                    # Log the chat message
                    self.persistence.log_message(MessageType.CHAT, handler.username, message)
                    self.broadcast_message(MessageType.CHAT, f"{handler.username}: {message}")
                elif message_type == MessageType.LEAVE:
                    break
                    
        except Exception as e:
            print(f"Error handling client {client_id}: {e}")
        finally:
            username = handler.username or "Unknown"
            # Log the leave message
            self.persistence.log_message(MessageType.SYSTEM, "System", f"{username} has left the chat")
            self.remove_client(client_id)
            self.broadcast_message(MessageType.SYSTEM, f"{username} has left the chat")

    def broadcast_message(self, message_type, message, exclude_client=None):
        for client_id, handler in self.clients.items():
            if client_id != exclude_client:
                try:
                    handler.send_message(message_type, message)
                    print(f"[DEBUG] Broadcasting to: {list(self.clients.keys())}")
                except Exception as e:
                    print(f"Error broadcasting to {client_id}: {e}")
                    self.remove_client(client_id)

    def remove_client(self, client_id):
        if client_id in self.clients:
            try:
                self.clients[client_id].socket.close()
            except: pass
            del self.clients[client_id]
            print(f"Client {client_id} disconnected")

    def stop(self):
        print("\nInitiating server shutdown...")
        self.running = False
        
        # Create a final backup before shutting down
        self.persistence.create_backup()
        
        if self.server_socket:
            self.server_socket.close()
        for client_id in list(self.clients.keys()):
            self.remove_client(client_id)
        print("Server stopped")

def signal_handler(sig, frame):
    print(f"\nReceived signal {sig}")
    server.stop()
    sys.exit(0)

if __name__ == "__main__":
    server = SecureChatServer()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    server.start()