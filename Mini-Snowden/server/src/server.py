import socket
import struct
import threading
import time
import signal
import sys
from enum import Enum


class MessageType(Enum):
    CHAT = 1
    SYSTEM = 2
    JOIN = 3
    LEAVE = 4

class ChatServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.running = False
        self.client_id_counter = 0

    def start(self):
        """Start the chat server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print(f"Server started on {self.host}:{self.port}")

            # Start accepting connections in a seperate thread
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()

            # Keep the main thread alive
            while self.running:
                time.sleep(1)

        except Exception as e:
            print(f"Error starting server: {e}")
        finally:
            self.stop()
    
    def accept_connections(self):
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.client_id_counter += 1
                client_id = f"client-{self.client_id_counter}"

                print(f"New connection from {client_address[0]}:{client_address[1]} assigned {client_id}")

                # Store client info
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': client_address,
                    'username': None
                }

                # Start a thread to handle this client
                client_thread = threading.Thread(
                    target = self.handle_client,
                    args = (client_id,)
                )
                client_thread.daemon = True
                client_thread.start()
            
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
    

    def handle_client(self, client_id):
        """Handle messages from a client"""
        client = self.clients[client_id]
        client_socket = client['socket']

        try:
            while self.running:
                # Read message length (4bytes)
                length_data = self.recv_all(client_socket, 4)
                if not length_data:
                    break
                    
                message_length = struct.unpack('>I', length_data)[0]

                # Read message type (1 byte)
                type_data = self.recv_all(client_socket, 1)
                if not type_data:
                    break

                message_type = MessageType(struct.unpack('>B', type_data)[0])

                # Read message content
                message_data = self.recv_all(client_socket, message_length)
                if not message_data:
                    break
                
                message = message_data.decode('utf-8')

                # Process the message based on it's type
                if message_type == MessageType.JOIN:
                    client['username'] = message
                    self.broadcast_message(
                        MessageType.SYSTEM,
                        f"{message} has joined the chat"
                    )
                elif message_type == MessageType.CHAT:
                    client['username'] = message
                    self.broadcast_message(
                        MessageType.SYSTEM,
                        f"{client['username']}: {message}"
                    )
                elif message_type == MessageType.LEAVE:
                    break
            
        except Exception as e:
            print(f"Error handling client {client_id}: {e}")
        
        finally:
            # clean up when client disconnects
            username = client['username'] or "Unknown"
            self.remove_client(client_id)
            self.broadcast_message(
                MessageType.SYSTEM,
                f"{username} has left the chat"
            )


    def recv_all(self, sock, size):
        """Receive exactly size bytes from socket"""
        data = b''
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return None
            data +=packet
        return data
    
    def broadcast_message(self, message_type, message):
        """Send a message to all connected clients"""
        message_bytes = message.encode('utf-8')

        # Create the message: length (4bytes) + type (1 byte) + content
        message_data = struct.pack('>I', len(message_bytes)) + struct.pack('>B', message_type.value) + message_bytes

        # Send to all clients
        disconnected_clients = []
        for client_id, client in self.clients.items():
            try:
                client['socket'].sendall(message_data)
            except Exception as e:
                print(f"Error sending to client {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # Remove disconnected clients
        for client_id in disconnected_clients:
            self.remove_client(client_id)

    def remove_client(self, client_id):
        """Remove a client from the server"""
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            del self.clients[client_id]
            print(f"Client {client_id} disconnected")


    def stop(self):
        """Stop the server"""
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        for client_id in list(self.clients.keys()):
            self.remove_client(client_id)
        
        print("Server stopped")

def signal_handler(sig, frame):
    print("\nShutting down server...")
    server.stop()
    sys.exit(0)

if __name__ == "__main__":
    server = ChatServer()
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    server.start()