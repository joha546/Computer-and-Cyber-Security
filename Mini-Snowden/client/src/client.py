import socket
import struct
import threading
import sys
from enum import Enum

class MessageType(Enum):
    CHAT = 1
    SYSTEM = 2
    JOIN = 3
    LEAVE = 4

class ChatClient:
    def __init__(self, host='chat-server', port=9999):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.username = None

    def connect(self, username):
        """Connect to the chat server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.username = username
            self.running = True
            
            # Send join message
            self.send_message(MessageType.JOIN, username)
            
            # Start a thread to receive messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            print(f"Connected to chat server as {username}")
            return True
            
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False

    def send_message(self, message_type, message):
        """Send a message to the server"""
        if not self.socket or not self.running:
            print("Not connected to server")
            return False
            
        try:
            message_bytes = message.encode('utf-8')
            
            # Create the message: length (4 bytes) + type (1 byte) + content
            message_data = struct.pack('>I', len(message_bytes)) + \
                           struct.pack('>B', message_type.value) + \
                           message_bytes
            
            self.socket.sendall(message_data)
            return True
            
        except Exception as e:
            print(f"Error sending message: {e}")
            self.running = False
            return False

    def receive_messages(self):
        """Receive messages from the server"""
        while self.running:
            try:
                # Read message length (4 bytes)
                length_data = self.recv_all(4)
                if not length_data:
                    break
                    
                message_length = struct.unpack('>I', length_data)[0]
                
                # Read message type (1 byte)
                type_data = self.recv_all(1)
                if not type_data:
                    break
                    
                message_type = MessageType(struct.unpack('>B', type_data)[0])
                
                # Read message content
                message_data = self.recv_all(message_length)
                if not message_data:
                    break
                
                message = message_data.decode('utf-8')
                
                # Print the message with appropriate formatting
                if message_type == MessageType.SYSTEM:
                    print(f"\n[SYSTEM] {message}")
                elif message_type == MessageType.CHAT:
                    print(f"\n{message}")
                
                # Show prompt again
                print("> ", end="", flush=True)
                
            except Exception as e:
                print(f"\nError receiving message: {e}")
                break
        
        self.running = False

    def recv_all(self, size):
        """Receive exactly size bytes from socket"""
        data = b''
        while len(data) < size:
            packet = self.socket.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data

    def disconnect(self):
        """Disconnect from the server"""
        if self.running:
            self.send_message(MessageType.LEAVE, "")
            self.running = False
            
        if self.socket:
            self.socket.close()
            
        print("Disconnected from chat server")

    def run(self):
        """Run the client interface"""
        # Get username
        while not self.username:
            username = input("Enter your username: ").strip()
            if username:
                if self.connect(username):
                    break
            else:
                print("Username cannot be empty")
        
        # Main chat loop
        try:
            while self.running:
                message = input("> ")
                if not message:
                    continue
                    
                if message.lower() in ('quit', 'exit', '/q'):
                    break
                    
                self.send_message(MessageType.CHAT, message)
                
        except KeyboardInterrupt:
            pass
        finally:
            self.disconnect()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = 'chat-server'
        
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = 9999
        
    client = ChatClient(host, port)
    client.run()