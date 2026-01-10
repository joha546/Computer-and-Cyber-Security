#!/usr/bin/env python3
import socket
import sys

def test_connectivity(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((host, port))
            if result == 0:
                print(f"Successfully connected to {host}:{port}")
                return True
            else:
                print(f"Failed to connect to {host}:{port}, error code: {result}")
                return False
    except Exception as e:
        print(f"Error connecting to {host}:{port}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 test_environment.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    success = test_connectivity(host, port)
    sys.exit(0 if success else 1)
