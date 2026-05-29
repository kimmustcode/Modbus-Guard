import socket
import sys

def start_plc():
    """
    A persistent Dummy Modbus PLC that stays open for multiple connections.
    Listens on port 502 and accepts all incoming Modbus TCP traffic.
    """
    PORT = 502
    
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow the port to be reused immediately after restart
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind to all interfaces on port 502
            s.bind(('0.0.0.0', PORT))
            s.listen(5)
            print(f"[*] Dummy PLC is ACTIVE and listening on port {PORT}...")
            print("[*] Press Ctrl+C to stop.")
            
            while True:
                # Wait for a connection
                conn, addr = s.accept()
                with conn:
                    # Receive the data (MBAP + PDU)
                    data = conn.recv(1024)
                    if data:
                        # Optional: Print a dot to show activity without flooding the terminal
                        sys.stdout.write(".")
                        sys.stdout.flush()
                        
                        # In a real PLC, we would send a Modbus response here.
                        # For a sniffer test, just closing the connection is fine.
        
        except PermissionError:
            print(f"[!] Error: Port {PORT} requires root privileges. Run with 'sudo'.")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    try:
        start_plc()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Dummy PLC.")
