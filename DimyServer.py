# Backend server code
import socket
import time
import threading
from auxiliary import get_elapsed_time

IP = socket.gethostbyname(socket.gethostname())
PORT = 55000
ADDR = (IP, PORT)
# Size representing 100KB + 4 bytes from string identification
SIZE = 102404
FORMAT = "utf-8"
DISCONNECT_MSG = "!DISCONNECTING"

# Datastores for CBFs and QBFs
cbf_list = []
qbf_list = []

# Compares the given QBF with the CBFs to see if there has been any issues
def bloom_match(qbf, cbf):
    """Bitwise check: returns True if any 1-bit overlaps."""
    # return any(b1 & b2 for b1, b2 in zip(qbf_bytes, cbf_bytes))
    return qbf & cbf
    
def handleClient(start_time, conn, addr):
    print(f"{get_elapsed_time(start_time)}s [NEW CONNECTION] {addr} connected.")
    try:
        data = conn.recv(SIZE)
        if not data:
            return

        if data.startswith(b'CBF'):
            cbf_data = data[4:].from_bytes(102400, 'big')
            cbf_list.append(cbf_data)
            print(f"{get_elapsed_time(start_time)}s [{addr}] \
Uploaded CBF with ({len(cbf_data)} bytes)")

            conn.sendall(b"Upload confirmed")

        elif data.startswith(b'QBF') :
            qbf_data = data[4:].from_bytes(102400, 'big')
            print(f"{get_elapsed_time(start_time)}s [{addr}] Received QBF \
({len(qbf_data)} bytes). Sample bits: {qbf_data[:8].hex()}...")

            result = "Not Matched"
            for cbf in cbf_list:
                if bloom_match(qbf_data, cbf):
                    result = "Matched"
                    break

            print(f"{get_elapsed_time(start_time)}s [{addr}] QBF checked -> {result}")
            conn.sendall(result.encode())

        else:
            conn.sendall(b"Invalid request")

    # except Exception as e:
    #     print(f"[ERROR] {e}")
    finally:
        conn.close()

def main():
    start_time = time.time()
    print(f"{get_elapsed_time(start_time)}s [STARTING] Server is starting up...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    
    server.listen()
    print(f"{get_elapsed_time(start_time)}s [LISTENING] \
Server is listening on {IP}:{PORT}.")

    try:
        while True:
            # Accept a client
            conn, addr = server.accept()
            # Create a new thread to handle actions with the newly accepted client
            thread = threading.Thread(target=handleClient, args=(start_time, conn, addr))
            thread.start()
            print(f"{get_elapsed_time(start_time)}s [ACTIVE CONNECTIONS] \
{threading.active_count() - 1}.")
    except KeyboardInterrupt:
        print(f"{get_elapsed_time(start_time)}s [Shutting Down] \
Server is shutting down...")
    
    server.close()

if __name__ == "__main__":
    main()
