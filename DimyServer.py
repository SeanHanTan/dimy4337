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
# qbf_list = []

# Compares the given QBF with the CBFs to see if there has been any issues
def bloom_match(start_time, qbf, cbf):
    # # Convert both QBF and CBF back to an array
    # qbf_array = [1 if digit=='1' else 0 for digit in bin(qbf)[2:]]
    # cbf_array = [1 if digit=='1' else 0 for digit in bin(cbf)[2:]]
    """Bitwise check: returns True if there are 3 or more bits overlapping."""

    t = bin(qbf & cbf).count('1')

    print(f"{get_elapsed_time(start_time)}s [SEGMENT 10-C] \
QBF & CBF matching found {t} intersections")

    return t >= 3
    # return any(b1 & b2 for b1, b2 in zip(qbf_bytes, cbf_bytes))    
    
def handleClient(start_time, conn, addr, cbf_lock):
    print(f"{get_elapsed_time(start_time)}s [NEW CONNECTION] {addr} connected.")
    try:
        data = conn.recv(SIZE)
        if not data:
            return

        if data.startswith(b'CBF'):
            cbf_data = data[4:]
            cbf_int = int.from_bytes(cbf_data, 'big')
            with cbf_lock:
                cbf_list.append(cbf_int)
            print(f"{get_elapsed_time(start_time)}s [{addr}] \
Uploaded CBF with ({len(cbf_data)} bytes)")

            conn.sendall(b"Upload confirmed")

        elif data.startswith(b'QBF') :
            qbf_data = data[4:]
            qbf_int = int.from_bytes(qbf_data, 'big')
            print(f"{get_elapsed_time(start_time)}s [{addr}] Received QBF \
({len(qbf_data)} bytes). Sample bits: {qbf_data[:8].hex()}...")

            result = "No Match"
            with cbf_lock:
                for cbf in cbf_list:
                    if bloom_match(start_time, qbf_int, cbf):
                        result = "Matched"
                        break

            print(f"{get_elapsed_time(start_time)}s [{addr}] QBF checked -> {result}")
            conn.sendall(result.encode())

        else:
            conn.sendall(b"Invalid request")

    except Exception as e:
        print(f"[ERROR] {e}")
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

    # Locks
    cbf_lock = threading.Lock()
    # qbf_lock = threading.Lock()

    try:
        while True:
            # Accept a client
            conn, addr = server.accept()
            # Create a new thread to handle actions with the newly accepted client
            thread = threading.Thread(target=handleClient, args=(start_time, conn, addr, \
                                        cbf_lock))
            thread.start()
            print(f"{get_elapsed_time(start_time)}s [ACTIVE CONNECTIONS] \
{threading.active_count() - 1}.")
    except KeyboardInterrupt:
        print(f"{get_elapsed_time(start_time)}s [Shutting Down] \
Server is shutting down...")
    
    server.close()

if __name__ == "__main__":
    main()
