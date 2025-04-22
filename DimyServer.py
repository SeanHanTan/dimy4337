# Backend server code
import socket
import threading

IP = socket.gethostbyname(socket.gethostname())
PORT = 55000
ADDR = (IP, PORT)
# Size representing 100KB
SIZE = 100000
FORMAT = "utf-8"
DISCONNECT_MSG = "!DISCONNECTING"

# Datastores for CBFs and QBFs
CBF={}
QBF={}
CBF_LIST = []

def bloom_match(qbf_bytes, cbf_bytes):
    """Bitwise check: returns True if any 1-bit overlaps."""
    return any(b1 & b2 for b1, b2 in zip(qbf_bytes, cbf_bytes))
    
# Compares the given QBF with the CBFs to see if there has been any issues
def compareBloomFilters():
    return


def handleClient(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        data = conn.recv(SIZE)
        if not data:
            return

        if data.startswith(b'CBF:'):
            cbf_data = data[4:]
            CBF_LIST.append(cbf_data)
            print(f"[{addr}] Uploaded CBF ({len(cbf_data)} bytes)")

            conn.sendall(b"Upload confirmed")

        elif data.startswith(b'QBF:'):
            qbf_data = data[4:]
            print(f"[{addr}] Received QBF ({len(qbf_data)} bytes). Sample bits: {qbf_data[:8].hex()}...")

            result = "not matched"
            for cbf in CBF_LIST:
                if bloom_match(qbf_data, cbf):
                    result = "matched"
                    break

            print(f"[{addr}] QBF checked -> {result}")
            conn.sendall(result.encode())

        else:
            conn.sendall(b"Invalid request")

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()



def main():
    print("[STARTING] Server is starting up...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}.")

    try:
        while True:
            # Accept a client
            conn, addr = server.accept()
            # Create a new thread to handle actions with the newly accepted client
            thread = threading.Thread(target=handleClient, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}.")
    except KeyboardInterrupt:
        print("[Shutting Down] Server is shutting down...")
    
    server.close()

if __name__ == "__main__":
    main()
