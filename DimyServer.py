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

# Compares the given QBF with the CBFs to see if there has been any issues
def compareBloomFilters():
    return


def handleClient(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        # Receive messages from the connection and decode it using our specified format
        msg = conn.recv(SIZE).decode(FORMAT)
        # Exit the while loop when we receive a message to disconnect
        if msg == DISCONNECT_MSG:
            connected = False
        
        print(f"[{addr}] {msg}")
        # Create a new message, encode it in utf-8 and then send it.
        msg = f"Message receive: {msg}"
        conn.send(msg.encode(FORMAT))

    # Finally close the connection
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
