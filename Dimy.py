# Front-end program code
import sys
import secrets
import time
from Crypto.Protocol.SecretSharing import Shamir
import socket

# Server details
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 55000
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

# UDP port to listen to
# Our Client and Server are both running on the same machine,
# So the IP will be the same
UDP_IP = SERVER_IP
UDP_PORT = 50001




allowed_time = [15, 18, 21, 24, 27, 30]
time_t=int(sys.argv[1])
k=int(sys.argv[2])
n=int(sys.argv[3])
if k <3 and n<5 and k>n:
    print("Invalid values for k and n... Exiting")
    sys.exit()

# Generator
g = 5  

def ephid(current_time):
    if current_time not in allowed_time:
        print("Invalid time... Exiting")
        sys.exit()
    x_At = secrets.token_bytes(32)
    g_bytes = g.to_bytes(32, byteorder='big')  
    eph_id = bytes(a ^ b for a, b in zip(x_At, g_bytes))
    print("eph_id:", eph_id.hex())
    return eph_id

def share_secret(secret, k, n):
    # secrets is being splited into n shares and being reconstructed using k shares
    share_split=Shamir.split(k,n,secret) 
    print("Secret shares:")
    for i,share in enumerate(share_split):
        print(f"Share {i+1}: {share.hex()}")
    return share_split

def broadcast_shares(sock, share_split):
    for i, share in enumerate(share_split):
        sock.sendto(share, (UDP_IP, UDP_PORT))
        print(f"Broadcasting share {i+1}: {share.hex()}")
        # Wait for 3 seconds before sending the next share
        time.sleep(3)
    print("All shares broadcasted successfully.")
    
for current_time in allowed_time:
    ephid(current_time)
    if time_t<15 or time_t>30:
        print("Invalid time... Exiting")
        sys.exit()
    share_secret(ephid(current_time), k, n)
    time.sleep(time_t) 
    

def main():
    print("[CLIENT {PORT}] Client starting...")
        
    # Enable broadcasting with UDP
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    client.bind(('', 50001))

    client.listen()
    print(f"[BROADCASTING] Client is broadcasting through port {UDP_PORT}.")

    while True:
        # # Connect to server
        # conn, addr = server.accept()
        # # Create a new thread to handle actions with the newly accepted client
        # thread = threading.Thread(target=handleClient, args=(conn, addr))
        # thread.start()
        # print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}.")
        


if __name__ == "__main__":
    main()
