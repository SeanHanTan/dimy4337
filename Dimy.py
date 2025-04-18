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
UDP_ADDR = (UDP_IP, UDP_PORT)

ALLOWED_TIME = [15, 18, 21, 24, 27, 30]


# Generator
g = 5

def gen_ephid(current_time):
    if current_time not in ALLOWED_TIME:
        print("Invalid time... Exiting")
        sys.exit()
    x_At = secrets.token_bytes(32)
    g_bytes = g.to_bytes(32, byteorder='big')  
    eph_id = bytes(a ^ b for a, b in zip(x_At, g_bytes))
    print("eph_id:", eph_id.hex())
    return eph_id

def split_secret(secret, k, n):
    if len(secret) != 32:
        raise ValueError("Secret must be 32 bytes long.")
    
    half1 = secret[:16]
    half2 = secret[16:]
    
    int1 = int.from_bytes(half1, byteorder='big')
    int2 = int.from_bytes(half2, byteorder='big')
    
    shares1 = Shamir.split(k, n, int1)  # List of (index, share) tuples
    shares2 = Shamir.split(k, n, int2)  # List of (index, share) tuples
    
    print(f"\nGenerated {n} shares for each half:")
    for i, ((idx1, s1), (idx2, s2)) in enumerate(zip(shares1, shares2)):
        print(f"Share {i+1} (Half1): {s1.hex()}")
        print(f"Share {i+1} (Half2): {s2.hex()}")
    
    # Extract just the shares (drop the indices)
    combined_shares = [s1 for (idx, s1) in shares1] + [s2 for (idx, s2) in shares2]
    return combined_shares

def broadcast_shares(sock, share_split):
    for i, share in enumerate(share_split):
        # TODO: Uncomment after done
        sock.sendto(share, UDP_ADDR)
        print()
        # print(f"Broadcasting share {i+1}: {share.hex()}")
        # Wait for 3 seconds before sending the next share
    print("All shares broadcasted successfully.")

# Main function that deals with general client functionality
def main():
    t = int(sys.argv[1])
    k = int(sys.argv[2])
    n = int(sys.argv[3])

    if t not in ALLOWED_TIME:
        print("Invalid time... Exiting")
        sys.exit(1)

    if k < 3 or n < 5 or k > n:
        print("[Invalid k and n values] Valid values: k >= 3, n >= 5, k < n ... Exiting")
        sys.exit(1)

    print(f"[CLIENT {UDP_PORT}] Client starting...")
        
    # Enable the UDP socket for client
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Reuse port 50001 for listening
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Set the socket to broadcast
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    client.bind(('', UDP_PORT))

    # Client starts to listen 
    # client.listen()
    # print(f"[BROADCASTING] Client is broadcasting through port {UDP_PORT}.")

    # First generate and 
    ephid = gen_ephid(t)
    shares = split_secret(ephid, k, n)

    curr_time = time.time()
    try:
        while True:
            # # Connect to server
            # conn, addr = server.accept()
            # # Create a new thread to handle actions with the newly accepted client
            # thread = threading.Thread(target=handleClient, args=(conn, addr))
            # thread.start()
            # print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}.")
            
            broadcast_shares(client, shares)
            # time.sleep(t)
    except KeyboardInterrupt:
        print("Quitting...")
    
    client.close()
    # except:
    #     print("Unknown Error Encountered, shutting down client")
    #     if client:
    #       
        


if __name__ == "__main__":
    main()
