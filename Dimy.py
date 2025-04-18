#################################### IMPORTS ###################################
# Front-end program code
import threading
import time
import secrets
import socket
import sys
from Crypto.Protocol.SecretSharing import Shamir

################################################################################
################################### CONSTANTS ##################################

# Server details
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 55000
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

# UDP port to listen to
# Our Clients and Server will both be running on the same machine,
# So the IP will be the same
UDP_IP = SERVER_IP
UDP_PORT = 50001
UDP_ADDR = (UDP_IP, UDP_PORT)

# List of allowed times that `t` can take
ALLOWED_TIME = [15, 18, 21, 24, 27, 30]

################################################################################
################################# ID GENERATORS ################################

# Generates the Ephemeral ID (EphID)
def gen_ephid():
    g = 5   # Generator
    x_At = secrets.token_bytes(32)
    g_bytes = g.to_bytes(32, byteorder='big')  
    eph_id = bytes(a ^ b for a, b in zip(x_At, g_bytes))
    print("[EphID Generation]", eph_id.hex())
    return eph_id

# Generates the Encounter ID (EncID) using the reconstructed EphID
# Applied through Diffie-Hellman key exchange
# TODO: Use Diffie-Hellman key exchange to 
def gen_encid():
    return

################################################################################
############################ CRYPTOGRAPHIC FUNCTIONS ###########################

# Creates 
def split_secret(secret, k, n):
    if len(secret) != 32:
        raise ValueError("[Error] Secret must be 32 bytes long.")
    
    half1 = secret[:16]
    half2 = secret[16:]
    
    int1 = int.from_bytes(half1, byteorder='big')
    int2 = int.from_bytes(half2, byteorder='big')
    
    shares1 = Shamir.split(k, n, int1)  # List of (index, share) tuples
    shares2 = Shamir.split(k, n, int2)  # List of (index, share) tuples
    
    print(f"\n[Shamir Share Generation] {n} shares for each half:")
    for i, ((idx1, s1), (idx2, s2)) in enumerate(zip(shares1, shares2)):
        print(f"[Share {i+1} (Half1)]: {s1.hex()}")
        print(f"[Share {i+1} (Half2)]: {s2.hex()}")
    
    # Extract just the shares (drop the indices)
    combined_shares = [s1 for (idx, s1) in shares1] + [s2 for (idx, s2) in shares2]
    return combined_shares

################################################################################
############################# UDP AND TCP FUNCTIONS ############################

# Broadcast the k out of n shares
# Used inside a new thread
def broadcast_shares(sock, share_split):
    for i, share in enumerate(share_split):
        rand_num = secrets.SystemRandom().uniform(0, 1)
        if rand_num < 0.5:
            print (f"[Share Dropped] Share {i+1}: {share.hex()}")
        else:
            sock.sendto(share, UDP_ADDR)
            print(f"[Broadcasting] Share {i+1}: {share.hex()}")
        # Wait for 3 seconds before sending the next share
        time.sleep(3)
    print("[Broadcast End] All shares have been broadcasted.")

# TODO: For server communications
def upload_contacts():
    # # Connect to server
    # conn, addr = server.accept()
    # # Create a new thread to handle actions with the newly accepted client
    # thread = threading.Thread(target=handleClient, args=(conn, addr))
    # thread.start()
    # print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}.")
    return

################################################################################
##################################### MAIN #####################################

# Main function that deals with general client functionality
def main():
    # Check for valid input
    try:
        t = int(sys.argv[1])
        k = int(sys.argv[2])
        n = int(sys.argv[3])
    except:
        print("Invalid number of inputs")
        print(f"Usage: {sys.argv[0]} t k n")
        sys.exit(1)

    # Check valid t input
    if t not in ALLOWED_TIME:
        print("Invalid time input.")
        print("Valid time values: 15,18,21,24,27,30")
        print("Exiting")
        sys.exit(1)

    # Check valid k and n inputs 
    if k < 3 or n < 5 or k > n:
        print("Invalid k and n input.")
        print("Valid values: k >= 3, n >= 5, k < n")
        print("Exiting")
        sys.exit(1)

    # Make sure that t > 3*n
    if t <= 3*n:
        print("Invalid time input: Time has to be larger than 3*n")
        print("Exiting")
        sys.exit(1)

    # print(f"[CLIENT {UDP_PORT}] Client starting...")
        
    # Enable the UDP socket for client
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Reuse port 50001 for listening
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Set the socket to broadcast
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    client.bind(('', UDP_PORT))
    print(f"[BROADCASTING] Client is broadcasting through port {UDP_PORT}.")

    # Client starts to listen for other broadcasts
    # client.listen()

    # First generate the EphId and the Shamir secret shares 
    ephid = gen_ephid()
    shares = split_secret(ephid, k, n)

    # Set the expected times for EphID generation
    initial_time = time.time()
    expected_time = initial_time + t
    # Start a new thread to broadcast our split shares
    broadcast_thread = threading.Thread(target=broadcast_shares, args=(client, shares))
    # Set the thread as a daemon so that it shuts down when the user wants to stop the program
    broadcast_thread.daemon = True
    broadcast_thread.start()

    try:
        while True:
            # Check that our current time has passed t seconds
            # Generate the new EphID, split the shares
            # Then broadcast it through a new thread 
            if time.time() > expected_time:
                ephid = gen_ephid()
                shares = split_secret(ephid, k, n)
                initial_time = time.time()
                expected_time = initial_time + t
                broadcast_thread.start()
                # broadcast_shares(client, shares)

            # Receive messages from any broadcasted shares


    except KeyboardInterrupt:
        print("[Exit] Attempting to close threads...")
        # broadcast_thread.join()
        print("[Shut Down] Client is quitting...")
    
    client.close()
    # except:
    #     print("Unknown Error Encountered, shutting down client")
    # 

################################################################################
#################################### START #####################################

if __name__ == "__main__":
    main()
