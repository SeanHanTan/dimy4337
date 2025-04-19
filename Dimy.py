#################################### IMPORTS ###################################
# Front-end program code

import threading
import time
import socket
import sys
from auxiliary import *

################################################################################
################################### CONSTANTS ##################################

# Server details
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 55000
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

# UDP port to send infromation.
# Our Clients and Server will both be running on the same machine,
# So the IP will be the same
# UDP_IP = SERVER_IP
# UDP_PORT = 5001
# UDP_ADDR = (UDP_IP, UDP_PORT)

# Details for Receiver
# RECV_IP = SERVER_IP
RECV_IP = '0.0.0.0'
RECV_PORT = 50001
RECV_ADDR = (RECV_IP, RECV_PORT)

# List of allowed times that `t` can take
ALLOWED_TIME = [15, 18, 21, 24, 27, 30]

################################## DATA STORES #################################
################################################################################

# Holds a dictionary of collected EphIDs
ephids_dict = {}

# Holds a dictionary of EncIDs
encids_dict = {}

# Holds the past 21 dbfs
dbf_dict = {}

################################################################################
############################### Program Argument ###############################

# Check the validity of sys args
# Returns `t`, `k` & `n`, the values for time, minimum shares and `n` amount of shares
def check_args():
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
    
    return t, k, n

################################################################################
##################################### MAIN #####################################

# Main function that deals with general client functionality
def main():
    t, k, n = check_args()

    # print(f"[CLIENT {UDP_PORT}] Client starting...")
        
    # Enable the UDP socket for receiver
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Reuse port 50001 for listening
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    recv_sock.bind(('', RECV_PORT))
    # Set the socket to broadcast
    broad_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broad_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print(f"[CLIENT] Broadcasting to port: {recv_sock.getsockname()[1]}.")

    client_port = check_port(broad_sock, recv_sock)
    print(f"[CLIENT] Using port: {client_port}")

    # First generate the EphId and the Shamir secret shares 
    ephid, eph_hash = gen_ephid()
    shares = split_secret(ephid, k, n)

    # Set the expected times for EphID generation
    initial_time = time.time()
    expected_time = initial_time + t
    # Start a new thread to broadcast our split shares
    broadcast_thread = threading.Thread(target=broadcast_shares, args=(broad_sock, shares, eph_hash))
    # Set the thread as a daemon so that it shuts down when the user wants to stop the program
    broadcast_thread.daemon = True
    broadcast_thread.start()

    try:
        while True:
            # Check that our current time has passed t seconds
            # Generate the new EphID and split the shares.
            # Then broadcast the shares through a new thread
            if time.time() > expected_time:
                ephid, eph_hash = gen_ephid()
                shares = split_secret(ephid, k, n)
                initial_time = time.time()
                expected_time = initial_time + t
                # Start a new thread to broadcast our split shares
                broadcast_thread = threading.Thread(target=broadcast_shares, args=(broad_sock, shares, eph_hash))
                # Set the thread as a daemon so that it shuts down when the user wants to stop the program
                broadcast_thread.daemon = True
                broadcast_thread.start()

            # Receive broadcasted messages from the receiver socket 
            receive_shares(recv_sock, client_port)

    except KeyboardInterrupt:
        print("[EXIT] Attempting to close threads...")
        # broadcast_thread.join()
        print("[SHUT DOWN] Client is quitting...")
    
    broad_sock.close()
    recv_sock.close()

################################################################################
#################################### START #####################################

if __name__ == "__main__":
    main()
