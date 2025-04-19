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
RECV_IP = SERVER_IP
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
        sys.exit(1)

    # Check valid k and n inputs 
    if k < 3 or n < 5 or k > n:
        print("Invalid k and n input.")
        print("Valid values: k >= 3, n >= 5, k < n")
        sys.exit(1)

    # Make sure that t > 3*n
    if t <= 3*n:
        print("Invalid time input: Time has to be larger than 3*n")
        sys.exit(1)
    
    return t, k, n

################################################################################
##################################### MAIN #####################################

# Main function that deals with general client functionality
def main():
    t, k, n = check_args()

    start_time = time.time()

    # Enable the UDP socket for receiver
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Reuse port 50001 for listening
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    recv_sock.bind(('', RECV_PORT))
    # Set the socket to broadcast
    broad_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broad_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print(f"{get_elapsed_time(start_time)}s [CLIENT] \
Broadcasting to port: {recv_sock.getsockname()[1]}.")

    client_port = check_port(broad_sock, start_time)
    print(f"{get_elapsed_time(start_time)}s [CLIENT] Using port: {client_port}")

    # First generate the EphId and the Shamir secret shares 
    ephid, eph_hash = gen_ephid(start_time)
    shares = split_secret(ephid, k, n, start_time)

    # Set the expected times for EphID generation
    initial_time = time.time()
    expected_time = initial_time + t
    # Start a new thread to broadcast our split shares
    broadcast_thread = threading.Thread(target=broadcast_shares, \
                                        args=(broad_sock, shares, eph_hash, start_time))

    # Set the thread as a daemon so that it shuts down 
    # when the user wants to stop the program.
    # We aren't reading or writing to files,
    # and the daemons are only sending data to other clients.
    # Other clients will drop EphIDs after a certain time
    # and if they don't have enough shares.
    broadcast_thread.daemon = True
    broadcast_thread.start()

    # Receive broadcasted messages from the receiver socket 
    receiver_thread = threading.Thread(target=receive_shares, \
                                       args=(start_time, recv_sock, client_port, t, k, n))
    receiver_thread.daemon = True
    receiver_thread.start()

    try:
        while True:
            # Check that our current time has passed t seconds
            # Generate the new EphID and split the shares.
            # Then broadcast the shares through a new thread
            if time.time() > expected_time:
                ephid, eph_hash = gen_ephid(start_time)
                shares = split_secret(ephid, k, n, start_time)
                initial_time = time.time()
                expected_time = initial_time + t
                # Start a new thread to broadcast our split shares
                broadcast_thread = threading.Thread(target=broadcast_shares, \
                                                    args=(broad_sock, shares, eph_hash, start_time))
                broadcast_thread.daemon = True
                broadcast_thread.start()

            # receive_shares(recv_sock, client_port)

    except KeyboardInterrupt:
        print(f"{get_elapsed_time(start_time)}s [EXIT THREADS] \
Forcefully closing threads...")
        # broadcast_thread.join()
        # receiver_thread.join()
        print(f"{get_elapsed_time(start_time)}s [SHUT DOWN] \
Client is quitting...")

    broad_sock.close()
    recv_sock.close()

################################################################################
#################################### START #####################################

if __name__ == "__main__":
    main()
