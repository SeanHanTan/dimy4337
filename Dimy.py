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

# Details for Receiver
# UDP port to send infromation.
# Our Clients and Server will both be running on the same machine,
# So the IP will be the same
RECV_IP = SERVER_IP
RECV_PORT = 50001
RECV_ADDR = (RECV_IP, RECV_PORT)

# List of allowed times that `t` can take
ALLOWED_TIME = [15, 18, 21, 24, 27, 30]

################################################################################
################################## DATA STORES #################################

'''
    Holds a dictionary of collected EphIDs
    Structure should look like
    {
        int<port_number>: {
            'hash':   bytes<hash>,
            'shares': [( index , bytes<share> )],
            'reconstructed': bytes<ephid>
        }
    }
'''
ephids_dict = {}

# # Holds a dictionary of EncIDs
# # Structure:
# # {
# #   int<port_number>: {
# #       'encid': bytes<encid>
# #       'time': int<time since last epoch in seconds>
# #   }
# #   
# # }
# #

# # Structure:
# # {
# #   bytes<encid>: int<time since last epoch in seconds>
# # }
# #
# encids_dict = {}

"""
    Holds the past 6 dbfs
    Length should always be 6
    Structure <List[<Tuple>]>:
    [( int<time of creation since program start (seconds)>, [0,1,...] )]
"""
dbf_list = []

################################################################################
############################### PROGRAM ARGUMENT ###############################

"""
    Check the validity of sys args
    Returns `t`, `k` & `n`, the values for time, minimum shares and `n` amount of shares
"""
def check_args():
    # Check for valid input
    try:
        t = int(sys.argv[1])
        k = int(sys.argv[2])
        n = int(sys.argv[3])
    except:
        print("Invalid number of inputs")
        print(f"Usage: {sys.argv[0]} t k n (optional true for sickness)")
        sys.exit(1)

    try:
        sick = sys.argv[4]
        if sick.lower() == 'true':
            sick = True
    except:
        sick = False

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
    
    return t, k, n, sick
dummy_cbf_uploaded = False

################################################################################
##################################### MAIN #####################################

# Main function that deals with general client functionality
def main():
    uploaded_cbf = False
    dummy_cbf_uploaded = False
    
    t, k, n, sick = check_args()

    # Set a flag to check if CBF was sent
    cbf_sent = False    

    # Determines when the thread will shutdown
    start_time = time.time()

    last_qbf_sent = 0
    Dt = (t * 6 * 6) / 3600 # Every 30 seconds we attempt QBF generation

    shut_down = threading.Event()

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
    ephid, ephid_pub, eph_hash = gen_ephid(start_time)
    shares = split_secret(ephid_pub, k, n, start_time)

    # Set the expected times for EphID generation
    initial_time = time.time()
    expected_time = initial_time + t
    # Start a new thread to broadcast our split shares
    broadcast_thread = threading.Thread(target=broadcast_shares, \
                        args=(start_time, broad_sock, shares, eph_hash, shut_down))
    broadcast_thread.start()

    # broadcast_thread.daemon = True
    # broadcast_thread.start()

    """
        Specific locks used to access variable
    """
    # Lock for EphID dictionary
    eph_dict_lock = threading.Lock()
    # Lock for EncID dictionary
    dbf_list_lock = threading.Lock()
    """
        Set the thread as a daemon so that it shuts down 
        when the user wants to stop the program.
        Our receiver is set to blocking mode, 
        and only writes to our dictionary
    """
    receiver_thread = threading.Thread(target=receive_shares, \
                    args=(start_time, recv_sock, client_port, ephids_dict, eph_dict_lock, n))
    receiver_thread.daemon = True
    receiver_thread.start()

    try:
        while True:
            # Check that our current time has passed t seconds
            # Generate the new EphID and split the shares.
            # Then broadcast the shares through a new thread
            if time.time() > expected_time:
                ephid, ephid_pub, eph_hash = gen_ephid(start_time)
                shares = split_secret(ephid_pub, k, n, start_time)
                initial_time = time.time()
                expected_time = initial_time + t
                # Start a new thread to broadcast our split shares
                broadcast_thread = threading.Thread(target=broadcast_shares, \
                        args=(start_time, broad_sock, shares, eph_hash, shut_down))
                # broadcast_thread.daemon = True
                broadcast_thread.start()

            # Check our accumulated shares
            process_shares(start_time, ephid, ephids_dict, dbf_list,eph_dict_lock, k, t)


            # Check our stored DBFs and delete the oldest one
            delete_oldest_dbf(start_time, dbf_list, dbf_list_lock, t)
            
            # This is hard coded so that the client will only send the CBF after at least 4 DBFs
            # have been created to show that all the DBFs were combined.
            with dbf_list_lock:
                if sick and len(dbf_list) >= 4 and not cbf_sent:
                    cbf = create_cbf(start_time, dbf_list, dbf_list_lock)
                    print(f"{get_elapsed_time(start_time)}s [Segment 9] \
CBF Created out of {len(dbf_list)} DBFs")
                    # TODO: Create entrypoint to server and send CBF

                    print(f"{get_elapsed_time(start_time)}s CBF Created \
out of {len(dbf_list)} DBFs")
                    
                    cbf_sent = True
                    uploaded_cbf = True

            # Task 10: QBF generation & server communication
            if not uploaded_cbf and (time.time() - last_qbf_sent > Dt):
                print(f"{get_elapsed_time(start_time)}s [QBF] Generating QBF from DBFs...")
                with dbf_list_lock:
                    if dbf_list:
                        qbf = dbf_list[0][1][:]
                        for i in range(1, len(dbf_list)):
                            qbf = [b1 | b2 for b1, b2 in zip(qbf, dbf_list[i][1])]
                        qbf_data = bytes(qbf)
                        print(f"{get_elapsed_time(start_time)}s [QBF] Sample bits (hex): {qbf_data[:8].hex()}...")
                        print(f"{get_elapsed_time(start_time)}s [QBF] Sending QBF ({len(qbf_data)} bytes) to server at {SERVER_IP}:{SERVER_PORT}...")
                        send_qbf_to_server(qbf_data, SERVER_IP, SERVER_PORT, start_time)
                        last_qbf_sent = time.time()
                        if not dummy_cbf_uploaded:
                            upload_dummy_cbf(start_time)
                            dummy_cbf_uploaded = True



    except KeyboardInterrupt:
        print(f"{get_elapsed_time(start_time)}s [EXIT THREADS] \
Attempting to close threads...")
        # broad_sock.close()
        # recv_sock.close()
        shut_down.set()
        broadcast_thread.join()
        # receiver_thread.join()
        print(f"{get_elapsed_time(start_time)}s [SHUT DOWN] \
Client is quitting...")

    broad_sock.close()
    recv_sock.close()

################################################################################
#################################### START #####################################

if __name__ == "__main__":
    main()
