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
        elif sick.lower() == 'false':
            sick = False
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
    if t < 3*n:
        print("Invalid time input: Time has to be larger than 3*n")
        sys.exit(1)
    
    return t, k, n, sick

################################################################################
##################################### MAIN #####################################

# Main function that deals with general client functionality
def main():
    t, k, n, sick = check_args()

    # Set a flag to check if CBF was sent
    cbf_sent = False    
    qbf_sent = False

    # Determines when the thread will shutdown
    start_time = time.time()

    Dt = ((t * 6 * 6) / 60) * 60

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
            process_shares(start_time, ephid, ephids_dict, dbf_list, \
                           eph_dict_lock, dbf_list_lock, k, t)

            # Check our stored DBFs and delete the oldest one
            delete_oldest_dbf(start_time, dbf_list, dbf_list_lock, Dt)
            
            # This is hard coded so that the client will only send the CBF after at least 4 DBFs
            # have been created to show that all the DBFs were combined.
            with dbf_list_lock:
                if sick and len(dbf_list) >= 4 and not cbf_sent and dbf_list:
                    cbf = combine_dbf(dbf_list)
                    print(f"{get_elapsed_time(start_time)}s [Segment 9] \
CBF Created out of {len(dbf_list)} DBFs")
                    cbf_data = bytes(cbf)
                    print(f"{get_elapsed_time(start_time)}s [SEGMENT 9] \
Sample bytes of CBF in hex: {qbf_data[:6].hex()}...")
                    print(f"{get_elapsed_time(start_time)}s [SEGMENT 9] Sending CBF \
of ({len(qbf_data)} bytes) to server at {SERVER_IP}:{SERVER_PORT}...")
                    # TODO: Create entrypoint to server and send CBF
                    cbf_sent = True

                if dbf_list:
                    # Check the oldest DBF and compare it to Dt
                    # Send a QBF if it is
                    oldest = min([t[0] for t in dbf_list])
                    curr_time = time.time() - start_time
                    if not cbf_sent and (curr_time > oldest + Dt):
                        print(f"{get_elapsed_time(start_time)}s [SEGMENT 8] Generating QBF: \
Oldest DBF was created at {oldest:.2f}secs.")
                        qbf = combine_dbf(start_time, dbf_list)
                        qbf_data = bytes(qbf)
                        print(f"{get_elapsed_time(start_time)}s [SEGMENT 8] \
Sample bytes of QBF in hex: {qbf_data[:6].hex()}...")
                        print(f"{get_elapsed_time(start_time)}s [SEGMENT 8] Sending QBF \
of ({len(qbf_data)} bytes) to server at {SERVER_IP}:{SERVER_PORT}...")
                        qbf_sent = True
            
            # Create a new thread and start a connection with the server
            if qbf_sent and qbf_data:
                # send_qbf_to_server(qbf_data, SERVER_IP, SERVER_PORT, start_time)
                # upload_combined_dbf(start_time, qbf_data, "QBF-")
                backend_communication = threading.Thread(target=upload_combined_dbf, \
                        args=(start_time, qbf_data, "QBF-"))
                backend_communication.start()
            elif cbf_sent and cbf_data:
                # upload_combined_dbf(start_time, cbf_data, "CBF-")
                backend_communication = threading.Thread(target=upload_combined_dbf, \
                        args=(start_time, qbf_data, "CBF-"))
                backend_communication.start()

            # Revert our qbf_sent flag
            # No need to revert CBF flag as specs do not mention any further sending
            # of CBFs or QBFs
            qbf_sent = False

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
