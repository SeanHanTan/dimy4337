import json
import secrets
import socket
import threading
import time
import uuid
from Crypto.Protocol.SecretSharing import Shamir
from hashlib import sha256

################################################################################
################################### CONSTANTS ##################################

# Server details
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 55000
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

# Details for Receiver
RECV_IP = SERVER_IP
RECV_PORT = 50001
RECV_ADDR = (RECV_IP, RECV_PORT)

# Initial Receiver details
INIT_RECV_IP = SERVER_IP
INIT_RECV_PORT = 8888
INIT_RECV_ADDR = (INIT_RECV_IP, INIT_RECV_PORT)

################################################################################
################################# ID GENERATORS ################################

# Generates the Ephemeral ID (EphID)
# and the first 3 bytes of its hash
def gen_ephid(start_time):
    g = 5   # Generator
    x_At = secrets.token_bytes(32)
    g_bytes = g.to_bytes(32, byteorder='big')  
    eph_id = bytes(a ^ b for a, b in zip(x_At, g_bytes))

    s = sha256(eph_id)
    hash = s.digest()[:3]
    
    print(f"{get_elapsed_time(start_time)}s [EPHID GENERATED] \
{eph_id.hex()[:6]}... with first 3 bytes of hash: {hash.hex()}")

    return eph_id, hash

# Generates the Encounter ID (EncID) using the reconstructed EphID
# Applied through Diffie-Hellman key exchange
# TODO: Use Diffie-Hellman key exchange to 
def gen_encid():
    return

################################################################################
############################ CRYPTOGRAPHIC FUNCTIONS ###########################

# Splits our EphID into `n` shares that can be constructed with
# `k` amount. This function uses our auxiliary function that
# has been taken from online
def split_secret(secret, k, n, start_time):
    if len(secret) != 32:
        raise ValueError(f"{get_elapsed_time(start_time)}s [ERROR] \
Secret must be 32 bytes long.")
    
    # Split our 32-byte long secret into `n` amounts 
    shares = split_large(k, n, secret)

    print(f"{get_elapsed_time(start_time)}s [SHAMIR SECRET SHARE] \
{n} shares have been generated with k = {k}.")

    for i, share in enumerate(shares):
        print(f"{get_elapsed_time(start_time)}s [SHARES GENERATED] \
Share {share[0]}: {share[1].hex()[:6]}...")

    return shares

################################################################################
######################### Shamir Secret Sharing Scheme #########################

SHAMIR_BLOCK_SIZE = 16

##
#   This code has been taken from https://github.com/Legrandin/pycryptodome/pull/593
#   It implements the Shamir Secret Sharing scheme from PyCryptodome and supports
#   secret sizes of over 16 bytes.
#   The modules were approved in 2022 but is not found in the current Crypto
#   library
##
@staticmethod
def split_large(k, n, secret, ssss=False):
    """
    Wrapper for Shamir.split()
    when len(key) > SHAMIR_BLOCK_SIZE (16)
    """
    if not isinstance(secret, bytes):
        raise TypeError("Secret must be bytes")
    if len(secret) % SHAMIR_BLOCK_SIZE != 0:
        raise ValueError(f"Secret size must be a multiple of {SHAMIR_BLOCK_SIZE}")
    blocks = len(secret) // SHAMIR_BLOCK_SIZE
    shares = [b'' for _ in range(n)]
    for i in range(blocks):
        block_shares = Shamir.split(k, n,
                secret[i*SHAMIR_BLOCK_SIZE:(i+1)*SHAMIR_BLOCK_SIZE], ssss)
        for j in range(n):
            shares[j] += block_shares[j][1]
    return [(i+1,shares[i]) for i in range(n)]

@staticmethod
def combine_large(shares, ssss=False):
    """
    Wrapper for Shamir.combine()
    when len(key) > SHAMIR_BLOCK_SIZE (16)
    """
    share_len = len(shares[0][1])
    for share in shares:
        if len(share[1]) % SHAMIR_BLOCK_SIZE:
            raise ValueError(f"Share #{share[0]} is not a multiple of {SHAMIR_BLOCK_SIZE}")
        if len(share[1]) != share_len:
            raise ValueError("Share sizes are inconsistent")
    blocks = share_len // SHAMIR_BLOCK_SIZE
    result = b''
    for i in range(blocks):
        block_shares = [
                (int(idx), share[i*SHAMIR_BLOCK_SIZE:(i+1)*SHAMIR_BLOCK_SIZE]) 
            for idx, share in shares]
        result += Shamir.combine(block_shares, ssss)
    return result

################################################################################
############################# UDP AND TCP FUNCTIONS ############################

# Broadcasts a random string to check for its port number,
# Also to ignore future broadcasts from its own
# Returns its own port number when found
def check_port(send_sock, start_time):
    port = ''
    rnd_msg = str(uuid.uuid4())

    # Create a new port and bind it to a specific port so that we don't
    # listen to the same UDP broadcasted port, otherwise the program goes into a loop
    # when another client is broadcasting its shares
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(('', INIT_RECV_PORT))

    while not port:
        print(f"{get_elapsed_time(start_time)}s [CHECK] \
Checking what port the client is using...")
        send_sock.sendto(rnd_msg.encode('utf-8'), INIT_RECV_ADDR)
        msg, addr = recv_sock.recvfrom(len(rnd_msg.encode('utf-8')))

        if msg.decode('utf-8') == rnd_msg:
            port = addr[1]

    # Close the socket before exit
    recv_sock.close()
    return port

# Broadcast the k out of n shares
# Used inside a new thread
def broadcast_shares(sock, shares, hash, start_time):
    sent = 0
    dropped = 0
    for i, share in enumerate(shares):
        rand_num = secrets.SystemRandom().uniform(0, 1)
        print(f"{get_elapsed_time(start_time)}s [BROADCASTING] \
Share {share[0]}: {share[1].hex()[:6]}...")
       
        if rand_num < 0.5:
            print (f"{get_elapsed_time(start_time)}s [SHARE DROPPED] \
Share {i+1}: {share[1].hex()[:6]}...")
            dropped += 1
        else:
            # First convert our tuple into a JSON object
            # data = json.dumps({share[0]: share[1].hex()})
            data = json.dumps({hash.hex():[share[0], share[1].hex()]})

            # Convert the JSON object into a bytes buffer
            buff = bytes(data,encoding="utf-8")
            print(f"{get_elapsed_time(start_time)}s [SHARE BROADCASTED] \
Buffer of share {share[0]}: {buff[:6]}...")
            # print(f"SHARE {i+1}: {buff} at {len(buff)} bytes")

            sock.sendto(buff, RECV_ADDR)
            sent += 1
        if i + 1 < len(shares):
            # Wait for 3 seconds before sending the next share
            time.sleep(3)
    print(f"{get_elapsed_time(start_time)}s [BROADCAST END] \
All shares have been broadcasted.")
    print(f"{get_elapsed_time(start_time)}s [BROADCAST SUMARRY] \
{sent} shares sent, {dropped} shares dropped.")

# Receives the broadcasted shares from one client
# Stores the shares into a dictionary
# TODO:
def receive_shares(start_time, sock, port, ephids_dict, dict_lock):

    while True:
        data, addr = sock.recvfrom(1024)

        if addr[1] != port:
            print(f"{get_elapsed_time(start_time)}s [RECEIVING] Captured data: \
{data[:6]}... from address: {addr}")

            # Extract the data we received and convert it to appropriate data types
            received = json.loads(data)
            # Collect the advertised hash
            eph_hash = list(received.keys())[0]

            # Process our share details
            recv_list = list(received.values())[0]

            # Turn the index and share into a tuple
            share_tuple = (recv_list[0], bytes.fromhex(recv_list[1]))

            # Lock the thread so that it we can include the received share in the dictionary
            with dict_lock:
                # First check if the port exists
                # so that we can create a new dictionary entry
                if addr[1] not in ephids_dict:
                    ephids_dict[addr[1]] = {
                        'hash'   : eph_hash,
                        'shares' : [share_tuple]
                    }
                else:
                    ephids_dict[addr[1]]['shares'].append(share_tuple)
                    

    # except KeyboardInterrupt:
    #     print(f"{get_elapsed_time(start_time)}s [END RECEIVER] Receiver is closing down")

    return

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
################################# MISCELLANEOUS ################################

def get_elapsed_time(start_time):
    return f"{(time.time() - start_time):.2f}"