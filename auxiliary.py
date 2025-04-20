import json
import secrets
import socket
import threading
import time
import uuid
from Crypto.Protocol.SecretSharing import Shamir
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

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
################################## ID RELATED ##################################

# Generates the Ephemeral ID (EphID)
# and the first 3 bytes of its hash
def gen_ephid(start_time):
    ephid     = x25519.X25519PrivateKey.generate()
    ephid_pub = ephid.public_key().public_bytes_raw()
    hash_prefix = hash_ephid(ephid_pub)

    print(f"{get_elapsed_time(start_time)}s [EPHID GENERATED] \
{ephid_pub.hex()[:6]}...")
    print(f"{get_elapsed_time(start_time)}s [EPHID HASH GENERATED] \
First 3 bytes of hash: {hash_prefix.hex()}")

    return ephid, ephid_pub, hash_prefix

# Given our private key and a peer EphID,
# Generate an Encounter ID (EncID) applied through Diffie-Hellman key exchange
def gen_encid(priv_key, ephid):
    # First convert the EphID into an 'X25519PublicKey' object
    loaded_public_key = x25519.X25519PublicKey.from_public_bytes(ephid)
    shared_key = priv_key.exchange(loaded_public_key)
    encid = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'Encounter ID',
    ).derive(shared_key)
    return encid

def hash_ephid(ephid):
    hash_digest = sha256(ephid).digest()
    hash_prefix = hash_digest[:3]
    return hash_prefix

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
def broadcast_shares(start_time, sock, shares, hash, shut_down):
    sent = 0
    dropped = 0
    i = 0
    while not shut_down.is_set() and i < len(shares):

        rand_num = secrets.SystemRandom().uniform(0, 1)
#         print(f"{get_elapsed_time(start_time)}s [BROADCASTING] \
# Share {shares[i][0]}: {shares[i][1].hex()[:6]}...")

#         if rand_num < 0.5:
#             print (f"{get_elapsed_time(start_time)}s [BROADCASTING] \
# Share {shares[i][0]} dropped: {shares[i][1].hex()[:6]}...")

#             dropped += 1
#         else:
#             # First convert our hash:tuple object into a JSON object
#             data = json.dumps({hash.hex():[shares[i][0], shares[i][1].hex()]})

#             # Convert the JSON object into a bytes buffer
#             buff = bytes(data,encoding="utf-8")
#             print(f"{get_elapsed_time(start_time)}s [BROADCASTING] \
# Share {shares[i][0]} broadcasted: {shares[i][1].hex()[:6]}...")

#             sock.sendto(buff, RECV_ADDR)
#             sent += 1

# First convert our hash:tuple object into a JSON object
        data = json.dumps({hash.hex():[shares[i][0], shares[i][1].hex()]})

        # Convert the JSON object into a bytes buffer
        buff = bytes(data,encoding="utf-8")
        print(f"{get_elapsed_time(start_time)}s [BROADCASTING] \
Share {shares[i][0]} broadcasted: {shares[i][1].hex()[:6]}...")

        sock.sendto(buff, RECV_ADDR)
        sent += 1

        if i + 1 < len(shares):
            # Wait for 3 seconds before sending the next share
            time.sleep(3)

        i += 1
        
    print(f"{get_elapsed_time(start_time)}s [BROADCAST END] \
All shares have been broadcasted.")
    print(f"{get_elapsed_time(start_time)}s [BROADCAST SUMARRY] \
{sent} shares sent, {dropped} shares dropped.")
    return

# Receives the broadcasted shares from one client
# Stores the shares into a dictionary
def receive_shares(start_time, sock, port, ephids_dict, dict_lock):
    while True:
        data, addr = sock.recvfrom(85)

        if addr[1] != port:
            # Extract the data we received and convert it to appropriate data types
            received = json.loads(data)
            # Collect the advertised hash
            eph_hash = bytes.fromhex(list(received.keys())[0])

            # Process our share details
            recv_list = list(received.values())[0]

            # Turn the index and share into a tuple
            share_tuple = (recv_list[0], bytes.fromhex(recv_list[1]))

            # Lock the thread so that it we can include the received share in the dictionary
            with dict_lock:
                # First check if the port exists
                # so that we can create a new dictionary entry
                # Store the hash and shares as raw bytes
                if addr[1] not in ephids_dict:
                    ephids_dict[addr[1]] = {
                        'hash'   : eph_hash,
                        'shares' : [share_tuple]
                    }
                else:
                    # Check that the advertised hash is not the same.
                    # Replace the shares and hash if it is
                    if ephids_dict[addr[1]]['hash'] == eph_hash:
                        ephids_dict[addr[1]]['shares'].append(share_tuple)
                    else:
                        ephids_dict[addr[1]]['hash']   = eph_hash
                        ephids_dict[addr[1]]['shares'] = [share_tuple]
                print(f"{get_elapsed_time(start_time)}s [RECEIVING {addr[1]}] \
Share {share_tuple[0]}: {share_tuple[1].hex()[:6]}...")

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
#################################### CHECKS ####################################

# Looks through all shares and then attempts to reconstruct them
def process_shares(start_time, priv_key, ephids_dict, encids_dict, eph_dict_lock, enc_dict_lock, k):
    # Go through our ephid dictionary.
    # Check that there are at least k shares.
    # Reconstruct the EphID, then hash it
    # Compare the first 3 bytes of the hash with the advertised one
    # Then Generate an EncID out of the EphID
    with eph_dict_lock:
        for port, frags in ephids_dict.items():
            
            ephid_hash = frags['hash']
            shares_list = frags['shares']
            
            # When the client has received >= k shares from the same port
            if len(shares_list) >= k:
                rec_ephid = combine_large(shares_list)
                # Hash our reconstructed EphID
                rec_hash = hash_ephid(rec_ephid)

                # Verify the hash of the reconstructed EphID
                # Move to the next entry in the dictionary if not
                if rec_hash != ephid_hash:
                    print(f"{get_elapsed_time(start_time)}s [RECONSTRUCTING EPHID] \
{rec_ephid.hex()[:6]}...")
                    print(f"{get_elapsed_time(start_time)}s [VERIFYING EPHID] \
Reconstructed EphID hash is not the same as advertised: {rec_hash.hex()} != {ephid_hash.hex()}.")
                    continue

                # Check if the EphID has been stored before
                if 'reconstructed' not in ephids_dict[port]:
                    print(f"{get_elapsed_time(start_time)}s [RECONSTRUCTING EPHID] \
{rec_ephid.hex()[:6]}...")
                    print(f"{get_elapsed_time(start_time)}s [VERIFYING EPHID] \
Reconstructed Hash: {rec_hash.hex()}, Advertised Hash: {ephid_hash.hex()}")
                    
                    ephids_dict[port]['reconstructed'] = rec_ephid

                # Generate the EncID based on the EphID we received    
                encid = gen_encid(priv_key, rec_ephid)
                with enc_dict_lock:
                    # Check that there is no entry for
                    # the EncID
                    # OR
                    # Check that the EncID is not the same as previous,
                    # Otherwise replace it with the new one
                    if port not in encids_dict or encids_dict[port] != encid: 
                        
                        encids_dict[port] = encid
                        print(f"{get_elapsed_time(start_time)}s [ENCID DERIVED] \
{encid.hex()[:6]}...")
    return

################################################################################
################################# MISCELLANEOUS ################################

# Returns the elapsed time since start of program in string format
def get_elapsed_time(start_time):
    return f"{(time.time() - start_time):.2f}"

# TODO: Modify if needed
# Given a dictionary and port, clears the entry relating to the port 
def clear_dict_items(dict, port):
    if port in dict:
        dict[port].clear()
