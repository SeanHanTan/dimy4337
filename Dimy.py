<<<<<<< HEAD
# Front-end program code
=======
import sys
import secrets
import time
from Crypto.Protocol.SecretSharing import Shamir
import socket

UDP_IP='127.0.0.1'
UDP_PORT=5005
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Enable broadcast

allowed_time = [15, 18, 21, 24, 27, 30]
time_t=int(sys.argv[1])
k=int(sys.argv[2])
n=int(sys.argv[3])
if k <3 and n<5 and k>n:
    print("Invalid values for k and n... Exiting")
    sys.exit()

g = 5  # generator

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
    share_split=Shamir.split(k,n,secret) # secrets is being splitted into n shares and being reconstructed using k shares
    print("Secret shares:")
    for i,share in enumerate(share_split):
        print(f"Share {i+1}: {share.hex()}")
    return share_split

def broadcast_shares(share_split):
    for i, share in enumerate(share_split):
        sock.sendto(share, (UDP_IP, UDP_PORT))
        print(f"Broadcasting share {i+1}: {share.hex()}")
        time.sleep(3)  # Wait for 3 seconds before sending the next share
    print("All shares broadcasted successfully.")
    
for current_time in allowed_time:
    ephid(current_time)
    if time_t<15 or time_t>30:
        print("Invalid time... Exiting")
        sys.exit()
    share_secret(ephid(current_time), k, n)
    time.sleep(time_t) 
    
>>>>>>> 1ddef6776646e2edff865de2939e3c9e1cdf968f
