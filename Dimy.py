import sys
import secrets
import time
from Crypto.Protocol.SecretSharing import Shamir
import socket

UDP_IP = '127.0.0.1'
UDP_PORT = 5005
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

allowed_time = [15, 18, 21, 24, 27, 30]
time_t = int(sys.argv[1])
k = int(sys.argv[2])
n = int(sys.argv[3])

if k < 3 or n < 5 or k > n:
    print("Invalid values for k and n... Exiting")
    sys.exit()

if time_t not in allowed_time:
    print("Invalid time... Exiting")
    sys.exit()

g = 5  # generator

def gen_ephid(current_time):
    if current_time not in allowed_time:
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

def broadcast_shares(share_split):
    for i, share in enumerate(share_split):
        rand_num = secrets.SystemRandom().uniform(0, 1)
        if rand_num < 0.5:
            print (f"Share Dropped: {share.hex()} at the {i+1}th share")
            continue
        else:
            sock.sendto(share, (UDP_IP, UDP_PORT))
            print(f"Broadcasting share {i+1}: {share.hex()}")
        time.sleep(3)
    print("All shares broadcasted")

def main():
    try:
        while True:
            ephid = gen_ephid(time_t)
            shares = split_secret(ephid, k, n)
            broadcast_shares(shares)
            time.sleep(time_t)
    except KeyboardInterrupt:
        print("Quitting...")
        sock.close()

if __name__ == "__main__":
    main()
