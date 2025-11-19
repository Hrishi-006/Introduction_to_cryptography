from pwn import *
from hashlib import sha256

HOST = "0.cloud.chals.io"
PORT = 18883

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python", "./server.py"])
target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp, end='')
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp, end='')
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp, end='')
    return resp


def get_proof(index : int) -> tuple[int, list[str]]:
    recvuntil(f"-{DATA_LEN-1}: ")
    sendline(str(index))
    recvuntil("Value: ")
    val = int(recvline().strip())
    recvuntil("Proof: ")
    proof = eval(recvline().strip())
    return val, proof


recvuntil("Data Length: ")
DATA_LEN = int(recvline().strip())
recvuntil("Root Hash: ")
ROOT_HASH = recvline().strip()

# ===== YOUR CODE BELOW =====
# You can use the function "get_proof(index : int) -> tuple[int, list[str]]" to retrieve the ASCII value of the character at the specified index and a list of hexstrings of the proof
# Set the data variable to your guess of data (in bytes)
# The variable "DATA_LEN" stores the length of the flag
# The variable "ROOT_HASH" stores the root hash of the Merkle Tree

# Build a map of single-byte digests and the composed two-byte digests (kept same keying as original)
digest_map = {}
for b in range(256):
    digest_map[b] = sha256(bytes([b])).digest().hex()

# Keep the same combined-key scheme as in the original script
for p in range(256):
    for q in range(256):
        digest_map[p * 256 + q * 256 * 256] = sha256(
            sha256(bytes([p])).digest() + sha256(bytes([q])).digest()
        ).digest().hex()

# Gather parts from proofs for every 4th index
leaf_last = []
leaf_second_last = []
leaf_values = []

for idx in range(0, DATA_LEN, 4):
    value, proof_list = get_proof(idx)
    leaf_last.append(proof_list[-1])
    leaf_second_last.append(proof_list[-2])
    leaf_values.append(value)

# Try to reconstruct bytes using the digest_map (same matching logic as original)
reconstructed = []

# print the second-last proof entries (as original did)
for entry in leaf_second_last:
    print(entry)

# For each 4-byte group attempt to find matching bytes
for i_grp in range(len(leaf_values)):
    # match the single-byte digest to find one byte
    for cand in range(256):
        if digest_map[cand] == leaf_last[i_grp]:
            reconstructed.append(leaf_values[i_grp])
            reconstructed.append(cand)

    # match the composed digest to find two more bytes
    for a in range(256):
        for b in range(256):
            if digest_map[a * 256 + b * 256 * 256] == leaf_second_last[i_grp]:
                reconstructed.append(a)
                reconstructed.append(b)

# convert to bytes
data = bytes(bytearray(reconstructed))
# ===== YOUR CODE ABOVE =====

recvuntil("(in hex): ")
sendline(data.hex())

recvline()

target.close()
