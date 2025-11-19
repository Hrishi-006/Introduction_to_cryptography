from pwn import *
import hashlib
import ecdsa
import random
from Crypto.Util.number import inverse
import time

HOST = "0.cloud.chals.io"
PORT = 32289

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
#target = process(["python3", "./server.py"])
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


def point_to_tuple(point):
    return (int(point.x()), int(point.y()))

def tuple_to_point(tup):
    return ecdsa.ellipticcurve.Point(ecdsa.ellipticcurve.CurveFp(ecdsa.NIST256p.curve.p(), ecdsa.NIST256p.curve.a(), ecdsa.NIST256p.curve.b()), tup[0], tup[1])


# -----VARIANT 1-----
recvuntil("Public Key: ")
VARIANT1_PUBKEY = tuple_to_point(eval(recvline().strip()))

# ===== YOUR CODE BELOW =====
# Variables You Have:
#     - VARIANT1_PUBKEY: the public key point used in VARIANT 1 signatures
# Enter the five message (str) you want to get signed in the list 'msgs'

msgs = ["m1", "m2", "m3", "m4", "m5"]
# ===== YOUR CODE ABOVE =====

assert len(msgs) == 5
sigs = []
for msg in msgs:
    recvuntil("]: ")
    sendline(msg)
    recvuntil("Signature: ")
    sigs.append(eval(recvline().strip()))
    sigs[-1] = (tuple_to_point(sigs[-1][0]), sigs[-1][1])

recvuntil("Variant 1: ")
challenge_msg_1 = recvline().strip().encode()

# ===== YOUR CODE BELOW =====
# Variables You Have:
#    - VARIANT1_PUBKEY: the public key point used in VARIANT 1 signatures
#    - msgs: the list of messages (str) you had submitted earlier
#    - sigs: list of respective (R, s) VARIANT 1 signatures for each of the messages you had submitted earlier
#    - challenge_msg_1: the message whose VARIANT 1 signature you have to provide
# Set the variable 'R' to the point R of the signature
# Set the variable 's' to the value s of the signature
G = ecdsa.NIST256p.generator
q = ecdsa.NIST256p.generator.order()

R0, s0 = sigs[0]
msg0 = msgs[0].encode()

r0 = int(hashlib.sha256(msg0 + str(VARIANT1_PUBKEY.x()).encode()).hexdigest(), 16) % q

h0 = int(hashlib.sha256(str(R0.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + msg0).hexdigest(), 16) % q

priv = ((s0 - r0) * inverse(h0, q)) % q

chal = challenge_msg_1
r_ch = int(hashlib.sha256(chal + str(VARIANT1_PUBKEY.x()).encode()).hexdigest(), 16) % q
R = r_ch * ecdsa.NIST256p.generator
h_ch = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + chal).hexdigest(), 16) % q
s = (r_ch + (h_ch * priv)) % q

# ===== YOUR CODE ABOVE =====

# send the forged signature for Variant 1
recvuntil(")): ")
sendline(f"({point_to_tuple(R)}, {int(s)})")

# -----VARIANT 2-----
recvuntil("Public Key: ")
VARIANT2_PUBKEY = tuple_to_point(eval(recvline().strip()))

# ===== YOUR CODE BELOW =====
# Variables You Have:
#     - VARIANT2_PUBKEY: the public key point used in VARIANT 1 signatures
# Enter the five message (str) you want to get signed in the list 'msgs'

msgs = ['message1','messahtj','message3','message4','message5']
# ===== YOUR CODE ABOVE =====

assert len(msgs) == 5
sigs = []
for msg in msgs:
    recvuntil("]: ")
    sendline(msg)
    recvuntil("Signature: ")
    sigs.append(eval(recvline().strip()))
    sigs[-1] = (tuple_to_point(sigs[-1][0]), sigs[-1][1])

recvuntil("Variant 2: ")
challenge_msg_2 = recvline().strip().encode()

# ===== YOUR CODE BELOW =====
# Variables You Have:
#    - VARIANT2_PUBKEY: the public key point used in VARIANT 2 signatures
#    - msgs: the list of messages (str) you had submitted earlier
#    - sigs: list of respective (R, s) VARIANT 2 signatures for each of the messages you had submitted earlier
#    - challenge_msg_2: the message whose VARIANT 2 signature you have to provide
# Set the variable 'R' to the point R of the signature
# Set the variable 's' to the value s of the signature
q = G.order()
R1, s1 = sigs[0]
R2, s2 = sigs[1]
h1 = int(hashlib.sha256(str(R1.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msgs[0].encode()).hexdigest(), base=16) % q
h2 = int(hashlib.sha256(str(R2.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msgs[1].encode()).hexdigest(), base=16) % q
VARIANT2_PRIVKEY = (s1-s2)*pow(h1-h2, -1, q)%q
r = int(hashlib.sha256(challenge_msg_2[:len(challenge_msg_2)//2] + str(VARIANT2_PRIVKEY).encode()).hexdigest(), base=16) % q
R = r*G
h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + challenge_msg_2).hexdigest(), base=16) % q
s = (r + h * VARIANT2_PRIVKEY) % q
# ===== YOUR CODE ABOVE =====

recvuntil(")): ")
sendline(f"({point_to_tuple(R)}, {int(s)})")

target.interactive()