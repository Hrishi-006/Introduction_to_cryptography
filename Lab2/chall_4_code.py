
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 23369

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python", "./server.py"])
target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp)
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp)
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp)
    return resp


def send_to_server(input: str) -> tuple[str, str]:
    recvuntil("$ ")
    sendline(input)
    recvuntil("Encrypted Input (hex): ")
    inp_enc = recvline().strip()
    recvuntil("Encrypted Output (hex): ")
    outp_enc = recvline().strip()
    return (inp_enc, outp_enc)


# ===== YOUR CODE BELOW =====
from Crypto.Util.strxor import strxor
from math import ceil

BLOCK_SIZE = 16

long_dummy = ("\x00" * 1600)
temp, out_enchex = send_to_server(long_dummy)

out_enc = bytes.fromhex(out_enchex)

temp, enc_flaghex = send_to_server("!flag")
enc_flag = bytes.fromhex(enc_flaghex)
m = len(enc_flag)
m_blocks = ceil(m/BLOCK_SIZE)

offset = 20*BLOCK_SIZE

slice = out_enc[offset: offset + m]
flag_bytes = strxor(enc_flag, slice)
try:
    flag = flag_bytes.decode('utf-8')
except:
    flag = flag_bytes.decode('utf-8', errors='replace')

print("Flag:", flag)

# ===== YOUR CODE ABOVE =====

target.close()

