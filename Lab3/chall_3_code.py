from pwn import *
import time

HOST = "0.cloud.chals.io"
PORT = 22320

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


def send_guess(hmac_guess : str) -> int:
    recvuntil("omniscience: ")
    sendline(hmac_guess)
    resp = recvline()
    if "omniscient" in resp:
        recvline()
        return 1
    else:
        return -1


recvuntil("of length ")
msg_len = int(recvuntil(" ")[:-1])

# ===== YOUR CODE BELOW =====
# The variable "msg_len" contains the length of the message that the server is asking for
# Set the message that you want to send to the server (in hex, as str) in the variable "msg"

message_payload_hex = ("c"*msg_len).encode().hex()
# ===== YOUR CODE ABOVE =====

recvuntil("in hex): ")
sendline(message_payload_hex)

# ===== YOUR CODE BELOW =====
# Use the function "send_guess(hmac_guess : str) -> int" to send your guess of the first 10 hexchars of the hmac to the server
#   A return value of -1 indicates that your guess was incorrect
#   A return value of 1 indicates the your guess was correct
HEX_CHARS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
HMAC_GUESS_LENGTH = 10
current_guess_indices = [0] * HMAC_GUESS_LENGTH


start_time = 0.0
end_time = 0.0


all_chars_guessed = False

while True:
    
    current_char_index = int(end_time - start_time)

    if current_char_index == HMAC_GUESS_LENGTH:
        if all_chars_guessed:
            break
        else:
            
            continue
    else:
       
        all_chars_guessed = False

    
    for reset_idx in range(current_char_index + 1, HMAC_GUESS_LENGTH):
        current_guess_indices[reset_idx] = 0

  
    current_guess_indices[current_char_index] += 1

    
    hex_guess_str = ""
    for char_idx in range(HMAC_GUESS_LENGTH):
        hex_guess_str += HEX_CHARS[current_guess_indices[char_idx]]

    # Time the guess attempt
    start_time = time.time()
    send_guess(hex_guess_str)
    end_time = time.time()

    time_elapsed = end_time - start_time
    print(f"Time taken for guess: {time_elapsed:.5f}s")
    

# ===== YOUR CODE ABOVE =====

target.close()