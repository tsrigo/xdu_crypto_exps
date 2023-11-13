import base64
import os
from random import randint
from Crypto.Cipher import AES

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

from math import ceil
def split_bytes_in_blocks(x, blocksize):
    nb_blocks = ceil(len(x)/blocksize)
    return [x[blocksize*i:blocksize*(i+1)] for i in range(nb_blocks)]

def pkcs7_padding(message, block_size):
    padding_length = block_size - ( len(message) % block_size )
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

def pkcs7_strip(data):
    padding_length = data[-1]
    return data[:- padding_length]

def encrypt_aes_128_ecb(msg, key):
    padded_msg = pkcs7_padding(msg, block_size=16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_msg) + encryptor.finalize()

def decrypt_aes_128_ecb(ctxt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    message = pkcs7_strip(decrypted_data)
    return message

# You are not suppose to see this
class Oracle:
    def __init__(self):
        self.key = 'Mambo NumberFive'.encode()
        self.prefix = 'PREF'.encode()
        self.target = base64.b64decode( #You are suppose to break this
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        )
    def encrypt(self, message):
        return encrypt_aes_128_ecb(
            self.prefix + message + self.target,
            self.key
        )

def findBlockSize():
    initialLength = len(Oracle().encrypt(b''))
    i = 0
    while 1: # Feed identical bytes of your-string to the function 1 at a time until you get the block length
        #You will also need to determine here the size of fixed prefix + target + pad
        #And the minimum size of the plaintext to make a new block
        length = len(Oracle().encrypt(b'X'*i))
        if length > initialLength:
            minimumSizeToAlighPlaintext = i+1
            blockSize = length - initialLength
            sizeOfTheFixedPrefixPlusTarget = initialLength
            break
        i+=1
    return blockSize, sizeOfTheFixedPrefixPlusTarget, minimumSizeToAlighPlaintext

def findPrefixSize(block_size):
    previous_blocks = None
    #Find the situation where prefix_size + padding_size - 1 = block_size
    ### Use split_bytes_in_blocks to get blocks of size(block_size)
    i = 0
    diff_idx = 0

    previous_blocks = split_bytes_in_blocks(Oracle().encrypt(b''), block_size)
    cmp_blocks = split_bytes_in_blocks(Oracle().encrypt(b'X'), block_size)
    for i in range(len(previous_blocks)):
        if previous_blocks[i] != cmp_blocks[i]:
            diff_idx = i
            break
    
    i = 1
    while 1:
        # len(R)+i = blockSize
        new_blocks = split_bytes_in_blocks(Oracle().encrypt(b'X'*i), block_size)
        if previous_blocks[diff_idx] == new_blocks[diff_idx]:
            prefix_size = blockSize - i + 1 + diff_idx * block_size
            break
        i+=1
        previous_blocks = new_blocks
    return prefix_size


def recoverOneByteAtATime(blockSize, prefixSize, targetSize):
    know_target_bytes = b""
    for _ in range(targetSize):
        # r+p+k+1 = 0 mod B
        r = prefixSize
        k = len(know_target_bytes)

        padding_length = (-k-1-r) % blockSize
        padding = b"X" * padding_length

        # target block plaintext contains only known characters except its last character
        ct_blocks = split_bytes_in_blocks(Oracle().encrypt(padding), blockSize)
        hh = split_bytes_in_blocks(Oracle().encrypt(padding+b'R'), blockSize)[0]

        # trying every possibility for the last character
        cmp_idx = (prefixSize+padding_length+len(know_target_bytes))//blockSize
        for cc in range(256):
            cc = chr(cc).encode()
            if split_bytes_in_blocks(Oracle().encrypt(padding+know_target_bytes+cc), blockSize)[cmp_idx] == ct_blocks[cmp_idx]:
                know_target_bytes += cc
                break

    print(know_target_bytes.decode())

#Find block size, prefix size, and length of plaintext size to allign blocks
blockSize, sizeOfTheFixedPrefixPlusTarget, minimumSizeToAlighPlaintext = findBlockSize();

print("Block size: ", blockSize)
print("Size of the fixed prefix + target: ", sizeOfTheFixedPrefixPlusTarget)
print("Minimum size to allign plaintext: ", minimumSizeToAlighPlaintext)

#Find size of the prefix
prefixSize = findPrefixSize(blockSize)
print("Prefix size: ", findPrefixSize(blockSize))

#Size of the target
targetSize = sizeOfTheFixedPrefixPlusTarget - minimumSizeToAlighPlaintext - prefixSize
print("Target size: ", targetSize)

print('*'*20+"Plaintext"+'*'*20+"\n")
recoverOneByteAtATime(blockSize, prefixSize, targetSize)