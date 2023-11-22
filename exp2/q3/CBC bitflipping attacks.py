from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom

BLOCK_SIZE = 16
KEY_SIZE = 32
_key = urandom(KEY_SIZE)
_iv = urandom(BLOCK_SIZE)

def bytes_xor(b1: bytes, b2: bytes) -> bytes:
    if len(b1) != len(b2):
        raise("length error")
    return bytes(a ^ b for a, b in zip(b1, b2))

def wrap(raw: bytes) -> bytes:
    prepend = b"comment1=cooking%20MCs;userdata="   # 2 blocks
    append = b";comment2=%20like%20a%20pound%20of%20bacon" # 2 blocks
    raw = prepend + raw.replace(b"=", b"%3D").replace(b";", b"%3B") + append
    cipher = AES.new(key=_key, mode=AES.MODE_CBC, iv=_iv)
    return cipher.encrypt(pad(raw, BLOCK_SIZE))

def admincheck(raw: bytes, quiet: bool = False) -> bytes:
    cipher = AES.new(key=_key, mode=AES.MODE_CBC, iv=_iv)
    pt = unpad(cipher.decrypt(raw), BLOCK_SIZE)
    # pt = cipher.decrypt(raw)
    if quiet: 
        print(f"{pt=}")
    return b";admin=true;" in pt

def crack() -> bytes:
    AA = b'A' * BLOCK_SIZE
    Anew = bytes_xor(AA, b";admin=true;".rjust(BLOCK_SIZE, b'A'))

    ct = wrap(AA * 2)
    align = Anew.rjust(BLOCK_SIZE*3, b"\x00").ljust(len(ct), b"\x00")
    
    return bytes_xor(ct, align)

if __name__ == "__main__":
    fake_ct = crack()
    print(f"{fake_ct=}")
    print("Adming check: ", admincheck(fake_ct, True))


    