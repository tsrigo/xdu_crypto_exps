# 问题1

## 1 求未知数字

```python
w = [7, 3, 1] * 10
letter2num = {chr(ord('A') + i): i+10 for i in range(26)}
letter2num.update({str(i): i for i in range(9)})
letter2num['<'] = 0

# 计算校验和
# 12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4
s = "12345678<8<<<1110182<111116"

for guess in range(9):
    teps = s + str(guess)
    checksum = 0
    for idx, ch in enumerate(teps):
        checksum += letter2num[ch] * w[idx]
    checksum = checksum % 10
    if checksum == 4:
        print(guess)

# 结果是 7
```

## 2 求key

### 2.1求Kseed

```python
def cal_Kseed() -> str:
    MRZ_information = "12345678<811101821111167"  # 护照信息
    H_information = sha1(MRZ_information.encode()).hexdigest()  # 使用SHA1进行哈希
    K_seed = H_information[0:32]  # 取哈希值的前32位作为K_seed
    return K_seed
```



### 2.2求Ka和Kb

```python
def cal_Ka_Kb(K_seed):
    c = "00000001"
    d = K_seed + c
    H_d = sha1(codecs.decode(d, "hex")).hexdigest()  # 对K_seed进行哈希
    ka = H_d[0:16]  # 取前16位作为ka
    kb = H_d[16:32]  # 取后16位作为kb
    return ka, kb
```



### 2.3对Ka和Kb奇偶校验生成key

```python
def Parity_Check(x):
    k_list = []
    a = bin(int(x, 16))[2:]  # 将16进制转为2进制
    for i in range(0, len(a), 8):
        # 7位一组分块，计算一个校验位，使1的个数为偶数
        if (a[i:i + 7].count("1")) % 2 == 0:
            k_list.append(a[i:i + 7])
            k_list.append('1')
        else:
            k_list.append(a[i:i + 7])
            k_list.append('0')
    k = hex(int(''.join(k_list), 2))  # 将2进制转为16进制
    return k
ka, kb = cal_Ka_Kb(cal_Kseed())
k1, k2 = Parity_Check(ka), Parity_Check(kb)
key = k1[2:] + k2[2:]  # 合并k_1和k_2作为最终的密钥
```



### 2.4. 拿key和base64解码后的密文解密

```python
ciphertext = base64.b64decode(
    "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI")
IV = '0' * 32  # 初始化向量

# 使用AES进行解密
m = AES.new(binascii.unhexlify(key), AES.MODE_CBC, binascii.unhexlify(IV)).decrypt(ciphertext)
print(m)  # 输出解密后的明文
```





# 问题2

# Byte-at-a-time ECB decryption (Harder)

## 题目

大意是利用选择明文攻击ECB。

[Challenge 14 Set 2 - The Cryptopals Crypto Challenges](https://cryptopals.com/sets/2/challenges/14)



该漏洞发生在以下情况:

- 你向服务器发送一个输入。
- 服务器将secret附加到INPUT→INPUT||secret
- 服务器用密钥和前缀加密→AES-128-ECB(random-prefix || attack -controlled || target-bytes, random-key)
- 服务器返回加密结果

## 参考链接

[参考链接](https://ocw.cs.pub.ro/courses/ic/res/tema1)

这个网站给出了题目的详细解释和代码框架，可以使人专注于核心部分。

## 思路

### 1 确定分组大小

原理：当明文的大小是分组的倍数的时候，pkcs7会添加一个dummy block，其大小就是分组大小。

做法：

1. 首先，通过调用 `Oracle().encrypt(b'')` 函数并获取长度来确定初始长度。
2. 然后，进入一个无限循环，每次循环都会向 `Oracle().encrypt(b'X'*i)` 函数提供延长明文长度，其中 `i` 是当前循环的迭代次数。
3. 在每次迭代中，检查新的长度是否大于初始长度。如果是，说明生成了一个dummy block，其大小等于新长度减去初始长度。根据需要的量，还可以顺便计算出对齐明文所需的最小大小（即 `i+1`），以及固定前缀加目标的密文大小（即初始长度）。

```python
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
```

### 2 确定前缀长度

原理：

见下例，其中R表示随机前缀，X表示我们将提供给oracle的输入(即选择明文，称 padding)，T表示目标。

仍然是不断延长明文，可以发现当 padding 的长度达到一定值时，我们可以发现前面的 block 将不再发生变化。

在发现前的第一次，满足：随机前缀的长度 + padding的长度 = 块长度

```
RRTT TT
RRXT TTT
RRXX TTTT * first time
RRXX XTTT T  *detected that first block did not change*
RRXT TTT
```

做法：

我这里担心随机前缀的长度大于block的长度，依次首先作了一个判断，但是感觉没有必要。

然后是不断使用延长的padding进行加密，判断第一个block是否不再变化（第一次遇到不变化就可以认为不再变化了）。如果是就可以确定前缀长度。

```python
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

```

### 3 逐字节攻击

原理：如下例，t 是target的第一个字节，c 是我们暴力枚举的字节，上下两个部分只有这个地方不一样，上方的加密结果是参考，下方暴力枚举 c，会得到 256 种加密结果，第一个 block 和上方加密结果一致的，就是 t。

```
|Block 1         |Block 2 |Block 3 |
|RRXXXXXXXXXXXXXt|?......?|?......?|
|------known-----|---m1---|---m2---|

|Block 1         |Block 2 |Block 3 |
|RRXXXXXXXXXXXXXc|?......?|?......?|
|------known-----|---m1---|---m2---|
```

*使用等宽字体观看更佳*



当得到一个 t 之后，我们将最后一个X替换为所得字符（去掉一个X，添加已得字符），就可以继续暴力破解下一个字节。

```
|Block 1         |Block 2 |Block 3 |
|RRXXXXXXXXXXXRt|?.....?|?......?|
|------known-----|---m1---|---m2---|

|Block 1         |Block 2 |Block 3 |
|RRXXXXXXXXXXXRc|?.....?|?......?|
|------known-----|---m1---|---m2---|
```



如果X用完了，就把重现更新X 的长度（祥见参考链接）。



有用的性质：

$r+p+k+1 \equiv 0 \mod B$，其中 r 是随机前缀的长度，p 是 padding 的长度，k 是已知的明文的长度，1 代表了待破解字符 c，B 代表块大小。同余于 0 B 的倍数。



```python
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

```

## 完整代码

```python
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
```





# 问题3

原理：[CBC(密码块链)自愈特性解释](https://stackoverflow.com/questions/26318430/explanation-of-self-healing-property-of-cbc-cipher-block-chaining)

大意就是某一个位被改变，该位所在的block会面目全非，但是之后的一个block只有一个相应的位发生变化，之后就不受影响。

做法：



参考：[CBC Bitflipping Attacks | full-stack overflow (thmsdnnr.com)](https://thmsdnnr.com/blog/cbc-bitflipping-attacks/)

```python
import os
import random
from Crypto.Cipher import AES
from AES_CBC import *
 
prepend_string = "comment1=cooking%20MCs;userdata="
append_string = ";comment2=%20like%20a%20pound%20of%20bacon"
parameter = b";admin=true;"
 
keysize = 16
random_key = os.urandom(keysize)
IV = os.urandom(keysize)
 
 
def encryptor(text: bytes, IV: bytes, key: bytes) -> bytes:
    # 将给定的字符串添加到自定义文本中，并通过AES_CBC模式进行加密
 
    plaintext = (prepend_string.encode() + text + append_string.encode()).replace(b';', b'";"').replace(b'=', b'"="')
    ciphertext = AES_CBC_encrypt(PKCS7_pad(plaintext, len(key)), IV, key)
    return ciphertext
 
 
def decryptor(byte_string: bytes, IV: bytes, key: bytes) -> bool:
    # 通过AES_CBC模式解密给定的密文并检查admin是否设置为true
 
    decrypted_string = PKCS7_unpad(AES_CBC_decrypt(byte_string, IV, key))
    if b";admin=true;" in decrypted_string:
        return True
    else:
        return False
 
 
def CBC_bit_flipping(parameter: bytes, keysize: int, encryptor: callable) -> bytes:
    # 填充
 
    padding = 0
    random_blocks = 0  # 寻找前缀长度
    cipher_length = len(encryptor(b'', IV, random_key))
    prefix_length = len(os.path.commonprefix([encryptor(b'AAAA', IV, random_key), encryptor(b'', IV, random_key)]))
    print("Prefix length: ", prefix_length)
 
    # 查找随机块的数量
    for i in range(int(cipher_length / keysize)):
        if prefix_length < i * keysize:
            random_blocks = i
            break
    print("Random blocks: ", random_blocks)
 
    # 查找所需的字节填充数
    base_cipher = encryptor(b'', IV, random_key)
    for i in range(1, keysize):
        new_cipher = encryptor(b'A' * i, IV, random_key)
        new_prefix_length = len(os.path.commonprefix([base_cipher, new_cipher]))
        if new_prefix_length > prefix_length:
            padding = i - 1
            break
        base_cipher = new_cipher
    print("Number of bytes of padding required: ", padding)
 
    # 翻转给定字符串的字节
    input_text = b'A' * padding + b"heytheremama"
    string = parameter
    modified_string = b""
    ciphertext = encryptor(input_text, IV, random_key)
    for i in range(len(string)):
        modified_string += (ciphertext[i + (random_blocks - 1) * keysize] ^ (input_text[i + padding] ^ string[i])).to_bytes(1, "big")
 
    modified_ciphertext = ciphertext[:(random_blocks - 1) * keysize] + modified_string + ciphertext[(random_blocks - 1) * keysize + len(modified_string):]
 
    return modified_ciphertext
 
 
modified_ciphertext = CBC_bit_flipping(parameter, keysize, encryptor)
print(AES_CBC_decrypt(modified_ciphertext, IV, random_key))
```

