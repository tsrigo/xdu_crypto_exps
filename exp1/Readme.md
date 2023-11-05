# manyTimePad

这是Coursera上“密码学I”课程的第1周编程作业的解决方案。

其实这个解决方案很简单,尤其是给出提示要将加密的`MSGS`异或在一起。只需每次取一个`MSGS`,与`TARGET`消息(在代码中恰好是`MSGS[10]`)异或,即:

```
Copy code  MSGS[0] XOR TARGET
  MSGS[1] XOR TARGET
  ... 
  MSGS[9] XOR TARGET
```

这样做会得到什么?想想提示的第二部分,如果异或运算符两侧有一个空格字符和一个字母字符在同一位置,运算后字母字符会从小写变成大写,或者从大写变成小写。

假设我们在异或运算的结果中的某个位置得到一个大写字符“A”,我们知道**可能**在这个位置`MSG[i]`和`TARGET`中有一个包含空格字符,另一个包含小写字母“a”(明文)。这不是绝对的,但可能性还是比较大的。

所以这个作业中剩下的诀窍就是我们如何输出`MSGS[i] XOR TARGET`的结果,以便我们可以清楚地看到结果。这里是一个可能的解决方案:

我使用python是因为作业已经有一个python源代码段,我们可以重用其中的一些部分,例如`strxor()`函数。在得到`MSGS[i] XOR TARGET`的结果后,我比较结果中的每个字节,看它是否在“a”~~“z”或“A”~~“Z”之间,如果是,我直接输出它;如果不是,我简单地输出一个“*”。这样我得到:

```
Copy codeSTART--- * * E C * * C * * * T * * S * * * E N * * X E * H T * * * * * * G Q * A * * * * A * O * * * * * * * * N * * E * A * S * L * * E F * * * O * O * * E T * * * B * * C T ---END
START--- * * * E * E * * * * D M * * * * * * L * S * N * * * N T * * * N * O * * * * * E * * E * * * * E * I C * * * * R A U * * R * * * * * * * N * O * * * * * * * T * N N E ---END
START--- * * * * * * * * E * H * * * S * * * U * S q E * * * * Q U * * N * O * * * * R * * * P * * * * * * D E * * V * * N U * * I * * E A K * * T M * * E F * * * * * * * * * ---END  
START--- * * * * * * * * * * T * * * S * * * D * * * D w * * N A U * * * * * * N * * * * * * O * I * * * * * I * * * E * O * * * * * * E G * * * * * * R * I * * * * T * * * E ---END
START--- * * * * * * * U * T W * * * S * * E B * * * A w * * * * * * I * * R A K * * * E * * O * I * H * * U * * * * E * P * * * A * * * E * E * N M * * * A * * * * * * * * * ---END
START--- * * * R * E * * * T T * * S * * * * S I * * * * * * * T * * * * * H * * * T * * * * * * * * * * R * I * * V * * E * S * E * * * T * E * A * * R * R * * A * O * * C * ---END
START--- * * * R * E * * * T T * * S * * * * S I * * * * * * * O * * * * * Y * * * * * E * * A * I * * * * * S N * * * R g * * * R * * * N * E * O M * * * * * * * * E O * * * ---END
START--- * * E C * * C * * * * * * * S * * * N * S M H * * * N T * * I * * I * * * * R * * * A * * * H * * * A N * * * * G U * * T T * * * * * * T M * * * * * * * * U * * * E ---END
START--- * H M P * * * * * * * * * * Z A G * N * * C P * * * * * * * * * * E A S * * * * * M * C * * * * * E T * * * I R N * * * L * H * * * * * C * * * * E T * * * * * * * * ---END   
START--- t * * E S * * * * * S * E * * * * * D * * Y T * * * * R * S A * W * W * S * * * * * N * * P * * * * T * E * * R T * * E A * * E O * E Y W * * * * N * H * N R O * * * ---END
```

- 现在看结果字符串中的位置0。我们得到9个“*”字符和一个小写“t”。然后**可能** `MSGS[9]`中的第一个字符是一个空格,`TARGET` 中是大写的“T”(明文)。
- 类似地,位置1可能是一个小写的“h”。
- 位置2会有点混乱,因为我们得到2个大写的“E”和一个大写的“M”。我会假设正确答案可能是小写的“e”,因为“E”出现了两次。
- 现在位置3。它有7个不同的字符,我会假设这次`TARGET`在这个位置包含一个空格字符。
- ...

通过这种方式,我们应该能推断出破解后的目标消息`CRACK`类似于:

```
The secuet message is  Whtn usinw a stream cipher  never use the key more than once
```

仍有一些奇怪的词组,不难调整为:

```
The secret message is  When using a stream cipher  never use the key more than once
```

我注意到“When using a stream cipher”周围有额外的空格字符。我会假设第一个额外空格实际上是一个冒号":"第二个是一个逗号","但我不能确定。但是很简单,因为我们现在有目标消息`TARGET`和它的明文`CRACK`,我们可以计算密钥,然后解密其他的`MSGS`来验证密钥是否正确。现在如果我们直接使用带有两个额外空格的`CRACK`,我们会得到如下破解的`MSGS`:

```
Copy codeSTART---We can factor the numxer 15 with quantum computer. We can also factor the number 1---END
START---Euler would probably njoy that now his theorem bicomes a corner stone of crypto - ---END  
START---The nice thing about Qeeyloq is now we cryptograpders can drive a lot of fancy cars---END
START---The ciphertext producd by a weak encryption algo~ithm looks as good as ciphertext ---END
START---You don't want to buy:a set of car keys from a guu who specializes in stealing cars---END
START---There are two types o| cryptography - that which {ill keep secrets safe from your l---END
START---There are two types o| cyptography: one that allo{s the Government to use brute for---END
START---We can see the point mhere the chip is unhappy if,a wrong bit is sent and consumes ---END
START---A (private-key)  encrcption scheme states 3 algorethms, namely a procedure for gene---END
START--- The Concise OxfordDiytionary (2006) defines cry|to as the art of  writing o r sol---END
```

显然,所有明文都有一些奇怪的词语(例如“numxer”、“njoy”、“bicomes”等)。现在我再次用假设的冒号和逗号补全`CRACK`:

```
The secret message is: When using a stream cipher, never use the key more than once
```

我再次验证了`MSGS`的明文,这次我们得到:

```
Copy codeSTART---We can factor the number 15 with quantum computers. We can also factor the number 1---END
START---Euler would probably enjoy that now his theorem becomes a corner stone of crypto - ---END
START---The nice thing about Keeyloq is now we cryptographers can drive a lot of fancy cars---END
START---The ciphertext produced by a weak encryption algorithm looks as good as ciphertext ---END
START---You don't want to buy a set of car keys from a guy who specializes in stealing cars---END
START---There are two types of cryptography - that which will keep secrets safe from your l---END
START---There are two types of cyptography: one that allows the Government to use brute for---END
START---We can see the point where the chip is unhappy if a wrong bit is sent and consumes ---END  
START---A (private-key)  encryption scheme states 3 algorithms, namely a procedure for gene---END
START--- The Concise OxfordDictionary (2006) defines crypto as the art of  writing o r sol---END
```

现在好多了。所以问题解决了。

使用代码如下：
```python
import string 
space = ' '
letter = string.ascii_letters

print(ord(space))
print(letter)
print(''.join([chr(ord(i)^ord(space)) for i in letter]))

# 32
# abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
# ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz

# 可以看出，空格和字母异或后，大小写会互换

import sys

ciphertexts=[  
"315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",  
"234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",  
"32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",  
"32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",  
"3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",  
"32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",  
"32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",  
"315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",  
"271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",  
"466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",  
"32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"  
]  
cArr = [
    [int(c[i:i+2], 16) for i in range(0, len(c), 2)] for c in ciphertexts
]

def strxor(a, b): 
    """xor two strings of different lengths"""  
    if len(a) > len(b):  
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])  
    else:  
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def arrxor(a, b):
    a = [int(a[i:i+2], 16) for i in range(0, len(a), 2)]
    b = [int(b[i:i+2], 16) for i in range(0, len(b), 2)]
    if len(a) > len(b):  
        return "".join([chr(x ^ y) for (x, y) in zip(a[:len(b)], b)])  
    else:  
        return "".join([chr(x ^ y) for (x, y) in zip(a, b[:len(a)])])

    # 若某个集合内字母不同，则该位置可能为空格，将空格对应的密文都提取出来，便可进一步计算明文
treshhold = 6
spaceIndex = []
for i in range(len(possibleLetter)):
    for j in range(len(possibleLetter[i])):
        if len(possibleLetter[i][j]) > treshhold:
            spaceIndex.append((i, j))
            
spaceArr = []
for i in range(len(spaceCipher)):
    ss = spaceCipher[i]
    if len(ss) == 1:
        for hh in ss :
            spaceArr.append(hh)
    else:
        spaceArr.append(ord(' '))
# len(spaceCipher), len(spaceArr), spaceArr

def xorDecArr(a, b):
    return [chr(a[i]^b[i]) for i in range(min(len(a), len(b)))]

''.join(xorDecArr(cArr[0], spaceArr))

# 若只有一个可能的字母，则大概率为明文
def xorOneHex(idx, a, b):
    i = idx * 2
    a = int(a[i:i+2], 16)
    b = int(b[i:i+2], 16)
    return chr(a ^ b)

def xorOneDec(a, b):
    return chr(a ^ b)

keySet = [set() for _ in range(max([len(cArr[i]) for i in range(len(possibleLetter))]))]

for i in range(len(possibleLetter)):
    for j in range(len(cArr[i])):
        possSet = possibleLetter[i][j]
        if len(possSet) == 1:
            for hh in possSet:
                keySet[j].add(xorOneHex(0, hex(ord(hh))[2:], hex(cArr[i][j])[2:]))

keySet

key1cnt = 0
for i in keySet:
    if len(i) == 1:
        key1cnt += 1
print(key1cnt)

keyArr = []
for i in range(len(keySet)):
    ss = keySet[i]
    if len(ss) == 1:
        for hh in ss :
            keyArr.append(ord(hh))
    else:
        keyArr.append(ord(' '))

''.join(xorDecArr(keyArr, cArr[0]))

# 还是有一些有多余的，，，看看密钥空间现在多大
ll = [len(i) for i in keySet]
ll
cnt = 1
for i in ll:
    if i != 0:
        cnt *= i
cnt
# 我超，8388608，肯定不行了，还有那么多为0的，mmp

# 不确定密钥的长度，看看密文的长度集合
[len(i) for i in cArr], max([len(i) for i in cArr])

[(idx, len(hh)) for idx, hh in enumerate(cArr)]

target = cArr[-1]
visible = string.ascii_letters
from collections import defaultdict

hh = [defaultdict(int) for _ in range(max([len(hh) for hh in cArr]))]

for i in range(10):
    print('0'+str(i), end='|')
for i in range(10, 100):
    print(i, end='|')
print()

for index, i in enumerate(cArr):
    res = xorDecArr(target, i)
    tep = ''
    for cidx, c in enumerate(res):
        if c in visible:
            tep += c
            print(c, end = ' |')
        else:
            tep += '*'
            print('*', end = ' |') 
    for cidx, c in enumerate(tep):
        if c == '*':
            continue
        hh[cidx][c] += 1
    print()

print('---Plain---')
thesh = 3

for dic in hh:
    if not len(dic):
        print('*', end=' |')
    elif len(dic) >= thesh:
            print(' ', end = ' |')
    else:
        maxn = max([dic[j] for j in dic])
        for j in dic:
            if dic[j] == maxn:
                print(j.lower(), end = ' |')
                break

hh

# 创建一个 defaultdict，当键不存在时，返回默认值 0
d = defaultdict(int)

# 当我们尝试访问一个不存在的键时，它会返回默认值 0
print(d["some_key"])  # 输出：0

# 现在 "some_key" 已经在字典中了，它的值是 0
print(d)  # 输出：defaultdict(<class 'int'>, {'some_key': 0})

possbilePlaintext = 'The secret message is: When using a stream cipher, never use the key more than once'
possbilePlaintextArr = [ord(x) for x in possbilePlaintext]
key = [ord(x) for x in xorDecArr(possbilePlaintextArr, cArr[-1])]
for i in cArr:
    print(''.join(xorDecArr(key, i)))
```

# vigenere-like cipher

设密文为 $c$，密钥为 $k$，则密文为 $c \oplus k$。

首先，题干中所说的维吉尼亚-like是指将密钥复制为和明文一样长（多出来的删除掉），然后进行异或运算。

因此，结合one-time pad的思想，可知利用密钥和密文进行异或，便得到明文。

题干中提到“明文包含大写字母、小写字母、标点符号和空格，但不包含数字”，因此可以枚举密钥，然后将密钥和密文进行异或，得到的结果中，如果有数字，则说明该密钥不正确。据此暴力找出密钥。

```python
c = "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"
cArr = [int(c[i:i+2], 16) for i in range(0, len(c), 2)] # 16进制转10进制：[249, 109, ...]
print(len(cArr))

correctChar = []
for x in range(32,126):
    correctChar.append(x)
for x in range(48, 58): # 不包含数字
    correctChar.remove(x)

def findindexkey(subarr): # 该函数可以找出将密文subarr解密成可见字符的所有可能值
    test_keys=[]# 用于测试密钥
    ans_keys=[]# 用于结果的返回
    for x in range(0x00,0xFF):# 枚举密钥里所有的值
        test_keys.append(x)
        ans_keys.append(x)
    for i in test_keys: # 对于0x00~0xFF里的每一个数i和subarr里的每个值s异或
        for s in subarr:
            if s^i not in correctChar: # 用i解密s，如果解密后明文不是可见字符，说明i不是密钥
                ans_keys.remove(i) # 去掉ans_keys里测试失败的密钥
                break
    return ans_keys
```

```python
def findKeySpace(maxLen=14):
    keySpace = []
    for keylen in range(1,maxLen): # 枚举密钥的长度1~14
        for index in range(0,keylen): # 对密钥里的第index个进行测试
            subarr=cArr[index::keylen] # 每隔keylen长度提取密文的内容，提取出来的内容都被密文的第index个加密
            ans_keys=findindexkey(subarr) # 找出密钥中第index个的可能的值
            if ans_keys:
                print('keylen=',keylen,'index=',index,'keys=',ans_keys)
                keySpace.append(ans_keys) # 将所有可能的值存入keySpace
    return keySpace
# 得出结论，密钥长度为 7
keySpace = findKeySpace()
```

```python
cnt = 1
for i in range(len(keySpace)):
    print('in index ', i, 'key space size is ', len(keySpace[i]))
    cnt *= len(keySpace[i])
print('total key space size is ', cnt)
# 结果是 497664，可以暴力枚举
```

```python
# 枚举所有可能的密钥，长度为 7 
hh = []
def enumKey(keySpace):
    for i in keySpace[0]:
        for j in keySpace[1]:
            for k in keySpace[2]:
                for l in keySpace[3]:
                    for m in keySpace[4]:
                        for n in keySpace[5]:
                            for o in keySpace[6]:
                                key = [i,j,k,l,m,n,o]
                                hh.append(key)
enumKey(keySpace)
```

```python
ansSpace = []
for key in hh:
    ansSpace.append(''.join([chr(cArr[i]^key[i%7]) for i in range(len(cArr))]))
# 输出为txt文件
with open('ans.txt', 'w') as f:
    for ans in ansSpace:
        f.write(ans+'\n')
```

```python
import string
# 不妨缩小一下明文范围：大写字母，小写字母，空格，逗号，句号，问号，感叹号
testString = string.ascii_letters + ' ,.?!'
correctChar = [ord(x) for x in testString]
keySpace = findKeySpace()

# 此时解唯一，密钥为：[186, 31, 145, 178, 83, 205, 62]
```

```python
# 解密时刻
keyLen = 7
for i in range(len(cArr)):
    print(chr(cArr[i] ^ keySpace[i % keyLen][0]), end='')
```

# the cryptopals crypto challenges Challenges Set 1

1. [Convert hex to base64](https://cryptopals.com/sets/1/challenges/1)
2. [Fixed XOR](https://cryptopals.com/sets/1/challenges/2)
3. [Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3)
4. [Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4)
![在这里插入图片描述](https://img-blog.csdnimg.cn/914beb3f3aa544dcb47350eed4f73e3c.png)

最近通了这几关，很有意思，记录一下思路

1. 使用 int, chr, join, base64的一些函数即可
2.  类似第一问
3. 暴力枚举，同时需要一个scoring函数来作为判断标准（在此之前我都是肉眼找能辨识的字符串呜呜呜
4. 利用第三问的代码暴力枚举，但是这里题目没有说异或的字符是字母！非常坑！

代码如下，仅作参考，慢慢学习发现如果自己找到bug效果是最好的，但是如果绞尽脑汁想破头皮都没办法，可能还是需要一点提示

1

```python
def hex2base64(raw: str):
    '''
    >>> hex2base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    '''
    Str = ''.join([chr(int(raw[i:i+2], 16)) for i in range(0, len(raw), 2)])
    print(Str)
    return base64.b64encode(Str.encode()).decode()
```
2
```python
def fixedXor(str1: str, str2: str) -> str:
    '''
    >>> fixedXor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    746865206b696420646f6e277420706c6179
    '''
    dec1 = [int(str1[i:i+2], 16) for i in range(0, len(str1), 2)]
    dec2 = [int(str2[i:i+2], 16) for i in range(0, len(str2), 2)]
    return ''.join([hex(i ^ j)[2:] for i,j in zip(dec1, dec2)])
```
3

```python
latter_frequency = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .15000
}

def scoring(t):
    '''
    >>> scoring("Cooking MC's like a pound of bacon")
    2.2632899999999996
    '''
    return sum([latter_frequency.get(i,0) for i in t.lower()])  
    
# 我一开始的写法，漏掉了空格！ cnm
def scoring2(raw: str):
    letter = string.ascii_letters
    cnt = 0
    for i in raw:
        if i in letter:
            cnt += latter_frequency[i.lower()]
    return cnt 
    
def findSingleXor(raw: str):
    letter = string.ascii_letters
    cmp = 0
    returnAns = ''
    for i in letter:
        hh = ''.join([str(hex(ord(i))[2:]) for _ in range(len(raw)>>1)])
        res = hex2ascii(fixedXor(hh, raw))
        if scoring(res) > cmp:
            cmp = scoring(res)
            returnAns = res
    return returnAns, cmp
```
4

```python
def findSingleXor(raw: str):
    letter = [chr(i) for i in range(255)] # 区别
    cmp = 0
    returnAns = ''
    for i in letter:
        hh = ''.join([str(hex(ord(i))[2:]) for _ in range(len(raw)>>1)])
        res = hex2ascii(fixedXor(hh, raw))
        if scoring(res) > cmp:
            cmp = scoring(res)
            returnAns = res
    return returnAns, cmp

# 打开文件
with open('4.txt', 'r') as file:
    # 读取每一行
    lines = file.readlines()

# 输出每一行
minni = 0
minn = 0
minnstr = ''
for i, line in enumerate(lines):
    line = line[0:-1]
    if (findSingleXor(line)[1] == 0):
        continue
    if (findSingleXor(line)[1] > minn):
        minni = i
        minnstr = findSingleXor(line)[0]
        minn = findSingleXor(line)[1]
print("The max score is the " + str(minni) + "th str and the plaintext is " + minnstr)
```

剩下的几题：

![在这里插入图片描述](https://img-blog.csdnimg.cn/954d6201f3e64f939cff47e163a391bd.png)
1. [Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)
2. [Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6)
3. [AES in ECB mode](https://cryptopals.com/sets/1/challenges/7)
4. [Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8)

## 思路与代码
### 1
利用之前的fixedxor函数就好，但是落实到具体容易出一些编码的问题。
我遇到的问题是在字符串和二进制/十六进制转换的时候，直接使用bin()/hex()去掉前缀的结果进行拼接，这样的后果是长度不对齐，字符转换成二进制，长度应为8，不足需要补前导0，十六进制则长度应为2，不足需要补前导0。
```python
def ascii2hex(raw: str):
    '''
    >>> ascii2hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    61616161616161616161616161616161616161616161616161616161616161616161
    >>> ascii2hex('\n')
    0a
    '''
    return ''.join([hex(ord(i))[2:].zfill(2) for i in raw])

def repeatXor(raw: str, key: str):
    '''
    >>> repeatXor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE')
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    '''
    key = (key * (int(len(raw) / len(key)) + 1))[:len(raw)]
    return fixedXor(ascii2hex((raw)), ascii2hex(key))

def fixedXor(str1: str, str2: str) -> str:
    '''
    >>> fixedXor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    746865206b696420646f6e277420706c6179
    '''
    dec1 = [int(str1[i:i+2], 16) for i in range(0, len(str1), 2)]
    dec2 = [int(str2[i:i+2], 16) for i in range(0, len(str2), 2)]
    return ''.join([hex(i ^ j)[2:].zfill(2) for i,j in zip(dec1, dec2)])
```

### 2
首先写一个计算汉明距离的函数，稍后利用汉明距离作为评分标准。
```python
def hamming(raw1: str, raw2: str):
    '''
    >>> hamming('this is a test', 'wokka wokka!!!')
    37
    '''
    bias = 0
    if (len(raw1) > len(raw2)):
        bias = len(raw1) - len((raw2))
        raw1 = raw1[:len(raw2)]
    elif (len(raw1) < len(raw2)):
        bias = len(raw2) - len((raw1))
        raw2 = raw2[:len(raw1)]
    raw1 = ascii2bin(raw1)
    raw2 = ascii2bin(raw2)
    return sum([raw1[i] != raw2[i] for i in range(len(raw1))])+bias
```
然后读取文件，解码base64，得到raw string。注意要去掉每一行的换行符，还要注意文件最后应以换行作为最后一行防止最后一个字符串缺一个字符。
```python
cipherFile = ''
with open('6.txt', 'r') as file:
    # 读取每一行
    lines = file.readlines()
for line in lines:
    cipherFile += line[0:-1]	
strCipherFile = base64.b64decode(cipherFile).decode()
```
用题目所给的两种方法计算汉明距离得分。得分的对应的keysize大概率就是keysize。
```python
candidate = []
strCipherFile = base64.b64decode(cipherFile).decode()
for KeySize in range(2, 40):
    ss1 = strCipherFile[:KeySize]
    ss2 = strCipherFile[KeySize: 2 * KeySize]
    candidate.append((hamming(ss1, ss2)/KeySize, KeySize))
print(sorted(candidate))

candidate = []
strCipherFile = base64.b64decode(cipherFile).decode()
for KeySize in range(1, 40):
    ss1 = strCipherFile[:KeySize]
    ss2 = strCipherFile[KeySize: 2 * KeySize]
    ss3 = strCipherFile[2 * KeySize: 3 * KeySize]
    ss4 = strCipherFile[3 * KeySize: 4 * KeySize]
    # 计算所有可能的汉明距离
    hamming_distances = [hamming(ss1, ss2), hamming(ss1, ss3), hamming(ss1, ss4), 
                    hamming(ss2, ss3), hamming(ss2, ss4), 
                    hamming(ss3, ss4)]
    # 计算平均汉明距离
    average_hamming_distance = sum(hamming_distances) / len(hamming_distances)

    candidate.append(((average_hamming_distance/KeySize), KeySize))
print(sorted(candidate))

```
第二种方法似乎更靠谱一点，因为真正的 keysize 没有出现在前一种里。。。最终 keysize 为 29。

然后基于 keysize 分块，按列划分字符串进行单个字符异或的破解（[Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4)），依次得到密钥的每一位，接着就可以用密钥进行解密（[Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)）。
ps（这里思路我当时没缕清，以为 findSingleXor 的结果应该是有特征的。。。但是它是又一列的字符构成的字符串，当然不会有规律了。。。重点是猜出这一位的 key，然后拼起来，最后用来解密密文，这时的结果才是有规律的。。。）

```python
KeySize = 29
strCipherFile = strCipherFile.zfill(2871+29)
breakCipher = [strCipherFile[i:i + KeySize] for i in range(0, len(strCipherFile), KeySize)]
transBreakCipher = [None for _ in range(len(breakCipher[0]))]
for i in range(KeySize):
    transBreakCipher[i] = ''.join([ss[i] for ss in breakCipher])

key = ''
for i in transBreakCipher:
    key += findSingleXor(ascii2hex(i))[2]
print(key)	# nator X: Bring the noiseTermi
print(hex2ascii(repeatXor(strCipherFile, key)))
```

看到明文时还是很感动的

![在这里插入图片描述](https://img-blog.csdnimg.cn/c3029720a6b140e2944ebc8a6b5b2b37.png)
### 3
不知道题目是不是想让我们手动实现ecb的解密？说是不建议用openssl命令行，那我用python写代码应该没问题吧）
```python
from Crypto.Cipher import AES
with open('7.txt', 'r') as file:
    lines = file.readlines()

cipherText = ''.join([i[:-1] for i in lines]) + 'H' # 原来的文件最后没有换行
cipherText = base64.b64decode(cipherText)	# 题目说到结果使用了base64编码
key = 'YELLOW SUBMARINE'

cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
cipher.decrypt(cipherText.encode())
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/e4f2c1d9f7304f8bb36a3dcc4f5e6a25.png)

### 4
检测 ECB 模式。使用 ECB 会导致重复的密文加密后出现重复的结果，以此为依据，分析每个分组的出现频次即可。这里我先用 set 记录每个字符串对应的分组的集合的大小，如果有重复集合就会比较小，结果证明这样就足以检测 ECB 了。
```python
with open('8.txt', 'r') as file:
    lines = file.readlines()

lines = [i[:-1] for i in lines]
# 16 bytes == 16 hex values -> length of 32
splitLines = [set([ss[i:i+32] for i in range(0, len(ss), 32)]) for ss in lines]
print(sorted([(len(hh), i) for i, hh in enumerate(splitLines)]))
```

# [MTC3]Cracking SHA1-Hashed Passwords

网上有用八重循环的，非常不优雅。。。

首先，我们知道密码是由给定字符集的字符组成的，每个字符都有两种可能的选择。这就形成了一个二叉树，其中每个节点都代表一个字符的选择，树的深度等于字符集的大小。

然后，我使用深度优先搜索（DFS）来遍历这个二叉树。DFS是一种用于遍历或搜索树或图的算法。在这个场景中，我从树的根节点开始，沿着一条路径向下搜索，直到达到一个叶节点，也就是一个可能的密码组合。

对于每一个叶节点，我使用`itertools.permutations`来生成所有可能的排列，然后计算每个排列的SHA1哈希值，与给定的哈希值进行比较。

如果找到了一个匹配的哈希值，我就立即停止搜索，并打印出对应的密码和搜索所用的时间。这样，一旦找到答案，就不需要再继续搜索了，这大大提高了代码的效率。

```python
#coding:utf-8
import hashlib
import itertools
import datetime

def sha_encrypt(str):
    sha = hashlib.sha1(str.encode())
    encrypts = sha.hexdigest()
    return encrypts

def dfs(idx, path, str2, hash1):
    if idx == len(str2):
        for p in itertools.permutations(path):
            if sha_encrypt("".join(p)) == hash1:
                print("".join(p))
                print((datetime.datetime.now() - starttime).seconds)
                return True
        return False

    for i in range(2):
        if dfs(idx + 1, path + [str2[idx][i]], str2, hash1):
            return True
    return False

starttime = datetime.datetime.now()
hash1="67ae1a64661ac8b4494666f58c4822408dd0a3e4"
str2=[['Q', 'q'],[ 'W', 'w'],[ '%', '5'], ['8', '('],[ '=', '0'], ['I', 'i'], ['*', '+'], ['n', 'N']]

dfs(0, [], str2, hash1)

```