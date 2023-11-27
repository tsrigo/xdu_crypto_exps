import sympy
import binascii

def exgcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = exgcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a, m):
    gcd, x, _ = exgcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def invmod(e, phi):
    '''
    >>> invmod(17, 3120)
    2753
    >>> invmod(3, 20)
    7
    '''
    return mod_inverse(e, phi)

def encrypt(m: int, e: int, n: int) -> int: 
    '''
    >>> encrypt(5, 3, 33)
    26
    '''
    return pow(m, e, n)

def decrypt(c: int, d: int, n: int) -> int:
    '''
    >>> decrypt(26, 7, 33)
    5
    '''
    return pow(c, d, n)

def str2hex(s):
    '''
    >>> str2hex("Hello, World!")
    '48656c6c6f2c20576f726c6421'
    '''
    return binascii.hexlify(s.encode()).decode()

def encstring(m: str, e: int, n: int) -> int:
    hexstr = str2hex(m)
    return encrypt(int(hexstr, 16), e, n)

p, q = sympy.randprime(2**128, 2**256), sympy.randprime(2**128, 2**256)
# p, q = 3, 11
n = p * q
phi = (p - 1) * (q - 1)

e = 3
e = 65537
assert(exgcd(e, phi)[0] == 1)
d = invmod(e, phi)

public = (e, phi)
private = (d, n)

test = 10
assert(test == decrypt(encrypt(test, e, n), d, n))
test = "Hello, World!"
assert(int(str2hex(test), 16) == decrypt(encstring(test, e, n), d, n))
print("test pass!")